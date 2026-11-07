"""Persistent, review-only successor-lease recovery proposals.

This module records a validated recovery proposal after an earlier lease expires.
It never issues the successor lease, claims a task, retries work, authenticates a
worker, performs side effects, or authorizes execution.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone

from scripts.enterprise_hq_lease_contract import validate_recovery_successor
from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
    _canonical_json,
    _utc_now,
    _validate_timestamp,
)
from scripts.enterprise_hq_verification_ledger import VerificationReceiptLedger

MAX_RECOVERY_PROPOSALS = 256
RECOVERY_ID_PATTERN = re.compile(r"^HQR-[A-F0-9]{24}$")


def _aware_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ContractError("RECOVERY_EVALUATION_TIME_INVALID")
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp")
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _recovery_id(
    task_id: str,
    previous_lease_id: str,
    successor_lease_id: str,
    successor_digest: str,
) -> str:
    body = {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "previous_lease_id": previous_lease_id,
        "successor_lease_id": successor_lease_id,
        "successor_digest": successor_digest,
    }
    digest = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest().upper()
    return "HQR-" + digest[:24]


class SuccessorLeaseRecoveryLedger(VerificationReceiptLedger):
    """Unified task/budget/lease/receipt ledger with review-only recovery proposals."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS recovery_proposals (
                    recovery_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL UNIQUE REFERENCES tasks(task_id),
                    previous_lease_id TEXT NOT NULL UNIQUE
                        REFERENCES lease_proposals(lease_id),
                    successor_lease_id TEXT NOT NULL UNIQUE,
                    proposal_digest TEXT NOT NULL,
                    successor_lease_json TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status = 'PROPOSED_FOR_HUMAN_REVIEW'),
                    side_effects_started INTEGER NOT NULL CHECK (side_effects_started = 0),
                    created_at TEXT NOT NULL
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS recovery_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    recovery_id TEXT NOT NULL UNIQUE
                        REFERENCES recovery_proposals(recovery_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    previous_lease_id TEXT NOT NULL,
                    successor_lease_id TEXT NOT NULL,
                    successor_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'SUCCESSOR_LEASE_PROPOSED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                )"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS recovery_audit_events_task_id_idx "
                "ON recovery_audit_events(task_id)"
            )
        except Exception:
            self.close()
            raise

    def _append_recovery_event(
        self,
        recovery_id: str,
        task_id: str,
        previous_lease_id: str,
        successor_lease_id: str,
        successor_digest: str,
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM recovery_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "recovery_id": recovery_id,
            "task_id": task_id,
            "previous_lease_id": previous_lease_id,
            "successor_lease_id": successor_lease_id,
            "successor_digest": successor_digest,
            "event": "SUCCESSOR_LEASE_PROPOSED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO recovery_audit_events
               (sequence, recovery_id, task_id, previous_lease_id,
                successor_lease_id, successor_digest, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, 'SUCCESSOR_LEASE_PROPOSED', ?, ?, ?)""",
            (
                sequence,
                recovery_id,
                task_id,
                previous_lease_id,
                successor_lease_id,
                successor_digest,
                occurred_at,
                previous_hash,
                record_hash,
            ),
        )

    @staticmethod
    def _result(
        recovery_id: str,
        task_id: str,
        previous_lease_id: str,
        successor_lease_id: str,
        *,
        created: bool,
        already_present: bool,
    ) -> dict:
        return {
            "recovery_id": recovery_id,
            "task_id": task_id,
            "previous_lease_id": previous_lease_id,
            "successor_lease_id": successor_lease_id,
            "created": created,
            "already_present": already_present,
            "status": "PROPOSED_FOR_HUMAN_REVIEW",
            "transition_status": "RECOVERY_PROPOSAL_VALIDATION_ONLY",
            "successor_proposal_persisted": True,
            "successor_lease_issued": False,
            "human_approval_required": True,
            "automatic_retry": False,
            "identity_assurance": "NOT_AUTHENTICATED",
            "execution_authorized": False,
        }

    def propose_successor_lease(
        self,
        task: Mapping,
        expired_lease: Mapping,
        successor_lease: Mapping,
        now: datetime,
        side_effects_started: bool = False,
    ) -> dict:
        """Persist one validated attempt-2 proposal for human review only."""
        if type(side_effects_started) is not bool:
            raise ContractError("RECOVERY_FLAGS_INVALID")
        evaluated = _aware_datetime(now)
        validated_task = validate_task(task)
        transition = validate_recovery_successor(
            task,
            expired_lease,
            successor_lease,
            evaluated,
            side_effects_started,
        )

        canonical_task = _canonical_json(dict(task))
        canonical_previous = _canonical_json(dict(expired_lease))
        canonical_successor = _canonical_json(dict(successor_lease))
        task_id = validated_task["task_id"]
        proposal_digest = validated_task["idempotency_key"]
        previous_lease_id = transition["previous_lease_id"]
        successor_lease_id = transition["successor_lease_id"]
        successor_digest = hashlib.sha256(
            canonical_successor.encode("utf-8")
        ).hexdigest()
        recovery_id = _recovery_id(
            task_id,
            previous_lease_id,
            successor_lease_id,
            successor_digest,
        )
        if not RECOVERY_ID_PATTERN.fullmatch(recovery_id):
            raise ContractError("RECOVERY_ID_INVALID")
        evaluated_at = _timestamp_text(evaluated)

        with self._transaction():
            # Verify every inherited chain before checking or appending recovery state.
            self.verify()
            task_row = self._connection.execute(
                "SELECT idempotency_key, task_json FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if (
                task_row is None
                or task_row["idempotency_key"] != proposal_digest
                or task_row["task_json"] != canonical_task
            ):
                raise LedgerError("RECOVERY_TASK_NOT_PERSISTED")

            previous_row = self._connection.execute(
                """SELECT task_id, proposal_digest, lease_json, status
                   FROM lease_proposals WHERE lease_id = ?""",
                (previous_lease_id,),
            ).fetchone()
            if (
                previous_row is None
                or previous_row["task_id"] != task_id
                or previous_row["proposal_digest"] != proposal_digest
                or previous_row["lease_json"] != canonical_previous
                or previous_row["status"] != "PROPOSED"
            ):
                raise LedgerError("RECOVERY_PREVIOUS_LEASE_NOT_PERSISTED")

            existing = self._connection.execute(
                "SELECT * FROM recovery_proposals WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["recovery_id"] != recovery_id
                    or existing["previous_lease_id"] != previous_lease_id
                    or existing["successor_lease_id"] != successor_lease_id
                    or existing["proposal_digest"] != proposal_digest
                    or existing["successor_lease_json"] != canonical_successor
                    or existing["side_effects_started"] != 0
                ):
                    raise TaskConflictError("RECOVERY_TASK_ALREADY_HAS_DIFFERENT_SUCCESSOR")
                return self._result(
                    recovery_id,
                    task_id,
                    previous_lease_id,
                    successor_lease_id,
                    created=False,
                    already_present=True,
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM recovery_proposals"
            ).fetchone()[0]
            if count >= MAX_RECOVERY_PROPOSALS:
                raise LedgerError("RECOVERY_PROPOSAL_CAPACITY_REACHED")

            self._connection.execute(
                """INSERT INTO recovery_proposals
                   (recovery_id, task_id, previous_lease_id, successor_lease_id,
                    proposal_digest, successor_lease_json, evaluated_at, status,
                    side_effects_started, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'PROPOSED_FOR_HUMAN_REVIEW', 0, ?)""",
                (
                    recovery_id,
                    task_id,
                    previous_lease_id,
                    successor_lease_id,
                    proposal_digest,
                    canonical_successor,
                    evaluated_at,
                    _utc_now(),
                ),
            )
            self._append_recovery_event(
                recovery_id,
                task_id,
                previous_lease_id,
                successor_lease_id,
                successor_digest,
            )

        return self._result(
            recovery_id,
            task_id,
            previous_lease_id,
            successor_lease_id,
            created=True,
            already_present=False,
        )

    def verify(self) -> dict:
        """Verify inherited ledgers and every persisted successor-recovery proposal."""
        base = super().verify()
        task_rows = self._connection.execute(
            "SELECT task_id, task_json, idempotency_key FROM tasks"
        ).fetchall()
        tasks = {
            row["task_id"]: {
                "task": json.loads(row["task_json"]),
                "digest": row["idempotency_key"],
            }
            for row in task_rows
        }
        lease_rows = self._connection.execute(
            """SELECT lease_id, task_id, proposal_digest, lease_json, status
               FROM lease_proposals"""
        ).fetchall()
        leases = {row["lease_id"]: row for row in lease_rows}

        recovery_rows = self._connection.execute(
            """SELECT recovery_id, task_id, previous_lease_id, successor_lease_id,
                      proposal_digest, successor_lease_json, evaluated_at, status,
                      side_effects_started, created_at
               FROM recovery_proposals ORDER BY recovery_id"""
        ).fetchall()
        if len(recovery_rows) > MAX_RECOVERY_PROPOSALS:
            raise LedgerCorruptionError("RECOVERY_PROPOSAL_CAPACITY_INVARIANT_FAILED")

        recovery_map = {}
        for row in recovery_rows:
            task_entry = tasks.get(row["task_id"])
            previous_row = leases.get(row["previous_lease_id"])
            if task_entry is None or previous_row is None:
                raise LedgerCorruptionError("RECOVERY_REFERENCE_INVALID")
            task = task_entry["task"]
            try:
                previous_lease = json.loads(previous_row["lease_json"])
                successor_lease = json.loads(row["successor_lease_json"])
                evaluated_at = _parse_timestamp(row["evaluated_at"])
                transition = validate_recovery_successor(
                    task,
                    previous_lease,
                    successor_lease,
                    evaluated_at,
                    False,
                )
            except (ValueError, TypeError, KeyError, AttributeError, ContractError):
                raise LedgerCorruptionError("STORED_RECOVERY_CONTRACT_INVALID") from None

            successor_canonical = _canonical_json(successor_lease)
            successor_digest = hashlib.sha256(
                successor_canonical.encode("utf-8")
            ).hexdigest()
            expected_id = _recovery_id(
                row["task_id"],
                row["previous_lease_id"],
                row["successor_lease_id"],
                successor_digest,
            )
            if (
                successor_canonical != row["successor_lease_json"]
                or previous_row["task_id"] != row["task_id"]
                or previous_row["proposal_digest"] != row["proposal_digest"]
                or previous_row["status"] != "PROPOSED"
                or row["proposal_digest"] != task_entry["digest"]
                or transition["previous_lease_id"] != row["previous_lease_id"]
                or transition["successor_lease_id"] != row["successor_lease_id"]
                or row["recovery_id"] != expected_id
                or not RECOVERY_ID_PATTERN.fullmatch(row["recovery_id"])
                or row["status"] != "PROPOSED_FOR_HUMAN_REVIEW"
                or row["side_effects_started"] != 0
                or not _validate_timestamp(row["evaluated_at"])
                or not _validate_timestamp(row["created_at"])
            ):
                raise LedgerCorruptionError("STORED_RECOVERY_INVARIANT_FAILED")
            recovery_map[row["recovery_id"]] = {
                "task_id": row["task_id"],
                "previous_lease_id": row["previous_lease_id"],
                "successor_lease_id": row["successor_lease_id"],
                "successor_digest": successor_digest,
            }

        events = self._connection.execute(
            """SELECT sequence, recovery_id, task_id, previous_lease_id,
                      successor_lease_id, successor_digest, event, occurred_at,
                      previous_hash, record_hash
               FROM recovery_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(recovery_rows):
            raise LedgerCorruptionError("RECOVERY_AUDIT_EVENT_COUNT_MISMATCH")

        previous_hash = None
        seen_recoveries = set()
        for expected_sequence, row in enumerate(events, start=1):
            proposal = recovery_map.get(row["recovery_id"])
            if (
                row["sequence"] != expected_sequence
                or proposal is None
                or row["recovery_id"] in seen_recoveries
                or row["task_id"] != proposal["task_id"]
                or row["previous_lease_id"] != proposal["previous_lease_id"]
                or row["successor_lease_id"] != proposal["successor_lease_id"]
                or row["successor_digest"] != proposal["successor_digest"]
                or row["event"] != "SUCCESSOR_LEASE_PROPOSED"
                or row["previous_hash"] != previous_hash
                or not _validate_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError("RECOVERY_AUDIT_CHAIN_STRUCTURE_INVALID")
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "recovery_id": row["recovery_id"],
                "task_id": row["task_id"],
                "previous_lease_id": row["previous_lease_id"],
                "successor_lease_id": row["successor_lease_id"],
                "successor_digest": row["successor_digest"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError("RECOVERY_AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen_recoveries.add(row["recovery_id"])

        return {
            **base,
            "recovery_proposal_count": len(recovery_rows),
            "recovery_audit_event_count": len(events),
            "recovery_audit_chain": "VALID",
            "recovery_status": "PROPOSALS_PENDING_HUMAN_REVIEW",
        }

    def recover_after_restart(self) -> dict:
        """Verify all persisted state after reopen; never resume or retry work."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "budget_proposals_recovered": verified["budget_count"],
            "lease_proposals_recovered": verified["lease_proposal_count"],
            "untrusted_receipts_recovered": verified["verification_receipt_count"],
            "successor_recovery_proposals_recovered": verified["recovery_proposal_count"],
            "successor_recovery_proposals_pending_review": verified["recovery_proposal_count"],
            "execution_resumed": False,
            "successor_lease_issued": False,
            "automatic_retry": False,
            "execution_authorized": False,
        }
