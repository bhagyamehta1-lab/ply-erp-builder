"""Local, durable lease-proposal records for the Enterprise-HQ company lane.

This extends the bounded proposal ledger with a second, independently verified audit
chain. It records future first-attempt lease envelopes for human review only. It never
issues an active lease, authenticates a worker, claims a task, retries work, or authorizes execution.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from collections.abc import Mapping

from scripts.enterprise_hq_lease_contract import validate_lease
from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_budgeted_task_ledger import BudgetedTaskLedger
from scripts.enterprise_hq_task_ledger import (
    MAX_LEDGER_TASKS,
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
)

MAX_LEASE_PROPOSALS = MAX_LEDGER_TASKS


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


class LeaseProposalLedger(BudgetedTaskLedger):
    """BudgetedTaskLedger extension that stores future first-attempt lease proposals only."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS lease_proposals (
                    lease_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    logical_owner_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL CHECK (attempt = 1),
                    lease_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status = 'PROPOSED'),
                    created_at TEXT NOT NULL,
                    UNIQUE(task_id, attempt)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS lease_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    lease_id TEXT NOT NULL UNIQUE REFERENCES lease_proposals(lease_id),
                    task_id TEXT NOT NULL,
                    event TEXT NOT NULL CHECK (event = 'LEASE_PROPOSED'),
                    logical_owner_id TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                )"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS lease_audit_events_task_id_idx "
                "ON lease_audit_events(task_id)"
            )
        except Exception:
            self.close()
            raise

    def _append_lease_event(
        self, lease_id: str, task_id: str, logical_owner_id: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM lease_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "lease_id": lease_id,
            "task_id": task_id,
            "event": "LEASE_PROPOSED",
            "logical_owner_id": logical_owner_id,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
        self._connection.execute(
            """INSERT INTO lease_audit_events
               (sequence, lease_id, task_id, event, logical_owner_id,
                occurred_at, previous_hash, record_hash)
               VALUES (?, ?, ?, 'LEASE_PROPOSED', ?, ?, ?, ?)""",
            (
                sequence, lease_id, task_id, logical_owner_id,
                occurred_at, previous_hash, record_hash,
            ),
        )

    def propose_lease(
        self, task: Mapping, lease: Mapping, now: datetime
    ) -> dict:
        """Persist a future first-attempt lease proposal after its task is recorded."""
        validated_task = validate_task(task)
        validated_lease = validate_lease(task, lease, now)
        if validated_lease["lease_status"] != "NOT_YET_VALID":
            raise ContractError("LEASE_PROPOSAL_MUST_BE_FUTURE")
        if validated_lease["attempt"] != 1:
            raise ContractError("LEASE_SUCCESSOR_REQUIRES_SEPARATE_REVIEW")

        canonical_task = _canonical_json(dict(task))
        canonical_lease = _canonical_json(dict(lease))
        lease_id = validated_lease["lease_id"]
        task_id = validated_task["task_id"]
        digest = validated_task["idempotency_key"]
        owner_id = validated_lease["logical_owner_id"]
        attempt = validated_lease["attempt"]

        created = False
        with self._transaction():
            # Both the task chain and the lease chain must verify before any append.
            self.verify()
            task_row = self._connection.execute(
                "SELECT idempotency_key, task_json FROM tasks WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if (task_row is None or task_row["idempotency_key"] != digest
                    or task_row["task_json"] != canonical_task):
                raise LedgerError("LEASE_TASK_NOT_PERSISTED")

            existing = self._connection.execute(
                "SELECT lease_json FROM lease_proposals WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if existing is not None:
                if existing["lease_json"] != canonical_lease:
                    raise TaskConflictError("LEASE_ID_CONTENT_CONFLICT")
                return {
                    "lease_id": lease_id,
                    "task_id": task_id,
                    "created": False,
                    "already_present": True,
                    "status": "HUMAN_REVIEW_REQUIRED",
                    "proposal_persisted": True,
                    "lease_issued": False,
                    "execution_authorized": False,
                }

            same_attempt = self._connection.execute(
                "SELECT lease_id FROM lease_proposals WHERE task_id = ? AND attempt = ?",
                (task_id, attempt),
            ).fetchone()
            if same_attempt is not None:
                raise TaskConflictError("LEASE_ATTEMPT_ALREADY_PROPOSED")

            count = self._connection.execute(
                "SELECT COUNT(*) FROM lease_proposals"
            ).fetchone()[0]
            if count >= MAX_LEASE_PROPOSALS:
                raise LedgerError("LEASE_PROPOSAL_CAPACITY_REACHED")

            self._connection.execute(
                """INSERT INTO lease_proposals
                   (lease_id, task_id, proposal_digest, logical_owner_id,
                    attempt, lease_json, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'PROPOSED', ?)""",
                (
                    lease_id, task_id, digest, owner_id, attempt,
                    canonical_lease, _utc_now(),
                ),
            )
            self._append_lease_event(lease_id, task_id, owner_id)
            created = True

        return {
            "lease_id": lease_id,
            "task_id": task_id,
            "created": created,
            "already_present": False,
            "status": "HUMAN_REVIEW_REQUIRED",
            "proposal_persisted": True,
            "lease_issued": False,
            "execution_authorized": False,
        }

    def verify(self) -> dict:
        """Verify the original task ledger and the complete lease-proposal audit chain."""
        base = super().verify()
        task_rows = self._connection.execute(
            "SELECT task_id, task_json FROM tasks"
        ).fetchall()
        tasks = {row["task_id"]: json.loads(row["task_json"]) for row in task_rows}

        lease_rows = self._connection.execute(
            """SELECT lease_id, task_id, proposal_digest, logical_owner_id,
                      attempt, lease_json, status, created_at
               FROM lease_proposals ORDER BY lease_id"""
        ).fetchall()
        if len(lease_rows) > MAX_LEASE_PROPOSALS:
            raise LedgerCorruptionError("LEASE_PROPOSAL_CAPACITY_INVARIANT_FAILED")

        lease_map = {}
        for row in lease_rows:
            task = tasks.get(row["task_id"])
            if task is None:
                raise LedgerCorruptionError("LEASE_TASK_REFERENCE_INVALID")
            try:
                lease = json.loads(row["lease_json"])
                issued_text = lease.get("issued_at") if isinstance(lease, dict) else None
                if not isinstance(issued_text, str):
                    raise ValueError("timestamp")
                issued_at = datetime.fromisoformat(issued_text.replace("Z", "+00:00"))
                validated = validate_lease(task, lease, issued_at)
            except (KeyError, TypeError, ValueError, AttributeError, ContractError):
                raise LedgerCorruptionError("STORED_LEASE_CONTRACT_INVALID") from None
            if (
                _canonical_json(lease) != row["lease_json"]
                or validated["lease_status"] != "ACTIVE"
                or validated["lease_id"] != row["lease_id"]
                or validated["task_id"] != row["task_id"]
                or validated["proposal_digest"] != row["proposal_digest"]
                or validated["logical_owner_id"] != row["logical_owner_id"]
                or validated["attempt"] != row["attempt"]
                or row["status"] != "PROPOSED"
                or row["attempt"] != 1
                or not _valid_timestamp(row["created_at"])
            ):
                raise LedgerCorruptionError("STORED_LEASE_INVARIANT_FAILED")
            lease_map[row["lease_id"]] = row

        events = self._connection.execute(
            """SELECT sequence, lease_id, task_id, event, logical_owner_id,
                      occurred_at, previous_hash, record_hash
               FROM lease_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(lease_rows):
            raise LedgerCorruptionError("LEASE_AUDIT_EVENT_COUNT_MISMATCH")

        previous_hash = None
        seen_leases = set()
        for expected_sequence, row in enumerate(events, start=1):
            proposal = lease_map.get(row["lease_id"])
            if (
                row["sequence"] != expected_sequence
                or proposal is None
                or row["lease_id"] in seen_leases
                or row["task_id"] != proposal["task_id"]
                or row["event"] != "LEASE_PROPOSED"
                or row["logical_owner_id"] != proposal["logical_owner_id"]
                or row["previous_hash"] != previous_hash
                or not _valid_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError("LEASE_AUDIT_CHAIN_STRUCTURE_INVALID")
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "lease_id": row["lease_id"],
                "task_id": row["task_id"],
                "event": row["event"],
                "logical_owner_id": row["logical_owner_id"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError("LEASE_AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen_leases.add(row["lease_id"])

        return {
            **base,
            "lease_proposal_count": len(lease_rows),
            "lease_audit_event_count": len(events),
            "lease_audit_chain": "VALID",
        }

    def recover_after_restart(self) -> dict:
        """Verify persisted proposals after reopen; never issue or resume a lease."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "pending_human_review": verified["task_count"],
            "audit_event_count": verified["audit_event_count"],
            "lease_proposals_recovered": verified["lease_proposal_count"],
            "pending_lease_review": verified["lease_proposal_count"],
            "budget_proposals_recovered": verified["budget_count"],
            "pending_budget_review": verified["budget_count"],
            "budget_audit_event_count": verified["budget_audit_event_count"],
            "budget_enforcement_status": "NOT_ENFORCED",
            "lease_execution_resumed": False,
            "lease_issued": False,
            "automatic_retry": False,
        }
