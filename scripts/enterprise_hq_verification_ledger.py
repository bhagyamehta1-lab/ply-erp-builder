"""Persistent storage for untrusted Enterprise-HQ verification receipt claims.

Receipts are structurally validated and durably recorded, but remain unauthenticated
claims. This module does not inspect evidence, authenticate principals, certify
independent verification, or authorize execution.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from scripts.enterprise_hq_lease_ledger import LeaseProposalLedger
from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
    _canonical_json,
    _utc_now,
    _validate_timestamp,
)
from scripts.enterprise_hq_verification_receipt import validate_verification_receipt

MAX_VERIFICATION_RECEIPTS = 256


class VerificationReceiptLedger(LeaseProposalLedger):
    """Unified local ledger for task, budget, lease and untrusted receipt records."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS verification_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status = 'UNAUTHENTICATED_CLAIM'),
                    created_at TEXT NOT NULL
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS verification_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE
                        REFERENCES verification_receipts(receipt_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    receipt_digest TEXT NOT NULL,
                    event TEXT NOT NULL CHECK (event = 'RECEIPT_RECORDED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                )"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS verification_audit_events_task_id_idx "
                "ON verification_audit_events(task_id)"
            )
        except Exception:
            self.close()
            raise

    def _append_receipt_event(
        self, receipt_id: str, task_id: str, receipt_digest: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM verification_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "receipt_id": receipt_id,
            "task_id": task_id,
            "receipt_digest": receipt_digest,
            "event": "RECEIPT_RECORDED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO verification_audit_events
               (sequence, receipt_id, task_id, receipt_digest, event,
                occurred_at, previous_hash, record_hash)
               VALUES (?, ?, ?, ?, 'RECEIPT_RECORDED', ?, ?, ?)""",
            (
                sequence,
                receipt_id,
                task_id,
                receipt_digest,
                occurred_at,
                previous_hash,
                record_hash,
            ),
        )

    @staticmethod
    def _result(
        validated: Mapping, *, created: bool, already_present: bool
    ) -> dict:
        return {
            "receipt_id": validated["receipt_id"],
            "task_id": validated["task_id"],
            "created": created,
            "already_present": already_present,
            "status": "UNAUTHENTICATED_CLAIM",
            "receipt_status": "STRUCTURE_VALID_ONLY",
            "identity_assurance": "NOT_AUTHENTICATED",
            "evidence_status": "DIGEST_FORMAT_ONLY",
            "semantic_verification": "NOT_PERFORMED",
            "independent_verification_status": "NOT_ESTABLISHED",
            "execution_authorized": False,
        }

    def record_untrusted_receipt(self, task: Mapping, receipt: Mapping) -> dict:
        """Persist a structurally valid receipt claim for later human review only."""
        validated_task = validate_task(task)
        validated_receipt = validate_verification_receipt(task, receipt)
        canonical_task = _canonical_json(dict(task))
        canonical_receipt = _canonical_json(dict(receipt))
        receipt_digest = hashlib.sha256(
            canonical_receipt.encode("utf-8")
        ).hexdigest()
        receipt_id = validated_receipt["receipt_id"]
        task_id = validated_task["task_id"]
        proposal_digest = validated_task["idempotency_key"]

        with self._transaction():
            # Verify every existing task, budget, lease and receipt chain before append.
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
                raise LedgerError("VERIFICATION_TASK_NOT_PERSISTED")

            existing = self._connection.execute(
                "SELECT receipt_json FROM verification_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if existing is not None:
                if existing["receipt_json"] != canonical_receipt:
                    raise TaskConflictError("VERIFICATION_RECEIPT_ID_CONTENT_CONFLICT")
                return self._result(
                    validated_receipt, created=False, already_present=True
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM verification_receipts"
            ).fetchone()[0]
            if count >= MAX_VERIFICATION_RECEIPTS:
                raise LedgerError("VERIFICATION_RECEIPT_CAPACITY_REACHED")

            self._connection.execute(
                """INSERT INTO verification_receipts
                   (receipt_id, task_id, proposal_digest, receipt_json, status, created_at)
                   VALUES (?, ?, ?, ?, 'UNAUTHENTICATED_CLAIM', ?)""",
                (
                    receipt_id,
                    task_id,
                    proposal_digest,
                    canonical_receipt,
                    _utc_now(),
                ),
            )
            self._append_receipt_event(receipt_id, task_id, receipt_digest)

        return self._result(validated_receipt, created=True, already_present=False)

    def verify(self) -> dict:
        """Verify all inherited chains plus the complete untrusted-receipt chain."""
        base = super().verify()
        task_rows = self._connection.execute(
            "SELECT task_id, task_json FROM tasks"
        ).fetchall()
        tasks = {row["task_id"]: json.loads(row["task_json"]) for row in task_rows}

        receipt_rows = self._connection.execute(
            """SELECT receipt_id, task_id, proposal_digest, receipt_json, status, created_at
               FROM verification_receipts ORDER BY receipt_id"""
        ).fetchall()
        if len(receipt_rows) > MAX_VERIFICATION_RECEIPTS:
            raise LedgerCorruptionError("VERIFICATION_RECEIPT_CAPACITY_INVARIANT_FAILED")

        receipt_map = {}
        for row in receipt_rows:
            task = tasks.get(row["task_id"])
            if task is None:
                raise LedgerCorruptionError("VERIFICATION_TASK_REFERENCE_INVALID")
            try:
                receipt = json.loads(row["receipt_json"])
                validated = validate_verification_receipt(task, receipt)
            except (ValueError, TypeError, ContractError):
                raise LedgerCorruptionError(
                    "STORED_VERIFICATION_RECEIPT_INVALID"
                ) from None
            if (
                _canonical_json(receipt) != row["receipt_json"]
                or validated["receipt_id"] != row["receipt_id"]
                or validated["task_id"] != row["task_id"]
                or validated["proposal_digest"] != row["proposal_digest"]
                or row["status"] != "UNAUTHENTICATED_CLAIM"
                or not _validate_timestamp(row["created_at"])
            ):
                raise LedgerCorruptionError(
                    "STORED_VERIFICATION_RECEIPT_INVARIANT_FAILED"
                )
            receipt_map[row["receipt_id"]] = {
                "task_id": row["task_id"],
                "receipt_digest": hashlib.sha256(
                    row["receipt_json"].encode("utf-8")
                ).hexdigest(),
            }

        events = self._connection.execute(
            """SELECT sequence, receipt_id, task_id, receipt_digest, event,
                      occurred_at, previous_hash, record_hash
               FROM verification_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(receipt_rows):
            raise LedgerCorruptionError("VERIFICATION_AUDIT_EVENT_COUNT_MISMATCH")

        previous_hash = None
        seen_receipts = set()
        for expected_sequence, row in enumerate(events, start=1):
            proposal = receipt_map.get(row["receipt_id"])
            if (
                row["sequence"] != expected_sequence
                or proposal is None
                or row["receipt_id"] in seen_receipts
                or row["task_id"] != proposal["task_id"]
                or row["receipt_digest"] != proposal["receipt_digest"]
                or row["event"] != "RECEIPT_RECORDED"
                or row["previous_hash"] != previous_hash
                or not _validate_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError(
                    "VERIFICATION_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "receipt_id": row["receipt_id"],
                "task_id": row["task_id"],
                "receipt_digest": row["receipt_digest"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError("VERIFICATION_AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen_receipts.add(row["receipt_id"])

        return {
            **base,
            "verification_receipt_count": len(receipt_rows),
            "verification_audit_event_count": len(events),
            "verification_audit_chain": "VALID",
            "independent_verification_status": "NOT_ESTABLISHED",
        }

    def recover_after_restart(self) -> dict:
        """Verify all persisted records after reopen; never resume or authorize work."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "budget_proposals_recovered": verified["budget_count"],
            "lease_proposals_recovered": verified["lease_proposal_count"],
            "untrusted_receipts_recovered": verified["verification_receipt_count"],
            "untrusted_receipts_pending_review": verified["verification_receipt_count"],
            "budget_enforcement_status": "NOT_ENFORCED",
            "independent_verification_status": "NOT_ESTABLISHED",
            "execution_resumed": False,
            "lease_issued": False,
            "automatic_retry": False,
        }
