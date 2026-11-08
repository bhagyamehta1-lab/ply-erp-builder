"""Persistent, metadata-only ledger for verified company evidence integrity.

This ledger re-runs bounded evidence verification before persistence, binds the
result to an already-persisted task and untrusted receipt, and stores no payload
bytes or paths. Content integrity is not semantic verification or authorization.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from scripts.enterprise_hq_evidence_verifier import (
    EvidenceVerificationError,
    MAX_EVIDENCE_ITEMS,
    MAX_TOTAL_EVIDENCE_BYTES,
    verify_evidence_bundle,
)
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
from scripts.enterprise_hq_verification_receipt import validate_verification_receipt

MAX_EVIDENCE_VERIFICATION_RECEIPTS = 256


class EvidenceVerificationLedger(VerificationReceiptLedger):
    """Unified local ledger for metadata-only evidence-integrity outcomes."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_verifications (
                    receipt_id TEXT PRIMARY KEY
                        REFERENCES verification_receipts(receipt_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL
                        CHECK (evidence_count BETWEEN 1 AND 16),
                    total_bytes INTEGER NOT NULL
                        CHECK (total_bytes BETWEEN 1 AND 1048576),
                    status TEXT NOT NULL
                        CHECK (status = 'CONTENT_INTEGRITY_VERIFIED'),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_verification_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE
                        REFERENCES evidence_verifications(receipt_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
                    manifest_digest TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL,
                    total_bytes INTEGER NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'EVIDENCE_CONTENT_VERIFIED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS evidence_verifications_task_id_idx
                    ON evidence_verifications(task_id);
                """
            )
        except Exception:
            self.close()
            raise

    def _append_evidence_event(
        self,
        *,
        receipt_id: str,
        task_id: str,
        proposal_digest: str,
        receipt_digest: str,
        manifest_digest: str,
        evidence_count: int,
        total_bytes: int,
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM evidence_verification_audit_events "
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
            "proposal_digest": proposal_digest,
            "receipt_digest": receipt_digest,
            "manifest_digest": manifest_digest,
            "evidence_count": evidence_count,
            "total_bytes": total_bytes,
            "event": "EVIDENCE_CONTENT_VERIFIED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO evidence_verification_audit_events
               (sequence, receipt_id, task_id, proposal_digest, receipt_digest,
                manifest_digest, evidence_count, total_bytes, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'EVIDENCE_CONTENT_VERIFIED', ?, ?, ?)""",
            (
                sequence,
                receipt_id,
                task_id,
                proposal_digest,
                receipt_digest,
                manifest_digest,
                evidence_count,
                total_bytes,
                occurred_at,
                previous_hash,
                record_hash,
            ),
        )

    @staticmethod
    def _result(
        *,
        task_id: str,
        receipt_id: str,
        manifest_digest: str,
        evidence_count: int,
        total_bytes: int,
        created: bool,
        already_present: bool,
    ) -> dict:
        return {
            "task_id": task_id,
            "receipt_id": receipt_id,
            "manifest_digest": manifest_digest,
            "evidence_count": evidence_count,
            "total_bytes": total_bytes,
            "created": created,
            "already_present": already_present,
            "status": "CONTENT_INTEGRITY_VERIFIED",
            "payload_retention": "NONE",
            "semantic_verification": "NOT_PERFORMED",
            "identity_authenticated": False,
            "reviewer_independence": "NOT_ESTABLISHED",
            "execution_authorized": False,
        }

    def record_verified_evidence(
        self,
        task: Mapping,
        receipt: Mapping,
        manifest: Mapping,
        payloads: Mapping[str, bytes],
    ) -> dict:
        """Verify supplied bytes and persist only receipt/manifest integrity metadata.

        The task and receipt must already exist in this same ledger. Evidence is
        re-verified in memory on every call. No path, payload, or raw manifest is
        persisted. The receipt's evidence_digest must equal the canonical manifest
        digest returned by the bounded verifier.
        """
        validated_task = validate_task(task)
        validated_receipt = validate_verification_receipt(task, receipt)
        verification = verify_evidence_bundle(
            manifest,
            payloads,
            expected_task_id=validated_task["task_id"],
            expected_proposal_digest=validated_task["idempotency_key"],
            expected_receipt_id=validated_receipt["receipt_id"],
        )
        manifest_digest = verification["manifest_digest"]
        if receipt.get("evidence_digest") != manifest_digest:
            raise EvidenceVerificationError(
                "EVIDENCE_RECEIPT_MANIFEST_DIGEST_MISMATCH"
            )

        task_id = validated_task["task_id"]
        receipt_id = validated_receipt["receipt_id"]
        proposal_digest = validated_task["idempotency_key"]
        canonical_task = _canonical_json(dict(task))
        canonical_receipt = _canonical_json(dict(receipt))
        receipt_digest = hashlib.sha256(
            canonical_receipt.encode("utf-8")
        ).hexdigest()
        evidence_count = verification["evidence_count"]
        total_bytes = verification["total_bytes"]

        with self._transaction():
            # Refuse all appends if any inherited or evidence audit chain is corrupt.
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
                raise LedgerError("EVIDENCE_TASK_NOT_PERSISTED")

            receipt_row = self._connection.execute(
                """SELECT task_id, proposal_digest, receipt_json, status
                   FROM verification_receipts WHERE receipt_id = ?""",
                (receipt_id,),
            ).fetchone()
            if (
                receipt_row is None
                or receipt_row["task_id"] != task_id
                or receipt_row["proposal_digest"] != proposal_digest
                or receipt_row["receipt_json"] != canonical_receipt
                or receipt_row["status"] != "UNAUTHENTICATED_CLAIM"
            ):
                raise LedgerError("EVIDENCE_RECEIPT_NOT_PERSISTED")

            existing = self._connection.execute(
                """SELECT task_id, proposal_digest, receipt_digest, manifest_digest,
                          evidence_count, total_bytes, status
                   FROM evidence_verifications WHERE receipt_id = ?""",
                (receipt_id,),
            ).fetchone()
            if existing is not None:
                expected = (
                    task_id,
                    proposal_digest,
                    receipt_digest,
                    manifest_digest,
                    evidence_count,
                    total_bytes,
                    "CONTENT_INTEGRITY_VERIFIED",
                )
                actual = tuple(existing[key] for key in (
                    "task_id", "proposal_digest", "receipt_digest", "manifest_digest",
                    "evidence_count", "total_bytes", "status",
                ))
                if actual != expected:
                    raise TaskConflictError(
                        "EVIDENCE_VERIFICATION_RECEIPT_CONTENT_CONFLICT"
                    )
                return self._result(
                    task_id=task_id,
                    receipt_id=receipt_id,
                    manifest_digest=manifest_digest,
                    evidence_count=evidence_count,
                    total_bytes=total_bytes,
                    created=False,
                    already_present=True,
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM evidence_verifications"
            ).fetchone()[0]
            if count >= MAX_EVIDENCE_VERIFICATION_RECEIPTS:
                raise LedgerError("EVIDENCE_VERIFICATION_CAPACITY_REACHED")

            self._connection.execute(
                """INSERT INTO evidence_verifications
                   (receipt_id, task_id, proposal_digest, receipt_digest,
                    manifest_digest, evidence_count, total_bytes, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'CONTENT_INTEGRITY_VERIFIED', ?)""",
                (
                    receipt_id,
                    task_id,
                    proposal_digest,
                    receipt_digest,
                    manifest_digest,
                    evidence_count,
                    total_bytes,
                    _utc_now(),
                ),
            )
            self._append_evidence_event(
                receipt_id=receipt_id,
                task_id=task_id,
                proposal_digest=proposal_digest,
                receipt_digest=receipt_digest,
                manifest_digest=manifest_digest,
                evidence_count=evidence_count,
                total_bytes=total_bytes,
            )

        return self._result(
            task_id=task_id,
            receipt_id=receipt_id,
            manifest_digest=manifest_digest,
            evidence_count=evidence_count,
            total_bytes=total_bytes,
            created=True,
            already_present=False,
        )

    def verify(self) -> dict:
        """Verify inherited ledgers and the complete metadata-only evidence chain."""
        base = super().verify()
        tasks = {
            row["task_id"]: json.loads(row["task_json"])
            for row in self._connection.execute(
                "SELECT task_id, task_json FROM tasks"
            ).fetchall()
        }
        receipts = {
            row["receipt_id"]: row
            for row in self._connection.execute(
                """SELECT receipt_id, task_id, proposal_digest, receipt_json, status
                   FROM verification_receipts"""
            ).fetchall()
        }
        rows = self._connection.execute(
            """SELECT receipt_id, task_id, proposal_digest, receipt_digest,
                      manifest_digest, evidence_count, total_bytes, status, created_at
               FROM evidence_verifications ORDER BY receipt_id"""
        ).fetchall()
        if len(rows) > MAX_EVIDENCE_VERIFICATION_RECEIPTS:
            raise LedgerCorruptionError(
                "EVIDENCE_VERIFICATION_CAPACITY_INVARIANT_FAILED"
            )

        evidence_map = {}
        for row in rows:
            task = tasks.get(row["task_id"])
            receipt_row = receipts.get(row["receipt_id"])
            if task is None or receipt_row is None:
                raise LedgerCorruptionError(
                    "EVIDENCE_VERIFICATION_REFERENCE_INVALID"
                )
            try:
                receipt = json.loads(receipt_row["receipt_json"])
                validated_task = validate_task(task)
                validated_receipt = validate_verification_receipt(task, receipt)
            except (ValueError, TypeError, ContractError):
                raise LedgerCorruptionError(
                    "STORED_EVIDENCE_VERIFICATION_BINDING_INVALID"
                ) from None
            expected_receipt_digest = hashlib.sha256(
                receipt_row["receipt_json"].encode("utf-8")
            ).hexdigest()
            if (
                _canonical_json(receipt) != receipt_row["receipt_json"]
                or validated_receipt["receipt_id"] != row["receipt_id"]
                or validated_receipt["task_id"] != row["task_id"]
                or validated_task["idempotency_key"] != row["proposal_digest"]
                or receipt_row["task_id"] != row["task_id"]
                or receipt_row["proposal_digest"] != row["proposal_digest"]
                or receipt_row["status"] != "UNAUTHENTICATED_CLAIM"
                or receipt.get("evidence_digest") != row["manifest_digest"]
                or row["receipt_digest"] != expected_receipt_digest
                or type(row["evidence_count"]) is not int
                or not 1 <= row["evidence_count"] <= MAX_EVIDENCE_ITEMS
                or type(row["total_bytes"]) is not int
                or not 1 <= row["total_bytes"] <= MAX_TOTAL_EVIDENCE_BYTES
                or row["status"] != "CONTENT_INTEGRITY_VERIFIED"
                or not _validate_timestamp(row["created_at"])
            ):
                raise LedgerCorruptionError(
                    "STORED_EVIDENCE_VERIFICATION_INVARIANT_FAILED"
                )
            evidence_map[row["receipt_id"]] = {
                "task_id": row["task_id"],
                "proposal_digest": row["proposal_digest"],
                "receipt_digest": row["receipt_digest"],
                "manifest_digest": row["manifest_digest"],
                "evidence_count": row["evidence_count"],
                "total_bytes": row["total_bytes"],
            }

        events = self._connection.execute(
            """SELECT sequence, receipt_id, task_id, proposal_digest, receipt_digest,
                      manifest_digest, evidence_count, total_bytes, event, occurred_at,
                      previous_hash, record_hash
               FROM evidence_verification_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(rows):
            raise LedgerCorruptionError(
                "EVIDENCE_VERIFICATION_AUDIT_EVENT_COUNT_MISMATCH"
            )

        previous_hash = None
        seen_receipts = set()
        for expected_sequence, row in enumerate(events, start=1):
            evidence = evidence_map.get(row["receipt_id"])
            if (
                row["sequence"] != expected_sequence
                or evidence is None
                or row["receipt_id"] in seen_receipts
                or row["task_id"] != evidence["task_id"]
                or row["proposal_digest"] != evidence["proposal_digest"]
                or row["receipt_digest"] != evidence["receipt_digest"]
                or row["manifest_digest"] != evidence["manifest_digest"]
                or row["evidence_count"] != evidence["evidence_count"]
                or row["total_bytes"] != evidence["total_bytes"]
                or row["event"] != "EVIDENCE_CONTENT_VERIFIED"
                or row["previous_hash"] != previous_hash
                or not _validate_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError(
                    "EVIDENCE_VERIFICATION_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "receipt_id": row["receipt_id"],
                "task_id": row["task_id"],
                "proposal_digest": row["proposal_digest"],
                "receipt_digest": row["receipt_digest"],
                "manifest_digest": row["manifest_digest"],
                "evidence_count": row["evidence_count"],
                "total_bytes": row["total_bytes"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError(
                    "EVIDENCE_VERIFICATION_AUDIT_CHAIN_HASH_INVALID"
                )
            previous_hash = expected_hash
            seen_receipts.add(row["receipt_id"])

        return {
            **base,
            "evidence_verification_count": len(rows),
            "evidence_verification_audit_event_count": len(events),
            "evidence_verification_audit_chain": "VALID",
            "evidence_payload_retention": "NONE",
            "evidence_semantic_verification": "NOT_PERFORMED",
        }

    def recover_after_restart(self) -> dict:
        """Verify persisted evidence metadata after reopen; never resume execution."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "verification_receipts_recovered": verified["verification_receipt_count"],
            "verified_evidence_receipts_recovered": verified[
                "evidence_verification_count"
            ],
            "evidence_audit_events_recovered": verified[
                "evidence_verification_audit_event_count"
            ],
            "evidence_pending_semantic_review": verified[
                "evidence_verification_count"
            ],
            "semantic_verification": "NOT_PERFORMED",
            "execution_resumed": False,
            "automatic_retry": False,
        }
