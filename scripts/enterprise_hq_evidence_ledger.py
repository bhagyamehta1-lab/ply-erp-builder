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
from scripts.enterprise_hq_principal_replay_ledger import PrincipalReplayLedger
from scripts.enterprise_hq_verification_receipt import validate_verification_receipt

MAX_EVIDENCE_VERIFICATION_RECEIPTS = 256


class EvidenceVerificationLedger(PrincipalReplayLedger):
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
                CREATE TABLE IF NOT EXISTS evidence_reviewer_bindings (
                    receipt_id TEXT PRIMARY KEY
                        REFERENCES evidence_verifications(receipt_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    nonce_fingerprint TEXT NOT NULL UNIQUE
                        REFERENCES principal_nonce_uses(nonce_fingerprint),
                    issuer TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    attestation_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evidence_reviewer_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE
                        REFERENCES evidence_reviewer_bindings(receipt_id),
                    nonce_fingerprint TEXT NOT NULL UNIQUE
                        REFERENCES principal_nonce_uses(nonce_fingerprint),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    attestation_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'EVIDENCE_REVIEWER_BOUND'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS evidence_verifications_task_id_idx
                    ON evidence_verifications(task_id);
                CREATE INDEX IF NOT EXISTS evidence_reviewer_bindings_task_id_idx
                    ON evidence_reviewer_bindings(task_id);
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

    def _append_reviewer_event(
        self,
        *,
        receipt_id: str,
        nonce_fingerprint: str,
        task_id: str,
        proposal_digest: str,
        issuer: str,
        principal_id: str,
        attestation_digest: str,
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM evidence_reviewer_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "receipt_id": receipt_id,
            "nonce_fingerprint": nonce_fingerprint,
            "task_id": task_id,
            "proposal_digest": proposal_digest,
            "issuer": issuer,
            "principal_id": principal_id,
            "attestation_digest": attestation_digest,
            "event": "EVIDENCE_REVIEWER_BOUND",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO evidence_reviewer_audit_events
               (sequence, receipt_id, nonce_fingerprint, task_id, proposal_digest,
                issuer, principal_id, attestation_digest, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'EVIDENCE_REVIEWER_BOUND', ?, ?, ?)""",
            (
                sequence, receipt_id, nonce_fingerprint, task_id, proposal_digest,
                issuer, principal_id, attestation_digest, occurred_at,
                previous_hash, record_hash,
            ),
        )

    @staticmethod
    def _evidence_result(
        *,
        task_id: str,
        receipt_id: str,
        manifest_digest: str,
        evidence_count: int,
        total_bytes: int,
        reviewer_attestation_digest: str,
        created: bool,
        already_present: bool,
    ) -> dict:
        return {
            "task_id": task_id,
            "receipt_id": receipt_id,
            "manifest_digest": manifest_digest,
            "evidence_count": evidence_count,
            "total_bytes": total_bytes,
            "reviewer_attestation_digest": reviewer_attestation_digest,
            "reviewer_binding_status": "REVIEWER_ATTESTATION_CLAIM_BOUND",
            "reviewer_identity_assurance": "EXTERNAL_ADAPTER_ASSERTED",
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
        """Verify evidence and bind its metadata to a previously accepted reviewer claim.

        The task, receipt, and reviewer principal nonce claim must already exist in
        this same ledger. Evidence is re-verified in memory on every call. No path,
        payload, raw manifest, signature, or raw attestation is persisted.
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

            reviewer_rows = self._connection.execute(
                """SELECT nonce_fingerprint, issuer, principal_id, attestation_digest
                   FROM principal_nonce_uses
                   WHERE task_id = ? AND proposal_digest = ?
                     AND principal_type = 'REVIEWER' AND binding_id = ?""",
                (task_id, proposal_digest, receipt_id),
            ).fetchall()
            if len(reviewer_rows) != 1:
                raise LedgerError("EVIDENCE_REVIEWER_IDENTITY_NOT_VERIFIED")
            reviewer = reviewer_rows[0]
            if reviewer["principal_id"] != receipt.get("logical_verifier_id"):
                raise LedgerError("EVIDENCE_REVIEWER_IDENTITY_RECEIPT_MISMATCH")

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
                binding = self._connection.execute(
                    """SELECT task_id, proposal_digest, nonce_fingerprint, issuer,
                              principal_id, attestation_digest
                       FROM evidence_reviewer_bindings WHERE receipt_id = ?""",
                    (receipt_id,),
                ).fetchone()
                expected_binding = (
                    task_id, proposal_digest, reviewer["nonce_fingerprint"],
                    reviewer["issuer"], reviewer["principal_id"],
                    reviewer["attestation_digest"],
                )
                actual_binding = None if binding is None else tuple(
                    binding[key] for key in (
                        "task_id", "proposal_digest", "nonce_fingerprint", "issuer",
                        "principal_id", "attestation_digest",
                    )
                )
                if actual != expected or actual_binding != expected_binding:
                    raise TaskConflictError(
                        "EVIDENCE_VERIFICATION_RECEIPT_CONTENT_CONFLICT"
                    )
                return self._evidence_result(
                    task_id=task_id,
                    receipt_id=receipt_id,
                    manifest_digest=manifest_digest,
                    evidence_count=evidence_count,
                    total_bytes=total_bytes,
                    reviewer_attestation_digest=reviewer["attestation_digest"],
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
            self._connection.execute(
                """INSERT INTO evidence_reviewer_bindings
                   (receipt_id, task_id, proposal_digest, nonce_fingerprint,
                    issuer, principal_id, attestation_digest, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt_id, task_id, proposal_digest,
                    reviewer["nonce_fingerprint"], reviewer["issuer"],
                    reviewer["principal_id"], reviewer["attestation_digest"],
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
            self._append_reviewer_event(
                receipt_id=receipt_id,
                nonce_fingerprint=reviewer["nonce_fingerprint"],
                task_id=task_id,
                proposal_digest=proposal_digest,
                issuer=reviewer["issuer"],
                principal_id=reviewer["principal_id"],
                attestation_digest=reviewer["attestation_digest"],
            )

        return self._evidence_result(
            task_id=task_id,
            receipt_id=receipt_id,
            manifest_digest=manifest_digest,
            evidence_count=evidence_count,
            total_bytes=total_bytes,
            reviewer_attestation_digest=reviewer["attestation_digest"],
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
        nonce_uses = {
            row["nonce_fingerprint"]: row
            for row in self._connection.execute(
                """SELECT nonce_fingerprint, task_id, proposal_digest, issuer,
                          principal_id, principal_type, binding_id, attestation_digest
                   FROM principal_nonce_uses"""
            ).fetchall()
        }
        reviewer_bindings = {
            row["receipt_id"]: row
            for row in self._connection.execute(
                """SELECT receipt_id, task_id, proposal_digest, nonce_fingerprint,
                          issuer, principal_id, attestation_digest, created_at
                   FROM evidence_reviewer_bindings"""
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

        if len(reviewer_bindings) != len(rows):
            raise LedgerCorruptionError(
                "EVIDENCE_REVIEWER_BINDING_COUNT_MISMATCH"
            )

        evidence_map = {}
        for row in rows:
            task = tasks.get(row["task_id"])
            receipt_row = receipts.get(row["receipt_id"])
            binding = reviewer_bindings.get(row["receipt_id"])
            if task is None or receipt_row is None or binding is None:
                raise LedgerCorruptionError(
                    "EVIDENCE_VERIFICATION_REFERENCE_INVALID"
                )
            nonce = nonce_uses.get(binding["nonce_fingerprint"])
            if (
                nonce is None
                or nonce["task_id"] != row["task_id"]
                or nonce["proposal_digest"] != row["proposal_digest"]
                or nonce["principal_type"] != "REVIEWER"
                or nonce["binding_id"] != row["receipt_id"]
                or nonce["issuer"] != binding["issuer"]
                or nonce["principal_id"] != binding["principal_id"]
                or nonce["attestation_digest"] != binding["attestation_digest"]
                or binding["task_id"] != row["task_id"]
                or binding["proposal_digest"] != row["proposal_digest"]
                or not _validate_timestamp(binding["created_at"])
            ):
                raise LedgerCorruptionError(
                    "EVIDENCE_REVIEWER_BINDING_INVARIANT_FAILED"
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
                or receipt.get("logical_verifier_id") != binding["principal_id"]
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
                "reviewer_nonce_fingerprint": binding["nonce_fingerprint"],
                "reviewer_issuer": binding["issuer"],
                "reviewer_principal_id": binding["principal_id"],
                "reviewer_attestation_digest": binding["attestation_digest"],
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

        reviewer_events = self._connection.execute(
            """SELECT sequence, receipt_id, nonce_fingerprint, task_id,
                      proposal_digest, issuer, principal_id, attestation_digest,
                      event, occurred_at, previous_hash, record_hash
               FROM evidence_reviewer_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(reviewer_events) != len(reviewer_bindings):
            raise LedgerCorruptionError(
                "EVIDENCE_REVIEWER_AUDIT_EVENT_COUNT_MISMATCH"
            )
        reviewer_previous_hash = None
        seen_reviewer_receipts = set()
        for expected_sequence, row in enumerate(reviewer_events, start=1):
            evidence = evidence_map.get(row["receipt_id"])
            if (
                row["sequence"] != expected_sequence
                or evidence is None
                or row["receipt_id"] in seen_reviewer_receipts
                or row["nonce_fingerprint"] != evidence["reviewer_nonce_fingerprint"]
                or row["task_id"] != evidence["task_id"]
                or row["proposal_digest"] != evidence["proposal_digest"]
                or row["issuer"] != evidence["reviewer_issuer"]
                or row["principal_id"] != evidence["reviewer_principal_id"]
                or row["attestation_digest"] != evidence["reviewer_attestation_digest"]
                or row["event"] != "EVIDENCE_REVIEWER_BOUND"
                or row["previous_hash"] != reviewer_previous_hash
                or not _validate_timestamp(row["occurred_at"])
            ):
                raise LedgerCorruptionError(
                    "EVIDENCE_REVIEWER_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "receipt_id": row["receipt_id"],
                "nonce_fingerprint": row["nonce_fingerprint"],
                "task_id": row["task_id"],
                "proposal_digest": row["proposal_digest"],
                "issuer": row["issuer"],
                "principal_id": row["principal_id"],
                "attestation_digest": row["attestation_digest"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(body).encode("utf-8")
            ).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError(
                    "EVIDENCE_REVIEWER_AUDIT_CHAIN_HASH_INVALID"
                )
            reviewer_previous_hash = expected_hash
            seen_reviewer_receipts.add(row["receipt_id"])

        return {
            **base,
            "evidence_verification_count": len(rows),
            "evidence_verification_audit_event_count": len(events),
            "evidence_verification_audit_chain": "VALID",
            "evidence_reviewer_binding_count": len(reviewer_bindings),
            "evidence_reviewer_audit_event_count": len(reviewer_events),
            "evidence_reviewer_audit_chain": "VALID",
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
            "evidence_reviewer_bindings_recovered": verified[
                "evidence_reviewer_binding_count"
            ],
            "evidence_reviewer_audit_events_recovered": verified[
                "evidence_reviewer_audit_event_count"
            ],
            "reviewer_identity_assurance": "EXTERNAL_ADAPTER_ASSERTED",
            "reviewer_independence": "NOT_ESTABLISHED",
            "identity_authenticated": False,
            "evidence_pending_semantic_review": verified[
                "evidence_verification_count"
            ],
            "semantic_verification": "NOT_PERFORMED",
            "execution_resumed": False,
            "automatic_retry": False,
        }
