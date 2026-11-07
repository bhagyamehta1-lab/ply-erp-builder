"""Persistent one-time nonce replay protection for company principal attestations.

The ledger stores only nonce fingerprints and attestation digests, never raw nonces,
signatures, or full attestation payloads. It consumes a nonce only after the injected
principal verifier accepts the task-bound assertion. It never authorizes execution.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime

from scripts.enterprise_hq_principal_contract import (
    PrincipalContractError,
    validate_principal_attestation,
)
from scripts.enterprise_hq_recovery_ledger import SuccessorLeaseRecoveryLedger
from scripts.enterprise_hq_task_contract import validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    _canonical_json,
    _utc_now,
    _validate_timestamp,
)

MAX_PRINCIPAL_NONCE_USES = 1024
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_PRINCIPAL_ID = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,63}$")
_PRINCIPAL_TYPES = frozenset({"WORKER", "REVIEWER"})


class PrincipalReplayError(LedgerError):
    """A principal nonce or task binding has already been consumed."""


class PrincipalReplayCorruptionError(LedgerCorruptionError):
    """Persisted principal replay state failed integrity verification."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _nonce_fingerprint(attestation: Mapping) -> str:
    identity = {
        "issuer": attestation["issuer"],
        "principal_id": attestation["principal_id"],
        "nonce": attestation["nonce"],
    }
    return _digest(_canonical_json(identity))


def _attestation_digest(attestation: Mapping) -> str:
    return _digest(_canonical_json(dict(attestation)))


class PrincipalReplayLedger(SuccessorLeaseRecoveryLedger):
    """Unified proposal ledger with durable, one-time principal nonce consumption."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS principal_nonce_uses (
                    nonce_fingerprint TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    principal_type TEXT NOT NULL
                        CHECK (principal_type IN ('WORKER', 'REVIEWER')),
                    binding_id TEXT NOT NULL,
                    attestation_digest TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (principal_type, binding_id)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS principal_nonce_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    nonce_fingerprint TEXT NOT NULL UNIQUE
                        REFERENCES principal_nonce_uses(nonce_fingerprint),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    proposal_digest TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    principal_type TEXT NOT NULL
                        CHECK (principal_type IN ('WORKER', 'REVIEWER')),
                    binding_id TEXT NOT NULL,
                    attestation_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'PRINCIPAL_NONCE_CONSUMED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                )"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS principal_nonce_uses_task_id_idx "
                "ON principal_nonce_uses(task_id)"
            )
        except Exception:
            self.close()
            raise

    def _append_nonce_event(
        self,
        *,
        nonce_fingerprint: str,
        task_id: str,
        proposal_digest: str,
        issuer: str,
        principal_id: str,
        principal_type: str,
        binding_id: str,
        attestation_digest: str,
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM principal_nonce_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "nonce_fingerprint": nonce_fingerprint,
            "task_id": task_id,
            "proposal_digest": proposal_digest,
            "issuer": issuer,
            "principal_id": principal_id,
            "principal_type": principal_type,
            "binding_id": binding_id,
            "attestation_digest": attestation_digest,
            "event": "PRINCIPAL_NONCE_CONSUMED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = _digest(_canonical_json(body))
        self._connection.execute(
            """INSERT INTO principal_nonce_audit_events
               (sequence, nonce_fingerprint, task_id, proposal_digest, issuer,
                principal_id, principal_type, binding_id, attestation_digest,
                event, occurred_at, previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sequence,
                nonce_fingerprint,
                task_id,
                proposal_digest,
                issuer,
                principal_id,
                principal_type,
                binding_id,
                attestation_digest,
                "PRINCIPAL_NONCE_CONSUMED",
                occurred_at,
                previous_hash,
                record_hash,
            ),
        )

    def record_verified_principal(
        self,
        task: Mapping,
        attestation: Mapping,
        *,
        expected_audience: str,
        now: datetime,
        verifier=None,
        expected_lease_id: str | None = None,
        expected_receipt_id: str | None = None,
    ) -> dict:
        """Verify an attestation, then atomically consume its nonce exactly once.

        Worker assertions must reference a persisted lease proposal. Reviewer
        assertions must reference a persisted untrusted receipt. The injected
        verifier runs before the SQLite transaction; nonce uniqueness and all
        persistence checks are enforced inside BEGIN IMMEDIATE.
        """
        validated = validate_principal_attestation(
            task,
            attestation,
            expected_audience=expected_audience,
            now=now,
            verifier=verifier,
            expected_lease_id=expected_lease_id,
            expected_receipt_id=expected_receipt_id,
        )
        validated_task = validate_task(task)
        task_id = validated_task["task_id"]
        proposal_digest = validated_task["idempotency_key"]
        canonical_task = _canonical_json(dict(task))
        issuer = attestation["issuer"]
        principal_id = attestation["principal_id"]
        principal_type = validated["principal_type"]
        binding_id = (
            attestation["lease_id"]
            if principal_type == "WORKER"
            else attestation["receipt_id"]
        )
        nonce_fingerprint = _nonce_fingerprint(attestation)
        attestation_digest = _attestation_digest(attestation)
        expires_at = attestation["expires_at"]

        with self._transaction():
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
                raise LedgerError("PRINCIPAL_TASK_NOT_PERSISTED")

            if principal_type == "WORKER":
                binding_row = self._connection.execute(
                    """SELECT task_id, proposal_digest, status
                       FROM lease_proposals WHERE lease_id = ?""",
                    (binding_id,),
                ).fetchone()
                if (
                    binding_row is None
                    or binding_row["task_id"] != task_id
                    or binding_row["proposal_digest"] != proposal_digest
                    or binding_row["status"] != "PROPOSED"
                ):
                    raise LedgerError("PRINCIPAL_WORKER_LEASE_NOT_PERSISTED")
            else:
                binding_row = self._connection.execute(
                    """SELECT task_id, proposal_digest, status
                       FROM verification_receipts WHERE receipt_id = ?""",
                    (binding_id,),
                ).fetchone()
                if (
                    binding_row is None
                    or binding_row["task_id"] != task_id
                    or binding_row["proposal_digest"] != proposal_digest
                    or binding_row["status"] != "UNAUTHENTICATED_CLAIM"
                ):
                    raise LedgerError("PRINCIPAL_REVIEW_RECEIPT_NOT_PERSISTED")

            existing_nonce = self._connection.execute(
                "SELECT 1 FROM principal_nonce_uses WHERE nonce_fingerprint = ?",
                (nonce_fingerprint,),
            ).fetchone()
            if existing_nonce is not None:
                raise PrincipalReplayError("PRINCIPAL_NONCE_REPLAYED")

            existing_binding = self._connection.execute(
                """SELECT 1 FROM principal_nonce_uses
                   WHERE principal_type = ? AND binding_id = ?""",
                (principal_type, binding_id),
            ).fetchone()
            if existing_binding is not None:
                raise PrincipalReplayError("PRINCIPAL_BINDING_ALREADY_CONSUMED")

            count = self._connection.execute(
                "SELECT COUNT(*) FROM principal_nonce_uses"
            ).fetchone()[0]
            if count >= MAX_PRINCIPAL_NONCE_USES:
                raise LedgerError("PRINCIPAL_NONCE_CAPACITY_REACHED")

            created_at = _utc_now()
            self._connection.execute(
                """INSERT INTO principal_nonce_uses
                   (nonce_fingerprint, task_id, proposal_digest, issuer,
                    principal_id, principal_type, binding_id, attestation_digest,
                    expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    nonce_fingerprint,
                    task_id,
                    proposal_digest,
                    issuer,
                    principal_id,
                    principal_type,
                    binding_id,
                    attestation_digest,
                    expires_at,
                    created_at,
                ),
            )
            self._append_nonce_event(
                nonce_fingerprint=nonce_fingerprint,
                task_id=task_id,
                proposal_digest=proposal_digest,
                issuer=issuer,
                principal_id=principal_id,
                principal_type=principal_type,
                binding_id=binding_id,
                attestation_digest=attestation_digest,
            )

        return {
            **validated,
            "nonce_status": "CONSUMED_ONCE",
            "replay_protection_status": "PERSISTED",
            "raw_nonce_persisted": False,
            "execution_authorized": False,
        }

    def verify(self) -> dict:
        """Verify inherited ledgers and the complete one-time nonce audit chain."""
        base = super().verify()
        task_rows = self._connection.execute(
            "SELECT task_id, idempotency_key FROM tasks"
        ).fetchall()
        task_digests = {row["task_id"]: row["idempotency_key"] for row in task_rows}

        uses = self._connection.execute(
            """SELECT nonce_fingerprint, task_id, proposal_digest, issuer,
                      principal_id, principal_type, binding_id, attestation_digest,
                      expires_at, created_at
               FROM principal_nonce_uses ORDER BY nonce_fingerprint"""
        ).fetchall()
        if len(uses) > MAX_PRINCIPAL_NONCE_USES:
            raise PrincipalReplayCorruptionError(
                "PRINCIPAL_NONCE_CAPACITY_INVARIANT_FAILED"
            )

        use_map = {}
        seen_bindings = set()
        for row in uses:
            binding_key = (row["principal_type"], row["binding_id"])
            if (
                not _HEX_64.fullmatch(row["nonce_fingerprint"])
                or row["task_id"] not in task_digests
                or task_digests[row["task_id"]] != row["proposal_digest"]
                or not _IDENTIFIER.fullmatch(row["issuer"])
                or not _PRINCIPAL_ID.fullmatch(row["principal_id"])
                or row["principal_type"] not in _PRINCIPAL_TYPES
                or not _IDENTIFIER.fullmatch(row["binding_id"])
                or not _HEX_64.fullmatch(row["attestation_digest"])
                or not _validate_timestamp(row["expires_at"])
                or not _validate_timestamp(row["created_at"])
                or binding_key in seen_bindings
            ):
                raise PrincipalReplayCorruptionError(
                    "PRINCIPAL_NONCE_RECORD_INVARIANT_FAILED"
                )
            seen_bindings.add(binding_key)
            use_map[row["nonce_fingerprint"]] = row

        events = self._connection.execute(
            """SELECT sequence, nonce_fingerprint, task_id, proposal_digest,
                      issuer, principal_id, principal_type, binding_id,
                      attestation_digest, event, occurred_at, previous_hash,
                      record_hash
               FROM principal_nonce_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(uses):
            raise PrincipalReplayCorruptionError(
                "PRINCIPAL_NONCE_AUDIT_EVENT_COUNT_MISMATCH"
            )

        previous_hash = None
        seen_nonces = set()
        for expected_sequence, row in enumerate(events, start=1):
            use = use_map.get(row["nonce_fingerprint"])
            if (
                row["sequence"] != expected_sequence
                or use is None
                or row["nonce_fingerprint"] in seen_nonces
                or row["task_id"] != use["task_id"]
                or row["proposal_digest"] != use["proposal_digest"]
                or row["issuer"] != use["issuer"]
                or row["principal_id"] != use["principal_id"]
                or row["principal_type"] != use["principal_type"]
                or row["binding_id"] != use["binding_id"]
                or row["attestation_digest"] != use["attestation_digest"]
                or row["event"] != "PRINCIPAL_NONCE_CONSUMED"
                or row["previous_hash"] != previous_hash
                or not _validate_timestamp(row["occurred_at"])
                or not _HEX_64.fullmatch(row["record_hash"])
            ):
                raise PrincipalReplayCorruptionError(
                    "PRINCIPAL_NONCE_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "nonce_fingerprint": row["nonce_fingerprint"],
                "task_id": row["task_id"],
                "proposal_digest": row["proposal_digest"],
                "issuer": row["issuer"],
                "principal_id": row["principal_id"],
                "principal_type": row["principal_type"],
                "binding_id": row["binding_id"],
                "attestation_digest": row["attestation_digest"],
                "event": row["event"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            if row["record_hash"] != _digest(_canonical_json(body)):
                raise PrincipalReplayCorruptionError(
                    "PRINCIPAL_NONCE_AUDIT_CHAIN_HASH_INVALID"
                )
            previous_hash = row["record_hash"]
            seen_nonces.add(row["nonce_fingerprint"])

        return {
            **base,
            "principal_nonce_use_count": len(uses),
            "principal_nonce_audit_event_count": len(events),
            "principal_nonce_audit_chain": "VALID",
            "raw_nonce_values_stored": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify all persisted ledgers after reopen without resuming execution."""
        base = super().recover_after_restart()
        verified = self.verify()
        return {
            **base,
            "principal_nonce_uses_recovered": verified["principal_nonce_use_count"],
            "principal_nonce_audit_event_count": verified[
                "principal_nonce_audit_event_count"
            ],
            "principal_nonce_replay_protection": "PERSISTED_ONE_TIME_NONCES",
            "raw_nonce_values_stored": False,
            "execution_resumed": False,
            "execution_authorized": False,
        }
