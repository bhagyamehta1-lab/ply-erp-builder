"""Persistent anti-rollback history for principal trust-policy snapshots.

Only policy identifiers, source revision metadata, digests, key fingerprints, status,
and audit records are stored. No keys, signatures, tokens, raw attestations, policy
payloads, or source credentials are persisted. A pin remains explicitly untrusted.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta

from scripts.enterprise_hq_principal_replay_ledger import (
    PrincipalReplayCorruptionError,
    PrincipalReplayError,
    PrincipalReplayLedger,
    _canonical_json,
    _digest,
    _utc_now,
)
from scripts.enterprise_hq_principal_trust_policy import (
    FINGERPRINT,
    POLICY_FIELDS,
    POLICY_ID,
    POLICY_STATUSES,
    SUPPORTED_ALGORITHM,
)

MAX_PRINCIPAL_POLICY_SNAPSHOTS = 1024
SOURCE_FIELDS = frozenset({
    "source_id", "source_version", "source_revision", "source_assurance",
    "read_only", "retrieved_at", "policy", "policy_digest",
})
SOURCE_ASSURANCE = "AUTHENTICATED_READ_ONLY_ADAPTER_ASSERTED"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HEX_64 = re.compile(r"^[a-f0-9]{64}$")
MAX_POLICY_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30


class PrincipalPolicyLedgerError(PrincipalReplayError):
    """A policy snapshot conflicts with previously pinned source history."""


class PrincipalPolicyLedgerCorruptionError(PrincipalReplayCorruptionError):
    """Persisted principal policy history failed integrity verification."""


def _aware_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed


def _canonical_policy_digest(policy: Mapping) -> str:
    rendered = json.dumps(
        dict(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


class PrincipalPolicyLedger(PrincipalReplayLedger):
    """Append-only local policy-version ledger with rollback and revocation guards."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS principal_policy_versions (
                    source_id TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
                    source_version TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    policy_status TEXT NOT NULL
                        CHECK (policy_status IN ('ACTIVE', 'DISABLED', 'REVOKED')),
                    revoked_at TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (source_id, issuer, key_id, source_revision),
                    UNIQUE (source_id, issuer, key_id, source_version)
                )"""
            )
            self._connection.execute(
                """CREATE TABLE IF NOT EXISTS principal_policy_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    source_revision INTEGER NOT NULL,
                    source_version TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    policy_status TEXT NOT NULL,
                    revoked_at TEXT,
                    event TEXT NOT NULL
                        CHECK (event IN ('POLICY_SNAPSHOT_PINNED', 'POLICY_KEY_REVOKED')),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE,
                    FOREIGN KEY (source_id, issuer, key_id, source_revision)
                        REFERENCES principal_policy_versions
                        (source_id, issuer, key_id, source_revision)
                )"""
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS principal_policy_versions_lookup_idx "
                "ON principal_policy_versions(source_id, issuer, key_id, source_revision)"
            )
        except Exception:
            self.close()
            raise

    def _append_policy_event(self, row: Mapping) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM principal_policy_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        event = (
            "POLICY_KEY_REVOKED"
            if row["policy_status"] == "REVOKED"
            else "POLICY_SNAPSHOT_PINNED"
        )
        body = {
            "schema_version": "1.0.0", "sequence": sequence,
            "source_id": row["source_id"], "issuer": row["issuer"],
            "key_id": row["key_id"], "source_revision": row["source_revision"],
            "source_version": row["source_version"], "policy_id": row["policy_id"],
            "policy_digest": row["policy_digest"],
            "key_fingerprint": row["key_fingerprint"],
            "policy_status": row["policy_status"], "revoked_at": row["revoked_at"],
            "event": event, "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = _digest(_canonical_json(body))
        self._connection.execute(
            """INSERT INTO principal_policy_audit_events
               (sequence, source_id, issuer, key_id, source_revision, source_version,
                policy_id, policy_digest, key_fingerprint, policy_status, revoked_at,
                event, occurred_at, previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                sequence, row["source_id"], row["issuer"], row["key_id"],
                row["source_revision"], row["source_version"], row["policy_id"],
                row["policy_digest"], row["key_fingerprint"], row["policy_status"],
                row["revoked_at"], event, occurred_at, previous_hash, record_hash,
            ),
        )

    def record_policy_snapshot(
        self,
        snapshot: Mapping,
        policy: Mapping,
        *,
        expected_issuer: str,
        expected_key_id: str,
        now: datetime,
    ) -> dict:
        """Pin a source revision before policy matching or signature verification.

        Disabled and revoked policies are recorded before the caller rejects them.
        Revisions are contiguous after the first observation. Revocation is terminal
        for this source/issuer/key tuple; rotation requires a new key ID.
        """
        if not isinstance(snapshot, Mapping) or set(snapshot) != SOURCE_FIELDS:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_SCHEMA_INVALID")
        if not isinstance(policy, Mapping) or set(policy) != POLICY_FIELDS:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SCHEMA_INVALID")
        snapshot_policy = snapshot.get("policy")
        if not isinstance(snapshot_policy, Mapping):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SNAPSHOT_POLICY_INVALID")

        source_id = snapshot.get("source_id")
        source_version = snapshot.get("source_version")
        source_revision = snapshot.get("source_revision")
        if not isinstance(source_id, str) or not IDENTIFIER.fullmatch(source_id):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_ID_INVALID")
        if not isinstance(source_version, str) or not IDENTIFIER.fullmatch(source_version):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_VERSION_INVALID")
        if type(source_revision) is not int or source_revision < 1:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_REVISION_INVALID")
        if snapshot.get("source_assurance") != SOURCE_ASSURANCE:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_NOT_AUTHENTICATED")
        if snapshot.get("read_only") is not True:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_NOT_READ_ONLY")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_CLOCK_INVALID")
        retrieved_at = _aware_timestamp(snapshot.get("retrieved_at"))
        if retrieved_at is None:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_TIME_INVALID")
        if retrieved_at > now + timedelta(seconds=MAX_FUTURE_SKEW_SECONDS):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_TIME_INVALID")
        if (now - retrieved_at).total_seconds() > MAX_POLICY_AGE_SECONDS:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_STALE")

        issuer = policy.get("issuer")
        key_id = policy.get("key_id")
        policy_id = policy.get("policy_id")
        algorithm = policy.get("algorithm")
        key_fingerprint = policy.get("key_fingerprint")
        policy_status = policy.get("status")
        revoked_at = policy.get("revoked_at")
        if issuer != expected_issuer or not isinstance(issuer, str) or not IDENTIFIER.fullmatch(issuer):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ISSUER_MISMATCH")
        if key_id != expected_key_id or not isinstance(key_id, str) or not IDENTIFIER.fullmatch(key_id):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_KEY_ID_MISMATCH")
        if not isinstance(policy_id, str) or not POLICY_ID.fullmatch(policy_id):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ID_INVALID")
        if algorithm != SUPPORTED_ALGORITHM:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ALGORITHM_INVALID")
        if not isinstance(key_fingerprint, str) or not FINGERPRINT.fullmatch(key_fingerprint):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_FINGERPRINT_INVALID")
        if not isinstance(policy_status, str) or policy_status not in POLICY_STATUSES:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_STATUS_INVALID")
        if policy_status == "REVOKED":
            if _aware_timestamp(revoked_at) is None:
                raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_REVOCATION_TIME_REQUIRED")
        elif revoked_at is not None:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_REVOCATION_STATE_INVALID")

        try:
            policy_digest = _canonical_policy_digest(policy)
            snapshot_policy_digest = _canonical_policy_digest(snapshot_policy)
        except (TypeError, ValueError):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ENCODING_INVALID") from None
        if snapshot_policy_digest != policy_digest:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SNAPSHOT_POLICY_MISMATCH")
        supplied_digest = snapshot.get("policy_digest")
        if not isinstance(supplied_digest, str) or not HEX_64.fullmatch(supplied_digest):
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_DIGEST_INVALID")
        if supplied_digest != policy_digest:
            raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_DIGEST_MISMATCH")

        key = (source_id, issuer, key_id)
        with self._transaction():
            self.verify()
            existing = self._connection.execute(
                """SELECT source_version, policy_id, policy_digest, key_fingerprint,
                          policy_status, revoked_at
                   FROM principal_policy_versions
                   WHERE source_id = ? AND issuer = ? AND key_id = ?
                     AND source_revision = ?""",
                (*key, source_revision),
            ).fetchone()
            if existing is not None:
                same = (
                    existing["source_version"] == source_version
                    and existing["policy_id"] == policy_id
                    and existing["policy_digest"] == policy_digest
                    and existing["key_fingerprint"] == key_fingerprint
                    and existing["policy_status"] == policy_status
                    and existing["revoked_at"] == revoked_at
                )
                if same:
                    return {
                        "status": "ALREADY_PINNED",
                        "source_revision": source_revision,
                        "policy_digest": policy_digest,
                        "execution_authorized": False,
                    }
                raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_REVISION_CONFLICT")

            latest = self._connection.execute(
                """SELECT source_revision, source_version, policy_id, key_fingerprint,
                          policy_status
                   FROM principal_policy_versions
                   WHERE source_id = ? AND issuer = ? AND key_id = ?
                   ORDER BY source_revision DESC LIMIT 1""",
                key,
            ).fetchone()
            if latest is not None:
                if source_revision < latest["source_revision"]:
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ROLLBACK_REJECTED")
                if source_revision > latest["source_revision"] + 1:
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_REVISION_GAP")
                if latest["policy_status"] == "REVOKED":
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_KEY_REVOKED")
                if latest["key_fingerprint"] != key_fingerprint:
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_KEY_FINGERPRINT_CHANGED")
                if latest["policy_id"] != policy_id:
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_ID_CHANGED")
                if latest["source_version"] == source_version:
                    raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_SOURCE_VERSION_REUSED")

            count = self._connection.execute(
                "SELECT COUNT(*) AS total FROM principal_policy_versions"
            ).fetchone()["total"]
            if count >= MAX_PRINCIPAL_POLICY_SNAPSHOTS:
                raise PrincipalPolicyLedgerError("PRINCIPAL_POLICY_LEDGER_CAPACITY_EXCEEDED")

            row = {
                "source_id": source_id, "issuer": issuer, "key_id": key_id,
                "source_revision": source_revision, "source_version": source_version,
                "policy_id": policy_id, "policy_digest": policy_digest,
                "key_fingerprint": key_fingerprint, "policy_status": policy_status,
                "revoked_at": revoked_at, "created_at": _utc_now(),
            }
            self._connection.execute(
                """INSERT INTO principal_policy_versions
                   (source_id, issuer, key_id, source_revision, source_version,
                    policy_id, policy_digest, key_fingerprint, policy_status,
                    revoked_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    row["source_id"], row["issuer"], row["key_id"],
                    row["source_revision"], row["source_version"], row["policy_id"],
                    row["policy_digest"], row["key_fingerprint"], row["policy_status"],
                    row["revoked_at"], row["created_at"],
                ),
            )
            self._append_policy_event(row)

        return {
            "status": "REVOKED_RECORDED" if policy_status == "REVOKED" else "PINNED_UNTRUSTED_SNAPSHOT",
            "source_revision": source_revision,
            "policy_digest": policy_digest,
            "execution_authorized": False,
        }

    def verify(self) -> dict:
        """Verify inherited ledgers, monotonic policy history and its audit chain."""
        base = super().verify()
        rows = self._connection.execute(
            """SELECT source_id, issuer, key_id, source_revision, source_version,
                      policy_id, policy_digest, key_fingerprint, policy_status,
                      revoked_at, created_at
               FROM principal_policy_versions
               ORDER BY source_id, issuer, key_id, source_revision"""
        ).fetchall()
        if len(rows) > MAX_PRINCIPAL_POLICY_SNAPSHOTS:
            raise PrincipalPolicyLedgerCorruptionError(
                "PRINCIPAL_POLICY_CAPACITY_INVARIANT_FAILED"
            )

        grouped = {}
        by_key = {}
        for row in rows:
            key = (row["source_id"], row["issuer"], row["key_id"])
            if (
                not isinstance(row["source_id"], str) or not IDENTIFIER.fullmatch(row["source_id"])
                or not isinstance(row["issuer"], str) or not IDENTIFIER.fullmatch(row["issuer"])
                or not isinstance(row["key_id"], str) or not IDENTIFIER.fullmatch(row["key_id"])
                or type(row["source_revision"]) is not int or row["source_revision"] < 1
                or not isinstance(row["source_version"], str) or not IDENTIFIER.fullmatch(row["source_version"])
                or not isinstance(row["policy_id"], str) or not POLICY_ID.fullmatch(row["policy_id"])
                or not isinstance(row["policy_digest"], str) or not HEX_64.fullmatch(row["policy_digest"])
                or not isinstance(row["key_fingerprint"], str) or not FINGERPRINT.fullmatch(row["key_fingerprint"])
                or row["policy_status"] not in POLICY_STATUSES
                or not _aware_timestamp(row["created_at"])
                or (row["policy_status"] == "REVOKED" and _aware_timestamp(row["revoked_at"]) is None)
                or (row["policy_status"] != "REVOKED" and row["revoked_at"] is not None)
            ):
                raise PrincipalPolicyLedgerCorruptionError(
                    "PRINCIPAL_POLICY_RECORD_INVARIANT_FAILED"
                )
            history = grouped.setdefault(key, [])
            if history:
                previous = history[-1]
                if row["source_revision"] != previous["source_revision"] + 1:
                    raise PrincipalPolicyLedgerCorruptionError(
                        "PRINCIPAL_POLICY_REVISION_SEQUENCE_INVALID"
                    )
                if previous["policy_status"] == "REVOKED":
                    raise PrincipalPolicyLedgerCorruptionError(
                        "PRINCIPAL_POLICY_REVOCATION_ROLLBACK_INVALID"
                    )
                if row["key_fingerprint"] != previous["key_fingerprint"]:
                    raise PrincipalPolicyLedgerCorruptionError(
                        "PRINCIPAL_POLICY_KEY_FINGERPRINT_HISTORY_INVALID"
                    )
                if row["policy_id"] != previous["policy_id"]:
                    raise PrincipalPolicyLedgerCorruptionError(
                        "PRINCIPAL_POLICY_ID_HISTORY_INVALID"
                    )
                if row["source_version"] == previous["source_version"]:
                    raise PrincipalPolicyLedgerCorruptionError(
                        "PRINCIPAL_POLICY_SOURCE_VERSION_HISTORY_INVALID"
                    )
            history.append(row)
            by_key[(key, row["source_revision"])] = row

        events = self._connection.execute(
            """SELECT sequence, source_id, issuer, key_id, source_revision,
                      source_version, policy_id, policy_digest, key_fingerprint,
                      policy_status, revoked_at, event, occurred_at, previous_hash,
                      record_hash
               FROM principal_policy_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(rows):
            raise PrincipalPolicyLedgerCorruptionError(
                "PRINCIPAL_POLICY_AUDIT_EVENT_COUNT_MISMATCH"
            )

        previous_hash = None
        seen = set()
        for expected_sequence, event in enumerate(events, start=1):
            event_key = (
                event["source_id"], event["issuer"], event["key_id"],
                event["source_revision"],
            )
            row = by_key.get((
                (event["source_id"], event["issuer"], event["key_id"]),
                event["source_revision"],
            ))
            expected_event = (
                "POLICY_KEY_REVOKED"
                if event["policy_status"] == "REVOKED"
                else "POLICY_SNAPSHOT_PINNED"
            )
            if (
                event["sequence"] != expected_sequence or row is None or event_key in seen
                or event["source_version"] != row["source_version"]
                or event["policy_id"] != row["policy_id"]
                or event["policy_digest"] != row["policy_digest"]
                or event["key_fingerprint"] != row["key_fingerprint"]
                or event["policy_status"] != row["policy_status"]
                or event["revoked_at"] != row["revoked_at"]
                or event["event"] != expected_event
                or not _aware_timestamp(event["occurred_at"])
                or event["previous_hash"] != previous_hash
                or not isinstance(event["record_hash"], str)
                or not HEX_64.fullmatch(event["record_hash"])
            ):
                raise PrincipalPolicyLedgerCorruptionError(
                    "PRINCIPAL_POLICY_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            body = {
                "schema_version": "1.0.0", "sequence": event["sequence"],
                "source_id": event["source_id"], "issuer": event["issuer"],
                "key_id": event["key_id"], "source_revision": event["source_revision"],
                "source_version": event["source_version"], "policy_id": event["policy_id"],
                "policy_digest": event["policy_digest"],
                "key_fingerprint": event["key_fingerprint"],
                "policy_status": event["policy_status"], "revoked_at": event["revoked_at"],
                "event": event["event"], "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            if event["record_hash"] != _digest(_canonical_json(body)):
                raise PrincipalPolicyLedgerCorruptionError(
                    "PRINCIPAL_POLICY_AUDIT_CHAIN_HASH_INVALID"
                )
            previous_hash = event["record_hash"]
            seen.add(event_key)

        return {
            **base,
            "principal_policy_snapshot_count": len(rows),
            "principal_policy_audit_event_count": len(events),
            "principal_policy_revoked_key_count": sum(
                1 for row in rows if row["policy_status"] == "REVOKED"
            ),
            "policy_identity_authenticated": False,
            "execution_authorized": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify all policy history after reopen without resuming execution."""
        base = super().recover_after_restart()
        verified = self.verify()
        return {
            **base,
            "principal_policy_snapshot_count": verified["principal_policy_snapshot_count"],
            "principal_policy_audit_event_count": verified["principal_policy_audit_event_count"],
            "policy_history_status": "PERSISTED_MONOTONIC_UNTRUSTED_HISTORY",
            "execution_resumed": False,
            "execution_authorized": False,
        }
