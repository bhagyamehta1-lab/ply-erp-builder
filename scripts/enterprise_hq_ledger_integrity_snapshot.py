"""Deterministic, metadata-only integrity checkpoints for local company ledgers.

The checkpoint calls the ledger's full verification and recovery checks, inventories
hash-chain heads, and emits counts/digests only. It does not persist, export, or
authenticate the checkpoint and never authorizes execution.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

MAX_AUDIT_CHAINS = 32
MAX_AUDIT_EVENTS_PER_CHAIN = 100_000
MAX_TOTAL_AUDIT_EVENTS = 1_000_000
MAX_SNAPSHOT_BYTES = 16 * 1024

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_LEDGER_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_AUDIT_TABLE = re.compile(r"^(?:audit_events|[a-z][a-z0-9_]*_audit_events)$")
_SUMMARY_KEY = re.compile(r"^[a-z][a-z0-9_]*_(?:count|chain)$")
_CHAIN_FIELDS = {"table", "event_count", "last_sequence", "head_hash"}
_TOP_FIELDS = {
    "schema_version", "snapshot_status", "ledger_type", "verification_summary",
    "recovery_summary", "audit_chains", "assurance", "execution_authorized",
    "execution_resumed", "automatic_retry", "snapshot_digest",
}
_RECOVERY_FIELDS = {
    "recovery_status", "tasks_recovered", "verification_receipts_recovered",
    "verified_evidence_receipts_recovered", "evidence_audit_events_recovered",
    "evidence_reviewer_bindings_recovered", "evidence_reviewer_audit_events_recovered",
    "identity_authenticated", "semantic_verification", "reviewer_independence",
    "evidence_payload_retention", "execution_authorized", "execution_resumed",
    "automatic_retry",
}


class LedgerIntegritySnapshotError(ValueError):
    """Stable fail-closed error for local ledger integrity checkpoints."""


def _canonical_json(value: Mapping) -> bytes:
    try:
        return json.dumps(
            dict(value), sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_ENCODING_INVALID") from None


def _row_value(row, key: str, index: int):
    try:
        return row[key]
    except (TypeError, IndexError, KeyError):
        return row[index]


def _audit_chain_heads(connection) -> list[dict]:
    try:
        rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND (name = 'audit_events' OR name LIKE '%_audit_events') "
            "ORDER BY name"
        ).fetchall()
    except Exception:
        raise LedgerIntegritySnapshotError("LEDGER_AUDIT_TABLE_DISCOVERY_FAILED") from None

    names = [_row_value(row, "name", 0) for row in rows]
    if not names or len(names) > MAX_AUDIT_CHAINS:
        raise LedgerIntegritySnapshotError("LEDGER_AUDIT_CHAIN_COUNT_INVALID")
    if any(not isinstance(name, str) or not _AUDIT_TABLE.fullmatch(name) for name in names):
        raise LedgerIntegritySnapshotError("LEDGER_AUDIT_TABLE_NAME_INVALID")
    if names != sorted(set(names)):
        raise LedgerIntegritySnapshotError("LEDGER_AUDIT_TABLE_ORDER_INVALID")

    heads = []
    total_events = 0
    for name in names:
        try:
            columns = connection.execute(f'PRAGMA table_info("{name}")').fetchall()
            column_names = {_row_value(row, "name", 1) for row in columns}
            if not {"sequence", "record_hash"}.issubset(column_names):
                raise LedgerIntegritySnapshotError("LEDGER_AUDIT_TABLE_SCHEMA_INVALID")
            count_row = connection.execute(
                f'SELECT COUNT(*) AS event_count FROM "{name}"'
            ).fetchone()
            event_count = _row_value(count_row, "event_count", 0)
            if type(event_count) is not int or not 0 <= event_count <= MAX_AUDIT_EVENTS_PER_CHAIN:
                raise LedgerIntegritySnapshotError("LEDGER_AUDIT_EVENT_COUNT_INVALID")
            total_events += event_count
            if total_events > MAX_TOTAL_AUDIT_EVENTS:
                raise LedgerIntegritySnapshotError("LEDGER_AUDIT_EVENT_TOTAL_LIMIT_EXCEEDED")
            last = connection.execute(
                f'SELECT sequence, record_hash FROM "{name}" ORDER BY sequence DESC LIMIT 1'
            ).fetchone()
        except LedgerIntegritySnapshotError:
            raise
        except Exception:
            raise LedgerIntegritySnapshotError("LEDGER_AUDIT_HEAD_READ_FAILED") from None

        if event_count == 0:
            last_sequence = None
            head_hash = None
        else:
            last_sequence = _row_value(last, "sequence", 0)
            head_hash = _row_value(last, "record_hash", 1)
            if (
                type(last_sequence) is not int
                or last_sequence != event_count
                or not isinstance(head_hash, str)
                or not _HEX_64.fullmatch(head_hash)
            ):
                raise LedgerIntegritySnapshotError("LEDGER_AUDIT_HEAD_INVALID")
        heads.append({
            "table": name, "event_count": event_count,
            "last_sequence": last_sequence, "head_hash": head_hash,
        })
    return heads


def build_ledger_integrity_snapshot(ledger) -> dict:
    """Return a deterministic metadata-only checkpoint after verify and recovery.

    The digest is unkeyed and local. It detects accidental alteration of the
    returned checkpoint but does not authenticate its origin or replace a backup.
    """
    verify = getattr(ledger, "verify", None)
    recover = getattr(ledger, "recover_after_restart", None)
    connection = getattr(ledger, "_connection", None)
    if not callable(verify) or not callable(recover) or not callable(
        getattr(connection, "execute", None)
    ):
        raise LedgerIntegritySnapshotError("LEDGER_INTERFACE_UNAVAILABLE")

    verified = verify()
    if not isinstance(verified, Mapping):
        raise LedgerIntegritySnapshotError("LEDGER_VERIFICATION_RESULT_INVALID")

    verification_summary = {}
    for key, value in verified.items():
        if not isinstance(key, str) or not _SUMMARY_KEY.fullmatch(key):
            continue
        if key.endswith("_count"):
            if type(value) is not int or value < 0:
                raise LedgerIntegritySnapshotError("LEDGER_VERIFICATION_COUNT_INVALID")
            verification_summary[key] = value
        else:
            if value != "VALID":
                raise LedgerIntegritySnapshotError("LEDGER_AUDIT_CHAIN_NOT_VALID")
            verification_summary[key] = value
    if not any(key.endswith("_chain") for key in verification_summary):
        raise LedgerIntegritySnapshotError("LEDGER_AUDIT_CHAIN_STATUS_MISSING")

    recovery = recover()
    if not isinstance(recovery, Mapping) or recovery.get("recovery_status") != "PASS":
        raise LedgerIntegritySnapshotError("LEDGER_RECOVERY_NOT_VERIFIED")
    for key in (
        "execution_authorized", "execution_resumed", "automatic_retry",
        "identity_authenticated",
    ):
        if key in recovery and recovery[key] is not False:
            raise LedgerIntegritySnapshotError("LEDGER_RECOVERY_AUTHORITY_INVARIANT_FAILED")

    recovery_summary = {}
    for key in _RECOVERY_FIELDS:
        if key in recovery:
            value = recovery[key]
            if not (value is None or type(value) in (bool, int, str)):
                raise LedgerIntegritySnapshotError("LEDGER_RECOVERY_SUMMARY_INVALID")
            recovery_summary[key] = value
    recovery_summary["recovery_status"] = "PASS"

    heads = _audit_chain_heads(connection)
    body = {
        "schema_version": "1.0.0",
        "snapshot_status": "VERIFIED_LOCAL_INTEGRITY",
        "ledger_type": type(ledger).__name__,
        "verification_summary": dict(sorted(verification_summary.items())),
        "recovery_summary": dict(sorted(recovery_summary.items())),
        "audit_chains": heads,
        "assurance": "LOCAL_SQLITE_UNSEALED",
        "execution_authorized": False,
        "execution_resumed": False,
        "automatic_retry": False,
    }
    encoded = _canonical_json(body)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_SIZE_LIMIT_EXCEEDED")
    return {**body, "snapshot_digest": hashlib.sha256(encoded).hexdigest()}


def verify_ledger_integrity_snapshot(snapshot: Mapping) -> dict:
    """Validate the bounded structure and unkeyed digest of a prior checkpoint."""
    if not isinstance(snapshot, Mapping) or set(snapshot) != _TOP_FIELDS:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_SCHEMA_INVALID")
    if snapshot.get("schema_version") != "1.0.0":
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_VERSION_UNSUPPORTED")
    if snapshot.get("snapshot_status") != "VERIFIED_LOCAL_INTEGRITY":
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_STATUS_INVALID")
    if not isinstance(snapshot.get("ledger_type"), str) or not _LEDGER_TYPE.fullmatch(snapshot["ledger_type"]):
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_LEDGER_TYPE_INVALID")
    if snapshot.get("assurance") != "LOCAL_SQLITE_UNSEALED":
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_ASSURANCE_INVALID")
    for key in ("execution_authorized", "execution_resumed", "automatic_retry"):
        if snapshot.get(key) is not False:
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUTHORITY_INVARIANT_FAILED")

    summary = snapshot.get("verification_summary")
    if not isinstance(summary, Mapping) or not summary:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_VERIFICATION_SUMMARY_INVALID")
    chain_statuses = 0
    for key, value in summary.items():
        if not isinstance(key, str) or not _SUMMARY_KEY.fullmatch(key):
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_SUMMARY_KEY_INVALID")
        if key.endswith("_count"):
            if type(value) is not int or value < 0:
                raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_COUNT_INVALID")
        else:
            if value != "VALID":
                raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_CHAIN_STATUS_INVALID")
            chain_statuses += 1
    if chain_statuses == 0:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_CHAIN_STATUS_MISSING")

    recovery = snapshot.get("recovery_summary")
    if not isinstance(recovery, Mapping) or recovery.get("recovery_status") != "PASS":
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_RECOVERY_INVALID")
    for key in ("execution_authorized", "execution_resumed", "automatic_retry", "identity_authenticated"):
        if key in recovery and recovery[key] is not False:
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_RECOVERY_AUTHORITY_INVALID")

    chains = snapshot.get("audit_chains")
    if not isinstance(chains, list) or not 1 <= len(chains) <= MAX_AUDIT_CHAINS:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_CHAINS_INVALID")
    names = []
    for chain in chains:
        if not isinstance(chain, Mapping) or set(chain) != _CHAIN_FIELDS:
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_CHAIN_SCHEMA_INVALID")
        name = chain.get("table")
        count = chain.get("event_count")
        sequence = chain.get("last_sequence")
        head_hash = chain.get("head_hash")
        if not isinstance(name, str) or not _AUDIT_TABLE.fullmatch(name):
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_TABLE_INVALID")
        if type(count) is not int or not 0 <= count <= MAX_AUDIT_EVENTS_PER_CHAIN:
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_COUNT_INVALID")
        if count == 0:
            if sequence is not None or head_hash is not None:
                raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_EMPTY_CHAIN_INVALID")
        elif (
            type(sequence) is not int or sequence != count
            or not isinstance(head_hash, str) or not _HEX_64.fullmatch(head_hash)
        ):
            raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_HEAD_INVALID")
        names.append(name)
    if names != sorted(set(names)):
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_AUDIT_ORDER_INVALID")

    digest = snapshot.get("snapshot_digest")
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_DIGEST_INVALID")
    body = {key: value for key, value in snapshot.items() if key != "snapshot_digest"}
    encoded = _canonical_json(body)
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_SIZE_LIMIT_EXCEEDED")
    if hashlib.sha256(encoded).hexdigest() != digest:
        raise LedgerIntegritySnapshotError("LEDGER_SNAPSHOT_DIGEST_MISMATCH")
    return {
        "status": "CHECKPOINT_INTEGRITY_VALID",
        "snapshot_digest": digest,
        "audit_chain_count": len(chains),
        "execution_authorized": False,
    }
