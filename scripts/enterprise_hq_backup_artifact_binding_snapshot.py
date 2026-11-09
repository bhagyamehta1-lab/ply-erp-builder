"""Independent verifier for exported backup-artifact binding receipt histories.

This module intentionally does not import the SQLite ledger or its private
hashing helpers. It validates the exported metadata contract, recomputes each
receipt hash, and checks sequence, timestamp, identifier, and chain continuity.
It never receives source backup IDs, file digests, paths, or artifact bytes.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

SCHEMA_VERSION = "1.0.0"
MAX_RECEIPTS = 512
MAX_RECORDED_AT_CHARS = 64
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_RECEIPT_ID = re.compile(r"^hqbr_[a-f0-9]{24}$")
_SNAPSHOT_FIELDS = frozenset({
    "status", "schema_version", "receipt_count", "records",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_RECORD_FIELDS = frozenset({
    "schema_version", "sequence", "receipt_id", "binding_digest",
    "binding_status", "binding_basis", "inventory_record_count",
    "inventory_generation", "observer_backup_sequence",
    "availability_observation_sequence", "availability",
    "inventory_artifact_presence", "artifact_bytes_verified",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
    "recorded_at", "previous_hash", "record_hash",
})


class BackupArtifactBindingSnapshotError(ValueError):
    """An exported binding-receipt snapshot failed independent verification."""


def _fail(code: str) -> None:
    raise BackupArtifactBindingSnapshotError(code)


def _canonical(value) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_ENCODING_INVALID")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _receipt_id(binding_digest: str) -> str:
    material = ("enterprise-hq-binding-receipt:v1:" + binding_digest).encode("ascii")
    return "hqbr_" + hashlib.sha256(material).hexdigest()[:24]


def _normalize_recorded_at(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RECORDED_AT_CHARS:
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except (TypeError, ValueError, OverflowError):
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_TIMESTAMP_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_TIMESTAMP_INVALID")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def verify_backup_artifact_binding_receipt_snapshot(snapshot: Mapping) -> dict:
    """Verify a metadata-only receipt snapshot without trusting the ledger verifier."""
    if not isinstance(snapshot, Mapping) or set(snapshot) != _SNAPSHOT_FIELDS:
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_SCHEMA_INVALID")
    if (
        snapshot.get("status") != "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED"
        or snapshot.get("schema_version") != SCHEMA_VERSION
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_STATUS_INVALID")
    for field in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
        if snapshot.get(field) is not False:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_AUTHORIZATION_INVALID")
    records = snapshot.get("records")
    count = snapshot.get("receipt_count")
    if (
        not isinstance(records, list)
        or type(count) is not int
        or count != len(records)
        or count < 0
        or count > MAX_RECEIPTS
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_COUNT_INVALID")

    previous_hash = None
    previous_at = None
    seen_digests = set()
    seen_ids = set()
    for expected_sequence, record in enumerate(records, 1):
        if not isinstance(record, Mapping) or set(record) != _RECORD_FIELDS:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_RECORD_SCHEMA_INVALID")
        if record.get("schema_version") != SCHEMA_VERSION:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_RECORD_VERSION_INVALID")
        if type(record.get("sequence")) is not int or record["sequence"] != expected_sequence:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_SEQUENCE_INVALID")

        binding_digest = record.get("binding_digest")
        if not isinstance(binding_digest, str) or not _HEX_64.fullmatch(binding_digest):
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_DIGEST_INVALID")
        receipt_id = record.get("receipt_id")
        if (
            not isinstance(receipt_id, str)
            or not _RECEIPT_ID.fullmatch(receipt_id)
            or receipt_id != _receipt_id(binding_digest)
        ):
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_RECEIPT_ID_INVALID")
        if binding_digest in seen_digests or receipt_id in seen_ids:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_DUPLICATE_RECEIPT")
        seen_digests.add(binding_digest)
        seen_ids.add(receipt_id)

        if (
            record.get("binding_status") != "METADATA_ASSOCIATION_VERIFIED"
            or record.get("binding_basis") != "EXPLICIT_CALLER_ASSOCIATION"
            or record.get("availability") != "AVAILABLE"
            or record.get("inventory_artifact_presence") != "NOT_INSPECTED"
        ):
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_BINDING_STATUS_INVALID")

        bounds = {
            "inventory_record_count": (1, 256),
            "inventory_generation": (1, 256),
            "observer_backup_sequence": (1, 256),
            "availability_observation_sequence": (1, 512),
        }
        for field, (minimum, maximum) in bounds.items():
            value = record.get(field)
            if type(value) is not int or not minimum <= value <= maximum:
                _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_COUNT_FIELD_INVALID")
        for field in (
            "artifact_bytes_verified", "execution_authorized",
            "automatic_dispatch", "automatic_retry",
        ):
            if record.get(field) is not False:
                _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_AUTHORIZATION_INVALID")

        recorded_at = _normalize_recorded_at(record.get("recorded_at"))
        if recorded_at != record.get("recorded_at"):
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_TIMESTAMP_NONCANONICAL")
        if previous_at is not None and recorded_at < previous_at:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_TIMESTAMP_REGRESSION")
        if record.get("previous_hash") != previous_hash:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_CHAIN_LINK_INVALID")

        record_hash = record.get("record_hash")
        if not isinstance(record_hash, str) or not _HEX_64.fullmatch(record_hash):
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_RECORD_HASH_INVALID")
        body = {key: value for key, value in record.items() if key != "record_hash"}
        if _digest(body) != record_hash:
            _fail("BACKUP_ARTIFACT_BINDING_SNAPSHOT_RECORD_HASH_MISMATCH")
        previous_hash = record_hash
        previous_at = recorded_at

    return {
        "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_VERIFIED",
        "receipt_count": count,
        "last_sequence": count if count else None,
        "chain_head_hash": previous_hash,
        "independent_hash_verification": True,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupArtifactBindingSnapshotError",
    "verify_backup_artifact_binding_receipt_snapshot",
]
