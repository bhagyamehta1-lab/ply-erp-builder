"""Read-only cross-ledger backup-generation continuity verification.

The verifier correlates already-verified inventory metadata, observer backup
receipts, and independently verified binding receipts. It emits aggregate counts
only and never reads, copies, restores, or publishes backup artifacts.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Mapping
from datetime import datetime, timedelta

from scripts.enterprise_hq_backup_artifact_binding_snapshot import (
    BackupArtifactBindingSnapshotError,
    verify_backup_artifact_binding_receipt_snapshot,
)

MAX_INVENTORY_RECORDS = 256
MAX_OBSERVER_BACKUPS = 256
MAX_BINDING_RECEIPTS = 512
MAX_DECLARED_BACKUP_SIZE_BYTES = 256 * 1024 * 1024
MAX_BACKUP_RETENTION_DAYS = 90

_INVENTORY_ID = re.compile(r"^hqbk_[a-f0-9]{24}$")
_OBSERVER_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")
_LEDGER_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_INVENTORY_SNAPSHOT_FIELDS = frozenset({
    "status", "record_count", "records", "execution_authorized",
    "automatic_dispatch", "automatic_retry",
})
_INVENTORY_RECORD_FIELDS = frozenset({
    "status", "backup_id", "ledger_type", "source_snapshot_digest",
    "restored_snapshot_digest", "audit_chain_count", "declared_size_bytes",
    "created_at", "retain_until", "generation", "predecessor_backup_id",
    "storage_scope", "restore_status", "artifact_presence", "entry_digest",
    "artifact_bytes_verified", "execution_authorized", "automatic_dispatch",
    "automatic_retry",
})
_OBSERVER_SNAPSHOT_FIELDS = frozenset({
    "status", "backup_count", "records", "execution_authorized",
    "automatic_dispatch", "automatic_retry",
})
_OBSERVER_RECORD_FIELDS = frozenset({
    "backup_count", "backup_id", "file_sha256", "source_receipt_count",
    "source_status_counts", "last_source_sequence", "source_chain_head_digest",
    "predecessor_backup_id", "record_hash", "execution_authorized",
    "automatic_dispatch", "automatic_retry",
})
_FRESHNESS_STATUSES = frozenset({
    "FRESH", "GRACE_PERIOD", "MISSED", "NEVER_OBSERVED", "CLOCK_SKEW",
})


class BackupGenerationContinuityError(ValueError):
    """A cross-ledger backup-generation continuity snapshot is invalid."""


def _fail(code: str) -> None:
    raise BackupGenerationContinuityError(code)


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("BACKUP_GENERATION_CONTINUITY_ENCODING_INVALID")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _association_digest(kind: str, identifier: str) -> str:
    material = (
        "enterprise-hq-backup-association:v1:"
        + kind + ":" + identifier
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(
            value[:-1] + "+00:00" if value.endswith("Z") else value
        )
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _validate_inventory_snapshot(snapshot: Mapping) -> list[dict]:
    if not isinstance(snapshot, Mapping) or set(snapshot) != _INVENTORY_SNAPSHOT_FIELDS:
        _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_SNAPSHOT_SCHEMA_INVALID")
    if snapshot.get("status") != "BACKUP_INVENTORY_METADATA_SNAPSHOT_EXPORTED":
        _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_SNAPSHOT_STATUS_INVALID")
    for flag in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
        if snapshot.get(flag) is not False:
            _fail("BACKUP_GENERATION_CONTINUITY_AUTHORIZATION_INVALID")
    records = snapshot.get("records")
    count = snapshot.get("record_count")
    if (
        not isinstance(records, list)
        or type(count) is not int
        or count != len(records)
        or not 0 <= count <= MAX_INVENTORY_RECORDS
    ):
        _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_COUNT_INVALID")

    seen_ids = set()
    seen_generations = set()
    grouped = defaultdict(list)
    for record in records:
        if not isinstance(record, Mapping) or set(record) != _INVENTORY_RECORD_FIELDS:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_RECORD_SCHEMA_INVALID")
        backup_id = record.get("backup_id")
        ledger_type = record.get("ledger_type")
        if not isinstance(backup_id, str) or not _INVENTORY_ID.fullmatch(backup_id):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_ID_INVALID")
        if not isinstance(ledger_type, str) or not _LEDGER_TYPE.fullmatch(ledger_type):
            _fail("BACKUP_GENERATION_CONTINUITY_LEDGER_TYPE_INVALID")
        if backup_id in seen_ids:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_DUPLICATE_ID")
        seen_ids.add(backup_id)

        generation = record.get("generation")
        if type(generation) is not int or not 1 <= generation <= MAX_INVENTORY_RECORDS:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_GENERATION_INVALID")
        generation_key = (ledger_type, generation)
        if generation_key in seen_generations:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_DUPLICATE_GENERATION")
        seen_generations.add(generation_key)

        source_digest = record.get("source_snapshot_digest")
        restored_digest = record.get("restored_snapshot_digest")
        entry_digest = record.get("entry_digest")
        if (
            not isinstance(source_digest, str) or not _HEX_64.fullmatch(source_digest)
            or source_digest != restored_digest
            or not isinstance(entry_digest, str) or not _HEX_64.fullmatch(entry_digest)
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_DIGEST_INVALID")
        if (
            type(record.get("audit_chain_count")) is not int
            or not 1 <= record["audit_chain_count"] <= 32
            or type(record.get("declared_size_bytes")) is not int
            or not 1 <= record["declared_size_bytes"] <= MAX_DECLARED_BACKUP_SIZE_BYTES
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_BOUNDS_INVALID")

        created_at = _parse_utc(record.get("created_at"))
        retain_until = _parse_utc(record.get("retain_until"))
        if (
            created_at is None or retain_until is None
            or retain_until <= created_at
            or retain_until - created_at > timedelta(days=MAX_BACKUP_RETENTION_DAYS)
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_TIMESTAMP_INVALID")

        predecessor = record.get("predecessor_backup_id")
        if generation == 1:
            if predecessor is not None:
                _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_PREDECESSOR_INVALID")
        elif not isinstance(predecessor, str) or not _INVENTORY_ID.fullmatch(predecessor):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_PREDECESSOR_INVALID")

        if (
            record.get("status") != "BACKUP_METADATA_FOUND"
            or record.get("storage_scope") != "LOCAL_ONLY"
            or record.get("restore_status") != "RESTORE_EQUIVALENCE_VERIFIED"
            or record.get("artifact_presence") != "NOT_INSPECTED"
            or any(record.get(flag) is not False for flag in (
                "artifact_bytes_verified", "execution_authorized",
                "automatic_dispatch", "automatic_retry",
            ))
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_POLICY_INVALID")

        body = {
            key: record[key] for key in (
                "backup_id", "ledger_type", "source_snapshot_digest",
                "restored_snapshot_digest", "audit_chain_count",
                "declared_size_bytes", "created_at", "retain_until",
                "generation", "predecessor_backup_id", "storage_scope",
                "restore_status", "artifact_presence",
            )
        }
        if _digest(body) != entry_digest:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_ENTRY_DIGEST_MISMATCH")
        grouped[ledger_type].append(record)

    predecessor_links = 0
    for ledger_type, rows in grouped.items():
        rows.sort(key=lambda item: item["generation"])
        previous_id = None
        for expected_generation, row in enumerate(rows, 1):
            if (
                row["generation"] != expected_generation
                or row["predecessor_backup_id"] != previous_id
            ):
                _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_LINEAGE_INVALID")
            if expected_generation > 1:
                predecessor_links += 1
            previous_id = row["backup_id"]
    return records, len(grouped), predecessor_links


def _validate_observer_snapshot(snapshot: Mapping) -> list[dict]:
    if not isinstance(snapshot, Mapping) or set(snapshot) != _OBSERVER_SNAPSHOT_FIELDS:
        _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_SNAPSHOT_SCHEMA_INVALID")
    if snapshot.get("status") != "OBSERVER_FRESHNESS_BACKUP_RECEIPT_SNAPSHOT_EXPORTED":
        _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_SNAPSHOT_STATUS_INVALID")
    for flag in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
        if snapshot.get(flag) is not False:
            _fail("BACKUP_GENERATION_CONTINUITY_AUTHORIZATION_INVALID")
    records = snapshot.get("records")
    count = snapshot.get("backup_count")
    if (
        not isinstance(records, list)
        or type(count) is not int
        or count != len(records)
        or not 0 <= count <= MAX_OBSERVER_BACKUPS
    ):
        _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_COUNT_INVALID")

    seen_ids = set()
    previous_id = None
    for expected_sequence, record in enumerate(records, 1):
        if not isinstance(record, Mapping) or set(record) != _OBSERVER_RECORD_FIELDS:
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_RECORD_SCHEMA_INVALID")
        sequence = record.get("backup_count")
        backup_id = record.get("backup_id")
        file_digest = record.get("file_sha256")
        if type(sequence) is not int or sequence != expected_sequence:
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_SEQUENCE_INVALID")
        if (
            not isinstance(file_digest, str) or not _HEX_64.fullmatch(file_digest)
            or not isinstance(backup_id, str)
            or not _OBSERVER_ID.fullmatch(backup_id)
            or backup_id != "hqfb_" + file_digest[:24]
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_ID_INVALID")
        if backup_id in seen_ids:
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_DUPLICATE_ID")
        seen_ids.add(backup_id)
        if record.get("predecessor_backup_id") != previous_id:
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_PREDECESSOR_INVALID")

        source_count = record.get("source_receipt_count")
        status_counts = record.get("source_status_counts")
        if (
            type(source_count) is not int or not 0 <= source_count <= 512
            or not isinstance(status_counts, Mapping)
            or any(
                key not in _FRESHNESS_STATUSES
                or type(value) is not int or value <= 0
                for key, value in status_counts.items()
            )
            or sum(status_counts.values()) != source_count
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_SOURCE_COUNTS_INVALID")
        last_sequence = record.get("last_source_sequence")
        chain_head = record.get("source_chain_head_digest")
        if source_count == 0:
            if status_counts or last_sequence is not None or chain_head is not None:
                _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_EMPTY_SUMMARY_INVALID")
        elif (
            type(last_sequence) is not int or last_sequence != source_count
            or not isinstance(chain_head, str) or not _HEX_64.fullmatch(chain_head)
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_CHAIN_HEAD_INVALID")

        record_hash = record.get("record_hash")
        if not isinstance(record_hash, str) or not _HEX_64.fullmatch(record_hash):
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_RECORD_HASH_INVALID")
        if any(record.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        )):
            _fail("BACKUP_GENERATION_CONTINUITY_AUTHORIZATION_INVALID")
        previous_id = backup_id
    return records


def verify_backup_generation_continuity_snapshot(
    inventory_snapshot: Mapping,
    observer_snapshot: Mapping,
    binding_snapshot: Mapping,
) -> dict:
    """Independently correlate verified source snapshots and binding receipts.

    Inventory entry digests and per-ledger predecessor chains are recomputed.
    Observer receipt sequence/predecessor metadata is checked against the stable
    source-ledger enumeration. Binding receipt hashes are independently verified
    by the separate binding-snapshot verifier. This function does not inspect
    backup files or prove byte equivalence.
    """
    inventory_records, ledger_type_count, inventory_links = _validate_inventory_snapshot(
        inventory_snapshot
    )
    observer_records = _validate_observer_snapshot(observer_snapshot)
    try:
        binding_result = verify_backup_artifact_binding_receipt_snapshot(binding_snapshot)
    except BackupArtifactBindingSnapshotError:
        _fail("BACKUP_GENERATION_CONTINUITY_BINDING_SNAPSHOT_INVALID")
    except Exception:
        _fail("BACKUP_GENERATION_CONTINUITY_BINDING_SNAPSHOT_INVALID")

    inventory_by_commitment = {}
    for row in inventory_records:
        key = _association_digest("inventory", row["backup_id"])
        if key in inventory_by_commitment:
            _fail("BACKUP_GENERATION_CONTINUITY_INVENTORY_COMMITMENT_COLLISION")
        inventory_by_commitment[key] = row

    observer_by_commitment = {}
    for row in observer_records:
        key = _association_digest("observer", row["backup_id"])
        if key in observer_by_commitment:
            _fail("BACKUP_GENERATION_CONTINUITY_OBSERVER_COMMITMENT_COLLISION")
        observer_by_commitment[key] = row

    bound_inventory = set()
    bound_observer = set()
    pairs = set()
    for receipt in binding_snapshot["records"]:
        inventory_key = receipt["inventory_association_digest"]
        observer_key = receipt["observer_association_digest"]
        inventory_row = inventory_by_commitment.get(inventory_key)
        observer_row = observer_by_commitment.get(observer_key)
        if inventory_row is None or observer_row is None:
            _fail("BACKUP_GENERATION_CONTINUITY_BINDING_REFERENCE_MISSING")
        if receipt["inventory_generation"] != inventory_row["generation"]:
            _fail("BACKUP_GENERATION_CONTINUITY_BINDING_GENERATION_MISMATCH")
        if receipt["observer_backup_sequence"] != observer_row["backup_count"]:
            _fail("BACKUP_GENERATION_CONTINUITY_BINDING_OBSERVER_SEQUENCE_MISMATCH")
        recorded_inventory_count = receipt["inventory_record_count"]
        if (
            type(recorded_inventory_count) is not int
            or recorded_inventory_count < inventory_row["generation"]
            or recorded_inventory_count > len(inventory_records)
        ):
            _fail("BACKUP_GENERATION_CONTINUITY_BINDING_INVENTORY_COUNT_INVALID")
        bound_inventory.add(inventory_key)
        bound_observer.add(observer_key)
        pairs.add((inventory_key, observer_key))

    inventory_count = len(inventory_records)
    observer_count = len(observer_records)
    binding_count = binding_result["receipt_count"]
    if not pairs:
        coverage = "NONE"
    elif len(bound_inventory) == inventory_count and len(bound_observer) == observer_count:
        coverage = "COMPLETE"
    else:
        coverage = "PARTIAL"

    return {
        "status": "BACKUP_GENERATION_CONTINUITY_VERIFIED",
        "inventory_record_count": inventory_count,
        "inventory_ledger_type_count": ledger_type_count,
        "inventory_predecessor_link_count": inventory_links,
        "observer_backup_count": observer_count,
        "observer_predecessor_link_count": max(0, observer_count - 1),
        "binding_receipt_count": binding_count,
        "binding_association_pair_count": len(pairs),
        "bound_inventory_count": len(bound_inventory),
        "bound_observer_backup_count": len(bound_observer),
        "unbound_inventory_count": inventory_count - len(bound_inventory),
        "unbound_observer_backup_count": observer_count - len(bound_observer),
        "association_coverage": coverage,
        "inventory_entry_digest_verification": True,
        "binding_receipt_hash_verification": binding_result["independent_hash_verification"],
        "lineage_verification": True,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def reconcile_backup_generation_continuity(
    inventory,
    observer_receipt_ledger,
    binding_receipt_ledger,
) -> dict:
    """Verify three local ledgers, correlate stable snapshots, and emit counts only."""
    required = (
        (inventory, ("verify", "list_backup_metadata")),
        (observer_receipt_ledger, ("verify", "list_backup_receipts")),
        (binding_receipt_ledger, ("verify", "export_verification_snapshot")),
    )
    if any(
        any(not callable(getattr(obj, name, None)) for name in methods)
        for obj, methods in required
    ):
        _fail("BACKUP_GENERATION_CONTINUITY_SOURCE_LEDGERS_REQUIRED")

    try:
        before = (
            inventory.verify(),
            observer_receipt_ledger.verify(),
            binding_receipt_ledger.verify(),
        )
        inventory_records = inventory.list_backup_metadata()
        observer_records = observer_receipt_ledger.list_backup_receipts()
        binding_snapshot = binding_receipt_ledger.export_verification_snapshot()
        after = (
            inventory.verify(),
            observer_receipt_ledger.verify(),
            binding_receipt_ledger.verify(),
        )
    except BackupGenerationContinuityError:
        raise
    except Exception:
        _fail("BACKUP_GENERATION_CONTINUITY_SOURCE_VERIFICATION_FAILED")

    if (
        not all(isinstance(item, dict) for item in before + after)
        or before != after
    ):
        _fail("BACKUP_GENERATION_CONTINUITY_SOURCE_SNAPSHOT_CHANGED")

    inventory_snapshot = {
        "status": "BACKUP_INVENTORY_METADATA_SNAPSHOT_EXPORTED",
        "record_count": len(inventory_records) if isinstance(inventory_records, list) else None,
        "records": inventory_records,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    observer_snapshot = {
        "status": "OBSERVER_FRESHNESS_BACKUP_RECEIPT_SNAPSHOT_EXPORTED",
        "backup_count": len(observer_records) if isinstance(observer_records, list) else None,
        "records": observer_records,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    result = verify_backup_generation_continuity_snapshot(
        inventory_snapshot, observer_snapshot, binding_snapshot
    )
    return {
        **result,
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 3,
    }


__all__ = [
    "BackupGenerationContinuityError",
    "reconcile_backup_generation_continuity",
    "verify_backup_generation_continuity_snapshot",
]
