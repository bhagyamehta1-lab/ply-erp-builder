"""Read-only explicit association between backup inventory and verified artifacts.

The contract binds metadata-only inventory records to a freshness-backup receipt
and its latest AVAILABLE observation. It does not claim that inventory artifact
bytes were inspected or that two separately supplied artifacts are byte-identical.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from scripts.enterprise_hq_backup_inventory import LedgerBackupInventory
from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptLedger,
)
from scripts.enterprise_hq_observer_freshness_backup_availability_ledger import (
    ObserverFreshnessBackupAvailabilityLedger,
)

_INVENTORY_ID = re.compile(r"^hqbk_[a-f0-9]{24}$")
_OBSERVER_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_BINDING_FIELDS = frozenset({
    "inventory_backup_id",
    "inventory_entry_digest",
    "observer_backup_id",
    "observer_file_sha256",
})


class BackupArtifactBindingError(ValueError):
    """An explicit backup-artifact association is invalid or changed during review."""


def _fail(code: str) -> None:
    raise BackupArtifactBindingError(code)


def _canonical(value) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("BACKUP_ARTIFACT_BINDING_METADATA_INVALID")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _association_digest(kind: str, identifier: str) -> str:
    material = f"enterprise-hq-backup-association:v1:{kind}:{identifier}".encode("ascii")
    return hashlib.sha256(material).hexdigest()


def verify_backup_artifact_binding(
    inventory: LedgerBackupInventory,
    receipt_ledger: ObserverFreshnessBackupReceiptLedger,
    availability_ledger: ObserverFreshnessBackupAvailabilityLedger,
    binding: Mapping,
) -> dict:
    """Verify one caller-declared metadata association across three local ledgers.

    The caller must explicitly pair an inventory ID and entry digest with an
    observer-backup ID and file digest. All three source ledgers are independently
    verified before and after the read. Only a latest AVAILABLE observation whose
    lineage and source summary match the verified receipt is accepted.
    """
    if (
        not isinstance(inventory, LedgerBackupInventory)
        or inventory._connection is None
        or not isinstance(receipt_ledger, ObserverFreshnessBackupReceiptLedger)
        or receipt_ledger._connection is None
        or not isinstance(availability_ledger, ObserverFreshnessBackupAvailabilityLedger)
        or availability_ledger._connection is None
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SOURCE_LEDGERS_REQUIRED")
    if not isinstance(binding, Mapping) or set(binding) != _BINDING_FIELDS:
        _fail("BACKUP_ARTIFACT_BINDING_SCHEMA_INVALID")

    inventory_id = binding.get("inventory_backup_id")
    inventory_digest = binding.get("inventory_entry_digest")
    observer_id = binding.get("observer_backup_id")
    observer_digest = binding.get("observer_file_sha256")
    if not isinstance(inventory_id, str) or not _INVENTORY_ID.fullmatch(inventory_id):
        _fail("BACKUP_ARTIFACT_BINDING_INVENTORY_ID_INVALID")
    if not isinstance(observer_id, str) or not _OBSERVER_ID.fullmatch(observer_id):
        _fail("BACKUP_ARTIFACT_BINDING_OBSERVER_ID_INVALID")
    if not isinstance(inventory_digest, str) or not _HEX_64.fullmatch(inventory_digest):
        _fail("BACKUP_ARTIFACT_BINDING_INVENTORY_DIGEST_INVALID")
    if not isinstance(observer_digest, str) or not _HEX_64.fullmatch(observer_digest):
        _fail("BACKUP_ARTIFACT_BINDING_FILE_DIGEST_INVALID")

    inventory_before = inventory.verify()
    receipt_before = receipt_ledger.verify()
    availability_before = availability_ledger.verify()

    inventory_record = inventory.get_backup_metadata(inventory_id)
    receipt = receipt_ledger.get_backup_receipt(observer_id)
    observations = availability_ledger.list_latest_observations()
    matching = [
        item for item in observations
        if isinstance(item, dict) and item.get("backup_id") == observer_id
    ]

    inventory_after = inventory.verify()
    receipt_after = receipt_ledger.verify()
    availability_after = availability_ledger.verify()
    if (
        inventory_before != inventory_after
        or receipt_before != receipt_after
        or availability_before != availability_after
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SOURCE_SNAPSHOT_CHANGED")

    if inventory_record.get("status") != "BACKUP_METADATA_FOUND":
        _fail("BACKUP_ARTIFACT_BINDING_INVENTORY_RECORD_NOT_FOUND")
    if (
        inventory_record.get("backup_id") != inventory_id
        or inventory_record.get("entry_digest") != inventory_digest
        or inventory_record.get("restore_status") != "RESTORE_EQUIVALENCE_VERIFIED"
        or inventory_record.get("storage_scope") != "LOCAL_ONLY"
        or inventory_record.get("artifact_presence") != "NOT_INSPECTED"
        or inventory_record.get("source_snapshot_digest")
           != inventory_record.get("restored_snapshot_digest")
        or type(inventory_record.get("generation")) is not int
        or inventory_record["generation"] < 1
        or any(inventory_record.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry",
            "artifact_bytes_verified",
        ))
    ):
        _fail("BACKUP_ARTIFACT_BINDING_INVENTORY_EVIDENCE_MISMATCH")

    if receipt.get("status") != "OBSERVER_FRESHNESS_BACKUP_RECEIPT_FOUND":
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_NOT_FOUND")
    if (
        receipt.get("backup_id") != observer_id
        or receipt.get("file_sha256") != observer_digest
        or type(receipt.get("backup_count")) is not int
        or receipt["backup_count"] < 1
        or not isinstance(receipt.get("record_hash"), str)
        or not _HEX_64.fullmatch(receipt["record_hash"])
        or any(receipt.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        ))
    ):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_EVIDENCE_MISMATCH")

    if len(matching) != 1:
        _fail("BACKUP_ARTIFACT_BINDING_AVAILABILITY_OBSERVATION_NOT_FOUND")
    observation = matching[0]
    if observation.get("availability") != "AVAILABLE":
        _fail("BACKUP_ARTIFACT_BINDING_ARTIFACT_NOT_AVAILABLE")
    if (
        observation.get("status") != "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED"
        or observation.get("file_sha256") != receipt.get("file_sha256")
        or observation.get("lineage_sequence") != receipt.get("backup_count")
        or observation.get("lineage_record_hash") != receipt.get("record_hash")
        or observation.get("source_receipt_count") != receipt.get("source_receipt_count")
        or observation.get("source_status_counts") != receipt.get("source_status_counts")
        or observation.get("last_source_sequence") != receipt.get("last_source_sequence")
        or observation.get("source_chain_head_digest") != receipt.get("source_chain_head_digest")
        or type(observation.get("sequence")) is not int
        or observation["sequence"] < 1
        or not isinstance(observation.get("observation_id"), str)
        or not observation["observation_id"]
        or not isinstance(observation.get("record_hash"), str)
        or not _HEX_64.fullmatch(observation["record_hash"])
        or any(observation.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        ))
    ):
        _fail("BACKUP_ARTIFACT_BINDING_AVAILABILITY_EVIDENCE_MISMATCH")

    inventory_association_digest = _association_digest("inventory", inventory_id)
    observer_association_digest = _association_digest("observer", observer_id)
    core = {
        "schema_version": "1.1.0",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "association_commitments": {
            "inventory": inventory_association_digest,
            "observer": observer_association_digest,
        },
        "inventory": {
            "backup_id": inventory_id,
            "ledger_type": inventory_record["ledger_type"],
            "generation": inventory_record["generation"],
            "predecessor_backup_id": inventory_record["predecessor_backup_id"],
            "entry_digest": inventory_record["entry_digest"],
            "source_snapshot_digest": inventory_record["source_snapshot_digest"],
            "restored_snapshot_digest": inventory_record["restored_snapshot_digest"],
            "restore_status": inventory_record["restore_status"],
            "storage_scope": inventory_record["storage_scope"],
            "artifact_presence": inventory_record["artifact_presence"],
        },
        "observer_backup": {
            "backup_id": observer_id,
            "backup_sequence": receipt["backup_count"],
            "receipt_record_hash": receipt["record_hash"],
            "file_sha256": receipt["file_sha256"],
            "source_receipt_count": receipt["source_receipt_count"],
            "source_status_counts": receipt["source_status_counts"],
            "last_source_sequence": receipt["last_source_sequence"],
            "source_chain_head_digest": receipt["source_chain_head_digest"],
        },
        "availability_observation": {
            "observation_id": observation["observation_id"],
            "sequence": observation["sequence"],
            "record_hash": observation["record_hash"],
            "availability": observation["availability"],
        },
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    return {
        "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
        "binding_status": "METADATA_ASSOCIATION_VERIFIED",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "inventory_association_digest": inventory_association_digest,
        "observer_association_digest": observer_association_digest,
        "binding_digest": _digest(core),
        "inventory_record_count": inventory_after["backup_inventory_count"],
        "inventory_generation": inventory_record["generation"],
        "observer_backup_sequence": receipt["backup_count"],
        "availability_observation_sequence": observation["sequence"],
        "availability": "AVAILABLE",
        "inventory_artifact_presence": "NOT_INSPECTED",
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = ["BackupArtifactBindingError", "verify_backup_artifact_binding"]
