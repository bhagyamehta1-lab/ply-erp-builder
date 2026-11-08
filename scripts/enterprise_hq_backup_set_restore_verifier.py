"""Metadata-only verification that a restored ledger preserves backup-set history.

Both checkpoints must be independently valid and contain a non-empty,
integrity-verified cross-ledger backup-set audit chain. This module does not
create, copy, inspect, or restore backup artifacts and never authorizes work.
"""
from __future__ import annotations

from collections.abc import Mapping

from scripts.enterprise_hq_ledger_integrity_snapshot import (
    LedgerIntegritySnapshotError,
    verify_ledger_integrity_snapshot,
)
from scripts.enterprise_hq_ledger_restore_verifier import (
    LedgerRestoreEquivalenceError,
    verify_ledger_restore_equivalence,
)

MAX_BACKUP_SET_RESTORE_RECORDS = 128
_BACKUP_SET_LEDGER_TYPE = "CrossLedgerBackupSetInventory"
_BACKUP_SET_AUDIT_TABLE = "ledger_backup_set_audit_events"


class BackupSetRestoreEquivalenceError(ValueError):
    """Stable fail-closed error for backup-set restoration comparisons."""


def _checkpoint_metadata(snapshot: Mapping) -> dict:
    try:
        verified = verify_ledger_integrity_snapshot(snapshot)
    except LedgerIntegritySnapshotError:
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_SNAPSHOT_INVALID"
        ) from None

    if snapshot.get("ledger_type") != _BACKUP_SET_LEDGER_TYPE:
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_LEDGER_TYPE_INVALID"
        )

    summary = snapshot.get("verification_summary")
    if not isinstance(summary, Mapping):
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_SUMMARY_INVALID"
        )
    count = summary.get("backup_set_count")
    if type(count) is not int or not 1 <= count <= MAX_BACKUP_SET_RESTORE_RECORDS:
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_HISTORY_COUNT_INVALID"
        )
    if summary.get("backup_set_chain") != "VALID":
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_HISTORY_NOT_VALID"
        )

    chains = snapshot.get("audit_chains")
    matching = [
        item for item in chains
        if isinstance(item, Mapping)
        and item.get("table") == _BACKUP_SET_AUDIT_TABLE
    ]
    if len(matching) != 1:
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_AUDIT_CHAIN_MISSING"
        )

    chain = matching[0]
    if (
        chain.get("event_count") != count
        or chain.get("last_sequence") != count
        or not isinstance(chain.get("head_hash"), str)
    ):
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_AUDIT_COUNT_MISMATCH"
        )

    return {
        "snapshot_digest": verified["snapshot_digest"],
        "backup_set_count": count,
        "audit_event_count": chain["event_count"],
        "audit_head_hash": chain["head_hash"],
    }


def verify_backup_set_restore_equivalence(
    source_snapshot: Mapping,
    restored_snapshot: Mapping,
) -> dict:
    """Require complete, non-empty backup-set history to survive restoration.

    This specialized check first validates the backup-set summary and its
    dedicated audit-chain head in each snapshot. It then delegates complete
    ledger equivalence to the general strict restore verifier. The return value
    contains digests and counts only; no backup-set IDs or member payloads.
    """
    source = _checkpoint_metadata(source_snapshot)
    restored = _checkpoint_metadata(restored_snapshot)

    if (
        source["backup_set_count"] != restored["backup_set_count"]
        or source["audit_event_count"] != restored["audit_event_count"]
        or source["audit_head_hash"] != restored["audit_head_hash"]
    ):
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_HISTORY_MISMATCH"
        )

    try:
        equivalence = verify_ledger_restore_equivalence(
            source_snapshot, restored_snapshot
        )
    except LedgerRestoreEquivalenceError:
        raise BackupSetRestoreEquivalenceError(
            "BACKUP_SET_RESTORE_SNAPSHOT_MISMATCH"
        ) from None

    return {
        "status": "BACKUP_SET_RESTORE_EQUIVALENCE_VERIFIED",
        "backup_set_count": source["backup_set_count"],
        "backup_set_audit_event_count": source["audit_event_count"],
        "source_snapshot_digest": equivalence["source_snapshot_digest"],
        "restored_snapshot_digest": equivalence["restored_snapshot_digest"],
        "source_audit_head_hash": source["audit_head_hash"],
        "restored_audit_head_hash": restored["audit_head_hash"],
        "execution_authorized": False,
        "execution_resumed": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupSetRestoreEquivalenceError",
    "verify_backup_set_restore_equivalence",
]
