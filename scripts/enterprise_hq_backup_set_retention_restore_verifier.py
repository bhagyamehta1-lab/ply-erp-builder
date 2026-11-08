"""Metadata-only verification that backup-set retention history survives restoration.

Both snapshots must be independently valid BackupSetRetentionLedger checkpoints.
The verifier compares the retention evaluation count and dedicated audit-chain
head, then delegates complete backup-set history comparison to the existing
backup-set restoration verifier. No artifacts are read or changed.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from scripts.enterprise_hq_backup_set_restore_verifier import (
    BackupSetRestoreEquivalenceError,
    verify_backup_set_restore_equivalence,
)
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    LedgerIntegritySnapshotError,
    verify_ledger_integrity_snapshot,
)

MAX_BACKUP_SET_RETENTION_RESTORE_EVALUATIONS = 512
_RETENTION_AUDIT_TABLE = "ledger_backup_set_retention_audit_events"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


class BackupSetRetentionRestoreEquivalenceError(ValueError):
    """Stable fail-closed error for retention-history restoration comparisons."""


def _retention_checkpoint_metadata(snapshot: Mapping) -> dict:
    try:
        verified = verify_ledger_integrity_snapshot(snapshot)
    except LedgerIntegritySnapshotError:
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_SNAPSHOT_INVALID"
        ) from None

    if snapshot.get("ledger_type") != "BackupSetRetentionLedger":
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_LEDGER_TYPE_INVALID"
        )

    summary = snapshot.get("verification_summary")
    if not isinstance(summary, Mapping):
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_SUMMARY_INVALID"
        )

    evaluation_count = summary.get("backup_set_retention_evaluation_count")
    if (
        type(evaluation_count) is not int
        or not 0 <= evaluation_count <= MAX_BACKUP_SET_RETENTION_RESTORE_EVALUATIONS
    ):
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_COUNT_INVALID"
        )
    if summary.get("backup_set_retention_chain") != "VALID":
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_CHAIN_NOT_VALID"
        )

    chains = snapshot.get("audit_chains")
    if not isinstance(chains, list):
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_AUDIT_CHAINS_INVALID"
        )
    matching = [
        item for item in chains
        if isinstance(item, Mapping)
        and item.get("table") == _RETENTION_AUDIT_TABLE
    ]
    if len(matching) != 1:
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_AUDIT_CHAIN_MISSING"
        )

    chain = matching[0]
    expected_sequence = evaluation_count if evaluation_count else None
    expected_head = chain.get("head_hash")
    if (
        chain.get("event_count") != evaluation_count
        or chain.get("last_sequence") != expected_sequence
        or (
            evaluation_count == 0
            and expected_head is not None
        )
        or (
            evaluation_count > 0
            and (
                not isinstance(expected_head, str)
                or not _HEX_64.fullmatch(expected_head)
            )
        )
    ):
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_AUDIT_COUNT_MISMATCH"
        )

    return {
        "snapshot_digest": verified["snapshot_digest"],
        "evaluation_count": evaluation_count,
        "audit_event_count": chain["event_count"],
        "audit_head_hash": expected_head,
    }


def verify_backup_set_retention_restore_equivalence(
    source_snapshot: Mapping,
    restored_snapshot: Mapping,
) -> dict:
    """Require the complete retention evaluation history to survive restoration.

    Empty retention history is valid only when its dedicated audit chain is also
    empty. Non-empty histories must have matching event counts, final sequence,
    and head hash. Complete backup-set history is then checked by the inherited
    specialized verifier. The result contains metadata only and never authorizes
    execution, retry, purge, or artifact access.
    """
    source = _retention_checkpoint_metadata(source_snapshot)
    restored = _retention_checkpoint_metadata(restored_snapshot)

    if (
        source["evaluation_count"] != restored["evaluation_count"]
        or source["audit_event_count"] != restored["audit_event_count"]
        or source["audit_head_hash"] != restored["audit_head_hash"]
    ):
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_HISTORY_MISMATCH"
        )

    try:
        base = verify_backup_set_restore_equivalence(
            source_snapshot, restored_snapshot
        )
    except BackupSetRestoreEquivalenceError:
        raise BackupSetRetentionRestoreEquivalenceError(
            "BACKUP_SET_RETENTION_RESTORE_BASE_HISTORY_INVALID"
        ) from None

    return {
        "status": "BACKUP_SET_RETENTION_RESTORE_EQUIVALENCE_VERIFIED",
        "backup_set_count": base["backup_set_count"],
        "retention_evaluation_count": source["evaluation_count"],
        "retention_audit_event_count": source["audit_event_count"],
        "source_snapshot_digest": source["snapshot_digest"],
        "restored_snapshot_digest": restored["snapshot_digest"],
        "source_retention_audit_head_hash": source["audit_head_hash"],
        "restored_retention_audit_head_hash": restored["audit_head_hash"],
        "execution_authorized": False,
        "execution_resumed": False,
        "automatic_retry": False,
        "automatic_purge": False,
        "artifact_bytes_verified": False,
    }


__all__ = [
    "BackupSetRetentionRestoreEquivalenceError",
    "MAX_BACKUP_SET_RETENTION_RESTORE_EVALUATIONS",
    "verify_backup_set_retention_restore_equivalence",
]
