"""Fail-closed metadata-only comparison of ledger backup/restore checkpoints.

This module compares two independently verified local integrity snapshots. It does
not create, copy, restore, or persist a database backup and never authorizes work.
"""
from __future__ import annotations

from collections.abc import Mapping

from scripts.enterprise_hq_ledger_integrity_snapshot import (
    verify_ledger_integrity_snapshot,
)


class LedgerRestoreEquivalenceError(ValueError):
    """Stable fail-closed error for ledger restore-equivalence checks."""


def verify_ledger_restore_equivalence(
    source_snapshot: Mapping,
    restored_snapshot: Mapping,
) -> dict:
    """Verify that a restored ledger reproduces the source integrity checkpoint.

    Both snapshots must independently pass the strict snapshot verifier. The
    comparison then requires the same ledger type, audit-chain inventory size,
    and complete canonical snapshot digest. Only aggregate metadata is returned.
    """
    source = verify_ledger_integrity_snapshot(source_snapshot)
    restored = verify_ledger_integrity_snapshot(restored_snapshot)

    if source_snapshot.get("ledger_type") != restored_snapshot.get("ledger_type"):
        raise LedgerRestoreEquivalenceError(
            "LEDGER_RESTORE_LEDGER_TYPE_MISMATCH"
        )
    if source["audit_chain_count"] != restored["audit_chain_count"]:
        raise LedgerRestoreEquivalenceError(
            "LEDGER_RESTORE_CHAIN_COUNT_MISMATCH"
        )
    if source["snapshot_digest"] != restored["snapshot_digest"]:
        raise LedgerRestoreEquivalenceError(
            "LEDGER_RESTORE_SNAPSHOT_MISMATCH"
        )

    return {
        "status": "RESTORE_EQUIVALENCE_VERIFIED",
        "source_snapshot_digest": source["snapshot_digest"],
        "restored_snapshot_digest": restored["snapshot_digest"],
        "audit_chain_count": source["audit_chain_count"],
        "execution_authorized": False,
        "execution_resumed": False,
        "automatic_retry": False,
    }


__all__ = [
    "LedgerRestoreEquivalenceError",
    "verify_ledger_restore_equivalence",
]
