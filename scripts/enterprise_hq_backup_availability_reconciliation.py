"""Read-only reconciliation of freshness backup receipts and availability history.

This module compares two independently verified local ledgers. It performs no
filesystem access, writes, restoration, retries, or task dispatch.
"""
from __future__ import annotations

from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptLedger,
)
from scripts.enterprise_hq_observer_freshness_backup_availability_ledger import (
    ObserverFreshnessBackupAvailabilityLedger,
)

_AVAILABILITY_STATES = frozenset({
    "AVAILABLE", "MISSING", "UNAVAILABLE", "INVALID", "MISMATCH", "UNKNOWN",
})


class BackupAvailabilityReconciliationError(ValueError):
    """A backup receipt/availability snapshot is invalid or changed during review."""


def _fail(code: str) -> None:
    raise BackupAvailabilityReconciliationError(code)


def reconcile_backup_availability(
    receipt_ledger: ObserverFreshnessBackupReceiptLedger,
    availability_ledger: ObserverFreshnessBackupAvailabilityLedger,
) -> dict:
    """Reconcile every receipt with the latest observation for its backup.

    Each ledger is independently verified before enumeration. Both ledgers are
    re-verified after their stable read snapshots; a concurrent append causes a
    fail-closed snapshot-change result rather than a mixed report.
    """
    if (
        not isinstance(receipt_ledger, ObserverFreshnessBackupReceiptLedger)
        or receipt_ledger._connection is None
        or not isinstance(availability_ledger, ObserverFreshnessBackupAvailabilityLedger)
        or availability_ledger._connection is None
    ):
        _fail("BACKUP_AVAILABILITY_RECONCILIATION_LEDGER_REQUIRED")

    receipt_before = receipt_ledger.verify()
    availability_before = availability_ledger.verify()
    receipts = receipt_ledger.list_backup_receipts()
    observations = availability_ledger.list_latest_observations()
    receipt_after = receipt_ledger.verify()
    availability_after = availability_ledger.verify()

    if (
        receipt_before["backup_count"] != receipt_after["backup_count"]
        or receipt_before["chain_head_digest"] != receipt_after["chain_head_digest"]
        or availability_before["observation_count"] != availability_after["observation_count"]
        or availability_before["chain_head_hash"] != availability_after["chain_head_hash"]
    ):
        _fail("BACKUP_AVAILABILITY_RECONCILIATION_SNAPSHOT_CHANGED")

    if len(receipts) > 256 or len(observations) > 512:
        _fail("BACKUP_AVAILABILITY_RECONCILIATION_CAPACITY_EXCEEDED")

    receipt_map = {}
    for receipt in receipts:
        if not isinstance(receipt, dict):
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_RECEIPT_INVALID")
        backup_id = receipt.get("backup_id")
        if not isinstance(backup_id, str) or backup_id in receipt_map:
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_RECEIPT_ID_INVALID")
        if any(receipt.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        )):
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_AUTHORIZATION_INVALID")
        receipt_map[backup_id] = receipt

    observation_map = {}
    availability_counts = {state: 0 for state in sorted(_AVAILABILITY_STATES)}
    unknown_count = 0
    orphan_count = 0
    lineage_mismatch_count = 0
    evidence_mismatch_count = 0
    matched_available_count = 0
    matched_nonavailable_count = 0

    for observation in observations:
        if not isinstance(observation, dict):
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_OBSERVATION_INVALID")
        backup_id = observation.get("backup_id")
        state = observation.get("availability")
        if (
            not isinstance(backup_id, str)
            or backup_id in observation_map
            or state not in _AVAILABILITY_STATES
        ):
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_OBSERVATION_ID_INVALID")
        if any(observation.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        )):
            _fail("BACKUP_AVAILABILITY_RECONCILIATION_AUTHORIZATION_INVALID")
        observation_map[backup_id] = observation
        availability_counts[state] += 1

        if state == "UNKNOWN":
            if (
                observation.get("lineage_sequence") is not None
                or observation.get("lineage_record_hash") is not None
            ):
                _fail("BACKUP_AVAILABILITY_RECONCILIATION_UNKNOWN_LINEAGE_INVALID")
            unknown_count += 1
            continue

        receipt = receipt_map.get(backup_id)
        if receipt is None:
            orphan_count += 1
            continue

        if (
            observation.get("lineage_sequence") != receipt.get("backup_count")
            or observation.get("lineage_record_hash") != receipt.get("record_hash")
        ):
            lineage_mismatch_count += 1
            continue

        if state == "AVAILABLE":
            expected = (
                receipt.get("file_sha256"),
                receipt.get("source_receipt_count"),
                receipt.get("source_status_counts"),
                receipt.get("last_source_sequence"),
                receipt.get("source_chain_head_digest"),
            )
            actual = (
                observation.get("file_sha256"),
                observation.get("source_receipt_count"),
                observation.get("source_status_counts"),
                observation.get("last_source_sequence"),
                observation.get("source_chain_head_digest"),
            )
            if actual != expected:
                evidence_mismatch_count += 1
            else:
                matched_available_count += 1
        else:
            matched_nonavailable_count += 1

    missing_observation_count = sum(
        1 for backup_id in receipt_map if backup_id not in observation_map
    )
    structural_issues = (
        missing_observation_count
        + orphan_count
        + unknown_count
        + lineage_mismatch_count
        + evidence_mismatch_count
    )
    if not receipt_map and not observation_map:
        status = "RECONCILED_EMPTY"
    elif structural_issues:
        status = "RECONCILIATION_INCOMPLETE"
    else:
        status = "RECONCILED"

    if not receipt_map:
        artifact_availability = "NO_BACKUPS"
    elif (
        status == "RECONCILED"
        and matched_available_count == len(receipt_map)
    ):
        artifact_availability = "ALL_AVAILABLE"
    else:
        artifact_availability = "PARTIAL_OR_UNAVAILABLE"

    return {
        "status": status,
        "receipt_count": len(receipt_map),
        "latest_observation_count": len(observation_map),
        "history_observation_count": availability_after["observation_count"],
        "matched_available_count": matched_available_count,
        "matched_nonavailable_count": matched_nonavailable_count,
        "missing_observation_count": missing_observation_count,
        "orphan_observation_count": orphan_count,
        "unknown_observation_count": unknown_count,
        "lineage_mismatch_count": lineage_mismatch_count,
        "evidence_mismatch_count": evidence_mismatch_count,
        "availability_counts": dict(sorted(availability_counts.items())),
        "artifact_availability": artifact_availability,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupAvailabilityReconciliationError",
    "reconcile_backup_availability",
]
