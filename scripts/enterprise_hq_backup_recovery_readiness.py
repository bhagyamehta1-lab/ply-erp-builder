"""Aggregate-only metadata recovery readiness over four verified local ledgers.

This module does not inspect backup bytes, restore artifacts, persist state, or
authorize execution. A READY result means metadata lineage and availability
evidence are internally consistent; it is not a physical restore certification.
"""
from __future__ import annotations

from collections.abc import Mapping

from scripts.enterprise_hq_backup_generation_continuity import (
    reconcile_backup_generation_continuity,
)

MAX_INVENTORY_RECORDS = 256
MAX_OBSERVER_BACKUPS = 256
MAX_BINDING_RECEIPTS = 512
MAX_AVAILABILITY_OBSERVATIONS = 512

_AVAILABILITY_STATES = frozenset({
    "AVAILABLE", "MISSING", "UNAVAILABLE", "INVALID", "MISMATCH", "UNKNOWN",
})
_SUMMARY_FIELDS = frozenset({
    "status",
    "inventory_record_count",
    "inventory_ledger_type_count",
    "inventory_predecessor_link_count",
    "observer_backup_count",
    "observer_predecessor_link_count",
    "binding_receipt_count",
    "binding_association_pair_count",
    "bound_inventory_count",
    "bound_observer_backup_count",
    "unbound_inventory_count",
    "unbound_observer_backup_count",
    "association_coverage",
    "inventory_entry_digest_verification",
    "binding_receipt_hash_verification",
    "lineage_verification",
    "artifact_bytes_verified",
    "execution_authorized",
    "automatic_dispatch",
    "automatic_retry",
    "availability_reconciliation_status",
    "availability_observation_count",
    "availability_counts",
    "matched_available_backup_count",
    "matched_nonavailable_backup_count",
    "missing_availability_observation_count",
    "unknown_availability_observation_count",
    "orphan_availability_observation_count",
    "availability_lineage_mismatch_count",
    "availability_evidence_mismatch_count",
    "predecessor_link_count",
    "predecessor_available_count",
    "predecessor_missing_observation_count",
    "predecessor_unknown_observation_count",
    "predecessor_nonavailable_count",
    "predecessor_lineage_mismatch_count",
    "predecessor_evidence_mismatch_count",
    "predecessor_availability_status",
    "recovery_chain_status",
    "source_snapshot_stable",
    "source_ledger_verification_count",
})
_COUNT_FIELDS = (
    "inventory_record_count",
    "inventory_ledger_type_count",
    "inventory_predecessor_link_count",
    "observer_backup_count",
    "observer_predecessor_link_count",
    "binding_receipt_count",
    "binding_association_pair_count",
    "bound_inventory_count",
    "bound_observer_backup_count",
    "unbound_inventory_count",
    "unbound_observer_backup_count",
    "availability_observation_count",
    "matched_available_backup_count",
    "matched_nonavailable_backup_count",
    "missing_availability_observation_count",
    "unknown_availability_observation_count",
    "orphan_availability_observation_count",
    "availability_lineage_mismatch_count",
    "availability_evidence_mismatch_count",
    "predecessor_link_count",
    "predecessor_available_count",
    "predecessor_missing_observation_count",
    "predecessor_unknown_observation_count",
    "predecessor_nonavailable_count",
    "predecessor_lineage_mismatch_count",
    "predecessor_evidence_mismatch_count",
    "source_ledger_verification_count",
)
_BLOCKER_ORDER = (
    "NO_BACKUP_EVIDENCE",
    "NO_BINDING_RECEIPTS",
    "ASSOCIATION_COVERAGE_INCOMPLETE",
    "UNBOUND_BACKUP_RECORDS",
    "AVAILABILITY_RECONCILIATION_INCOMPLETE",
    "CURRENT_BACKUP_AVAILABILITY_INCOMPLETE",
    "AVAILABILITY_EVIDENCE_INCOMPLETE",
    "PREDECESSOR_AVAILABILITY_UNVERIFIED",
    "PREDECESSOR_EVIDENCE_INCOMPLETE",
    "RECOVERY_CHAIN_INCOMPLETE",
)


class BackupRecoveryReadinessError(ValueError):
    """The four-ledger recovery-readiness contract is invalid."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessError(code)


def _validate_summary(summary: Mapping) -> dict:
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_FIELDS:
        _fail("BACKUP_RECOVERY_READINESS_SUMMARY_SCHEMA_INVALID")
    if summary.get("status") != "BACKUP_GENERATION_CONTINUITY_VERIFIED":
        _fail("BACKUP_RECOVERY_READINESS_CONTINUITY_STATUS_INVALID")
    if summary.get("source_snapshot_stable") is not True:
        _fail("BACKUP_RECOVERY_READINESS_SOURCE_SNAPSHOT_UNSTABLE")
    if type(summary.get("source_ledger_verification_count")) is not int or summary["source_ledger_verification_count"] != 4:
        _fail("BACKUP_RECOVERY_READINESS_FOUR_LEDGER_VERIFICATION_REQUIRED")

    for flag in (
        "inventory_entry_digest_verification",
        "binding_receipt_hash_verification",
        "lineage_verification",
    ):
        if summary.get(flag) is not True:
            _fail("BACKUP_RECOVERY_READINESS_SOURCE_INTEGRITY_UNVERIFIED")
    for flag in (
        "artifact_bytes_verified",
        "execution_authorized",
        "automatic_dispatch",
        "automatic_retry",
    ):
        if summary.get(flag) is not False:
            _fail("BACKUP_RECOVERY_READINESS_AUTHORIZATION_INVALID")

    limits = {
        "inventory_record_count": MAX_INVENTORY_RECORDS,
        "inventory_ledger_type_count": MAX_INVENTORY_RECORDS,
        "inventory_predecessor_link_count": MAX_INVENTORY_RECORDS,
        "observer_backup_count": MAX_OBSERVER_BACKUPS,
        "observer_predecessor_link_count": MAX_OBSERVER_BACKUPS,
        "binding_receipt_count": MAX_BINDING_RECEIPTS,
        "binding_association_pair_count": MAX_OBSERVER_BACKUPS,
        "bound_inventory_count": MAX_INVENTORY_RECORDS,
        "bound_observer_backup_count": MAX_OBSERVER_BACKUPS,
        "unbound_inventory_count": MAX_INVENTORY_RECORDS,
        "unbound_observer_backup_count": MAX_OBSERVER_BACKUPS,
        "availability_observation_count": MAX_AVAILABILITY_OBSERVATIONS,
        "matched_available_backup_count": MAX_OBSERVER_BACKUPS,
        "matched_nonavailable_backup_count": MAX_OBSERVER_BACKUPS,
        "missing_availability_observation_count": MAX_OBSERVER_BACKUPS,
        "unknown_availability_observation_count": MAX_AVAILABILITY_OBSERVATIONS,
        "orphan_availability_observation_count": MAX_AVAILABILITY_OBSERVATIONS,
        "availability_lineage_mismatch_count": MAX_AVAILABILITY_OBSERVATIONS,
        "availability_evidence_mismatch_count": MAX_AVAILABILITY_OBSERVATIONS,
        "predecessor_link_count": MAX_OBSERVER_BACKUPS,
        "predecessor_available_count": MAX_OBSERVER_BACKUPS,
        "predecessor_missing_observation_count": MAX_OBSERVER_BACKUPS,
        "predecessor_unknown_observation_count": MAX_OBSERVER_BACKUPS,
        "predecessor_nonavailable_count": MAX_OBSERVER_BACKUPS,
        "predecessor_lineage_mismatch_count": MAX_OBSERVER_BACKUPS,
        "predecessor_evidence_mismatch_count": MAX_OBSERVER_BACKUPS,
        "source_ledger_verification_count": 4,
    }
    values = {}
    for key in _COUNT_FIELDS:
        value = summary.get(key)
        if type(value) is not int or not 0 <= value <= limits[key]:
            _fail("BACKUP_RECOVERY_READINESS_COUNT_INVALID")
        values[key] = value
    if values["source_ledger_verification_count"] != 4:
        _fail("BACKUP_RECOVERY_READINESS_FOUR_LEDGER_VERIFICATION_REQUIRED")

    inventory_count = values["inventory_record_count"]
    observer_count = values["observer_backup_count"]
    pair_count = values["binding_association_pair_count"]
    if (
        values["inventory_ledger_type_count"] > inventory_count
        or values["inventory_predecessor_link_count"] > inventory_count
        or values["observer_predecessor_link_count"] != max(0, observer_count - 1)
        or values["binding_receipt_count"] < pair_count
        or pair_count != values["bound_inventory_count"]
        or pair_count != values["bound_observer_backup_count"]
        or pair_count > min(inventory_count, observer_count)
        or values["unbound_inventory_count"] != inventory_count - values["bound_inventory_count"]
        or values["unbound_observer_backup_count"] != observer_count - values["bound_observer_backup_count"]
    ):
        _fail("BACKUP_RECOVERY_READINESS_ASSOCIATION_COUNTS_INVALID")

    availability_counts = summary.get("availability_counts")
    if (
        not isinstance(availability_counts, Mapping)
        or set(availability_counts) != _AVAILABILITY_STATES
        or any(type(value) is not int or not 0 <= value <= MAX_AVAILABILITY_OBSERVATIONS
               for value in availability_counts.values())
        or sum(availability_counts.values()) != values["availability_observation_count"]
        or availability_counts["UNKNOWN"] != values["unknown_availability_observation_count"]
    ):
        _fail("BACKUP_RECOVERY_READINESS_AVAILABILITY_COUNTS_INVALID")

    observation_categories = sum(values[key] for key in (
        "matched_available_backup_count",
        "matched_nonavailable_backup_count",
        "unknown_availability_observation_count",
        "orphan_availability_observation_count",
        "availability_lineage_mismatch_count",
        "availability_evidence_mismatch_count",
    ))
    if (
        observation_categories != values["availability_observation_count"]
        or values["matched_available_backup_count"] > availability_counts["AVAILABLE"]
        or values["matched_available_backup_count"] > observer_count
        or values["matched_nonavailable_backup_count"] > observer_count
        or values["missing_availability_observation_count"] > observer_count
    ):
        _fail("BACKUP_RECOVERY_READINESS_AVAILABILITY_TOTALS_INVALID")

    predecessor_categories = sum(values[key] for key in (
        "predecessor_available_count",
        "predecessor_missing_observation_count",
        "predecessor_unknown_observation_count",
        "predecessor_nonavailable_count",
        "predecessor_lineage_mismatch_count",
        "predecessor_evidence_mismatch_count",
    ))
    if (
        values["predecessor_link_count"] != values["observer_predecessor_link_count"]
        or predecessor_categories != values["predecessor_link_count"]
        or values["predecessor_available_count"] > values["predecessor_link_count"]
    ):
        _fail("BACKUP_RECOVERY_READINESS_PREDECESSOR_TOTALS_INVALID")

    coverage = summary.get("association_coverage")
    if coverage not in {"NONE", "PARTIAL", "COMPLETE"}:
        _fail("BACKUP_RECOVERY_READINESS_ASSOCIATION_STATUS_INVALID")
    expected_coverage = (
        "NONE" if pair_count == 0
        else "COMPLETE" if (
            values["bound_inventory_count"] == inventory_count
            and values["bound_observer_backup_count"] == observer_count
        )
        else "PARTIAL"
    )
    if coverage != expected_coverage:
        _fail("BACKUP_RECOVERY_READINESS_ASSOCIATION_STATUS_INCONSISTENT")

    structural_issues = sum(values[key] for key in (
        "missing_availability_observation_count",
        "unknown_availability_observation_count",
        "orphan_availability_observation_count",
        "availability_lineage_mismatch_count",
        "availability_evidence_mismatch_count",
    ))
    if not observer_count and not values["availability_observation_count"]:
        expected_reconciliation = "RECONCILED_EMPTY"
    elif structural_issues:
        expected_reconciliation = "INCOMPLETE"
    else:
        expected_reconciliation = "RECONCILED"
    reconciliation = summary.get("availability_reconciliation_status")
    if reconciliation != expected_reconciliation:
        _fail("BACKUP_RECOVERY_READINESS_AVAILABILITY_STATUS_INCONSISTENT")

    predecessor_issues = sum(values[key] for key in (
        "predecessor_missing_observation_count",
        "predecessor_unknown_observation_count",
        "predecessor_nonavailable_count",
        "predecessor_lineage_mismatch_count",
        "predecessor_evidence_mismatch_count",
    ))
    if values["predecessor_link_count"] == 0:
        expected_predecessor_status = "NOT_APPLICABLE"
    elif predecessor_issues == 0 and values["predecessor_available_count"] == values["predecessor_link_count"]:
        expected_predecessor_status = "VERIFIED"
    else:
        expected_predecessor_status = "BLOCKED"
    if summary.get("predecessor_availability_status") != expected_predecessor_status:
        _fail("BACKUP_RECOVERY_READINESS_PREDECESSOR_STATUS_INCONSISTENT")

    if not observer_count and not values["availability_observation_count"]:
        expected_recovery_status = "NO_BACKUPS"
    elif predecessor_issues:
        expected_recovery_status = "BLOCKED_PREDECESSOR_UNAVAILABLE"
    elif (
        reconciliation == "RECONCILED"
        and values["matched_available_backup_count"] == observer_count
        and values["matched_nonavailable_backup_count"] == 0
    ):
        expected_recovery_status = "COMPLETE"
    else:
        expected_recovery_status = "INCOMPLETE"
    if summary.get("recovery_chain_status") != expected_recovery_status:
        _fail("BACKUP_RECOVERY_READINESS_RECOVERY_STATUS_INCONSISTENT")
    return dict(summary)


def summarize_backup_recovery_readiness(continuity_result: Mapping) -> dict:
    """Return a bounded aggregate readiness report from a verified four-ledger result."""
    result = _validate_summary(continuity_result)
    values = {key: result[key] for key in _COUNT_FIELDS}
    blockers = set()

    if values["inventory_record_count"] == 0 and values["observer_backup_count"] == 0:
        blockers.add("NO_BACKUP_EVIDENCE")
    if values["binding_receipt_count"] == 0:
        blockers.add("NO_BINDING_RECEIPTS")
    if result["association_coverage"] != "COMPLETE":
        blockers.add("ASSOCIATION_COVERAGE_INCOMPLETE")
    if values["unbound_inventory_count"] or values["unbound_observer_backup_count"]:
        blockers.add("UNBOUND_BACKUP_RECORDS")
    if result["availability_reconciliation_status"] != "RECONCILED":
        blockers.add("AVAILABILITY_RECONCILIATION_INCOMPLETE")
    if (
        values["matched_available_backup_count"] != values["observer_backup_count"]
        or values["matched_nonavailable_backup_count"] != 0
    ):
        blockers.add("CURRENT_BACKUP_AVAILABILITY_INCOMPLETE")
    if any(values[key] for key in (
        "missing_availability_observation_count",
        "unknown_availability_observation_count",
        "orphan_availability_observation_count",
        "availability_lineage_mismatch_count",
        "availability_evidence_mismatch_count",
    )):
        blockers.add("AVAILABILITY_EVIDENCE_INCOMPLETE")
    if result["predecessor_availability_status"] not in {"VERIFIED", "NOT_APPLICABLE"}:
        blockers.add("PREDECESSOR_AVAILABILITY_UNVERIFIED")
    if any(values[key] for key in (
        "predecessor_missing_observation_count",
        "predecessor_unknown_observation_count",
        "predecessor_nonavailable_count",
        "predecessor_lineage_mismatch_count",
        "predecessor_evidence_mismatch_count",
    )):
        blockers.add("PREDECESSOR_EVIDENCE_INCOMPLETE")
    if result["recovery_chain_status"] != "COMPLETE":
        blockers.add("RECOVERY_CHAIN_INCOMPLETE")

    return {
        "status": "BACKUP_RECOVERY_READINESS_REPORTED",
        "metadata_readiness": "READY" if not blockers else "NOT_READY",
        "readiness_scope": "METADATA_ONLY",
        "blocker_codes": [code for code in _BLOCKER_ORDER if code in blockers],
        "inventory_record_count": values["inventory_record_count"],
        "observer_backup_count": values["observer_backup_count"],
        "binding_receipt_count": values["binding_receipt_count"],
        "availability_observation_count": values["availability_observation_count"],
        "predecessor_link_count": values["predecessor_link_count"],
        "predecessor_available_count": values["predecessor_available_count"],
        "association_coverage": result["association_coverage"],
        "availability_reconciliation_status": result["availability_reconciliation_status"],
        "predecessor_availability_status": result["predecessor_availability_status"],
        "recovery_chain_status": result["recovery_chain_status"],
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def reconcile_backup_recovery_readiness(
    inventory,
    observer_receipt_ledger,
    binding_receipt_ledger,
    availability_ledger,
) -> dict:
    """Verify all four source ledgers and return metadata-only recovery readiness."""
    if any(item is None for item in (
        inventory, observer_receipt_ledger, binding_receipt_ledger, availability_ledger
    )):
        _fail("BACKUP_RECOVERY_READINESS_SOURCE_LEDGERS_REQUIRED")
    try:
        continuity = reconcile_backup_generation_continuity(
            inventory,
            observer_receipt_ledger,
            binding_receipt_ledger,
            availability_ledger,
        )
    except Exception as exc:
        raise BackupRecoveryReadinessError(
            "BACKUP_RECOVERY_READINESS_SOURCE_RECONCILIATION_FAILED"
        ) from exc
    return summarize_backup_recovery_readiness(continuity)


__all__ = [
    "BackupRecoveryReadinessError",
    "reconcile_backup_recovery_readiness",
    "summarize_backup_recovery_readiness",
]
