"""Read-only availability checks for every predecessor in an observer backup chain.

The caller must verify the source receipt and availability ledgers before and
after enumeration. This module correlates only bounded metadata snapshots; it
never opens backup files, restores data, or authorizes execution.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

MAX_BACKUP_RECEIPTS = 256
MAX_AVAILABILITY_OBSERVATIONS = 512

_BACKUP_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")
_OBSERVATION_ID = re.compile(r"^hqba_[a-f0-9]{24}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_FRESHNESS_STATUSES = frozenset({
    "FRESH", "GRACE_PERIOD", "MISSED", "NEVER_OBSERVED", "CLOCK_SKEW",
})
_AVAILABILITY_STATUS = {
    "AVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
    "MISSING": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING",
    "UNAVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
    "INVALID": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_INVALID",
    "MISMATCH": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISMATCH",
    "UNKNOWN": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
}
_RECEIPT_FIELDS = frozenset({
    "backup_count", "backup_id", "file_sha256", "source_receipt_count",
    "source_status_counts", "last_source_sequence", "source_chain_head_digest",
    "predecessor_backup_id", "record_hash", "execution_authorized",
    "automatic_dispatch", "automatic_retry",
})
_OBSERVATION_COMMON_FIELDS = frozenset({
    "status", "availability", "backup_id", "lineage_sequence",
    "lineage_record_hash", "observation_id", "sequence", "record_hash",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_OBSERVATION_AVAILABLE_FIELDS = frozenset({
    "file_sha256", "source_receipt_count", "source_status_counts",
    "last_source_sequence", "source_chain_head_digest",
})


class BackupPredecessorAvailabilityError(ValueError):
    """A backup receipt or latest availability snapshot is malformed."""


def _fail(code: str) -> None:
    raise BackupPredecessorAvailabilityError(code)


def _validate_receipts(records: object) -> tuple[list[dict], dict[str, dict]]:
    if not isinstance(records, list) or len(records) > MAX_BACKUP_RECEIPTS:
        _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_COUNT_INVALID")
    by_id: dict[str, dict] = {}
    previous_id = None
    for expected_sequence, row in enumerate(records, 1):
        if not isinstance(row, Mapping) or set(row) != _RECEIPT_FIELDS:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_SCHEMA_INVALID")
        sequence = row.get("backup_count")
        backup_id = row.get("backup_id")
        file_digest = row.get("file_sha256")
        if type(sequence) is not int or sequence != expected_sequence:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_SEQUENCE_INVALID")
        if (
            not isinstance(file_digest, str) or not _HEX_64.fullmatch(file_digest)
            or not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id)
            or backup_id != "hqfb_" + file_digest[:24]
        ):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_ID_INVALID")
        if backup_id in by_id:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_DUPLICATE_ID")
        if row.get("predecessor_backup_id") != previous_id:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_LINEAGE_INVALID")
        count = row.get("source_receipt_count")
        counts = row.get("source_status_counts")
        last = row.get("last_source_sequence")
        head = row.get("source_chain_head_digest")
        if (
            type(count) is not int or not 0 <= count <= 512
            or not isinstance(counts, Mapping)
            or any(
                key not in _FRESHNESS_STATUSES
                or type(value) is not int or value <= 0
                for key, value in counts.items()
            )
            or sum(counts.values()) != count
        ):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_SUMMARY_INVALID")
        if count == 0:
            if counts or last is not None or head is not None:
                _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_EMPTY_SUMMARY_INVALID")
        elif (
            type(last) is not int or last != count
            or not isinstance(head, str) or not _HEX_64.fullmatch(head)
        ):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_CHAIN_HEAD_INVALID")
        if not isinstance(row.get("record_hash"), str) or not _HEX_64.fullmatch(row["record_hash"]):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_RECEIPT_HASH_INVALID")
        if any(row.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        )):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_AUTHORIZATION_INVALID")
        normalized = dict(row)
        by_id[backup_id] = normalized
        previous_id = backup_id
    return records, by_id


def _validate_observations(observations: object) -> dict[str, dict]:
    if (
        not isinstance(observations, list)
        or len(observations) > MAX_AVAILABILITY_OBSERVATIONS
    ):
        _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_COUNT_INVALID")
    by_backup: dict[str, dict] = {}
    seen_sequences = set()
    seen_observation_ids = set()
    for row in observations:
        if not isinstance(row, Mapping):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_SCHEMA_INVALID")
        state = row.get("availability")
        if not isinstance(state, str) or state not in _AVAILABILITY_STATUS:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_STATE_INVALID")
        expected_fields = _OBSERVATION_COMMON_FIELDS | (
            _OBSERVATION_AVAILABLE_FIELDS if state == "AVAILABLE" else frozenset()
        )
        if set(row) != expected_fields:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_SCHEMA_INVALID")
        backup_id = row.get("backup_id")
        sequence = row.get("sequence")
        observation_id = row.get("observation_id")
        record_hash = row.get("record_hash")
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_ID_INVALID")
        if backup_id in by_backup:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_DUPLICATE_OBSERVATION")
        if type(sequence) is not int or not 1 <= sequence <= MAX_AVAILABILITY_OBSERVATIONS:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_SEQUENCE_INVALID")
        if sequence in seen_sequences:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_DUPLICATE_SEQUENCE")
        if not isinstance(observation_id, str) or not _OBSERVATION_ID.fullmatch(observation_id):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_IDENTITY_INVALID")
        if observation_id in seen_observation_ids:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_DUPLICATE_OBSERVATION_ID")
        if not isinstance(record_hash, str) or not _HEX_64.fullmatch(record_hash):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_OBSERVATION_HASH_INVALID")
        if row.get("status") != _AVAILABILITY_STATUS[state]:
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_STATUS_MISMATCH")
        if any(row.get(flag) is not False for flag in (
            "execution_authorized", "automatic_dispatch", "automatic_retry"
        )):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_AUTHORIZATION_INVALID")
        lineage_sequence = row.get("lineage_sequence")
        lineage_hash = row.get("lineage_record_hash")
        if state == "UNKNOWN":
            if lineage_sequence is not None or lineage_hash is not None:
                _fail("BACKUP_PREDECESSOR_AVAILABILITY_UNKNOWN_LINEAGE_INVALID")
        elif (
            type(lineage_sequence) is not int or lineage_sequence < 1
            or not isinstance(lineage_hash, str) or not _HEX_64.fullmatch(lineage_hash)
        ):
            _fail("BACKUP_PREDECESSOR_AVAILABILITY_LINEAGE_INVALID")
        if state == "AVAILABLE":
            file_digest = row.get("file_sha256")
            count = row.get("source_receipt_count")
            counts = row.get("source_status_counts")
            last = row.get("last_source_sequence")
            head = row.get("source_chain_head_digest")
            if (
                not isinstance(file_digest, str) or not _HEX_64.fullmatch(file_digest)
                or type(count) is not int or not 0 <= count <= 512
                or not isinstance(counts, Mapping)
                or any(
                    key not in _FRESHNESS_STATUSES
                    or type(value) is not int or value <= 0
                    for key, value in counts.items()
                )
                or sum(counts.values()) != count
            ):
                _fail("BACKUP_PREDECESSOR_AVAILABILITY_EVIDENCE_INVALID")
            if count == 0:
                if counts or last is not None or head is not None:
                    _fail("BACKUP_PREDECESSOR_AVAILABILITY_EMPTY_EVIDENCE_INVALID")
            elif (
                type(last) is not int or last != count
                or not isinstance(head, str) or not _HEX_64.fullmatch(head)
            ):
                _fail("BACKUP_PREDECESSOR_AVAILABILITY_EVIDENCE_CHAIN_INVALID")
        seen_sequences.add(sequence)
        seen_observation_ids.add(observation_id)
        by_backup[backup_id] = dict(row)
    return by_backup


def _evidence_matches(receipt: Mapping, observation: Mapping) -> bool:
    return (
        observation.get("file_sha256") == receipt.get("file_sha256")
        and observation.get("source_receipt_count") == receipt.get("source_receipt_count")
        and observation.get("source_status_counts") == receipt.get("source_status_counts")
        and observation.get("last_source_sequence") == receipt.get("last_source_sequence")
        and observation.get("source_chain_head_digest") == receipt.get("source_chain_head_digest")
    )


def _matches_receipt(receipt: Mapping, observation: Mapping) -> bool:
    return (
        observation.get("lineage_sequence") == receipt.get("backup_count")
        and observation.get("lineage_record_hash") == receipt.get("record_hash")
    )


def verify_backup_predecessor_availability_snapshot(
    observer_receipts: object,
    latest_availability_observations: object,
) -> dict:
    """Verify current and predecessor availability using bounded latest snapshots.

    The source ledgers must be independently verified by the caller before and
    after enumeration. This function validates snapshot shape and lineage
    correspondence, then reports aggregate recovery-chain readiness only.
    """
    receipts, receipt_map = _validate_receipts(observer_receipts)
    observations = _validate_observations(latest_availability_observations)

    availability_counts = {state: 0 for state in sorted(_AVAILABILITY_STATUS)}
    matched_available = 0
    matched_nonavailable = 0
    missing_observations = 0
    unknown_observations = 0
    orphan_observations = 0
    lineage_mismatches = 0
    evidence_mismatches = 0

    for backup_id, observation in observations.items():
        state = observation["availability"]
        availability_counts[state] += 1
        receipt = receipt_map.get(backup_id)
        if state == "UNKNOWN":
            unknown_observations += 1
            continue
        if receipt is None:
            orphan_observations += 1
            continue
        if not _matches_receipt(receipt, observation):
            lineage_mismatches += 1
            continue
        if state == "AVAILABLE":
            if _evidence_matches(receipt, observation):
                matched_available += 1
            else:
                evidence_mismatches += 1
        else:
            matched_nonavailable += 1

    for backup_id in receipt_map:
        if backup_id not in observations:
            missing_observations += 1

    predecessor_links = 0
    predecessor_available = 0
    predecessor_missing = 0
    predecessor_unknown = 0
    predecessor_nonavailable = 0
    predecessor_lineage_mismatches = 0
    predecessor_evidence_mismatches = 0
    for receipt in receipts:
        predecessor_id = receipt["predecessor_backup_id"]
        if predecessor_id is None:
            continue
        predecessor_links += 1
        observation = observations.get(predecessor_id)
        predecessor_receipt = receipt_map[predecessor_id]
        if observation is None:
            predecessor_missing += 1
        elif observation["availability"] == "UNKNOWN":
            predecessor_unknown += 1
        elif not _matches_receipt(predecessor_receipt, observation):
            predecessor_lineage_mismatches += 1
        elif observation["availability"] != "AVAILABLE":
            predecessor_nonavailable += 1
        elif not _evidence_matches(predecessor_receipt, observation):
            predecessor_evidence_mismatches += 1
        else:
            predecessor_available += 1

    structural_issues = (
        missing_observations + unknown_observations + orphan_observations
        + lineage_mismatches + evidence_mismatches
    )
    if not receipts and not observations:
        reconciliation_status = "RECONCILED_EMPTY"
    elif structural_issues:
        reconciliation_status = "INCOMPLETE"
    else:
        reconciliation_status = "RECONCILED"

    predecessor_issues = (
        predecessor_missing + predecessor_unknown + predecessor_nonavailable
        + predecessor_lineage_mismatches + predecessor_evidence_mismatches
    )
    if predecessor_links == 0:
        predecessor_status = "NOT_APPLICABLE"
    elif predecessor_issues == 0 and predecessor_available == predecessor_links:
        predecessor_status = "VERIFIED"
    else:
        predecessor_status = "BLOCKED"

    if not receipts and not observations:
        recovery_status = "NO_BACKUPS"
    elif predecessor_issues:
        recovery_status = "BLOCKED_PREDECESSOR_UNAVAILABLE"
    elif (
        reconciliation_status == "RECONCILED"
        and matched_available == len(receipts)
        and matched_nonavailable == 0
    ):
        recovery_status = "COMPLETE"
    else:
        recovery_status = "INCOMPLETE"

    return {
        "availability_reconciliation_status": reconciliation_status,
        "availability_observation_count": len(observations),
        "availability_counts": availability_counts,
        "matched_available_backup_count": matched_available,
        "matched_nonavailable_backup_count": matched_nonavailable,
        "missing_availability_observation_count": missing_observations,
        "unknown_availability_observation_count": unknown_observations,
        "orphan_availability_observation_count": orphan_observations,
        "availability_lineage_mismatch_count": lineage_mismatches,
        "availability_evidence_mismatch_count": evidence_mismatches,
        "predecessor_link_count": predecessor_links,
        "predecessor_available_count": predecessor_available,
        "predecessor_missing_observation_count": predecessor_missing,
        "predecessor_unknown_observation_count": predecessor_unknown,
        "predecessor_nonavailable_count": predecessor_nonavailable,
        "predecessor_lineage_mismatch_count": predecessor_lineage_mismatches,
        "predecessor_evidence_mismatch_count": predecessor_evidence_mismatches,
        "predecessor_availability_status": predecessor_status,
        "recovery_chain_status": recovery_status,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupPredecessorAvailabilityError",
    "verify_backup_predecessor_availability_snapshot",
]
