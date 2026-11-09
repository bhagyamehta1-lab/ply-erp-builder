"""Independent verifier for aggregate-only recovery-readiness history snapshots."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

MAX_RECOVERY_READINESS_EVALUATIONS = 512
SCHEMA_VERSION = "1.0.0"
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_EVALUATION_ID = re.compile(r"^hqrr_[a-f0-9]{24}$")
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
_REPORT_FIELDS = frozenset({
    "status", "metadata_readiness", "readiness_scope", "blocker_codes",
    "inventory_record_count", "observer_backup_count", "binding_receipt_count",
    "availability_observation_count", "predecessor_link_count",
    "predecessor_available_count", "association_coverage",
    "availability_reconciliation_status", "predecessor_availability_status",
    "recovery_chain_status", "source_snapshot_stable",
    "source_ledger_verification_count", "artifact_bytes_verified",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_COUNT_LIMITS = {
    "inventory_record_count": 256,
    "observer_backup_count": 256,
    "binding_receipt_count": 512,
    "availability_observation_count": 512,
    "predecessor_link_count": 256,
    "predecessor_available_count": 256,
    "source_ledger_verification_count": 4,
}
_SNAPSHOT_FIELDS = frozenset({
    "schema_version", "record_count", "records", "artifact_bytes_verified",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_RECORD_FIELDS = frozenset({
    "schema_version", "sequence", "evaluation_id", "evaluated_at",
    "report_digest", "metadata_readiness", "blocker_count", "report",
    "previous_hash", "record_hash",
})
_RECORD_BODY_FIELDS = (
    "schema_version", "sequence", "evaluation_id", "evaluated_at",
    "report_digest", "metadata_readiness", "blocker_count", "report",
    "previous_hash",
)


class BackupRecoveryReadinessSnapshotError(ValueError):
    """An exported recovery-readiness history snapshot is invalid."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessSnapshotError(code)


def _canonical(value) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_CANONICALIZATION_FAILED")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_TIMESTAMP_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_TIMESTAMP_INVALID")
    canonical = parsed.astimezone(timezone.utc).isoformat(
        timespec="microseconds"
    ).replace("+00:00", "Z")
    if canonical != value:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_TIMESTAMP_NONCANONICAL")
    return parsed.astimezone(timezone.utc)


def validate_backup_recovery_readiness_report(report: Mapping) -> dict:
    """Validate the exact bounded aggregate report accepted by the history ledger."""
    if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_SCHEMA_INVALID")
    value = dict(report)
    if value["status"] != "BACKUP_RECOVERY_READINESS_REPORTED":
        _fail("BACKUP_RECOVERY_READINESS_REPORT_STATUS_INVALID")
    if value["readiness_scope"] != "METADATA_ONLY":
        _fail("BACKUP_RECOVERY_READINESS_REPORT_SCOPE_INVALID")
    if value["metadata_readiness"] not in {"READY", "NOT_READY"}:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_CLASSIFICATION_INVALID")
    if value["association_coverage"] not in {"NONE", "PARTIAL", "COMPLETE"}:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_ASSOCIATION_INVALID")
    if value["availability_reconciliation_status"] not in {
        "RECONCILED", "RECONCILED_EMPTY", "INCOMPLETE"
    }:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_AVAILABILITY_INVALID")
    if value["predecessor_availability_status"] not in {
        "VERIFIED", "NOT_APPLICABLE", "BLOCKED"
    }:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_INVALID")
    if value["recovery_chain_status"] not in {
        "COMPLETE", "INCOMPLETE", "BLOCKED_PREDECESSOR_UNAVAILABLE", "NO_BACKUPS"
    }:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_RECOVERY_INVALID")

    for key, limit in _COUNT_LIMITS.items():
        count = value[key]
        if type(count) is not int or not 0 <= count <= limit:
            _fail("BACKUP_RECOVERY_READINESS_REPORT_COUNT_INVALID")
    if value["source_ledger_verification_count"] != 4:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_FOUR_LEDGER_REQUIRED")
    if value["source_snapshot_stable"] is not True:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_SOURCE_UNSTABLE")
    for key in (
        "artifact_bytes_verified", "execution_authorized",
        "automatic_dispatch", "automatic_retry",
    ):
        if value[key] is not False:
            _fail("BACKUP_RECOVERY_READINESS_REPORT_AUTHORIZATION_INVALID")

    blockers = value["blocker_codes"]
    if (
        not isinstance(blockers, list)
        or len(blockers) > len(_BLOCKER_ORDER)
        or any(not isinstance(code, str) or code not in _BLOCKER_ORDER for code in blockers)
        or len(blockers) != len(set(blockers))
        or blockers != sorted(blockers, key=_BLOCKER_ORDER.index)
    ):
        _fail("BACKUP_RECOVERY_READINESS_REPORT_BLOCKERS_INVALID")

    inventory_count = value["inventory_record_count"]
    observer_count = value["observer_backup_count"]
    if value["predecessor_link_count"] > observer_count:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_TOTAL_INVALID")
    if value["predecessor_available_count"] > value["predecessor_link_count"]:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_TOTAL_INVALID")
    if value["predecessor_link_count"] == 0:
        if value["predecessor_available_count"] != 0 or value["predecessor_availability_status"] != "NOT_APPLICABLE":
            _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_STATUS_INVALID")
    elif value["predecessor_availability_status"] == "NOT_APPLICABLE":
        _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_STATUS_INVALID")
    elif value["predecessor_availability_status"] == "VERIFIED":
        if value["predecessor_available_count"] != value["predecessor_link_count"]:
            _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_STATUS_INVALID")
    elif value["predecessor_available_count"] >= value["predecessor_link_count"]:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_PREDECESSOR_STATUS_INVALID")

    if value["association_coverage"] == "COMPLETE":
        if (
            inventory_count == 0 or observer_count == 0
            or inventory_count != observer_count
            or value["binding_receipt_count"] < observer_count
        ):
            _fail("BACKUP_RECOVERY_READINESS_REPORT_ASSOCIATION_TOTAL_INVALID")
    if value["association_coverage"] == "PARTIAL" and value["binding_receipt_count"] == 0:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_ASSOCIATION_TOTAL_INVALID")

    if value["availability_reconciliation_status"] == "RECONCILED":
        if observer_count == 0 or value["availability_observation_count"] != observer_count:
            _fail("BACKUP_RECOVERY_READINESS_REPORT_AVAILABILITY_TOTAL_INVALID")
    if value["availability_reconciliation_status"] == "RECONCILED_EMPTY":
        if observer_count != 0 or value["availability_observation_count"] != 0:
            _fail("BACKUP_RECOVERY_READINESS_REPORT_AVAILABILITY_TOTAL_INVALID")

    if value["recovery_chain_status"] == "COMPLETE":
        if (
            observer_count == 0
            or value["availability_observation_count"] != observer_count
            or value["availability_reconciliation_status"] != "RECONCILED"
            or value["predecessor_availability_status"] not in {"VERIFIED", "NOT_APPLICABLE"}
        ):
            _fail("BACKUP_RECOVERY_READINESS_REPORT_RECOVERY_TOTAL_INVALID")
    if value["recovery_chain_status"] == "NO_BACKUPS" and observer_count != 0:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_RECOVERY_TOTAL_INVALID")

    if value["metadata_readiness"] == "READY":
        if (
            blockers
            or value["association_coverage"] != "COMPLETE"
            or value["availability_reconciliation_status"] != "RECONCILED"
            or value["predecessor_availability_status"] not in {"VERIFIED", "NOT_APPLICABLE"}
            or value["recovery_chain_status"] != "COMPLETE"
        ):
            _fail("BACKUP_RECOVERY_READINESS_REPORT_READY_CONTRACT_INVALID")
    elif not blockers:
        _fail("BACKUP_RECOVERY_READINESS_REPORT_BLOCKERS_REQUIRED")
    return value


def verify_backup_recovery_readiness_snapshot(snapshot: Mapping) -> dict:
    """Independently verify every bounded readiness-history record and hash link."""
    if not isinstance(snapshot, Mapping) or set(snapshot) != _SNAPSHOT_FIELDS:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_SCHEMA_INVALID")
    if snapshot["schema_version"] != SCHEMA_VERSION:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_VERSION_INVALID")
    count = snapshot["record_count"]
    records = snapshot["records"]
    if type(count) is not int or not 0 <= count <= MAX_RECOVERY_READINESS_EVALUATIONS:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_COUNT_INVALID")
    if not isinstance(records, list) or len(records) != count:
        _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_COUNT_MISMATCH")
    for key in (
        "artifact_bytes_verified", "execution_authorized",
        "automatic_dispatch", "automatic_retry",
    ):
        if snapshot[key] is not False:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_AUTHORIZATION_INVALID")

    previous_hash = None
    previous_time = None
    seen_ids = set()
    ready_count = 0
    not_ready_count = 0
    blocker_count_total = 0

    for expected_sequence, record in enumerate(records, 1):
        if not isinstance(record, Mapping) or set(record) != _RECORD_FIELDS:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_RECORD_SCHEMA_INVALID")
        row = dict(record)
        if row["schema_version"] != SCHEMA_VERSION:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_RECORD_VERSION_INVALID")
        if type(row["sequence"]) is not int or row["sequence"] != expected_sequence:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_SEQUENCE_INVALID")
        evaluation_id = row["evaluation_id"]
        if not isinstance(evaluation_id, str) or not _EVALUATION_ID.fullmatch(evaluation_id):
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_ID_INVALID")
        if evaluation_id in seen_ids:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_DUPLICATE_ID")
        seen_ids.add(evaluation_id)

        evaluated_at = _parse_timestamp(row["evaluated_at"])
        if previous_time is not None and evaluated_at < previous_time:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_TIMESTAMP_ORDER_INVALID")
        previous_time = evaluated_at

        report = validate_backup_recovery_readiness_report(row["report"])
        report_digest = row["report_digest"]
        if not isinstance(report_digest, str) or not _HEX_64.fullmatch(report_digest):
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_REPORT_DIGEST_INVALID")
        if _digest(report) != report_digest:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_REPORT_DIGEST_MISMATCH")

        expected_id = "hqrr_" + _digest({
            "schema_version": SCHEMA_VERSION,
            "evaluated_at": row["evaluated_at"],
            "report_digest": report_digest,
        })[:24]
        if evaluation_id != expected_id:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_ID_MISMATCH")
        if row["metadata_readiness"] != report["metadata_readiness"]:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_CLASSIFICATION_MISMATCH")
        if type(row["blocker_count"]) is not int or row["blocker_count"] != len(report["blocker_codes"]):
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_BLOCKER_COUNT_MISMATCH")
        if row["previous_hash"] != previous_hash:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_PREVIOUS_HASH_MISMATCH")
        record_hash = row["record_hash"]
        if not isinstance(record_hash, str) or not _HEX_64.fullmatch(record_hash):
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_RECORD_HASH_INVALID")
        body = {key: row[key] for key in _RECORD_BODY_FIELDS}
        if _digest(body) != record_hash:
            _fail("BACKUP_RECOVERY_READINESS_SNAPSHOT_RECORD_HASH_MISMATCH")

        previous_hash = record_hash
        if report["metadata_readiness"] == "READY":
            ready_count += 1
        else:
            not_ready_count += 1
        blocker_count_total += row["blocker_count"]

    return {
        "status": "BACKUP_RECOVERY_READINESS_HISTORY_VERIFIED",
        "history_status": "VALID",
        "record_count": count,
        "last_sequence": count,
        "ready_count": ready_count,
        "not_ready_count": not_ready_count,
        "blocker_count_total": blocker_count_total,
        "chain_head_hash": previous_hash,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupRecoveryReadinessSnapshotError",
    "validate_backup_recovery_readiness_report",
    "verify_backup_recovery_readiness_snapshot",
]
