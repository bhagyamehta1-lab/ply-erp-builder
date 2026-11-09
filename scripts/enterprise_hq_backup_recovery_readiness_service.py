"""Record and independently read back four-ledger recovery-readiness evaluations."""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime

from scripts.enterprise_hq_backup_recovery_readiness import (
    reconcile_backup_recovery_readiness,
)
from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
    verify_backup_recovery_readiness_snapshot,
)

MAX_EVALUATIONS = 512
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_EVALUATION_ID = re.compile(r"^hqrr_[a-f0-9]{24}$")
_RECORD_RESULT_FIELDS = frozenset({
    "status", "evaluation_id", "evaluation_digest", "sequence",
    "evaluation_count", "metadata_readiness", "blocker_count", "created",
    "already_present", "artifact_bytes_verified", "execution_authorized",
    "automatic_dispatch", "automatic_retry",
})


class BackupRecoveryReadinessServiceError(RuntimeError):
    """A recovery-readiness evaluation could not be safely recorded and verified."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessServiceError(code)


def _validate_record_result(result: Mapping) -> dict:
    if not isinstance(result, Mapping) or set(result) != _RECORD_RESULT_FIELDS:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_RECORD_RESULT_SCHEMA_INVALID")
    value = dict(result)
    if value["status"] != "BACKUP_RECOVERY_READINESS_HISTORY_RECORDED":
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_RECORD_STATUS_INVALID")
    if not isinstance(value["evaluation_id"], str) or not _EVALUATION_ID.fullmatch(value["evaluation_id"]):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_EVALUATION_ID_INVALID")
    if not isinstance(value["evaluation_digest"], str) or not _HEX_64.fullmatch(value["evaluation_digest"]):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_EVALUATION_DIGEST_INVALID")
    for key in ("sequence", "evaluation_count"):
        if type(value[key]) is not int or not 1 <= value[key] <= MAX_EVALUATIONS:
            _fail("BACKUP_RECOVERY_READINESS_SERVICE_RECORD_COUNT_INVALID")
    if value["sequence"] != value["evaluation_count"]:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_RECORD_SEQUENCE_INVALID")
    if value["metadata_readiness"] not in {"READY", "NOT_READY"}:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_CLASSIFICATION_INVALID")
    if type(value["blocker_count"]) is not int or not 0 <= value["blocker_count"] <= 10:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_BLOCKER_COUNT_INVALID")
    if type(value["created"]) is not bool or type(value["already_present"]) is not bool:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_REPLAY_FLAGS_INVALID")
    if value["created"] == value["already_present"]:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_REPLAY_FLAGS_INVALID")
    for key in (
        "artifact_bytes_verified", "execution_authorized",
        "automatic_dispatch", "automatic_retry",
    ):
        if value[key] is not False:
            _fail("BACKUP_RECOVERY_READINESS_SERVICE_AUTHORIZATION_INVALID")
    return value


def evaluate_and_record_backup_recovery_readiness(
    inventory,
    observer_receipt_ledger,
    binding_receipt_ledger,
    availability_ledger,
    history_ledger,
    *,
    now: datetime | None = None,
) -> dict:
    """Reconcile four source ledgers, persist the aggregate report, and verify readback.

    A post-write readback failure is reported explicitly. The append-only record is
    not rolled back; callers should inspect the history before retrying. This
    function does not claim that a process restart occurred.
    """
    sources = (
        inventory,
        observer_receipt_ledger,
        binding_receipt_ledger,
        availability_ledger,
    )
    if any(item is None for item in sources):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_FOUR_SOURCE_LEDGERS_REQUIRED")
    if history_ledger is None or any(
        not callable(getattr(history_ledger, name, None))
        for name in (
            "record_readiness_report",
            "export_verification_snapshot",
            "verify",
        )
    ):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_LEDGER_REQUIRED")

    try:
        report = reconcile_backup_recovery_readiness(*sources)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_SOURCE_RECONCILIATION_FAILED")

    try:
        record_result = _validate_record_result(
            history_ledger.record_readiness_report(report, now=now)
        )
    except BackupRecoveryReadinessServiceError:
        raise
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_RECORD_FAILED")

    try:
        snapshot = history_ledger.export_verification_snapshot()
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_EXPORT_FAILED")

    try:
        independent = verify_backup_recovery_readiness_snapshot(snapshot)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_INDEPENDENT_VERIFICATION_FAILED")

    try:
        ledger_verification = history_ledger.verify()
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_LEDGER_VERIFICATION_FAILED")

    if (
        not isinstance(snapshot, Mapping)
        or not isinstance(snapshot.get("records"), list)
        or not snapshot["records"]
        or not isinstance(independent, Mapping)
        or independent.get("status") != "BACKUP_RECOVERY_READINESS_HISTORY_VERIFIED"
        or independent.get("history_status") != "VALID"
        or not isinstance(ledger_verification, Mapping)
        or dict(ledger_verification) != dict(independent)
    ):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_VERIFICATION_DISAGREEMENT")

    latest = snapshot["records"][-1]
    expected = {
        "evaluation_id": record_result["evaluation_id"],
        "report_digest": record_result["evaluation_digest"],
        "sequence": record_result["sequence"],
        "metadata_readiness": record_result["metadata_readiness"],
        "blocker_count": record_result["blocker_count"],
        "report": dict(report),
    }
    if any(latest.get(key) != value for key, value in expected.items()):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_READBACK_MISMATCH")
    if (
        independent.get("record_count") != record_result["evaluation_count"]
        or independent.get("last_sequence") != record_result["sequence"]
        or independent.get("chain_head_hash") != latest.get("record_hash")
        or not isinstance(independent.get("chain_head_hash"), str)
        or not _HEX_64.fullmatch(independent["chain_head_hash"])
    ):
        _fail("BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_HEAD_MISMATCH")

    return {
        "status": "BACKUP_RECOVERY_READINESS_EVALUATION_RECORDED_AND_VERIFIED",
        "metadata_readiness": record_result["metadata_readiness"],
        "readiness_scope": "METADATA_ONLY",
        "blocker_codes": list(report["blocker_codes"]),
        "evaluation_id": record_result["evaluation_id"],
        "evaluation_digest": record_result["evaluation_digest"],
        "sequence": record_result["sequence"],
        "evaluation_count": independent["record_count"],
        "blocker_count": record_result["blocker_count"],
        "created": record_result["created"],
        "already_present": record_result["already_present"],
        "history_status": independent["history_status"],
        "chain_head_hash": independent["chain_head_hash"],
        "independent_history_verification": True,
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupRecoveryReadinessServiceError",
    "evaluate_and_record_backup_recovery_readiness",
]
