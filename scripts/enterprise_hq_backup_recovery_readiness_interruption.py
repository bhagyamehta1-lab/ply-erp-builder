"""Read-only reconciliation of interrupted recovery-readiness append attempts."""
from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)
from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
    verify_backup_recovery_readiness_snapshot,
)
from scripts.enterprise_hq_backup_recovery_readiness_transitions import (
    verify_backup_recovery_readiness_transitions,
)


_FALSE_FLAGS = (
    "artifact_bytes_verified",
    "execution_authorized",
    "automatic_dispatch",
    "automatic_retry",
)


class BackupRecoveryReadinessInterruptionError(RuntimeError):
    """An interrupted readiness append could not be reconciled safely."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessInterruptionError(code)


def _database_path(value) -> str:
    try:
        path = os.fspath(value)
    except TypeError:
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_PATH_INVALID")
    if (
        not isinstance(path, str)
        or not path.strip()
        or path == ":memory:"
        or path.startswith("file:")
        or "\x00" in path
    ):
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_PATH_INVALID")
    return path


def _require_false_flags(value: Mapping, code: str) -> None:
    if not isinstance(value, Mapping) or any(
        value.get(key) is not False for key in _FALSE_FLAGS
    ):
        _fail(code)


def reconcile_interrupted_backup_recovery_readiness_evaluation(
    database,
    report,
    *,
    now: datetime | None = None,
) -> dict:
    """Inspect whether an exact append committed before its caller was interrupted.

    The database is opened in SQLite read-only mode. The exact original report
    and timezone-aware timestamp are required. A missing record is reported as
    NOT_COMMITTED; this function never retries or writes the evaluation.
    """
    if now is None:
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_TIMESTAMP_REQUIRED")
    database_path = _database_path(database)
    if not Path(database_path).is_file():
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_NOT_FOUND")

    try:
        with BackupRecoveryReadinessLedger(
            database_path, read_only=True
        ) as history:
            inspection = history.inspect_evaluation(report, now=now)
            recovered = history.recover_after_restart()
            snapshot = history.export_verification_snapshot()
            ledger_verification = history.verify()
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_HISTORY_READ_FAILED")

    try:
        independent = verify_backup_recovery_readiness_snapshot(snapshot)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_INDEPENDENT_HISTORY_FAILED")

    try:
        transitions = verify_backup_recovery_readiness_transitions(snapshot)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_TRANSITIONS_FAILED")

    if (
        not isinstance(inspection, Mapping)
        or not isinstance(recovered, Mapping)
        or not isinstance(snapshot, Mapping)
        or not isinstance(snapshot.get("records"), list)
        or not isinstance(independent, Mapping)
        or independent.get("status") != "BACKUP_RECOVERY_READINESS_HISTORY_VERIFIED"
        or independent.get("history_status") != "VALID"
        or not isinstance(ledger_verification, Mapping)
        or dict(ledger_verification) != dict(independent)
        or recovered.get("status") != "BACKUP_RECOVERY_READINESS_HISTORY_RECOVERED"
        or recovered.get("recovery_status") != "PASS"
        or recovered.get("recovered_evaluation_count") != independent.get("record_count")
        or recovered.get("last_sequence") != independent.get("last_sequence")
        or recovered.get("chain_head_hash") != independent.get("chain_head_hash")
        or recovered.get("ready_count") != independent.get("ready_count")
        or recovered.get("not_ready_count") != independent.get("not_ready_count")
        or recovered.get("blocker_count_total") != independent.get("blocker_count_total")
        or not isinstance(transitions, Mapping)
        or transitions.get("status") != "BACKUP_RECOVERY_READINESS_TRANSITIONS_VERIFIED"
        or transitions.get("history_status") != "VALID"
        or transitions.get("record_count") != independent.get("record_count")
        or transitions.get("transition_count") != max(0, independent.get("record_count", 0) - 1)
        or inspection.get("evaluation_count") != independent.get("record_count")
        or inspection.get("chain_head_hash") != independent.get("chain_head_hash")
        or type(inspection.get("found")) is not bool
    ):
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_VERIFICATION_DISAGREEMENT")

    found = inspection["found"]
    expected_status = (
        "BACKUP_RECOVERY_READINESS_EVALUATION_FOUND"
        if found else "BACKUP_RECOVERY_READINESS_EVALUATION_NOT_FOUND"
    )
    if (
        inspection.get("status") != expected_status
        or inspection.get("metadata_readiness") not in {"READY", "NOT_READY"}
        or type(inspection.get("blocker_count")) is not int
        or inspection["blocker_count"] < 0
        or (found and (
            type(inspection.get("sequence")) is not int
            or not 1 <= inspection["sequence"] <= independent["record_count"]
        ))
        or (not found and inspection.get("sequence") is not None)
    ):
        _fail("BACKUP_RECOVERY_READINESS_INTERRUPTION_INSPECTION_INVALID")

    for value in (inspection, recovered, independent, transitions, snapshot):
        _require_false_flags(
            value, "BACKUP_RECOVERY_READINESS_INTERRUPTION_AUTHORIZATION_INVALID"
        )

    return {
        "status": "BACKUP_RECOVERY_READINESS_INTERRUPTION_RECONCILED",
        "outcome": "COMMITTED" if found else "NOT_COMMITTED",
        "evaluation_present": found,
        "next_step": "NO_RETRY_REQUIRED" if found else "MANUAL_REVIEW_REQUIRED",
        "evaluation_count": independent["record_count"],
        "sequence": inspection["sequence"],
        "metadata_readiness": inspection["metadata_readiness"],
        "blocker_count": inspection["blocker_count"],
        "history_status": "VALID",
        "recovery_status": "PASS",
        "transition_status": "VALID",
        "transition_count": transitions["transition_count"],
        "readiness_change_count": transitions["readiness_change_count"],
        "blocker_addition_events": transitions["blocker_addition_events"],
        "blocker_resolution_events": transitions["blocker_resolution_events"],
        "latest_readiness": transitions["latest_readiness"],
        "latest_blocker_count": transitions["latest_blocker_count"],
        "chain_head_hash": independent["chain_head_hash"],
        "inspection_read_only": True,
        "automatic_retry": False,
        "retry_authorized": False,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
    }


__all__ = [
    "BackupRecoveryReadinessInterruptionError",
    "reconcile_interrupted_backup_recovery_readiness_evaluation",
]
