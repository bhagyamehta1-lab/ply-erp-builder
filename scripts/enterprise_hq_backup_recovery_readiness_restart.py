"""Close/reopen and independently verify persistent recovery-readiness history."""
from __future__ import annotations

import os
from collections.abc import Mapping
from datetime import datetime

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)
from scripts.enterprise_hq_backup_recovery_readiness_service import (
    evaluate_and_record_backup_recovery_readiness,
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


class BackupRecoveryReadinessRestartError(RuntimeError):
    """A persisted recovery-readiness evaluation failed close/reopen verification."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessRestartError(code)


def _database_path(value) -> str:
    try:
        path = os.fspath(value)
    except TypeError:
        _fail("BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID")
    if (
        not isinstance(path, str)
        or not path.strip()
        or path == ":memory:"
        or path.startswith("file:")
        or "\x00" in path
    ):
        _fail("BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID")
    return path


def _require_false_flags(value: Mapping, code: str) -> None:
    if not isinstance(value, Mapping) or any(value.get(key) is not False for key in _FALSE_FLAGS):
        _fail(code)


def evaluate_record_and_verify_backup_recovery_readiness_restart(
    inventory,
    observer_receipt_ledger,
    binding_receipt_ledger,
    availability_ledger,
    database,
    *,
    now: datetime | None = None,
) -> dict:
    """Record a four-ledger evaluation, close SQLite, reopen, and verify again.

    The database must be file-backed so the second connection represents a real
    close/reopen boundary. The result is aggregate metadata only. This function
    never restores backup bytes, dispatches work, retries tasks, or changes authority.
    """
    sources = (
        inventory,
        observer_receipt_ledger,
        binding_receipt_ledger,
        availability_ledger,
    )
    if any(source is None for source in sources):
        _fail("BACKUP_RECOVERY_READINESS_RESTART_FOUR_SOURCE_LEDGERS_REQUIRED")
    database_path = _database_path(database)

    try:
        with BackupRecoveryReadinessLedger(database_path) as history:
            recorded = evaluate_and_record_backup_recovery_readiness(
                *sources, history, now=now
            )
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_RESTART_RECORD_FAILED")

    try:
        with BackupRecoveryReadinessLedger(database_path) as reopened:
            recovered = reopened.recover_after_restart()
            snapshot = reopened.export_verification_snapshot()
            ledger_verification = reopened.verify()
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_RESTART_RECOVERY_FAILED")

    try:
        independent = verify_backup_recovery_readiness_snapshot(snapshot)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_RESTART_INDEPENDENT_HISTORY_FAILED")

    try:
        transitions = verify_backup_recovery_readiness_transitions(snapshot)
    except Exception:
        _fail("BACKUP_RECOVERY_READINESS_RESTART_TRANSITION_HISTORY_FAILED")

    if (
        not isinstance(recorded, Mapping)
        or recorded.get("status")
        != "BACKUP_RECOVERY_READINESS_EVALUATION_RECORDED_AND_VERIFIED"
        or not isinstance(snapshot, Mapping)
        or not isinstance(snapshot.get("records"), list)
        or not snapshot["records"]
        or not isinstance(independent, Mapping)
        or independent.get("status")
        != "BACKUP_RECOVERY_READINESS_HISTORY_VERIFIED"
        or independent.get("history_status") != "VALID"
        or not isinstance(ledger_verification, Mapping)
        or dict(ledger_verification) != dict(independent)
        or not isinstance(recovered, Mapping)
        or recovered.get("status")
        != "BACKUP_RECOVERY_READINESS_HISTORY_RECOVERED"
        or recovered.get("recovery_status") != "PASS"
        or not isinstance(transitions, Mapping)
        or transitions.get("status")
        != "BACKUP_RECOVERY_READINESS_TRANSITIONS_VERIFIED"
        or transitions.get("history_status") != "VALID"
    ):
        _fail("BACKUP_RECOVERY_READINESS_RESTART_VERIFICATION_DISAGREEMENT")

    latest = snapshot["records"][-1]
    record_count = independent.get("record_count")
    if (
        latest.get("evaluation_id") != recorded.get("evaluation_id")
        or latest.get("report_digest") != recorded.get("evaluation_digest")
        or latest.get("sequence") != recorded.get("sequence")
        or latest.get("metadata_readiness") != recorded.get("metadata_readiness")
        or latest.get("blocker_count") != recorded.get("blocker_count")
        or recorded.get("evaluation_count") != record_count
        or recorded.get("sequence") != independent.get("last_sequence")
        or recovered.get("recovered_evaluation_count") != record_count
        or recovered.get("last_sequence") != independent.get("last_sequence")
        or recovered.get("chain_head_hash") != independent.get("chain_head_hash")
        or recovered.get("ready_count") != independent.get("ready_count")
        or recovered.get("not_ready_count") != independent.get("not_ready_count")
        or recovered.get("blocker_count_total") != independent.get("blocker_count_total")
        or independent.get("chain_head_hash") != latest.get("record_hash")
        or transitions.get("record_count") != record_count
        or transitions.get("transition_count") != max(0, record_count - 1)
        or transitions.get("latest_readiness") != latest.get("metadata_readiness")
        or transitions.get("latest_blocker_count") != latest.get("blocker_count")
        or recorded.get("source_snapshot_stable") is not True
        or recorded.get("source_ledger_verification_count") != 4
    ):
        _fail("BACKUP_RECOVERY_READINESS_RESTART_READBACK_MISMATCH")

    for value in (recorded, recovered, independent, transitions, snapshot):
        _require_false_flags(
            value, "BACKUP_RECOVERY_READINESS_RESTART_AUTHORIZATION_INVALID"
        )

    if (
        type(recorded.get("created")) is not bool
        or type(recorded.get("already_present")) is not bool
        or recorded["created"] == recorded["already_present"]
    ):
        _fail("BACKUP_RECOVERY_READINESS_RESTART_REPLAY_FLAGS_INVALID")

    return {
        "status": "BACKUP_RECOVERY_READINESS_RESTART_VERIFIED",
        "readiness_scope": "METADATA_ONLY",
        "metadata_readiness": recorded["metadata_readiness"],
        "evaluation_count": record_count,
        "sequence": independent["last_sequence"],
        "blocker_count": latest["blocker_count"],
        "created": recorded["created"],
        "already_present": recorded["already_present"],
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
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "close_reopen_performed": True,
        "restart_recovery_verified": True,
        "independent_history_verification": True,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupRecoveryReadinessRestartError",
    "evaluate_record_and_verify_backup_recovery_readiness_restart",
]
