"""Independent aggregate verification of recovery-readiness history transitions."""
from __future__ import annotations

from collections.abc import Mapping

from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
    BackupRecoveryReadinessSnapshotError,
    verify_backup_recovery_readiness_snapshot,
)


class BackupRecoveryReadinessTransitionError(ValueError):
    """A readiness-history transition report could not be verified."""


def _fail(code: str) -> None:
    raise BackupRecoveryReadinessTransitionError(code)


def verify_backup_recovery_readiness_transitions(snapshot: Mapping) -> dict:
    """Verify a bounded history and summarize adjacent readiness transitions.

    The function reports transition and blocker-change counts only. It does not
    expose evaluation identifiers, timestamps, blocker names, or report bodies.
    A transition is descriptive history, not causal analysis or authorization.
    """
    try:
        history = verify_backup_recovery_readiness_snapshot(snapshot)
    except BackupRecoveryReadinessSnapshotError:
        _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_HISTORY_INVALID")

    if (
        not isinstance(history, Mapping)
        or history.get("history_status") != "VALID"
        or not isinstance(snapshot, Mapping)
        or not isinstance(snapshot.get("records"), list)
        or history.get("record_count") != len(snapshot["records"])
    ):
        _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_HISTORY_INVALID")

    records = snapshot["records"]
    counts = {
        "READY_TO_READY": 0,
        "READY_TO_NOT_READY": 0,
        "NOT_READY_TO_READY": 0,
        "NOT_READY_TO_NOT_READY": 0,
    }
    blocker_addition_events = 0
    blocker_resolution_events = 0

    for previous, current in zip(records, records[1:]):
        previous_state = previous["metadata_readiness"]
        current_state = current["metadata_readiness"]
        transition = f"{previous_state}_TO_{current_state}"
        if transition not in counts:
            _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_CLASSIFICATION_INVALID")
        counts[transition] += 1

        previous_blockers = set(previous["report"]["blocker_codes"])
        current_blockers = set(current["report"]["blocker_codes"])
        added = current_blockers - previous_blockers
        resolved = previous_blockers - current_blockers
        blocker_addition_events += len(added)
        blocker_resolution_events += len(resolved)

        if transition == "READY_TO_NOT_READY" and not added:
            _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_BLOCKER_ADDITION_MISSING")
        if transition == "NOT_READY_TO_READY" and not resolved:
            _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_BLOCKER_RESOLUTION_MISSING")

    transition_count = max(0, len(records) - 1)
    if sum(counts.values()) != transition_count:
        _fail("BACKUP_RECOVERY_READINESS_TRANSITIONS_COUNT_MISMATCH")

    readiness_change_count = (
        counts["READY_TO_NOT_READY"] + counts["NOT_READY_TO_READY"]
    )
    latest = records[-1] if records else None
    return {
        "status": "BACKUP_RECOVERY_READINESS_TRANSITIONS_VERIFIED",
        "history_status": "VALID",
        "record_count": len(records),
        "transition_count": transition_count,
        "ready_to_ready_count": counts["READY_TO_READY"],
        "ready_to_not_ready_count": counts["READY_TO_NOT_READY"],
        "not_ready_to_ready_count": counts["NOT_READY_TO_READY"],
        "not_ready_to_not_ready_count": counts["NOT_READY_TO_NOT_READY"],
        "readiness_change_count": readiness_change_count,
        "blocker_addition_events": blocker_addition_events,
        "blocker_resolution_events": blocker_resolution_events,
        "latest_readiness": latest["metadata_readiness"] if latest else "NONE",
        "latest_blocker_count": latest["blocker_count"] if latest else 0,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupRecoveryReadinessTransitionError",
    "verify_backup_recovery_readiness_transitions",
]
