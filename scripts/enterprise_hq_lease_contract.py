"""Pure lease-envelope and recovery-transition contracts for Enterprise-HQ.

This module validates bounded, task-bound lease claims. It does not issue or persist
leases, authenticate principals, start workers, retry tasks, dispatch product work,
or authorize execution. Every accepted owner identifier remains an untrusted claim.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone

from scripts.enterprise_hq_task_contract import (
    ContractError,
    MAX_ATTEMPTS,
    validate_task,
)

LEASE_FIELDS = frozenset({
    "schema_version",
    "lease_id",
    "task_id",
    "proposal_digest",
    "logical_owner_id",
    "attempt",
    "issued_at",
    "expires_at",
})
LEASE_ID_PATTERN = re.compile(r"^HQL-[A-Z0-9](?:[A-Z0-9-]{0,30}[A-Z0-9])?$")
LOGICAL_OWNER_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,63}$")
MAX_LEASE_SECONDS = 15 * 60
MAX_LEASE_BYTES = 1024


def _aware_utc(value: object, error_code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ContractError(error_code)
    return value.astimezone(timezone.utc)


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ContractError("LEASE_TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("LEASE_TIMESTAMP_INVALID") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ContractError("LEASE_TIMESTAMP_INVALID")
    return parsed.astimezone(timezone.utc)


def _timestamp_text(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_lease(task: Mapping, lease: Mapping, now: datetime) -> dict:
    """Validate task binding, owner syntax, attempt bounds and a 15-minute lease window."""
    validated_task = validate_task(task)
    current = _aware_utc(now, "LEASE_NOW_INVALID")
    if not isinstance(lease, Mapping) or set(lease) != LEASE_FIELDS:
        raise ContractError("LEASE_SCHEMA_INVALID")

    try:
        encoded = json.dumps(
            dict(lease), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ContractError("LEASE_ENCODING_INVALID") from None
    if len(encoded) > MAX_LEASE_BYTES:
        raise ContractError("LEASE_TOO_LARGE")

    if lease.get("schema_version") != "1.0.0":
        raise ContractError("LEASE_VERSION_INVALID")
    lease_id = lease.get("lease_id")
    if not isinstance(lease_id, str) or not LEASE_ID_PATTERN.fullmatch(lease_id):
        raise ContractError("LEASE_ID_INVALID")
    if lease.get("task_id") != validated_task["task_id"]:
        raise ContractError("LEASE_TASK_ID_MISMATCH")
    if lease.get("proposal_digest") != validated_task["idempotency_key"]:
        raise ContractError("LEASE_PROPOSAL_DIGEST_MISMATCH")

    owner_id = lease.get("logical_owner_id")
    if not isinstance(owner_id, str) or not LOGICAL_OWNER_PATTERN.fullmatch(owner_id):
        raise ContractError("LEASE_OWNER_ID_INVALID")
    attempt = lease.get("attempt")
    if type(attempt) is not int or not 1 <= attempt <= MAX_ATTEMPTS:
        raise ContractError("LEASE_ATTEMPT_INVALID")

    issued_at = _parse_timestamp(lease.get("issued_at"))
    expires_at = _parse_timestamp(lease.get("expires_at"))
    if expires_at <= issued_at:
        raise ContractError("LEASE_WINDOW_INVALID")
    duration = (expires_at - issued_at).total_seconds()
    if duration > MAX_LEASE_SECONDS:
        raise ContractError("LEASE_DURATION_EXCEEDED")

    if current < issued_at:
        status = "NOT_YET_VALID"
    elif current >= expires_at:
        status = "EXPIRED"
    else:
        status = "ACTIVE"

    return {
        "lease_id": lease_id,
        "task_id": validated_task["task_id"],
        "proposal_digest": validated_task["idempotency_key"],
        "logical_owner_id": owner_id,
        "attempt": attempt,
        "issued_at": _timestamp_text(issued_at),
        "expires_at": _timestamp_text(expires_at),
        "lease_status": status,
        "identity_assurance": "NOT_AUTHENTICATED",
        "lease_persisted": False,
        "execution_authorized": False,
    }


def lease_recovery_decision(
    task: Mapping,
    lease: Mapping,
    now: datetime,
    side_effects_started: bool,
) -> dict:
    """Classify an expired lease without retrying or changing any task state."""
    if type(side_effects_started) is not bool:
        raise ContractError("RECOVERY_FLAGS_INVALID")
    validated = validate_lease(task, lease, now)
    if validated["lease_status"] != "EXPIRED":
        decision = "NO_ACTION"
    elif side_effects_started or validated["attempt"] >= MAX_ATTEMPTS:
        decision = "HUMAN_REVIEW_REQUIRED"
    else:
        decision = "RETRY_ELIGIBLE"

    return {
        "lease_id": validated["lease_id"],
        "task_id": validated["task_id"],
        "recovery_decision": decision,
        "human_approval_required": True,
        "automatic_retry": False,
        "execution_authorized": False,
        "identity_assurance": "NOT_AUTHENTICATED",
    }


def validate_recovery_successor(
    task: Mapping,
    expired_lease: Mapping,
    successor_lease: Mapping,
    now: datetime,
    side_effects_started: bool,
) -> dict:
    """Validate a proposed successor lease; never issues or persists it."""
    if type(side_effects_started) is not bool:
        raise ContractError("RECOVERY_FLAGS_INVALID")
    previous = validate_lease(task, expired_lease, now)
    if previous["lease_status"] != "EXPIRED":
        raise ContractError("PRIOR_LEASE_NOT_EXPIRED")
    if side_effects_started:
        raise ContractError("RECOVERY_SIDE_EFFECTS_REQUIRE_HUMAN")
    if previous["attempt"] >= MAX_ATTEMPTS:
        raise ContractError("RECOVERY_ATTEMPTS_EXHAUSTED")

    successor = validate_lease(task, successor_lease, now)
    if successor["lease_status"] == "EXPIRED":
        raise ContractError("SUCCESSOR_LEASE_ALREADY_EXPIRED")
    if successor["lease_id"] == previous["lease_id"]:
        raise ContractError("SUCCESSOR_LEASE_ID_REUSED")
    if successor["task_id"] != previous["task_id"]:
        raise ContractError("SUCCESSOR_TASK_MISMATCH")
    if successor["proposal_digest"] != previous["proposal_digest"]:
        raise ContractError("SUCCESSOR_PROPOSAL_MISMATCH")
    if successor["attempt"] != previous["attempt"] + 1:
        raise ContractError("SUCCESSOR_ATTEMPT_INVALID")
    if _parse_timestamp(successor["issued_at"]) < _parse_timestamp(previous["expires_at"]):
        raise ContractError("SUCCESSOR_LEASE_OVERLAPS_PRIOR")

    return {
        "task_id": previous["task_id"],
        "previous_lease_id": previous["lease_id"],
        "successor_lease_id": successor["lease_id"],
        "transition_status": "RECOVERY_PROPOSAL_VALIDATION_ONLY",
        "human_approval_required": True,
        "automatic_retry": False,
        "execution_authorized": False,
        "identity_assurance": "NOT_AUTHENTICATED",
    }
