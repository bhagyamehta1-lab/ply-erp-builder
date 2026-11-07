"""Pure, deterministic contracts for parent-company internal task planning.

This module validates plans and emits audit metadata only. It never executes tasks,
dispatches product work, accesses the network, or invokes an LLM/provider.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

ALLOWED_WORKSTREAMS = frozenset(f"WS-{number:02d}" for number in range(1, 12))
TASK_KIND_TO_ROLE = {
    "INTERNAL_RESEARCH": "RESEARCH_ANALYST",
    "INTERNAL_DOCUMENTATION": "DOCUMENTATION_STEWARD",
    "INTERNAL_CODE": "CODE_MAINTAINER",
    "READ_ONLY_AUDIT": "READ_ONLY_AUDITOR",
}
ALLOWED_LOGICAL_ROLES = frozenset((*TASK_KIND_TO_ROLE.values(), "INDEPENDENT_VERIFIER"))
ALLOWED_AUDIT_EVENTS = frozenset({
    "TASK_PROPOSED",
    "TASK_ROUTED",
    "VERIFICATION_REQUESTED",
    "RECOVERY_REVIEW_REQUIRED",
})
TASK_FIELDS = frozenset({
    "task_id",
    "workstream_id",
    "task_kind",
    "attempt",
    "status",
    "external_effects",
    "requires_human_approval",
})
TASK_ID_PATTERN = re.compile(r"^HQ-[A-Z0-9][A-Z0-9-]{1,31}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
MAX_TASKS_PER_BATCH = 8
MAX_TASK_BYTES = 2048
MAX_BATCH_BYTES = 8192
MAX_ATTEMPTS = 2


class ContractError(ValueError):
    """A task plan violates the deterministic parent-company contract."""


def _canonical_bytes(value: Mapping) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _validate_task_id(task_id: object) -> str:
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
        raise ContractError("TASK_ID_INVALID")
    return task_id


def validate_task(task: Mapping) -> dict:
    if not isinstance(task, Mapping) or set(task) != TASK_FIELDS:
        raise ContractError("TASK_SCHEMA_INVALID")
    task_id = _validate_task_id(task["task_id"])
    workstream_id = task["workstream_id"]
    task_kind = task["task_kind"]
    if workstream_id not in ALLOWED_WORKSTREAMS:
        raise ContractError("WORKSTREAM_NOT_ALLOWED")
    if task_kind not in TASK_KIND_TO_ROLE:
        raise ContractError("TASK_KIND_NOT_ALLOWED")
    if type(task["attempt"]) is not int or task["attempt"] != 0:
        raise ContractError("INITIAL_ATTEMPT_MUST_BE_ZERO")
    if task["status"] != "PROPOSED":
        raise ContractError("TASK_MUST_START_PROPOSED")
    if task["external_effects"] is not False:
        raise ContractError("EXTERNAL_EFFECTS_FORBIDDEN")
    if task["requires_human_approval"] is not True:
        raise ContractError("HUMAN_REVIEW_REQUIRED")
    try:
        encoded = _canonical_bytes(task)
    except (TypeError, ValueError):
        raise ContractError("TASK_ENCODING_INVALID") from None
    if len(encoded) > MAX_TASK_BYTES:
        raise ContractError("TASK_TOO_LARGE")
    role = TASK_KIND_TO_ROLE[task_kind]
    return {
        "task_id": task_id,
        "workstream_id": workstream_id,
        "task_kind": task_kind,
        "attempt": 0,
        "status": "PROPOSED",
        "logical_role": role,
        "idempotency_key": hashlib.sha256(encoded).hexdigest(),
    }


def validate_batch(tasks: list) -> list[dict]:
    if not isinstance(tasks, list) or len(tasks) > MAX_TASKS_PER_BATCH:
        raise ContractError("BATCH_SIZE_INVALID")
    normalized = [validate_task(task) for task in tasks]
    identifiers = [task["task_id"] for task in normalized]
    if len(identifiers) != len(set(identifiers)):
        raise ContractError("DUPLICATE_TASK_ID")
    batch_size = sum(len(_canonical_bytes(task)) for task in tasks)
    if batch_size > MAX_BATCH_BYTES:
        raise ContractError("BATCH_TOO_LARGE")
    return normalized


def route_task(task: Mapping) -> dict:
    """Return a logical role assignment; this is not an authenticated worker identity."""
    return validate_task(task)


def verification_plan(validated_task: Mapping) -> dict:
    if not isinstance(validated_task, Mapping) or validated_task.get("logical_role") not in TASK_KIND_TO_ROLE.values():
        raise ContractError("ASSIGNEE_ROLE_INVALID")
    return {
        "task_id": _validate_task_id(validated_task.get("task_id")),
        "assignee_role": validated_task["logical_role"],
        "verifier_role": "INDEPENDENT_VERIFIER",
        "verification_status": "REVIEW_REQUIRED",
        "identity_assurance": "NOT_AUTHENTICATED",
    }


def recovery_decision(attempts: int, lease_expired: bool, side_effects_started: bool) -> str:
    if type(attempts) is not int or not 0 <= attempts <= MAX_ATTEMPTS:
        raise ContractError("ATTEMPT_COUNT_INVALID")
    if type(lease_expired) is not bool or type(side_effects_started) is not bool:
        raise ContractError("RECOVERY_FLAGS_INVALID")
    if not lease_expired:
        return "NO_ACTION"
    if side_effects_started or attempts >= MAX_ATTEMPTS:
        return "HUMAN_REVIEW_REQUIRED"
    return "RETRY_ELIGIBLE"


def make_audit_record(
    task_id: str,
    event: str,
    logical_role: str,
    previous_hash: str | None = None,
) -> dict:
    task_id = _validate_task_id(task_id)
    if event not in ALLOWED_AUDIT_EVENTS or logical_role not in ALLOWED_LOGICAL_ROLES:
        raise ContractError("AUDIT_EVENT_OR_ROLE_INVALID")
    if previous_hash is not None and (
        not isinstance(previous_hash, str) or not SHA256_PATTERN.fullmatch(previous_hash)
    ):
        raise ContractError("PREVIOUS_HASH_INVALID")
    body = {
        "schema_version": "1.0.0",
        "task_id": task_id,
        "event": event,
        "logical_role": logical_role,
        "previous_hash": previous_hash,
    }
    return {**body, "record_hash": hashlib.sha256(_canonical_bytes(body)).hexdigest()}


def verify_audit_chain(records: list) -> bool:
    if not isinstance(records, list):
        return False
    previous_hash = None
    expected_fields = {
        "schema_version", "task_id", "event", "logical_role", "previous_hash", "record_hash"
    }
    for record in records:
        if not isinstance(record, Mapping) or set(record) != expected_fields:
            return False
        if record.get("previous_hash") != previous_hash:
            return False
        try:
            _validate_task_id(record.get("task_id"))
        except ContractError:
            return False
        if record.get("schema_version") != "1.0.0":
            return False
        if record.get("event") not in ALLOWED_AUDIT_EVENTS:
            return False
        if record.get("logical_role") not in ALLOWED_LOGICAL_ROLES:
            return False
        body = {key: value for key, value in record.items() if key != "record_hash"}
        expected_hash = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        if record.get("record_hash") != expected_hash:
            return False
        previous_hash = expected_hash
    return True
