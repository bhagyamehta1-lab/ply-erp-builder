"""Pure resource-budget contracts for bounded Enterprise-HQ internal tasks.

This module validates declared ceilings only. It does not enforce CPU, memory,
network, output, retry, or monetary limits at runtime and never authorizes execution.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from scripts.enterprise_hq_task_contract import (
    ContractError,
    MAX_ATTEMPTS,
    validate_task,
)

BUDGET_FIELDS = frozenset({
    "schema_version",
    "budget_id",
    "task_id",
    "proposal_digest",
    "max_runtime_seconds",
    "max_memory_mib",
    "max_output_bytes",
    "max_network_bytes",
    "max_attempts",
    "cloud_spend_limit_usd",
    "network_mode",
    "paid_services_allowed",
    "external_effects",
    "requires_human_approval",
})
BUDGET_ID_PATTERN = re.compile(r"^HQB-[A-Z0-9](?:[A-Z0-9-]{0,30}[A-Z0-9])?$")

MAX_RUNTIME_SECONDS = 300
MAX_MEMORY_MIB = 512
MAX_OUTPUT_BYTES = 65_536
MAX_NETWORK_BYTES = 0
MAX_CLOUD_SPEND_USD = "0.00"


def _bounded_integer(value: object, minimum: int, maximum: int, error: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(error)
    return value


def validate_resource_budget(task: Mapping, budget: Mapping) -> dict:
    """Validate a zero-spend, offline budget envelope without enforcing it."""
    validated_task = validate_task(task)
    if not isinstance(budget, Mapping) or set(budget) != BUDGET_FIELDS:
        raise ContractError("RESOURCE_BUDGET_SCHEMA_INVALID")
    if budget.get("schema_version") != "1.0.0":
        raise ContractError("RESOURCE_BUDGET_VERSION_INVALID")

    budget_id = budget.get("budget_id")
    if not isinstance(budget_id, str) or not BUDGET_ID_PATTERN.fullmatch(budget_id):
        raise ContractError("RESOURCE_BUDGET_ID_INVALID")
    if budget.get("task_id") != validated_task["task_id"]:
        raise ContractError("RESOURCE_BUDGET_TASK_MISMATCH")
    if budget.get("proposal_digest") != validated_task["idempotency_key"]:
        raise ContractError("RESOURCE_BUDGET_DIGEST_MISMATCH")

    runtime = _bounded_integer(
        budget.get("max_runtime_seconds"), 1, MAX_RUNTIME_SECONDS,
        "RESOURCE_RUNTIME_LIMIT_INVALID",
    )
    memory = _bounded_integer(
        budget.get("max_memory_mib"), 64, MAX_MEMORY_MIB,
        "RESOURCE_MEMORY_LIMIT_INVALID",
    )
    output = _bounded_integer(
        budget.get("max_output_bytes"), 1, MAX_OUTPUT_BYTES,
        "RESOURCE_OUTPUT_LIMIT_INVALID",
    )
    network = _bounded_integer(
        budget.get("max_network_bytes"), 0, MAX_NETWORK_BYTES,
        "RESOURCE_NETWORK_LIMIT_INVALID",
    )
    attempts = _bounded_integer(
        budget.get("max_attempts"), 1, MAX_ATTEMPTS,
        "RESOURCE_ATTEMPT_LIMIT_INVALID",
    )

    if budget.get("cloud_spend_limit_usd") != MAX_CLOUD_SPEND_USD:
        raise ContractError("RESOURCE_PAID_SPEND_FORBIDDEN")
    if budget.get("network_mode") != "DISABLED" or network != 0:
        raise ContractError("RESOURCE_NETWORK_ACCESS_FORBIDDEN")
    if budget.get("paid_services_allowed") is not False:
        raise ContractError("RESOURCE_PAID_SERVICES_FORBIDDEN")
    if budget.get("external_effects") is not False:
        raise ContractError("RESOURCE_EXTERNAL_EFFECTS_FORBIDDEN")
    if budget.get("requires_human_approval") is not True:
        raise ContractError("RESOURCE_HUMAN_REVIEW_REQUIRED")

    return {
        "budget_id": budget_id,
        "task_id": validated_task["task_id"],
        "proposal_digest": validated_task["idempotency_key"],
        "max_runtime_seconds": runtime,
        "max_memory_mib": memory,
        "max_output_bytes": output,
        "max_network_bytes": network,
        "max_attempts": attempts,
        "cloud_spend_limit_usd": MAX_CLOUD_SPEND_USD,
        "network_mode": "DISABLED",
        "paid_services_allowed": False,
        "external_effects": False,
        "human_approval_required": True,
        "budget_status": "STRUCTURE_VALID_ONLY",
        "enforcement_status": "NOT_ENFORCED",
        "identity_assurance": "NOT_AUTHENTICATED",
        "execution_authorized": False,
    }
