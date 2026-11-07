"""Structural validation for parent-company verification receipt envelopes.

This module validates task binding and logical reviewer separation only. It does not
authenticate principals, inspect evidence, perform semantic verification, or authorize
execution. Every accepted receipt remains an untrusted claim for audit review.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime

from scripts.enterprise_hq_task_contract import ContractError, validate_task

RECEIPT_FIELDS = frozenset({
    "schema_version", "receipt_id", "task_id", "proposal_digest",
    "logical_proposer_id", "logical_verifier_id", "proposer_role",
    "verifier_role", "claimed_verdict", "evidence_digest", "reviewed_at",
})
RECEIPT_ID_PATTERN = re.compile(r"^HQV-[A-Z0-9](?:[A-Z0-9-]{0,30}[A-Z0-9])?$")
LOGICAL_ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_VERDICTS = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})
MAX_RECEIPT_BYTES = 1024


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def validate_verification_receipt(task: Mapping, receipt: Mapping) -> dict:
    """Validate a receipt's structure and binding without trusting its claims."""
    validated_task = validate_task(task)
    if not isinstance(receipt, Mapping) or set(receipt) != RECEIPT_FIELDS:
        raise ContractError("VERIFICATION_RECEIPT_SCHEMA_INVALID")

    try:
        encoded = json.dumps(
            dict(receipt), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise ContractError("VERIFICATION_RECEIPT_ENCODING_INVALID") from None
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise ContractError("VERIFICATION_RECEIPT_TOO_LARGE")

    if receipt.get("schema_version") != "1.0.0":
        raise ContractError("VERIFICATION_RECEIPT_VERSION_INVALID")
    receipt_id = receipt.get("receipt_id")
    if not isinstance(receipt_id, str) or not RECEIPT_ID_PATTERN.fullmatch(receipt_id):
        raise ContractError("VERIFICATION_RECEIPT_ID_INVALID")
    if receipt.get("task_id") != validated_task["task_id"]:
        raise ContractError("VERIFICATION_TASK_ID_MISMATCH")
    if receipt.get("proposal_digest") != validated_task["idempotency_key"]:
        raise ContractError("VERIFICATION_PROPOSAL_DIGEST_MISMATCH")

    proposer_id = receipt.get("logical_proposer_id")
    verifier_id = receipt.get("logical_verifier_id")
    if (not isinstance(proposer_id, str) or not LOGICAL_ID_PATTERN.fullmatch(proposer_id)
            or not isinstance(verifier_id, str) or not LOGICAL_ID_PATTERN.fullmatch(verifier_id)):
        raise ContractError("VERIFICATION_LOGICAL_ID_INVALID")
    if proposer_id == verifier_id:
        raise ContractError("VERIFICATION_SELF_REVIEW_FORBIDDEN")

    if receipt.get("proposer_role") != validated_task["logical_role"]:
        raise ContractError("VERIFICATION_PROPOSER_ROLE_MISMATCH")
    if receipt.get("verifier_role") != "INDEPENDENT_VERIFIER":
        raise ContractError("VERIFICATION_VERIFIER_ROLE_INVALID")
    claimed_verdict = receipt.get("claimed_verdict")
    if not isinstance(claimed_verdict, str) or claimed_verdict not in ALLOWED_VERDICTS:
        raise ContractError("VERIFICATION_VERDICT_INVALID")

    evidence_digest = receipt.get("evidence_digest")
    if not isinstance(evidence_digest, str) or not SHA256_PATTERN.fullmatch(evidence_digest):
        raise ContractError("VERIFICATION_EVIDENCE_DIGEST_INVALID")
    if not _valid_timestamp(receipt.get("reviewed_at")):
        raise ContractError("VERIFICATION_TIMESTAMP_INVALID")

    return {
        "receipt_id": receipt_id,
        "task_id": validated_task["task_id"],
        "proposal_digest": validated_task["idempotency_key"],
        "claimed_verdict": claimed_verdict,
        "receipt_status": "STRUCTURE_VALID_ONLY",
        "logical_separation": "DISTINCT_ASSERTED_PRINCIPALS",
        "identity_assurance": "NOT_AUTHENTICATED",
        "evidence_status": "DIGEST_FORMAT_ONLY",
        "semantic_verification": "NOT_PERFORMED",
        "execution_authorized": False,
    }
