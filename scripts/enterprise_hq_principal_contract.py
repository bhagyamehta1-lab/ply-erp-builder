"""Fail-closed contract for externally attested company-worker principals.

This module validates task-bound identity envelopes and delegates cryptographic
verification to an explicitly configured adapter. It contains no trust store,
key retrieval, credential handling, network client, or default verifier.
Without an adapter, validation fails closed. Even an adapter-accepted assertion
does not authorize execution.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Protocol

from scripts.enterprise_hq_task_contract import (
    ContractError,
    TASK_KIND_TO_ROLE,
    validate_task,
)

PRINCIPAL_FIELDS = frozenset({
    "schema_version",
    "issuer",
    "subject",
    "audience",
    "principal_id",
    "principal_type",
    "role",
    "task_id",
    "proposal_digest",
    "lease_id",
    "receipt_id",
    "issued_at",
    "expires_at",
    "nonce",
    "algorithm",
    "key_id",
    "signature",
})
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
PRINCIPAL_ID_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9._:-]{0,63}$")
NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
RECEIPT_ID_PATTERN = re.compile(r"^HQV-[A-Z0-9](?:[A-Z0-9-]{0,30}[A-Z0-9])?$")
SIGNATURE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{86}$")

SUPPORTED_ALGORITHM = "Ed25519"
PRINCIPAL_TYPES = frozenset({"WORKER", "REVIEWER"})
REVIEWER_ROLE = "INDEPENDENT_VERIFIER"
MAX_ATTESTATION_BYTES = 2048
MAX_ATTESTATION_TTL_SECONDS = 900
CLOCK_SKEW_SECONDS = 30


class PrincipalContractError(ContractError):
    """A principal attestation violates the fail-closed identity contract."""


class PrincipalVerifier(Protocol):
    """Adapter contract for an externally configured trust implementation."""

    def verify(
        self,
        *,
        issuer: str,
        audience: str,
        key_id: str,
        algorithm: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        """Return True only when the adapter verifies the signature and trust chain."""


def _identifier(value: object, error_code: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise PrincipalContractError(error_code)
    return value


def _timestamp(value: object, error_code: str) -> datetime:
    if not isinstance(value, str):
        raise PrincipalContractError(error_code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PrincipalContractError(error_code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PrincipalContractError(error_code)
    return parsed


def _canonical_payload(attestation: Mapping) -> bytes:
    unsigned = {key: value for key, value in attestation.items() if key != "signature"}
    try:
        return json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise PrincipalContractError("PRINCIPAL_ENCODING_INVALID") from None


def validate_principal_attestation(
    task: Mapping,
    attestation: Mapping,
    *,
    expected_audience: str,
    now: datetime,
    verifier: PrincipalVerifier | None = None,
    expected_lease_id: str | None = None,
    expected_receipt_id: str | None = None,
) -> dict:
    """Validate task binding and delegate signature/trust checks to an adapter.

    WORKER attestations must bind to the exact task proposal and lease.
    REVIEWER attestations must bind to the exact task proposal and receipt.
    The adapter is mandatory; there is intentionally no permissive fallback.
    """
    validated_task = validate_task(task)
    if not isinstance(attestation, Mapping) or set(attestation) != PRINCIPAL_FIELDS:
        raise PrincipalContractError("PRINCIPAL_SCHEMA_INVALID")
    try:
        encoded = json.dumps(
            dict(attestation), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise PrincipalContractError("PRINCIPAL_ENCODING_INVALID") from None
    if len(encoded) > MAX_ATTESTATION_BYTES:
        raise PrincipalContractError("PRINCIPAL_ATTESTATION_TOO_LARGE")

    if attestation.get("schema_version") != "1.0.0":
        raise PrincipalContractError("PRINCIPAL_SCHEMA_VERSION_INVALID")
    issuer = _identifier(attestation.get("issuer"), "PRINCIPAL_ISSUER_INVALID")
    subject = _identifier(attestation.get("subject"), "PRINCIPAL_SUBJECT_INVALID")
    audience = _identifier(attestation.get("audience"), "PRINCIPAL_AUDIENCE_INVALID")
    principal_id = attestation.get("principal_id")
    if not isinstance(principal_id, str) or not PRINCIPAL_ID_PATTERN.fullmatch(principal_id):
        raise PrincipalContractError("PRINCIPAL_ID_INVALID")
    expected_audience = _identifier(expected_audience, "EXPECTED_AUDIENCE_INVALID")
    if audience != expected_audience:
        raise PrincipalContractError("PRINCIPAL_AUDIENCE_MISMATCH")

    principal_type = attestation.get("principal_type")
    if not isinstance(principal_type, str) or principal_type not in PRINCIPAL_TYPES:
        raise PrincipalContractError("PRINCIPAL_TYPE_INVALID")
    role = attestation.get("role")
    if not isinstance(role, str):
        raise PrincipalContractError("PRINCIPAL_ROLE_INVALID")
    if attestation.get("task_id") != validated_task["task_id"]:
        raise PrincipalContractError("PRINCIPAL_TASK_ID_MISMATCH")
    if attestation.get("proposal_digest") != validated_task["idempotency_key"]:
        raise PrincipalContractError("PRINCIPAL_PROPOSAL_DIGEST_MISMATCH")

    lease_id = attestation.get("lease_id")
    receipt_id = attestation.get("receipt_id")
    if principal_type == "WORKER":
        if role != TASK_KIND_TO_ROLE[validated_task["task_kind"]]:
            raise PrincipalContractError("WORKER_ROLE_MISMATCH")
        if expected_lease_id is None:
            raise PrincipalContractError("EXPECTED_LEASE_BINDING_REQUIRED")
        expected_lease_id = _identifier(
            expected_lease_id, "EXPECTED_LEASE_ID_INVALID"
        )
        if not isinstance(lease_id, str) or lease_id != expected_lease_id:
            raise PrincipalContractError("PRINCIPAL_LEASE_ID_MISMATCH")
        if receipt_id is not None:
            raise PrincipalContractError("WORKER_RECEIPT_BINDING_FORBIDDEN")
        binding = "TASK_AND_LEASE"
    else:
        if role != REVIEWER_ROLE:
            raise PrincipalContractError("REVIEWER_ROLE_INVALID")
        if lease_id is not None:
            raise PrincipalContractError("REVIEWER_LEASE_BINDING_FORBIDDEN")
        if expected_receipt_id is None:
            raise PrincipalContractError("EXPECTED_RECEIPT_BINDING_REQUIRED")
        if (not isinstance(receipt_id, str)
                or not RECEIPT_ID_PATTERN.fullmatch(receipt_id)):
            raise PrincipalContractError("PRINCIPAL_RECEIPT_ID_INVALID")
        if receipt_id != expected_receipt_id:
            raise PrincipalContractError("PRINCIPAL_RECEIPT_ID_MISMATCH")
        binding = "TASK_AND_RECEIPT"

    if attestation.get("algorithm") != SUPPORTED_ALGORITHM:
        raise PrincipalContractError("PRINCIPAL_ALGORITHM_UNSUPPORTED")
    key_id = _identifier(attestation.get("key_id"), "PRINCIPAL_KEY_ID_INVALID")
    nonce = attestation.get("nonce")
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise PrincipalContractError("PRINCIPAL_NONCE_INVALID")

    signature_text = attestation.get("signature")
    if not isinstance(signature_text, str) or not SIGNATURE_PATTERN.fullmatch(signature_text):
        raise PrincipalContractError("PRINCIPAL_SIGNATURE_FORMAT_INVALID")
    try:
        signature = base64.urlsafe_b64decode(signature_text + "==")
    except (ValueError, binascii.Error):
        raise PrincipalContractError("PRINCIPAL_SIGNATURE_FORMAT_INVALID") from None
    if len(signature) != 64:
        raise PrincipalContractError("PRINCIPAL_SIGNATURE_LENGTH_INVALID")

    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalContractError("PRINCIPAL_EVALUATION_TIME_INVALID")
    issued_at = _timestamp(attestation.get("issued_at"), "PRINCIPAL_ISSUED_AT_INVALID")
    expires_at = _timestamp(attestation.get("expires_at"), "PRINCIPAL_EXPIRES_AT_INVALID")
    if expires_at <= issued_at:
        raise PrincipalContractError("PRINCIPAL_TIME_WINDOW_INVALID")
    lifetime = (expires_at - issued_at).total_seconds()
    if lifetime > MAX_ATTESTATION_TTL_SECONDS:
        raise PrincipalContractError("PRINCIPAL_TTL_EXCEEDED")
    skew = timedelta(seconds=CLOCK_SKEW_SECONDS)
    if issued_at > now + skew:
        raise PrincipalContractError("PRINCIPAL_NOT_YET_VALID")
    if expires_at < now - skew:
        raise PrincipalContractError("PRINCIPAL_ATTESTATION_EXPIRED")

    if verifier is None:
        raise PrincipalContractError("IDENTITY_VERIFIER_UNAVAILABLE")
    verify = getattr(verifier, "verify", None)
    if not callable(verify):
        raise PrincipalContractError("IDENTITY_VERIFIER_INTERFACE_INVALID")
    payload = _canonical_payload(attestation)
    try:
        accepted = verify(
            issuer=issuer,
            audience=audience,
            key_id=key_id,
            algorithm=SUPPORTED_ALGORITHM,
            payload=payload,
            signature=signature,
        )
    except Exception:
        raise PrincipalContractError("IDENTITY_VERIFIER_ERROR") from None
    if type(accepted) is not bool:
        raise PrincipalContractError("IDENTITY_VERIFIER_RESULT_INVALID")
    if not accepted:
        raise PrincipalContractError("IDENTITY_SIGNATURE_REJECTED")

    return {
        "task_id": validated_task["task_id"],
        "principal_type": principal_type,
        "role": role,
        "binding": binding,
        "identity_status": "ADAPTER_VERIFICATION_ACCEPTED",
        "identity_assurance": "EXTERNAL_ADAPTER_ASSERTED",
        "execution_authorized": False,
    }
