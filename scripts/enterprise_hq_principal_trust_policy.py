"""Fail-closed structural policy matching for principal attestations.

This module validates an explicitly supplied issuer/key policy envelope before a
cryptographic verifier is called. It is deliberately NOT a trust store: policy
objects are caller-supplied and unauthenticated, no keys are loaded, and a match
never authenticates a principal or authorizes execution.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime

POLICY_FIELDS = frozenset({
    "schema_version",
    "policy_id",
    "issuer",
    "key_id",
    "algorithm",
    "key_fingerprint",
    "audiences",
    "principal_types",
    "not_before",
    "not_after",
    "status",
    "revoked_at",
})
POLICY_ID = re.compile(r"^HQT-[A-Z0-9](?:[A-Z0-9-]{0,30}[A-Z0-9])?$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
PRINCIPAL_TYPES = frozenset({"WORKER", "REVIEWER"})
SUPPORTED_ALGORITHM = "Ed25519"
POLICY_STATUSES = frozenset({"ACTIVE", "DISABLED", "REVOKED"})
MAX_POLICY_BYTES = 4096
MAX_AUDIENCES = 8


class PrincipalTrustPolicyError(ValueError):
    """A supplied principal trust-policy envelope is invalid or non-matching."""


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise PrincipalTrustPolicyError(code)
    return value


def _timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise PrincipalTrustPolicyError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PrincipalTrustPolicyError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PrincipalTrustPolicyError(code)
    return parsed


def _string_set(value: object, code: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > MAX_AUDIENCES:
        raise PrincipalTrustPolicyError(code)
    if any(not isinstance(item, str) for item in value) or len(set(value)) != len(value):
        raise PrincipalTrustPolicyError(code)
    for item in value:
        _identifier(item, code)
        if allowed is not None and item not in allowed:
            raise PrincipalTrustPolicyError(code)
    return tuple(value)


def _canonical_digest(value: Mapping) -> str:
    try:
        rendered = json.dumps(
            dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise PrincipalTrustPolicyError("TRUST_POLICY_ENCODING_INVALID") from None
    return hashlib.sha256(rendered).hexdigest()


def evaluate_principal_trust_policy(
    attestation: Mapping,
    policy: Mapping | None,
    *,
    now: datetime,
) -> dict:
    """Match an attestation to an explicitly supplied, untrusted policy envelope.

    A successful result means only that the supplied policy fields match. The
    caller must still perform cryptographic signature/trust-chain verification
    using a separately configured adapter. This function has no I/O or side effects.
    """
    if policy is None:
        raise PrincipalTrustPolicyError("TRUST_POLICY_UNAVAILABLE")
    if not isinstance(attestation, Mapping):
        raise PrincipalTrustPolicyError("PRINCIPAL_ATTESTATION_INVALID")
    if not isinstance(policy, Mapping) or set(policy) != POLICY_FIELDS:
        raise PrincipalTrustPolicyError("TRUST_POLICY_SCHEMA_INVALID")

    try:
        encoded = json.dumps(
            dict(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise PrincipalTrustPolicyError("TRUST_POLICY_ENCODING_INVALID") from None
    if len(encoded) > MAX_POLICY_BYTES:
        raise PrincipalTrustPolicyError("TRUST_POLICY_TOO_LARGE")

    if policy.get("schema_version") != "1.0.0":
        raise PrincipalTrustPolicyError("TRUST_POLICY_VERSION_INVALID")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not POLICY_ID.fullmatch(policy_id):
        raise PrincipalTrustPolicyError("TRUST_POLICY_ID_INVALID")

    issuer = _identifier(policy.get("issuer"), "TRUST_POLICY_ISSUER_INVALID")
    key_id = _identifier(policy.get("key_id"), "TRUST_POLICY_KEY_ID_INVALID")
    algorithm = policy.get("algorithm")
    if algorithm != SUPPORTED_ALGORITHM:
        raise PrincipalTrustPolicyError("TRUST_POLICY_ALGORITHM_UNSUPPORTED")
    fingerprint = policy.get("key_fingerprint")
    if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
        raise PrincipalTrustPolicyError("TRUST_POLICY_FINGERPRINT_INVALID")

    audiences = _string_set(policy.get("audiences"), "TRUST_POLICY_AUDIENCES_INVALID")
    principal_types = _string_set(
        policy.get("principal_types"), "TRUST_POLICY_PRINCIPAL_TYPES_INVALID",
        allowed=PRINCIPAL_TYPES,
    )

    status = policy.get("status")
    if not isinstance(status, str) or status not in POLICY_STATUSES:
        raise PrincipalTrustPolicyError("TRUST_POLICY_STATUS_INVALID")
    revoked_at_value = policy.get("revoked_at")
    if status == "REVOKED":
        if revoked_at_value is None:
            raise PrincipalTrustPolicyError("TRUST_POLICY_REVOCATION_TIME_REQUIRED")
        _timestamp(revoked_at_value, "TRUST_POLICY_REVOCATION_TIME_INVALID")
        raise PrincipalTrustPolicyError("TRUST_POLICY_REVOKED")
    if revoked_at_value is not None:
        raise PrincipalTrustPolicyError("TRUST_POLICY_REVOCATION_STATE_INVALID")
    if status == "DISABLED":
        raise PrincipalTrustPolicyError("TRUST_POLICY_DISABLED")

    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise PrincipalTrustPolicyError("TRUST_POLICY_EVALUATION_TIME_INVALID")
    not_before = _timestamp(policy.get("not_before"), "TRUST_POLICY_NOT_BEFORE_INVALID")
    not_after = _timestamp(policy.get("not_after"), "TRUST_POLICY_NOT_AFTER_INVALID")
    if not_after <= not_before:
        raise PrincipalTrustPolicyError("TRUST_POLICY_TIME_WINDOW_INVALID")
    if now < not_before:
        raise PrincipalTrustPolicyError("TRUST_POLICY_NOT_YET_VALID")
    if now > not_after:
        raise PrincipalTrustPolicyError("TRUST_POLICY_EXPIRED")

    expected = {
        "issuer": issuer,
        "key_id": key_id,
        "algorithm": algorithm,
    }
    for field, value in expected.items():
        if attestation.get(field) != value:
            raise PrincipalTrustPolicyError(f"TRUST_POLICY_{field.upper()}_MISMATCH")

    audience = _identifier(attestation.get("audience"), "PRINCIPAL_AUDIENCE_INVALID")
    if audience not in audiences:
        raise PrincipalTrustPolicyError("TRUST_POLICY_AUDIENCE_NOT_ALLOWED")
    principal_type = attestation.get("principal_type")
    if principal_type not in principal_types:
        raise PrincipalTrustPolicyError("TRUST_POLICY_PRINCIPAL_TYPE_NOT_ALLOWED")

    issued_at = _timestamp(attestation.get("issued_at"), "PRINCIPAL_ISSUED_AT_INVALID")
    expires_at = _timestamp(attestation.get("expires_at"), "PRINCIPAL_EXPIRES_AT_INVALID")
    if expires_at <= issued_at:
        raise PrincipalTrustPolicyError("PRINCIPAL_TIME_WINDOW_INVALID")
    if issued_at < not_before or expires_at > not_after:
        raise PrincipalTrustPolicyError("TRUST_POLICY_DOES_NOT_COVER_ATTESTATION")

    return {
        "policy_id": policy_id,
        "policy_digest": _canonical_digest(policy),
        "issuer": issuer,
        "key_id": key_id,
        "key_fingerprint": fingerprint,
        "audience": audience,
        "principal_type": principal_type,
        "policy_match_status": "MATCHED_UNTRUSTED_POLICY_ENVELOPE",
        "policy_source_assurance": "CALLER_SUPPLIED_UNAUTHENTICATED",
        "cryptographic_verification": "NOT_PERFORMED",
        "identity_authenticated": False,
        "execution_authorized": False,
    }
