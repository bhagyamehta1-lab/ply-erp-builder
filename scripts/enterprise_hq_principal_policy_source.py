"""Read-only, fail-closed policy-source adapter for principal signature verification.

The source and signature adapters are injected. This module performs no network I/O,
loads no keys, stores no credentials, and never authorizes task execution. The
AUTHENTICATED_READ_ONLY_ADAPTER_ASSERTED value is an adapter contract, not a
cryptographic proof of source authenticity.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Protocol

from scripts.enterprise_hq_principal_trust_policy import (
    PrincipalTrustPolicyError,
    evaluate_principal_trust_policy,
)
from scripts.enterprise_hq_principal_policy_ledger import PrincipalPolicyLedgerError

SOURCE_FIELDS = frozenset({
    "source_id",
    "source_version",
    "source_revision",
    "source_assurance",
    "read_only",
    "retrieved_at",
    "policy",
    "policy_digest",
})
SOURCE_ASSURANCE = "AUTHENTICATED_READ_ONLY_ADAPTER_ASSERTED"
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
SHA256_HEX = re.compile(r"^[a-f0-9]{64}$")
MAX_SNAPSHOT_BYTES = 8192
MAX_POLICY_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 30
MAX_SIGNED_PAYLOAD_BYTES = 2048


class PrincipalPolicySourceError(ValueError):
    """A trusted policy-source or policy-bound verification contract failed."""


class PrincipalPolicySource(Protocol):
    """Injected read-only adapter for an authenticated issuer/key policy source."""

    def load_policy(self, *, issuer: str, key_id: str) -> Mapping | None:
        """Return a source snapshot; implementations must authenticate their source."""


class PolicyBoundSignatureVerifier(Protocol):
    """Cryptographic adapter that must verify against the pinned policy context."""

    def verify(
        self,
        *,
        issuer: str,
        audience: str,
        key_id: str,
        algorithm: str,
        payload: bytes,
        signature: bytes,
        key_fingerprint: str,
        policy_digest: str,
        policy_id: str,
        policy_version: str,
        policy_revision: int,
        policy_source_id: str,
    ) -> bool:
        """Verify the signature and ensure the actual key matches the supplied pin."""


def canonical_policy_digest(policy: Mapping) -> str:
    """Return the SHA-256 digest of the canonical JSON policy envelope."""
    if not isinstance(policy, Mapping):
        raise PrincipalPolicySourceError("TRUST_POLICY_ENCODING_INVALID")
    try:
        encoded = json.dumps(
            dict(policy), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise PrincipalPolicySourceError("TRUST_POLICY_ENCODING_INVALID") from None
    return hashlib.sha256(encoded).hexdigest()


def _aware_timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str):
        raise PrincipalPolicySourceError(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PrincipalPolicySourceError(code) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PrincipalPolicySourceError(code)
    return parsed


class PolicyBoundPrincipalVerifier:
    """Compose a read-only policy source with a policy-pinned signature adapter.

    The object implements the PrincipalVerifier interface used by
    validate_principal_attestation. A source snapshot is fetched for every
    verification, structurally validated, freshness-checked and digest-pinned
    before the cryptographic adapter is called.

    The injected policy source is a trust boundary. Its authenticated/read-only
    assurance is asserted by that adapter and is not proven by this wrapper.
    The cryptographic adapter must independently verify the signature and confirm
    that the actual verification key matches key_fingerprint and policy_digest.
    """

    def __init__(
        self,
        policy_source: PrincipalPolicySource | None,
        signature_verifier: PolicyBoundSignatureVerifier | None,
        *,
        now_provider,
        policy_ledger=None,
    ) -> None:
        self.policy_source = policy_source
        self.signature_verifier = signature_verifier
        self.now_provider = now_provider
        self.policy_ledger = policy_ledger

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
        if self.policy_source is None:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_UNAVAILABLE")
        if self.signature_verifier is None:
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNATURE_VERIFIER_UNAVAILABLE")

        load_policy = getattr(self.policy_source, "load_policy", None)
        if not callable(load_policy):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_INTERFACE_INVALID")
        verify_signature = getattr(self.signature_verifier, "verify", None)
        if not callable(verify_signature):
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNATURE_VERIFIER_INTERFACE_INVALID")
        if self.policy_ledger is None:
            raise PrincipalPolicySourceError("TRUST_POLICY_HISTORY_LEDGER_UNAVAILABLE")
        record_policy_snapshot = getattr(self.policy_ledger, "record_policy_snapshot", None)
        if not callable(record_policy_snapshot):
            raise PrincipalPolicySourceError("TRUST_POLICY_HISTORY_LEDGER_INTERFACE_INVALID")
        if not callable(self.now_provider):
            raise PrincipalPolicySourceError("TRUST_POLICY_CLOCK_UNAVAILABLE")

        try:
            now = self.now_provider()
        except Exception:
            raise PrincipalPolicySourceError("TRUST_POLICY_CLOCK_ERROR") from None
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PrincipalPolicySourceError("TRUST_POLICY_CLOCK_INVALID")

        if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_SIGNED_PAYLOAD_BYTES:
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNED_PAYLOAD_INVALID")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNATURE_LENGTH_INVALID")
        if algorithm != "Ed25519":
            raise PrincipalPolicySourceError("TRUST_POLICY_ALGORITHM_UNSUPPORTED")

        try:
            attestation = json.loads(bytes(payload).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNED_PAYLOAD_INVALID") from None
        if not isinstance(attestation, Mapping):
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNED_PAYLOAD_INVALID")
        if (
            attestation.get("issuer") != issuer
            or attestation.get("audience") != audience
            or attestation.get("key_id") != key_id
            or attestation.get("algorithm") != algorithm
        ):
            raise PrincipalPolicySourceError("PRINCIPAL_VERIFIER_ARGUMENT_MISMATCH")

        try:
            supplied_snapshot = load_policy(issuer=issuer, key_id=key_id)
        except Exception:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_ERROR") from None
        if not isinstance(supplied_snapshot, Mapping):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_RESPONSE_INVALID")
        if set(supplied_snapshot) != SOURCE_FIELDS:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_SCHEMA_INVALID")

        try:
            snapshot_bytes = json.dumps(
                dict(supplied_snapshot),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        except (TypeError, ValueError):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_RESPONSE_INVALID") from None
        if len(snapshot_bytes) > MAX_SNAPSHOT_BYTES:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_RESPONSE_TOO_LARGE")
        try:
            snapshot = json.loads(snapshot_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_RESPONSE_INVALID") from None

        source_id = snapshot.get("source_id")
        source_version = snapshot.get("source_version")
        if not isinstance(source_id, str) or not IDENTIFIER.fullmatch(source_id):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_ID_INVALID")
        if not isinstance(source_version, str) or not IDENTIFIER.fullmatch(source_version):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_VERSION_INVALID")
        source_revision = snapshot.get("source_revision")
        if type(source_revision) is not int or source_revision < 1:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_REVISION_INVALID")
        if snapshot.get("source_assurance") != SOURCE_ASSURANCE:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_NOT_AUTHENTICATED")
        if snapshot.get("read_only") is not True:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_NOT_READ_ONLY")

        retrieved_at = _aware_timestamp(
            snapshot.get("retrieved_at"), "TRUST_POLICY_SOURCE_TIME_INVALID"
        )
        skew = timedelta(seconds=MAX_FUTURE_SKEW_SECONDS)
        if retrieved_at > now + skew:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_TIME_INVALID")
        if (now - retrieved_at).total_seconds() > MAX_POLICY_AGE_SECONDS:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_STALE")

        policy = snapshot.get("policy")
        if not isinstance(policy, Mapping):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_POLICY_INVALID")
        digest = canonical_policy_digest(policy)
        snapshot_digest = snapshot.get("policy_digest")
        if not isinstance(snapshot_digest, str) or not SHA256_HEX.fullmatch(snapshot_digest):
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_DIGEST_INVALID")
        if snapshot_digest != digest:
            raise PrincipalPolicySourceError("TRUST_POLICY_SOURCE_DIGEST_MISMATCH")

        try:
            record_policy_snapshot(
                snapshot,
                policy,
                expected_issuer=issuer,
                expected_key_id=key_id,
                now=now,
            )
        except PrincipalPolicyLedgerError as exc:
            raise PrincipalPolicySourceError(str(exc)) from None
        except Exception:
            raise PrincipalPolicySourceError("TRUST_POLICY_HISTORY_LEDGER_ERROR") from None

        try:
            match = evaluate_principal_trust_policy(attestation, policy, now=now)
        except PrincipalTrustPolicyError as exc:
            code = str(exc)
            raise PrincipalPolicySourceError(code) from None

        try:
            accepted = verify_signature(
                issuer=issuer,
                audience=audience,
                key_id=key_id,
                algorithm=algorithm,
                payload=bytes(payload),
                signature=signature,
                key_fingerprint=match["key_fingerprint"],
                policy_digest=match["policy_digest"],
                policy_id=match["policy_id"],
                policy_version=source_version,
                policy_revision=source_revision,
                policy_source_id=source_id,
            )
        except Exception:
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNATURE_VERIFIER_ERROR") from None
        if type(accepted) is not bool:
            raise PrincipalPolicySourceError("PRINCIPAL_SIGNATURE_VERIFIER_RESULT_INVALID")
        return accepted
