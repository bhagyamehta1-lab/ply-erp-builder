"""Tests for the fail-closed, policy-pinned principal verifier adapter."""
from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from scripts.enterprise_hq_principal_contract import validate_principal_attestation
from scripts.enterprise_hq_principal_policy_source import (
    PolicyBoundPrincipalVerifier,
    PrincipalPolicySourceError,
    SOURCE_ASSURANCE,
    canonical_policy_digest,
)
from scripts.enterprise_hq_task_contract import validate_task

NOW = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
ISSUER = "https://identity.example.test"
AUDIENCE = "enterprise-hq-company-runtime"
KEY_ID = "test-key-01"


def policy_fixture(**overrides):
    value = {
        "schema_version": "1.0.0",
        "policy_id": "HQT-SYNTHETIC-01",
        "issuer": ISSUER,
        "key_id": KEY_ID,
        "algorithm": "Ed25519",
        "key_fingerprint": "a" * 64,
        "audiences": [AUDIENCE],
        "principal_types": ["WORKER"],
        "not_before": "2026-11-01T00:00:00Z",
        "not_after": "2026-12-01T00:00:00Z",
        "status": "ACTIVE",
        "revoked_at": None,
    }
    value.update(overrides)
    return value


def attestation_payload(**overrides):
    value = {
        "schema_version": "1.0.0",
        "issuer": ISSUER,
        "subject": "worker:synthetic-001",
        "audience": AUDIENCE,
        "principal_id": "WORKER.SYNTHETIC.001",
        "principal_type": "WORKER",
        "role": "CODE_MAINTAINER",
        "task_id": "HQ-IDENTITY-01",
        "proposal_digest": "1" * 64,
        "lease_id": "HQL-IDENTITY-LEASE-01",
        "receipt_id": None,
        "issued_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "nonce": "synthetic_nonce_0001",
        "algorithm": "Ed25519",
        "key_id": KEY_ID,
    }
    value.update(overrides)
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def snapshot_fixture(policy=None, **overrides):
    policy = policy or policy_fixture()
    value = {
        "source_id": "synthetic-policy-source",
        "source_version": "v1",
        "source_revision": 1,
        "source_assurance": SOURCE_ASSURANCE,
        "read_only": True,
        "retrieved_at": NOW.isoformat(),
        "policy": policy,
        "policy_digest": canonical_policy_digest(policy),
    }
    value.update(overrides)
    return value


class FakePolicySource:
    def __init__(self, snapshot=None, error=None):
        self.snapshot = snapshot if snapshot is not None else snapshot_fixture()
        self.error = error
        self.calls = []

    def load_policy(self, *, issuer, key_id):
        self.calls.append((issuer, key_id))
        if self.error is not None:
            raise self.error
        return self.snapshot


class FakePolicyHistory:
    def __init__(self):
        self.calls = []

    def record_policy_snapshot(self, snapshot, policy, *, expected_issuer, expected_key_id, now):
        self.calls.append({
            "snapshot": dict(snapshot),
            "policy": dict(policy),
            "expected_issuer": expected_issuer,
            "expected_key_id": expected_key_id,
            "now": now,
        })
        return {"status": "PINNED_UNTRUSTED_SNAPSHOT", "execution_authorized": False}


class FakeSignatureVerifier:
    def __init__(self, result=True, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def verify(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class PrincipalPolicySourceTests(unittest.TestCase):
    def setUp(self):
        self.policy = policy_fixture()
        self.snapshot = snapshot_fixture(self.policy)
        self.source = FakePolicySource(self.snapshot)
        self.signature = FakeSignatureVerifier()
        self.history = FakePolicyHistory()
        self.payload = attestation_payload()

    def build(self, source=None, signature=None, now_provider=lambda: NOW, history=None):
        return PolicyBoundPrincipalVerifier(
            self.source if source is None else source,
            self.signature if signature is None else signature,
            now_provider=now_provider,
            policy_ledger=self.history if history is None else history,
        )

    def verify(self, verifier=None, payload=None, signature=b"x" * 64):
        return (verifier or self.build()).verify(
            issuer=ISSUER,
            audience=AUDIENCE,
            key_id=KEY_ID,
            algorithm="Ed25519",
            payload=self.payload if payload is None else payload,
            signature=signature,
        )

    def test_policy_is_checked_before_signature_verifier(self):
        self.assertTrue(self.verify())
        self.assertEqual(len(self.source.calls), 1)
        self.assertEqual(len(self.history.calls), 1)
        self.assertEqual(len(self.signature.calls), 1)
        self.assertEqual(self.signature.calls[0]["policy_revision"], 1)

    def test_missing_policy_source_fails_closed(self):
        verifier = PolicyBoundPrincipalVerifier(None, self.signature, now_provider=lambda: NOW)
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_UNAVAILABLE"):
            self.verify(verifier)

    def test_missing_signature_verifier_fails_closed(self):
        verifier = PolicyBoundPrincipalVerifier(self.source, None, now_provider=lambda: NOW)
        with self.assertRaisesRegex(PrincipalPolicySourceError, "PRINCIPAL_SIGNATURE_VERIFIER_UNAVAILABLE"):
            self.verify(verifier)

    def test_missing_policy_history_ledger_fails_closed(self):
        verifier = PolicyBoundPrincipalVerifier(
            self.source, self.signature, now_provider=lambda: NOW, policy_ledger=None
        )
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_HISTORY_LEDGER_UNAVAILABLE"):
            self.verify(verifier)

    def test_invalid_policy_source_interface_rejected(self):
        verifier = PolicyBoundPrincipalVerifier(object(), self.signature, now_provider=lambda: NOW)
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_INTERFACE_INVALID"):
            self.verify(verifier)

    def test_policy_source_exception_is_sanitized(self):
        source = FakePolicySource(error=RuntimeError("private policy contents"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_ERROR") as ctx:
            self.verify(self.build(source=source))
        self.assertNotIn("private policy contents", str(ctx.exception))

    def test_missing_source_snapshot_rejected(self):
        source = FakePolicySource(snapshot=None)
        source.snapshot = None
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_RESPONSE_INVALID"):
            self.verify(self.build(source=source))

    def test_unknown_snapshot_fields_rejected(self):
        snapshot = dict(self.snapshot, unexpected="value")
        source = FakePolicySource(snapshot)
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_SCHEMA_INVALID"):
            self.verify(self.build(source=source))

    def test_source_assurance_is_required(self):
        source = FakePolicySource(dict(self.snapshot, source_assurance="UNAUTHENTICATED"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_NOT_AUTHENTICATED"):
            self.verify(self.build(source=source))

    def test_source_must_assert_read_only(self):
        source = FakePolicySource(dict(self.snapshot, read_only=False))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_NOT_READ_ONLY"):
            self.verify(self.build(source=source))

    def test_source_id_must_be_valid(self):
        source = FakePolicySource(dict(self.snapshot, source_id="../source"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_ID_INVALID"):
            self.verify(self.build(source=source))

    def test_source_version_must_be_valid(self):
        source = FakePolicySource(dict(self.snapshot, source_version=" "))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_VERSION_INVALID"):
            self.verify(self.build(source=source))

    def test_source_revision_must_be_positive_integer(self):
        for revision in (0, -1, True, "2", 1.0):
            source = FakePolicySource(dict(self.snapshot, source_revision=revision))
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_REVISION_INVALID"):
                    self.verify(self.build(source=source))

    def test_revoked_policy_is_recorded_before_policy_rejection(self):
        revoked = policy_fixture(status="REVOKED", revoked_at=NOW.isoformat())
        source = FakePolicySource(snapshot_fixture(revoked))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_REVOKED"):
            self.verify(self.build(source=source))
        self.assertEqual(len(self.history.calls), 1)
        self.assertEqual(self.history.calls[0]["policy"]["status"], "REVOKED")

    def test_policy_history_error_is_sanitized(self):
        class BrokenHistory:
            def record_policy_snapshot(self, *args, **kwargs):
                raise RuntimeError("private database detail")
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_HISTORY_LEDGER_ERROR") as ctx:
            self.verify(self.build(history=BrokenHistory()))
        self.assertNotIn("private database detail", str(ctx.exception))


    def test_retrieval_timestamp_must_be_timezone_aware(self):
        source = FakePolicySource(dict(self.snapshot, retrieved_at="2026-11-08T00:00:00"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_TIME_INVALID"):
            self.verify(self.build(source=source))

    def test_stale_snapshot_rejected(self):
        old = NOW - timedelta(seconds=301)
        source = FakePolicySource(dict(self.snapshot, retrieved_at=old.isoformat()))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_STALE"):
            self.verify(self.build(source=source))

    def test_future_snapshot_beyond_clock_skew_rejected(self):
        future = NOW + timedelta(seconds=31)
        source = FakePolicySource(dict(self.snapshot, retrieved_at=future.isoformat()))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_TIME_INVALID"):
            self.verify(self.build(source=source))

    def test_snapshot_digest_must_be_sha256_hex(self):
        source = FakePolicySource(dict(self.snapshot, policy_digest="bad"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_DIGEST_INVALID"):
            self.verify(self.build(source=source))

    def test_snapshot_digest_mismatch_rejected(self):
        source = FakePolicySource(dict(self.snapshot, policy_digest="0" * 64))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_DIGEST_MISMATCH"):
            self.verify(self.build(source=source))

    def test_policy_issuer_mismatch_rejected(self):
        policy = policy_fixture(issuer="https://other.example.test")
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_ISSUER_MISMATCH"):
            self.verify(self.build(source=source))

    def test_policy_key_mismatch_rejected(self):
        policy = policy_fixture(key_id="other-key")
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_KEY_ID_MISMATCH"):
            self.verify(self.build(source=source))

    def test_disallowed_audience_rejected(self):
        policy = policy_fixture(audiences=["other-runtime"])
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_AUDIENCE_NOT_ALLOWED"):
            self.verify(self.build(source=source))

    def test_disabled_policy_rejected(self):
        policy = policy_fixture(status="DISABLED")
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_DISABLED"):
            self.verify(self.build(source=source))

    def test_revoked_policy_rejected(self):
        policy = policy_fixture(status="REVOKED", revoked_at="2026-11-07T20:00:00Z")
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_REVOKED"):
            self.verify(self.build(source=source))

    def test_expired_policy_rejected(self):
        policy = policy_fixture(not_after="2026-11-07T23:59:59Z")
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_EXPIRED"):
            self.verify(self.build(source=source))

    def test_signature_verifier_exception_is_sanitized(self):
        signature = FakeSignatureVerifier(error=RuntimeError("private key detail"))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "PRINCIPAL_SIGNATURE_VERIFIER_ERROR") as ctx:
            self.verify(self.build(signature=signature))
        self.assertNotIn("private key detail", str(ctx.exception))

    def test_signature_verifier_result_must_be_boolean(self):
        signature = FakeSignatureVerifier(result="true")
        with self.assertRaisesRegex(PrincipalPolicySourceError, "PRINCIPAL_SIGNATURE_VERIFIER_RESULT_INVALID"):
            self.verify(self.build(signature=signature))

    def test_rejected_signature_returns_false(self):
        signature = FakeSignatureVerifier(result=False)
        self.assertFalse(self.verify(self.build(signature=signature)))

    def test_malformed_signed_payload_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicySourceError, "PRINCIPAL_SIGNED_PAYLOAD_INVALID"):
            self.verify(payload=b"not-json")

    def test_invalid_policy_prevents_signature_verifier_call(self):
        policy = policy_fixture(status="DISABLED")
        source = FakePolicySource(snapshot_fixture(policy))
        signature = FakeSignatureVerifier()
        with self.assertRaises(PrincipalPolicySourceError):
            self.verify(self.build(source=source, signature=signature))
        self.assertEqual(signature.calls, [])

    def test_source_is_queried_by_exact_issuer_and_key(self):
        self.verify()
        self.assertEqual(self.source.calls, [(ISSUER, KEY_ID)])

    def test_signature_verifier_receives_policy_pins(self):
        self.verify()
        call = self.signature.calls[0]
        self.assertEqual(call["key_fingerprint"], "a" * 64)
        self.assertEqual(call["policy_digest"], canonical_policy_digest(self.policy))
        self.assertEqual(call["policy_id"], "HQT-SYNTHETIC-01")
        self.assertEqual(call["policy_version"], "v1")
        self.assertEqual(call["policy_source_id"], "synthetic-policy-source")

    def test_source_snapshot_is_not_mutated(self):
        before = json.dumps(self.snapshot, sort_keys=True)
        self.verify()
        self.assertEqual(json.dumps(self.snapshot, sort_keys=True), before)

    def test_naive_clock_is_rejected(self):
        verifier = self.build(now_provider=lambda: datetime(2026, 11, 8))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_CLOCK_INVALID"):
            self.verify(verifier)

    def test_clock_exception_is_sanitized(self):
        def broken_clock():
            raise RuntimeError("private clock detail")
        verifier = self.build(now_provider=broken_clock)
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_CLOCK_ERROR") as ctx:
            self.verify(verifier)
        self.assertNotIn("private clock detail", str(ctx.exception))

    def test_oversized_snapshot_rejected(self):
        policy = policy_fixture(issuer="x" * 9000)
        source = FakePolicySource(snapshot_fixture(policy))
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_SOURCE_RESPONSE_TOO_LARGE"):
            self.verify(self.build(source=source))

    def test_five_minute_freshness_boundary_is_accepted(self):
        retrieved = NOW - timedelta(seconds=300)
        source = FakePolicySource(dict(self.snapshot, retrieved_at=retrieved.isoformat()))
        self.assertTrue(self.verify(self.build(source=source)))

    def test_end_to_end_principal_contract_uses_policy_bound_verifier(self):
        task = {
            "task_id": "HQ-IDENTITY-01",
            "workstream_id": "WS-05",
            "task_kind": "INTERNAL_CODE",
            "attempt": 0,
            "status": "PROPOSED",
            "external_effects": False,
            "requires_human_approval": True,
        }
        validated = validate_task(task)
        issued = NOW
        attestation = {
            "schema_version": "1.0.0",
            "issuer": ISSUER,
            "subject": "worker:synthetic-001",
            "audience": AUDIENCE,
            "principal_id": "WORKER.SYNTHETIC.001",
            "principal_type": "WORKER",
            "role": "CODE_MAINTAINER",
            "task_id": task["task_id"],
            "proposal_digest": validated["idempotency_key"],
            "lease_id": "HQL-IDENTITY-LEASE-01",
            "receipt_id": None,
            "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(minutes=5)).isoformat(),
            "nonce": "synthetic_nonce_0001",
            "algorithm": "Ed25519",
            "key_id": KEY_ID,
            "signature": base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("="),
        }
        policy = policy_fixture()
        source = FakePolicySource(snapshot_fixture(policy))
        signature = FakeSignatureVerifier()
        verifier = self.build(source=source, signature=signature)
        result = validate_principal_attestation(
            task,
            attestation,
            expected_audience=AUDIENCE,
            expected_lease_id="HQL-IDENTITY-LEASE-01",
            now=NOW,
            verifier=verifier,
        )
        self.assertEqual(result["identity_status"], "ADAPTER_VERIFICATION_ACCEPTED")
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(len(source.calls), 1)
        self.assertEqual(len(signature.calls), 1)


if __name__ == "__main__":
    unittest.main()
