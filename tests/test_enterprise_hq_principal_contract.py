"""Focused tests for fail-closed principal-attestation validation."""
from __future__ import annotations

import base64
import json
import unittest
from datetime import datetime, timedelta, timezone

from scripts.enterprise_hq_principal_contract import (
    PrincipalContractError,
    validate_principal_attestation,
)
from scripts.enterprise_hq_task_contract import validate_task


class FakeVerifier:
    """Test-only adapter; it does not provide production authentication."""

    def __init__(self, result=True, error=None):
        self.result = result
        self.error = error
        self.calls = []

    def verify(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


def task_fixture():
    return {
        "task_id": "HQ-IDENTITY-01",
        "workstream_id": "WS-05",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def attestation_fixture(task=None, **overrides):
    task = task or task_fixture()
    now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
    value = {
        "schema_version": "1.0.0",
        "issuer": "https://identity.example.test",
        "subject": "worker:synthetic-001",
        "audience": "enterprise-hq-company-runtime",
        "principal_id": "WORKER.SYNTHETIC.001",
        "principal_type": "WORKER",
        "role": "CODE_MAINTAINER",
        "task_id": task["task_id"],
        "proposal_digest": validate_task(task)["idempotency_key"],
        "lease_id": "HQL-IDENTITY-LEASE-01",
        "receipt_id": None,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "nonce": "synthetic_nonce_0001",
        "algorithm": "Ed25519",
        "key_id": "test-key-01",
        "signature": base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("="),
    }
    value.update(overrides)
    return value, now


class PrincipalContractTests(unittest.TestCase):
    def validate_worker(self, attestation, now, verifier=None, task=None, **kwargs):
        return validate_principal_attestation(
            task or task_fixture(),
            attestation,
            expected_audience="enterprise-hq-company-runtime",
            expected_lease_id="HQL-IDENTITY-LEASE-01",
            now=now,
            verifier=verifier,
            **kwargs,
        )

    def test_worker_attestation_is_bound_to_task_and_lease(self):
        task = task_fixture()
        attestation, now = attestation_fixture(task)
        verifier = FakeVerifier()
        result = self.validate_worker(attestation, now, verifier, task)
        self.assertEqual(result["binding"], "TASK_AND_LEASE")
        self.assertEqual(result["identity_status"], "ADAPTER_VERIFICATION_ACCEPTED")
        self.assertEqual(result["identity_assurance"], "EXTERNAL_ADAPTER_ASSERTED")
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual(verifier.calls[0]["algorithm"], "Ed25519")
        self.assertEqual(
            json.loads(verifier.calls[0]["payload"])["task_id"], task["task_id"]
        )
        self.assertEqual(len(verifier.calls[0]["signature"]), 64)

    def test_reviewer_attestation_is_bound_to_receipt(self):
        task = task_fixture()
        receipt_id = "HQV-IDENTITY-REVIEW-01"
        attestation, now = attestation_fixture(
            task,
            principal_id="REVIEWER.SYNTHETIC.001",
            principal_type="REVIEWER",
            role="INDEPENDENT_VERIFIER",
            lease_id=None,
            receipt_id=receipt_id,
        )
        verifier = FakeVerifier()
        result = validate_principal_attestation(
            task,
            attestation,
            expected_audience="enterprise-hq-company-runtime",
            expected_receipt_id=receipt_id,
            now=now,
            verifier=verifier,
        )
        self.assertEqual(result["binding"], "TASK_AND_RECEIPT")
        self.assertEqual(result["principal_type"], "REVIEWER")
        self.assertFalse(result["execution_authorized"])

    def test_missing_verifier_fails_closed(self):
        attestation, now = attestation_fixture()
        with self.assertRaisesRegex(
            PrincipalContractError, "IDENTITY_VERIFIER_UNAVAILABLE"
        ):
            self.validate_worker(attestation, now)

    def test_invalid_verifier_interface_fails_closed(self):
        attestation, now = attestation_fixture()
        with self.assertRaisesRegex(
            PrincipalContractError, "IDENTITY_VERIFIER_INTERFACE_INVALID"
        ):
            self.validate_worker(attestation, now, verifier=object())

    def test_rejected_signature_fails_closed(self):
        attestation, now = attestation_fixture()
        with self.assertRaisesRegex(
            PrincipalContractError, "IDENTITY_SIGNATURE_REJECTED"
        ):
            self.validate_worker(attestation, now, FakeVerifier(False))

    def test_verifier_exception_is_sanitized(self):
        attestation, now = attestation_fixture()
        with self.assertRaisesRegex(PrincipalContractError, "IDENTITY_VERIFIER_ERROR"):
            self.validate_worker(
                attestation, now, FakeVerifier(error=RuntimeError("private detail"))
            )

    def test_non_boolean_verifier_result_fails_closed(self):
        attestation, now = attestation_fixture()
        with self.assertRaisesRegex(
            PrincipalContractError, "IDENTITY_VERIFIER_RESULT_INVALID"
        ):
            self.validate_worker(attestation, now, FakeVerifier("true"))

    def test_wrong_audience_is_rejected_before_adapter(self):
        attestation, now = attestation_fixture(audience="other-runtime")
        verifier = FakeVerifier()
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_AUDIENCE_MISMATCH"
        ):
            self.validate_worker(attestation, now, verifier)
        self.assertEqual(verifier.calls, [])

    def test_wrong_task_id_is_rejected(self):
        attestation, now = attestation_fixture(task_id="HQ-OTHER")
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_TASK_ID_MISMATCH"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_wrong_proposal_digest_is_rejected(self):
        attestation, now = attestation_fixture(proposal_digest="0" * 64)
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_PROPOSAL_DIGEST_MISMATCH"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_worker_role_must_match_task_kind(self):
        attestation, now = attestation_fixture(role="READ_ONLY_AUDITOR")
        with self.assertRaisesRegex(PrincipalContractError, "WORKER_ROLE_MISMATCH"):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_worker_requires_exact_lease_binding(self):
        attestation, now = attestation_fixture(lease_id="HQL-OTHER")
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_LEASE_ID_MISMATCH"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_worker_cannot_bind_a_review_receipt(self):
        attestation, now = attestation_fixture(receipt_id="HQV-IDENTITY-REVIEW-01")
        with self.assertRaisesRegex(
            PrincipalContractError, "WORKER_RECEIPT_BINDING_FORBIDDEN"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_reviewer_requires_exact_receipt_binding(self):
        task = task_fixture()
        receipt_id = "HQV-IDENTITY-REVIEW-01"
        attestation, now = attestation_fixture(
            task,
            principal_id="REVIEWER.SYNTHETIC.001",
            principal_type="REVIEWER",
            role="INDEPENDENT_VERIFIER",
            lease_id=None,
            receipt_id="HQV-OTHER",
        )
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_RECEIPT_ID_MISMATCH"
        ):
            validate_principal_attestation(
                task,
                attestation,
                expected_audience="enterprise-hq-company-runtime",
                expected_receipt_id=receipt_id,
                now=now,
                verifier=FakeVerifier(),
            )

    def test_reviewer_cannot_claim_worker_lease(self):
        task = task_fixture()
        attestation, now = attestation_fixture(
            task,
            principal_id="REVIEWER.SYNTHETIC.001",
            principal_type="REVIEWER",
            role="INDEPENDENT_VERIFIER",
            receipt_id="HQV-IDENTITY-REVIEW-01",
        )
        with self.assertRaisesRegex(
            PrincipalContractError, "REVIEWER_LEASE_BINDING_FORBIDDEN"
        ):
            validate_principal_attestation(
                task,
                attestation,
                expected_audience="enterprise-hq-company-runtime",
                expected_receipt_id="HQV-IDENTITY-REVIEW-01",
                now=now,
                verifier=FakeVerifier(),
            )

    def test_unknown_fields_are_rejected(self):
        attestation, now = attestation_fixture(extra="not-allowed")
        with self.assertRaisesRegex(PrincipalContractError, "PRINCIPAL_SCHEMA_INVALID"):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_invalid_signature_length_is_rejected(self):
        attestation, now = attestation_fixture(signature="A" * 86)
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_SIGNATURE_LENGTH_INVALID"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_unsupported_algorithm_is_rejected(self):
        attestation, now = attestation_fixture(algorithm="HS256")
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_ALGORITHM_UNSUPPORTED"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_naive_evaluation_time_is_rejected(self):
        attestation, _ = attestation_fixture()
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_EVALUATION_TIME_INVALID"
        ):
            self.validate_worker(
                attestation, datetime(2026, 11, 8, 0, 0), FakeVerifier()
            )

    def test_expired_attestation_is_rejected(self):
        now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
        issued = now - timedelta(minutes=20)
        attestation, _ = attestation_fixture(
            issued_at=issued.isoformat(),
            expires_at=(issued + timedelta(minutes=5)).isoformat(),
        )
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_ATTESTATION_EXPIRED"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_future_attestation_is_rejected(self):
        now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
        issued = now + timedelta(minutes=2)
        attestation, _ = attestation_fixture(
            issued_at=issued.isoformat(),
            expires_at=(issued + timedelta(minutes=5)).isoformat(),
        )
        with self.assertRaisesRegex(
            PrincipalContractError, "PRINCIPAL_NOT_YET_VALID"
        ):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_attestation_ttl_is_bounded(self):
        now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
        attestation, _ = attestation_fixture(
            expires_at=(now + timedelta(minutes=16)).isoformat()
        )
        with self.assertRaisesRegex(PrincipalContractError, "PRINCIPAL_TTL_EXCEEDED"):
            self.validate_worker(attestation, now, FakeVerifier())

    def test_invalid_nonce_is_rejected(self):
        attestation, now = attestation_fixture(nonce="short")
        with self.assertRaisesRegex(PrincipalContractError, "PRINCIPAL_NONCE_INVALID"):
            self.validate_worker(attestation, now, FakeVerifier())


if __name__ == "__main__":
    unittest.main()
