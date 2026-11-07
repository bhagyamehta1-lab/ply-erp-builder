import unittest
from datetime import datetime, timezone

from scripts.enterprise_hq_principal_trust_policy import (
    PrincipalTrustPolicyError,
    evaluate_principal_trust_policy,
)


class PrincipalTrustPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
        self.attestation = {
            "issuer": "https://identity.example.test",
            "key_id": "worker-key-01",
            "algorithm": "Ed25519",
            "audience": "enterprise-hq-company-runtime",
            "principal_type": "WORKER",
            "issued_at": "2026-11-07T23:55:00Z",
            "expires_at": "2026-11-08T00:05:00Z",
        }
        self.policy = {
            "schema_version": "1.0.0",
            "policy_id": "HQT-LOCAL-TEST-01",
            "issuer": "https://identity.example.test",
            "key_id": "worker-key-01",
            "algorithm": "Ed25519",
            "key_fingerprint": "a" * 64,
            "audiences": ["enterprise-hq-company-runtime"],
            "principal_types": ["WORKER", "REVIEWER"],
            "not_before": "2026-11-01T00:00:00Z",
            "not_after": "2026-12-01T00:00:00Z",
            "status": "ACTIVE",
            "revoked_at": None,
        }

    def evaluate(self, policy=None, attestation=None):
        return evaluate_principal_trust_policy(
            self.attestation if attestation is None else attestation,
            self.policy if policy is None else policy,
            now=self.now,
        )

    def test_matching_policy_returns_untrusted_match_only(self):
        result = self.evaluate()
        self.assertEqual(result["policy_match_status"], "MATCHED_UNTRUSTED_POLICY_ENVELOPE")
        self.assertEqual(result["policy_source_assurance"], "CALLER_SUPPLIED_UNAUTHENTICATED")
        self.assertEqual(result["cryptographic_verification"], "NOT_PERFORMED")
        self.assertFalse(result["identity_authenticated"])
        self.assertFalse(result["execution_authorized"])
        self.assertEqual(len(result["policy_digest"]), 64)

    def test_missing_policy_fails_closed(self):
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_UNAVAILABLE"):
            evaluate_principal_trust_policy(self.attestation, None, now=self.now)

    def test_non_mapping_policy_rejected(self):
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_SCHEMA_INVALID"):
            self.evaluate(policy=[])

    def test_unknown_policy_field_rejected(self):
        policy = dict(self.policy, public_key="must-not-be-accepted")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_SCHEMA_INVALID"):
            self.evaluate(policy=policy)

    def test_missing_policy_field_rejected(self):
        policy = dict(self.policy)
        policy.pop("key_fingerprint")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_SCHEMA_INVALID"):
            self.evaluate(policy=policy)

    def test_oversized_policy_rejected(self):
        policy = dict(self.policy, policy_id="HQT-" + "A" * 5000)
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_TOO_LARGE"):
            self.evaluate(policy=policy)

    def test_policy_version_rejected(self):
        policy = dict(self.policy, schema_version="2.0.0")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_VERSION_INVALID"):
            self.evaluate(policy=policy)

    def test_policy_identifier_rejected(self):
        policy = dict(self.policy, policy_id="bad policy id")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_ID_INVALID"):
            self.evaluate(policy=policy)

    def test_invalid_issuer_rejected(self):
        policy = dict(self.policy, issuer="bad issuer with spaces")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_ISSUER_INVALID"):
            self.evaluate(policy=policy)

    def test_issuer_mismatch_rejected(self):
        attestation = dict(self.attestation, issuer="https://other.example.test")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_ISSUER_MISMATCH"):
            self.evaluate(attestation=attestation)

    def test_key_mismatch_rejected(self):
        attestation = dict(self.attestation, key_id="different-key")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_KEY_ID_MISMATCH"):
            self.evaluate(attestation=attestation)

    def test_unsupported_algorithm_rejected(self):
        policy = dict(self.policy, algorithm="RS256")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_ALGORITHM_UNSUPPORTED"):
            self.evaluate(policy=policy)

    def test_fingerprint_must_be_sha256_hex(self):
        policy = dict(self.policy, key_fingerprint="not-a-fingerprint")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_FINGERPRINT_INVALID"):
            self.evaluate(policy=policy)

    def test_duplicate_audiences_rejected(self):
        policy = dict(self.policy, audiences=["runtime", "runtime"])
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_AUDIENCES_INVALID"):
            self.evaluate(policy=policy)

    def test_audience_not_allowlisted_rejected(self):
        policy = dict(self.policy, audiences=["other-runtime"])
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_AUDIENCE_NOT_ALLOWED"):
            self.evaluate(policy=policy)

    def test_unknown_principal_type_in_policy_rejected(self):
        policy = dict(self.policy, principal_types=["ADMIN"])
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_PRINCIPAL_TYPES_INVALID"):
            self.evaluate(policy=policy)

    def test_disallowed_principal_type_rejected(self):
        policy = dict(self.policy, principal_types=["REVIEWER"])
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_PRINCIPAL_TYPE_NOT_ALLOWED"):
            self.evaluate(policy=policy)

    def test_disabled_policy_rejected(self):
        policy = dict(self.policy, status="DISABLED")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_DISABLED"):
            self.evaluate(policy=policy)

    def test_revoked_policy_rejected(self):
        policy = dict(self.policy, status="REVOKED", revoked_at="2026-11-07T20:00:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_REVOKED"):
            self.evaluate(policy=policy)

    def test_revoked_policy_requires_timestamp(self):
        policy = dict(self.policy, status="REVOKED")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_REVOCATION_TIME_REQUIRED"):
            self.evaluate(policy=policy)

    def test_active_policy_cannot_have_revocation_timestamp(self):
        policy = dict(self.policy, revoked_at="2026-11-07T20:00:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_REVOCATION_STATE_INVALID"):
            self.evaluate(policy=policy)

    def test_not_yet_valid_policy_rejected(self):
        policy = dict(self.policy, not_before="2026-11-09T00:00:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_NOT_YET_VALID"):
            self.evaluate(policy=policy)

    def test_expired_policy_rejected(self):
        policy = dict(self.policy, not_after="2026-11-07T23:59:59Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_EXPIRED"):
            self.evaluate(policy=policy)

    def test_invalid_policy_window_rejected(self):
        policy = dict(self.policy, not_before="2026-12-01T00:00:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_TIME_WINDOW_INVALID"):
            self.evaluate(policy=policy)

    def test_naive_evaluation_time_rejected(self):
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_EVALUATION_TIME_INVALID"):
            evaluate_principal_trust_policy(self.attestation, self.policy, now=datetime(2026, 11, 8))

    def test_naive_policy_timestamp_rejected(self):
        policy = dict(self.policy, not_before="2026-11-01T00:00:00")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_NOT_BEFORE_INVALID"):
            self.evaluate(policy=policy)

    def test_attestation_must_fit_inside_policy_window(self):
        attestation = dict(self.attestation, expires_at="2026-12-02T00:00:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "TRUST_POLICY_DOES_NOT_COVER_ATTESTATION"):
            self.evaluate(attestation=attestation)

    def test_invalid_attestation_window_rejected(self):
        attestation = dict(self.attestation, expires_at="2026-11-07T23:54:00Z")
        with self.assertRaisesRegex(PrincipalTrustPolicyError, "PRINCIPAL_TIME_WINDOW_INVALID"):
            self.evaluate(attestation=attestation)

    def test_digest_changes_when_policy_changes(self):
        first = self.evaluate()
        policy = dict(self.policy, policy_id="HQT-LOCAL-TEST-02")
        second = self.evaluate(policy=policy)
        self.assertNotEqual(first["policy_digest"], second["policy_digest"])

    def test_policy_has_no_write_or_execution_side_effect(self):
        before = dict(self.policy)
        self.evaluate()
        self.assertEqual(self.policy, before)


if __name__ == "__main__":
    unittest.main()
