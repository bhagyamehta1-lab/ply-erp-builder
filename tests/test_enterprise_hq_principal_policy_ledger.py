"""Tests for persistent principal policy version and revocation history."""
from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_principal_policy_ledger import (
    PrincipalPolicyLedger,
    PrincipalPolicyLedgerCorruptionError,
    PrincipalPolicyLedgerError,
)
from scripts.enterprise_hq_principal_policy_source import (
    PolicyBoundPrincipalVerifier,
    PrincipalPolicySourceError,
    SOURCE_ASSURANCE,
    canonical_policy_digest,
)

NOW = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
ISSUER = "https://identity.example.test"
KEY_ID = "test-key-01"
SOURCE_ID = "synthetic-policy-source"
AUDIENCE = "enterprise-hq-company-runtime"


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


def snapshot_fixture(policy=None, *, revision=1, version=None, **overrides):
    policy = policy or policy_fixture()
    value = {
        "source_id": SOURCE_ID,
        "source_version": version or ("v" + str(revision)),
        "source_revision": revision,
        "source_assurance": SOURCE_ASSURANCE,
        "read_only": True,
        "retrieved_at": NOW.isoformat(),
        "policy": policy,
        "policy_digest": canonical_policy_digest(policy),
    }
    value.update(overrides)
    return value


class FakeSource:
    def __init__(self, snapshot):
        self.snapshot = snapshot

    def load_policy(self, *, issuer, key_id):
        return self.snapshot


class FakeSignatureVerifier:
    def verify(self, **kwargs):
        return True


class PrincipalPolicyLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "policy.sqlite3")
        self.ledger = PrincipalPolicyLedger(self.database)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def record(self, policy=None, *, revision=1, version=None, snapshot_overrides=None):
        policy = policy or policy_fixture()
        snapshot = snapshot_fixture(
            policy, revision=revision, version=version, **(snapshot_overrides or {})
        )
        return self.ledger.record_policy_snapshot(
            snapshot, policy, expected_issuer=ISSUER, expected_key_id=KEY_ID, now=NOW
        )

    def test_first_policy_snapshot_is_pinned_as_untrusted(self):
        result = self.record()
        self.assertEqual(result["status"], "PINNED_UNTRUSTED_SNAPSHOT")
        self.assertFalse(result["execution_authorized"])
        verified = self.ledger.verify()
        self.assertEqual(verified["principal_policy_snapshot_count"], 1)
        self.assertEqual(verified["principal_policy_audit_event_count"], 1)
        self.assertFalse(verified["policy_identity_authenticated"])

    def test_exact_snapshot_replay_is_idempotent(self):
        self.record()
        self.assertEqual(self.record()["status"], "ALREADY_PINNED")
        self.assertEqual(self.ledger.verify()["principal_policy_audit_event_count"], 1)

    def test_same_revision_with_different_digest_is_rejected(self):
        self.record()
        changed = policy_fixture(audiences=[AUDIENCE, "other-runtime"])
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_REVISION_CONFLICT"):
            self.record(changed)

    def test_lower_revision_is_rejected(self):
        self.record(revision=2)
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_ROLLBACK_REJECTED"):
            self.record(revision=1)

    def test_revision_gap_is_rejected(self):
        self.record(revision=1)
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_REVISION_GAP"):
            self.record(revision=3)

    def test_key_fingerprint_cannot_change_under_same_key_id(self):
        self.record()
        changed = policy_fixture(key_fingerprint="b" * 64)
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_KEY_FINGERPRINT_CHANGED"):
            self.record(changed, revision=2)

    def test_policy_id_cannot_change_under_same_key_id(self):
        self.record()
        changed = policy_fixture(policy_id="HQT-SYNTHETIC-02")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_ID_CHANGED"):
            self.record(changed, revision=2)

    def test_source_version_cannot_be_reused(self):
        self.record(revision=1, version="stable-v1")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_VERSION_REUSED"):
            self.record(revision=2, version="stable-v1")

    def test_revoked_policy_is_persisted_before_policy_matcher_rejects_it(self):
        revoked = policy_fixture(status="REVOKED", revoked_at=NOW.isoformat())
        self.assertEqual(self.record(revoked)["status"], "REVOKED_RECORDED")
        self.assertEqual(self.ledger.verify()["principal_policy_revoked_key_count"], 1)

    def test_revoked_key_cannot_be_reactivated(self):
        revoked = policy_fixture(status="REVOKED", revoked_at=NOW.isoformat())
        self.record(revoked)
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_KEY_REVOKED"):
            self.record(policy_fixture(), revision=2)

    def test_disabled_policy_can_be_reenabled_only_by_next_revision(self):
        self.record(policy_fixture(status="DISABLED"))
        self.assertEqual(
            self.record(policy_fixture(), revision=2)["status"],
            "PINNED_UNTRUSTED_SNAPSHOT",
        )

    def test_issuer_mismatch_is_rejected(self):
        wrong = policy_fixture(issuer="https://other.example.test")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_ISSUER_MISMATCH"):
            self.record(wrong)

    def test_key_id_mismatch_is_rejected(self):
        wrong = policy_fixture(key_id="other-key")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_KEY_ID_MISMATCH"):
            self.record(wrong)

    def test_wrong_policy_digest_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_DIGEST_MISMATCH"):
            self.record(snapshot_overrides={"policy_digest": "0" * 64})

    def test_untrusted_source_assurance_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_NOT_AUTHENTICATED"):
            self.record(snapshot_overrides={"source_assurance": "UNTRUSTED"})

    def test_non_read_only_source_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_NOT_READ_ONLY"):
            self.record(snapshot_overrides={"read_only": False})

    def test_boolean_revision_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_REVISION_INVALID"):
            self.record(snapshot_overrides={"source_revision": True})

    def test_zero_revision_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_REVISION_INVALID"):
            self.record(snapshot_overrides={"source_revision": 0})

    def test_unknown_policy_fields_are_rejected(self):
        invalid = policy_fixture(extra="not-allowed")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SCHEMA_INVALID"):
            self.record(invalid)

    def test_invalid_policy_status_is_rejected(self):
        invalid = policy_fixture(status="UNKNOWN")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_STATUS_INVALID"):
            self.record(invalid)

    def test_revoked_policy_requires_timestamp(self):
        invalid = policy_fixture(status="REVOKED")
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_REVOCATION_TIME_REQUIRED"):
            self.record(invalid)

    def test_non_revoked_policy_rejects_revocation_timestamp(self):
        invalid = policy_fixture(revoked_at=NOW.isoformat())
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_REVOCATION_STATE_INVALID"):
            self.record(invalid)

    def test_stale_snapshot_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_STALE"):
            self.record(snapshot_overrides={"retrieved_at": "2026-11-07T23:54:59+00:00"})

    def test_future_snapshot_outside_skew_is_rejected(self):
        with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_SOURCE_TIME_INVALID"):
            self.record(snapshot_overrides={"retrieved_at": "2026-11-08T00:00:31+00:00"})

    def test_audit_chain_corruption_is_detected(self):
        self.record()
        self.ledger._connection.execute(
            "UPDATE principal_policy_audit_events SET record_hash = ? WHERE sequence = 1",
            ("f" * 64,),
        )
        with self.assertRaisesRegex(PrincipalPolicyLedgerCorruptionError, "PRINCIPAL_POLICY_AUDIT_CHAIN_HASH_INVALID"):
            self.ledger.verify()

    def test_missing_audit_event_is_detected(self):
        self.record()
        self.ledger._connection.execute("DELETE FROM principal_policy_audit_events")
        with self.assertRaisesRegex(PrincipalPolicyLedgerCorruptionError, "PRINCIPAL_POLICY_AUDIT_EVENT_COUNT_MISMATCH"):
            self.ledger.verify()

    def test_restart_recovery_preserves_policy_history(self):
        self.record()
        self.ledger.close()
        self.ledger = PrincipalPolicyLedger(self.database)
        result = self.ledger.recover_after_restart()
        self.assertEqual(result["principal_policy_snapshot_count"], 1)
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["execution_authorized"])

    def test_concurrent_identical_snapshots_pin_once(self):
        def attempt():
            ledger = PrincipalPolicyLedger(self.database)
            try:
                return ledger.record_policy_snapshot(
                    snapshot_fixture(), policy_fixture(),
                    expected_issuer=ISSUER, expected_key_id=KEY_ID, now=NOW,
                )["status"]
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(
            sorted(results), ["ALREADY_PINNED", "PINNED_UNTRUSTED_SNAPSHOT"]
        )
        self.assertEqual(self.ledger.verify()["principal_policy_audit_event_count"], 1)

    def test_concurrent_conflicting_snapshots_have_one_winner(self):
        changed = policy_fixture(audiences=[AUDIENCE, "other-runtime"])

        def attempt(policy):
            ledger = PrincipalPolicyLedger(self.database)
            try:
                snapshot = snapshot_fixture(policy)
                return ledger.record_policy_snapshot(
                    snapshot, policy, expected_issuer=ISSUER,
                    expected_key_id=KEY_ID, now=NOW,
                )["status"]
            except PrincipalPolicyLedgerError as exc:
                return str(exc)
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, [policy_fixture(), changed]))
        self.assertEqual(
            sum(value == "PINNED_UNTRUSTED_SNAPSHOT" for value in results), 1
        )
        self.assertEqual(
            sum(value == "PRINCIPAL_POLICY_REVISION_CONFLICT" for value in results), 1
        )
        self.assertEqual(self.ledger.verify()["principal_policy_audit_event_count"], 1)

    def test_capacity_fails_closed(self):
        with patch("scripts.enterprise_hq_principal_policy_ledger.MAX_PRINCIPAL_POLICY_SNAPSHOTS", 1):
            self.record(revision=1)
            with self.assertRaisesRegex(PrincipalPolicyLedgerError, "PRINCIPAL_POLICY_LEDGER_CAPACITY_EXCEEDED"):
                self.record(revision=2)

    def test_policy_verifier_persists_revocation_before_rejecting_attestation(self):
        revoked = policy_fixture(status="REVOKED", revoked_at=NOW.isoformat())
        source = FakeSource(snapshot_fixture(revoked))
        verifier = PolicyBoundPrincipalVerifier(
            source, FakeSignatureVerifier(), now_provider=lambda: NOW,
            policy_ledger=self.ledger,
        )
        import json
        payload = json.dumps({
            "issuer": ISSUER, "audience": AUDIENCE,
            "key_id": KEY_ID, "algorithm": "Ed25519",
        }).encode("utf-8")
        with self.assertRaisesRegex(PrincipalPolicySourceError, "TRUST_POLICY_REVOKED"):
            verifier.verify(
                issuer=ISSUER, audience=AUDIENCE, key_id=KEY_ID,
                algorithm="Ed25519", payload=payload, signature=b"x" * 64,
            )
        self.assertEqual(self.ledger.verify()["principal_policy_revoked_key_count"], 1)
        source.snapshot = snapshot_fixture(policy_fixture(), revision=2, version="v2")
        with self.assertRaisesRegex(PrincipalPolicySourceError, "PRINCIPAL_POLICY_KEY_REVOKED"):
            verifier.verify(
                issuer=ISSUER, audience=AUDIENCE, key_id=KEY_ID,
                algorithm="Ed25519", payload=payload, signature=b"x" * 64,
            )


if __name__ == "__main__":
    unittest.main()
