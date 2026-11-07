"""Tests for durable one-time principal nonce replay protection."""
from __future__ import annotations

import base64
import hashlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_principal_contract import PrincipalContractError
from scripts.enterprise_hq_principal_replay_ledger import (
    PrincipalReplayCorruptionError,
    PrincipalReplayError,
    PrincipalReplayLedger,
)
from scripts.enterprise_hq_task_contract import validate_task
from scripts.enterprise_hq_task_ledger import LedgerError


AUDIENCE = "enterprise-hq-company-runtime"


class FakeVerifier:
    """Test-only adapter; it does not provide production authentication."""

    def __init__(self, result=True, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def verify(self, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def task_fixture(task_id="HQ-REPLAY-01"):
    return {
        "task_id": task_id,
        "workstream_id": "WS-07",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def lease_fixture(task, now, lease_id="HQL-REPLAY-01"):
    validated = validate_task(task)
    issued = now + timedelta(minutes=1)
    return {
        "schema_version": "1.0.0",
        "lease_id": lease_id,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_owner_id": "LOCAL-WORKER-REPLAY",
        "attempt": 1,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=10)).isoformat(),
    }


def receipt_fixture(task, now, receipt_id="HQV-REPLAY-01"):
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "receipt_id": receipt_id,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_proposer_id": "LOCAL-WORKER-REPLAY",
        "logical_verifier_id": "LOCAL-REVIEWER-REPLAY",
        "proposer_role": validated["logical_role"],
        "verifier_role": "INDEPENDENT_VERIFIER",
        "claimed_verdict": "PASS",
        "evidence_digest": hashlib.sha256(b"synthetic-evidence").hexdigest(),
        "reviewed_at": now.isoformat(),
    }


def attestation_fixture(
    task,
    now,
    *,
    principal_type="WORKER",
    nonce="replay_nonce_000001",
    principal_id="WORKER.REPLAY.001",
    lease_id="HQL-REPLAY-01",
    receipt_id=None,
    issuer="https://identity.example.test",
    **overrides,
):
    validated = validate_task(task)
    if principal_type == "REVIEWER":
        role = "INDEPENDENT_VERIFIER"
        lease_id = None
        receipt_id = receipt_id or "HQV-REPLAY-01"
    else:
        role = validated["logical_role"]
    value = {
        "schema_version": "1.0.0",
        "issuer": issuer,
        "subject": "principal:synthetic-replay",
        "audience": AUDIENCE,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "role": role,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "lease_id": lease_id,
        "receipt_id": receipt_id,
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=4)).isoformat(),
        "nonce": nonce,
        "algorithm": "Ed25519",
        "key_id": "synthetic-key-01",
        "signature": base64.urlsafe_b64encode(b"x" * 64).decode("ascii").rstrip("="),
    }
    value.update(overrides)
    return value


class PrincipalReplayLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "principal-replay.sqlite")
        self.now = datetime(2026, 11, 8, 0, 0, tzinfo=timezone.utc)
        self.task = task_fixture()
        self.ledger = PrincipalReplayLedger(self.database)
        self.ledger.propose_many([self.task])

    def tearDown(self):
        try:
            self.ledger.close()
        except Exception:
            pass
        self.temp_dir.cleanup()

    def persist_lease(self, task=None, lease_id="HQL-REPLAY-01", ledger=None):
        target = ledger or self.ledger
        task = task or self.task
        lease = lease_fixture(task, self.now, lease_id)
        target.propose_lease(task, lease, self.now)
        return lease

    def persist_receipt(self, task=None, receipt_id="HQV-REPLAY-01", ledger=None):
        target = ledger or self.ledger
        task = task or self.task
        receipt = receipt_fixture(task, self.now, receipt_id)
        target.record_untrusted_receipt(task, receipt)
        return receipt

    def record_worker(
        self,
        *,
        task=None,
        nonce="replay_nonce_000001",
        principal_id="WORKER.REPLAY.001",
        issuer="https://identity.example.test",
        lease_id="HQL-REPLAY-01",
        verifier=None,
        ledger=None,
    ):
        target = ledger or self.ledger
        task = task or self.task
        attestation = attestation_fixture(
            task,
            self.now,
            nonce=nonce,
            principal_id=principal_id,
            issuer=issuer,
            lease_id=lease_id,
        )
        result = target.record_verified_principal(
            task,
            attestation,
            expected_audience=AUDIENCE,
            expected_lease_id=lease_id,
            now=self.now,
            verifier=verifier or FakeVerifier(),
        )
        return result, attestation

    def test_worker_nonce_is_consumed_once_and_execution_remains_disabled(self):
        self.persist_lease()
        result, _ = self.record_worker()
        self.assertEqual(result["nonce_status"], "CONSUMED_ONCE")
        self.assertEqual(result["replay_protection_status"], "PERSISTED")
        self.assertFalse(result["raw_nonce_persisted"])
        self.assertFalse(result["execution_authorized"])
        verified = self.ledger.verify()
        self.assertEqual(verified["principal_nonce_use_count"], 1)
        self.assertEqual(verified["principal_nonce_audit_chain"], "VALID")

    def test_identical_attestation_replay_is_rejected(self):
        self.persist_lease()
        _, attestation = self.record_worker()
        with self.assertRaisesRegex(PrincipalReplayError, "PRINCIPAL_NONCE_REPLAYED"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now, verifier=FakeVerifier()
            )

    def test_changed_signature_with_same_nonce_is_rejected(self):
        self.persist_lease()
        _, attestation = self.record_worker()
        changed = dict(attestation)
        changed["signature"] = base64.urlsafe_b64encode(
            b"y" * 64
        ).decode("ascii").rstrip("=")
        with self.assertRaisesRegex(PrincipalReplayError, "PRINCIPAL_NONCE_REPLAYED"):
            self.ledger.record_verified_principal(
                self.task, changed, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now, verifier=FakeVerifier()
            )

    def test_same_nonce_same_principal_across_tasks_is_rejected(self):
        self.persist_lease()
        self.record_worker()
        second_task = task_fixture("HQ-REPLAY-02")
        self.ledger.propose_many([second_task])
        self.persist_lease(second_task, "HQL-REPLAY-02")
        with self.assertRaisesRegex(PrincipalReplayError, "PRINCIPAL_NONCE_REPLAYED"):
            self.record_worker(
                task=second_task, lease_id="HQL-REPLAY-02",
                principal_id="WORKER.REPLAY.001"
            )

    def test_same_nonce_different_principal_and_task_is_separately_scoped(self):
        self.persist_lease()
        self.record_worker()
        second_task = task_fixture("HQ-REPLAY-03")
        self.ledger.propose_many([second_task])
        self.persist_lease(second_task, "HQL-REPLAY-03")
        result, _ = self.record_worker(
            task=second_task, lease_id="HQL-REPLAY-03",
            principal_id="WORKER.REPLAY.002"
        )
        self.assertEqual(result["nonce_status"], "CONSUMED_ONCE")
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 2)

    def test_nonce_scope_includes_issuer(self):
        self.persist_lease()
        self.record_worker(issuer="https://issuer-one.example.test")
        second_task = task_fixture("HQ-REPLAY-04")
        self.ledger.propose_many([second_task])
        self.persist_lease(second_task, "HQL-REPLAY-04")
        result, _ = self.record_worker(
            task=second_task, lease_id="HQL-REPLAY-04",
            issuer="https://issuer-two.example.test"
        )
        self.assertEqual(result["nonce_status"], "CONSUMED_ONCE")

    def test_worker_requires_persisted_task(self):
        unpersisted = task_fixture("HQ-REPLAY-UNPERSISTED")
        attestation = attestation_fixture(
            unpersisted, self.now, lease_id="HQL-REPLAY-MISSING"
        )
        with self.assertRaisesRegex(LedgerError, "PRINCIPAL_TASK_NOT_PERSISTED"):
            self.ledger.record_verified_principal(
                unpersisted, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-MISSING", now=self.now,
                verifier=FakeVerifier()
            )

    def test_worker_requires_persisted_lease(self):
        attestation = attestation_fixture(
            self.task, self.now, lease_id="HQL-REPLAY-MISSING"
        )
        with self.assertRaisesRegex(LedgerError, "PRINCIPAL_WORKER_LEASE_NOT_PERSISTED"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-MISSING", now=self.now,
                verifier=FakeVerifier()
            )

    def test_reviewer_requires_persisted_receipt(self):
        attestation = attestation_fixture(
            self.task, self.now, principal_type="REVIEWER",
            receipt_id="HQV-REPLAY-MISSING",
        )
        with self.assertRaisesRegex(LedgerError, "PRINCIPAL_REVIEW_RECEIPT_NOT_PERSISTED"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_receipt_id="HQV-REPLAY-MISSING", now=self.now,
                verifier=FakeVerifier()
            )

    def test_reviewer_receipt_binding_consumes_nonce_once(self):
        self.persist_receipt()
        attestation = attestation_fixture(
            self.task, self.now, principal_type="REVIEWER",
            principal_id="REVIEWER.REPLAY.001",
        )
        result = self.ledger.record_verified_principal(
            self.task, attestation, expected_audience=AUDIENCE,
            expected_receipt_id="HQV-REPLAY-01", now=self.now,
            verifier=FakeVerifier()
        )
        self.assertEqual(result["binding"], "TASK_AND_RECEIPT")
        self.assertEqual(result["nonce_status"], "CONSUMED_ONCE")
        self.assertFalse(result["execution_authorized"])

    def test_worker_and_reviewer_bind_to_distinct_persisted_records(self):
        self.persist_lease()
        self.persist_receipt()
        worker, _ = self.record_worker(
            nonce="worker_nonce_replay_0001",
            principal_id="WORKER.REPLAY.001",
        )
        reviewer_attestation = attestation_fixture(
            self.task, self.now, principal_type="REVIEWER",
            nonce="reviewer_nonce_replay_01",
            principal_id="REVIEWER.REPLAY.001",
        )
        reviewer = self.ledger.record_verified_principal(
            self.task, reviewer_attestation, expected_audience=AUDIENCE,
            expected_receipt_id="HQV-REPLAY-01", now=self.now,
            verifier=FakeVerifier()
        )
        self.assertEqual(worker["principal_type"], "WORKER")
        self.assertEqual(reviewer["principal_type"], "REVIEWER")
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 2)

    def test_second_identity_cannot_claim_same_worker_lease(self):
        self.persist_lease()
        self.record_worker()
        with self.assertRaisesRegex(
            PrincipalReplayError, "PRINCIPAL_BINDING_ALREADY_CONSUMED"
        ):
            self.record_worker(
                nonce="worker_nonce_replay_0002",
                principal_id="WORKER.REPLAY.002",
            )

    def test_second_identity_cannot_claim_same_reviewer_receipt(self):
        self.persist_receipt()
        first = attestation_fixture(
            self.task, self.now, principal_type="REVIEWER",
            principal_id="REVIEWER.REPLAY.001",
            nonce="reviewer_nonce_replay_0001",
        )
        self.ledger.record_verified_principal(
            self.task, first, expected_audience=AUDIENCE,
            expected_receipt_id="HQV-REPLAY-01", now=self.now,
            verifier=FakeVerifier()
        )
        second = attestation_fixture(
            self.task, self.now, principal_type="REVIEWER",
            principal_id="REVIEWER.REPLAY.002",
            nonce="reviewer_nonce_replay_0002",
        )
        with self.assertRaisesRegex(
            PrincipalReplayError, "PRINCIPAL_BINDING_ALREADY_CONSUMED"
        ):
            self.ledger.record_verified_principal(
                self.task, second, expected_audience=AUDIENCE,
                expected_receipt_id="HQV-REPLAY-01", now=self.now,
                verifier=FakeVerifier()
            )

    def test_same_identity_cannot_be_worker_and_reviewer_for_same_task(self):
        self.persist_lease()
        self.persist_receipt()
        self.record_worker(principal_id="SHARED.PRINCIPAL.001")

        reviewer = attestation_fixture(
            self.task,
            self.now,
            principal_type="REVIEWER",
            nonce="reviewer_cross_role_nonce_0001",
            principal_id="SHARED.PRINCIPAL.001",
        )
        with self.assertRaisesRegex(
            PrincipalReplayError, "PRINCIPAL_CROSS_ROLE_IDENTITY_REUSE"
        ):
            self.ledger.record_verified_principal(
                self.task,
                reviewer,
                expected_audience=AUDIENCE,
                expected_receipt_id="HQV-REPLAY-01",
                now=self.now,
                verifier=FakeVerifier(),
            )
        verified = self.ledger.verify()
        self.assertEqual(verified["principal_nonce_use_count"], 1)
        self.assertEqual(verified["principal_nonce_audit_chain"], "VALID")

    def test_reviewer_identity_cannot_later_claim_worker_role_on_same_task(self):
        self.persist_receipt()
        reviewer = attestation_fixture(
            self.task,
            self.now,
            principal_type="REVIEWER",
            nonce="reviewer_cross_role_nonce_0002",
            principal_id="SHARED.PRINCIPAL.002",
        )
        self.ledger.record_verified_principal(
            self.task,
            reviewer,
            expected_audience=AUDIENCE,
            expected_receipt_id="HQV-REPLAY-01",
            now=self.now,
            verifier=FakeVerifier(),
        )
        self.persist_lease()
        worker = attestation_fixture(
            self.task,
            self.now,
            nonce="worker_cross_role_nonce_0002",
            principal_id="SHARED.PRINCIPAL.002",
        )
        with self.assertRaisesRegex(
            PrincipalReplayError, "PRINCIPAL_CROSS_ROLE_IDENTITY_REUSE"
        ):
            self.ledger.record_verified_principal(
                self.task,
                worker,
                expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01",
                now=self.now,
                verifier=FakeVerifier(),
            )
        verified = self.ledger.verify()
        self.assertEqual(verified["principal_nonce_use_count"], 1)
        self.assertEqual(verified["principal_nonce_audit_chain"], "VALID")

    def test_same_principal_may_hold_different_roles_on_different_tasks(self):
        self.persist_lease()
        self.record_worker(principal_id="SHARED.PRINCIPAL.003")

        second_task = task_fixture("HQ-REPLAY-CROSS-ROLE-02")
        self.ledger.propose_many([second_task])
        self.persist_receipt(second_task, receipt_id="HQV-REPLAY-CROSS-ROLE-02")
        reviewer = attestation_fixture(
            second_task,
            self.now,
            principal_type="REVIEWER",
            nonce="reviewer_cross_role_nonce_0003",
            principal_id="SHARED.PRINCIPAL.003",
            receipt_id="HQV-REPLAY-CROSS-ROLE-02",
        )
        result = self.ledger.record_verified_principal(
            second_task,
            reviewer,
            expected_audience=AUDIENCE,
            expected_receipt_id="HQV-REPLAY-CROSS-ROLE-02",
            now=self.now,
            verifier=FakeVerifier(),
        )
        self.assertEqual(result["principal_type"], "REVIEWER")
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 2)

    def test_concurrent_worker_and_reviewer_claims_for_same_identity_allow_one_role(self):
        self.persist_lease()
        self.persist_receipt()
        worker = attestation_fixture(
            self.task,
            self.now,
            nonce="worker_cross_role_race_0001",
            principal_id="SHARED.PRINCIPAL.RACE",
        )
        reviewer = attestation_fixture(
            self.task,
            self.now,
            principal_type="REVIEWER",
            nonce="reviewer_cross_role_race_0001",
            principal_id="SHARED.PRINCIPAL.RACE",
        )

        def consume(principal_type):
            connection = PrincipalReplayLedger(self.database)
            try:
                if principal_type == "WORKER":
                    return connection.record_verified_principal(
                        self.task,
                        worker,
                        expected_audience=AUDIENCE,
                        expected_lease_id="HQL-REPLAY-01",
                        now=self.now,
                        verifier=FakeVerifier(),
                    )
                return connection.record_verified_principal(
                    self.task,
                    reviewer,
                    expected_audience=AUDIENCE,
                    expected_receipt_id="HQV-REPLAY-01",
                    now=self.now,
                    verifier=FakeVerifier(),
                )
            except Exception as exc:
                return ("ERROR", str(exc))
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(consume, ("WORKER", "REVIEWER")))

        successes = [item for item in results if isinstance(item, dict)]
        failures = [item for item in results if isinstance(item, tuple)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0][1], "PRINCIPAL_CROSS_ROLE_IDENTITY_REUSE")
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 1)

    def test_rejected_signature_does_not_consume_nonce(self):
        self.persist_lease()
        attestation = attestation_fixture(self.task, self.now)
        with self.assertRaisesRegex(PrincipalContractError, "IDENTITY_SIGNATURE_REJECTED"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now,
                verifier=FakeVerifier(False)
            )
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 0)

    def test_verifier_exception_does_not_consume_nonce(self):
        self.persist_lease()
        attestation = attestation_fixture(self.task, self.now)
        with self.assertRaisesRegex(PrincipalContractError, "IDENTITY_VERIFIER_ERROR"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now,
                verifier=FakeVerifier(error=RuntimeError("synthetic private detail"))
            )
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 0)

    def test_invalid_audience_does_not_consume_nonce(self):
        self.persist_lease()
        attestation = attestation_fixture(
            self.task, self.now, audience="wrong-audience"
        )
        with self.assertRaisesRegex(PrincipalContractError, "PRINCIPAL_AUDIENCE_MISMATCH"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now,
                verifier=FakeVerifier()
            )
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 0)

    def test_raw_nonce_and_signature_are_not_stored(self):
        self.persist_lease()
        nonce = "raw_nonce_must_not_persist_01"
        self.record_worker(nonce=nonce)
        columns = {
            row["name"] for row in self.ledger._connection.execute(
                "PRAGMA table_info(principal_nonce_uses)"
            ).fetchall()
        }
        self.assertNotIn("nonce", columns)
        self.assertNotIn("signature", columns)
        rows = self.ledger._connection.execute(
            "SELECT * FROM principal_nonce_uses"
        ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertNotIn(nonce, repr(dict(rows[0])))

    def test_concurrent_replay_allows_exactly_one_consumer(self):
        self.persist_lease()
        attestation = attestation_fixture(self.task, self.now)

        def attempt():
            ledger = PrincipalReplayLedger(self.database)
            try:
                ledger.record_verified_principal(
                    self.task, attestation, expected_audience=AUDIENCE,
                    expected_lease_id="HQL-REPLAY-01", now=self.now,
                    verifier=FakeVerifier()
                )
                return "ACCEPTED"
            except PrincipalReplayError as exc:
                return str(exc)
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: attempt(), range(2)))
        self.assertEqual(results.count("ACCEPTED"), 1)
        self.assertEqual(results.count("PRINCIPAL_NONCE_REPLAYED"), 1)
        self.assertEqual(self.ledger.verify()["principal_nonce_use_count"], 1)

    def test_restart_recovery_preserves_replay_protection(self):
        self.persist_lease()
        _, attestation = self.record_worker()
        self.ledger.close()
        self.ledger = PrincipalReplayLedger(self.database)
        recovered = self.ledger.recover_after_restart()
        self.assertEqual(recovered["principal_nonce_uses_recovered"], 1)
        self.assertEqual(
            recovered["principal_nonce_replay_protection"],
            "PERSISTED_ONE_TIME_NONCES",
        )
        self.assertFalse(recovered["raw_nonce_values_stored"])
        self.assertFalse(recovered["execution_resumed"])
        with self.assertRaisesRegex(PrincipalReplayError, "PRINCIPAL_NONCE_REPLAYED"):
            self.ledger.record_verified_principal(
                self.task, attestation, expected_audience=AUDIENCE,
                expected_lease_id="HQL-REPLAY-01", now=self.now,
                verifier=FakeVerifier()
            )

    def test_nonce_audit_chain_detects_corruption(self):
        self.persist_lease()
        self.record_worker()
        self.ledger._connection.execute(
            "UPDATE principal_nonce_audit_events SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            PrincipalReplayCorruptionError, "PRINCIPAL_NONCE_AUDIT_CHAIN_HASH_INVALID"
        ):
            self.ledger.verify()

    def test_capacity_fails_closed(self):
        self.persist_lease()
        with patch(
            "scripts.enterprise_hq_principal_replay_ledger.MAX_PRINCIPAL_NONCE_USES", 1
        ):
            self.record_worker()
            second_task = task_fixture("HQ-REPLAY-CAPACITY")
            self.ledger.propose_many([second_task])
            self.persist_lease(second_task, "HQL-REPLAY-CAPACITY")
            with self.assertRaisesRegex(
                LedgerError, "PRINCIPAL_NONCE_CAPACITY_REACHED"
            ):
                self.record_worker(
                    task=second_task,
                    lease_id="HQL-REPLAY-CAPACITY",
                    nonce="capacity_nonce_replay_02",
                    principal_id="WORKER.REPLAY.002",
                )


if __name__ == "__main__":
    unittest.main()
