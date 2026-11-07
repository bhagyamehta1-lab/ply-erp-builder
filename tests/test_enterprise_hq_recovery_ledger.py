import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock
from unittest.mock import patch

from scripts.enterprise_hq_recovery_ledger import (
    MAX_RECOVERY_PROPOSALS,
    SuccessorLeaseRecoveryLedger,
)
from scripts.enterprise_hq_task_contract import validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
)


def task_fixture(task_id="HQ-RECOVERY-01", workstream_id="WS-01"):
    return {
        "task_id": task_id,
        "workstream_id": workstream_id,
        "task_kind": "INTERNAL_RESEARCH",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def lease_fixture(
    task=None,
    lease_id="HQL-RECOVERY-OLD",
    owner="LOCAL-WORKER-A",
    attempt=1,
    issued=None,
    expires=None,
):
    task = task or task_fixture()
    validated = validate_task(task)
    issued = issued or datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
    expires = expires or issued + timedelta(minutes=10)
    return {
        "schema_version": "1.0.0",
        "lease_id": lease_id,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_owner_id": owner,
        "attempt": attempt,
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
    }


class SuccessorLeaseRecoveryLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "company-ledger.sqlite3"
        self.task = task_fixture()
        self.now = datetime(2026, 11, 7, 12, 20, tzinfo=timezone.utc)
        self.previous = lease_fixture()
        self.successor = lease_fixture(
            lease_id="HQL-RECOVERY-NEXT",
            owner="LOCAL-WORKER-B",
            attempt=2,
            issued=self.now + timedelta(minutes=1),
            expires=self.now + timedelta(minutes=11),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def open_ledger_with_expired_lease(self):
        ledger = SuccessorLeaseRecoveryLedger(self.database)
        ledger.propose_many([self.task])
        ledger.propose_lease(
            self.task,
            self.previous,
            self.previous_issued_time(),
        )
        return ledger

    def previous_issued_time(self):
        return datetime(2026, 11, 7, 11, 55, tzinfo=timezone.utc)

    def propose(self, ledger, **kwargs):
        return ledger.propose_successor_lease(
            self.task,
            kwargs.get("previous", self.previous),
            kwargs.get("successor", self.successor),
            kwargs.get("now", self.now),
            kwargs.get("side_effects_started", False),
        )

    def test_requires_persisted_task(self):
        with SuccessorLeaseRecoveryLedger(self.database) as ledger:
            with self.assertRaisesRegex(LedgerError, "RECOVERY_TASK_NOT_PERSISTED"):
                self.propose(ledger)

    def test_requires_exact_persisted_previous_lease(self):
        with SuccessorLeaseRecoveryLedger(self.database) as ledger:
            ledger.propose_many([self.task])
            with self.assertRaisesRegex(
                LedgerError, "RECOVERY_PREVIOUS_LEASE_NOT_PERSISTED"
            ):
                self.propose(ledger)

    def test_persists_attempt_two_proposal_for_human_review_only(self):
        with self.open_ledger_with_expired_lease() as ledger:
            result = self.propose(ledger)
            self.assertTrue(result["created"])
            self.assertTrue(result["successor_proposal_persisted"])
            self.assertFalse(result["successor_lease_issued"])
            self.assertFalse(result["automatic_retry"])
            self.assertFalse(result["execution_authorized"])
            verified = ledger.verify()
            self.assertEqual(verified["recovery_proposal_count"], 1)
            self.assertEqual(verified["recovery_audit_event_count"], 1)
            self.assertEqual(verified["recovery_audit_chain"], "VALID")

    def test_side_effects_started_requires_human_and_rejects_persistence(self):
        with self.open_ledger_with_expired_lease() as ledger:
            with self.assertRaisesRegex(
                ValueError, "RECOVERY_SIDE_EFFECTS_REQUIRE_HUMAN"
            ):
                self.propose(ledger, side_effects_started=True)
            self.assertEqual(ledger.verify()["recovery_proposal_count"], 0)

    def test_active_previous_lease_is_rejected(self):
        with self.open_ledger_with_expired_lease() as ledger:
            active_now = datetime(2026, 11, 7, 12, 5, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "PRIOR_LEASE_NOT_EXPIRED"):
                self.propose(ledger, now=active_now)

    def test_successor_cannot_overlap_previous_lease(self):
        with self.open_ledger_with_expired_lease() as ledger:
            now = datetime(2026, 11, 7, 12, 12, tzinfo=timezone.utc)
            overlapping = lease_fixture(
                lease_id="HQL-RECOVERY-OVERLAP",
                attempt=2,
                issued=datetime(2026, 11, 7, 12, 8, tzinfo=timezone.utc),
                expires=datetime(2026, 11, 7, 12, 18, tzinfo=timezone.utc),
            )
            with self.assertRaisesRegex(
                ValueError, "SUCCESSOR_LEASE_OVERLAPS_PRIOR"
            ):
                self.propose(ledger, successor=overlapping, now=now)

    def test_successor_must_be_attempt_two(self):
        with self.open_ledger_with_expired_lease() as ledger:
            wrong_attempt = lease_fixture(
                lease_id="HQL-RECOVERY-WRONG-ATTEMPT",
                attempt=1,
                issued=self.now + timedelta(minutes=1),
                expires=self.now + timedelta(minutes=11),
            )
            with self.assertRaisesRegex(ValueError, "SUCCESSOR_ATTEMPT_INVALID"):
                self.propose(ledger, successor=wrong_attempt)

    def test_successor_must_have_a_distinct_lease_id(self):
        with self.open_ledger_with_expired_lease() as ledger:
            reused = lease_fixture(
                lease_id=self.previous["lease_id"],
                attempt=2,
                issued=self.now + timedelta(minutes=1),
                expires=self.now + timedelta(minutes=11),
            )
            with self.assertRaisesRegex(ValueError, "SUCCESSOR_LEASE_ID_REUSED"):
                self.propose(ledger, successor=reused)

    def test_naive_evaluation_time_is_rejected(self):
        with self.open_ledger_with_expired_lease() as ledger:
            with self.assertRaisesRegex(ValueError, "RECOVERY_EVALUATION_TIME_INVALID"):
                self.propose(ledger, now=datetime(2026, 11, 7, 12, 20))

    def test_identical_recovery_proposal_is_idempotent(self):
        with self.open_ledger_with_expired_lease() as ledger:
            first = self.propose(ledger)
            second = self.propose(ledger, now=self.now + timedelta(seconds=5))
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertTrue(second["already_present"])
            self.assertEqual(ledger.verify()["recovery_audit_event_count"], 1)

    def test_different_successor_for_same_task_is_rejected(self):
        with self.open_ledger_with_expired_lease() as ledger:
            self.propose(ledger)
            different = lease_fixture(
                lease_id="HQL-RECOVERY-OTHER",
                owner="LOCAL-WORKER-C",
                attempt=2,
                issued=self.now + timedelta(minutes=2),
                expires=self.now + timedelta(minutes=12),
            )
            with self.assertRaisesRegex(
                TaskConflictError, "RECOVERY_TASK_ALREADY_HAS_DIFFERENT_SUCCESSOR"
            ):
                self.propose(ledger, successor=different)

    def test_previous_lease_payload_must_match_persisted_record(self):
        with self.open_ledger_with_expired_lease() as ledger:
            changed_previous = lease_fixture(owner="LOCAL-WORKER-X")
            with self.assertRaisesRegex(
                LedgerError, "RECOVERY_PREVIOUS_LEASE_NOT_PERSISTED"
            ):
                self.propose(ledger, previous=changed_previous)

    def test_recovery_and_audit_writes_roll_back_together(self):
        with self.open_ledger_with_expired_lease() as ledger:
            with patch.object(
                ledger, "_append_recovery_event", side_effect=RuntimeError("injected")
            ):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.propose(ledger)
            report = ledger.verify()
            self.assertEqual(report["recovery_proposal_count"], 0)
            self.assertEqual(report["recovery_audit_event_count"], 0)

    def test_recovery_audit_corruption_is_detected(self):
        with self.open_ledger_with_expired_lease() as ledger:
            self.propose(ledger)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE recovery_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with SuccessorLeaseRecoveryLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "RECOVERY_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.verify()

    def test_corrupt_recovery_chain_blocks_another_append(self):
        second_task = task_fixture("HQ-RECOVERY-02", "WS-02")
        with self.open_ledger_with_expired_lease() as ledger:
            self.propose(ledger)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE recovery_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with SuccessorLeaseRecoveryLedger(self.database) as reopened:
            reopened.propose_many([second_task])
            second_previous = lease_fixture(
                task=second_task,
                lease_id="HQL-RECOVERY-OLD-02",
                issued=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc),
                expires=datetime(2026, 11, 7, 12, 10, tzinfo=timezone.utc),
            )
            reopened.propose_lease(
                second_task, second_previous, self.previous_issued_time()
            )
            second_successor = lease_fixture(
                task=second_task,
                lease_id="HQL-RECOVERY-NEXT-02",
                attempt=2,
                issued=self.now + timedelta(minutes=1),
                expires=self.now + timedelta(minutes=11),
            )
            with self.assertRaises(LedgerCorruptionError):
                reopened.propose_successor_lease(
                    second_task, second_previous, second_successor, self.now
                )

    def test_restart_recovery_preserves_pending_proposal_without_execution(self):
        with self.open_ledger_with_expired_lease() as ledger:
            self.propose(ledger)
        with SuccessorLeaseRecoveryLedger(self.database) as reopened:
            result = reopened.recover_after_restart()
            self.assertEqual(result["recovery_status"], "PASS")
            self.assertEqual(result["successor_recovery_proposals_recovered"], 1)
            self.assertEqual(result["successor_recovery_proposals_pending_review"], 1)
            self.assertFalse(result["execution_resumed"])
            self.assertFalse(result["successor_lease_issued"])
            self.assertFalse(result["automatic_retry"])
            self.assertFalse(result["execution_authorized"])

    def test_recovery_capacity_is_bounded_and_failure_is_atomic(self):
        second_task = task_fixture("HQ-RECOVERY-02", "WS-02")
        with self.open_ledger_with_expired_lease() as ledger:
            with patch(
                "scripts.enterprise_hq_recovery_ledger.MAX_RECOVERY_PROPOSALS", 1
            ):
                self.propose(ledger)
                ledger.propose_many([second_task])
                second_previous = lease_fixture(
                    task=second_task,
                    lease_id="HQL-RECOVERY-OLD-02",
                    issued=datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc),
                    expires=datetime(2026, 11, 7, 12, 10, tzinfo=timezone.utc),
                )
                ledger.propose_lease(
                    second_task, second_previous, self.previous_issued_time()
                )
                second_successor = lease_fixture(
                    task=second_task,
                    lease_id="HQL-RECOVERY-NEXT-02",
                    attempt=2,
                    issued=self.now + timedelta(minutes=1),
                    expires=self.now + timedelta(minutes=11),
                )
                with self.assertRaisesRegex(
                    LedgerError, "RECOVERY_PROPOSAL_CAPACITY_REACHED"
                ):
                    ledger.propose_successor_lease(
                        second_task, second_previous, second_successor, self.now
                    )
            self.assertEqual(ledger.verify()["recovery_proposal_count"], 1)

    def test_concurrent_identical_recovery_proposals_are_idempotent(self):
        with self.open_ledger_with_expired_lease() as ledger:
            ledger.close()
        worker_count = 6
        barrier = Barrier(worker_count)
        initialization_lock = Lock()

        def submit():
            with initialization_lock:
                ledger = SuccessorLeaseRecoveryLedger(self.database)
            try:
                barrier.wait(timeout=10)
                return self.propose(ledger)
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(lambda _: submit(), range(worker_count)))

        self.assertEqual(sum(item["created"] for item in results), 1)
        self.assertEqual(sum(item["already_present"] for item in results), worker_count - 1)
        with SuccessorLeaseRecoveryLedger(self.database) as ledger:
            verified = ledger.verify()
            self.assertEqual(verified["recovery_proposal_count"], 1)
            self.assertEqual(verified["recovery_audit_event_count"], 1)

    def test_concurrent_conflicting_successors_allow_one_binding(self):
        with self.open_ledger_with_expired_lease() as ledger:
            ledger.close()
        barrier = Barrier(2)
        initialization_lock = Lock()

        def submit(successor):
            with initialization_lock:
                ledger = SuccessorLeaseRecoveryLedger(self.database)
            try:
                barrier.wait(timeout=10)
                try:
                    return ("created", self.propose(ledger, successor=successor))
                except TaskConflictError as exc:
                    return ("conflict", str(exc))
            finally:
                ledger.close()

        other = lease_fixture(
            lease_id="HQL-RECOVERY-OTHER",
            owner="LOCAL-WORKER-C",
            attempt=2,
            issued=self.now + timedelta(minutes=2),
            expires=self.now + timedelta(minutes=12),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, (self.successor, other)))

        self.assertEqual([item[0] for item in results].count("created"), 1)
        self.assertEqual([item[0] for item in results].count("conflict"), 1)
        with SuccessorLeaseRecoveryLedger(self.database) as ledger:
            self.assertEqual(ledger.verify()["recovery_proposal_count"], 1)

    def test_verification_covers_all_inherited_and_recovery_chains(self):
        with self.open_ledger_with_expired_lease() as ledger:
            result = self.propose(ledger)
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 1)
            self.assertEqual(verified["lease_proposal_count"], 1)
            self.assertEqual(verified["recovery_proposal_count"], 1)
            self.assertEqual(verified["lease_audit_chain"], "VALID")
            self.assertEqual(verified["recovery_audit_chain"], "VALID")
            self.assertEqual(result["status"], "PROPOSED_FOR_HUMAN_REVIEW")


if __name__ == "__main__":
    unittest.main()
