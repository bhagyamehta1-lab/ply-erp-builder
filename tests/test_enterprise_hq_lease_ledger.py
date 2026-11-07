import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_lease_ledger import LeaseProposalLedger
from scripts.enterprise_hq_task_contract import validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
)


def task_fixture(task_id="HQ-LEASE-01", workstream_id="WS-01"):
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
    lease_id="HQL-PROPOSAL-01",
    owner="LOCAL-WORKER-A",
    attempt=1,
    issued=None,
    expires=None,
):
    task = task or task_fixture()
    validated = validate_task(task)
    issued = issued or datetime(2026, 11, 7, 13, 0, tzinfo=timezone.utc)
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


class LeaseProposalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "company-ledger.sqlite3"
        self.now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
        self.task = task_fixture()

    def tearDown(self):
        self.temp_dir.cleanup()

    def open_ledger_with_task(self):
        ledger = LeaseProposalLedger(self.database)
        ledger.propose_many([self.task])
        return ledger

    def test_lease_requires_an_existing_identical_task_proposal(self):
        with LeaseProposalLedger(self.database) as ledger:
            with self.assertRaisesRegex(LedgerError, "LEASE_TASK_NOT_PERSISTED"):
                ledger.propose_lease(self.task, lease_fixture(), self.now)

    def test_future_first_attempt_is_persisted_only_for_human_review(self):
        with self.open_ledger_with_task() as ledger:
            result = ledger.propose_lease(self.task, lease_fixture(), self.now)
            self.assertTrue(result["created"])
            self.assertTrue(result["proposal_persisted"])
            self.assertFalse(result["lease_issued"])
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(ledger.verify()["lease_proposal_count"], 1)

    def test_active_lease_cannot_be_persisted_as_a_proposal(self):
        with self.open_ledger_with_task() as ledger:
            active = lease_fixture(
                issued=self.now - timedelta(minutes=1),
                expires=self.now + timedelta(minutes=5),
            )
            with self.assertRaisesRegex(ValueError, "LEASE_PROPOSAL_MUST_BE_FUTURE"):
                ledger.propose_lease(self.task, active, self.now)

    def test_expired_lease_cannot_be_persisted_as_a_proposal(self):
        with self.open_ledger_with_task() as ledger:
            expired = lease_fixture(
                issued=self.now - timedelta(minutes=20),
                expires=self.now - timedelta(minutes=10),
            )
            with self.assertRaisesRegex(ValueError, "LEASE_PROPOSAL_MUST_BE_FUTURE"):
                ledger.propose_lease(self.task, expired, self.now)

    def test_successor_attempt_is_not_persisted_by_this_stage(self):
        with self.open_ledger_with_task() as ledger:
            successor = lease_fixture(attempt=2)
            with self.assertRaisesRegex(ValueError, "LEASE_SUCCESSOR_REQUIRES_SEPARATE_REVIEW"):
                ledger.propose_lease(self.task, successor, self.now)

    def test_identical_lease_proposal_is_idempotent(self):
        with self.open_ledger_with_task() as ledger:
            first = ledger.propose_lease(self.task, lease_fixture(), self.now)
            second = ledger.propose_lease(self.task, lease_fixture(), self.now)
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertTrue(second["already_present"])
            self.assertEqual(ledger.verify()["lease_audit_event_count"], 1)

    def test_reused_lease_id_with_different_content_is_rejected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
            changed = lease_fixture(owner="LOCAL-WORKER-B")
            with self.assertRaisesRegex(TaskConflictError, "LEASE_ID_CONTENT_CONFLICT"):
                ledger.propose_lease(self.task, changed, self.now)

    def test_only_one_lease_proposal_per_task_attempt_is_allowed(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
            other = lease_fixture(lease_id="HQL-PROPOSAL-02", owner="LOCAL-WORKER-B")
            with self.assertRaisesRegex(TaskConflictError, "LEASE_ATTEMPT_ALREADY_PROPOSED"):
                ledger.propose_lease(self.task, other, self.now)

    def test_proposal_cannot_be_bound_to_a_different_task_digest(self):
        with self.open_ledger_with_task() as ledger:
            changed_task = task_fixture(workstream_id="WS-02")
            lease = lease_fixture(task=changed_task)
            with self.assertRaisesRegex(LedgerError, "LEASE_TASK_NOT_PERSISTED"):
                ledger.propose_lease(changed_task, lease, self.now)

    def test_lease_audit_corruption_is_detected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE lease_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with LeaseProposalLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "LEASE_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.verify()

    def test_malformed_persisted_lease_is_rejected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE lease_proposals SET lease_json = ?", ('{"issued_at":17}',)
        )
        connection.commit()
        connection.close()
        with LeaseProposalLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "STORED_LEASE_CONTRACT_INVALID"
            ):
                reopened.verify()

    def test_corrupt_lease_chain_cannot_be_extended(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE lease_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with LeaseProposalLedger(self.database) as reopened:
            with self.assertRaises(LedgerCorruptionError):
                reopened.propose_lease(
                    self.task,
                    lease_fixture(lease_id="HQL-PROPOSAL-02"),
                    self.now,
                )
            connection = sqlite3.connect(self.database)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM lease_proposals").fetchone()[0],
                1,
            )
            connection.close()

    def test_restart_recovery_verifies_both_chains_without_resuming_work(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
        with LeaseProposalLedger(self.database) as reopened:
            result = reopened.recover_after_restart()
            self.assertEqual(result["recovery_status"], "PASS")
            self.assertEqual(result["lease_proposals_recovered"], 1)
            self.assertEqual(result["pending_lease_review"], 1)
            self.assertFalse(result["lease_execution_resumed"])
            self.assertFalse(result["lease_issued"])
            self.assertFalse(result["automatic_retry"])

    def test_lease_and_audit_write_roll_back_together(self):
        with self.open_ledger_with_task() as ledger:
            with patch.object(
                ledger, "_append_lease_event", side_effect=RuntimeError("injected")
            ):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    ledger.propose_lease(self.task, lease_fixture(), self.now)
            report = ledger.verify()
            self.assertEqual(report["lease_proposal_count"], 0)
            self.assertEqual(report["lease_audit_event_count"], 0)

    def test_lease_proposal_capacity_is_bounded(self):
        second_task = task_fixture(task_id="HQ-LEASE-02", workstream_id="WS-02")
        with LeaseProposalLedger(self.database) as ledger:
            ledger.propose_many([self.task, second_task])
            with patch(
                "scripts.enterprise_hq_lease_ledger.MAX_LEASE_PROPOSALS", 1
            ):
                ledger.propose_lease(self.task, lease_fixture(), self.now)
                with self.assertRaisesRegex(
                    LedgerError, "LEASE_PROPOSAL_CAPACITY_REACHED"
                ):
                    ledger.propose_lease(
                        second_task,
                        lease_fixture(
                            task=second_task, lease_id="HQL-PROPOSAL-02"
                        ),
                        self.now,
                    )

    def test_proposal_audit_event_is_separate_from_task_proposal_event(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
            task_events = ledger._connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event = 'TASK_PROPOSED'"
            ).fetchone()[0]
            lease_events = ledger._connection.execute(
                "SELECT COUNT(*) FROM lease_audit_events WHERE event = 'LEASE_PROPOSED'"
            ).fetchone()[0]
            self.assertEqual(task_events, 1)
            self.assertEqual(lease_events, 1)

    def test_task_status_remains_proposed_after_lease_proposal(self):
        with self.open_ledger_with_task() as ledger:
            ledger.propose_lease(self.task, lease_fixture(), self.now)
            status = ledger._connection.execute(
                "SELECT status FROM tasks WHERE task_id = ?",
                (self.task["task_id"],),
            ).fetchone()[0]
            self.assertEqual(status, "PROPOSED")


if __name__ == "__main__":
    unittest.main()
