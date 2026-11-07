import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
    TaskLedger,
)


def task(task_id="HQ-001", workstream_id="WS-01"):
    return {
        "task_id": task_id,
        "workstream_id": workstream_id,
        "task_kind": "INTERNAL_RESEARCH",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


class TaskLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "company-ledger.sqlite3"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_proposal_is_durable_across_reopen_and_recovery_is_read_only(self):
        with TaskLedger(self.database) as ledger:
            result = ledger.propose_many([task()])
            self.assertEqual(result["created"], 1)
            self.assertFalse(result["execution_performed"])
            self.assertEqual(ledger.verify()["integrity"], "PASS")

        with TaskLedger(self.database) as reopened:
            recovered = reopened.recover_after_restart()
            self.assertEqual(recovered["recovery_status"], "PASS")
            self.assertEqual(recovered["tasks_recovered"], 1)
            self.assertEqual(recovered["pending_human_review"], 1)
            self.assertFalse(recovered["execution_resumed"])
            self.assertFalse(recovered["automatic_retry"])

    def test_identical_proposal_is_idempotent(self):
        with TaskLedger(self.database) as ledger:
            first = ledger.propose_many([task()])
            second = ledger.propose_many([task()])
            self.assertEqual(first["created"], 1)
            self.assertEqual(second["created"], 0)
            self.assertEqual(second["already_present"], 1)
            self.assertEqual(ledger.verify()["audit_event_count"], 1)

    def test_same_task_id_with_different_content_is_rejected(self):
        with TaskLedger(self.database) as ledger:
            ledger.propose_many([task()])
            with self.assertRaisesRegex(TaskConflictError, "TASK_ID_CONTENT_CONFLICT"):
                ledger.propose_many([task(workstream_id="WS-02")])
            self.assertEqual(ledger.verify()["task_count"], 1)

    def test_batch_write_rolls_back_if_any_proposal_conflicts(self):
        with TaskLedger(self.database) as ledger:
            ledger.propose_many([task(task_id="HQ-002")])
            with self.assertRaises(TaskConflictError):
                ledger.propose_many([task(task_id="HQ-001"), task(task_id="HQ-002", workstream_id="WS-03")])
            report = ledger.verify()
            self.assertEqual(report["task_count"], 1)
            self.assertEqual(report["audit_event_count"], 1)

    def test_event_failure_rolls_back_task_and_audit_together(self):
        with TaskLedger(self.database) as ledger:
            with patch.object(ledger, "_append_proposal_event", side_effect=RuntimeError("injected")):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    ledger.propose_many([task()])
            self.assertEqual(ledger.verify()["task_count"], 0)
            self.assertEqual(ledger.verify()["audit_event_count"], 0)

    def test_corrupt_audit_hash_fails_closed_on_recovery(self):
        with TaskLedger(self.database) as ledger:
            ledger.propose_many([task()])
        connection = sqlite3.connect(self.database)
        connection.execute("UPDATE audit_events SET record_hash = ?", ("0" * 64,))
        connection.commit()
        connection.close()
        with TaskLedger(self.database) as reopened:
            with self.assertRaisesRegex(LedgerCorruptionError, "AUDIT_CHAIN_HASH_INVALID"):
                reopened.recover_after_restart()

    def test_capacity_is_bounded(self):
        with TaskLedger(self.database) as ledger:
            with patch("scripts.enterprise_hq_task_ledger.MAX_LEDGER_TASKS", 1):
                ledger.propose_many([task()])
                with self.assertRaisesRegex(LedgerError, "LEDGER_CAPACITY_REACHED"):
                    ledger.propose_many([task(task_id="HQ-002")])

    def test_execution_or_claim_status_cannot_be_persisted(self):
        with TaskLedger(self.database) as ledger:
            with self.assertRaises(ValueError):
                ledger.propose_many([{**task(), "status": "CLAIMED"}])
            self.assertEqual(ledger.verify()["task_count"], 0)


if __name__ == "__main__":
    unittest.main()
