import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_budgeted_task_ledger import (
    BudgetedTaskLedger,
    MAX_LEDGER_BUDGETS,
)
from scripts.enterprise_hq_resource_budget import validate_resource_budget
from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
    TaskConflictError,
)


def task(task_id="HQ-BUDGET-01", workstream_id="WS-05"):
    return {
        "task_id": task_id,
        "workstream_id": workstream_id,
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def budget(task_value=None, budget_id="HQB-BIND-01"):
    task_value = task_value or task()
    normalized = validate_task(task_value)
    return {
        "schema_version": "1.0.0",
        "budget_id": budget_id,
        "task_id": normalized["task_id"],
        "proposal_digest": normalized["idempotency_key"],
        "max_runtime_seconds": 300,
        "max_memory_mib": 512,
        "max_output_bytes": 65536,
        "max_network_bytes": 0,
        "max_attempts": 2,
        "cloud_spend_limit_usd": "0.00",
        "network_mode": "DISABLED",
        "paid_services_allowed": False,
        "external_effects": False,
        "requires_human_approval": True,
    }


class BudgetedTaskLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = Path(self.temp_dir.name) / "budgeted-ledger.sqlite3"

    def tearDown(self):
        self.temp_dir.cleanup()

    def pair(self, task_value=None, budget_id="HQB-BIND-01"):
        task_value = task_value or task()
        return {"task": task_value, "budget": budget(task_value, budget_id)}

    def test_task_and_budget_are_persisted_atomically_with_two_valid_chains(self):
        with BudgetedTaskLedger(self.database) as ledger:
            result = ledger.propose_many_with_budgets([self.pair()])
            self.assertEqual(result["created_tasks"], 1)
            self.assertEqual(result["created_budgets"], 1)
            self.assertEqual(result["task_count"], 1)
            self.assertEqual(result["budget_count"], 1)
            self.assertEqual(result["status"], "HUMAN_REVIEW_REQUIRED")
            self.assertEqual(result["budget_enforcement_status"], "NOT_ENFORCED")
            self.assertFalse(result["execution_performed"])
            self.assertFalse(result["execution_authorized"])
            verified = ledger.verify()
            self.assertEqual(verified["integrity"], "PASS")
            self.assertEqual(verified["budget_audit_chain"], "VALID")

    def test_budget_binding_survives_reopen_without_execution_or_retry(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([self.pair()])
        with BudgetedTaskLedger(self.database) as reopened:
            recovered = reopened.recover_after_restart()
            self.assertEqual(recovered["recovery_status"], "PASS")
            self.assertEqual(recovered["tasks_recovered"], 1)
            self.assertEqual(recovered["budget_proposals_recovered"], 1)
            self.assertEqual(recovered["budget_proposals_pending_human_review"], 1)
            self.assertEqual(recovered["budget_enforcement_status"], "NOT_ENFORCED")
            self.assertFalse(recovered["execution_resumed"])
            self.assertFalse(recovered["automatic_retry"])

    def test_identical_task_and_budget_pair_is_idempotent(self):
        with BudgetedTaskLedger(self.database) as ledger:
            first = ledger.propose_many_with_budgets([self.pair()])
            second = ledger.propose_many_with_budgets([self.pair()])
            self.assertEqual(first["created_tasks"], 1)
            self.assertEqual(first["created_budgets"], 1)
            self.assertEqual(second["created_tasks"], 0)
            self.assertEqual(second["created_budgets"], 0)
            self.assertEqual(second["budgets_already_present"], 1)
            self.assertEqual(ledger.verify()["budget_audit_event_count"], 1)

    def test_existing_task_proposal_can_receive_its_first_budget(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many([task()])
            result = ledger.propose_many_with_budgets([self.pair()])
            self.assertEqual(result["created_tasks"], 0)
            self.assertEqual(result["created_budgets"], 1)
            self.assertEqual(ledger.verify()["task_count"], 1)
            self.assertEqual(ledger.verify()["budget_count"], 1)

    def test_wrong_proposal_digest_is_rejected_without_writes(self):
        pair = self.pair()
        pair["budget"]["proposal_digest"] = "0" * 64
        with BudgetedTaskLedger(self.database) as ledger:
            with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_DIGEST_MISMATCH"):
                ledger.propose_many_with_budgets([pair])
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 0)
            self.assertEqual(verified["budget_count"], 0)

    def test_budget_for_another_task_is_rejected_without_writes(self):
        pair = {"task": task(), "budget": budget(task("HQ-OTHER"))}
        with BudgetedTaskLedger(self.database) as ledger:
            with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_TASK_MISMATCH"):
                ledger.propose_many_with_budgets([pair])
            self.assertEqual(ledger.verify()["task_count"], 0)

    def test_conflicting_second_budget_for_same_task_is_rejected(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([self.pair()])
            with self.assertRaisesRegex(TaskConflictError, "TASK_BUDGET_CONTENT_CONFLICT"):
                ledger.propose_many_with_budgets([self.pair(budget_id="HQB-BIND-02")])
            self.assertEqual(ledger.verify()["budget_count"], 1)

    def test_duplicate_budget_ids_in_one_batch_are_rejected(self):
        first = self.pair(task("HQ-BUDGET-01"))
        second = self.pair(task("HQ-BUDGET-02"))
        second["budget"]["budget_id"] = first["budget"]["budget_id"]
        with BudgetedTaskLedger(self.database) as ledger:
            with self.assertRaisesRegex(ContractError, "DUPLICATE_BUDGET_ID"):
                ledger.propose_many_with_budgets([first, second])
            self.assertEqual(ledger.verify()["task_count"], 0)

    def test_budget_audit_append_failure_rolls_back_task_and_budget(self):
        with BudgetedTaskLedger(self.database) as ledger:
            with patch.object(
                ledger, "_append_budget_event", side_effect=RuntimeError("injected")
            ):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    ledger.propose_many_with_budgets([self.pair()])
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 0)
            self.assertEqual(verified["audit_event_count"], 0)
            self.assertEqual(verified["budget_count"], 0)
            self.assertEqual(verified["budget_audit_event_count"], 0)

    def test_corrupt_budget_hash_fails_closed_on_restart(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([self.pair()])
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE budget_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with BudgetedTaskLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "BUDGET_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.recover_after_restart()

    def test_corrupt_budget_chain_blocks_ordinary_task_append(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([self.pair()])
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE budget_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with BudgetedTaskLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "BUDGET_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.propose_many([task("HQ-BUDGET-02")])

    def test_budget_capacity_is_bounded_and_batch_rolls_back(self):
        first = self.pair(task("HQ-BUDGET-01"), "HQB-BIND-01")
        second = self.pair(task("HQ-BUDGET-02"), "HQB-BIND-02")
        with BudgetedTaskLedger(self.database) as ledger:
            with patch(
                "scripts.enterprise_hq_budgeted_task_ledger.MAX_LEDGER_BUDGETS", 1
            ):
                with self.assertRaisesRegex(
                    LedgerError, "BUDGET_LEDGER_CAPACITY_REACHED"
                ):
                    ledger.propose_many_with_budgets([first, second])
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 0)
            self.assertEqual(verified["budget_count"], 0)

    def test_invalid_pair_schema_is_rejected(self):
        pair = self.pair()
        pair["unexpected"] = True
        with BudgetedTaskLedger(self.database) as ledger:
            with self.assertRaisesRegex(
                ContractError, "BUDGET_PROPOSAL_SCHEMA_INVALID"
            ):
                ledger.propose_many_with_budgets([pair])

    def test_empty_or_oversized_budget_batch_is_rejected(self):
        with BudgetedTaskLedger(self.database) as ledger:
            with self.assertRaisesRegex(
                ContractError, "BUDGET_BATCH_SIZE_INVALID"
            ):
                ledger.propose_many_with_budgets([])
            pairs = [
                self.pair(task(f"HQ-BUDGET-{index:02d}"), f"HQB-BIND-{index:02d}")
                for index in range(1, 10)
            ]
            with self.assertRaisesRegex(
                ContractError, "BUDGET_BATCH_SIZE_INVALID"
            ):
                ledger.propose_many_with_budgets(pairs)

    def test_budget_rows_remain_proposals_not_claims_or_execution(self):
        with BudgetedTaskLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([self.pair()])
            row = ledger._connection.execute(
                "SELECT status FROM resource_budgets"
            ).fetchone()
            self.assertEqual(row["status"], "PROPOSED")
            verified = ledger.verify()
            self.assertEqual(verified["budget_enforcement_status"], "NOT_ENFORCED")
            self.assertFalse(ledger.recover_after_restart()["execution_resumed"])


    def test_concurrent_identical_budgeted_proposals_are_serialized(self):
        with BudgetedTaskLedger(self.database):
            pass
        worker_count = 6
        barrier = Barrier(worker_count)
        initialization_lock = Lock()

        def submit():
            with initialization_lock:
                ledger = BudgetedTaskLedger(self.database)
            try:
                barrier.wait(timeout=10)
                return ledger.propose_many_with_budgets([self.pair()])
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(lambda _: submit(), range(worker_count)))

        self.assertEqual(sum(item["created_tasks"] for item in results), 1)
        self.assertEqual(sum(item["created_budgets"] for item in results), 1)
        self.assertEqual(sum(item["budgets_already_present"] for item in results), worker_count - 1)
        with BudgetedTaskLedger(self.database) as ledger:
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 1)
            self.assertEqual(verified["budget_count"], 1)
            self.assertEqual(verified["audit_event_count"], 1)
            self.assertEqual(verified["budget_audit_event_count"], 1)

    def test_concurrent_conflicting_budgets_allow_only_one_binding(self):
        with BudgetedTaskLedger(self.database):
            pass
        barrier = Barrier(2)
        initialization_lock = Lock()

        def submit(budget_id):
            with initialization_lock:
                ledger = BudgetedTaskLedger(self.database)
            try:
                barrier.wait(timeout=10)
                try:
                    return ("created", ledger.propose_many_with_budgets([
                        self.pair(budget_id=budget_id)
                    ]))
                except TaskConflictError as exc:
                    return ("conflict", str(exc))
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(
                submit, ("HQB-CONCURRENT-A", "HQB-CONCURRENT-B")
            ))

        outcomes = [item[0] for item in results]
        self.assertEqual(outcomes.count("created"), 1)
        self.assertEqual(outcomes.count("conflict"), 1)
        with BudgetedTaskLedger(self.database) as ledger:
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 1)
            self.assertEqual(verified["budget_count"], 1)
            self.assertEqual(verified["audit_event_count"], 1)
            self.assertEqual(verified["budget_audit_event_count"], 1)


if __name__ == "__main__":
    unittest.main()
