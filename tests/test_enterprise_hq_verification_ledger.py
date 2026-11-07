import hashlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Lock
from unittest.mock import patch

from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_task_ledger import LedgerCorruptionError, LedgerError, TaskConflictError
from scripts.enterprise_hq_verification_ledger import (
    VerificationReceiptLedger,
)
from scripts.enterprise_hq_lease_ledger import LeaseProposalLedger


def task_fixture(task_id="HQ-VERIFY-01"):
    return {
        "task_id": task_id,
        "workstream_id": "WS-07",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def receipt_fixture(task=None, *, receipt_id="HQV-REVIEW-01", verdict="PASS"):
    task = task or task_fixture()
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "receipt_id": receipt_id,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_proposer_id": "LOCAL-WORKER-A",
        "logical_verifier_id": "LOCAL-REVIEWER-B",
        "proposer_role": validated["logical_role"],
        "verifier_role": "INDEPENDENT_VERIFIER",
        "claimed_verdict": verdict,
        "evidence_digest": hashlib.sha256(b"evidence-placeholder").hexdigest(),
        "reviewed_at": "2026-11-07T12:00:00+00:00",
    }


def budget_fixture(task=None):
    task = task or task_fixture()
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "budget_id": "HQB-VERIFY-01",
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
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


def lease_fixture(task=None):
    task = task or task_fixture()
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "lease_id": "HQL-VERIFY-01",
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_owner_id": "LOCAL-WORKER-A",
        "attempt": 1,
        "issued_at": "2026-11-07T12:00:00+00:00",
        "expires_at": "2026-11-07T12:10:00+00:00",
    }


class VerificationReceiptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp_dir.name) / "verification-ledger.sqlite3")
        self.task = task_fixture()

    def tearDown(self):
        self.temp_dir.cleanup()

    def open_ledger_with_task(self):
        ledger = VerificationReceiptLedger(self.database)
        ledger.propose_many([self.task])
        return ledger

    def test_receipt_requires_an_existing_identical_task_proposal(self):
        with VerificationReceiptLedger(self.database) as ledger:
            with self.assertRaisesRegex(LedgerError, "VERIFICATION_TASK_NOT_PERSISTED"):
                ledger.record_untrusted_receipt(self.task, receipt_fixture())

    def test_valid_receipt_is_persisted_as_an_unauthenticated_claim(self):
        with self.open_ledger_with_task() as ledger:
            result = ledger.record_untrusted_receipt(self.task, receipt_fixture())
            self.assertTrue(result["created"])
            self.assertEqual(result["status"], "UNAUTHENTICATED_CLAIM")
            self.assertEqual(result["receipt_status"], "STRUCTURE_VALID_ONLY")
            self.assertEqual(result["identity_assurance"], "NOT_AUTHENTICATED")
            self.assertEqual(result["evidence_status"], "DIGEST_FORMAT_ONLY")
            self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
            self.assertEqual(result["independent_verification_status"], "NOT_ESTABLISHED")
            self.assertFalse(result["execution_authorized"])
            self.assertEqual(ledger.verify()["verification_receipt_count"], 1)

    def test_identical_receipt_is_idempotent(self):
        with self.open_ledger_with_task() as ledger:
            first = ledger.record_untrusted_receipt(self.task, receipt_fixture())
            second = ledger.record_untrusted_receipt(self.task, receipt_fixture())
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertTrue(second["already_present"])
            self.assertEqual(ledger.verify()["verification_audit_event_count"], 1)

    def test_receipt_id_conflict_with_different_content_is_rejected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
            changed = receipt_fixture(verdict="FAIL")
            with self.assertRaisesRegex(
                TaskConflictError, "VERIFICATION_RECEIPT_ID_CONTENT_CONFLICT"
            ):
                ledger.record_untrusted_receipt(self.task, changed)
            self.assertEqual(ledger.verify()["verification_receipt_count"], 1)

    def test_wrong_task_digest_is_rejected_without_writes(self):
        receipt = receipt_fixture()
        receipt["proposal_digest"] = "0" * 64
        with self.open_ledger_with_task() as ledger:
            with self.assertRaisesRegex(
                ContractError, "VERIFICATION_PROPOSAL_DIGEST_MISMATCH"
            ):
                ledger.record_untrusted_receipt(self.task, receipt)
            self.assertEqual(ledger.verify()["verification_receipt_count"], 0)

    def test_cross_task_receipt_is_rejected_without_writes(self):
        receipt = receipt_fixture()
        receipt["task_id"] = "HQ-OTHER-01"
        with self.open_ledger_with_task() as ledger:
            with self.assertRaisesRegex(
                ContractError, "VERIFICATION_TASK_ID_MISMATCH"
            ):
                ledger.record_untrusted_receipt(self.task, receipt)
            self.assertEqual(ledger.verify()["verification_receipt_count"], 0)

    def test_self_review_claim_is_rejected(self):
        receipt = receipt_fixture()
        receipt["logical_verifier_id"] = receipt["logical_proposer_id"]
        with self.open_ledger_with_task() as ledger:
            with self.assertRaisesRegex(
                ContractError, "VERIFICATION_SELF_REVIEW_FORBIDDEN"
            ):
                ledger.record_untrusted_receipt(self.task, receipt)

    def test_unpersisted_different_task_is_rejected(self):
        other = task_fixture("HQ-VERIFY-02")
        with self.open_ledger_with_task() as ledger:
            with self.assertRaisesRegex(LedgerError, "VERIFICATION_TASK_NOT_PERSISTED"):
                ledger.record_untrusted_receipt(other, receipt_fixture(other))

    def test_receipt_and_audit_event_roll_back_together(self):
        with self.open_ledger_with_task() as ledger:
            with patch.object(
                ledger, "_append_receipt_event", side_effect=RuntimeError("injected")
            ):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    ledger.record_untrusted_receipt(self.task, receipt_fixture())
            verified = ledger.verify()
            self.assertEqual(verified["verification_receipt_count"], 0)
            self.assertEqual(verified["verification_audit_event_count"], 0)

    def test_corrupt_receipt_hash_fails_restart_recovery(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE verification_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with VerificationReceiptLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "VERIFICATION_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.recover_after_restart()

    def test_corrupt_receipt_chain_blocks_a_new_append(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE verification_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with VerificationReceiptLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "VERIFICATION_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.record_untrusted_receipt(
                    self.task, receipt_fixture(receipt_id="HQV-REVIEW-02")
                )

    def test_tampered_receipt_payload_is_detected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE verification_receipts SET receipt_json = ?", ('{"claimed_verdict":"PASS"}',)
        )
        connection.commit()
        connection.close()
        with VerificationReceiptLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "STORED_VERIFICATION_RECEIPT_INVALID"
            ):
                reopened.verify()

    def test_missing_receipt_audit_event_is_detected(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        connection = sqlite3.connect(self.database)
        connection.execute("DELETE FROM verification_audit_events")
        connection.commit()
        connection.close()
        with VerificationReceiptLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "VERIFICATION_AUDIT_EVENT_COUNT_MISMATCH"
            ):
                reopened.verify()

    def test_receipt_capacity_is_bounded_and_failure_is_atomic(self):
        second = task_fixture("HQ-VERIFY-02")
        with VerificationReceiptLedger(self.database) as ledger:
            ledger.propose_many([self.task, second])
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
            with patch(
                "scripts.enterprise_hq_verification_ledger.MAX_VERIFICATION_RECEIPTS", 1
            ):
                with self.assertRaisesRegex(
                    LedgerError, "VERIFICATION_RECEIPT_CAPACITY_REACHED"
                ):
                    ledger.record_untrusted_receipt(
                        second, receipt_fixture(second, receipt_id="HQV-REVIEW-02")
                    )
            self.assertEqual(ledger.verify()["verification_receipt_count"], 1)

    def test_restart_recovery_preserves_untrusted_state_without_execution(self):
        with self.open_ledger_with_task() as ledger:
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        with VerificationReceiptLedger(self.database) as reopened:
            result = reopened.recover_after_restart()
            self.assertEqual(result["recovery_status"], "PASS")
            self.assertEqual(result["untrusted_receipts_recovered"], 1)
            self.assertEqual(result["untrusted_receipts_pending_review"], 1)
            self.assertEqual(
                result["independent_verification_status"], "NOT_ESTABLISHED"
            )
            self.assertFalse(result["execution_resumed"])
            self.assertFalse(result["lease_issued"])
            self.assertFalse(result["automatic_retry"])

    def test_concurrent_identical_receipts_are_serialized(self):
        with VerificationReceiptLedger(self.database) as ledger:
            ledger.propose_many([self.task])
        worker_count = 6
        barrier = Barrier(worker_count)
        initialization_lock = Lock()

        def submit():
            with initialization_lock:
                ledger = VerificationReceiptLedger(self.database)
            try:
                barrier.wait(timeout=10)
                return ledger.record_untrusted_receipt(self.task, receipt_fixture())
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            results = list(executor.map(lambda _: submit(), range(worker_count)))

        self.assertEqual(sum(item["created"] for item in results), 1)
        self.assertEqual(sum(item["already_present"] for item in results), worker_count - 1)
        with VerificationReceiptLedger(self.database) as ledger:
            verified = ledger.verify()
            self.assertEqual(verified["verification_receipt_count"], 1)
            self.assertEqual(verified["verification_audit_event_count"], 1)

    def test_concurrent_conflicting_receipts_allow_one_content_binding(self):
        with VerificationReceiptLedger(self.database) as ledger:
            ledger.propose_many([self.task])
        barrier = Barrier(2)
        initialization_lock = Lock()

        def submit(verdict):
            with initialization_lock:
                ledger = VerificationReceiptLedger(self.database)
            try:
                barrier.wait(timeout=10)
                try:
                    return ("created", ledger.record_untrusted_receipt(
                        self.task, receipt_fixture(verdict=verdict)
                    ))
                except TaskConflictError as exc:
                    return ("conflict", str(exc))
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(submit, ("PASS", "FAIL")))

        self.assertEqual([item[0] for item in results].count("created"), 1)
        self.assertEqual([item[0] for item in results].count("conflict"), 1)
        with VerificationReceiptLedger(self.database) as ledger:
            self.assertEqual(ledger.verify()["verification_receipt_count"], 1)

    def test_unified_ledger_verifies_task_budget_lease_and_receipt_chains(self):
        now = datetime(2026, 11, 7, 11, 55, tzinfo=timezone.utc)
        with VerificationReceiptLedger(self.database) as ledger:
            ledger.propose_many_with_budgets([
                {"task": self.task, "budget": budget_fixture(self.task)}
            ])
            lease_result = ledger.propose_lease(self.task, lease_fixture(self.task), now)
            self.assertTrue(lease_result["proposal_persisted"])
            receipt_result = ledger.record_untrusted_receipt(
                self.task, receipt_fixture(self.task)
            )
            self.assertEqual(receipt_result["status"], "UNAUTHENTICATED_CLAIM")
            verified = ledger.verify()
            self.assertEqual(verified["task_count"], 1)
            self.assertEqual(verified["budget_count"], 1)
            self.assertEqual(verified["lease_proposal_count"], 1)
            self.assertEqual(verified["verification_receipt_count"], 1)
            self.assertEqual(verified["budget_audit_chain"], "VALID")
            self.assertEqual(verified["lease_audit_chain"], "VALID")
            self.assertEqual(verified["verification_audit_chain"], "VALID")

    def test_recovery_reports_all_chain_counts_without_resuming_work(self):
        with VerificationReceiptLedger(self.database) as ledger:
            ledger.propose_many([self.task])
            ledger.record_untrusted_receipt(self.task, receipt_fixture())
        with VerificationReceiptLedger(self.database) as reopened:
            result = reopened.recover_after_restart()
            self.assertEqual(result["tasks_recovered"], 1)
            self.assertEqual(result["budget_proposals_recovered"], 0)
            self.assertEqual(result["lease_proposals_recovered"], 0)
            self.assertEqual(result["untrusted_receipts_recovered"], 1)
            self.assertFalse(result["execution_resumed"])


if __name__ == "__main__":
    unittest.main()
