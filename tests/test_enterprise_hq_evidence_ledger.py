"""Tests for persistent metadata-only evidence verification outcomes."""
from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock
from unittest.mock import patch

from scripts.enterprise_hq_evidence_verifier import (
    EvidenceVerificationError,
    verify_evidence_bundle,
)
from scripts.enterprise_hq_evidence_ledger import (
    EvidenceVerificationLedger,
)
from scripts.enterprise_hq_task_contract import validate_task
from scripts.enterprise_hq_task_ledger import (
    LedgerCorruptionError,
    LedgerError,
)
from scripts.enterprise_hq_verification_ledger import (
    VerificationReceiptLedger,
)
from scripts.enterprise_hq_verification_receipt import validate_verification_receipt


TASK_ID = "HQ-EVIDENCE-01"
RECEIPT_ID = "HQV-EVIDENCE-01"
PATH = "docs/enterprise-hq-runtime.md"
PAYLOAD = b"sanitized internal company evidence"


def task_fixture(task_id=TASK_ID):
    return {
        "task_id": task_id,
        "workstream_id": "WS-07",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def bundle_fixture(task=None, *, receipt_id=RECEIPT_ID, payload=PAYLOAD):
    task = task or task_fixture()
    validated = validate_task(task)
    payloads = {PATH: payload}
    manifest = {
        "schema_version": "1.0.0",
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "receipt_id": receipt_id,
        "evidence": [{
            "path": PATH,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }],
    }
    verified = verify_evidence_bundle(
        manifest,
        payloads,
        expected_task_id=validated["task_id"],
        expected_proposal_digest=validated["idempotency_key"],
        expected_receipt_id=receipt_id,
    )
    return manifest, payloads, verified["manifest_digest"]


def receipt_fixture(task=None, *, receipt_id=RECEIPT_ID, evidence_digest=None):
    task = task or task_fixture()
    validated = validate_task(task)
    if evidence_digest is None:
        _, _, evidence_digest = bundle_fixture(task, receipt_id=receipt_id)
    return {
        "schema_version": "1.0.0",
        "receipt_id": receipt_id,
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_proposer_id": "LOCAL-WORKER-A",
        "logical_verifier_id": "LOCAL-REVIEWER-B",
        "proposer_role": validated["logical_role"],
        "verifier_role": "INDEPENDENT_VERIFIER",
        "claimed_verdict": "PASS",
        "evidence_digest": evidence_digest,
        "reviewed_at": "2026-11-08T00:00:00+00:00",
    }


class EvidenceVerificationLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "evidence-ledger.sqlite3")
        self.task = task_fixture()
        self.manifest, self.payloads, self.manifest_digest = bundle_fixture(self.task)
        self.receipt = receipt_fixture(
            self.task, evidence_digest=self.manifest_digest
        )

    def tearDown(self):
        self.temp.cleanup()

    def open_ready_ledger(self):
        ledger = EvidenceVerificationLedger(self.database)
        ledger.propose_many([self.task])
        ledger.record_untrusted_receipt(self.task, self.receipt)
        return ledger

    def record(self, ledger, **overrides):
        return ledger.record_verified_evidence(
            overrides.get("task", self.task),
            overrides.get("receipt", self.receipt),
            overrides.get("manifest", self.manifest),
            overrides.get("payloads", self.payloads),
        )

    def test_requires_existing_task_proposal(self):
        with EvidenceVerificationLedger(self.database) as ledger:
            with self.assertRaisesRegex(LedgerError, "EVIDENCE_TASK_NOT_PERSISTED"):
                self.record(ledger)
            self.assertEqual(ledger.verify()["evidence_verification_count"], 0)

    def test_requires_existing_identical_receipt_claim(self):
        with EvidenceVerificationLedger(self.database) as ledger:
            ledger.propose_many([self.task])
            with self.assertRaisesRegex(LedgerError, "EVIDENCE_RECEIPT_NOT_PERSISTED"):
                self.record(ledger)
            self.assertEqual(ledger.verify()["evidence_verification_count"], 0)

    def test_valid_evidence_is_persisted_as_integrity_metadata_only(self):
        with self.open_ready_ledger() as ledger:
            result = self.record(ledger)
            self.assertTrue(result["created"])
            self.assertEqual(result["status"], "CONTENT_INTEGRITY_VERIFIED")
            self.assertEqual(result["manifest_digest"], self.manifest_digest)
            self.assertEqual(result["evidence_count"], 1)
            self.assertEqual(result["total_bytes"], len(PAYLOAD))
            self.assertEqual(result["payload_retention"], "NONE")
            self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
            self.assertFalse(result["identity_authenticated"])
            self.assertEqual(result["reviewer_independence"], "NOT_ESTABLISHED")
            self.assertFalse(result["execution_authorized"])
            verified = ledger.verify()
            self.assertEqual(verified["evidence_verification_count"], 1)
            self.assertEqual(verified["evidence_verification_audit_event_count"], 1)
            self.assertEqual(verified["evidence_verification_audit_chain"], "VALID")

    def test_identical_evidence_verification_is_idempotent(self):
        with self.open_ready_ledger() as ledger:
            first = self.record(ledger)
            second = self.record(ledger)
            self.assertTrue(first["created"])
            self.assertFalse(second["created"])
            self.assertTrue(second["already_present"])
            self.assertEqual(ledger.verify()["evidence_verification_audit_event_count"], 1)

    def test_receipt_manifest_digest_mismatch_rejected(self):
        wrong = receipt_fixture(self.task, evidence_digest="f" * 64)
        other_db = str(Path(self.temp.name) / "wrong-receipt.sqlite3")
        with EvidenceVerificationLedger(other_db) as ledger:
            ledger.propose_many([self.task])
            ledger.record_untrusted_receipt(self.task, wrong)
            with self.assertRaisesRegex(
                EvidenceVerificationError, "RECEIPT_MANIFEST_DIGEST_MISMATCH"
            ):
                self.record(ledger, receipt=wrong)
            self.assertEqual(ledger.verify()["evidence_verification_count"], 0)

    def test_task_binding_mismatch_rejected(self):
        changed = dict(self.manifest)
        changed["task_id"] = "HQ-EVIDENCE-02"
        with self.open_ready_ledger() as ledger:
            with self.assertRaisesRegex(
                EvidenceVerificationError, "TASK_BINDING_MISMATCH"
            ):
                self.record(ledger, manifest=changed)

    def test_proposal_binding_mismatch_rejected(self):
        changed = dict(self.manifest)
        changed["proposal_digest"] = "b" * 64
        with self.open_ready_ledger() as ledger:
            with self.assertRaisesRegex(
                EvidenceVerificationError, "PROPOSAL_BINDING_MISMATCH"
            ):
                self.record(ledger, manifest=changed)

    def test_receipt_binding_mismatch_rejected(self):
        changed = dict(self.manifest)
        changed["receipt_id"] = "HQV-EVIDENCE-02"
        with self.open_ready_ledger() as ledger:
            with self.assertRaisesRegex(
                EvidenceVerificationError, "RECEIPT_BINDING_MISMATCH"
            ):
                self.record(ledger, manifest=changed)

    def test_payload_digest_mismatch_rejected(self):
        changed = {PATH: b"sanitized internal company evidencf"}
        with self.open_ready_ledger() as ledger:
            with self.assertRaisesRegex(
                EvidenceVerificationError, "EVIDENCE_DIGEST_MISMATCH"
            ):
                self.record(ledger, payloads=changed)

    def test_payload_set_mismatch_rejected(self):
        with self.open_ready_ledger() as ledger:
            with self.assertRaisesRegex(
                EvidenceVerificationError, "PAYLOAD_SET_MISMATCH"
            ):
                self.record(ledger, payloads={})

    def test_manifest_digest_is_deterministic(self):
        _, _, digest_again = bundle_fixture(self.task)
        self.assertEqual(self.manifest_digest, digest_again)

    def test_raw_payload_bytes_are_not_persisted(self):
        marker = b"UNIQUE-SANITIZED-TEST-PAYLOAD-NOT-TO-BE-STORED"
        manifest, payloads, digest = bundle_fixture(self.task, payload=marker)
        receipt = receipt_fixture(self.task, evidence_digest=digest)
        with EvidenceVerificationLedger(self.database) as ledger:
            ledger.propose_many([self.task])
            ledger.record_untrusted_receipt(self.task, receipt)
            ledger.record_verified_evidence(self.task, receipt, manifest, payloads)
        connection = sqlite3.connect(self.database)
        try:
            stored = []
            for table in (
                "evidence_verifications",
                "evidence_verification_audit_events",
                "verification_receipts",
            ):
                for row in connection.execute(f"SELECT * FROM {table}").fetchall():
                    stored.extend(str(value) for value in row if value is not None)
            self.assertNotIn(marker.decode("ascii"), " ".join(stored))
        finally:
            connection.close()

    def test_audit_hash_corruption_is_detected_after_restart(self):
        with self.open_ready_ledger() as ledger:
            self.record(ledger)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE evidence_verification_audit_events SET record_hash = ?",
            ("0" * 64,),
        )
        connection.commit()
        connection.close()
        with EvidenceVerificationLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "EVIDENCE_VERIFICATION_AUDIT_CHAIN_HASH_INVALID"
            ):
                reopened.recover_after_restart()

    def test_missing_audit_event_is_detected(self):
        with self.open_ready_ledger() as ledger:
            self.record(ledger)
        connection = sqlite3.connect(self.database)
        connection.execute("DELETE FROM evidence_verification_audit_events")
        connection.commit()
        connection.close()
        with EvidenceVerificationLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "EVIDENCE_VERIFICATION_AUDIT_EVENT_COUNT_MISMATCH"
            ):
                reopened.verify()

    def test_tampered_manifest_digest_is_detected(self):
        with self.open_ready_ledger() as ledger:
            self.record(ledger)
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE evidence_verifications SET manifest_digest = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with EvidenceVerificationLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "STORED_EVIDENCE_VERIFICATION_INVARIANT_FAILED"
            ):
                reopened.verify()

    def test_restart_recovery_preserves_review_only_state(self):
        with self.open_ready_ledger() as ledger:
            self.record(ledger)
        with EvidenceVerificationLedger(self.database) as reopened:
            result = reopened.recover_after_restart()
            self.assertEqual(result["recovery_status"], "PASS")
            self.assertEqual(result["verified_evidence_receipts_recovered"], 1)
            self.assertEqual(result["evidence_pending_semantic_review"], 1)
            self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
            self.assertFalse(result["execution_resumed"])
            self.assertFalse(result["automatic_retry"])

    def test_audit_append_failure_rolls_back_record_and_event(self):
        with self.open_ready_ledger() as ledger:
            with patch.object(
                ledger, "_append_evidence_event", side_effect=RuntimeError("injected")
            ):
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.record(ledger)
            verified = ledger.verify()
            self.assertEqual(verified["evidence_verification_count"], 0)
            self.assertEqual(verified["evidence_verification_audit_event_count"], 0)

    def test_capacity_is_bounded_and_failure_is_atomic(self):
        second_task = task_fixture("HQ-EVIDENCE-02")
        second_manifest, second_payloads, second_digest = bundle_fixture(
            second_task, receipt_id="HQV-EVIDENCE-02"
        )
        second_receipt = receipt_fixture(
            second_task, receipt_id="HQV-EVIDENCE-02", evidence_digest=second_digest
        )
        with EvidenceVerificationLedger(self.database) as ledger:
            ledger.propose_many([self.task, second_task])
            ledger.record_untrusted_receipt(self.task, self.receipt)
            ledger.record_untrusted_receipt(second_task, second_receipt)
            self.record(ledger)
            with patch(
                "scripts.enterprise_hq_evidence_ledger.MAX_EVIDENCE_VERIFICATION_RECEIPTS",
                1,
            ):
                with self.assertRaisesRegex(
                    LedgerError, "EVIDENCE_VERIFICATION_CAPACITY_REACHED"
                ):
                    ledger.record_verified_evidence(
                        second_task, second_receipt, second_manifest, second_payloads
                    )
            self.assertEqual(ledger.verify()["evidence_verification_count"], 1)

    def test_corrupt_inherited_receipt_chain_blocks_evidence_append(self):
        with self.open_ready_ledger() as ledger:
            ledger.record_verified_evidence(
                self.task, self.receipt, self.manifest, self.payloads
            )
        connection = sqlite3.connect(self.database)
        connection.execute(
            "UPDATE verification_audit_events SET record_hash = ?", ("0" * 64,)
        )
        connection.commit()
        connection.close()
        with EvidenceVerificationLedger(self.database) as reopened:
            with self.assertRaisesRegex(
                LedgerCorruptionError, "VERIFICATION_AUDIT_CHAIN_HASH_INVALID"
            ):
                self.record(reopened)

    def test_concurrent_identical_verifications_are_serialized(self):
        with self.open_ready_ledger() as ledger:
            pass
        workers = 6
        barrier = Barrier(workers)
        initialization_lock = Lock()

        def submit():
            with initialization_lock:
                ledger = EvidenceVerificationLedger(self.database)
            try:
                barrier.wait(timeout=10)
                return self.record(ledger)
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda _: submit(), range(workers)))
        self.assertEqual(sum(item["created"] for item in results), 1)
        self.assertEqual(
            sum(item["already_present"] for item in results), workers - 1
        )
        with EvidenceVerificationLedger(self.database) as ledger:
            verified = ledger.verify()
            self.assertEqual(verified["evidence_verification_count"], 1)
            self.assertEqual(verified["evidence_verification_audit_event_count"], 1)

    def test_unified_ledger_reports_all_inherited_and_evidence_chains(self):
        with self.open_ready_ledger() as ledger:
            self.record(ledger)
            result = ledger.verify()
            self.assertEqual(result["task_count"], 1)
            self.assertEqual(result["verification_receipt_count"], 1)
            self.assertEqual(result["evidence_verification_count"], 1)
            self.assertEqual(result["audit_chain"], "VALID")
            self.assertEqual(result["verification_audit_chain"], "VALID")
            self.assertEqual(result["evidence_verification_audit_chain"], "VALID")
            self.assertEqual(result["evidence_payload_retention"], "NONE")

    def test_result_never_claims_semantic_or_execution_authority(self):
        with self.open_ready_ledger() as ledger:
            result = self.record(ledger)
            self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
            self.assertFalse(result["identity_authenticated"])
            self.assertFalse(result["execution_authorized"])
            self.assertNotIn("payloads", result)
            self.assertNotIn("evidence", result)


if __name__ == "__main__":
    unittest.main()
