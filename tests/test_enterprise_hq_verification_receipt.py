import hashlib
import unittest

from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_verification_receipt import validate_verification_receipt


def task_fixture():
    return {
        "task_id": "HQ-VERIFY-01",
        "workstream_id": "WS-07",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def receipt_fixture(task=None):
    task = task or task_fixture()
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "receipt_id": "HQV-REVIEW-01",
        "task_id": validated["task_id"],
        "proposal_digest": validated["idempotency_key"],
        "logical_proposer_id": "LOCAL-WORKER-A",
        "logical_verifier_id": "LOCAL-REVIEWER-B",
        "proposer_role": validated["logical_role"],
        "verifier_role": "INDEPENDENT_VERIFIER",
        "claimed_verdict": "PASS",
        "evidence_digest": hashlib.sha256(b"evidence-placeholder").hexdigest(),
        "reviewed_at": "2026-11-07T12:00:00+00:00",
    }


class VerificationReceiptTests(unittest.TestCase):
    def test_valid_receipt_is_only_structurally_accepted(self):
        result = validate_verification_receipt(task_fixture(), receipt_fixture())
        self.assertEqual(result["receipt_status"], "STRUCTURE_VALID_ONLY")
        self.assertEqual(result["logical_separation"], "DISTINCT_ASSERTED_PRINCIPALS")
        self.assertEqual(result["identity_assurance"], "NOT_AUTHENTICATED")
        self.assertEqual(result["evidence_status"], "DIGEST_FORMAT_ONLY")
        self.assertEqual(result["semantic_verification"], "NOT_PERFORMED")
        self.assertIs(result["execution_authorized"], False)

    def test_rejects_same_asserted_principal(self):
        receipt = receipt_fixture()
        receipt["logical_verifier_id"] = receipt["logical_proposer_id"]
        with self.assertRaisesRegex(ContractError, "VERIFICATION_SELF_REVIEW_FORBIDDEN"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_cross_task_receipt(self):
        task = task_fixture()
        receipt = receipt_fixture(task)
        receipt["task_id"] = "HQ-OTHER-01"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_TASK_ID_MISMATCH"):
            validate_verification_receipt(task, receipt)

    def test_rejects_stale_proposal_digest(self):
        receipt = receipt_fixture()
        receipt["proposal_digest"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "VERIFICATION_PROPOSAL_DIGEST_MISMATCH"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_proposer_role_mismatch(self):
        receipt = receipt_fixture()
        receipt["proposer_role"] = "RESEARCH_ANALYST"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_PROPOSER_ROLE_MISMATCH"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_non_independent_verifier_role(self):
        receipt = receipt_fixture()
        receipt["verifier_role"] = "CODE_MAINTAINER"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_VERIFIER_ROLE_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_malformed_evidence_digest(self):
        receipt = receipt_fixture()
        receipt["evidence_digest"] = "not-a-digest"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_EVIDENCE_DIGEST_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_naive_timestamp(self):
        receipt = receipt_fixture()
        receipt["reviewed_at"] = "2026-11-07T12:00:00"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_TIMESTAMP_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_unknown_fields(self):
        receipt = receipt_fixture()
        receipt["identity_authenticated"] = True
        with self.assertRaisesRegex(ContractError, "VERIFICATION_RECEIPT_SCHEMA_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_unapproved_verdict(self):
        receipt = receipt_fixture()
        receipt["claimed_verdict"] = "APPROVED_FOR_EXECUTION"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_VERDICT_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_non_string_verdict_without_type_error(self):
        receipt = receipt_fixture()
        receipt["claimed_verdict"] = ["PASS"]
        with self.assertRaisesRegex(ContractError, "VERIFICATION_VERDICT_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_oversized_receipt(self):
        receipt = receipt_fixture()
        receipt["logical_verifier_id"] = "A" * 1000
        with self.assertRaisesRegex(ContractError, "VERIFICATION_RECEIPT_TOO_LARGE"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_invalid_receipt_id(self):
        receipt = receipt_fixture()
        receipt["receipt_id"] = "../forged"
        with self.assertRaisesRegex(ContractError, "VERIFICATION_RECEIPT_ID_INVALID"):
            validate_verification_receipt(task_fixture(), receipt)

    def test_rejects_invalid_task_before_receipt_validation(self):
        task = task_fixture()
        task["external_effects"] = True
        with self.assertRaisesRegex(ContractError, "EXTERNAL_EFFECTS_FORBIDDEN"):
            validate_verification_receipt(task, receipt_fixture())


if __name__ == "__main__":
    unittest.main()
