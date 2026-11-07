import unittest

from scripts.enterprise_hq_resource_budget import (
    MAX_MEMORY_MIB,
    MAX_OUTPUT_BYTES,
    MAX_RUNTIME_SECONDS,
    validate_resource_budget,
)
from scripts.enterprise_hq_task_contract import ContractError, validate_task


def task_fixture():
    return {
        "task_id": "HQ-BUDGET-01",
        "workstream_id": "WS-05",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def budget_fixture(task=None):
    task = task or task_fixture()
    validated = validate_task(task)
    return {
        "schema_version": "1.0.0",
        "budget_id": "HQB-LOCAL-01",
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


class ResourceBudgetTests(unittest.TestCase):
    def test_valid_budget_is_validation_only_and_never_authorizes_execution(self):
        result = validate_resource_budget(task_fixture(), budget_fixture())
        self.assertEqual(result["budget_status"], "STRUCTURE_VALID_ONLY")
        self.assertEqual(result["enforcement_status"], "NOT_ENFORCED")
        self.assertFalse(result["execution_authorized"])
        self.assertTrue(result["human_approval_required"])
        self.assertEqual(result["cloud_spend_limit_usd"], "0.00")
        self.assertEqual(result["network_mode"], "DISABLED")

    def test_exact_resource_caps_are_accepted(self):
        result = validate_resource_budget(task_fixture(), budget_fixture())
        self.assertEqual(result["max_runtime_seconds"], MAX_RUNTIME_SECONDS)
        self.assertEqual(result["max_memory_mib"], MAX_MEMORY_MIB)
        self.assertEqual(result["max_output_bytes"], MAX_OUTPUT_BYTES)

    def test_unknown_budget_field_is_rejected(self):
        budget = budget_fixture()
        budget["unreviewed_limit"] = 1
        with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_SCHEMA_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_invalid_budget_identifier_is_rejected(self):
        budget = budget_fixture()
        budget["budget_id"] = "not-valid"
        with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_ID_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_wrong_task_identifier_is_rejected(self):
        budget = budget_fixture()
        budget["task_id"] = "HQ-OTHER"
        with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_TASK_MISMATCH"):
            validate_resource_budget(task_fixture(), budget)

    def test_wrong_proposal_digest_is_rejected(self):
        budget = budget_fixture()
        budget["proposal_digest"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "RESOURCE_BUDGET_DIGEST_MISMATCH"):
            validate_resource_budget(task_fixture(), budget)

    def test_runtime_above_cap_is_rejected(self):
        budget = budget_fixture()
        budget["max_runtime_seconds"] = MAX_RUNTIME_SECONDS + 1
        with self.assertRaisesRegex(ContractError, "RESOURCE_RUNTIME_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_boolean_runtime_is_not_accepted_as_integer(self):
        budget = budget_fixture()
        budget["max_runtime_seconds"] = True
        with self.assertRaisesRegex(ContractError, "RESOURCE_RUNTIME_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_memory_above_cap_is_rejected(self):
        budget = budget_fixture()
        budget["max_memory_mib"] = MAX_MEMORY_MIB + 1
        with self.assertRaisesRegex(ContractError, "RESOURCE_MEMORY_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_output_above_cap_is_rejected(self):
        budget = budget_fixture()
        budget["max_output_bytes"] = MAX_OUTPUT_BYTES + 1
        with self.assertRaisesRegex(ContractError, "RESOURCE_OUTPUT_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_nonzero_network_budget_is_rejected(self):
        budget = budget_fixture()
        budget["max_network_bytes"] = 1
        with self.assertRaisesRegex(ContractError, "RESOURCE_NETWORK_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_negative_network_budget_is_rejected(self):
        budget = budget_fixture()
        budget["max_network_bytes"] = -1
        with self.assertRaisesRegex(ContractError, "RESOURCE_NETWORK_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_nonzero_cloud_spend_is_rejected(self):
        budget = budget_fixture()
        budget["cloud_spend_limit_usd"] = "0.01"
        with self.assertRaisesRegex(ContractError, "RESOURCE_PAID_SPEND_FORBIDDEN"):
            validate_resource_budget(task_fixture(), budget)

    def test_numeric_zero_spend_is_rejected_as_noncanonical(self):
        budget = budget_fixture()
        budget["cloud_spend_limit_usd"] = 0
        with self.assertRaisesRegex(ContractError, "RESOURCE_PAID_SPEND_FORBIDDEN"):
            validate_resource_budget(task_fixture(), budget)

    def test_network_mode_must_be_disabled(self):
        budget = budget_fixture()
        budget["network_mode"] = "READ_ONLY"
        with self.assertRaisesRegex(ContractError, "RESOURCE_NETWORK_ACCESS_FORBIDDEN"):
            validate_resource_budget(task_fixture(), budget)

    def test_paid_services_must_remain_disabled(self):
        budget = budget_fixture()
        budget["paid_services_allowed"] = True
        with self.assertRaisesRegex(ContractError, "RESOURCE_PAID_SERVICES_FORBIDDEN"):
            validate_resource_budget(task_fixture(), budget)

    def test_external_effects_must_remain_disabled(self):
        budget = budget_fixture()
        budget["external_effects"] = True
        with self.assertRaisesRegex(ContractError, "RESOURCE_EXTERNAL_EFFECTS_FORBIDDEN"):
            validate_resource_budget(task_fixture(), budget)

    def test_human_approval_cannot_be_disabled(self):
        budget = budget_fixture()
        budget["requires_human_approval"] = False
        with self.assertRaisesRegex(ContractError, "RESOURCE_HUMAN_REVIEW_REQUIRED"):
            validate_resource_budget(task_fixture(), budget)

    def test_attempt_limit_cannot_exceed_contract_maximum(self):
        budget = budget_fixture()
        budget["max_attempts"] = 3
        with self.assertRaisesRegex(ContractError, "RESOURCE_ATTEMPT_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_boolean_attempt_limit_is_rejected(self):
        budget = budget_fixture()
        budget["max_attempts"] = True
        with self.assertRaisesRegex(ContractError, "RESOURCE_ATTEMPT_LIMIT_INVALID"):
            validate_resource_budget(task_fixture(), budget)

    def test_budget_cannot_make_an_invalid_task_eligible(self):
        task = task_fixture()
        task["external_effects"] = True
        with self.assertRaisesRegex(ContractError, "EXTERNAL_EFFECTS_FORBIDDEN"):
            validate_resource_budget(task, budget_fixture())


if __name__ == "__main__":
    unittest.main()
