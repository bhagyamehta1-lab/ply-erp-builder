import unittest

from scripts.enterprise_hq_task_contract import (
    ContractError,
    make_audit_record,
    recovery_decision,
    route_task,
    validate_batch,
    validate_task,
    verification_plan,
    verify_audit_chain,
)


def task(**overrides):
    value = {
        "task_id": "HQ-001",
        "workstream_id": "WS-01",
        "task_kind": "INTERNAL_RESEARCH",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }
    value.update(overrides)
    return value


class TaskContractTests(unittest.TestCase):
    def test_routes_only_to_deterministic_logical_role(self):
        routed = route_task(task(task_kind="INTERNAL_CODE"))
        self.assertEqual(routed["logical_role"], "CODE_MAINTAINER")
        self.assertEqual(routed["status"], "PROPOSED")

    def test_rejects_unhashable_task_kind_and_workstream(self):
        with self.assertRaises(ContractError):
            validate_task(task(workstream_id=["WS-01"]))
        with self.assertRaises(ContractError):
            validate_task(task(task_kind=["INTERNAL_RESEARCH"]))

    def test_rejects_malformed_task_id(self):
        with self.assertRaisesRegex(ContractError, "TASK_ID_INVALID"):
            validate_task(task(task_id="HQ-A-"))

    def test_rejects_product_workstream(self):
        with self.assertRaisesRegex(ContractError, "WORKSTREAM_NOT_ALLOWED"):
            validate_task(task(workstream_id="PLY-0001"))

    def test_rejects_external_effects(self):
        with self.assertRaisesRegex(ContractError, "EXTERNAL_EFFECTS_FORBIDDEN"):
            validate_task(task(external_effects=True))

    def test_requires_human_review(self):
        with self.assertRaisesRegex(ContractError, "HUMAN_REVIEW_REQUIRED"):
            validate_task(task(requires_human_approval=False))

    def test_rejects_non_proposed_or_retried_input(self):
        with self.assertRaises(ContractError):
            validate_task(task(status="CLAIMED"))
        with self.assertRaises(ContractError):
            validate_task(task(attempt=1))

    def test_rejects_extra_payload_fields(self):
        with self.assertRaisesRegex(ContractError, "TASK_SCHEMA_INVALID"):
            validate_task(task(private_payload="not-allowed"))

    def test_idempotency_key_is_deterministic(self):
        first = validate_task(task())
        second = validate_task(task())
        self.assertEqual(first["idempotency_key"], second["idempotency_key"])

    def test_batch_is_bounded_and_ids_are_unique(self):
        self.assertEqual(len(validate_batch([task(), task(task_id="HQ-002")])), 2)
        with self.assertRaisesRegex(ContractError, "DUPLICATE_TASK_ID"):
            validate_batch([task(), task()])
        with self.assertRaisesRegex(ContractError, "BATCH_SIZE_INVALID"):
            validate_batch([task(task_id=f"HQ-{i:03d}") for i in range(9)])

    def test_verification_plan_separates_logical_roles_without_claiming_identity(self):
        plan = verification_plan(validate_task(task()))
        self.assertNotEqual(plan["assignee_role"], plan["verifier_role"])
        self.assertEqual(plan["verification_status"], "REVIEW_REQUIRED")
        self.assertEqual(plan["identity_assurance"], "NOT_AUTHENTICATED")

    def test_recovery_is_bounded_and_never_dispatches(self):
        self.assertEqual(recovery_decision(0, False, False), "NO_ACTION")
        self.assertEqual(recovery_decision(0, True, False), "RETRY_ELIGIBLE")
        self.assertEqual(recovery_decision(2, True, False), "HUMAN_REVIEW_REQUIRED")
        self.assertEqual(recovery_decision(0, True, True), "HUMAN_REVIEW_REQUIRED")

    def test_hash_chained_audit_records_detect_tampering(self):
        first = make_audit_record("HQ-001", "TASK_PROPOSED", "RESEARCH_ANALYST")
        second = make_audit_record(
            "HQ-001", "VERIFICATION_REQUESTED", "INDEPENDENT_VERIFIER", first["record_hash"]
        )
        self.assertTrue(verify_audit_chain([first, second]))
        altered = dict(second)
        altered["event"] = "TASK_ROUTED"
        self.assertFalse(verify_audit_chain([first, altered]))

    def test_audit_chain_rejects_malformed_event_types(self):
        first = make_audit_record("HQ-001", "TASK_PROPOSED", "RESEARCH_ANALYST")
        malformed = dict(first)
        malformed["event"] = ["TASK_PROPOSED"]
        self.assertFalse(verify_audit_chain([malformed]))

    def test_audit_chain_rejects_broken_link(self):
        first = make_audit_record("HQ-001", "TASK_PROPOSED", "RESEARCH_ANALYST")
        second = make_audit_record("HQ-001", "TASK_ROUTED", "CODE_MAINTAINER")
        self.assertFalse(verify_audit_chain([first, second]))


if __name__ == "__main__":
    unittest.main()
