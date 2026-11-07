import unittest
from datetime import datetime, timedelta, timezone

from scripts.enterprise_hq_task_contract import ContractError, validate_task
from scripts.enterprise_hq_lease_contract import (
    MAX_LEASE_SECONDS,
    lease_recovery_decision,
    validate_lease,
    validate_recovery_successor,
)


def task_fixture():
    return {
        "task_id": "HQ-LEASE-01",
        "workstream_id": "WS-08",
        "task_kind": "INTERNAL_CODE",
        "attempt": 0,
        "status": "PROPOSED",
        "external_effects": False,
        "requires_human_approval": True,
    }


def lease_fixture(
    task=None,
    *,
    lease_id="HQL-LEASE-01",
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


class LeaseContractTests(unittest.TestCase):
    def setUp(self):
        self.task = task_fixture()
        self.now = datetime(2026, 11, 7, 12, 5, tzinfo=timezone.utc)

    def test_active_lease_is_structural_only_and_not_authorized(self):
        result = validate_lease(self.task, lease_fixture(), self.now)
        self.assertEqual(result["lease_status"], "ACTIVE")
        self.assertEqual(result["identity_assurance"], "NOT_AUTHENTICATED")
        self.assertFalse(result["lease_persisted"])
        self.assertFalse(result["execution_authorized"])

    def test_future_lease_is_not_yet_valid(self):
        lease = lease_fixture(issued=self.now + timedelta(minutes=1))
        result = validate_lease(self.task, lease, self.now)
        self.assertEqual(result["lease_status"], "NOT_YET_VALID")

    def test_expired_lease_is_reported(self):
        lease = lease_fixture(expires=self.now)
        result = validate_lease(self.task, lease, self.now)
        self.assertEqual(result["lease_status"], "EXPIRED")

    def test_rejects_unknown_fields(self):
        lease = lease_fixture()
        lease["authenticated"] = True
        with self.assertRaisesRegex(ContractError, "LEASE_SCHEMA_INVALID"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_task_mismatch(self):
        lease = lease_fixture()
        lease["task_id"] = "HQ-OTHER-01"
        with self.assertRaisesRegex(ContractError, "LEASE_TASK_ID_MISMATCH"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_proposal_digest_mismatch(self):
        lease = lease_fixture()
        lease["proposal_digest"] = "0" * 64
        with self.assertRaisesRegex(ContractError, "LEASE_PROPOSAL_DIGEST_MISMATCH"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_invalid_owner_identifier(self):
        lease = lease_fixture(owner="../runner")
        with self.assertRaisesRegex(ContractError, "LEASE_OWNER_ID_INVALID"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_zero_or_boolean_attempt(self):
        for attempt in (0, True, 3):
            lease = lease_fixture(attempt=attempt)
            with self.subTest(attempt=attempt):
                with self.assertRaisesRegex(ContractError, "LEASE_ATTEMPT_INVALID"):
                    validate_lease(self.task, lease, self.now)

    def test_rejects_naive_timestamp(self):
        lease = lease_fixture()
        lease["issued_at"] = "2026-11-07T12:00:00"
        with self.assertRaisesRegex(ContractError, "LEASE_TIMESTAMP_INVALID"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_non_increasing_window(self):
        issued = self.now
        lease = lease_fixture(issued=issued, expires=issued)
        with self.assertRaisesRegex(ContractError, "LEASE_WINDOW_INVALID"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_lease_longer_than_fifteen_minutes(self):
        issued = self.now
        lease = lease_fixture(
            issued=issued,
            expires=issued + timedelta(seconds=MAX_LEASE_SECONDS + 1),
        )
        with self.assertRaisesRegex(ContractError, "LEASE_DURATION_EXCEEDED"):
            validate_lease(self.task, lease, self.now)

    def test_rejects_oversized_lease(self):
        lease = lease_fixture(owner="A" * 2000)
        with self.assertRaisesRegex(ContractError, "LEASE_TOO_LARGE"):
            validate_lease(self.task, lease, self.now)

    def test_requires_timezone_aware_now(self):
        with self.assertRaisesRegex(ContractError, "LEASE_NOW_INVALID"):
            validate_lease(self.task, lease_fixture(), datetime(2026, 11, 7, 12, 5))

    def test_expired_lease_can_only_be_marked_retry_eligible(self):
        lease = lease_fixture(expires=self.now - timedelta(seconds=1))
        result = lease_recovery_decision(self.task, lease, self.now, False)
        self.assertEqual(result["recovery_decision"], "RETRY_ELIGIBLE")
        self.assertTrue(result["human_approval_required"])
        self.assertFalse(result["automatic_retry"])
        self.assertFalse(result["execution_authorized"])

    def test_active_lease_has_no_recovery_action(self):
        result = lease_recovery_decision(self.task, lease_fixture(), self.now, False)
        self.assertEqual(result["recovery_decision"], "NO_ACTION")

    def test_side_effects_require_human_review(self):
        lease = lease_fixture(expires=self.now - timedelta(seconds=1))
        result = lease_recovery_decision(self.task, lease, self.now, True)
        self.assertEqual(result["recovery_decision"], "HUMAN_REVIEW_REQUIRED")

    def test_attempt_limit_requires_human_review(self):
        lease = lease_fixture(attempt=2, expires=self.now - timedelta(seconds=1))
        result = lease_recovery_decision(self.task, lease, self.now, False)
        self.assertEqual(result["recovery_decision"], "HUMAN_REVIEW_REQUIRED")

    def test_valid_successor_requires_expiry_and_next_attempt(self):
        old_expiry = self.now - timedelta(seconds=1)
        previous = lease_fixture(
            lease_id="HQL-LEASE-01",
            attempt=1,
            issued=self.now - timedelta(minutes=11),
            expires=old_expiry,
        )
        successor = lease_fixture(
            lease_id="HQL-LEASE-02",
            attempt=2,
            issued=old_expiry,
            expires=old_expiry + timedelta(minutes=10),
        )
        result = validate_recovery_successor(self.task, previous, successor, self.now, False)
        self.assertEqual(result["transition_status"], "RECOVERY_PROPOSAL_VALIDATION_ONLY")
        self.assertTrue(result["human_approval_required"])
        self.assertFalse(result["automatic_retry"])
        self.assertFalse(result["execution_authorized"])

    def test_successor_cannot_overlap_prior_lease(self):
        previous = lease_fixture(
            attempt=1,
            issued=self.now - timedelta(minutes=11),
            expires=self.now - timedelta(seconds=1),
        )
        successor = lease_fixture(
            lease_id="HQL-LEASE-02",
            attempt=2,
            issued=self.now - timedelta(seconds=2),
            expires=self.now + timedelta(minutes=5),
        )
        with self.assertRaisesRegex(ContractError, "SUCCESSOR_LEASE_OVERLAPS_PRIOR"):
            validate_recovery_successor(self.task, previous, successor, self.now, False)

    def test_successor_requires_prior_lease_to_be_expired(self):
        previous = lease_fixture()
        successor = lease_fixture(lease_id="HQL-LEASE-02", attempt=2)
        with self.assertRaisesRegex(ContractError, "PRIOR_LEASE_NOT_EXPIRED"):
            validate_recovery_successor(self.task, previous, successor, self.now, False)

    def test_successor_is_blocked_if_side_effects_started(self):
        previous = lease_fixture(
            attempt=1,
            issued=self.now - timedelta(minutes=11),
            expires=self.now - timedelta(seconds=1),
        )
        successor = lease_fixture(
            lease_id="HQL-LEASE-02",
            attempt=2,
            issued=self.now,
            expires=self.now + timedelta(minutes=5),
        )
        with self.assertRaisesRegex(ContractError, "RECOVERY_SIDE_EFFECTS_REQUIRE_HUMAN"):
            validate_recovery_successor(self.task, previous, successor, self.now, True)

    def test_successor_is_blocked_when_attempts_exhausted(self):
        previous = lease_fixture(
            attempt=2,
            issued=self.now - timedelta(minutes=11),
            expires=self.now - timedelta(seconds=1),
        )
        successor = lease_fixture(
            lease_id="HQL-LEASE-02",
            attempt=3,
            issued=self.now,
            expires=self.now + timedelta(minutes=5),
        )
        with self.assertRaisesRegex(ContractError, "RECOVERY_ATTEMPTS_EXHAUSTED"):
            validate_recovery_successor(self.task, previous, successor, self.now, False)

    def test_task_still_must_satisfy_parent_company_scope(self):
        invalid = dict(self.task, external_effects=True)
        with self.assertRaisesRegex(ContractError, "EXTERNAL_EFFECTS_FORBIDDEN"):
            validate_lease(invalid, lease_fixture(), self.now)


if __name__ == "__main__":
    unittest.main()
