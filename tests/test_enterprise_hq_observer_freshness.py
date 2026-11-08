from __future__ import annotations

import unittest

from scripts.enterprise_hq_observer_freshness import (
    ObserverFreshnessError,
    evaluate_observer_freshness,
    verify_observer_freshness_receipt,
)


class ObserverFreshnessTests(unittest.TestCase):
    def evaluate(self, age, interval=1800, grace=900):
        from datetime import datetime, timedelta, timezone
        now = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
        last = None if age is None else (
            now - timedelta(seconds=age)
        ).isoformat().replace("+00:00", "Z")
        return evaluate_observer_freshness(
            last, "2026-11-08T12:00:00Z", interval, grace
        )

    def test_never_observed_is_explicit_and_non_authorizing(self):
        result = self.evaluate(None)
        self.assertEqual(result["status"], "NEVER_OBSERVED")
        self.assertIsNone(result["age_seconds"])
        self.assertFalse(result["execution_authorized"])

    def test_fresh_at_zero_age(self):
        self.assertEqual(self.evaluate(0)["status"], "FRESH")

    def test_fresh_at_interval_boundary(self):
        self.assertEqual(self.evaluate(1800)["status"], "FRESH")

    def test_grace_period_after_interval(self):
        self.assertEqual(self.evaluate(1801)["status"], "GRACE_PERIOD")

    def test_grace_period_at_upper_boundary(self):
        self.assertEqual(self.evaluate(2700)["status"], "GRACE_PERIOD")

    def test_missed_after_grace_boundary(self):
        self.assertEqual(self.evaluate(2701)["status"], "MISSED")

    def test_zero_grace_has_no_grace_state(self):
        self.assertEqual(self.evaluate(1801, grace=0)["status"], "MISSED")

    def test_custom_interval_is_applied(self):
        self.assertEqual(self.evaluate(600, interval=600)["status"], "FRESH")

    def test_timezone_offset_is_normalized(self):
        result = evaluate_observer_freshness(
            "2026-11-08T16:00:00+05:30", "2026-11-08T10:30:00Z"
        )
        self.assertEqual(result["status"], "FRESH")

    def test_small_future_clock_skew_is_clamped_to_fresh(self):
        result = evaluate_observer_freshness(
            "2026-11-08T12:00:30Z", "2026-11-08T12:00:00Z"
        )
        self.assertEqual(result["status"], "FRESH")
        self.assertEqual(result["age_seconds"], 0)

    def test_large_future_clock_skew_is_reported(self):
        result = evaluate_observer_freshness(
            "2026-11-08T12:01:01Z", "2026-11-08T12:00:00Z"
        )
        self.assertEqual(result["status"], "CLOCK_SKEW")
        self.assertIsNone(result["age_seconds"])

    def test_missing_observation_timestamp_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "")

    def test_naive_observation_timestamp_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "2026-11-08T12:00:00")

    def test_naive_last_success_timestamp_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(
                "2026-11-08T11:30:00", "2026-11-08T12:00:00Z"
            )

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "yesterday")

    def test_oversized_timestamp_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "2" * 65)

    def test_boolean_interval_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "2026-11-08T12:00:00Z", True)

    def test_interval_out_of_range_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "2026-11-08T12:00:00Z", 86401)

    def test_negative_grace_rejected(self):
        with self.assertRaises(ObserverFreshnessError):
            evaluate_observer_freshness(None, "2026-11-08T12:00:00Z", 1800, -1)

    def test_valid_receipt_verifies(self):
        result = self.evaluate(2000)
        verified = verify_observer_freshness_receipt(result)
        self.assertEqual(verified["status"], "OBSERVER_FRESHNESS_RECEIPT_VALID")
        self.assertFalse(verified["automatic_dispatch"])

    def test_receipt_rejects_extra_fields(self):
        result = self.evaluate(0)
        result["workflow_name"] = "must-not-be-emitted"
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_rejects_digest_tampering(self):
        result = self.evaluate(0)
        result["age_seconds"] = 1
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_rejects_authority_escalation(self):
        result = self.evaluate(0)
        result["execution_authorized"] = True
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_rejects_inconsistent_status(self):
        from scripts.enterprise_hq_observer_freshness import _canonical_digest
        result = self.evaluate(0)
        result["status"] = "MISSED"
        payload = {key: value for key, value in result.items() if key != "decision_digest"}
        result["decision_digest"] = _canonical_digest(payload)
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_rejects_boolean_age(self):
        from scripts.enterprise_hq_observer_freshness import _canonical_digest
        result = self.evaluate(0)
        result["age_seconds"] = True
        payload = {key: value for key, value in result.items() if key != "decision_digest"}
        result["decision_digest"] = _canonical_digest(payload)
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_rejects_non_string_status(self):
        from scripts.enterprise_hq_observer_freshness import _canonical_digest
        result = self.evaluate(0)
        result["status"] = []
        payload = {key: value for key, value in result.items() if key != "decision_digest"}
        result["decision_digest"] = _canonical_digest(payload)
        with self.assertRaises(ObserverFreshnessError):
            verify_observer_freshness_receipt(result)

    def test_receipt_does_not_echo_timestamps(self):
        result = self.evaluate(0)
        self.assertNotIn("last_success_at", result)
        self.assertNotIn("observed_at", result)

    def test_equivalent_timezone_instants_produce_same_decision(self):
        first = evaluate_observer_freshness(
            "2026-11-08T11:30:00Z", "2026-11-08T12:00:00Z"
        )
        second = evaluate_observer_freshness(
            "2026-11-08T17:00:00+05:30", "2026-11-08T17:30:00+05:30"
        )
        self.assertEqual(first["decision_digest"], second["decision_digest"])

    def test_module_has_no_network_or_process_execution_imports(self):
        import ast
        from pathlib import Path
        source = Path(__file__).resolve().parents[1] / "scripts" / "enterprise_hq_observer_freshness.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        imported = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
        self.assertFalse(any(
            name.startswith(("urllib", "http", "socket", "subprocess"))
            for name in imported
        ))


if __name__ == "__main__":
    unittest.main()
