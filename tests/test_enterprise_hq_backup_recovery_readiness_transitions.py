from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta, timezone

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)
from scripts.enterprise_hq_backup_recovery_readiness_transitions import (
    BackupRecoveryReadinessTransitionError,
    verify_backup_recovery_readiness_transitions,
)


def ready_report():
    return {
        "status": "BACKUP_RECOVERY_READINESS_REPORTED",
        "metadata_readiness": "READY",
        "readiness_scope": "METADATA_ONLY",
        "blocker_codes": [],
        "inventory_record_count": 1,
        "observer_backup_count": 1,
        "binding_receipt_count": 1,
        "availability_observation_count": 1,
        "predecessor_link_count": 0,
        "predecessor_available_count": 0,
        "association_coverage": "COMPLETE",
        "availability_reconciliation_status": "RECONCILED",
        "predecessor_availability_status": "NOT_APPLICABLE",
        "recovery_chain_status": "COMPLETE",
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def not_ready_report(blockers=None):
    value = ready_report()
    value.update({
        "metadata_readiness": "NOT_READY",
        "blocker_codes": list(blockers or [
            "AVAILABILITY_RECONCILIATION_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ]),
        "availability_observation_count": 0,
        "availability_reconciliation_status": "INCOMPLETE",
        "recovery_chain_status": "INCOMPLETE",
    })
    return value


class BackupRecoveryReadinessTransitionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc)

    def snapshot(self, *reports):
        ledger = BackupRecoveryReadinessLedger(":memory:")
        try:
            for offset, report in enumerate(reports):
                ledger.record_readiness_report(
                    report, now=self.now + timedelta(minutes=offset)
                )
            return ledger.export_verification_snapshot()
        finally:
            ledger.close()

    def reject(self, snapshot):
        with self.assertRaises(BackupRecoveryReadinessTransitionError):
            verify_backup_recovery_readiness_transitions(snapshot)

    def test_accepts_empty_history(self):
        result = verify_backup_recovery_readiness_transitions(self.snapshot())
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["transition_count"], 0)
        self.assertEqual(result["latest_readiness"], "NONE")

    def test_accepts_single_ready_evaluation(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report())
        )
        self.assertEqual(result["latest_readiness"], "READY")
        self.assertEqual(result["latest_blocker_count"], 0)

    def test_accepts_single_not_ready_evaluation(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(not_ready_report())
        )
        self.assertEqual(result["latest_readiness"], "NOT_READY")
        self.assertEqual(result["latest_blocker_count"], 2)

    def test_counts_ready_to_ready_transition(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), ready_report())
        )
        self.assertEqual(result["ready_to_ready_count"], 1)
        self.assertEqual(result["readiness_change_count"], 0)

    def test_counts_ready_to_not_ready_transition(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report())
        )
        self.assertEqual(result["ready_to_not_ready_count"], 1)
        self.assertEqual(result["blocker_addition_events"], 2)

    def test_counts_not_ready_to_ready_transition(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(not_ready_report(), ready_report())
        )
        self.assertEqual(result["not_ready_to_ready_count"], 1)
        self.assertEqual(result["blocker_resolution_events"], 2)

    def test_counts_not_ready_to_not_ready_transition(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(not_ready_report(), not_ready_report())
        )
        self.assertEqual(result["not_ready_to_not_ready_count"], 1)
        self.assertEqual(result["readiness_change_count"], 0)

    def test_counts_all_transition_classes(self):
        changed_not_ready = not_ready_report([
            "AVAILABILITY_EVIDENCE_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ])
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(
                ready_report(), not_ready_report(), changed_not_ready, ready_report()
            )
        )
        self.assertEqual(result["transition_count"], 3)
        self.assertEqual(result["ready_to_not_ready_count"], 1)
        self.assertEqual(result["not_ready_to_not_ready_count"], 1)
        self.assertEqual(result["not_ready_to_ready_count"], 1)
        self.assertEqual(result["readiness_change_count"], 2)

    def test_counts_blocker_addition_events(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report())
        )
        self.assertEqual(result["blocker_addition_events"], 2)
        self.assertEqual(result["blocker_resolution_events"], 0)

    def test_counts_blocker_resolution_events(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(not_ready_report(), ready_report())
        )
        self.assertEqual(result["blocker_addition_events"], 0)
        self.assertEqual(result["blocker_resolution_events"], 2)

    def test_counts_replaced_blockers_as_addition_and_resolution(self):
        first = not_ready_report()
        second = not_ready_report([
            "AVAILABILITY_EVIDENCE_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ])
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(first, second)
        )
        self.assertEqual(result["blocker_addition_events"], 1)
        self.assertEqual(result["blocker_resolution_events"], 1)

    def test_counts_blocker_events_across_multiple_transitions(self):
        changed = not_ready_report([
            "AVAILABILITY_EVIDENCE_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ])
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report(), changed, ready_report())
        )
        self.assertEqual(result["blocker_addition_events"], 3)
        self.assertEqual(result["blocker_resolution_events"], 3)

    def test_reports_latest_classification_and_blocker_count(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report())
        )
        self.assertEqual(result["latest_readiness"], "NOT_READY")
        self.assertEqual(result["latest_blocker_count"], 2)

    def test_reports_history_and_transition_counts(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report(), ready_report())
        )
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["transition_count"], 2)
        self.assertEqual(result["history_status"], "VALID")

    def test_returns_aggregate_fields_only(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report(), not_ready_report())
        )
        rendered = str(result)
        self.assertNotIn("evaluation_id", rendered)
        self.assertNotIn("report_digest", rendered)
        self.assertNotIn("blocker_codes", rendered)
        self.assertNotIn("records", result)
        self.assertNotIn("report", result)

    def test_preserves_non_authorization_flags(self):
        result = verify_backup_recovery_readiness_transitions(
            self.snapshot(ready_report())
        )
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_rejects_missing_snapshot(self):
        self.reject(None)

    def test_rejects_wrong_snapshot_schema(self):
        self.reject({"schema_version": "1.0.0", "records": []})

    def test_rejects_record_count_mismatch(self):
        snapshot = self.snapshot(ready_report())
        snapshot["record_count"] = 0
        self.reject(snapshot)

    def test_rejects_report_digest_tampering(self):
        snapshot = self.snapshot(ready_report())
        snapshot["records"][0]["report_digest"] = "0" * 64
        self.reject(snapshot)

    def test_rejects_record_hash_tampering(self):
        snapshot = self.snapshot(ready_report())
        snapshot["records"][0]["record_hash"] = "0" * 64
        self.reject(snapshot)

    def test_rejects_raw_identifier_field(self):
        snapshot = self.snapshot(ready_report())
        snapshot["records"][0]["source_backup_id"] = "raw-id"
        self.reject(snapshot)

    def test_rejects_raw_report_field(self):
        snapshot = self.snapshot(ready_report())
        snapshot["records"][0]["report"]["filesystem_path"] = "/private/path"
        self.reject(snapshot)

    def test_rejects_authorization_escalation(self):
        snapshot = self.snapshot(ready_report())
        snapshot["execution_authorized"] = True
        self.reject(snapshot)

    def test_rejects_artifact_byte_escalation(self):
        snapshot = self.snapshot(ready_report())
        snapshot["artifact_bytes_verified"] = True
        self.reject(snapshot)

    def test_rejects_timestamp_regression(self):
        snapshot = self.snapshot(ready_report(), not_ready_report())
        snapshot["records"][1]["evaluated_at"] = snapshot["records"][0]["evaluated_at"]
        self.reject(snapshot)

    def test_rejects_ready_report_with_blockers(self):
        report = ready_report()
        report["blocker_codes"] = ["RECOVERY_CHAIN_INCOMPLETE"]
        self.reject(self.snapshot(report))

    def test_rejects_not_ready_report_without_blockers(self):
        report = not_ready_report()
        report["blocker_codes"] = []
        self.reject(self.snapshot(report))


if __name__ == "__main__":
    unittest.main()
