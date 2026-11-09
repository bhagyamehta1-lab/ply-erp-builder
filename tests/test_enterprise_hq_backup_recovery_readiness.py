"""Regression tests for aggregate-only four-ledger backup recovery readiness."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts.enterprise_hq_backup_recovery_readiness import (
    BackupRecoveryReadinessError,
    reconcile_backup_recovery_readiness,
    summarize_backup_recovery_readiness,
)

STATES = ("AVAILABLE", "MISSING", "UNAVAILABLE", "INVALID", "MISMATCH", "UNKNOWN")


def make_ready_summary():
    return {
        "status": "BACKUP_GENERATION_CONTINUITY_VERIFIED",
        "inventory_record_count": 2,
        "inventory_ledger_type_count": 1,
        "inventory_predecessor_link_count": 1,
        "observer_backup_count": 2,
        "observer_predecessor_link_count": 1,
        "binding_receipt_count": 2,
        "binding_association_pair_count": 2,
        "bound_inventory_count": 2,
        "bound_observer_backup_count": 2,
        "unbound_inventory_count": 0,
        "unbound_observer_backup_count": 0,
        "association_coverage": "COMPLETE",
        "inventory_entry_digest_verification": True,
        "binding_receipt_hash_verification": True,
        "lineage_verification": True,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
        "availability_reconciliation_status": "RECONCILED",
        "availability_observation_count": 2,
        "availability_counts": {"AVAILABLE": 2, "MISSING": 0, "UNAVAILABLE": 0,
                                "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
        "matched_available_backup_count": 2,
        "matched_nonavailable_backup_count": 0,
        "missing_availability_observation_count": 0,
        "unknown_availability_observation_count": 0,
        "orphan_availability_observation_count": 0,
        "availability_lineage_mismatch_count": 0,
        "availability_evidence_mismatch_count": 0,
        "predecessor_link_count": 1,
        "predecessor_available_count": 1,
        "predecessor_missing_observation_count": 0,
        "predecessor_unknown_observation_count": 0,
        "predecessor_nonavailable_count": 0,
        "predecessor_lineage_mismatch_count": 0,
        "predecessor_evidence_mismatch_count": 0,
        "predecessor_availability_status": "VERIFIED",
        "recovery_chain_status": "COMPLETE",
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
    }


def report(summary=None):
    return summarize_backup_recovery_readiness(make_ready_summary() if summary is None else summary)


class BackupRecoveryReadinessTests(unittest.TestCase):
    def test_complete_two_backup_chain_is_metadata_ready(self):
        result = report()
        self.assertEqual(result["metadata_readiness"], "READY")
        self.assertEqual(result["readiness_scope"], "METADATA_ONLY")
        self.assertEqual(result["blocker_codes"], [])

    def test_single_genesis_backup_needs_no_predecessor(self):
        summary = make_ready_summary()
        summary.update({
            "inventory_record_count": 1,
            "inventory_predecessor_link_count": 0,
            "observer_backup_count": 1,
            "observer_predecessor_link_count": 0,
            "binding_receipt_count": 1,
            "binding_association_pair_count": 1,
            "bound_inventory_count": 1,
            "bound_observer_backup_count": 1,
            "availability_observation_count": 1,
            "availability_counts": {"AVAILABLE": 1, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "matched_available_backup_count": 1,
            "predecessor_link_count": 0,
            "predecessor_available_count": 0,
            "predecessor_availability_status": "NOT_APPLICABLE",
        })
        self.assertEqual(report(summary)["metadata_readiness"], "READY")

    def test_empty_history_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "inventory_record_count": 0, "inventory_ledger_type_count": 0,
            "inventory_predecessor_link_count": 0, "observer_backup_count": 0,
            "observer_predecessor_link_count": 0, "binding_receipt_count": 0,
            "binding_association_pair_count": 0, "bound_inventory_count": 0,
            "bound_observer_backup_count": 0, "unbound_inventory_count": 0,
            "unbound_observer_backup_count": 0, "association_coverage": "NONE",
            "availability_reconciliation_status": "RECONCILED_EMPTY",
            "availability_observation_count": 0,
            "availability_counts": {state: 0 for state in STATES},
            "matched_available_backup_count": 0,
            "predecessor_link_count": 0, "predecessor_available_count": 0,
            "predecessor_availability_status": "NOT_APPLICABLE",
            "recovery_chain_status": "NO_BACKUPS",
        })
        result = report(summary)
        self.assertEqual(result["metadata_readiness"], "NOT_READY")
        self.assertIn("NO_BACKUP_EVIDENCE", result["blocker_codes"])

    def test_partial_association_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "binding_receipt_count": 1, "binding_association_pair_count": 1,
            "bound_inventory_count": 1, "bound_observer_backup_count": 1,
            "unbound_inventory_count": 1, "unbound_observer_backup_count": 1,
            "association_coverage": "PARTIAL",
        })
        self.assertIn("ASSOCIATION_COVERAGE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_missing_binding_receipts_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "binding_receipt_count": 0, "binding_association_pair_count": 0,
            "bound_inventory_count": 0, "bound_observer_backup_count": 0,
            "unbound_inventory_count": 2, "unbound_observer_backup_count": 2,
            "association_coverage": "NONE",
        })
        result = report(summary)
        self.assertIn("NO_BINDING_RECEIPTS", result["blocker_codes"])
        self.assertEqual(result["metadata_readiness"], "NOT_READY")

    def test_missing_availability_observation_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "availability_observation_count": 1,
            "availability_counts": {"AVAILABLE": 1, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "matched_available_backup_count": 1,
            "missing_availability_observation_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        self.assertIn("AVAILABILITY_RECONCILIATION_INCOMPLETE", report(summary)["blocker_codes"])

    def test_unknown_observation_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "availability_counts": {"AVAILABLE": 1, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 1},
            "matched_available_backup_count": 1,
            "unknown_availability_observation_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        self.assertIn("AVAILABILITY_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_orphan_observation_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "availability_observation_count": 3,
            "availability_counts": {"AVAILABLE": 3, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "orphan_availability_observation_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        self.assertIn("AVAILABILITY_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_lineage_mismatch_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "matched_available_backup_count": 1,
            "availability_lineage_mismatch_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        self.assertIn("AVAILABILITY_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_evidence_mismatch_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "matched_available_backup_count": 1,
            "availability_evidence_mismatch_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        self.assertIn("AVAILABILITY_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_current_backup_unavailable_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_counts": {"AVAILABLE": 1, "MISSING": 1, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "matched_available_backup_count": 1,
            "matched_nonavailable_backup_count": 1,
            "recovery_chain_status": "INCOMPLETE",
        })
        result = report(summary)
        self.assertIn("CURRENT_BACKUP_AVAILABILITY_INCOMPLETE", result["blocker_codes"])

    def test_missing_predecessor_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "availability_observation_count": 1,
            "availability_counts": {"AVAILABLE": 1, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "matched_available_backup_count": 1,
            "missing_availability_observation_count": 1,
            "predecessor_available_count": 0,
            "predecessor_missing_observation_count": 1,
            "predecessor_availability_status": "BLOCKED",
            "recovery_chain_status": "BLOCKED_PREDECESSOR_UNAVAILABLE",
        })
        self.assertIn("PREDECESSOR_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_unknown_predecessor_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_counts": {"AVAILABLE": 1, "MISSING": 0, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 1},
            "matched_available_backup_count": 1,
            "unknown_availability_observation_count": 1,
            "predecessor_available_count": 0,
            "predecessor_unknown_observation_count": 1,
            "predecessor_availability_status": "BLOCKED",
            "availability_reconciliation_status": "INCOMPLETE",
            "recovery_chain_status": "BLOCKED_PREDECESSOR_UNAVAILABLE",
        })
        self.assertIn("PREDECESSOR_AVAILABILITY_UNVERIFIED", report(summary)["blocker_codes"])

    def test_unavailable_predecessor_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_counts": {"AVAILABLE": 1, "MISSING": 1, "UNAVAILABLE": 0,
                                    "INVALID": 0, "MISMATCH": 0, "UNKNOWN": 0},
            "matched_available_backup_count": 1,
            "matched_nonavailable_backup_count": 1,
            "predecessor_available_count": 0,
            "predecessor_nonavailable_count": 1,
            "predecessor_availability_status": "BLOCKED",
            "recovery_chain_status": "BLOCKED_PREDECESSOR_UNAVAILABLE",
        })
        self.assertIn("PREDECESSOR_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_predecessor_lineage_mismatch_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "matched_available_backup_count": 1,
            "availability_lineage_mismatch_count": 1,
            "predecessor_available_count": 0,
            "predecessor_lineage_mismatch_count": 1,
            "predecessor_availability_status": "BLOCKED",
            "recovery_chain_status": "BLOCKED_PREDECESSOR_UNAVAILABLE",
        })
        self.assertIn("PREDECESSOR_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_predecessor_evidence_mismatch_is_not_ready(self):
        summary = make_ready_summary()
        summary.update({
            "availability_reconciliation_status": "INCOMPLETE",
            "matched_available_backup_count": 1,
            "availability_evidence_mismatch_count": 1,
            "predecessor_available_count": 0,
            "predecessor_evidence_mismatch_count": 1,
            "predecessor_availability_status": "BLOCKED",
            "recovery_chain_status": "BLOCKED_PREDECESSOR_UNAVAILABLE",
        })
        self.assertIn("PREDECESSOR_EVIDENCE_INCOMPLETE", report(summary)["blocker_codes"])

    def test_rejects_availability_not_checked(self):
        summary = make_ready_summary()
        summary["availability_reconciliation_status"] = "NOT_CHECKED"
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_unstable_source_snapshot(self):
        summary = make_ready_summary()
        summary["source_snapshot_stable"] = False
        with self.assertRaisesRegex(BackupRecoveryReadinessError, "SOURCE_SNAPSHOT_UNSTABLE"):
            report(summary)

    def test_rejects_only_three_ledgers(self):
        summary = make_ready_summary()
        summary["source_ledger_verification_count"] = 3
        with self.assertRaisesRegex(BackupRecoveryReadinessError, "FOUR_LEDGER"):
            report(summary)

    def test_rejects_artifact_byte_verification_claim(self):
        summary = make_ready_summary()
        summary["artifact_bytes_verified"] = True
        with self.assertRaisesRegex(BackupRecoveryReadinessError, "AUTHORIZATION_INVALID"):
            report(summary)

    def test_rejects_execution_authorization(self):
        summary = make_ready_summary()
        summary["execution_authorized"] = True
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_dispatch_authorization(self):
        summary = make_ready_summary()
        summary["automatic_dispatch"] = True
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_automatic_retry_authorization(self):
        summary = make_ready_summary()
        summary["automatic_retry"] = True
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_boolean_as_integer_count(self):
        summary = make_ready_summary()
        summary["inventory_record_count"] = True
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_invalid_availability_status_keys(self):
        summary = make_ready_summary()
        summary["availability_counts"] = {"AVAILABLE": 2}
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_availability_count_sum_mismatch(self):
        summary = make_ready_summary()
        summary["availability_counts"]["AVAILABLE"] = 1
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_observation_category_sum_mismatch(self):
        summary = make_ready_summary()
        summary["orphan_availability_observation_count"] = 1
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_predecessor_category_sum_mismatch(self):
        summary = make_ready_summary()
        summary["predecessor_missing_observation_count"] = 1
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_inconsistent_association_counts(self):
        summary = make_ready_summary()
        summary["bound_inventory_count"] = 1
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_inconsistent_recovery_status(self):
        summary = make_ready_summary()
        summary["recovery_chain_status"] = "INCOMPLETE"
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_unexpected_summary_field(self):
        summary = make_ready_summary()
        summary["raw_backup_id"] = "must-not-be-present"
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_rejects_missing_summary_field(self):
        summary = make_ready_summary()
        summary.pop("binding_receipt_hash_verification")
        with self.assertRaises(BackupRecoveryReadinessError):
            report(summary)

    def test_wrapper_always_passes_four_ledgers(self):
        inventory, observer, binding, availability = object(), object(), object(), object()
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness.reconcile_backup_generation_continuity",
            return_value=make_ready_summary(),
        ) as reconcile:
            result = reconcile_backup_recovery_readiness(inventory, observer, binding, availability)
        reconcile.assert_called_once_with(inventory, observer, binding, availability)
        self.assertEqual(result["metadata_readiness"], "READY")

    def test_wrapper_rejects_missing_availability_ledger(self):
        with self.assertRaisesRegex(BackupRecoveryReadinessError, "SOURCE_LEDGERS_REQUIRED"):
            reconcile_backup_recovery_readiness(object(), object(), object(), None)

    def test_wrapper_fails_closed_on_source_error(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness.reconcile_backup_generation_continuity",
            side_effect=RuntimeError("private source detail must not escape"),
        ):
            with self.assertRaisesRegex(BackupRecoveryReadinessError, "SOURCE_RECONCILIATION_FAILED") as caught:
                reconcile_backup_recovery_readiness(object(), object(), object(), object())
        self.assertNotIn("private source detail", str(caught.exception))

    def test_report_is_aggregate_only_and_non_authorizing(self):
        result = report()
        self.assertEqual(result["source_ledger_verification_count"], 4)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])
        for forbidden in ("backup_id", "file_sha256", "path", "digest", "raw_backup_id"):
            self.assertNotIn(forbidden, result)


if __name__ == "__main__":
    unittest.main()
