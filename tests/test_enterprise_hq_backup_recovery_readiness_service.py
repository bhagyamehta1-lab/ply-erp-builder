from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)
from scripts.enterprise_hq_backup_recovery_readiness_service import (
    BackupRecoveryReadinessServiceError,
    evaluate_and_record_backup_recovery_readiness,
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


def not_ready_report():
    value = ready_report()
    value.update({
        "metadata_readiness": "NOT_READY",
        "blocker_codes": [
            "AVAILABILITY_RECONCILIATION_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ],
        "availability_observation_count": 0,
        "availability_reconciliation_status": "INCOMPLETE",
        "recovery_chain_status": "INCOMPLETE",
    })
    return value


class BackupRecoveryReadinessServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.now = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)
        self.sources = (object(), object(), object(), object())
        self.history = BackupRecoveryReadinessLedger(self.database)

    def tearDown(self):
        try:
            self.history.close()
        except Exception:
            pass
        self.temp.cleanup()

    def run_service(self, report=None, *, now=None):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "reconcile_backup_recovery_readiness",
            return_value=ready_report() if report is None else report,
        ) as reconcile:
            result = evaluate_and_record_backup_recovery_readiness(
                *self.sources, self.history, now=self.now if now is None else now
            )
        return result, reconcile

    def test_records_ready_report_and_independently_reads_it_back(self):
        result, _ = self.run_service()
        self.assertEqual(result["metadata_readiness"], "READY")
        self.assertTrue(result["independent_history_verification"])
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["evaluation_count"], 1)

    def test_records_not_ready_report_without_promoting_it(self):
        result, _ = self.run_service(not_ready_report())
        self.assertEqual(result["metadata_readiness"], "NOT_READY")
        self.assertEqual(result["blocker_count"], 2)
        self.assertEqual(result["blocker_codes"], [
            "AVAILABILITY_RECONCILIATION_INCOMPLETE",
            "RECOVERY_CHAIN_INCOMPLETE",
        ])

    def test_exact_replay_is_idempotent(self):
        first, _ = self.run_service()
        second, _ = self.run_service()
        self.assertEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertEqual(self.history.verify()["record_count"], 1)

    def test_later_evaluation_advances_history(self):
        self.run_service()
        result, _ = self.run_service(now=self.now + timedelta(minutes=1))
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(result["evaluation_count"], 2)

    def test_requires_all_four_source_ledgers(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "reconcile_backup_recovery_readiness"
        ) as reconcile:
            with self.assertRaisesRegex(
                BackupRecoveryReadinessServiceError,
                "BACKUP_RECOVERY_READINESS_SERVICE_FOUR_SOURCE_LEDGERS_REQUIRED",
            ):
                evaluate_and_record_backup_recovery_readiness(
                    self.sources[0], self.sources[1], self.sources[2], None,
                    self.history, now=self.now,
                )
        reconcile.assert_not_called()

    def test_requires_history_ledger(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessServiceError,
            "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_LEDGER_REQUIRED",
        ):
            evaluate_and_record_backup_recovery_readiness(
                *self.sources, None, now=self.now
            )

    def test_rejects_incomplete_history_interface(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessServiceError,
            "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_LEDGER_REQUIRED",
        ):
            evaluate_and_record_backup_recovery_readiness(
                *self.sources, object(), now=self.now
            )

    def test_source_reconciliation_failure_does_not_write_history(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "reconcile_backup_recovery_readiness",
            side_effect=RuntimeError("synthetic source failure"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessServiceError,
                "BACKUP_RECOVERY_READINESS_SERVICE_SOURCE_RECONCILIATION_FAILED",
            ):
                evaluate_and_record_backup_recovery_readiness(
                    *self.sources, self.history, now=self.now
                )
        self.assertEqual(self.history.verify()["record_count"], 0)

    def test_history_record_failure_fails_closed(self):
        with patch.object(
            self.history, "record_readiness_report",
            side_effect=RuntimeError("synthetic write failure"),
        ):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_RECORD_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_snapshot_export_failure_is_reported_after_record(self):
        original = self.history.export_verification_snapshot
        calls = {"count": 0}

        def fail_after_record():
            calls["count"] += 1
            if calls["count"] >= 3:
                raise RuntimeError("synthetic export failure")
            return original()

        with patch.object(
            self.history, "export_verification_snapshot",
            side_effect=fail_after_record,
        ):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_EXPORT_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )
        self.assertEqual(self.history.verify()["record_count"], 1)

    def test_independent_snapshot_verifier_failure_is_reported(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "verify_backup_recovery_readiness_snapshot",
            side_effect=ValueError("synthetic verifier failure"),
        ):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_INDEPENDENT_VERIFICATION_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_tampered_snapshot_identifier(self):
        original = self.history.export_verification_snapshot

        def altered():
            snapshot = copy.deepcopy(original())
            snapshot["records"][-1]["evaluation_id"] = "hqrr_" + "0" * 24
            return snapshot

        with patch.object(self.history, "export_verification_snapshot", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_INDEPENDENT_VERIFICATION_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_tampered_snapshot_digest(self):
        original = self.history.export_verification_snapshot

        def altered():
            snapshot = copy.deepcopy(original())
            snapshot["records"][-1]["report_digest"] = "0" * 64
            return snapshot

        with patch.object(self.history, "export_verification_snapshot", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_INDEPENDENT_VERIFICATION_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_tampered_snapshot_report(self):
        original = self.history.export_verification_snapshot

        def altered():
            snapshot = copy.deepcopy(original())
            snapshot["records"][-1]["report"]["metadata_readiness"] = "NOT_READY"
            return snapshot

        with patch.object(self.history, "export_verification_snapshot", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_INDEPENDENT_VERIFICATION_FAILED",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_evaluation_id_disagreement(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["evaluation_id"] = "hqrr_" + "0" * 24
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_READBACK_MISMATCH",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_digest_disagreement(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["evaluation_digest"] = "0" * 64
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_READBACK_MISMATCH",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_sequence_disagreement(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["sequence"] = 2
            result["evaluation_count"] = 2
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_READBACK_MISMATCH",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_classification_disagreement(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["metadata_readiness"] = "NOT_READY"
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_READBACK_MISMATCH",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_extra_field(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["private_payload"] = "forbidden"
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_RECORD_RESULT_SCHEMA_INVALID",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_record_result_authorization(self):
        original = self.history.record_readiness_report

        def altered(report, *, now=None):
            result = original(report, now=now)
            result["execution_authorized"] = True
            return result

        with patch.object(self.history, "record_readiness_report", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_AUTHORIZATION_INVALID",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_independent_verification_summary_disagreement(self):
        from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
            verify_backup_recovery_readiness_snapshot as verify,
        )

        def altered(snapshot):
            result = verify(snapshot)
            result["record_count"] += 1
            return result

        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "verify_backup_recovery_readiness_snapshot",
            side_effect=altered,
        ):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_VERIFICATION_DISAGREEMENT",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_rejects_ledger_and_independent_verifier_disagreement(self):
        original = self.history.verify
        calls = {"count": 0}

        def altered():
            calls["count"] += 1
            result = original()
            if calls["count"] >= 3:
                result = dict(result)
                result["chain_head_hash"] = "0" * 64
            return result

        with patch.object(self.history, "verify", side_effect=altered):
            with patch(
                "scripts.enterprise_hq_backup_recovery_readiness_service."
                "reconcile_backup_recovery_readiness",
                return_value=ready_report(),
            ):
                with self.assertRaisesRegex(
                    BackupRecoveryReadinessServiceError,
                    "BACKUP_RECOVERY_READINESS_SERVICE_HISTORY_VERIFICATION_DISAGREEMENT",
                ):
                    evaluate_and_record_backup_recovery_readiness(
                        *self.sources, self.history, now=self.now
                    )

    def test_passes_exact_four_sources_to_reconciler(self):
        result, reconcile = self.run_service()
        reconcile.assert_called_once_with(*self.sources)
        self.assertTrue(result["source_snapshot_stable"])
        self.assertEqual(result["source_ledger_verification_count"], 4)

    def test_passes_evaluation_time_to_history_ledger(self):
        with patch.object(
            self.history, "record_readiness_report",
            wraps=self.history.record_readiness_report,
        ) as record:
            self.run_service()
        record.assert_called_once()
        self.assertEqual(record.call_args.kwargs["now"], self.now)

    def test_result_is_aggregate_only(self):
        result, _ = self.run_service()
        self.assertNotIn("report", result)
        self.assertNotIn("records", result)
        self.assertNotIn("backup_id", str(result))
        self.assertNotIn("filesystem_path", str(result))
        self.assertNotIn("private_payload", str(result))

    def test_result_preserves_chain_head(self):
        result, _ = self.run_service()
        self.assertEqual(len(result["chain_head_hash"]), 64)
        self.assertEqual(result["history_status"], "VALID")

    def test_all_authorization_flags_remain_false(self):
        result, _ = self.run_service()
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_not_ready_report_is_never_promoted(self):
        result, _ = self.run_service(not_ready_report())
        self.assertEqual(result["metadata_readiness"], "NOT_READY")
        self.assertNotEqual(result["metadata_readiness"], "READY")

    def test_history_verification_is_independent_and_explicit(self):
        result, _ = self.run_service()
        self.assertEqual(
            result["status"],
            "BACKUP_RECOVERY_READINESS_EVALUATION_RECORDED_AND_VERIFIED",
        )
        self.assertTrue(result["independent_history_verification"])


if __name__ == "__main__":
    unittest.main()
