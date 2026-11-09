from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_backup_recovery_readiness_restart as restart_module
from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)
from scripts.enterprise_hq_backup_recovery_readiness_restart import (
    BackupRecoveryReadinessRestartError,
    evaluate_record_and_verify_backup_recovery_readiness_restart,
)


_DEFAULT = object()


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


class BackupRecoveryReadinessRestartTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.now = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
        self.sources = (object(), object(), object(), object())

    def tearDown(self):
        self.temp.cleanup()

    def run_once(self, report=None, *, minute=0, database=_DEFAULT, sources=None):
        value = ready_report() if report is None else copy.deepcopy(report)
        target = self.database if database is _DEFAULT else database
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "reconcile_backup_recovery_readiness",
            return_value=value,
        ):
            return evaluate_record_and_verify_backup_recovery_readiness_restart(
                *(self.sources if sources is None else sources),
                target,
                now=self.now + timedelta(minutes=minute),
            )

    def test_ready_report_survives_real_close_and_reopen(self):
        result = self.run_once()
        self.assertEqual(result["status"], "BACKUP_RECOVERY_READINESS_RESTART_VERIFIED")
        self.assertEqual(result["metadata_readiness"], "READY")
        self.assertTrue(result["close_reopen_performed"])
        self.assertTrue(result["restart_recovery_verified"])
        self.assertEqual(result["evaluation_count"], 1)
        self.assertEqual(result["sequence"], 1)

    def test_not_ready_report_remains_not_ready_after_restart(self):
        result = self.run_once(not_ready_report())
        self.assertEqual(result["metadata_readiness"], "NOT_READY")
        self.assertEqual(result["blocker_count"], 2)
        self.assertEqual(result["latest_readiness"], "NOT_READY")
        self.assertEqual(result["latest_blocker_count"], 2)

    def test_exact_replay_is_idempotent_across_reopen(self):
        first = self.run_once()
        second = self.run_once()
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertEqual(second["evaluation_count"], 1)
        self.assertEqual(first["chain_head_hash"], second["chain_head_hash"])

    def test_later_evaluation_advances_persisted_sequence(self):
        self.run_once()
        result = self.run_once(minute=1)
        self.assertEqual(result["evaluation_count"], 2)
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(result["transition_count"], 1)

    def test_ready_to_not_ready_transition_survives_restart(self):
        self.run_once()
        result = self.run_once(not_ready_report(), minute=1)
        self.assertEqual(result["transition_count"], 1)
        self.assertEqual(result["readiness_change_count"], 1)
        self.assertEqual(result["blocker_addition_events"], 2)
        self.assertEqual(result["blocker_resolution_events"], 0)

    def test_not_ready_to_ready_transition_survives_restart(self):
        self.run_once(not_ready_report())
        result = self.run_once(ready_report(), minute=1)
        self.assertEqual(result["readiness_change_count"], 1)
        self.assertEqual(result["blocker_resolution_events"], 2)
        self.assertEqual(result["latest_readiness"], "READY")

    def test_multiple_transition_classes_reconcile(self):
        self.run_once(ready_report())
        self.run_once(ready_report(), minute=1)
        self.run_once(not_ready_report(), minute=2)
        result = self.run_once(ready_report(), minute=3)
        self.assertEqual(result["transition_count"], 3)
        self.assertEqual(result["readiness_change_count"], 2)
        self.assertEqual(result["blocker_addition_events"], 2)
        self.assertEqual(result["blocker_resolution_events"], 2)

    def test_database_remains_readable_after_adapter_returns(self):
        result = self.run_once()
        with BackupRecoveryReadinessLedger(self.database) as history:
            recovered = history.recover_after_restart()
        self.assertEqual(recovered["recovery_status"], "PASS")
        self.assertEqual(recovered["recovered_evaluation_count"], result["evaluation_count"])

    def test_accepts_pathlib_database_path(self):
        result = self.run_once(database=Path(self.database))
        self.assertTrue(result["restart_recovery_verified"])

    def test_requires_all_four_source_ledgers(self):
        sources = (self.sources[0], None, self.sources[2], self.sources[3])
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_FOUR_SOURCE_LEDGERS_REQUIRED",
        ):
            self.run_once(sources=sources)

    def test_rejects_in_memory_database(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database=":memory:")

    def test_rejects_file_uri_database(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database="file:readiness?mode=memory")

    def test_rejects_empty_database_path(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database="")

    def test_rejects_none_database_path(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database=None)

    def test_rejects_bytes_database_path(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database=b"/tmp/readiness.sqlite3")

    def test_rejects_non_path_database_value(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessRestartError,
            "BACKUP_RECOVERY_READINESS_RESTART_DATABASE_PATH_INVALID",
        ):
            self.run_once(database=object())

    def test_source_reconciliation_failure_is_fail_closed(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_service."
            "reconcile_backup_recovery_readiness",
            side_effect=RuntimeError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_RECORD_FAILED",
            ):
                evaluate_record_and_verify_backup_recovery_readiness_restart(
                    *self.sources, self.database, now=self.now
                )

    def test_restart_recovery_failure_is_fail_closed(self):
        with patch.object(
            BackupRecoveryReadinessLedger,
            "recover_after_restart",
            side_effect=RuntimeError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_RECOVERY_FAILED",
            ):
                self.run_once()

    def test_recovered_count_must_match_independent_snapshot(self):
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def inconsistent(ledger):
            result = original(ledger)
            result["recovered_evaluation_count"] += 1
            return result

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", inconsistent
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_READBACK_MISMATCH",
            ):
                self.run_once()

    def test_recovered_chain_head_must_match_snapshot(self):
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def inconsistent(ledger):
            result = original(ledger)
            result["chain_head_hash"] = "0" * 64
            return result

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", inconsistent
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_READBACK_MISMATCH",
            ):
                self.run_once()

    def test_restart_authorization_escalation_is_rejected(self):
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def escalated(ledger):
            result = original(ledger)
            result["execution_authorized"] = True
            return result

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", escalated
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_AUTHORIZATION_INVALID",
            ):
                self.run_once()

    def test_independent_snapshot_failure_is_rejected(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_restart."
            "verify_backup_recovery_readiness_snapshot",
            side_effect=ValueError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_INDEPENDENT_HISTORY_FAILED",
            ):
                self.run_once()

    def test_transition_verification_failure_is_rejected(self):
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_restart."
            "verify_backup_recovery_readiness_transitions",
            side_effect=ValueError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_TRANSITION_HISTORY_FAILED",
            ):
                self.run_once()

    def test_recorded_tail_identifier_must_match_after_restart(self):
        original = restart_module.evaluate_and_record_backup_recovery_readiness

        def altered(*args, **kwargs):
            result = original(*args, **kwargs)
            result["evaluation_id"] = "hqrr_" + "0" * 24
            return result

        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_restart."
            "evaluate_and_record_backup_recovery_readiness",
            side_effect=altered,
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_READBACK_MISMATCH",
            ):
                self.run_once()

    def test_output_is_aggregate_only(self):
        result = self.run_once(not_ready_report())
        self.assertNotIn("evaluation_id", result)
        self.assertNotIn("evaluation_digest", result)
        self.assertNotIn("blocker_codes", result)
        self.assertNotIn("report", result)
        self.assertNotIn("filesystem_path", result)

    def test_authorization_flags_remain_false(self):
        result = self.run_once()
        for key in (
            "artifact_bytes_verified",
            "execution_authorized",
            "automatic_dispatch",
            "automatic_retry",
        ):
            self.assertIs(result[key], False)

    def test_restart_result_confirms_four_source_ledger_verifications(self):
        result = self.run_once()
        self.assertIs(result["source_snapshot_stable"], True)
        self.assertEqual(result["source_ledger_verification_count"], 4)

    def test_transition_summary_matches_latest_record(self):
        result = self.run_once(not_ready_report())
        self.assertEqual(result["latest_readiness"], result["metadata_readiness"])
        self.assertEqual(result["latest_blocker_count"], result["blocker_count"])

    def test_restart_result_exposes_no_private_payload_fields(self):
        result = self.run_once()
        forbidden = {"backup_id", "file_digest", "receipt_payload", "customer", "vendor"}
        self.assertTrue(forbidden.isdisjoint(result))

    def test_history_is_not_deleted_or_reinitialized_between_calls(self):
        self.run_once()
        second = self.run_once(minute=1)
        self.assertEqual(second["evaluation_count"], 2)
        self.assertEqual(second["sequence"], 2)


    def _replace_restart_immutability_trigger_with_noop(self, ledger):
        ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
        )
        ledger._connection.execute(
            """
            CREATE TRIGGER ledger_backup_recovery_readiness_no_update
            BEFORE UPDATE ON ledger_backup_recovery_readiness_records
            BEGIN
                SELECT 1;
            END
            """
        )

    def test_restart_rejects_schema_drift_before_recovery_verification(self):
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def tampered(ledger):
            self._replace_restart_immutability_trigger_with_noop(ledger)
            return original(ledger)

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", tampered
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_RECOVERY_FAILED",
            ):
                self.run_once()

        with sqlite3.connect(self.database) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_recovery_readiness_records"
            ).fetchone()[0]
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'ledger_backup_recovery_readiness_no_update'"
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertIn("select 1", trigger_sql.casefold())

    def test_restart_rechecks_schema_after_recovery_before_snapshot(self):
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def recovered_then_tampered(ledger):
            result = original(ledger)
            self._replace_restart_immutability_trigger_with_noop(ledger)
            return result

        with patch.object(
            BackupRecoveryReadinessLedger,
            "recover_after_restart",
            recovered_then_tampered,
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessRestartError,
                "BACKUP_RECOVERY_READINESS_RESTART_RECOVERY_FAILED",
            ):
                self.run_once()

        with sqlite3.connect(self.database) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_recovery_readiness_records"
            ).fetchone()[0]
            trigger_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
                "AND name = 'ledger_backup_recovery_readiness_no_update'"
            ).fetchone()[0]
        self.assertEqual(count, 1)
        self.assertIn("select 1", trigger_sql.casefold())


if __name__ == "__main__":
    unittest.main()
