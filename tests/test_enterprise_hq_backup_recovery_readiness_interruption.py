from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_recovery_readiness_interruption import (
    BackupRecoveryReadinessInterruptionError,
    reconcile_interrupted_backup_recovery_readiness_evaluation,
)
from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
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
    report = ready_report()
    report.update({
        "metadata_readiness": "NOT_READY",
        "blocker_codes": ["AVAILABILITY_RECONCILIATION_INCOMPLETE"],
        "availability_observation_count": 0,
        "availability_reconciliation_status": "INCOMPLETE",
        "recovery_chain_status": "INCOMPLETE",
    })
    return report


class BackupRecoveryReadinessInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.now = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
        with BackupRecoveryReadinessLedger(self.database):
            pass

    def tearDown(self):
        self.temp.cleanup()

    def record(self, report=None, *, minute=0):
        with BackupRecoveryReadinessLedger(self.database) as history:
            return history.record_readiness_report(
                ready_report() if report is None else copy.deepcopy(report),
                now=self.now + timedelta(minutes=minute),
            )

    def inspect(self, report=None, *, minute=0, database=None, now_marker=True):
        target = self.database if database is None else database
        timestamp = self.now + timedelta(minutes=minute) if now_marker else None
        return reconcile_interrupted_backup_recovery_readiness_evaluation(
            target,
            ready_report() if report is None else copy.deepcopy(report),
            now=timestamp,
        )

    def test_committed_append_is_found_after_caller_lost_result(self):
        self.record()
        result = self.inspect()
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertTrue(result["evaluation_present"])
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["evaluation_count"], 1)

    def test_rolled_back_append_is_not_committed_after_reopen(self):
        with BackupRecoveryReadinessLedger(self.database) as history:
            @contextmanager
            def interrupted_transaction():
                history._connection.execute("BEGIN IMMEDIATE")
                try:
                    yield
                finally:
                    history._connection.rollback()

            with patch.object(history, "_transaction", interrupted_transaction):
                history.record_readiness_report(ready_report(), now=self.now)
        result = self.inspect()
        self.assertEqual(result["outcome"], "NOT_COMMITTED")
        self.assertFalse(result["evaluation_present"])
        self.assertIsNone(result["sequence"])
        self.assertEqual(result["evaluation_count"], 0)

    def test_rollback_reconciliation_never_retries(self):
        result = self.inspect()
        self.assertEqual(result["outcome"], "NOT_COMMITTED")
        self.assertEqual(result["next_step"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(result["automatic_retry"])
        self.assertFalse(result["retry_authorized"])

    def test_not_committed_inspection_does_not_change_history(self):
        before = self.inspect()
        with BackupRecoveryReadinessLedger(self.database, read_only=True) as history:
            first = history.verify()
        after = self.inspect()
        with BackupRecoveryReadinessLedger(self.database, read_only=True) as history:
            second = history.verify()
        self.assertEqual(first, second)
        self.assertEqual(before["evaluation_count"], after["evaluation_count"])
        self.assertEqual(before["chain_head_hash"], after["chain_head_hash"])

    def test_older_committed_evaluation_is_found_after_newer_append(self):
        self.record()
        self.record(not_ready_report(), minute=1)
        result = self.inspect()
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(result["evaluation_count"], 2)
        self.assertEqual(result["latest_readiness"], "NOT_READY")

    def test_wrong_report_is_not_mistaken_for_committed(self):
        self.record()
        result = self.inspect(not_ready_report())
        self.assertEqual(result["outcome"], "NOT_COMMITTED")
        self.assertEqual(result["evaluation_count"], 1)

    def test_wrong_timestamp_is_not_mistaken_for_committed(self):
        self.record()
        result = self.inspect(minute=1)
        self.assertEqual(result["outcome"], "NOT_COMMITTED")

    def test_repeated_inspection_is_idempotent(self):
        self.record()
        first = self.inspect()
        second = self.inspect()
        self.assertEqual(first, second)

    def test_read_only_open_does_not_change_database_file(self):
        self.record()
        before = Path(self.database).stat()
        result = self.inspect()
        after = Path(self.database).stat()
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertEqual(before.st_size, after.st_size)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def test_read_only_ledger_rejects_recording(self):
        with BackupRecoveryReadinessLedger(self.database, read_only=True) as history:
            with self.assertRaisesRegex(
                ValueError, "BACKUP_RECOVERY_READINESS_LEDGER_READ_ONLY"
            ):
                history.record_readiness_report(ready_report(), now=self.now)

    def test_read_only_sqlite_connection_rejects_direct_insert(self):
        with BackupRecoveryReadinessLedger(self.database, read_only=True) as history:
            with self.assertRaises(sqlite3.OperationalError):
                history._connection.execute(
                    "INSERT INTO ledger_backup_recovery_readiness_records "
                    "(sequence, evaluation_id, evaluated_at, report_digest, report_json, "
                    "metadata_readiness, blocker_count, previous_hash, record_hash) "
                    "VALUES (1, 'x', 'x', 'x', '{}', 'READY', 0, NULL, 'x')"
                )

    def test_missing_database_is_not_created(self):
        Path(self.database).unlink()
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_NOT_FOUND",
        ):
            self.inspect()
        self.assertFalse(Path(self.database).exists())

    def test_in_memory_database_is_rejected(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_PATH_INVALID",
        ):
            self.inspect(database=":memory:")

    def test_file_uri_database_is_rejected(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_DATABASE_PATH_INVALID",
        ):
            self.inspect(database="file:readiness?mode=ro")

    def test_missing_timestamp_is_rejected(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_TIMESTAMP_REQUIRED",
        ):
            reconcile_interrupted_backup_recovery_readiness_evaluation(
                self.database, ready_report()
            )

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_HISTORY_READ_FAILED",
        ):
            reconcile_interrupted_backup_recovery_readiness_evaluation(
                self.database, ready_report(), now=datetime(2026, 11, 9, 12, 0)
            )

    def test_invalid_report_is_rejected(self):
        report = ready_report()
        report["private_payload"] = "not-allowed"
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_HISTORY_READ_FAILED",
        ):
            self.inspect(report)

    def test_corrupt_history_fails_closed(self):
        self.record()
        with BackupRecoveryReadinessLedger(self.database) as history:
            history._connection.execute(
                "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
            )
            history._connection.execute(
                "UPDATE ledger_backup_recovery_readiness_records "
                "SET record_hash = ?", ("0" * 64,)
            )
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_HISTORY_READ_FAILED",
        ):
            self.inspect()

    def test_unsupported_schema_fails_closed(self):
        with BackupRecoveryReadinessLedger(self.database) as history:
            history._connection.execute(
                "UPDATE ledger_backup_recovery_readiness_meta "
                "SET value = '2.0.0' WHERE key = 'schema_version'"
            )
        with self.assertRaisesRegex(
            BackupRecoveryReadinessInterruptionError,
            "BACKUP_RECOVERY_READINESS_INTERRUPTION_HISTORY_READ_FAILED",
        ):
            self.inspect()

    def test_independent_snapshot_failure_fails_closed(self):
        self.record()
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_interruption."
            "verify_backup_recovery_readiness_snapshot",
            side_effect=ValueError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessInterruptionError,
                "BACKUP_RECOVERY_READINESS_INTERRUPTION_INDEPENDENT_HISTORY_FAILED",
            ):
                self.inspect()

    def test_transition_failure_fails_closed(self):
        self.record()
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_interruption."
            "verify_backup_recovery_readiness_transitions",
            side_effect=ValueError("synthetic"),
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessInterruptionError,
                "BACKUP_RECOVERY_READINESS_INTERRUPTION_TRANSITIONS_FAILED",
            ):
                self.inspect()

    def test_recovery_count_mismatch_fails_closed(self):
        self.record()
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def inconsistent(history):
            result = original(history)
            result["recovered_evaluation_count"] += 1
            return result

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", inconsistent
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessInterruptionError,
                "BACKUP_RECOVERY_READINESS_INTERRUPTION_VERIFICATION_DISAGREEMENT",
            ):
                self.inspect()

    def test_chain_head_mismatch_fails_closed(self):
        self.record()
        original = BackupRecoveryReadinessLedger.recover_after_restart

        def inconsistent(history):
            result = original(history)
            result["chain_head_hash"] = "0" * 64
            return result

        with patch.object(
            BackupRecoveryReadinessLedger, "recover_after_restart", inconsistent
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessInterruptionError,
                "BACKUP_RECOVERY_READINESS_INTERRUPTION_VERIFICATION_DISAGREEMENT",
            ):
                self.inspect()

    def test_result_contains_no_evaluation_identifier_or_report(self):
        self.record()
        result = self.inspect()
        self.assertNotIn("evaluation_id", result)
        self.assertNotIn("evaluation_digest", result)
        self.assertNotIn("report", result)
        self.assertNotIn("blocker_codes", result)
        self.assertNotIn("filesystem_path", result)

    def test_authorization_flags_remain_false(self):
        result = self.inspect()
        for key in (
            "artifact_bytes_verified",
            "execution_authorized",
            "automatic_dispatch",
            "automatic_retry",
            "retry_authorized",
        ):
            self.assertIs(result[key], False)

    def test_history_transition_counts_survive_interruption_reconciliation(self):
        self.record()
        self.record(not_ready_report(), minute=1)
        result = self.inspect()
        self.assertEqual(result["transition_count"], 1)
        self.assertEqual(result["readiness_change_count"], 1)
        self.assertEqual(result["blocker_addition_events"], 1)

    def test_read_only_mode_requires_an_existing_database(self):
        missing = str(Path(self.temp.name) / "missing.sqlite3")
        with self.assertRaisesRegex(
            ValueError, "BACKUP_RECOVERY_READINESS_LEDGER_DATABASE_NOT_FOUND"
        ):
            BackupRecoveryReadinessLedger(missing, read_only=True)
        self.assertFalse(Path(missing).exists())


if __name__ == "__main__":
    unittest.main()
