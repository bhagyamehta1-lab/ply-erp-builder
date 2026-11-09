from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
    BackupRecoveryReadinessLedgerCorruptionError,
    BackupRecoveryReadinessLedgerError,
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


class BackupRecoveryReadinessLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.now = datetime(2026, 11, 9, 8, 0, tzinfo=timezone.utc)
        self.ledger = BackupRecoveryReadinessLedger(self.database)

    def tearDown(self):
        try:
            self.ledger.close()
        except sqlite3.Error:
            pass
        self.temp.cleanup()

    def test_empty_history_verifies(self):
        result = self.ledger.verify()
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["history_status"], "VALID")

    def test_records_ready_report(self):
        result = self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.assertTrue(result["created"])
        self.assertEqual(result["metadata_readiness"], "READY")
        self.assertEqual(result["sequence"], 1)
        self.assertEqual(self.ledger.verify()["ready_count"], 1)

    def test_records_not_ready_report(self):
        result = self.ledger.record_readiness_report(not_ready_report(), now=self.now)
        self.assertEqual(result["metadata_readiness"], "NOT_READY")
        self.assertEqual(result["blocker_count"], 2)
        self.assertEqual(self.ledger.verify()["not_ready_count"], 1)

    def test_exact_replay_is_idempotent(self):
        first = self.ledger.record_readiness_report(ready_report(), now=self.now)
        second = self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.assertEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertFalse(second["created"])
        self.assertTrue(second["already_present"])
        self.assertEqual(self.ledger.verify()["record_count"], 1)

    def test_same_report_at_later_time_creates_history(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        second = self.ledger.record_readiness_report(
            ready_report(), now=self.now + timedelta(minutes=1)
        )
        self.assertTrue(second["created"])
        self.assertEqual(second["sequence"], 2)

    def test_distinct_readiness_transition_is_recorded(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        second = self.ledger.record_readiness_report(
            not_ready_report(), now=self.now + timedelta(minutes=1)
        )
        self.assertEqual(second["metadata_readiness"], "NOT_READY")
        report = self.ledger.verify()
        self.assertEqual(report["ready_count"], 1)
        self.assertEqual(report["not_ready_count"], 1)

    def test_rejects_clock_rollback(self):
        self.ledger.record_readiness_report(
            ready_report(), now=self.now + timedelta(minutes=2)
        )
        with self.assertRaisesRegex(
            BackupRecoveryReadinessLedgerError,
            "BACKUP_RECOVERY_READINESS_LEDGER_CLOCK_ROLLBACK",
        ):
            self.ledger.record_readiness_report(ready_report(), now=self.now)

    def test_restart_verifies_persisted_history(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.ledger.record_readiness_report(
            not_ready_report(), now=self.now + timedelta(minutes=1)
        )
        self.ledger.close()
        self.ledger = BackupRecoveryReadinessLedger(self.database)
        result = self.ledger.recover_after_restart()
        self.assertEqual(result["recovery_status"], "PASS")
        self.assertEqual(result["recovered_evaluation_count"], 2)
        self.assertEqual(result["ready_count"], 1)
        self.assertEqual(result["not_ready_count"], 1)

    def test_snapshot_contains_only_aggregate_report_fields(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        snapshot = self.ledger.export_verification_snapshot()
        rendered = str(snapshot)
        self.assertNotIn("backup_id", rendered)
        self.assertNotIn("file_digest", rendered)
        self.assertNotIn("filesystem_path", rendered)
        self.assertNotIn("private_payload", rendered)
        self.assertFalse(snapshot["execution_authorized"])

    def test_snapshot_binds_the_exact_schema_fingerprint(self):
        snapshot = self.ledger.export_verification_snapshot()
        self.assertEqual(
            snapshot["schema_fingerprint"],
            "bf38ee3acdf673e16b22eb1eb45a306a8622a5e043aa065cc60b73b700e9a9ec",
        )
        self.assertEqual(self.ledger.verify()["history_status"], "VALID")

    def test_verify_detects_schema_definition_change_after_open(self):
        self.ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
        )
        self.ledger._connection.execute(
            "CREATE TRIGGER ledger_backup_recovery_readiness_no_update "
            "BEFORE UPDATE ON ledger_backup_recovery_readiness_records "
            "BEGIN SELECT 1; END"
        )
        with self.assertRaisesRegex(
            BackupRecoveryReadinessLedgerCorruptionError,
            "SCHEMA_FINGERPRINT_INVALID",
        ):
            self.ledger.verify()

    def test_rejects_extra_report_field(self):
        report = ready_report()
        report["backup_id"] = "raw-identifier"
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_missing_report_field(self):
        report = ready_report()
        del report["blocker_codes"]
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_ready_report_with_blocker(self):
        report = ready_report()
        report["blocker_codes"] = ["RECOVERY_CHAIN_INCOMPLETE"]
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_not_ready_report_without_blocker(self):
        report = not_ready_report()
        report["blocker_codes"] = []
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_wrong_readiness_scope(self):
        report = ready_report()
        report["readiness_scope"] = "PHYSICAL_RESTORE"
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_boolean_as_integer_count(self):
        report = ready_report()
        report["inventory_record_count"] = True
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_count_over_limit(self):
        report = ready_report()
        report["inventory_record_count"] = 257
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_wrong_source_ledger_count(self):
        report = ready_report()
        report["source_ledger_verification_count"] = 3
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_unstable_source_snapshot(self):
        report = ready_report()
        report["source_snapshot_stable"] = False
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_execution_authorization(self):
        report = ready_report()
        report["execution_authorized"] = True
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_artifact_byte_claim(self):
        report = ready_report()
        report["artifact_bytes_verified"] = True
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_inconsistent_predecessor_counts(self):
        report = ready_report()
        report["predecessor_available_count"] = 1
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(report, now=self.now)

    def test_rejects_naive_timestamp(self):
        with self.assertRaises(BackupRecoveryReadinessLedgerError):
            self.ledger.record_readiness_report(
                ready_report(), now=datetime(2026, 11, 9, 8, 0)
            )

    def test_capacity_fails_closed(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_ledger."
            "MAX_RECOVERY_READINESS_EVALUATIONS",
            1,
        ):
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError,
                "BACKUP_RECOVERY_READINESS_LEDGER_CAPACITY_REACHED",
            ):
                self.ledger.record_readiness_report(
                    not_ready_report(), now=self.now + timedelta(minutes=1)
                )

    def test_database_records_are_immutable(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "UPDATE ledger_backup_recovery_readiness_records "
                "SET metadata_readiness = 'NOT_READY'"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "DELETE FROM ledger_backup_recovery_readiness_records"
            )

    def test_detects_report_digest_corruption(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE ledger_backup_recovery_readiness_records "
            "SET report_digest = ?", ("0" * 64,)
        )
        with self.assertRaises(BackupRecoveryReadinessLedgerCorruptionError):
            self.ledger.verify()

    def test_detects_record_hash_corruption(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE ledger_backup_recovery_readiness_records "
            "SET record_hash = ?", ("0" * 64,)
        )
        with self.assertRaises(BackupRecoveryReadinessLedgerCorruptionError):
            self.ledger.verify()

    def test_detects_previous_hash_corruption(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.ledger.record_readiness_report(
            not_ready_report(), now=self.now + timedelta(minutes=1)
        )
        self.ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE ledger_backup_recovery_readiness_records "
            "SET previous_hash = ? WHERE sequence = 2", ("0" * 64,)
        )
        with self.assertRaises(BackupRecoveryReadinessLedgerCorruptionError):
            self.ledger.verify()

    def test_detects_tail_truncation_against_persisted_head(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        self.ledger._connection.execute(
            "DROP TRIGGER ledger_backup_recovery_readiness_no_delete"
        )
        self.ledger._connection.execute(
            "DELETE FROM ledger_backup_recovery_readiness_records"
        )
        with self.assertRaisesRegex(
            BackupRecoveryReadinessLedgerCorruptionError,
            "BACKUP_RECOVERY_READINESS_LEDGER_STATE_HEAD_MISMATCH",
        ):
            self.ledger.verify()

    def test_snapshot_is_consistent_during_concurrent_wal_append(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        journal_mode = self.ledger._connection.execute(
            "PRAGMA journal_mode = WAL"
        ).fetchone()[0]
        self.assertEqual(journal_mode.casefold(), "wal")
        second = BackupRecoveryReadinessLedger(self.database)
        try:
            original_rows = self.ledger._snapshot_rows

            def append_after_snapshot_rows():
                rows = original_rows()
                second.record_readiness_report(
                    not_ready_report(), now=self.now + timedelta(minutes=1)
                )
                return rows

            with patch.object(
                self.ledger, "_snapshot_rows", side_effect=append_after_snapshot_rows
            ):
                snapshot = self.ledger.export_verification_snapshot()

            self.assertEqual(snapshot["record_count"], 1)
            self.assertEqual(snapshot["records"][-1]["sequence"], 1)
            self.assertEqual(second.verify()["record_count"], 2)
            self.assertEqual(self.ledger.verify()["record_count"], 2)
        finally:
            second.close()

    def test_concurrent_exact_replays_are_idempotent(self):
        second = BackupRecoveryReadinessLedger(self.database)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first_future = pool.submit(
                    self.ledger.record_readiness_report, ready_report(), now=self.now
                )
                second_future = pool.submit(
                    second.record_readiness_report, ready_report(), now=self.now
                )
                results = [first_future.result(), second_future.result()]
            self.assertEqual(sum(bool(item["created"]) for item in results), 1)
            self.assertEqual(self.ledger.verify()["record_count"], 1)
        finally:
            second.close()

    def test_recovery_result_never_authorizes_execution(self):
        self.ledger.record_readiness_report(ready_report(), now=self.now)
        result = self.ledger.recover_after_restart()
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_rejects_unsupported_schema_version(self):
        self.ledger._connection.execute(
            "UPDATE ledger_backup_recovery_readiness_meta "
            "SET value = '2.0.0' WHERE key = 'schema_version'"
        )
        self.ledger.close()
        with self.assertRaisesRegex(
            BackupRecoveryReadinessLedgerError,
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_VERSION_UNSUPPORTED",
        ):
            BackupRecoveryReadinessLedger(self.database)


if __name__ == "__main__":
    unittest.main()
