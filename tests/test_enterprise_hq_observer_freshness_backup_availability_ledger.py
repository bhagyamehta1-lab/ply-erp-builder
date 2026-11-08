from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_observer_freshness_backup_availability_ledger as ledger_module
from scripts.enterprise_hq_observer_freshness_backup_availability_ledger import (
    ObserverFreshnessBackupAvailabilityLedger,
    ObserverFreshnessBackupAvailabilityLedgerCorruptionError,
    ObserverFreshnessBackupAvailabilityLedgerError,
)


class ObserverFreshnessBackupAvailabilityLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "availability.sqlite3"
        self.ledger = ObserverFreshnessBackupAvailabilityLedger(str(self.path))
        self.recorded_at = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)
        self.available = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
            "availability": "AVAILABLE",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": "hqfb_" + "a" * 24,
            "lineage_sequence": 1,
            "lineage_record_hash": "b" * 64,
            "file_sha256": "c" * 64,
            "source_receipt_count": 2,
            "source_status_counts": {"FRESH": 2},
            "last_source_sequence": 2,
            "source_chain_head_digest": "d" * 64,
            "backup_integrity_verified": True,
            "lineage_match_verified": True,
        }

    def tearDown(self):
        if getattr(self, "ledger", None) is not None:
            self.ledger.close()
        self.temp.cleanup()

    def at(self, minutes=0):
        return (self.recorded_at + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")

    def unavailable(self, availability="MISSING"):
        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_" + availability,
            "availability": availability,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": self.available["backup_id"],
            "lineage_sequence": 1,
            "lineage_record_hash": "b" * 64,
        }

    def test_empty_ledger_verifies(self):
        result = self.ledger.verify()
        self.assertEqual(result["observation_count"], 0)
        self.assertIsNone(result["last_sequence"])
        self.assertFalse(result["execution_authorized"])

    def test_records_available_observation(self):
        result = self.ledger.append_observation(self.available, recorded_at=self.at())
        self.assertTrue(result["created"])
        self.assertEqual(result["availability"], "AVAILABLE")
        self.assertFalse(result["automatic_dispatch"])
        self.assertEqual(self.ledger.verify()["availability_counts"]["AVAILABLE"], 1)

    def test_exact_replay_is_idempotent(self):
        first = self.ledger.append_observation(self.available, recorded_at=self.at())
        second = self.ledger.append_observation(self.available, recorded_at=self.at())
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertFalse(second["created"])
        self.assertEqual(self.ledger.verify()["observation_count"], 1)

    def test_same_result_at_later_time_is_a_new_observation(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger.append_observation(self.available, recorded_at=self.at(1))
        self.assertEqual(self.ledger.verify()["observation_count"], 2)

    def test_availability_transition_is_preserved(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger.append_observation(self.unavailable("MISSING"), recorded_at=self.at(1))
        latest = self.ledger.get_latest_for_backup(self.available["backup_id"])
        self.assertEqual(latest["availability"], "MISSING")
        self.assertEqual(self.ledger.verify()["availability_counts"]["AVAILABLE"], 1)
        self.assertEqual(self.ledger.verify()["availability_counts"]["MISSING"], 1)

    def test_unknown_receipt_can_be_recorded_without_lineage(self):
        unknown = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
            "availability": "UNKNOWN",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": self.available["backup_id"],
            "lineage_sequence": None,
            "lineage_record_hash": None,
        }
        result = self.ledger.append_observation(unknown, recorded_at=self.at())
        self.assertEqual(result["availability"], "UNKNOWN")

    def test_non_available_observation_requires_verified_lineage(self):
        invalid = self.unavailable()
        invalid["lineage_record_hash"] = None
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_timestamp_regression_is_rejected(self):
        self.ledger.append_observation(self.available, recorded_at=self.at(2))
        with self.assertRaisesRegex(
            ObserverFreshnessBackupAvailabilityLedgerError,
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_TIME_REGRESSION",
        ):
            self.ledger.append_observation(self.unavailable(), recorded_at=self.at(1))

    def test_naive_timestamp_is_rejected(self):
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(self.available, recorded_at="2026-11-09T00:00:00")

    def test_non_utc_timestamp_is_rejected(self):
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(self.available, recorded_at="2026-11-09T05:30:00+05:30")

    def test_extra_result_field_is_rejected(self):
        invalid = dict(self.available, filesystem_path="/tmp/private.sqlite3")
        with self.assertRaisesRegex(
            ObserverFreshnessBackupAvailabilityLedgerError,
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RESULT_SCHEMA_INVALID",
        ):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_missing_result_field_is_rejected(self):
        invalid = dict(self.available)
        invalid.pop("lineage_record_hash")
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_authorization_escalation_is_rejected(self):
        invalid = dict(self.available, execution_authorized=True)
        with self.assertRaisesRegex(
            ObserverFreshnessBackupAvailabilityLedgerError,
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_AUTHORIZATION_INVALID",
        ):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_status_classification_mismatch_is_rejected(self):
        invalid = dict(self.available, status="OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING")
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_invalid_backup_identifier_is_rejected(self):
        invalid = dict(self.available, backup_id="../backup.sqlite3")
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_invalid_file_digest_is_rejected(self):
        invalid = dict(self.available, file_sha256="not-a-digest")
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_source_status_counts_must_sum_to_receipt_count(self):
        invalid = dict(self.available, source_status_counts={"FRESH": 1})
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_empty_source_summary_must_be_consistent(self):
        invalid = dict(
            self.available,
            source_receipt_count=0,
            source_status_counts={},
            last_source_sequence=1,
            source_chain_head_digest="d" * 64,
        )
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_non_available_result_cannot_include_file_evidence(self):
        invalid = dict(self.unavailable(), file_sha256="c" * 64)
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            self.ledger.append_observation(invalid, recorded_at=self.at())

    def test_restart_recovery_verifies_persisted_history(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger.close()
        self.ledger = ObserverFreshnessBackupAvailabilityLedger(str(self.path))
        recovered = self.ledger.recover_after_restart()
        self.assertEqual(recovered["observation_count"], 1)
        self.assertEqual(recovered["status"], "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECOVERY_VERIFIED")
        self.assertFalse(recovered["execution_authorized"])

    def test_tampered_record_hash_is_rejected(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_backup_availability_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_backup_availability_observations SET record_hash = ?",
            ("f" * 64,),
        )
        self.ledger._connection.execute(
            "CREATE TRIGGER observer_freshness_backup_availability_no_update "
            "BEFORE UPDATE ON observer_freshness_backup_availability_observations "
            "BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_APPEND_ONLY'); END"
        )
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            self.ledger.verify()

    def test_broken_previous_hash_is_rejected(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_backup_availability_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_backup_availability_observations SET previous_hash = ?",
            ("e" * 64,),
        )
        self.ledger._connection.execute(
            "CREATE TRIGGER observer_freshness_backup_availability_no_update "
            "BEFORE UPDATE ON observer_freshness_backup_availability_observations "
            "BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_APPEND_ONLY'); END"
        )
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            self.ledger.verify()

    def test_missing_trigger_is_rejected_on_reopen(self):
        self.ledger.close()
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TRIGGER observer_freshness_backup_availability_no_delete")
        connection.commit()
        connection.close()
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            ObserverFreshnessBackupAvailabilityLedger(str(self.path))

    def test_unexpected_table_is_rejected_on_reopen(self):
        self.ledger.close()
        connection = sqlite3.connect(self.path)
        connection.execute("CREATE TABLE unexpected(value TEXT)")
        connection.commit()
        connection.close()
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            ObserverFreshnessBackupAvailabilityLedger(str(self.path))

    def test_latest_lookup_returns_not_found_without_exposing_path(self):
        result = self.ledger.get_latest_for_backup(self.available["backup_id"])
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_OBSERVATION_NOT_FOUND")
        self.assertNotIn("path", result)

    def test_observation_response_contains_no_filesystem_path(self):
        result = self.ledger.append_observation(self.available, recorded_at=self.at())
        self.assertNotIn("filesystem_path", repr(result))
        self.assertNotIn(str(self.root), repr(result))

    def test_invalid_database_parent_is_rejected(self):
        parent = self.root / "real-parent"
        parent.mkdir()
        link = self.root / "linked-parent"
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerError):
            ObserverFreshnessBackupAvailabilityLedger(str(link / "ledger.sqlite3"))

    def test_capacity_fails_closed(self):
        self.ledger.append_observation(self.available, recorded_at=self.at())
        self.ledger.append_observation(self.available, recorded_at=self.at(1))
        with patch.object(ledger_module, "MAX_OBSERVATIONS", 2):
            with self.assertRaisesRegex(
                ObserverFreshnessBackupAvailabilityLedgerError,
                "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CAPACITY_REACHED",
            ):
                self.ledger.append_observation(self.available, recorded_at=self.at(2))
        self.assertEqual(self.ledger.verify()["observation_count"], 2)


if __name__ == "__main__":
    unittest.main()
