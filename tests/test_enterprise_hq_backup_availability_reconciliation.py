from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_observer_freshness_backup_availability_ledger as availability_module
import scripts.enterprise_hq_observer_freshness_backup_receipts as receipt_module
from scripts.enterprise_hq_backup_availability_reconciliation import (
    BackupAvailabilityReconciliationError,
    reconcile_backup_availability,
)
from scripts.enterprise_hq_observer_freshness_backup_availability_ledger import (
    ObserverFreshnessBackupAvailabilityLedger,
    ObserverFreshnessBackupAvailabilityLedgerCorruptionError,
)
from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptLedger,
    ObserverFreshnessBackupReceiptCorruptionError,
)


class BackupAvailabilityReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.receipts = ObserverFreshnessBackupReceiptLedger(
            str(self.root / "receipts.sqlite3")
        )
        self.availability = ObserverFreshnessBackupAvailabilityLedger(
            str(self.root / "availability.sqlite3")
        )
        self.base = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)
        self.receipt_seconds = 0
        self.observation_seconds = 0

    def tearDown(self):
        self.availability.close()
        self.receipts.close()
        self.temp.cleanup()

    def _at(self, seconds):
        return (self.base + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def add_receipt(self, index=1, *, file_sha=None):
        digest = file_sha or hashlib.sha256(f"backup-file-{index}".encode()).hexdigest()
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_VERIFIED",
            "file_sha256": digest,
            "receipt_count": 2,
            "status_counts": {"FRESH": 2},
            "last_sequence": 2,
            "chain_head_digest": hashlib.sha256(
                f"source-head-{index}".encode()
            ).hexdigest(),
            "equivalence_verified": True,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }
        recorded = self._at(self.receipt_seconds)
        self.receipt_seconds += 1
        return self.receipts.append_backup(result, recorded_at=recorded)

    def receipt_details(self, receipt):
        return self.receipts.get_backup_receipt(receipt["backup_id"])

    def add_available(self, receipt, **overrides):
        details = self.receipt_details(receipt)
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
            "availability": "AVAILABLE",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": details["backup_id"],
            "lineage_sequence": details["backup_count"],
            "lineage_record_hash": details["record_hash"],
            "file_sha256": details["file_sha256"],
            "source_receipt_count": details["source_receipt_count"],
            "source_status_counts": details["source_status_counts"],
            "last_source_sequence": details["last_source_sequence"],
            "source_chain_head_digest": details["source_chain_head_digest"],
            "backup_integrity_verified": True,
            "lineage_match_verified": True,
        }
        result.update(overrides)
        recorded = self._at(self.observation_seconds)
        self.observation_seconds += 1
        return self.availability.append_observation(result, recorded_at=recorded)

    def add_nonavailable(self, receipt, state="MISSING", **overrides):
        details = self.receipt_details(receipt)
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_" + state,
            "availability": state,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": details["backup_id"],
            "lineage_sequence": details["backup_count"],
            "lineage_record_hash": details["record_hash"],
        }
        result.update(overrides)
        recorded = self._at(self.observation_seconds)
        self.observation_seconds += 1
        return self.availability.append_observation(result, recorded_at=recorded)

    def add_unknown(self, backup_id):
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
            "availability": "UNKNOWN",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": backup_id,
            "lineage_sequence": None,
            "lineage_record_hash": None,
        }
        recorded = self._at(self.observation_seconds)
        self.observation_seconds += 1
        return self.availability.append_observation(result, recorded_at=recorded)

    def reconcile(self):
        return reconcile_backup_availability(self.receipts, self.availability)

    def test_empty_ledgers_reconcile_without_authorizing_execution(self):
        result = self.reconcile()
        self.assertEqual(result["status"], "RECONCILED_EMPTY")
        self.assertEqual(result["receipt_count"], 0)
        self.assertEqual(result["latest_observation_count"], 0)
        self.assertEqual(result["artifact_availability"], "NO_BACKUPS")
        self.assertFalse(result["execution_authorized"])

    def test_matching_available_receipt_and_observation_reconcile(self):
        receipt = self.add_receipt()
        self.add_available(receipt)
        result = self.reconcile()
        self.assertEqual(result["status"], "RECONCILED")
        self.assertEqual(result["matched_available_count"], 1)
        self.assertEqual(result["artifact_availability"], "ALL_AVAILABLE")

    def test_matching_missing_observation_is_reconciled_but_not_available(self):
        receipt = self.add_receipt()
        self.add_nonavailable(receipt, "MISSING")
        result = self.reconcile()
        self.assertEqual(result["status"], "RECONCILED")
        self.assertEqual(result["matched_nonavailable_count"], 1)
        self.assertEqual(result["availability_counts"]["MISSING"], 1)
        self.assertEqual(result["artifact_availability"], "PARTIAL_OR_UNAVAILABLE")

    def test_latest_transition_controls_current_availability(self):
        receipt = self.add_receipt()
        self.add_available(receipt)
        self.add_nonavailable(receipt, "MISSING")
        result = self.reconcile()
        self.assertEqual(result["history_observation_count"], 2)
        self.assertEqual(result["latest_observation_count"], 1)
        self.assertEqual(result["availability_counts"]["MISSING"], 1)
        self.assertEqual(result["availability_counts"]["AVAILABLE"], 0)
        self.assertEqual(result["matched_nonavailable_count"], 1)

    def test_receipt_without_observation_is_incomplete(self):
        self.add_receipt()
        result = self.reconcile()
        self.assertEqual(result["status"], "RECONCILIATION_INCOMPLETE")
        self.assertEqual(result["missing_observation_count"], 1)

    def test_non_unknown_observation_without_receipt_is_orphaned(self):
        backup_id = "hqfb_" + "a" * 24
        self.add_unknown(backup_id)
        result = {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING",
            "availability": "MISSING",
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
            "backup_id": backup_id,
            "lineage_sequence": 1,
            "lineage_record_hash": "b" * 64,
        }
        self.availability.append_observation(
            result, recorded_at=self._at(self.observation_seconds)
        )
        self.observation_seconds += 1
        summary = self.reconcile()
        self.assertEqual(summary["orphan_observation_count"], 1)

    def test_unknown_observation_without_receipt_is_not_called_orphan(self):
        self.add_unknown("hqfb_" + "c" * 24)
        result = self.reconcile()
        self.assertEqual(result["orphan_observation_count"], 0)
        self.assertEqual(result["unknown_observation_count"], 1)
        self.assertEqual(result["status"], "RECONCILIATION_INCOMPLETE")

    def test_unknown_observation_remains_incomplete_if_receipt_arrives_later(self):
        digest = "d" * 64
        backup_id = "hqfb_" + digest[:24]
        self.add_unknown(backup_id)
        self.add_receipt(file_sha=digest)
        result = self.reconcile()
        self.assertEqual(result["unknown_observation_count"], 1)
        self.assertEqual(result["missing_observation_count"], 0)
        self.assertEqual(result["status"], "RECONCILIATION_INCOMPLETE")

    def test_lineage_sequence_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(receipt, lineage_sequence=2)
        result = self.reconcile()
        self.assertEqual(result["lineage_mismatch_count"], 1)

    def test_lineage_record_hash_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(receipt, lineage_record_hash="e" * 64)
        result = self.reconcile()
        self.assertEqual(result["lineage_mismatch_count"], 1)

    def test_file_digest_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(receipt, file_sha256="f" * 64)
        result = self.reconcile()
        self.assertEqual(result["evidence_mismatch_count"], 1)

    def test_source_receipt_count_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(
            receipt,
            source_receipt_count=3,
            source_status_counts={"FRESH": 3},
            last_source_sequence=3,
        )
        result = self.reconcile()
        self.assertEqual(result["evidence_mismatch_count"], 1)

    def test_source_status_count_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(receipt, source_status_counts={"MISSED": 2})
        result = self.reconcile()
        self.assertEqual(result["evidence_mismatch_count"], 1)

    def test_source_chain_head_mismatch_is_detected(self):
        receipt = self.add_receipt()
        self.add_available(receipt, source_chain_head_digest="9" * 64)
        result = self.reconcile()
        self.assertEqual(result["evidence_mismatch_count"], 1)

    def test_corrupted_receipt_ledger_fails_closed(self):
        self.add_receipt()
        self.receipts._connection.execute(
            "DROP TRIGGER observer_freshness_backup_receipts_no_update"
        )
        self.receipts._connection.execute(
            f"UPDATE {receipt_module._TABLE} SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.reconcile()

    def test_corrupted_availability_ledger_fails_closed(self):
        receipt = self.add_receipt()
        self.add_available(receipt)
        self.availability._connection.execute(
            f"DROP TRIGGER {availability_module._UPDATE_TRIGGER}"
        )
        self.availability._connection.execute(
            f"UPDATE {availability_module._TABLE} SET record_hash = ? WHERE sequence = 1",
            ("0" * 64,),
        )
        self.availability._connection.commit()
        with self.assertRaises(ObserverFreshnessBackupAvailabilityLedgerCorruptionError):
            self.reconcile()

    def test_wrong_ledger_types_are_rejected(self):
        with self.assertRaises(BackupAvailabilityReconciliationError):
            reconcile_backup_availability(object(), self.availability)
        with self.assertRaises(BackupAvailabilityReconciliationError):
            reconcile_backup_availability(self.receipts, object())

    def test_result_contains_aggregate_counts_only(self):
        receipt = self.add_receipt()
        self.add_available(receipt)
        result = self.reconcile()
        forbidden = {
            "backup_id", "observation_id", "file_sha256", "recorded_at",
            "path", "database", "payload", "record_hash",
        }
        self.assertTrue(forbidden.isdisjoint(result))
        self.assertEqual(result["receipt_count"], 1)

    def test_all_authorization_flags_remain_false(self):
        result = self.reconcile()
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_concurrent_append_invalidates_cross_ledger_snapshot(self):
        receipt = self.add_receipt()
        original = self.availability.list_latest_observations

        def append_during_read():
            rows = original()
            self.add_available(receipt)
            return rows

        with patch.object(
            self.availability, "list_latest_observations", side_effect=append_during_read
        ):
            with self.assertRaisesRegex(
                BackupAvailabilityReconciliationError,
                "BACKUP_AVAILABILITY_RECONCILIATION_SNAPSHOT_CHANGED",
            ):
                self.reconcile()


if __name__ == "__main__":
    unittest.main()
