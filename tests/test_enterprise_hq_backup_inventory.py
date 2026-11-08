from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_inventory import (
    BackupInventoryCorruptionError, BackupInventoryError, LedgerBackupInventory,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot, verify_ledger_integrity_snapshot,
)


class LedgerBackupInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 5, 0, tzinfo=timezone.utc)
        self.source_path = self.root / "source.sqlite3"
        self.restore_path = self.root / "restored.sqlite3"
        self.inventory_path = self.root / "inventory.sqlite3"
        self.source = EvidenceVerificationLedger(str(self.source_path))
        self.inventory = LedgerBackupInventory(str(self.inventory_path))
        self.source_snapshot, self.restored_snapshot = self._make_equal_snapshots()
        self.entry = self._entry()

    def tearDown(self):
        self.inventory.close()
        self.source.close()
        self.temp.cleanup()

    def _make_equal_snapshots(self):
        source_snapshot = build_ledger_integrity_snapshot(self.source)
        target = sqlite3.connect(str(self.restore_path))
        try:
            self.source._connection.backup(target)
        finally:
            target.close()
        self.restore_path.chmod(0o600)
        restored = EvidenceVerificationLedger(str(self.restore_path))
        try:
            restored_snapshot = build_ledger_integrity_snapshot(restored)
        finally:
            restored.close()
        return source_snapshot, restored_snapshot

    def _entry(self, **overrides):
        entry = {
            "backup_id": "hqbk_0123456789abcdef01234567",
            "ledger_type": self.source_snapshot["ledger_type"],
            "declared_size_bytes": 4096,
            "created_at": self.now.isoformat().replace("+00:00", "Z"),
            "retain_until": (self.now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "generation": 1,
            "predecessor_backup_id": None,
            "storage_scope": "LOCAL_ONLY",
        }
        entry.update(overrides)
        return entry

    def _record(self, entry=None, source=None, restored=None, now=None):
        return self.inventory.record_backup(
            self.entry if entry is None else entry,
            self.source_snapshot if source is None else source,
            self.restored_snapshot if restored is None else restored,
            now=self.now if now is None else now,
        )

    def test_records_restore_verified_metadata_only(self):
        result = self._record()
        self.assertEqual(result["status"], "BACKUP_METADATA_REGISTERED")
        self.assertTrue(result["created"])
        self.assertEqual(result["restore_status"], "RESTORE_EQUIVALENCE_VERIFIED")
        self.assertEqual(result["artifact_presence"], "NOT_INSPECTED")
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["automatic_purge"])
        self.assertFalse(result["execution_authorized"])

    def test_identical_record_is_idempotent(self):
        first, second = self._record(), self._record()
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertFalse(second["created"])

    def test_conflicting_reuse_of_backup_id_is_rejected(self):
        self._record()
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_ID_CONTENT_CONFLICT"):
            self._record(entry=self._entry(declared_size_bytes=8192))

    def test_unknown_entry_field_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_SCHEMA_INVALID"):
            self._record(entry=self._entry(unapproved_path="/tmp/private-backup.sqlite3"))

    def test_missing_entry_field_is_rejected(self):
        changed = self._entry()
        changed.pop("storage_scope")
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_SCHEMA_INVALID"):
            self._record(entry=changed)

    def test_invalid_backup_identifier_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_ID_INVALID"):
            self._record(entry=self._entry(backup_id="../backup.sqlite3"))

    def test_invalid_ledger_type_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_LEDGER_TYPE_INVALID"):
            self._record(entry=self._entry(ledger_type="../private"))

    def test_nonlocal_storage_scope_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_STORAGE_SCOPE_UNSUPPORTED"):
            self._record(entry=self._entry(storage_scope="CLOUD"))

    def test_oversized_declared_backup_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_SIZE_INVALID"):
            self._record(entry=self._entry(declared_size_bytes=256 * 1024 * 1024 + 1))

    def test_zero_declared_backup_size_is_rejected(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_SIZE_INVALID"):
            self._record(entry=self._entry(declared_size_bytes=0))

    def test_expired_retention_window_cannot_be_registered(self):
        changed = self._entry(retain_until=(self.now - timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_RETENTION_INVALID"):
            self._record(entry=changed)

    def test_retention_window_over_ninety_days_is_rejected(self):
        changed = self._entry(retain_until=(self.now + timedelta(days=91)).isoformat())
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_RETENTION_LIMIT_EXCEEDED"):
            self._record(entry=changed)

    def test_naive_timestamp_is_rejected(self):
        changed = self._entry(created_at="2026-11-08T05:00:00")
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_CREATED_AT_INVALID"):
            self._record(entry=changed)

    def test_future_created_timestamp_is_rejected(self):
        changed = self._entry(created_at=(self.now + timedelta(minutes=2)).isoformat())
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_CREATED_AT_INVALID"):
            self._record(entry=changed)

    def test_generation_must_start_at_one(self):
        changed = self._entry(generation=2, predecessor_backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa")
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_LINEAGE_INVALID"):
            self._record(entry=changed)

    def test_second_generation_requires_exact_predecessor(self):
        self._record()
        changed = self._entry(
            backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa",
            generation=2,
            predecessor_backup_id="hqbk_bbbbbbbbbbbbbbbbbbbbbbbb",
        )
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_LINEAGE_INVALID"):
            self._record(entry=changed)

    def test_valid_second_generation_extends_lineage(self):
        first = self._record()
        changed = self._entry(
            backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa",
            generation=2,
            predecessor_backup_id=first["backup_id"],
        )
        second = self._record(entry=changed)
        self.assertEqual(second["generation"], 2)
        self.assertEqual(self.inventory.verify()["backup_inventory_count"], 2)

    def test_generation_gap_is_rejected(self):
        first = self._record()
        changed = self._entry(
            backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa",
            generation=3,
            predecessor_backup_id=first["backup_id"],
        )
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_LINEAGE_INVALID"):
            self._record(entry=changed)

    def test_retention_evaluation_never_deletes_expired_records(self):
        self._record()
        result = self.inventory.evaluate_retention(now=self.now + timedelta(days=31))
        self.assertEqual(result["expired_count"], 1)
        self.assertEqual(result["retained_count"], 0)
        self.assertFalse(result["automatic_purge"])
        self.assertEqual(result["records_deleted"], 0)
        self.assertEqual(self.inventory.verify()["backup_inventory_count"], 1)

    def test_restart_and_integrity_snapshot_include_backup_inventory(self):
        self._record()
        snapshot = build_ledger_integrity_snapshot(self.inventory)
        verified = verify_ledger_integrity_snapshot(snapshot)
        self.assertEqual(verified["status"], "CHECKPOINT_INTEGRITY_VALID")
        self.assertEqual(snapshot["verification_summary"]["backup_inventory_count"], 1)
        self.assertEqual(snapshot["verification_summary"]["backup_inventory_chain"], "VALID")
        recovered = self.inventory.recover_after_restart()
        self.assertEqual(recovered["backup_inventory_records_recovered"], 1)
        self.assertFalse(recovered["backup_automatic_purge"])

    def test_corrupted_backup_audit_hash_is_rejected(self):
        self._record()
        self.inventory._connection.execute(
            "UPDATE ledger_backup_inventory_audit_events SET record_hash = ?", ("0" * 64,)
        )
        with self.assertRaisesRegex(BackupInventoryCorruptionError, "BACKUP_INVENTORY_AUDIT_CHAIN_HASH_INVALID"):
            self.inventory.verify()

    def test_corrupted_inventory_entry_digest_is_rejected(self):
        self._record()
        self.inventory._connection.execute(
            "UPDATE ledger_backup_inventory SET entry_digest = ?", ("0" * 64,)
        )
        with self.assertRaisesRegex(BackupInventoryCorruptionError, "BACKUP_INVENTORY_ENTRY_DIGEST_INVALID"):
            self.inventory.verify()

    def test_concurrent_duplicate_registration_is_idempotent(self):
        def worker():
            ledger = LedgerBackupInventory(str(self.inventory_path))
            try:
                return ledger.record_backup(
                    self.entry, self.source_snapshot, self.restored_snapshot, now=self.now
                )
            finally:
                ledger.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(sum(1 for item in results if item["created"]), 1)
        self.assertEqual(sum(1 for item in results if item["already_present"]), 1)

    def test_entry_and_snapshots_are_not_mutated(self):
        entry = self._entry()
        before_entry = json.dumps(entry, sort_keys=True)
        before_source = json.dumps(self.source_snapshot, sort_keys=True)
        before_restored = json.dumps(self.restored_snapshot, sort_keys=True)
        self._record(entry=entry)
        self.assertEqual(json.dumps(entry, sort_keys=True), before_entry)
        self.assertEqual(json.dumps(self.source_snapshot, sort_keys=True), before_source)
        self.assertEqual(json.dumps(self.restored_snapshot, sort_keys=True), before_restored)

    def test_mismatched_source_and_restore_snapshots_are_rejected(self):
        other = EvidenceVerificationLedger(str(self.root / "other.sqlite3"))
        try:
            other.propose_many([{
                "task_id": "HQ-BACKUP-OTHER",
                "workstream_id": "WS-08",
                "task_kind": "INTERNAL_CODE",
                "attempt": 0,
                "status": "PROPOSED",
                "external_effects": False,
                "requires_human_approval": True,
            }])
            changed = build_ledger_integrity_snapshot(other)
        finally:
            other.close()
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_RESTORE_EQUIVALENCE_FAILED"):
            self._record(restored=changed)

    def test_retention_evaluation_persists_metadata_only(self):
        self._record()
        result = self.inventory.evaluate_retention(now=self.now)
        self.assertEqual(result["status"], "RETENTION_EVALUATED")
        self.assertTrue(result["created"])
        self.assertRegex(result["evaluation_id"], r"^hqre_[a-f0-9]{24}$")
        self.assertEqual(result["inventory_count"], 1)
        self.assertEqual(result["retained_count"], 1)
        self.assertEqual(result["expired_count"], 0)
        self.assertFalse(result["automatic_purge"])
        self.assertEqual(result["records_deleted"], 0)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        verified = self.inventory.verify()
        self.assertEqual(verified["backup_retention_evaluation_count"], 1)
        self.assertEqual(verified["backup_retention_audit_event_count"], 1)
        self.assertEqual(verified["backup_retention_chain"], "VALID")

    def test_identical_retention_evaluation_is_idempotent(self):
        first = self.inventory.evaluate_retention(now=self.now)
        second = self.inventory.evaluate_retention(now=self.now)
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertFalse(second["created"])
        self.assertEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertEqual(self.inventory.verify()["backup_retention_evaluation_count"], 1)

    def test_inventory_change_produces_new_retention_evaluation(self):
        self._record()
        first = self.inventory.evaluate_retention(now=self.now)
        second_entry = self._entry(
            backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa",
            generation=2,
            predecessor_backup_id=self.entry["backup_id"],
        )
        self._record(entry=second_entry)
        second = self.inventory.evaluate_retention(now=self.now)
        self.assertNotEqual(first["inventory_digest"], second["inventory_digest"])
        self.assertNotEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertEqual(second["inventory_count"], 2)

    def test_retention_evaluation_history_survives_restart(self):
        self._record()
        self.inventory.evaluate_retention(now=self.now)
        self.inventory.close()
        self.inventory = LedgerBackupInventory(str(self.inventory_path))
        recovered = self.inventory.recover_after_restart()
        self.assertEqual(recovered["backup_retention_evaluations_recovered"], 1)
        self.assertEqual(recovered["backup_retention_audit_events_recovered"], 1)
        self.assertFalse(recovered["backup_automatic_purge"])

    def test_corrupted_retention_evaluation_digest_is_rejected(self):
        self.inventory.evaluate_retention(now=self.now)
        self.inventory._connection.execute(
            "UPDATE ledger_backup_retention_evaluations SET evaluation_digest = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupInventoryCorruptionError,
            "BACKUP_RETENTION_EVALUATION_DIGEST_INVALID",
        ):
            self.inventory.verify()

    def test_corrupted_retention_audit_hash_is_rejected(self):
        self.inventory.evaluate_retention(now=self.now)
        self.inventory._connection.execute(
            "UPDATE ledger_backup_retention_audit_events SET record_hash = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupInventoryCorruptionError,
            "BACKUP_RETENTION_AUDIT_CHAIN_HASH_INVALID",
        ):
            self.inventory.verify()

    def test_retention_evaluation_capacity_fails_closed(self):
        with patch(
            "scripts.enterprise_hq_backup_inventory.MAX_RETENTION_EVALUATION_RECORDS", 1
        ):
            self.inventory.evaluate_retention(now=self.now)
            with self.assertRaisesRegex(
                BackupInventoryError,
                "BACKUP_RETENTION_EVALUATION_CAPACITY_REACHED",
            ):
                self.inventory.evaluate_retention(now=self.now + timedelta(seconds=1))

    def test_concurrent_identical_retention_evaluations_are_idempotent(self):
        def worker():
            ledger = LedgerBackupInventory(str(self.inventory_path))
            try:
                return ledger.evaluate_retention(now=self.now)
            finally:
                ledger.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: worker(), range(2)))
        self.assertEqual(sum(1 for item in results if item["created"]), 1)
        self.assertEqual(sum(1 for item in results if item["already_present"]), 1)
        self.assertEqual(self.inventory.verify()["backup_retention_evaluation_count"], 1)

    def test_corrupt_inventory_prevents_retention_evaluation(self):
        self._record()
        self.inventory._connection.execute(
            "UPDATE ledger_backup_inventory SET entry_digest = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupInventoryCorruptionError,
            "BACKUP_INVENTORY_ENTRY_DIGEST_INVALID",
        ):
            self.inventory.evaluate_retention(now=self.now)
        count = self.inventory._connection.execute(
            "SELECT COUNT(*) FROM ledger_backup_retention_evaluations"
        ).fetchone()[0]
        self.assertEqual(count, 0)

    def test_retention_result_exposes_no_artifact_path_or_payload(self):
        result = self.inventory.evaluate_retention(now=self.now)
        self.assertNotIn("path", result)
        self.assertNotIn("artifact_path", result)
        self.assertNotIn("payload", result)
        self.assertFalse(result["artifact_bytes_verified"])

    def test_retention_evaluation_requires_aware_utc_clock(self):
        with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_CLOCK_INVALID"):
            self.inventory.evaluate_retention(now=datetime(2026, 11, 8, 5, 0))

    def test_capacity_fails_closed(self):
        with patch("scripts.enterprise_hq_backup_inventory.MAX_BACKUP_INVENTORY_RECORDS", 1):
            self._record()
            changed = self._entry(
                backup_id="hqbk_aaaaaaaaaaaaaaaaaaaaaaaa",
                generation=2,
                predecessor_backup_id=self.entry["backup_id"],
            )
            with self.assertRaisesRegex(BackupInventoryError, "BACKUP_INVENTORY_CAPACITY_REACHED"):
                self._record(entry=changed)

    def test_result_does_not_claim_artifact_or_payload_verification(self):
        result = self._record()
        rendered = json.dumps(result, sort_keys=True).lower()
        self.assertNotIn("path", rendered)
        self.assertNotIn("payload", rendered)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertEqual(result["artifact_presence"], "NOT_INSPECTED")


if __name__ == "__main__":
    unittest.main()
