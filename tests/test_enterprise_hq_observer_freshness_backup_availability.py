from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import scripts.enterprise_hq_observer_freshness_backup_availability as availability_module
from scripts.enterprise_hq_observer_freshness import evaluate_observer_freshness
from scripts.enterprise_hq_observer_freshness_backup import create_verified_backup
from scripts.enterprise_hq_observer_freshness_backup_availability import (
    ObserverFreshnessBackupAvailabilityError,
    verify_backup_availability,
)
from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptCorruptionError,
    ObserverFreshnessBackupReceiptLedger,
)
from scripts.enterprise_hq_observer_freshness_ledger import ObserverFreshnessLedger


class ObserverFreshnessBackupAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_path = self.root / "source.sqlite3"
        self.backup_path = self.root / "backup.sqlite3"
        self.receipt_path = self.root / "backup-receipts.sqlite3"
        self.source = ObserverFreshnessLedger(str(self.source_path))
        self.lineage = ObserverFreshnessBackupReceiptLedger(str(self.receipt_path))
        self.base_at = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)
        self._append_source(1)
        self.backup_result = create_verified_backup(self.source, self.backup_path)
        self.receipt = self.lineage.append_backup(
            self.backup_result,
            recorded_at=self.base_at.isoformat().replace("+00:00", "Z"),
        )

    def tearDown(self):
        if getattr(self, "source", None) is not None:
            self.source.close()
        if getattr(self, "lineage", None) is not None:
            self.lineage.close()
        self.temp.cleanup()

    def _append_source(self, index):
        current = self.base_at + timedelta(minutes=index - 1)
        last = current - timedelta(seconds=900)
        receipt = evaluate_observer_freshness(
            last.isoformat().replace("+00:00", "Z"),
            current.isoformat().replace("+00:00", "Z"),
        )
        key = hashlib.sha256(f"availability-source-{index}".encode()).hexdigest()
        return self.source.append(
            receipt,
            idempotency_key=key,
            recorded_at=current.isoformat().replace("+00:00", "Z"),
        )

    def verify(self, path=None, backup_id=None):
        return verify_backup_availability(
            self.lineage,
            self.receipt["backup_id"] if backup_id is None else backup_id,
            self.backup_path if path is None else path,
        )

    def test_available_backup_matches_recorded_lineage(self):
        result = self.verify()
        self.assertEqual(result["availability"], "AVAILABLE")
        self.assertTrue(result["backup_integrity_verified"])
        self.assertTrue(result["lineage_match_verified"])
        self.assertEqual(result["source_receipt_count"], 1)

    def test_missing_backup_is_reported_without_mutation(self):
        self.backup_path.unlink()
        result = self.verify()
        self.assertEqual(result["availability"], "MISSING")
        self.assertFalse(result["execution_authorized"])

    def test_unknown_receipt_is_reported_before_path_inspection(self):
        result = self.verify(backup_id="hqfb_" + "0" * 24)
        self.assertEqual(result["availability"], "UNKNOWN")
        self.assertEqual(
            result["status"],
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
        )

    def test_inaccessible_file_is_reported_separately(self):
        original = os.lstat

        def guarded(value):
            if os.fspath(value) == os.fspath(self.backup_path):
                raise PermissionError("injected")
            return original(value)

        with patch.object(availability_module.os, "lstat", side_effect=guarded):
            result = self.verify()
        self.assertEqual(result["availability"], "UNAVAILABLE")

    def test_symlink_backup_is_invalid(self):
        link = self.root / "backup-link.sqlite3"
        link.symlink_to(self.backup_path)
        result = self.verify(path=link)
        self.assertEqual(result["availability"], "INVALID")

    def test_symlink_parent_is_invalid(self):
        parent_link = self.root / "linked-parent"
        parent_link.symlink_to(self.root, target_is_directory=True)
        result = self.verify(path=parent_link / self.backup_path.name)
        self.assertEqual(result["availability"], "INVALID")

    def test_directory_is_invalid(self):
        result = self.verify(path=self.root)
        self.assertEqual(result["availability"], "INVALID")

    def test_group_or_world_readable_file_is_invalid(self):
        os.chmod(self.backup_path, 0o644)
        result = self.verify()
        self.assertEqual(result["availability"], "INVALID")

    def test_oversized_file_is_invalid(self):
        oversized = self.root / "oversized.sqlite3"
        oversized.write_bytes(b"x" * (1024 * 1024 + 1))
        os.chmod(oversized, 0o600)
        result = self.verify(path=oversized)
        self.assertEqual(result["availability"], "INVALID")

    def test_non_sqlite_file_is_invalid(self):
        self.backup_path.write_bytes(b"not-a-sqlite-database")
        os.chmod(self.backup_path, 0o600)
        result = self.verify()
        self.assertEqual(result["availability"], "INVALID")

    def test_corrupted_backup_hash_chain_is_invalid(self):
        connection = sqlite3.connect(self.backup_path)
        try:
            connection.execute("DROP TRIGGER observer_freshness_receipts_no_update")
            connection.execute(
                "UPDATE observer_freshness_receipts SET record_hash = ? WHERE sequence = 1",
                ("f" * 64,),
            )
            connection.execute(
                "CREATE TRIGGER observer_freshness_receipts_no_update "
                "BEFORE UPDATE ON observer_freshness_receipts "
                "BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_LEDGER_APPEND_ONLY'); END"
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.backup_path, 0o600)
        result = self.verify()
        self.assertEqual(result["availability"], "INVALID")

    def test_valid_but_different_backup_is_a_lineage_mismatch(self):
        self._append_source(2)
        second_path = self.root / "backup-second.sqlite3"
        second_result = create_verified_backup(self.source, second_path)
        self.lineage.append_backup(
            second_result,
            recorded_at=(self.base_at + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        )
        result = self.verify(path=second_path)
        self.assertEqual(result["availability"], "MISMATCH")

    def test_corrupt_lineage_is_rejected_before_file_access(self):
        self.lineage._connection.execute(
            "DROP TRIGGER observer_freshness_backup_receipts_no_update"
        )
        self.lineage._connection.execute(
            "UPDATE observer_freshness_backup_receipts SET record_hash = ? WHERE sequence = 1",
            ("e" * 64,),
        )
        self.lineage._connection.execute(
            "CREATE TRIGGER observer_freshness_backup_receipts_no_update "
            "BEFORE UPDATE ON observer_freshness_backup_receipts "
            "BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_RECEIPT_APPEND_ONLY'); END"
        )
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.verify(path=self.root / "missing.sqlite3")

    def test_get_receipt_returns_only_aggregate_metadata(self):
        result = self.lineage.get_backup_receipt(self.receipt["backup_id"])
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_RECEIPT_FOUND")
        self.assertEqual(result["source_receipt_count"], 1)
        self.assertNotIn("recorded_at", result)
        self.assertNotIn("path", result)

    def test_backup_file_verification_does_not_change_file_metadata(self):
        before = self.backup_path.stat()
        result = self.verify()
        after = self.backup_path.stat()
        self.assertEqual(result["availability"], "AVAILABLE")
        self.assertEqual(
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, stat.S_IMODE(before.st_mode)),
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, stat.S_IMODE(after.st_mode)),
        )

    def test_result_never_contains_caller_path(self):
        result = self.verify()
        self.assertNotIn(str(self.backup_path), repr(result))
        self.assertNotIn(str(self.root), repr(result))

    def test_result_never_authorizes_execution_or_retry(self):
        result = self.verify()
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_invalid_backup_identifier_is_rejected(self):
        with self.assertRaises(ObserverFreshnessBackupAvailabilityError):
            self.verify(backup_id="not-a-backup-id")

    def test_invalid_ledger_object_is_rejected(self):
        with self.assertRaises(ObserverFreshnessBackupAvailabilityError):
            verify_backup_availability(object(), self.receipt["backup_id"], self.backup_path)

    def test_missing_parent_is_reported_as_missing(self):
        result = self.verify(path=self.root / "absent" / "backup.sqlite3")
        self.assertEqual(result["availability"], "MISSING")


if __name__ == "__main__":
    unittest.main()
