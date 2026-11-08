from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

import scripts.enterprise_hq_observer_freshness_backup as backup_module
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_observer_freshness import evaluate_observer_freshness
from scripts.enterprise_hq_observer_freshness_backup import (
    ObserverFreshnessBackupError,
    create_verified_backup,
    restore_verified_backup,
    verify_backup_equivalence,
)
from scripts.enterprise_hq_observer_freshness_ledger import ObserverFreshnessLedger


class ObserverFreshnessBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_path = self.root / "source.sqlite3"
        self.backup_path = self.root / "backup.sqlite3"
        self.restore_path = self.root / "restored.sqlite3"
        self.ledger = ObserverFreshnessLedger(str(self.source_path))
        self.base_at = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        if getattr(self, "ledger", None) is not None:
            self.ledger.close()
        self.temp.cleanup()

    def append(self, index=1, age_seconds=900):
        current = self.base_at + timedelta(minutes=index - 1)
        last = current - timedelta(seconds=age_seconds)
        receipt = evaluate_observer_freshness(
            last.isoformat().replace("+00:00", "Z"),
            current.isoformat().replace("+00:00", "Z"),
        )
        key = hashlib.sha256(f"freshness-backup-test-{index}".encode()).hexdigest()
        return self.ledger.append(
            receipt,
            idempotency_key=key,
            recorded_at=current.isoformat().replace("+00:00", "Z"),
        )

    def populate(self, count=2):
        for index in range(1, count + 1):
            self.append(index=index, age_seconds=900 if index % 2 else 2100)

    @staticmethod
    def tamper_record_hash(path):
        connection = sqlite3.connect(path)
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
        os.chmod(path, 0o600)

    def test_backup_of_empty_ledger_is_verified(self):
        result = create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_VERIFIED")
        self.assertEqual(result["receipt_count"], 0)
        self.assertIsNone(result["chain_head_digest"])

    def test_backup_preserves_multiple_receipts(self):
        self.populate(3)
        result = create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(result["receipt_count"], 3)
        self.assertEqual(result["last_sequence"], 3)
        self.assertTrue(result["equivalence_verified"])

    def test_backup_digest_is_sha256(self):
        result = create_verified_backup(self.ledger, self.backup_path)
        self.assertRegex(result["file_sha256"], r"^[a-f0-9]{64}$")

    def test_backup_file_is_owner_only(self):
        create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(stat.S_IMODE(self.backup_path.stat().st_mode), 0o600)

    def test_backup_does_not_change_source_history(self):
        self.populate()
        before = self.ledger.verify()
        create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(self.ledger.verify(), before)

    def test_backup_response_contains_only_aggregate_metadata(self):
        self.append()
        result = create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(
            set(result),
            {
                "status", "file_sha256", "receipt_count", "status_counts",
                "last_sequence", "chain_head_digest", "equivalence_verified",
                "execution_authorized", "automatic_dispatch", "automatic_retry",
            },
        )
        self.assertNotIn("path", result)
        self.assertNotIn("receipt_id", result)
        self.assertNotIn("recorded_at", result)

    def test_backup_equivalence_verifier_accepts_exact_copy(self):
        self.populate()
        create_verified_backup(self.ledger, self.backup_path)
        result = verify_backup_equivalence(self.ledger, self.backup_path)
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_EQUIVALENCE_VERIFIED")

    def test_restore_preserves_multiple_receipts(self):
        self.populate(3)
        create_verified_backup(self.ledger, self.backup_path)
        result = restore_verified_backup(self.backup_path, self.restore_path)
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_RESTORE_VERIFIED")
        self.assertEqual(result["receipt_count"], 3)
        with ObserverFreshnessLedger(str(self.restore_path)) as restored:
            self.assertEqual(restored.verify(), self.ledger.verify())

    def test_restore_of_empty_ledger_is_verified(self):
        create_verified_backup(self.ledger, self.backup_path)
        result = restore_verified_backup(self.backup_path, self.restore_path)
        self.assertEqual(result["receipt_count"], 0)
        self.assertTrue(result["equivalence_verified"])

    def test_restore_file_is_owner_only(self):
        create_verified_backup(self.ledger, self.backup_path)
        restore_verified_backup(self.backup_path, self.restore_path)
        self.assertEqual(stat.S_IMODE(self.restore_path.stat().st_mode), 0o600)

    def test_restore_response_contains_only_aggregate_metadata(self):
        self.append()
        create_verified_backup(self.ledger, self.backup_path)
        result = restore_verified_backup(self.backup_path, self.restore_path)
        self.assertNotIn("path", result)
        self.assertNotIn("receipt_id", result)
        self.assertNotIn("recorded_at", result)

    def test_backup_refuses_existing_destination(self):
        self.backup_path.write_text("existing", encoding="utf-8")
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, self.backup_path)
        self.assertEqual(self.backup_path.read_text(encoding="utf-8"), "existing")

    def test_restore_refuses_existing_destination(self):
        create_verified_backup(self.ledger, self.backup_path)
        self.restore_path.write_text("existing", encoding="utf-8")
        with self.assertRaises(ObserverFreshnessBackupError):
            restore_verified_backup(self.backup_path, self.restore_path)
        self.assertEqual(self.restore_path.read_text(encoding="utf-8"), "existing")

    def test_backup_refuses_symlink_destination(self):
        target = self.root / "target.txt"
        target.write_text("keep", encoding="utf-8")
        link = self.root / "backup-link.sqlite3"
        link.symlink_to(target)
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, link)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_restore_refuses_symlink_destination(self):
        create_verified_backup(self.ledger, self.backup_path)
        target = self.root / "target.txt"
        target.write_text("keep", encoding="utf-8")
        link = self.root / "restore-link.sqlite3"
        link.symlink_to(target)
        with self.assertRaises(ObserverFreshnessBackupError):
            restore_verified_backup(self.backup_path, link)
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_backup_refuses_directory_destination(self):
        directory = self.root / "destination"
        directory.mkdir()
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, directory)

    def test_backup_refuses_missing_parent(self):
        missing = self.root / "missing" / "backup.sqlite3"
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, missing)

    def test_backup_refuses_source_as_destination(self):
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, self.source_path)

    def test_corrupted_source_blocks_backup_without_output(self):
        self.append()
        self.ledger._connection.execute(
            "DROP TRIGGER observer_freshness_receipts_no_update"
        )
        self.ledger._connection.execute(
            "UPDATE observer_freshness_receipts SET record_hash = ? WHERE sequence = 1",
            ("e" * 64,),
        )
        with self.assertRaises(ObserverFreshnessBackupError):
            create_verified_backup(self.ledger, self.backup_path)
        self.assertFalse(self.backup_path.exists())

    def test_corrupted_backup_is_rejected(self):
        self.append()
        create_verified_backup(self.ledger, self.backup_path)
        self.tamper_record_hash(self.backup_path)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_backup_with_missing_append_only_trigger_is_rejected(self):
        create_verified_backup(self.ledger, self.backup_path)
        connection = sqlite3.connect(self.backup_path)
        try:
            connection.execute("DROP TRIGGER observer_freshness_receipts_no_delete")
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.backup_path, 0o600)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_backup_with_wrong_schema_version_is_rejected(self):
        create_verified_backup(self.ledger, self.backup_path)
        connection = sqlite3.connect(self.backup_path)
        try:
            connection.execute("PRAGMA user_version=99")
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.backup_path, 0o600)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_backup_with_extra_table_is_rejected(self):
        create_verified_backup(self.ledger, self.backup_path)
        connection = sqlite3.connect(self.backup_path)
        try:
            connection.execute("CREATE TABLE unexpected(value TEXT)")
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.backup_path, 0o600)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_backup_with_broad_permissions_is_rejected(self):
        create_verified_backup(self.ledger, self.backup_path)
        os.chmod(self.backup_path, 0o644)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_non_sqlite_backup_is_rejected(self):
        invalid = self.root / "invalid.sqlite3"
        invalid.write_bytes(b"not a sqlite database")
        os.chmod(invalid, 0o600)
        with self.assertRaises(ObserverFreshnessBackupError):
            restore_verified_backup(invalid, self.restore_path)

    def test_oversized_backup_is_rejected(self):
        oversized = self.root / "oversized.sqlite3"
        oversized.write_bytes(b"x" * (1024 * 1024 + 1))
        os.chmod(oversized, 0o600)
        with self.assertRaises(ObserverFreshnessBackupError):
            restore_verified_backup(oversized, self.restore_path)

    def test_source_advance_makes_old_backup_non_equivalent(self):
        self.append(1)
        create_verified_backup(self.ledger, self.backup_path)
        self.append(2, 2100)
        with self.assertRaises(ObserverFreshnessBackupError):
            verify_backup_equivalence(self.ledger, self.backup_path)

    def test_backup_and_restore_never_authorize_execution(self):
        self.populate()
        backup = create_verified_backup(self.ledger, self.backup_path)
        restored = restore_verified_backup(self.backup_path, self.restore_path)
        for result in (backup, restored):
            self.assertFalse(result["execution_authorized"])
            self.assertFalse(result["automatic_dispatch"])
            self.assertFalse(result["automatic_retry"])


    def test_backup_destination_is_hidden_until_verification_finishes(self):
        self.populate()
        original_verify = backup_module._verified_summary

        def inspect_temporary(path):
            self.assertFalse(self.backup_path.exists())
            return original_verify(path)

        with patch.object(backup_module, "_verified_summary", side_effect=inspect_temporary):
            result = create_verified_backup(self.ledger, self.backup_path)

        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_VERIFIED")
        self.assertTrue(self.backup_path.is_file())

    def test_interrupted_backup_removes_temporary_file(self):
        original_copy = backup_module._copy_connection

        def interrupt_after_copy(source, destination):
            original_copy(source, destination)
            raise RuntimeError("simulated backup interruption")

        with patch.object(backup_module, "_copy_connection", side_effect=interrupt_after_copy):
            with self.assertRaisesRegex(RuntimeError, "simulated backup interruption"):
                create_verified_backup(self.ledger, self.backup_path)

        self.assertFalse(self.backup_path.exists())
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["source.sqlite3"],
        )

    def test_interrupted_restore_keeps_backup_and_removes_temporary_file(self):
        self.populate()
        create_verified_backup(self.ledger, self.backup_path)
        original_copy = backup_module._copy_connection

        def interrupt_after_copy(source, destination):
            original_copy(source, destination)
            raise RuntimeError("simulated restore interruption")

        with patch.object(backup_module, "_copy_connection", side_effect=interrupt_after_copy):
            with self.assertRaisesRegex(RuntimeError, "simulated restore interruption"):
                restore_verified_backup(self.backup_path, self.restore_path)

        self.assertFalse(self.restore_path.exists())
        self.assertEqual(
            verify_backup_equivalence(self.ledger, self.backup_path)["receipt_count"],
            2,
        )
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["backup.sqlite3", "source.sqlite3"],
        )

    def test_backup_verification_failure_never_publishes_destination(self):
        def fail_verification(path):
            raise ObserverFreshnessBackupError("simulated verification failure")

        with patch.object(backup_module, "_verified_summary", side_effect=fail_verification):
            with self.assertRaisesRegex(ObserverFreshnessBackupError, "simulated verification failure"):
                create_verified_backup(self.ledger, self.backup_path)

        self.assertFalse(self.backup_path.exists())
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["source.sqlite3"],
        )

    def test_backup_publish_race_never_overwrites_competing_destination(self):
        original_copy = backup_module._copy_connection

        def create_competing_destination(source, temporary):
            original_copy(source, temporary)
            self.backup_path.write_bytes(b"concurrent destination")
            os.chmod(self.backup_path, 0o600)

        with patch.object(backup_module, "_copy_connection", side_effect=create_competing_destination):
            with self.assertRaises(ObserverFreshnessBackupError):
                create_verified_backup(self.ledger, self.backup_path)

        self.assertEqual(self.backup_path.read_bytes(), b"concurrent destination")
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["backup.sqlite3", "source.sqlite3"],
        )

    def test_restore_publish_race_never_overwrites_competing_destination(self):
        self.populate()
        create_verified_backup(self.ledger, self.backup_path)
        original_copy = backup_module._copy_connection

        def create_competing_destination(source, temporary):
            original_copy(source, temporary)
            self.restore_path.write_bytes(b"concurrent destination")
            os.chmod(self.restore_path, 0o600)

        with patch.object(backup_module, "_copy_connection", side_effect=create_competing_destination):
            with self.assertRaises(ObserverFreshnessBackupError):
                restore_verified_backup(self.backup_path, self.restore_path)

        self.assertEqual(self.restore_path.read_bytes(), b"concurrent destination")
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["backup.sqlite3", "restored.sqlite3", "source.sqlite3"],
        )

if __name__ == "__main__":
    unittest.main()
