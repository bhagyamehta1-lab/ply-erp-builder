from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_set_reconciliation import (
    CrossLedgerBackupSetInventory,
)
from scripts.enterprise_hq_backup_set_restore_ledger import (
    BackupSetRestoreReceiptCorruptionError,
    BackupSetRestoreReceiptError,
    BackupSetRestoreReceiptLedger,
    verify_backup_set_restore_equivalence,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
)


class BackupSetRestoreReceiptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        seed = EvidenceVerificationLedger(str(self.root / "seed.sqlite3"))
        self.seed_snapshot = build_ledger_integrity_snapshot(seed)
        seed.close()
        self.source = BackupSetRestoreReceiptLedger(
            str(self.root / "source.sqlite3")
        )
        self.ledger_types = ["EvidenceVerificationLedger", "TaskLedger"]
        self._populate(self.source)
        restored_path = self.root / "restored.sqlite3"
        restored_connection = sqlite3.connect(restored_path)
        try:
            self.source._connection.backup(restored_connection)
        finally:
            restored_connection.close()
        os.chmod(restored_path, 0o600)
        self.restored = BackupSetRestoreReceiptLedger(str(restored_path))
        self.source_snapshot = build_ledger_integrity_snapshot(self.source)
        self.restored_snapshot = build_ledger_integrity_snapshot(self.restored)
        self.assertEqual(self.source_snapshot, self.restored_snapshot)
        self.verified_at = self.now + timedelta(minutes=2)

    def tearDown(self):
        self.source.close()
        self.restored.close()
        self.temp.cleanup()

    def _snapshot_for_type(self, ledger_type):
        snapshot = copy.deepcopy(self.seed_snapshot)
        snapshot["ledger_type"] = ledger_type
        snapshot.pop("snapshot_digest", None)
        encoded = json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        snapshot["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        return snapshot

    def _populate(self, inventory):
        previous = {}
        created = self.now
        for ledger_type in self.ledger_types:
            backup_id = "hqbk_" + hashlib.sha256(
                f"{ledger_type}:1".encode("utf-8")
            ).hexdigest()[:24]
            entry = {
                "backup_id": backup_id,
                "ledger_type": ledger_type,
                "declared_size_bytes": 4096,
                "created_at": created.isoformat().replace("+00:00", "Z"),
                "retain_until": (created + timedelta(days=30)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "generation": 1,
                "predecessor_backup_id": previous.get(ledger_type),
                "storage_scope": "LOCAL_ONLY",
            }
            snapshot = self._snapshot_for_type(ledger_type)
            inventory.record_backup(entry, snapshot, snapshot, now=created)
            previous[ledger_type] = backup_id
        inventory.record_backup_set(
            self.ledger_types, 1, now=created + timedelta(minutes=1)
        )

    def test_records_verified_receipt(self):
        result = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.assertEqual(result["status"], "BACKUP_SET_RESTORE_RECEIPT_RECORDED")
        self.assertTrue(result["created"])
        self.assertEqual(result["backup_set_count"], 1)
        self.assertEqual(result["audit_event_count"], 1)
        self.assertEqual(
            self.source.verify()["backup_set_restore_receipt_chain"], "VALID"
        )

    def test_identical_submission_is_idempotent(self):
        first = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        second = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.assertEqual(first["receipt_id"], second["receipt_id"])
        self.assertFalse(second["created"])
        self.assertTrue(second["already_present"])
        self.assertEqual(
            self.source.verify()["backup_set_restore_receipt_count"], 1
        )

    def test_distinct_verification_time_creates_new_receipt(self):
        first = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        second = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot,
            now=self.verified_at + timedelta(minutes=1),
        )
        self.assertNotEqual(first["receipt_id"], second["receipt_id"])
        self.assertEqual(
            self.source.verify()["backup_set_restore_receipt_count"], 2
        )

    def test_rejects_mismatched_restored_snapshot(self):
        changed = copy.deepcopy(self.restored_snapshot)
        changed["verification_summary"]["backup_set_count"] = 2
        changed.pop("snapshot_digest", None)
        changed["snapshot_digest"] = hashlib.sha256(
            json.dumps(
                changed, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaises(ValueError):
            self.source.record_restore_verification(
                self.source_snapshot, changed, now=self.verified_at
            )
        self.assertEqual(
            self.source.verify()["backup_set_restore_receipt_count"], 0
        )

    def test_receipt_output_is_metadata_only_and_non_authorizing(self):
        result = self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.assertNotIn("backup_set_id", result)
        self.assertNotIn("backup_ids", result)
        self.assertNotIn("path", result)
        self.assertNotIn("payload", result)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["automatic_retry"])

    def test_restart_verifies_receipt_and_audit_history(self):
        self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.source.close()
        self.source = BackupSetRestoreReceiptLedger(
            str(self.root / "source.sqlite3")
        )
        report = self.source.verify()
        self.assertEqual(report["backup_set_restore_receipt_count"], 1)
        self.assertEqual(report["backup_set_restore_receipt_chain"], "VALID")

    def test_rejects_receipt_digest_corruption(self):
        self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.source._connection.execute(
            "UPDATE ledger_backup_set_restore_receipts "
            "SET receipt_digest = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupSetRestoreReceiptCorruptionError,
            "BACKUP_SET_RESTORE_RECEIPT_DIGEST_INVALID",
        ):
            self.source.verify()

    def test_rejects_audit_hash_corruption(self):
        self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.source._connection.execute(
            "UPDATE ledger_backup_set_restore_audit_events "
            "SET record_hash = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupSetRestoreReceiptCorruptionError,
            "BACKUP_SET_RESTORE_AUDIT_CHAIN_INVALID",
        ):
            self.source.verify()

    def test_rejects_missing_audit_event(self):
        self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        self.source._connection.execute(
            "DELETE FROM ledger_backup_set_restore_audit_events"
        )
        with self.assertRaisesRegex(
            BackupSetRestoreReceiptCorruptionError,
            "BACKUP_SET_RESTORE_AUDIT_COUNT_MISMATCH",
        ):
            self.source.verify()

    def test_capacity_fails_closed(self):
        self.source.record_restore_verification(
            self.source_snapshot, self.restored_snapshot, now=self.verified_at
        )
        with patch(
            "scripts.enterprise_hq_backup_set_restore_ledger.MAX_BACKUP_SET_RESTORE_RECEIPTS",
            1,
        ):
            with self.assertRaisesRegex(
                BackupSetRestoreReceiptError,
                "BACKUP_SET_RESTORE_RECEIPT_CAPACITY_REACHED",
            ):
                self.source.record_restore_verification(
                    self.source_snapshot, self.restored_snapshot,
                    now=self.verified_at + timedelta(minutes=1),
                )

    def test_concurrent_identical_submissions_are_idempotent(self):
        database = str(self.root / "source.sqlite3")

        def submit(_):
            ledger = BackupSetRestoreReceiptLedger(database)
            try:
                return ledger.record_restore_verification(
                    self.source_snapshot, self.restored_snapshot,
                    now=self.verified_at,
                )
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, range(2)))
        self.assertEqual(results[0]["receipt_id"], results[1]["receipt_id"])
        self.assertEqual(sum(bool(item["created"]) for item in results), 1)
        self.assertEqual(
            self.source.verify()["backup_set_restore_receipt_count"], 1
        )

    def test_rejects_naive_clock(self):
        with self.assertRaisesRegex(
            BackupSetRestoreReceiptError,
            "BACKUP_INVENTORY_CLOCK_INVALID",
        ):
            self.source.record_restore_verification(
                self.source_snapshot, self.restored_snapshot,
                now=datetime(2026, 11, 8, 9, 2),
            )


if __name__ == "__main__":
    unittest.main()
