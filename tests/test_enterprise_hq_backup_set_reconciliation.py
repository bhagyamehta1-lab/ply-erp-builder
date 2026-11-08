from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_inventory import BackupInventoryCorruptionError
from scripts.enterprise_hq_backup_set_reconciliation import (
    BackupSetReconciliationCorruptionError,
    BackupSetReconciliationError,
    CrossLedgerBackupSetInventory,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
)


class CrossLedgerBackupSetInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 8, 0, tzinfo=timezone.utc)
        self.source = EvidenceVerificationLedger(str(self.root / "source.sqlite3"))
        self.inventory_path = self.root / "inventory.sqlite3"
        self.inventory = CrossLedgerBackupSetInventory(str(self.inventory_path))
        self.source_snapshot = build_ledger_integrity_snapshot(self.source)
        self.backup_ids = {}
        self.counter = 1

    def tearDown(self):
        self.inventory.close()
        self.source.close()
        self.temp.cleanup()

    def _snapshot_for_type(self, ledger_type):
        snapshot = dict(self.source_snapshot)
        snapshot["ledger_type"] = ledger_type
        snapshot.pop("snapshot_digest")
        canonical = json.dumps(
            snapshot, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        snapshot["snapshot_digest"] = hashlib.sha256(canonical).hexdigest()
        return snapshot

    def _record(
        self,
        ledger_type,
        generation=1,
        *,
        created_at=None,
        retain_until=None,
    ):
        created = created_at or self.now
        retained = retain_until or created + timedelta(days=30)
        backup_id = f"hqbk_{self.counter:024x}"
        self.counter += 1
        predecessor = (
            None if generation == 1
            else self.backup_ids[(ledger_type, generation - 1)]
        )
        source = self._snapshot_for_type(ledger_type)
        restored = dict(source)
        entry = {
            "backup_id": backup_id,
            "ledger_type": ledger_type,
            "declared_size_bytes": 4096,
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "retain_until": retained.isoformat().replace("+00:00", "Z"),
            "generation": generation,
            "predecessor_backup_id": predecessor,
            "storage_scope": "LOCAL_ONLY",
        }
        self.inventory.record_backup(
            entry, source, restored, now=self.now
        )
        self.backup_ids[(ledger_type, generation)] = backup_id
        return backup_id

    def _record_pair(self, generation=1, *, first_time=None, second_time=None):
        first_type = "EvidenceVerificationLedger"
        second_type = "TaskLedger"
        self._record(first_type, generation, created_at=first_time)
        self._record(second_type, generation, created_at=second_time)
        return [first_type, second_type]

    def test_reconciles_complete_two_type_generation(self):
        types = self._record_pair()
        result = self.inventory.record_backup_set(types, 1, now=self.now)
        self.assertEqual(result["status"], "BACKUP_SET_RECONCILED")
        self.assertEqual(result["member_count"], 2)
        self.assertEqual(result["generation"], 1)
        self.assertTrue(result["created"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["artifact_bytes_verified"])

    def test_normalizes_ledger_type_order_without_mutating_input(self):
        types = self._record_pair()
        supplied = list(reversed(types))
        result = self.inventory.record_backup_set(supplied, 1, now=self.now)
        self.assertEqual(supplied, list(reversed(types)))
        self.assertEqual(result["ledger_types"], sorted(types))

    def test_rejects_single_ledger_type(self):
        self._record("EvidenceVerificationLedger")
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_LEDGER_TYPES_INVALID"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger"], 1, now=self.now
            )

    def test_rejects_duplicate_ledger_types(self):
        self._record_pair()
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_LEDGER_TYPES_DUPLICATE"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "EvidenceVerificationLedger"],
                1, now=self.now,
            )

    def test_rejects_invalid_ledger_type(self):
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_LEDGER_TYPE_INVALID"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "../private"], 1, now=self.now
            )

    def test_rejects_missing_member(self):
        self._record("EvidenceVerificationLedger")
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_MEMBER_MISSING"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "TaskLedger"], 1, now=self.now
            )

    def test_rejects_excessive_time_skew(self):
        self._record_pair(
            first_time=self.now - timedelta(minutes=5),
            second_time=self.now,
        )
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_TIME_SKEW_EXCEEDED"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "TaskLedger"],
                1, max_skew_seconds=120, now=self.now,
            )

    def test_rejects_expired_member(self):
        self._record(
            "EvidenceVerificationLedger",
            retain_until=self.now + timedelta(days=1),
        )
        self._record(
            "TaskLedger",
            retain_until=self.now + timedelta(days=1),
        )
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_MEMBER_EXPIRED"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "TaskLedger"],
                1, now=self.now + timedelta(days=2),
            )

    def test_rejects_invalid_skew_limit(self):
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_SKEW_LIMIT_INVALID"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "TaskLedger"],
                1, max_skew_seconds=301, now=self.now,
            )

    def test_generation_two_requires_predecessor_set(self):
        self._record_pair(1)
        self._record_pair(2)
        with self.assertRaisesRegex(
            BackupSetReconciliationError, "BACKUP_SET_PREDECESSOR_SET_MISSING"
        ):
            self.inventory.record_backup_set(
                ["EvidenceVerificationLedger", "TaskLedger"], 2, now=self.now
            )

    def test_generation_two_extends_exact_predecessor_set(self):
        types = self._record_pair(1)
        first = self.inventory.record_backup_set(types, 1, now=self.now)
        self._record_pair(2)
        second = self.inventory.record_backup_set(types, 2, now=self.now)
        self.assertEqual(second["predecessor_set_id"], first["backup_set_id"])
        self.assertEqual(second["generation"], 2)

    def test_identical_set_reconciliation_is_idempotent(self):
        types = self._record_pair()
        first = self.inventory.record_backup_set(types, 1, now=self.now)
        second = self.inventory.record_backup_set(types, 1, now=self.now)
        self.assertTrue(first["created"])
        self.assertTrue(second["already_present"])
        self.assertEqual(first["backup_set_id"], second["backup_set_id"])

    def test_inventory_corruption_blocks_set_reconciliation(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        self.inventory._connection.execute(
            "UPDATE ledger_backup_inventory SET entry_digest = ? "
            "WHERE ledger_type = ?",
            ("0" * 64, "TaskLedger"),
        )
        with self.assertRaises(BackupInventoryCorruptionError):
            self.inventory.record_backup_set(types, 1, now=self.now)

    def test_restart_verifies_backup_set_history(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        self.inventory.close()
        self.inventory = CrossLedgerBackupSetInventory(str(self.inventory_path))
        verified = self.inventory.verify()
        self.assertEqual(verified["backup_set_count"], 1)
        self.assertEqual(verified["backup_set_chain"], "VALID")

    def test_integrity_snapshot_includes_backup_set_audit_chain(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        snapshot = build_ledger_integrity_snapshot(self.inventory)
        tables = {item["table"] for item in snapshot["audit_chains"]}
        self.assertIn("ledger_backup_set_audit_events", tables)

    def test_rejects_corrupted_set_digest(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        self.inventory._connection.execute(
            "UPDATE ledger_backup_sets SET set_digest = ?", ("0" * 64,)
        )
        with self.assertRaisesRegex(
            BackupSetReconciliationCorruptionError, "BACKUP_SET_DIGEST_INVALID"
        ):
            self.inventory.verify()

    def test_rejects_corrupted_set_audit_chain(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        self.inventory._connection.execute(
            "UPDATE ledger_backup_set_audit_events SET record_hash = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupSetReconciliationCorruptionError, "BACKUP_SET_AUDIT_CHAIN_INVALID"
        ):
            self.inventory.verify()

    def test_set_capacity_fails_closed(self):
        types = self._record_pair()
        with patch(
            "scripts.enterprise_hq_backup_set_reconciliation.MAX_BACKUP_SET_RECORDS",
            0,
        ):
            with self.assertRaisesRegex(
                BackupSetReconciliationError, "BACKUP_SET_CAPACITY_REACHED"
            ):
                self.inventory.record_backup_set(types, 1, now=self.now)

    def test_result_contains_no_artifact_path_or_payload(self):
        types = self._record_pair()
        result = self.inventory.record_backup_set(types, 1, now=self.now)
        self.assertNotIn("path", result)
        self.assertNotIn("payload", result)
        self.assertNotIn("backup_ids", result)
        self.assertEqual(result["artifact_presence"], "NOT_INSPECTED")

    def test_recovery_keeps_execution_disabled(self):
        types = self._record_pair()
        self.inventory.record_backup_set(types, 1, now=self.now)
        recovery = self.inventory.recover_after_restart()
        self.assertEqual(recovery["recovery_status"], "PASS")
        self.assertFalse(recovery["execution_authorized"])
        self.assertFalse(recovery["execution_resumed"])
        self.assertFalse(recovery["automatic_retry"])


if __name__ == "__main__":
    unittest.main()
