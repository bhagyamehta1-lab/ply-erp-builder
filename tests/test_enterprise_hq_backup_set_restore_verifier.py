from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_set_reconciliation import (
    CrossLedgerBackupSetInventory,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
)
from scripts.enterprise_hq_backup_set_restore_verifier import (
    BackupSetRestoreEquivalenceError,
    verify_backup_set_restore_equivalence,
)


class BackupSetRestoreEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        seed = EvidenceVerificationLedger(str(self.root / "seed.sqlite3"))
        self.seed_snapshot = build_ledger_integrity_snapshot(seed)
        seed.close()
        self.source = CrossLedgerBackupSetInventory(
            str(self.root / "source.sqlite3")
        )
        self.restored = CrossLedgerBackupSetInventory(
            str(self.root / "restored.sqlite3")
        )
        self.ledger_types = ["EvidenceVerificationLedger", "TaskLedger"]
        self._populate(self.source, generations=1)
        self._populate(self.restored, generations=1)
        self.source_snapshot = build_ledger_integrity_snapshot(self.source)
        self.restored_snapshot = build_ledger_integrity_snapshot(self.restored)

    def tearDown(self):
        self.source.close()
        self.restored.close()
        self.temp.cleanup()

    def _seal(self, snapshot):
        result = copy.deepcopy(dict(snapshot))
        result.pop("snapshot_digest", None)
        encoded = json.dumps(
            result, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        ).encode("utf-8")
        result["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        return result

    def _snapshot_for_type(self, ledger_type):
        snapshot = copy.deepcopy(self.seed_snapshot)
        snapshot["ledger_type"] = ledger_type
        return self._seal(snapshot)

    def _populate(self, inventory, *, generations):
        previous = {}
        for generation in range(1, generations + 1):
            created = self.now + timedelta(days=generation - 1)
            for ledger_type in self.ledger_types:
                backup_id = "hqbk_" + hashlib.sha256(
                    f"{ledger_type}:{generation}".encode("utf-8")
                ).hexdigest()[:24]
                entry = {
                    "backup_id": backup_id,
                    "ledger_type": ledger_type,
                    "declared_size_bytes": 4096,
                    "created_at": created.isoformat().replace("+00:00", "Z"),
                    "retain_until": (created + timedelta(days=30)).isoformat().replace(
                        "+00:00", "Z"
                    ),
                    "generation": generation,
                    "predecessor_backup_id": previous.get(ledger_type),
                    "storage_scope": "LOCAL_ONLY",
                }
                snapshot = self._snapshot_for_type(ledger_type)
                inventory.record_backup(
                    entry, snapshot, snapshot, now=created
                )
                previous[ledger_type] = backup_id
            inventory.record_backup_set(
                self.ledger_types,
                generation,
                now=created + timedelta(minutes=1),
            )

    def test_verifies_identical_nonempty_backup_set_history(self):
        result = verify_backup_set_restore_equivalence(
            self.source_snapshot, self.restored_snapshot
        )
        self.assertEqual(
            result["status"], "BACKUP_SET_RESTORE_EQUIVALENCE_VERIFIED"
        )
        self.assertEqual(result["backup_set_count"], 1)
        self.assertEqual(result["backup_set_audit_event_count"], 1)
        self.assertEqual(
            result["source_snapshot_digest"],
            result["restored_snapshot_digest"],
        )

    def test_rejects_empty_backup_set_history(self):
        empty = CrossLedgerBackupSetInventory(
            str(self.root / "empty.sqlite3")
        )
        try:
            snapshot = build_ledger_integrity_snapshot(empty)
            with self.assertRaisesRegex(
                BackupSetRestoreEquivalenceError,
                "BACKUP_SET_RESTORE_HISTORY_COUNT_INVALID",
            ):
                verify_backup_set_restore_equivalence(snapshot, snapshot)
        finally:
            empty.close()

    def test_rejects_wrong_ledger_type(self):
        wrong = self._snapshot_for_type("EvidenceVerificationLedger")
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_LEDGER_TYPE_INVALID",
        ):
            verify_backup_set_restore_equivalence(
                wrong, self.restored_snapshot
            )

    def test_rejects_missing_backup_set_chain_status(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"].pop("backup_set_chain")
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_HISTORY_NOT_VALID",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_missing_backup_set_audit_table(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["audit_chains"] = [
            chain for chain in altered["audit_chains"]
            if chain["table"] != "ledger_backup_set_audit_events"
        ]
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_AUDIT_CHAIN_MISSING",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_backup_set_count_audit_mismatch(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"]["backup_set_count"] = 2
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_AUDIT_COUNT_MISMATCH",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_history_above_bound(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"]["backup_set_count"] = 129
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_HISTORY_COUNT_INVALID",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_tampered_snapshot_digest(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["snapshot_digest"] = "0" * 64
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_execution_authorization_claim(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["execution_authorized"] = True
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_different_restored_generation_history(self):
        self._populate(self.restored, generations=2)
        self.restored_snapshot = build_ledger_integrity_snapshot(self.restored)
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_HISTORY_MISMATCH|BACKUP_SET_RESTORE_SNAPSHOT_MISMATCH",
        ):
            verify_backup_set_restore_equivalence(
                self.source_snapshot, self.restored_snapshot
            )

    def test_rejects_invalid_snapshot_type(self):
        with self.assertRaisesRegex(
            BackupSetRestoreEquivalenceError,
            "BACKUP_SET_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_restore_equivalence(
                None, self.restored_snapshot
            )

    def test_result_is_metadata_only_and_non_authorizing(self):
        result = verify_backup_set_restore_equivalence(
            self.source_snapshot, self.restored_snapshot
        )
        self.assertNotIn("backup_set_id", result)
        self.assertNotIn("backup_ids", result)
        self.assertNotIn("path", result)
        self.assertNotIn("payload", result)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["automatic_retry"])


if __name__ == "__main__":
    unittest.main()
