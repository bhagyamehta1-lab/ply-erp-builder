from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_set_retention_ledger import (
    BackupSetRetentionLedger,
)
from scripts.enterprise_hq_backup_set_retention_restore_verifier import (
    BackupSetRetentionRestoreEquivalenceError,
    verify_backup_set_retention_restore_equivalence,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
)


class BackupSetRetentionRestoreVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        seed = EvidenceVerificationLedger(str(self.root / "seed.sqlite3"))
        self.seed_snapshot = build_ledger_integrity_snapshot(seed)
        seed.close()

        self.source = BackupSetRetentionLedger(str(self.root / "source.sqlite3"))
        self.ledger_types = ["EvidenceVerificationLedger", "TaskLedger"]
        self._populate(self.source)
        self.evaluated_at = self.now + timedelta(minutes=2)
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)

        self.restored = self._clone(
            self.source, self.root / "restored.sqlite3"
        )
        self.source_snapshot = build_ledger_integrity_snapshot(self.source)
        self.restored_snapshot = build_ledger_integrity_snapshot(self.restored)
        self.assertEqual(self.source_snapshot, self.restored_snapshot)

    def tearDown(self):
        self.source.close()
        self.restored.close()
        self.temp.cleanup()

    def _seal(self, snapshot):
        result = copy.deepcopy(dict(snapshot))
        result.pop("snapshot_digest", None)
        encoded = json.dumps(
            result,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        result["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        return result

    def _snapshot_for_type(self, ledger_type):
        snapshot = copy.deepcopy(self.seed_snapshot)
        snapshot["ledger_type"] = ledger_type
        return self._seal(snapshot)

    def _populate(self, ledger):
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
                "predecessor_backup_id": None,
                "storage_scope": "LOCAL_ONLY",
            }
            snapshot = self._snapshot_for_type(ledger_type)
            ledger.record_backup(entry, snapshot, snapshot, now=created)
        ledger.record_backup_set(
            self.ledger_types, 1, now=created + timedelta(minutes=1)
        )

    def _clone(self, ledger, path):
        destination = sqlite3.connect(path)
        try:
            ledger._connection.backup(destination)
        finally:
            destination.close()
        os.chmod(path, 0o600)
        return BackupSetRetentionLedger(str(path))

    def test_verifies_identical_nonempty_retention_history(self):
        result = verify_backup_set_retention_restore_equivalence(
            self.source_snapshot, self.restored_snapshot
        )
        self.assertEqual(
            result["status"],
            "BACKUP_SET_RETENTION_RESTORE_EQUIVALENCE_VERIFIED",
        )
        self.assertEqual(result["backup_set_count"], 1)
        self.assertEqual(result["retention_evaluation_count"], 1)
        self.assertEqual(result["retention_audit_event_count"], 1)
        self.assertEqual(
            result["source_snapshot_digest"],
            result["restored_snapshot_digest"],
        )

    def test_accepts_empty_retention_history_with_empty_audit_chain(self):
        empty = BackupSetRetentionLedger(str(self.root / "empty.sqlite3"))
        restored = None
        try:
            self._populate(empty)
            restored = self._clone(empty, self.root / "empty-restored.sqlite3")
            source_snapshot = build_ledger_integrity_snapshot(empty)
            restored_snapshot = build_ledger_integrity_snapshot(restored)
            result = verify_backup_set_retention_restore_equivalence(
                source_snapshot, restored_snapshot
            )
            self.assertEqual(result["retention_evaluation_count"], 0)
            self.assertEqual(result["retention_audit_event_count"], 0)
            self.assertIsNone(result["source_retention_audit_head_hash"])
        finally:
            empty.close()
            if restored is not None:
                restored.close()

    def test_rejects_wrong_ledger_type(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["ledger_type"] = "BackupSetRestoreReceiptLedger"
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_LEDGER_TYPE_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_missing_retention_chain_status(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"].pop("backup_set_retention_chain")
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_CHAIN_NOT_VALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_missing_retention_audit_table(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["audit_chains"] = [
            row for row in altered["audit_chains"]
            if row["table"] != "ledger_backup_set_retention_audit_events"
        ]
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_AUDIT_CHAIN_MISSING",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_evaluation_count_audit_count_mismatch(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"][
            "backup_set_retention_evaluation_count"
        ] = 2
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_AUDIT_COUNT_MISMATCH",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_invalid_audit_sequence(self):
        altered = copy.deepcopy(self.source_snapshot)
        for row in altered["audit_chains"]:
            if row["table"] == "ledger_backup_set_retention_audit_events":
                row["last_sequence"] = 2
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_different_retention_audit_head(self):
        altered = copy.deepcopy(self.source_snapshot)
        for row in altered["audit_chains"]:
            if row["table"] == "ledger_backup_set_retention_audit_events":
                row["head_hash"] = "0" * 64
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_HISTORY_MISMATCH",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_additional_restored_retention_evaluation(self):
        self.restored.evaluate_backup_set_retention(
            now=self.evaluated_at + timedelta(minutes=1)
        )
        restored_snapshot = build_ledger_integrity_snapshot(self.restored)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_HISTORY_MISMATCH",
        ):
            verify_backup_set_retention_restore_equivalence(
                self.source_snapshot, restored_snapshot
            )

    def test_rejects_tampered_snapshot_digest(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["snapshot_digest"] = "0" * 64
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_execution_authorization_claim(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["execution_authorized"] = True
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_SNAPSHOT_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_invalid_retention_count_bound(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"][
            "backup_set_retention_evaluation_count"
        ] = 513
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_COUNT_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_rejects_base_backup_set_history_mismatch(self):
        altered = copy.deepcopy(self.source_snapshot)
        altered["verification_summary"]["backup_set_count"] = 2
        altered = self._seal(altered)
        with self.assertRaisesRegex(
            BackupSetRetentionRestoreEquivalenceError,
            "BACKUP_SET_RETENTION_RESTORE_BASE_HISTORY_INVALID",
        ):
            verify_backup_set_retention_restore_equivalence(
                altered, self.restored_snapshot
            )

    def test_result_is_metadata_only_and_non_authorizing(self):
        result = verify_backup_set_retention_restore_equivalence(
            self.source_snapshot, self.restored_snapshot
        )
        for key in (
            "backup_set_id", "backup_set_ids", "member_ids",
            "backup_path", "path", "payload", "evidence",
        ):
            self.assertNotIn(key, result)
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["automatic_retry"])
        self.assertFalse(result["automatic_purge"])
        self.assertFalse(result["artifact_bytes_verified"])


if __name__ == "__main__":
    unittest.main()
