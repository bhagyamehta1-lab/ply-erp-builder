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

from scripts.enterprise_hq_backup_set_retention_ledger import (
    BackupSetRetentionCorruptionError,
    BackupSetRetentionError,
    BackupSetRetentionLedger,
)
from scripts.enterprise_hq_backup_set_restore_verifier import (
    verify_backup_set_restore_equivalence,
)
from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_integrity_snapshot import (
    build_ledger_integrity_snapshot,
    verify_ledger_integrity_snapshot,
)


class BackupSetRetentionLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        seed = EvidenceVerificationLedger(str(self.root / "seed.sqlite3"))
        self.seed_snapshot = build_ledger_integrity_snapshot(seed)
        seed.close()
        self.source = BackupSetRetentionLedger(str(self.root / "source.sqlite3"))
        self.ledger_types = ["EvidenceVerificationLedger", "TaskLedger"]
        self._populate(
            self.source,
            {
                "EvidenceVerificationLedger": 10,
                "TaskLedger": 30,
            },
        )
        restored_path = self.root / "restored.sqlite3"
        restored_connection = sqlite3.connect(restored_path)
        try:
            self.source._connection.backup(restored_connection)
        finally:
            restored_connection.close()
        os.chmod(restored_path, 0o600)
        self.restored = BackupSetRetentionLedger(str(restored_path))
        self.source_snapshot = build_ledger_integrity_snapshot(self.source)
        self.restored_snapshot = build_ledger_integrity_snapshot(self.restored)
        self.assertEqual(self.source_snapshot, self.restored_snapshot)
        self.evaluated_at = self.now + timedelta(minutes=2)

    def tearDown(self):
        self.source.close()
        self.restored.close()
        self.temp.cleanup()

    def _snapshot_for_type(self, ledger_type):
        snapshot = copy.deepcopy(self.seed_snapshot)
        snapshot["ledger_type"] = ledger_type
        snapshot.pop("snapshot_digest", None)
        encoded = json.dumps(
            snapshot,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        snapshot["snapshot_digest"] = hashlib.sha256(encoded).hexdigest()
        return snapshot

    def _populate(self, ledger, retention_days):
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
                "retain_until": (
                    created + timedelta(days=retention_days[ledger_type])
                ).isoformat().replace("+00:00", "Z"),
                "generation": 1,
                "predecessor_backup_id": None,
                "storage_scope": "LOCAL_ONLY",
            }
            snapshot = self._snapshot_for_type(ledger_type)
            ledger.record_backup(entry, snapshot, snapshot, now=created)
        ledger.record_backup_set(
            self.ledger_types, 1, now=created + timedelta(minutes=1)
        )

    def test_evaluates_retained_set_and_all_members(self):
        result = self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.assertEqual(result["status"], "BACKUP_SET_RETENTION_EVALUATED")
        self.assertEqual(result["backup_set_count"], 1)
        self.assertEqual(result["retained_set_count"], 1)
        self.assertEqual(result["expired_set_count"], 0)
        self.assertEqual(result["partially_expired_set_count"], 0)
        self.assertEqual(result["member_count"], 2)
        self.assertEqual(result["retained_member_count"], 2)
        self.assertEqual(result["expired_member_count"], 0)

    def test_any_expired_member_expires_the_complete_set(self):
        result = self.source.evaluate_backup_set_retention(
            now=self.now + timedelta(days=15)
        )
        self.assertEqual(result["retained_set_count"], 0)
        self.assertEqual(result["expired_set_count"], 1)
        self.assertEqual(result["partially_expired_set_count"], 1)
        self.assertEqual(result["retained_member_count"], 1)
        self.assertEqual(result["expired_member_count"], 1)

    def test_all_expired_members_expire_set_without_partial_flag(self):
        result = self.source.evaluate_backup_set_retention(
            now=self.now + timedelta(days=31)
        )
        self.assertEqual(result["expired_set_count"], 1)
        self.assertEqual(result["partially_expired_set_count"], 0)
        self.assertEqual(result["expired_member_count"], 2)

    def test_empty_inventory_is_evaluated_without_failure(self):
        empty = BackupSetRetentionLedger(str(self.root / "empty.sqlite3"))
        try:
            result = empty.evaluate_backup_set_retention(now=self.evaluated_at)
            self.assertEqual(result["backup_set_count"], 0)
            self.assertEqual(result["retained_set_count"], 0)
            self.assertEqual(result["expired_set_count"], 0)
            self.assertEqual(result["member_count"], 0)
            self.assertEqual(empty.verify()["backup_set_retention_chain"], "VALID")
        finally:
            empty.close()

    def test_identical_evaluation_is_idempotent(self):
        first = self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        second = self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.assertEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertTrue(second["already_present"])
        self.assertFalse(second["created"])
        self.assertEqual(
            self.source.verify()["backup_set_retention_evaluation_count"], 1
        )

    def test_distinct_evaluation_time_creates_new_history(self):
        first = self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        second = self.source.evaluate_backup_set_retention(
            now=self.evaluated_at + timedelta(minutes=1)
        )
        self.assertNotEqual(first["evaluation_id"], second["evaluation_id"])
        self.assertEqual(
            self.source.verify()["backup_set_retention_evaluation_count"], 2
        )

    def test_rejects_clock_rollback(self):
        self.source.evaluate_backup_set_retention(
            now=self.evaluated_at + timedelta(minutes=1)
        )
        with self.assertRaisesRegex(
            BackupSetRetentionError,
            "BACKUP_SET_RETENTION_CLOCK_ROLLBACK",
        ):
            self.source.evaluate_backup_set_retention(now=self.evaluated_at)

    def test_restart_verifies_retention_history(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.source.close()
        self.source = BackupSetRetentionLedger(str(self.root / "source.sqlite3"))
        report = self.source.verify()
        self.assertEqual(report["backup_set_retention_evaluation_count"], 1)
        self.assertEqual(report["backup_set_retention_audit_event_count"], 1)
        self.assertEqual(report["backup_set_retention_chain"], "VALID")
        recovered = self.source.recover_after_restart()
        self.assertEqual(recovered["recovery_status"], "PASS")
        self.assertEqual(recovered["backup_set_retention_evaluations_recovered"], 1)

    def test_rejects_evaluation_digest_corruption(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.source._connection.execute(
            "UPDATE ledger_backup_set_retention_evaluations "
            "SET evaluation_digest = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupSetRetentionCorruptionError,
            "BACKUP_SET_RETENTION_EVALUATION_DIGEST_INVALID",
        ):
            self.source.verify()

    def test_rejects_audit_hash_corruption(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.source._connection.execute(
            "UPDATE ledger_backup_set_retention_audit_events SET record_hash = ?",
            ("0" * 64,),
        )
        with self.assertRaisesRegex(
            BackupSetRetentionCorruptionError,
            "BACKUP_SET_RETENTION_AUDIT_CHAIN_INVALID",
        ):
            self.source.verify()

    def test_rejects_missing_audit_event(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        self.source._connection.execute(
            "DELETE FROM ledger_backup_set_retention_audit_events"
        )
        with self.assertRaisesRegex(
            BackupSetRetentionCorruptionError,
            "BACKUP_SET_RETENTION_AUDIT_COUNT_MISMATCH",
        ):
            self.source.verify()

    def test_capacity_fails_closed(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        with patch(
            "scripts.enterprise_hq_backup_set_retention_ledger."
            "MAX_BACKUP_SET_RETENTION_EVALUATIONS",
            1,
        ):
            with self.assertRaisesRegex(
                BackupSetRetentionError,
                "BACKUP_SET_RETENTION_CAPACITY_REACHED",
            ):
                self.source.evaluate_backup_set_retention(
                    now=self.evaluated_at + timedelta(minutes=1)
                )

    def test_concurrent_identical_evaluations_are_idempotent(self):
        database = str(self.root / "source.sqlite3")

        def submit(_):
            ledger = BackupSetRetentionLedger(database)
            try:
                return ledger.evaluate_backup_set_retention(now=self.evaluated_at)
            finally:
                ledger.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, range(2)))
        self.assertEqual(results[0]["evaluation_id"], results[1]["evaluation_id"])
        self.assertEqual(sum(bool(item["created"]) for item in results), 1)
        self.assertEqual(
            self.source.verify()["backup_set_retention_evaluation_count"], 1
        )

    def test_result_is_metadata_only_and_never_deletes(self):
        before = self.source._connection.execute(
            "SELECT COUNT(*) FROM ledger_backup_sets"
        ).fetchone()[0]
        result = self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        after = self.source._connection.execute(
            "SELECT COUNT(*) FROM ledger_backup_sets"
        ).fetchone()[0]
        self.assertEqual(before, after)
        for key in ("backup_set_id", "backup_set_ids", "member_ids", "path", "payload"):
            self.assertNotIn(key, result)
        self.assertFalse(result["automatic_purge"])
        self.assertEqual(result["records_deleted"], 0)
        self.assertFalse(result["artifact_bytes_verified"])
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["execution_resumed"])
        self.assertFalse(result["automatic_retry"])

    def test_integrity_snapshot_includes_retention_audit_chain(self):
        self.source.evaluate_backup_set_retention(now=self.evaluated_at)
        snapshot = build_ledger_integrity_snapshot(self.source)
        verified = verify_ledger_integrity_snapshot(snapshot)
        self.assertEqual(verified["status"], "CHECKPOINT_INTEGRITY_VALID")
        self.assertEqual(
            snapshot["verification_summary"]["backup_set_retention_evaluation_count"],
            1,
        )
        names = {row["table"] for row in snapshot["audit_chains"]}
        self.assertIn("ledger_backup_set_retention_audit_events", names)

    def test_restore_verifier_accepts_retention_ledger_subclass(self):
        result = verify_backup_set_restore_equivalence(
            self.source_snapshot, self.restored_snapshot
        )
        self.assertEqual(result["status"], "BACKUP_SET_RESTORE_EQUIVALENCE_VERIFIED")
        self.assertEqual(result["backup_set_count"], 1)
        self.assertFalse(result["execution_authorized"])

    def test_rejects_corrupted_inherited_backup_set_history(self):
        self.source._connection.execute(
            "UPDATE ledger_backup_sets SET set_digest = ?",
            ("0" * 64,),
        )
        with self.assertRaises(Exception):
            self.source.evaluate_backup_set_retention(now=self.evaluated_at)

    def test_rejects_naive_clock(self):
        with self.assertRaisesRegex(
            BackupSetRetentionError,
            "BACKUP_INVENTORY_CLOCK_INVALID",
        ):
            self.source.evaluate_backup_set_retention(
                now=datetime(2026, 11, 8, 9, 2)
            )


if __name__ == "__main__":
    unittest.main()
