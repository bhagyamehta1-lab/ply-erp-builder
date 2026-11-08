from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    MAX_BACKUP_RECEIPTS,
    ObserverFreshnessBackupReceiptCorruptionError,
    ObserverFreshnessBackupReceiptError,
    ObserverFreshnessBackupReceiptLedger,
)


class ObserverFreshnessBackupReceiptLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.database = self.root / "backup-receipts.sqlite3"
        self.ledger = ObserverFreshnessBackupReceiptLedger(str(self.database))
        self.base_at = datetime(2026, 11, 9, 0, 0, tzinfo=timezone.utc)

    def tearDown(self):
        if getattr(self, "ledger", None) is not None:
            self.ledger.close()
        self.temp.cleanup()

    def result(self, index=1, *, count=1, status="FRESH"):
        file_sha = hashlib.sha256(f"backup-file-{index}".encode()).hexdigest()
        if count == 0:
            counts, last, head = {}, None, None
        else:
            counts = {status: count}
            last = count
            head = hashlib.sha256(f"source-head-{index}".encode()).hexdigest()
        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_VERIFIED",
            "file_sha256": file_sha,
            "receipt_count": count,
            "status_counts": counts,
            "last_sequence": last,
            "chain_head_digest": head,
            "equivalence_verified": True,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def recorded_at(self, seconds=0):
        return (self.base_at + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

    def append(self, index=1, *, seconds=0, count=1, status="FRESH"):
        return self.ledger.append_backup(
            self.result(index, count=count, status=status),
            recorded_at=self.recorded_at(seconds),
        )

    def test_empty_ledger_verifies(self):
        result = self.ledger.verify()
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_RECEIPT_LEDGER_VALID")
        self.assertEqual(result["backup_count"], 0)
        self.assertIsNone(result["chain_head_digest"])

    def test_records_verified_backup(self):
        result = self.append()
        self.assertEqual(result["status"], "OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED")
        self.assertEqual(result["backup_count"], 1)
        self.assertTrue(result["created"])
        self.assertFalse(result["execution_authorized"])

    def test_backup_id_is_derived_from_file_digest(self):
        result = self.append()
        self.assertEqual(result["backup_id"], "hqfb_" + self.result()["file_sha256"][:24])

    def test_exact_backup_replay_is_idempotent(self):
        first = self.append()
        replay = self.append(seconds=90)
        self.assertEqual(replay["record_hash"], first["record_hash"])
        self.assertTrue(replay["already_present"])
        self.assertFalse(replay["created"])
        self.assertEqual(self.ledger.verify()["backup_count"], 1)

    def test_same_digest_with_changed_metadata_is_rejected(self):
        self.append()
        changed = self.result(count=2)
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(changed, recorded_at=self.recorded_at(1))

    def test_second_backup_links_to_predecessor(self):
        first = self.append(index=1)
        second = self.append(index=2, seconds=1)
        self.assertEqual(second["predecessor_backup_id"], first["backup_id"])
        self.assertEqual(self.ledger.verify()["backup_count"], 2)

    def test_recording_time_must_not_regress(self):
        self.append(seconds=10)
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.append(index=2, seconds=9)

    def test_recording_time_is_normalized_to_utc(self):
        value = self.ledger.append_backup(
            self.result(),
            recorded_at="2026-11-09T05:30:00+05:30",
        )
        self.assertEqual(value["status"], "OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED")

    def test_restart_recovery_verifies_history(self):
        self.append()
        self.ledger.close()
        self.ledger = ObserverFreshnessBackupReceiptLedger(str(self.database))
        result = self.ledger.recover_after_restart()
        self.assertEqual(result["recovery_status"], "PASS")
        self.assertEqual(result["backup_receipts_verified"], 1)
        self.assertFalse(result["automatic_dispatch"])

    def test_recovery_never_authorizes_execution(self):
        self.append()
        result = self.ledger.recover_after_restart()
        self.assertFalse(result["execution_authorized"])
        self.assertFalse(result["automatic_dispatch"])
        self.assertFalse(result["automatic_retry"])

    def test_report_contains_aggregate_metadata_only(self):
        result = self.append()
        forbidden = {"recorded_at", "path", "database", "receipt_json", "private_payload"}
        self.assertTrue(forbidden.isdisjoint(result))
        verified = self.ledger.verify()
        self.assertTrue(forbidden.isdisjoint(verified))

    def test_database_is_owner_only(self):
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)

    def test_update_trigger_rejects_mutation(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "UPDATE observer_freshness_backup_receipts SET receipt_count = 9"
            )

    def test_delete_trigger_rejects_mutation(self):
        self.append()
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "DELETE FROM observer_freshness_backup_receipts"
            )

    def _tamper(self, sql, parameters=()):
        self.ledger.close()
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "DROP TRIGGER observer_freshness_backup_receipts_no_update"
            )
            connection.execute(sql, parameters)
            connection.execute(
                "CREATE TRIGGER observer_freshness_backup_receipts_no_update "
                "BEFORE UPDATE ON observer_freshness_backup_receipts "
                "BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_RECEIPT_APPEND_ONLY'); END"
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(self.database, 0o600)
        self.ledger = ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_detects_record_hash_tampering(self):
        self.append()
        self._tamper(
            "UPDATE observer_freshness_backup_receipts SET record_hash = ? WHERE sequence = 1",
            ("f" * 64,),
        )
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.ledger.verify()

    def test_detects_predecessor_tampering(self):
        self.append(index=1)
        self.append(index=2, seconds=1)
        self._tamper(
            "UPDATE observer_freshness_backup_receipts SET predecessor_backup_id = ? WHERE sequence = 2",
            ("hqfb_" + "a" * 24,),
        )
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.ledger.verify()

    def test_append_refuses_corrupted_history(self):
        self.append()
        self._tamper(
            "UPDATE observer_freshness_backup_receipts SET record_hash = ? WHERE sequence = 1",
            ("e" * 64,),
        )
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            self.append(index=2, seconds=1)

    def test_reopen_rejects_missing_append_only_trigger(self):
        self.ledger.close()
        connection = sqlite3.connect(self.database)
        connection.execute("DROP TRIGGER observer_freshness_backup_receipts_no_delete")
        connection.commit()
        connection.close()
        os.chmod(self.database, 0o600)
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_reopen_rejects_unexpected_table(self):
        self.ledger.close()
        connection = sqlite3.connect(self.database)
        connection.execute("CREATE TABLE unexpected(value TEXT)")
        connection.commit()
        connection.close()
        os.chmod(self.database, 0o600)
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_reopen_rejects_wrong_schema_version(self):
        self.ledger.close()
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA user_version=2")
        connection.commit()
        connection.close()
        os.chmod(self.database, 0o600)
        with self.assertRaises(ObserverFreshnessBackupReceiptCorruptionError):
            ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_rejects_symlink_database(self):
        self.ledger.close()
        link = self.root / "linked.sqlite3"
        link.symlink_to(self.database)
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            ObserverFreshnessBackupReceiptLedger(str(link))
        self.ledger = ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_rejects_oversized_database(self):
        self.ledger.close()
        large = self.root / "large.sqlite3"
        large.write_bytes(b"x" * (1024 * 1024 + 1))
        os.chmod(large, 0o600)
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            ObserverFreshnessBackupReceiptLedger(str(large))
        self.ledger = ObserverFreshnessBackupReceiptLedger(str(self.database))

    def test_rejects_unknown_result_field(self):
        result = self.result()
        result["path"] = "/private/path"
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_unverified_backup_status(self):
        result = self.result()
        result["status"] = "OBSERVER_FRESHNESS_BACKUP_FAILED"
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_invalid_file_digest(self):
        result = self.result()
        result["file_sha256"] = "x" * 64
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_boolean_receipt_count(self):
        result = self.result()
        result["receipt_count"] = True
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_status_count_mismatch(self):
        result = self.result()
        result["status_counts"] = {"FRESH": 2}
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_invalid_empty_summary(self):
        result = self.result(count=0)
        result["status_counts"] = {"FRESH": 1}
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_missing_chain_head(self):
        result = self.result()
        result["chain_head_digest"] = None
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_unknown_freshness_status(self):
        result = self.result(status="UNRECOGNIZED")
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_authority_escalation(self):
        result = self.result()
        result["automatic_dispatch"] = True
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_non_equivalent_backup(self):
        result = self.result()
        result["equivalence_verified"] = False
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(result, recorded_at=self.recorded_at())

    def test_rejects_naive_recording_time(self):
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.ledger.append_backup(self.result(), recorded_at="2026-11-09T00:00:00")

    def test_capacity_is_bounded(self):
        for index in range(1, MAX_BACKUP_RECEIPTS + 1):
            self.append(index=index)
        with self.assertRaises(ObserverFreshnessBackupReceiptError):
            self.append(index=MAX_BACKUP_RECEIPTS + 1)
        self.assertEqual(self.ledger.verify()["backup_count"], MAX_BACKUP_RECEIPTS)


if __name__ == "__main__":
    unittest.main()
