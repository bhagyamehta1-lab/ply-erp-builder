from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_recovery_readiness_interruption import (
    reconcile_interrupted_backup_recovery_readiness_evaluation,
)
from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
    BackupRecoveryReadinessLedgerCorruptionError,
)


def ready_report():
    return {
        "status": "BACKUP_RECOVERY_READINESS_REPORTED",
        "metadata_readiness": "READY",
        "readiness_scope": "METADATA_ONLY",
        "blocker_codes": [],
        "inventory_record_count": 1,
        "observer_backup_count": 1,
        "binding_receipt_count": 1,
        "availability_observation_count": 1,
        "predecessor_link_count": 0,
        "predecessor_available_count": 0,
        "association_coverage": "COMPLETE",
        "availability_reconciliation_status": "RECONCILED",
        "predecessor_availability_status": "NOT_APPLICABLE",
        "recovery_chain_status": "COMPLETE",
        "source_snapshot_stable": True,
        "source_ledger_verification_count": 4,
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


class _FaultingConnection:
    """Inject one deterministic SQLite failure at a selected write boundary."""

    def __init__(self, connection, fault):
        self._connection = connection
        self.fault = fault
        self.fired = False

    def execute(self, sql, parameters=()):
        normalized = " ".join(sql.split()).lower()
        is_record_insert = normalized.startswith(
            "insert into ledger_backup_recovery_readiness_records"
        )
        is_state_update = normalized.startswith(
            "update ledger_backup_recovery_readiness_state"
        )
        if self.fault == "before_record_insert" and is_record_insert:
            self.fired = True
            raise sqlite3.OperationalError("synthetic failure before record insert")

        cursor = self._connection.execute(sql, parameters)
        if self.fault == "after_record_insert" and is_record_insert:
            self.fired = True
            raise sqlite3.OperationalError("synthetic failure after record insert")
        if self.fault == "after_checkpoint_update" and is_state_update:
            self.fired = True
            raise sqlite3.OperationalError("synthetic failure after checkpoint update")
        return cursor

    def commit(self):
        if self.fault == "before_commit":
            self.fired = True
            raise sqlite3.OperationalError("synthetic failure before commit")
        if self.fault == "commit_ack_lost":
            self._connection.commit()
            self.fired = True
            raise sqlite3.OperationalError("synthetic lost commit acknowledgement")
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def __getattr__(self, name):
        return getattr(self._connection, name)


class ExistingHistoryCrashPointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.base_time = datetime(2026, 11, 9, 18, 0, tzinfo=timezone.utc)
        self.target_time = self.base_time + timedelta(minutes=2)
        with BackupRecoveryReadinessLedger(self.database) as history:
            history.record_readiness_report(copy.deepcopy(ready_report()), now=self.base_time)
            history.record_readiness_report(
                copy.deepcopy(ready_report()),
                now=self.base_time + timedelta(minutes=1),
            )
            self.baseline = history.verify()
        self.assertEqual(self.baseline["record_count"], 2)
        self.assertEqual(self.baseline["last_sequence"], 2)

    def tearDown(self):
        self.temp.cleanup()

    def _inject(self, fault):
        with BackupRecoveryReadinessLedger(self.database) as history:
            proxy = _FaultingConnection(history._connection, fault)
            history._connection = proxy
            with self.assertRaises(sqlite3.OperationalError):
                history.record_readiness_report(
                    copy.deepcopy(ready_report()), now=self.target_time
                )
            self.assertTrue(proxy.fired)

    def _assert_prior_history_preserved(self):
        result = reconcile_interrupted_backup_recovery_readiness_evaluation(
            self.database, ready_report(), now=self.target_time
        )
        self.assertEqual(result["outcome"], "NOT_COMMITTED")
        self.assertFalse(result["evaluation_present"])
        self.assertEqual(result["evaluation_count"], 2)
        self.assertIsNone(result["sequence"])
        self.assertEqual(result["chain_head_hash"], self.baseline["chain_head_hash"])
        self.assertEqual(result["transition_count"], 1)
        self.assertFalse(result["automatic_retry"])

        with BackupRecoveryReadinessLedger(
            self.database, read_only=True
        ) as history:
            verification = history.verify()
        self.assertEqual(verification["record_count"], 2)
        self.assertEqual(verification["last_sequence"], 2)
        self.assertEqual(verification["ready_count"], 2)
        self.assertEqual(verification["chain_head_hash"], self.baseline["chain_head_hash"])

    def test_failure_before_insert_preserves_existing_history(self):
        self._inject("before_record_insert")
        self._assert_prior_history_preserved()

    def test_failure_after_insert_preserves_existing_history_and_checkpoint(self):
        self._inject("after_record_insert")
        self._assert_prior_history_preserved()

    def test_failure_after_checkpoint_update_preserves_existing_history(self):
        self._inject("after_checkpoint_update")
        self._assert_prior_history_preserved()

    def test_commit_failure_preserves_existing_history(self):
        self._inject("before_commit")
        self._assert_prior_history_preserved()

    def test_lost_commit_acknowledgement_adds_exactly_one_record(self):
        self._inject("commit_ack_lost")
        result = reconcile_interrupted_backup_recovery_readiness_evaluation(
            self.database, ready_report(), now=self.target_time
        )
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertTrue(result["evaluation_present"])
        self.assertEqual(result["evaluation_count"], 3)
        self.assertEqual(result["sequence"], 3)
        self.assertNotEqual(result["chain_head_hash"], self.baseline["chain_head_hash"])
        self.assertEqual(result["transition_count"], 2)
        self.assertFalse(result["automatic_retry"])

        with BackupRecoveryReadinessLedger(self.database) as history:
            replay = history.record_readiness_report(
                copy.deepcopy(ready_report()), now=self.target_time
            )
        self.assertTrue(replay["already_present"])
        self.assertFalse(replay["created"])
        self.assertEqual(replay["sequence"], 3)
        self.assertEqual(replay["evaluation_count"], 3)

        with BackupRecoveryReadinessLedger(
            self.database, read_only=True
        ) as history:
            verification = history.verify()
        self.assertEqual(verification["record_count"], 3)
        self.assertEqual(verification["last_sequence"], 3)
        self.assertEqual(verification["ready_count"], 3)
        self.assertEqual(verification["chain_head_hash"], result["chain_head_hash"])

    def test_checkpoint_corruption_fails_closed_without_read_repair(self):
        corrupted_head = "0" * 64
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE ledger_backup_recovery_readiness_state "
                "SET chain_head_hash = ? WHERE id = 1",
                (corrupted_head,),
            )

        with self.assertRaises(BackupRecoveryReadinessLedgerCorruptionError):
            with BackupRecoveryReadinessLedger(
                self.database, read_only=True
            ) as history:
                history.verify()

        with sqlite3.connect(self.database) as connection:
            state = connection.execute(
                "SELECT last_sequence, chain_head_hash "
                "FROM ledger_backup_recovery_readiness_state WHERE id = 1"
            ).fetchone()
            record_count = connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_recovery_readiness_records"
            ).fetchone()[0]
        self.assertEqual(state, (2, corrupted_head))
        self.assertEqual(record_count, 2)


if __name__ == "__main__":
    unittest.main()
