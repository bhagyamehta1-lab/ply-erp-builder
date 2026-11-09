from __future__ import annotations

import copy
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_recovery_readiness_interruption import (
    reconcile_interrupted_backup_recovery_readiness_evaluation,
)
from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
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


class BackupRecoveryReadinessCrashPointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "readiness.sqlite3")
        self.now = datetime(2026, 11, 9, 18, 0, tzinfo=timezone.utc)
        with BackupRecoveryReadinessLedger(self.database):
            pass

    def tearDown(self):
        self.temp.cleanup()

    def _inject(self, fault):
        with BackupRecoveryReadinessLedger(self.database) as history:
            proxy = _FaultingConnection(history._connection, fault)
            history._connection = proxy
            with self.assertRaises(sqlite3.OperationalError):
                history.record_readiness_report(
                    copy.deepcopy(ready_report()), now=self.now
                )
            self.assertTrue(proxy.fired)

    def _assert_not_committed(self):
        result = reconcile_interrupted_backup_recovery_readiness_evaluation(
            self.database, ready_report(), now=self.now
        )
        self.assertEqual(result["outcome"], "NOT_COMMITTED")
        self.assertFalse(result["evaluation_present"])
        self.assertEqual(result["evaluation_count"], 0)
        self.assertIsNone(result["sequence"])
        self.assertEqual(result["next_step"], "MANUAL_REVIEW_REQUIRED")
        self.assertFalse(result["automatic_retry"])
        with BackupRecoveryReadinessLedger(
            self.database, read_only=True
        ) as history:
            verification = history.verify()
        self.assertEqual(verification["record_count"], 0)
        self.assertIsNone(verification["chain_head_hash"])

    def test_failure_before_record_insert_leaves_empty_history(self):
        self._inject("before_record_insert")
        self._assert_not_committed()

    def test_failure_after_record_insert_rolls_back_record_and_checkpoint(self):
        self._inject("after_record_insert")
        self._assert_not_committed()

    def test_failure_after_checkpoint_update_rolls_back_both_writes(self):
        self._inject("after_checkpoint_update")
        self._assert_not_committed()

    def test_commit_failure_before_sqlite_commit_is_not_committed(self):
        self._inject("before_commit")
        self._assert_not_committed()

    def test_lost_commit_acknowledgement_is_reconciled_without_duplicate(self):
        self._inject("commit_ack_lost")
        result = reconcile_interrupted_backup_recovery_readiness_evaluation(
            self.database, ready_report(), now=self.now
        )
        self.assertEqual(result["outcome"], "COMMITTED")
        self.assertTrue(result["evaluation_present"])
        self.assertEqual(result["evaluation_count"], 1)
        self.assertEqual(result["sequence"], 1)
        self.assertFalse(result["automatic_retry"])

        with BackupRecoveryReadinessLedger(self.database) as history:
            replay = history.record_readiness_report(
                copy.deepcopy(ready_report()), now=self.now
            )
        self.assertTrue(replay["already_present"])
        self.assertFalse(replay["created"])
        self.assertEqual(replay["sequence"], 1)
        self.assertEqual(replay["evaluation_count"], 1)

        with BackupRecoveryReadinessLedger(
            self.database, read_only=True
        ) as history:
            self.assertEqual(history.verify()["record_count"], 1)


if __name__ == "__main__":
    unittest.main()
