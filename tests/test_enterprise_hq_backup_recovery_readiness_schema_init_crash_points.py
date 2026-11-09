from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from scripts.enterprise_hq_backup_recovery_readiness_ledger import (
    BackupRecoveryReadinessLedger,
)


DDL_STATEMENT_COUNT = 7


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


class _SchemaInitializationFault:
    """Inject one deterministic failure after a schema-initialization boundary."""

    def __init__(self, connection, fault):
        self._connection = connection
        self.fault = fault
        self.ddl_count = 0
        self.fired = False
        self.transaction_active_at_fault = False

    @property
    def row_factory(self):
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self._connection.row_factory = value

    def executescript(self, script):
        pending = ""
        for line in script.splitlines(keepends=True):
            pending += line
            if not sqlite3.complete_statement(pending):
                continue
            statement = pending.strip()
            pending = ""
            if not statement:
                continue
            self._connection.execute(statement)
            normalized = " ".join(statement.split()).upper()
            if normalized.startswith(("CREATE TABLE", "CREATE INDEX", "CREATE TRIGGER")):
                self.ddl_count += 1
                if self.fault == f"after_ddl_{self.ddl_count}":
                    self.fired = True
                    self.transaction_active_at_fault = self._connection.in_transaction
                    raise sqlite3.OperationalError(
                        "synthetic interruption during schema initialization"
                    )
        if pending.strip():
            self._connection.execute(pending)
        return None

    def execute(self, sql, parameters=()):
        cursor = self._connection.execute(sql, parameters)
        normalized = " ".join(sql.split()).lower()
        if (
            self.fault == "after_meta_seed"
            and normalized.startswith(
                "insert or ignore into ledger_backup_recovery_readiness_meta"
            )
        ):
            self.fired = True
            self.transaction_active_at_fault = self._connection.in_transaction
            raise sqlite3.OperationalError("synthetic interruption after metadata seed")
        if (
            self.fault == "after_state_seed"
            and normalized.startswith(
                "insert or ignore into ledger_backup_recovery_readiness_state"
            )
        ):
            self.fired = True
            self.transaction_active_at_fault = self._connection.in_transaction
            raise sqlite3.OperationalError("synthetic interruption after state seed")
        return cursor

    def commit(self):
        if self.fault == "before_initialization_commit":
            self.fired = True
            self.transaction_active_at_fault = self._connection.in_transaction
            raise sqlite3.OperationalError("synthetic initialization commit failure")
        return self._connection.commit()

    def rollback(self):
        return self._connection.rollback()

    def __getattr__(self, name):
        return getattr(self._connection, name)


class RecoveryReadinessSchemaInitializationCrashTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.real_connect = sqlite3.connect

    def tearDown(self):
        self.temp.cleanup()

    def _interrupt_initialization(self, database, fault):
        proxy = None

        def connect(*args, **kwargs):
            nonlocal proxy
            proxy = _SchemaInitializationFault(self.real_connect(*args, **kwargs), fault)
            return proxy

        with patch(
            "scripts.enterprise_hq_backup_recovery_readiness_ledger.sqlite3.connect",
            side_effect=connect,
        ):
            with self.assertRaises(sqlite3.OperationalError):
                BackupRecoveryReadinessLedger(str(database))

        self.assertIsNotNone(proxy)
        self.assertTrue(proxy.fired)
        self.assertTrue(proxy.transaction_active_at_fault)

        raw = self.real_connect(str(database))
        try:
            objects = raw.execute(
                "SELECT type, name FROM sqlite_master "
                "WHERE name LIKE 'ledger_backup_recovery_readiness_%' "
                "ORDER BY type, name"
            ).fetchall()
        finally:
            raw.close()
        self.assertEqual(objects, [])
        return proxy

    def _retry_and_verify_empty_ledger(self, database):
        with BackupRecoveryReadinessLedger(str(database)) as history:
            verification = history.verify()
            snapshot = history.export_verification_snapshot()
        self.assertEqual(verification["history_status"], "VALID")
        self.assertEqual(verification["record_count"], 0)
        self.assertEqual(verification["last_sequence"], 0)
        self.assertIsNone(verification["chain_head_hash"])
        self.assertEqual(snapshot["record_count"], 0)

        raw = self.real_connect(str(database))
        try:
            objects = raw.execute(
                "SELECT type, name FROM sqlite_master "
                "WHERE name LIKE 'ledger_backup_recovery_readiness_%'"
            ).fetchall()
        finally:
            raw.close()
        self.assertEqual(len(objects), DDL_STATEMENT_COUNT)

    def test_every_schema_ddl_boundary_rolls_back_and_can_be_retried(self):
        for index in range(1, DDL_STATEMENT_COUNT + 1):
            with self.subTest(ddl_boundary=index):
                database = self.root / f"ddl-{index}.sqlite3"
                self._interrupt_initialization(database, f"after_ddl_{index}")
                self._retry_and_verify_empty_ledger(database)

    def test_metadata_seed_interruption_rolls_back_schema_and_seed(self):
        database = self.root / "metadata-seed.sqlite3"
        self._interrupt_initialization(database, "after_meta_seed")
        self._retry_and_verify_empty_ledger(database)

    def test_state_seed_interruption_rolls_back_schema_and_seed(self):
        database = self.root / "state-seed.sqlite3"
        self._interrupt_initialization(database, "after_state_seed")
        self._retry_and_verify_empty_ledger(database)

    def test_initialization_commit_failure_rolls_back_schema_and_seed(self):
        database = self.root / "commit.sqlite3"
        self._interrupt_initialization(database, "before_initialization_commit")
        self._retry_and_verify_empty_ledger(database)

    def test_reopening_initialized_history_does_not_reset_records(self):
        database = self.root / "existing.sqlite3"
        timestamp = datetime(2026, 11, 9, 19, 0, tzinfo=timezone.utc)
        with BackupRecoveryReadinessLedger(str(database)) as history:
            first = history.record_readiness_report(ready_report(), now=timestamp)
            before = history.verify()
        with BackupRecoveryReadinessLedger(str(database)) as history:
            second = history.verify()
        self.assertEqual(first["sequence"], 1)
        self.assertEqual(before["record_count"], 1)
        self.assertEqual(second["record_count"], 1)
        self.assertEqual(second["last_sequence"], 1)
        self.assertEqual(second["chain_head_hash"], before["chain_head_hash"])


if __name__ == "__main__":
    unittest.main()
