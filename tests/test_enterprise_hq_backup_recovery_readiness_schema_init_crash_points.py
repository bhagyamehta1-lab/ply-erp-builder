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



class RecoveryReadinessSchemaCompatibilityTests(unittest.TestCase):
    """Existing schemas must be validated, never silently repaired or migrated."""

    def _snapshot(self, database):
        connection = sqlite3.connect(str(database))
        try:
            objects = tuple(connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall())
            names = {row[1] for row in objects}
            metadata = (
                tuple(connection.execute(
                    "SELECT key, value FROM ledger_backup_recovery_readiness_meta "
                    "ORDER BY key"
                ).fetchall())
                if "ledger_backup_recovery_readiness_meta" in names else None
            )
            state = (
                tuple(connection.execute(
                    "SELECT id, last_sequence, chain_head_hash, updated_at "
                    "FROM ledger_backup_recovery_readiness_state ORDER BY id"
                ).fetchall())
                if "ledger_backup_recovery_readiness_state" in names else None
            )
            record_count = (
                connection.execute(
                    "SELECT COUNT(*) FROM ledger_backup_recovery_readiness_records"
                ).fetchone()[0]
                if "ledger_backup_recovery_readiness_records" in names else None
            )
            records = (
                tuple(connection.execute(
                    "SELECT sequence, evaluation_id, record_hash "
                    "FROM ledger_backup_recovery_readiness_records ORDER BY sequence"
                ).fetchall())
                if "ledger_backup_recovery_readiness_records" in names else None
            )
            journal_mode = connection.execute(
                "PRAGMA journal_mode"
            ).fetchone()[0]
            return {
                "objects": objects,
                "metadata": metadata,
                "state": state,
                "record_count": record_count,
                "records": records,
                "journal_mode": journal_mode,
            }
        finally:
            connection.close()

    def _create_valid_ledger(self, database, *, with_record=False):
        with BackupRecoveryReadinessLedger(str(database)) as history:
            if with_record:
                history.record_readiness_report(
                    ready_report(),
                    now=datetime(2026, 11, 9, 19, 30, tzinfo=timezone.utc),
                )

    def _set_wal(self, database):
        connection = sqlite3.connect(str(database))
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            self.assertEqual(mode.lower(), "wal")
        finally:
            connection.close()

    def _assert_schema_invalid_without_mutation(self, database):
        before = self._snapshot(database)
        with self.assertRaisesRegex(
            BackupRecoveryReadinessLedgerError, "SCHEMA_INVALID"
        ):
            BackupRecoveryReadinessLedger(str(database))
        self.assertEqual(self._snapshot(database), before)

    def test_partial_schema_is_rejected_without_repair_or_journal_change(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "partial.sqlite3"
            connection = sqlite3.connect(str(database))
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute(
                    "CREATE TABLE ledger_backup_recovery_readiness_meta "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO ledger_backup_recovery_readiness_meta(key, value) "
                    "VALUES('schema_version', '1.0.0')"
                )
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError, "SCHEMA_PARTIAL"
            ):
                BackupRecoveryReadinessLedger(str(database))
            self.assertEqual(self._snapshot(database), before)

    def test_missing_guard_is_not_recreated(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing-guard.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
                )
                connection.execute("PRAGMA journal_mode = WAL")
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError, "SCHEMA_PARTIAL"
            ):
                BackupRecoveryReadinessLedger(str(database))
            self.assertEqual(self._snapshot(database), before)

    def test_unsupported_schema_version_is_not_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "unsupported-version.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute(
                    "UPDATE ledger_backup_recovery_readiness_meta "
                    "SET value = '0.9.0' WHERE key = 'schema_version'"
                )
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError, "SCHEMA_VERSION_UNSUPPORTED"
            ):
                BackupRecoveryReadinessLedger(str(database))
            self.assertEqual(self._snapshot(database), before)

    def test_missing_initial_checkpoint_is_not_reseeded(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "missing-state.sqlite3"
            self._create_valid_ledger(database)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute(
                    "DROP TRIGGER ledger_backup_recovery_readiness_state_no_delete"
                )
                connection.execute(
                    "DELETE FROM ledger_backup_recovery_readiness_state WHERE id = 1"
                )
                connection.execute(
                    "CREATE TRIGGER ledger_backup_recovery_readiness_state_no_delete "
                    "BEFORE DELETE ON ledger_backup_recovery_readiness_state "
                    "BEGIN SELECT RAISE(ABORT, 'READINESS_HISTORY_STATE_REQUIRED'); END"
                )
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerCorruptionError, "STATE_MISSING"
            ):
                BackupRecoveryReadinessLedger(str(database))
            self.assertEqual(self._snapshot(database), before)

    def test_read_only_open_rejects_partial_schema_without_repair(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "readonly-partial.sqlite3"
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "CREATE TABLE ledger_backup_recovery_readiness_meta "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO ledger_backup_recovery_readiness_meta(key, value) "
                    "VALUES('schema_version', '1.0.0')"
                )
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError, "SCHEMA_PARTIAL"
            ):
                BackupRecoveryReadinessLedger(str(database), read_only=True)
            self.assertEqual(self._snapshot(database), before)

    def test_unrelated_database_objects_are_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "unrelated.sqlite3"
            connection = sqlite3.connect(str(database))
            try:
                connection.execute("CREATE TABLE unrelated_notes (value TEXT)")
                connection.commit()
            finally:
                connection.close()

            before = self._snapshot(database)
            with self.assertRaisesRegex(
                BackupRecoveryReadinessLedgerError, "SCHEMA_PARTIAL"
            ):
                BackupRecoveryReadinessLedger(str(database))
            self.assertEqual(self._snapshot(database), before)

    def test_existing_wal_schema_reopens_without_reconfiguration_or_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "existing-wal.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            self._set_wal(database)
            before = self._snapshot(database)

            with BackupRecoveryReadinessLedger(str(database)) as history:
                verification = history.verify()

            after = self._snapshot(database)
            self.assertEqual(after, before)
            self.assertEqual(after["journal_mode"], "wal")
            self.assertEqual(verification["record_count"], 1)
            self.assertEqual(verification["last_sequence"], 1)


    def test_same_name_noop_immutability_trigger_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "noop-trigger.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
                )
                connection.execute(
                    "CREATE TRIGGER ledger_backup_recovery_readiness_no_update "
                    "BEFORE UPDATE ON ledger_backup_recovery_readiness_records "
                    "BEGIN SELECT 1; END"
                )
                connection.commit()
            finally:
                connection.close()

            self._assert_schema_invalid_without_mutation(database)

    def test_same_name_misdirected_history_index_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "wrong-index.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "DROP INDEX ledger_backup_recovery_readiness_time_idx"
                )
                connection.execute(
                    "CREATE INDEX ledger_backup_recovery_readiness_time_idx "
                    "ON ledger_backup_recovery_readiness_records(sequence)"
                )
                connection.commit()
            finally:
                connection.close()

            self._assert_schema_invalid_without_mutation(database)

    def test_same_name_table_with_weakened_checks_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "weakened-table.sqlite3"
            self._create_valid_ledger(database, with_record=True)
            connection = sqlite3.connect(str(database))
            try:
                connection.execute(
                    "DROP TRIGGER ledger_backup_recovery_readiness_no_update"
                )
                connection.execute(
                    "DROP TRIGGER ledger_backup_recovery_readiness_no_delete"
                )
                connection.execute(
                    "DROP INDEX ledger_backup_recovery_readiness_time_idx"
                )
                connection.execute(
                    "ALTER TABLE ledger_backup_recovery_readiness_records "
                    "RENAME TO ledger_backup_recovery_readiness_records_legacy"
                )
                connection.execute(
                    """
                    CREATE TABLE ledger_backup_recovery_readiness_records (
                        sequence INTEGER PRIMARY KEY,
                        evaluation_id TEXT NOT NULL UNIQUE,
                        evaluated_at TEXT NOT NULL,
                        report_digest TEXT NOT NULL,
                        report_json TEXT NOT NULL,
                        metadata_readiness TEXT NOT NULL,
                        blocker_count INTEGER NOT NULL,
                        previous_hash TEXT,
                        record_hash TEXT NOT NULL UNIQUE
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO ledger_backup_recovery_readiness_records "
                    "SELECT sequence, evaluation_id, evaluated_at, report_digest, "
                    "report_json, metadata_readiness, blocker_count, previous_hash, "
                    "record_hash FROM ledger_backup_recovery_readiness_records_legacy"
                )
                connection.execute(
                    "DROP TABLE ledger_backup_recovery_readiness_records_legacy"
                )
                connection.execute(
                    "CREATE INDEX ledger_backup_recovery_readiness_time_idx "
                    "ON ledger_backup_recovery_readiness_records(evaluated_at)"
                )
                connection.execute(
                    "CREATE TRIGGER ledger_backup_recovery_readiness_no_update "
                    "BEFORE UPDATE ON ledger_backup_recovery_readiness_records "
                    "BEGIN SELECT RAISE(ABORT, 'READINESS_HISTORY_IMMUTABLE'); END"
                )
                connection.execute(
                    "CREATE TRIGGER ledger_backup_recovery_readiness_no_delete "
                    "BEFORE DELETE ON ledger_backup_recovery_readiness_records "
                    "BEGIN SELECT RAISE(ABORT, 'READINESS_HISTORY_IMMUTABLE'); END"
                )
                connection.commit()
            finally:
                connection.close()

            self._assert_schema_invalid_without_mutation(database)



if __name__ == "__main__":
    unittest.main()
