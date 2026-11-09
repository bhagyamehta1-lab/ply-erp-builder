"""Persistent aggregate-only history for Enterprise-HQ backup recovery readiness."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from scripts.enterprise_hq_backup_recovery_readiness_snapshot import (
    BackupRecoveryReadinessSnapshotError,
    validate_backup_recovery_readiness_report,
    verify_backup_recovery_readiness_snapshot,
)

MAX_RECOVERY_READINESS_EVALUATIONS = 512
SCHEMA_VERSION = "1.0.0"

_SCHEMA_OBJECTS = frozenset({
    ("table", "ledger_backup_recovery_readiness_meta"),
    ("table", "ledger_backup_recovery_readiness_state"),
    ("table", "ledger_backup_recovery_readiness_records"),
    ("index", "ledger_backup_recovery_readiness_time_idx"),
    ("trigger", "ledger_backup_recovery_readiness_no_update"),
    ("trigger", "ledger_backup_recovery_readiness_no_delete"),
    ("trigger", "ledger_backup_recovery_readiness_state_no_delete"),
})
_SCHEMA_COLUMNS = {
    "ledger_backup_recovery_readiness_meta": frozenset({"key", "value"}),
    "ledger_backup_recovery_readiness_state": frozenset({
        "id", "last_sequence", "chain_head_hash", "updated_at",
    }),
    "ledger_backup_recovery_readiness_records": frozenset({
        "sequence", "evaluation_id", "evaluated_at", "report_digest",
        "report_json", "metadata_readiness", "blocker_count",
        "previous_hash", "record_hash",
    }),
}


def _validate_existing_schema(connection, *, allow_empty: bool) -> bool:
    """Validate the complete on-disk schema without repairing or migrating it."""
    try:
        rows = connection.execute(
            "SELECT type, name FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
        ).fetchall()
        objects = {(row["type"], row["name"]) for row in rows}
    except sqlite3.Error:
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_INVALID"
        ) from None

    if not objects:
        if allow_empty:
            return False
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_INVALID"
        )
    if objects != _SCHEMA_OBJECTS:
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_PARTIAL"
        )

    try:
        for table, expected_columns in _SCHEMA_COLUMNS.items():
            actual_columns = {
                row["name"]
                for row in connection.execute(
                    f"PRAGMA table_info('{table}')"
                ).fetchall()
            }
            if actual_columns != expected_columns:
                raise BackupRecoveryReadinessLedgerError(
                    "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_INVALID"
                )
        version = connection.execute(
            "SELECT value FROM ledger_backup_recovery_readiness_meta "
            "WHERE key = 'schema_version'"
        ).fetchone()
        state = connection.execute(
            "SELECT last_sequence, chain_head_hash FROM "
            "ledger_backup_recovery_readiness_state WHERE id = 1"
        ).fetchone()
    except sqlite3.Error:
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_INVALID"
        ) from None

    if version is None or version["value"] != SCHEMA_VERSION:
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_VERSION_UNSUPPORTED"
        )
    if state is None:
        raise BackupRecoveryReadinessLedgerCorruptionError(
            "BACKUP_RECOVERY_READINESS_LEDGER_STATE_MISSING"
        )
    return True


class BackupRecoveryReadinessLedgerError(ValueError):
    """A readiness-history write is invalid or outside its bounded contract."""


class BackupRecoveryReadinessLedgerCorruptionError(
    BackupRecoveryReadinessLedgerError
):
    """Persistent readiness history failed independent verification."""


def _canonical(value) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


def _digest(value) -> str:
    import hashlib
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _timestamp(now: datetime | None) -> str:
    current = datetime.now(timezone.utc) if now is None else now
    if not isinstance(current, datetime) or current.tzinfo is None:
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_TIMESTAMP_INVALID"
        )
    try:
        return current.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
    except (OverflowError, ValueError):
        raise BackupRecoveryReadinessLedgerError(
            "BACKUP_RECOVERY_READINESS_LEDGER_TIMESTAMP_INVALID"
        ) from None


class BackupRecoveryReadinessLedger:
    """Append-only, local SQLite history of sanitized recovery-readiness reports."""

    def __init__(self, database: str, *, read_only: bool = False):
        self.database = str(database)
        if type(read_only) is not bool:
            raise BackupRecoveryReadinessLedgerError(
                "BACKUP_RECOVERY_READINESS_LEDGER_READ_ONLY_FLAG_INVALID"
            )
        self.read_only = read_only
        self._lock = threading.RLock()
        if not self.read_only and self.database != ":memory:":
            Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.read_only:
                path = Path(self.database)
                if self.database == ":memory:" or not path.is_file():
                    raise BackupRecoveryReadinessLedgerError(
                        "BACKUP_RECOVERY_READINESS_LEDGER_DATABASE_NOT_FOUND"
                    )
                uri = path.resolve().as_uri() + "?mode=ro"
                self._connection = sqlite3.connect(
                    uri, uri=True, timeout=5, isolation_level=None,
                    check_same_thread=False,
                )
                self._connection.row_factory = sqlite3.Row
                self._connection.execute("PRAGMA foreign_keys = ON")
                self._connection.execute("PRAGMA busy_timeout = 5000")
                self._connection.execute("PRAGMA query_only = ON")
                _validate_existing_schema(self._connection, allow_empty=False)
            else:
                self._connection = sqlite3.connect(
                    self.database, timeout=5, isolation_level=None,
                    check_same_thread=False,
                )
                self._connection.row_factory = sqlite3.Row
                self._connection.execute("PRAGMA foreign_keys = ON")
                self._connection.execute("PRAGMA busy_timeout = 5000")
                existing_schema = _validate_existing_schema(
                    self._connection, allow_empty=True
                )
                if not existing_schema:
                    self._connection.executescript(
                        """
                        BEGIN IMMEDIATE;
                        CREATE TABLE IF NOT EXISTS ledger_backup_recovery_readiness_meta (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS ledger_backup_recovery_readiness_state (
                            id INTEGER PRIMARY KEY CHECK (id = 1),
                            last_sequence INTEGER NOT NULL CHECK (last_sequence BETWEEN 0 AND 512),
                            chain_head_hash TEXT,
                            updated_at TEXT NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS ledger_backup_recovery_readiness_records (
                            sequence INTEGER PRIMARY KEY CHECK (sequence BETWEEN 1 AND 512),
                            evaluation_id TEXT NOT NULL UNIQUE,
                            evaluated_at TEXT NOT NULL,
                            report_digest TEXT NOT NULL,
                            report_json TEXT NOT NULL,
                            metadata_readiness TEXT NOT NULL
                                CHECK (metadata_readiness IN ('READY', 'NOT_READY')),
                            blocker_count INTEGER NOT NULL CHECK (blocker_count BETWEEN 0 AND 10),
                            previous_hash TEXT,
                            record_hash TEXT NOT NULL UNIQUE
                        );
                        CREATE INDEX IF NOT EXISTS ledger_backup_recovery_readiness_time_idx
                            ON ledger_backup_recovery_readiness_records(evaluated_at);
                        CREATE TRIGGER IF NOT EXISTS ledger_backup_recovery_readiness_no_update
                        BEFORE UPDATE ON ledger_backup_recovery_readiness_records
                        BEGIN
                            SELECT RAISE(ABORT, 'READINESS_HISTORY_IMMUTABLE');
                        END;
                        CREATE TRIGGER IF NOT EXISTS ledger_backup_recovery_readiness_no_delete
                        BEFORE DELETE ON ledger_backup_recovery_readiness_records
                        BEGIN
                            SELECT RAISE(ABORT, 'READINESS_HISTORY_IMMUTABLE');
                        END;
                        CREATE TRIGGER IF NOT EXISTS ledger_backup_recovery_readiness_state_no_delete
                        BEFORE DELETE ON ledger_backup_recovery_readiness_state
                        BEGIN
                            SELECT RAISE(ABORT, 'READINESS_HISTORY_STATE_REQUIRED');
                        END;
                        """
                    )
                    self._connection.execute(
                        "INSERT OR IGNORE INTO ledger_backup_recovery_readiness_meta(key, value) "
                        "VALUES('schema_version', ?)",
                        (SCHEMA_VERSION,),
                    )
                    self._connection.execute(
                        "INSERT OR IGNORE INTO ledger_backup_recovery_readiness_state"
                        "(id, last_sequence, chain_head_hash, updated_at) "
                        "VALUES(1, 0, NULL, '1970-01-01T00:00:00.000000Z')"
                    )
                    version = self._connection.execute(
                        "SELECT value FROM ledger_backup_recovery_readiness_meta "
                        "WHERE key = 'schema_version'"
                    ).fetchone()
                    if version is None or version["value"] != SCHEMA_VERSION:
                        raise BackupRecoveryReadinessLedgerError(
                            "BACKUP_RECOVERY_READINESS_LEDGER_SCHEMA_VERSION_UNSUPPORTED"
                        )
                    _validate_existing_schema(self._connection, allow_empty=False)
                    self._connection.commit()
                    if Path(self.database).exists():
                        os.chmod(self.database, 0o600)
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                try:
                    if connection.in_transaction:
                        connection.rollback()
                except Exception:
                    pass
                finally:
                    connection.close()
            raise

    @contextmanager
    def _transaction(self):
        if self.read_only:
            raise BackupRecoveryReadinessLedgerError(
                "BACKUP_RECOVERY_READINESS_LEDGER_READ_ONLY"
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _snapshot(self) -> dict:
        rows = self._connection.execute(
            "SELECT sequence, evaluation_id, evaluated_at, report_digest, "
            "report_json, metadata_readiness, blocker_count, previous_hash, record_hash "
            "FROM ledger_backup_recovery_readiness_records ORDER BY sequence"
        ).fetchall()
        state = self._connection.execute(
            "SELECT last_sequence, chain_head_hash FROM "
            "ledger_backup_recovery_readiness_state WHERE id = 1"
        ).fetchone()
        if state is None:
            raise BackupRecoveryReadinessLedgerCorruptionError(
                "BACKUP_RECOVERY_READINESS_LEDGER_STATE_MISSING"
            )
        records = []
        for row in rows:
            try:
                report = json.loads(row["report_json"])
            except (TypeError, ValueError):
                raise BackupRecoveryReadinessLedgerCorruptionError(
                    "BACKUP_RECOVERY_READINESS_LEDGER_REPORT_JSON_INVALID"
                ) from None
            if _canonical(report) != row["report_json"]:
                raise BackupRecoveryReadinessLedgerCorruptionError(
                    "BACKUP_RECOVERY_READINESS_LEDGER_REPORT_JSON_NONCANONICAL"
                )
            records.append({
                "schema_version": SCHEMA_VERSION,
                "sequence": row["sequence"],
                "evaluation_id": row["evaluation_id"],
                "evaluated_at": row["evaluated_at"],
                "report_digest": row["report_digest"],
                "metadata_readiness": row["metadata_readiness"],
                "blocker_count": row["blocker_count"],
                "report": report,
                "previous_hash": row["previous_hash"],
                "record_hash": row["record_hash"],
            })
        expected_head = records[-1]["record_hash"] if records else None
        if state["last_sequence"] != len(records) or state["chain_head_hash"] != expected_head:
            raise BackupRecoveryReadinessLedgerCorruptionError(
                "BACKUP_RECOVERY_READINESS_LEDGER_STATE_HEAD_MISMATCH"
            )
        return {
            "schema_version": SCHEMA_VERSION,
            "record_count": len(records),
            "records": records,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def export_verification_snapshot(self) -> dict:
        """Export only validated aggregate reports and their integrity chain."""
        with self._lock:
            return self._snapshot()

    def verify(self) -> dict:
        """Independently verify the complete persistent history."""
        try:
            snapshot = self.export_verification_snapshot()
            return verify_backup_recovery_readiness_snapshot(snapshot)
        except BackupRecoveryReadinessSnapshotError as exc:
            raise BackupRecoveryReadinessLedgerCorruptionError(str(exc)) from None

    @staticmethod
    def _record_body(
        *, sequence: int, evaluation_id: str, evaluated_at: str,
        report_digest: str, report: dict, previous_hash: str | None,
    ) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "evaluation_id": evaluation_id,
            "evaluated_at": evaluated_at,
            "report_digest": report_digest,
            "metadata_readiness": report["metadata_readiness"],
            "blocker_count": len(report["blocker_codes"]),
            "report": report,
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _result(row, *, evaluation_count: int, created: bool) -> dict:
        return {
            "status": "BACKUP_RECOVERY_READINESS_HISTORY_RECORDED",
            "evaluation_id": row["evaluation_id"],
            "evaluation_digest": row["report_digest"],
            "sequence": row["sequence"],
            "evaluation_count": evaluation_count,
            "metadata_readiness": row["metadata_readiness"],
            "blocker_count": row["blocker_count"],
            "created": created,
            "already_present": not created,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def record_readiness_report(
        self, report, *, now: datetime | None = None
    ) -> dict:
        """Append one bounded report; exact timestamp/report replay is idempotent."""
        try:
            normalized = validate_backup_recovery_readiness_report(report)
        except BackupRecoveryReadinessSnapshotError as exc:
            raise BackupRecoveryReadinessLedgerError(str(exc)) from None
        evaluated_at = _timestamp(now)
        report_json = _canonical(normalized)
        report_digest = _digest(normalized)
        evaluation_id = "hqrr_" + _digest({
            "schema_version": SCHEMA_VERSION,
            "evaluated_at": evaluated_at,
            "report_digest": report_digest,
        })[:24]

        with self._transaction():
            self.verify()
            latest = self._connection.execute(
                "SELECT sequence, evaluated_at, record_hash "
                "FROM ledger_backup_recovery_readiness_records "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest is not None and evaluated_at < latest["evaluated_at"]:
                raise BackupRecoveryReadinessLedgerError(
                    "BACKUP_RECOVERY_READINESS_LEDGER_CLOCK_ROLLBACK"
                )

            existing = self._connection.execute(
                "SELECT * FROM ledger_backup_recovery_readiness_records "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["report_digest"] != report_digest
                    or existing["report_json"] != report_json
                    or existing["evaluated_at"] != evaluated_at
                ):
                    raise BackupRecoveryReadinessLedgerCorruptionError(
                        "BACKUP_RECOVERY_READINESS_LEDGER_IDEMPOTENCY_CONFLICT"
                    )
                return self._result(
                    existing,
                    evaluation_count=self.verify()["record_count"],
                    created=False,
                )

            count = self._connection.execute(
                "SELECT COUNT(*) AS count FROM ledger_backup_recovery_readiness_records"
            ).fetchone()["count"]
            if count >= MAX_RECOVERY_READINESS_EVALUATIONS:
                raise BackupRecoveryReadinessLedgerError(
                    "BACKUP_RECOVERY_READINESS_LEDGER_CAPACITY_REACHED"
                )
            sequence = count + 1
            previous_hash = None if latest is None else latest["record_hash"]
            body = self._record_body(
                sequence=sequence,
                evaluation_id=evaluation_id,
                evaluated_at=evaluated_at,
                report_digest=report_digest,
                report=normalized,
                previous_hash=previous_hash,
            )
            record_hash = _digest(body)
            self._connection.execute(
                """
                INSERT INTO ledger_backup_recovery_readiness_records
                    (sequence, evaluation_id, evaluated_at, report_digest,
                     report_json, metadata_readiness, blocker_count,
                     previous_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence, evaluation_id, evaluated_at, report_digest,
                    report_json, normalized["metadata_readiness"],
                    len(normalized["blocker_codes"]), previous_hash, record_hash,
                ),
            )
            self._connection.execute(
                "UPDATE ledger_backup_recovery_readiness_state "
                "SET last_sequence = ?, chain_head_hash = ?, updated_at = ? "
                "WHERE id = 1",
                (sequence, record_hash, evaluated_at),
            )
            verification = self.verify()
            row = self._connection.execute(
                "SELECT * FROM ledger_backup_recovery_readiness_records "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            return self._result(
                row, evaluation_count=verification["record_count"], created=True
            )

    def inspect_evaluation(
        self, report, *, now: datetime | None = None
    ) -> dict:
        """Read-only lookup for an append whose caller may have been interrupted.

        The exact original timezone-aware timestamp is required because it is part
        of the deterministic evaluation identifier. This method never inserts,
        updates, or deletes a record.
        """
        if now is None:
            raise BackupRecoveryReadinessLedgerError(
                "BACKUP_RECOVERY_READINESS_LEDGER_INSPECTION_TIMESTAMP_REQUIRED"
            )
        try:
            normalized = validate_backup_recovery_readiness_report(report)
        except BackupRecoveryReadinessSnapshotError as exc:
            raise BackupRecoveryReadinessLedgerError(str(exc)) from None
        evaluated_at = _timestamp(now)
        report_json = _canonical(normalized)
        report_digest = _digest(normalized)
        evaluation_id = "hqrr_" + _digest({
            "schema_version": SCHEMA_VERSION,
            "evaluated_at": evaluated_at,
            "report_digest": report_digest,
        })[:24]

        with self._lock:
            verification = self.verify()
            row = self._connection.execute(
                "SELECT sequence, evaluation_id, evaluated_at, report_digest, "
                "report_json, metadata_readiness, blocker_count "
                "FROM ledger_backup_recovery_readiness_records "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()

        found = row is not None
        if found and (
            row["evaluation_id"] != evaluation_id
            or row["evaluated_at"] != evaluated_at
            or row["report_digest"] != report_digest
            or row["report_json"] != report_json
            or row["metadata_readiness"] != normalized["metadata_readiness"]
            or row["blocker_count"] != len(normalized["blocker_codes"])
        ):
            raise BackupRecoveryReadinessLedgerCorruptionError(
                "BACKUP_RECOVERY_READINESS_LEDGER_INSPECTION_RECORD_MISMATCH"
            )

        return {
            "status": (
                "BACKUP_RECOVERY_READINESS_EVALUATION_FOUND"
                if found else "BACKUP_RECOVERY_READINESS_EVALUATION_NOT_FOUND"
            ),
            "found": found,
            "evaluation_id": evaluation_id,
            "evaluation_digest": report_digest,
            "sequence": row["sequence"] if found else None,
            "evaluation_count": verification["record_count"],
            "metadata_readiness": normalized["metadata_readiness"],
            "blocker_count": len(normalized["blocker_codes"]),
            "chain_head_hash": verification["chain_head_hash"],
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify persisted history after a caller closes and reopens the database."""
        verification = self.verify()
        return {
            "status": "BACKUP_RECOVERY_READINESS_HISTORY_RECOVERED",
            "recovery_status": "PASS",
            "recovered_evaluation_count": verification["record_count"],
            "last_sequence": verification["last_sequence"],
            "chain_head_hash": verification["chain_head_hash"],
            "ready_count": verification["ready_count"],
            "not_ready_count": verification["not_ready_count"],
            "blocker_count_total": verification["blocker_count_total"],
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }


__all__ = [
    "BackupRecoveryReadinessLedger",
    "BackupRecoveryReadinessLedgerCorruptionError",
    "BackupRecoveryReadinessLedgerError",
    "MAX_RECOVERY_READINESS_EVALUATIONS",
]
