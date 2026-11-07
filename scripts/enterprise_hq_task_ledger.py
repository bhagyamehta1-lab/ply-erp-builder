"""Local, durable proposal ledger for Enterprise-HQ internal tasks.

This module persists validated task proposals and a tamper-evident event chain.
It does not claim, execute, dispatch, verify task results, or contact external systems.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from scripts.enterprise_hq_task_contract import ContractError, validate_batch, validate_task

SCHEMA_VERSION = 1
MAX_LEDGER_TASKS = 256
MAX_LEDGER_FILE_BYTES = 8 * 1024 * 1024


class LedgerError(RuntimeError):
    """The proposal ledger cannot safely complete the requested operation."""


class TaskConflictError(LedgerError):
    """A task ID or idempotency key already exists with different content."""


class LedgerCorruptionError(LedgerError):
    """Persisted ledger state failed integrity or audit-chain verification."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _validate_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _prepare_database_file(database: str | Path) -> None:
    """Require a regular, owner-only local database file; never follow a symlink."""
    if str(database) == ":memory:":
        return
    if not isinstance(database, (str, Path)) or str(database).startswith("file:"):
        raise LedgerError("LEDGER_PATH_UNSAFE")
    path = Path(database)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if path.is_symlink():
        raise LedgerError("LEDGER_PATH_UNSAFE")
    try:
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | nofollow,
                0o600,
            )
        except FileExistsError:
            descriptor = os.open(path, os.O_RDONLY | nofollow)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise LedgerError("LEDGER_PATH_UNSAFE")
            if stat.S_IMODE(info.st_mode) & 0o600 != 0o600 or stat.S_IMODE(info.st_mode) & 0o077:
                raise LedgerError("LEDGER_FILE_PERMISSIONS_UNSAFE")
            if info.st_size > MAX_LEDGER_FILE_BYTES:
                raise LedgerError("LEDGER_FILE_TOO_LARGE")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise LedgerError("LEDGER_FILE_OWNER_UNSAFE")
        finally:
            os.close(descriptor)
    except LedgerError:
        raise
    except OSError:
        raise LedgerError("LEDGER_PATH_UNSAFE") from None


class TaskLedger:
    """SQLite-backed, bounded storage for proposals awaiting human review."""

    def __init__(self, database: str | Path):
        _prepare_database_file(database)
        self.database = str(database)
        self._connection = sqlite3.connect(
            self.database,
            timeout=2.0,
            isolation_level=None,
        )
        try:
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 2000")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._connection.execute("PRAGMA journal_mode = DELETE")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
            max_pages = max(1, MAX_LEDGER_FILE_BYTES // page_size)
            self._connection.execute(f"PRAGMA max_page_count = {max_pages}")
            self._initialize()
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "TaskLedger":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    def _initialize(self) -> None:
        current_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if current_version > SCHEMA_VERSION:
            raise LedgerError("LEDGER_SCHEMA_NEWER_THAN_RUNTIME")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                task_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK (status = 'PROPOSED'),
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                sequence INTEGER PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(task_id),
                event TEXT NOT NULL CHECK (event = 'TASK_PROPOSED'),
                logical_role TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                previous_hash TEXT,
                record_hash TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS audit_events_task_id_idx
                ON audit_events(task_id);
            """
        )
        if current_version == 0:
            self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    def _append_proposal_event(self, task_id: str, logical_role: str) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "task_id": task_id,
            "event": "TASK_PROPOSED",
            "logical_role": logical_role,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
        self._connection.execute(
            """INSERT INTO audit_events
               (sequence, task_id, event, logical_role, occurred_at, previous_hash, record_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (sequence, task_id, "TASK_PROPOSED", logical_role, occurred_at, previous_hash, record_hash),
        )

    def propose_many(self, tasks: list[dict]) -> dict:
        """Persist up to eight proposals atomically; repeated identical proposals are idempotent."""
        normalized = validate_batch(tasks)
        canonical_tasks = [_canonical_json(task) for task in tasks]
        created = 0
        already_present = 0
        with self._transaction():
            # Never extend an audit chain until the entire existing ledger verifies.
            self.verify()
            current_count = self._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            for original, canonical, validated in zip(tasks, canonical_tasks, normalized):
                existing = self._connection.execute(
                    "SELECT task_id, idempotency_key, task_json FROM tasks WHERE task_id = ?",
                    (validated["task_id"],),
                ).fetchone()
                if existing is not None:
                    if (existing["idempotency_key"] != validated["idempotency_key"]
                            or existing["task_json"] != canonical):
                        raise TaskConflictError("TASK_ID_CONTENT_CONFLICT")
                    already_present += 1
                    continue

                key_owner = self._connection.execute(
                    "SELECT task_id FROM tasks WHERE idempotency_key = ?",
                    (validated["idempotency_key"],),
                ).fetchone()
                if key_owner is not None:
                    raise TaskConflictError("IDEMPOTENCY_KEY_CONTENT_CONFLICT")
                if current_count + created >= MAX_LEDGER_TASKS:
                    raise LedgerError("LEDGER_CAPACITY_REACHED")

                self._connection.execute(
                    """INSERT INTO tasks
                       (task_id, idempotency_key, task_json, status, created_at)
                       VALUES (?, ?, ?, 'PROPOSED', ?)""",
                    (validated["task_id"], validated["idempotency_key"], canonical, _utc_now()),
                )
                self._append_proposal_event(validated["task_id"], validated["logical_role"])
                created += 1

        return {
            "created": created,
            "already_present": already_present,
            "task_count": current_count + created,
            "status": "HUMAN_REVIEW_REQUIRED",
            "execution_performed": False,
        }

    def verify(self) -> dict:
        """Check SQLite integrity, stored task contracts, and the complete audit chain."""
        integrity_rows = self._connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity_rows) != 1 or integrity_rows[0][0] != "ok":
            raise LedgerCorruptionError("SQLITE_INTEGRITY_CHECK_FAILED")
        foreign_key_rows = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_key_rows:
            raise LedgerCorruptionError("LEDGER_FOREIGN_KEY_CHECK_FAILED")

        task_rows = self._connection.execute(
            "SELECT task_id, idempotency_key, task_json, status, created_at FROM tasks ORDER BY task_id"
        ).fetchall()
        if len(task_rows) > MAX_LEDGER_TASKS:
            raise LedgerCorruptionError("LEDGER_CAPACITY_INVARIANT_FAILED")

        task_roles: dict[str, str] = {}
        for row in task_rows:
            try:
                task = json.loads(row["task_json"])
                validated = validate_task(task)
            except (ValueError, TypeError, ContractError):
                raise LedgerCorruptionError("STORED_TASK_CONTRACT_INVALID") from None
            if (_canonical_json(task) != row["task_json"]
                    or validated["task_id"] != row["task_id"]
                    or validated["idempotency_key"] != row["idempotency_key"]
                    or row["status"] != "PROPOSED"
                    or not _validate_timestamp(row["created_at"])):
                raise LedgerCorruptionError("STORED_TASK_INVARIANT_FAILED")
            task_roles[row["task_id"]] = validated["logical_role"]

        events = self._connection.execute(
            """SELECT sequence, task_id, event, logical_role, occurred_at,
                      previous_hash, record_hash
               FROM audit_events ORDER BY sequence"""
        ).fetchall()
        previous_hash = None
        if len(events) != len(task_rows):
            raise LedgerCorruptionError("AUDIT_EVENT_COUNT_MISMATCH")
        seen_tasks: set[str] = set()
        for expected_sequence, row in enumerate(events, start=1):
            if (row["sequence"] != expected_sequence
                    or row["task_id"] not in task_roles
                    or row["task_id"] in seen_tasks
                    or row["event"] != "TASK_PROPOSED"
                    or row["logical_role"] != task_roles[row["task_id"]]
                    or row["previous_hash"] != previous_hash
                    or not _validate_timestamp(row["occurred_at"])):
                raise LedgerCorruptionError("AUDIT_CHAIN_STRUCTURE_INVALID")
            body = {
                "schema_version": "1.0.0",
                "sequence": row["sequence"],
                "task_id": row["task_id"],
                "event": row["event"],
                "logical_role": row["logical_role"],
                "occurred_at": row["occurred_at"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
            if row["record_hash"] != expected_hash:
                raise LedgerCorruptionError("AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen_tasks.add(row["task_id"])

        return {
            "integrity": "PASS",
            "task_count": len(task_rows),
            "audit_event_count": len(events),
            "audit_chain": "VALID",
        }

    def recover_after_restart(self) -> dict:
        """Re-open-safe recovery check; proposals remain pending human review, never auto-run."""
        verified = self.verify()
        return {
            "recovery_status": "PASS",
            "tasks_recovered": verified["task_count"],
            "pending_human_review": verified["task_count"],
            "audit_event_count": verified["audit_event_count"],
            "execution_resumed": False,
            "automatic_retry": False,
        }
