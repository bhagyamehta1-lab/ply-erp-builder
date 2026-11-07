"""Local, durable proposal ledger for Enterprise-HQ internal tasks.

This module persists validated task proposals and a tamper-evident event chain.
It does not claim, execute, dispatch, verify task results, or contact external systems.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from scripts.enterprise_hq_task_contract import ContractError, validate_batch, validate_task

SCHEMA_VERSION = 1
MAX_LEDGER_TASKS = 256


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


class TaskLedger:
    """SQLite-backed, bounded storage for proposals awaiting human review."""

    def __init__(self, database: str | Path):
        self.database = str(database)
        self._connection = sqlite3.connect(
            self.database,
            timeout=2.0,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 2000")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._initialize()

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
        except Exception:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def _initialize(self) -> None:
        current_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if current_version > SCHEMA_VERSION:
            self.close()
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

        task_rows = self._connection.execute(
            "SELECT task_id, idempotency_key, task_json, status FROM tasks ORDER BY task_id"
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
                    or row["status"] != "PROPOSED"):
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
                    or not isinstance(row["occurred_at"], str)):
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
