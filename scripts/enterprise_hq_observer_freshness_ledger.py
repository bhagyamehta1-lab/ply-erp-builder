"""Append-only, bounded local ledger for sanitized observer freshness receipts.

The ledger stores only the already-sanitized decision envelope, an opaque
idempotency-key digest, a caller-supplied recording time, and a hash chain.
It never polls GitHub, dispatches work, or deletes old receipts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timezone
from pathlib import Path

from scripts.enterprise_hq_observer_freshness import (
    ObserverFreshnessError,
    verify_observer_freshness_receipt,
)

SCHEMA_VERSION = "1.0.0"
MAX_OBSERVER_FRESHNESS_RECEIPTS = 512
MAX_DATABASE_BYTES = 1024 * 1024
MAX_RECORDED_AT_CHARS = 64
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class ObserverFreshnessLedgerError(ValueError):
    """A ledger input, capacity, or persistence operation is invalid."""


class ObserverFreshnessLedgerCorruptionError(ObserverFreshnessLedgerError):
    """Persisted observer freshness history failed integrity verification."""


def _fail(code: str) -> None:
    raise ObserverFreshnessLedgerError(code)


def _corrupt(code: str) -> None:
    raise ObserverFreshnessLedgerCorruptionError(code)


def _canonical(value: dict) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("OBSERVER_FRESHNESS_LEDGER_CANONICALIZATION_INVALID")


def _digest(value: dict) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _normalize_recorded_at(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RECORDED_AT_CHARS:
        _fail("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_INVALID")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError, OverflowError):
        _fail("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_TIMEZONE_REQUIRED")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class ObserverFreshnessLedger:
    """Append-only SQLite receipt history with bounded capacity and hash chaining."""

    def __init__(self, database: str):
        if not isinstance(database, (str, os.PathLike)):
            _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_INVALID")
        raw_path = os.fspath(database)
        if not raw_path or raw_path == ":memory:":
            _fail("OBSERVER_FRESHNESS_LEDGER_PERSISTENT_PATH_REQUIRED")
        self._path = Path(raw_path)
        if self._path.is_symlink():
            _fail("OBSERVER_FRESHNESS_LEDGER_SYMLINK_FORBIDDEN")
        if not self._path.parent.exists() or not self._path.parent.is_dir():
            _fail("OBSERVER_FRESHNESS_LEDGER_PARENT_DIRECTORY_INVALID")
        if self._path.exists():
            try:
                mode = self._path.lstat().st_mode
            except OSError:
                _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_INVALID")
            if not stat.S_ISREG(mode):
                _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_NOT_REGULAR")
            if self._path.stat().st_size > MAX_DATABASE_BYTES:
                _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_TOO_LARGE")

        self._connection = None
        try:
            self._connection = sqlite3.connect(
                str(self._path), timeout=5.0, isolation_level=None
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS observer_freshness_receipts (
                    sequence INTEGER PRIMARY KEY
                        CHECK (sequence BETWEEN 1 AND 512),
                    receipt_id TEXT NOT NULL UNIQUE
                        CHECK (length(receipt_id) = 64),
                    recorded_at TEXT NOT NULL
                        CHECK (length(recorded_at) BETWEEN 1 AND 64),
                    receipt_json TEXT NOT NULL
                        CHECK (length(receipt_json) BETWEEN 2 AND 4096),
                    decision_digest TEXT NOT NULL
                        CHECK (length(decision_digest) = 64),
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                        CHECK (length(record_hash) = 64)
                );
                CREATE TRIGGER IF NOT EXISTS observer_freshness_receipts_no_update
                BEFORE UPDATE ON observer_freshness_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_LEDGER_APPEND_ONLY');
                END;
                CREATE TRIGGER IF NOT EXISTS observer_freshness_receipts_no_delete
                BEFORE DELETE ON observer_freshness_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_LEDGER_APPEND_ONLY');
                END;
                """
            )
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                _fail("OBSERVER_FRESHNESS_LEDGER_SCHEMA_VERSION_UNSUPPORTED")
            self._connection.execute("PRAGMA user_version=1")
            page_limit = self._connection.execute(
                "PRAGMA max_page_count=256"
            ).fetchone()[0]
            if page_limit > 256:
                _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_TOO_LARGE")
            if self._path.is_symlink() or not self._path.is_file():
                _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_PATH_CHANGED")
            os.chmod(self._path, 0o600)
        except ObserverFreshnessLedgerError:
            self.close()
            raise
        except (OSError, sqlite3.Error):
            self.close()
            _fail("OBSERVER_FRESHNESS_LEDGER_DATABASE_OPEN_FAILED")

    @staticmethod
    def _record_body(
        *, sequence: int, receipt_id: str, recorded_at: str,
        receipt: dict, previous_hash: str | None,
    ) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "receipt_id": receipt_id,
            "recorded_at": recorded_at,
            "receipt": receipt,
            "previous_hash": previous_hash,
        }

    def append(
        self, receipt: dict, *, idempotency_key: str, recorded_at: str
    ) -> dict:
        """Append one verified receipt; exact replays are idempotent."""
        try:
            verified = verify_observer_freshness_receipt(receipt)
        except ObserverFreshnessError:
            _fail("OBSERVER_FRESHNESS_LEDGER_RECEIPT_INVALID")
        if verified.get("status") != "OBSERVER_FRESHNESS_RECEIPT_VALID":
            _fail("OBSERVER_FRESHNESS_LEDGER_RECEIPT_INVALID")
        if not isinstance(idempotency_key, str) or not _HEX_64.fullmatch(idempotency_key):
            _fail("OBSERVER_FRESHNESS_LEDGER_IDEMPOTENCY_KEY_INVALID")
        receipt_id = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
        normalized_at = _normalize_recorded_at(recorded_at)
        receipt_json = _canonical(receipt)
        decision_digest = receipt["decision_digest"]

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                "SELECT sequence, recorded_at, receipt_json, decision_digest, record_hash "
                "FROM observer_freshness_receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["recorded_at"] != normalized_at
                    or existing["receipt_json"] != receipt_json
                    or existing["decision_digest"] != decision_digest
                ):
                    _fail("OBSERVER_FRESHNESS_LEDGER_IDEMPOTENCY_CONFLICT")
                self._connection.commit()
                return {
                    "status": "OBSERVER_FRESHNESS_RECEIPT_REPLAYED",
                    "sequence": existing["sequence"],
                    "receipt_id": receipt_id,
                    "decision_digest": decision_digest,
                    "record_hash": existing["record_hash"],
                    "created": False,
                    "already_present": True,
                    "execution_authorized": False,
                    "automatic_dispatch": False,
                    "automatic_retry": False,
                }

            count = self._connection.execute(
                "SELECT COUNT(*) FROM observer_freshness_receipts"
            ).fetchone()[0]
            if count >= MAX_OBSERVER_FRESHNESS_RECEIPTS:
                _fail("OBSERVER_FRESHNESS_LEDGER_CAPACITY_REACHED")
            previous = self._connection.execute(
                "SELECT sequence, record_hash, recorded_at "
                "FROM observer_freshness_receipts ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            sequence = 1 if previous is None else previous["sequence"] + 1
            previous_hash = None if previous is None else previous["record_hash"]
            if previous is not None and normalized_at < previous["recorded_at"]:
                _fail("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_REGRESSION")
            body = self._record_body(
                sequence=sequence,
                receipt_id=receipt_id,
                recorded_at=normalized_at,
                receipt=receipt,
                previous_hash=previous_hash,
            )
            record_hash = _digest(body)
            self._connection.execute(
                "INSERT INTO observer_freshness_receipts "
                "(sequence, receipt_id, recorded_at, receipt_json, decision_digest, "
                "previous_hash, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    sequence, receipt_id, normalized_at, receipt_json,
                    decision_digest, previous_hash, record_hash,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

        return {
            "status": "OBSERVER_FRESHNESS_RECEIPT_RECORDED",
            "sequence": sequence,
            "receipt_id": receipt_id,
            "decision_digest": decision_digest,
            "record_hash": record_hash,
            "created": True,
            "already_present": False,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def verify(self) -> dict:
        """Verify every receipt, sequence, timestamp, and hash-chain link."""
        rows = self._connection.execute(
            "SELECT sequence, receipt_id, recorded_at, receipt_json, "
            "decision_digest, previous_hash, record_hash "
            "FROM observer_freshness_receipts ORDER BY sequence"
        ).fetchall()
        if len(rows) > MAX_OBSERVER_FRESHNESS_RECEIPTS:
            _corrupt("OBSERVER_FRESHNESS_LEDGER_CAPACITY_CORRUPT")
        previous_hash = None
        previous_at = None
        counts: dict[str, int] = {}
        for expected_sequence, row in enumerate(rows, start=1):
            if row["sequence"] != expected_sequence:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_SEQUENCE_INVALID")
            if row["previous_hash"] != previous_hash:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_CHAIN_LINK_INVALID")
            if not _HEX_64.fullmatch(row["receipt_id"]):
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECEIPT_ID_INVALID")
            if not _HEX_64.fullmatch(row["decision_digest"]):
                _corrupt("OBSERVER_FRESHNESS_LEDGER_DECISION_DIGEST_INVALID")
            if not _HEX_64.fullmatch(row["record_hash"]):
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECORD_HASH_INVALID")
            try:
                normalized_at = _normalize_recorded_at(row["recorded_at"])
                receipt = json.loads(row["receipt_json"])
                if _canonical(receipt) != row["receipt_json"]:
                    _corrupt("OBSERVER_FRESHNESS_LEDGER_RECEIPT_ENCODING_INVALID")
                verified = verify_observer_freshness_receipt(receipt)
            except (ObserverFreshnessLedgerError, ObserverFreshnessError, ValueError, TypeError):
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECEIPT_INVALID")
            if normalized_at != row["recorded_at"]:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_INVALID")
            if previous_at is not None and normalized_at < previous_at:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECORDED_AT_REGRESSION")
            if receipt.get("decision_digest") != row["decision_digest"]:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_DECISION_DIGEST_MISMATCH")
            if verified.get("execution_authorized") is not False:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_AUTHORITY_INVALID")
            body = self._record_body(
                sequence=row["sequence"],
                receipt_id=row["receipt_id"],
                recorded_at=row["recorded_at"],
                receipt=receipt,
                previous_hash=row["previous_hash"],
            )
            if _digest(body) != row["record_hash"]:
                _corrupt("OBSERVER_FRESHNESS_LEDGER_RECORD_HASH_MISMATCH")
            counts[receipt["status"]] = counts.get(receipt["status"], 0) + 1
            previous_hash = row["record_hash"]
            previous_at = normalized_at

        return {
            "status": "OBSERVER_FRESHNESS_LEDGER_VALID",
            "receipt_count": len(rows),
            "status_counts": dict(sorted(counts.items())),
            "last_sequence": len(rows) if rows else None,
            "chain_head_digest": previous_hash,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def close(self) -> None:
        connection = getattr(self, "_connection", None)
        if connection is not None:
            self._connection = None
            connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False


__all__ = [
    "MAX_OBSERVER_FRESHNESS_RECEIPTS",
    "ObserverFreshnessLedger",
    "ObserverFreshnessLedgerCorruptionError",
    "ObserverFreshnessLedgerError",
]
