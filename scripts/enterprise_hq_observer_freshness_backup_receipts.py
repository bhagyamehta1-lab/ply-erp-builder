"""Append-only lineage receipts for verified observer-freshness backups.

This local SQLite ledger records only aggregate metadata returned by the
verified backup routine. It stores no backup paths, timestamps from source
receipts, repository identifiers, workflow names, or private payloads.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = "1.0.0"
MAX_BACKUP_RECEIPTS = 256
MAX_DATABASE_BYTES = 1024 * 1024
MAX_SOURCE_RECEIPTS = 512
MAX_RECORDED_AT_CHARS = 64
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_BACKUP_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")
_ALLOWED_FRESHNESS_STATUSES = frozenset({
    "NEVER_OBSERVED", "CLOCK_SKEW", "FRESH", "GRACE_PERIOD", "MISSED",
})
_RESULT_FIELDS = frozenset({
    "status", "file_sha256", "receipt_count", "status_counts",
    "last_sequence", "chain_head_digest", "equivalence_verified",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_TABLE = "observer_freshness_backup_receipts"
_COLUMNS = (
    "sequence", "backup_id", "recorded_at", "file_sha256",
    "receipt_count", "status_counts_json", "last_sequence",
    "chain_head_digest", "predecessor_backup_id", "previous_hash",
    "record_hash",
)
_TRIGGERS = {
    "observer_freshness_backup_receipts_no_update",
    "observer_freshness_backup_receipts_no_delete",
}


class ObserverFreshnessBackupReceiptError(ValueError):
    """Invalid backup receipt input or bounded persistence operation."""


class ObserverFreshnessBackupReceiptCorruptionError(
    ObserverFreshnessBackupReceiptError
):
    """Persisted backup receipt lineage failed independent verification."""


def _fail(code: str) -> None:
    raise ObserverFreshnessBackupReceiptError(code)


def _corrupt(code: str) -> None:
    raise ObserverFreshnessBackupReceiptCorruptionError(code)


def _canonical(value) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_ENCODING_INVALID")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _normalize_recorded_at(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RECORDED_AT_CHARS:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED_AT_INVALID")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError, OverflowError):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED_AT_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_TIMEZONE_REQUIRED")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _normalize_backup_result(result: Mapping) -> dict:
    if not isinstance(result, Mapping) or set(result) != _RESULT_FIELDS:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RESULT_SCHEMA_INVALID")
    if result.get("status") != "OBSERVER_FRESHNESS_BACKUP_VERIFIED":
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_BACKUP_NOT_VERIFIED")
    if result.get("equivalence_verified") is not True:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_EQUIVALENCE_REQUIRED")
    for flag in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
        if result.get(flag) is not False:
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_AUTHORITY_INVARIANT_FAILED")

    file_sha = result.get("file_sha256")
    count = result.get("receipt_count")
    counts = result.get("status_counts")
    last = result.get("last_sequence")
    head = result.get("chain_head_digest")
    if not isinstance(file_sha, str) or not _HEX_64.fullmatch(file_sha):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_FILE_DIGEST_INVALID")
    if type(count) is not int or not 0 <= count <= MAX_SOURCE_RECEIPTS:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_COUNT_INVALID")
    if not isinstance(counts, Mapping):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_STATUS_COUNTS_INVALID")
    normalized_counts = dict(counts)
    if any(
        not isinstance(key, str) or key not in _ALLOWED_FRESHNESS_STATUSES
        or type(value) is not int or value <= 0
        for key, value in normalized_counts.items()
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_STATUS_COUNTS_INVALID")
    normalized_counts = dict(sorted(normalized_counts.items()))
    if sum(normalized_counts.values()) != count:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_STATUS_TOTAL_INVALID")
    if count == 0:
        if normalized_counts or last is not None or head is not None:
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_EMPTY_SUMMARY_INVALID")
    elif (
        type(last) is not int or last != count
        or not isinstance(head, str) or not _HEX_64.fullmatch(head)
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CHAIN_HEAD_INVALID")
    return {
        "backup_id": "hqfb_" + file_sha[:24],
        "file_sha256": file_sha,
        "receipt_count": count,
        "status_counts": normalized_counts,
        "last_sequence": last,
        "chain_head_digest": head,
    }


class ObserverFreshnessBackupReceiptLedger:
    """Bounded append-only SQLite lineage for verified freshness backup files."""

    def __init__(self, database: str):
        if not isinstance(database, (str, os.PathLike)):
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_INVALID")
        raw = os.fspath(database)
        if not raw or raw == ":memory:":
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PERSISTENT_PATH_REQUIRED")
        self._path = Path(raw)
        if self._path.is_symlink():
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_SYMLINK_FORBIDDEN")
        if not self._path.parent.exists() or not self._path.parent.is_dir():
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PARENT_INVALID")
        existed = self._path.exists()
        if existed:
            try:
                mode = self._path.lstat().st_mode
                size = self._path.stat().st_size
            except OSError:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_INVALID")
            if not stat.S_ISREG(mode):
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_NOT_REGULAR")
            if stat.S_IMODE(mode) & 0o077:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PERMISSIONS_INVALID")
            if size > MAX_DATABASE_BYTES:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_TOO_LARGE")

        self._connection = None
        try:
            self._connection = sqlite3.connect(
                str(self._path), timeout=5.0, isolation_level=None
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            if existed:
                self._validate_schema()
            else:
                self._connection.executescript(
                    """
                    CREATE TABLE observer_freshness_backup_receipts (
                        sequence INTEGER PRIMARY KEY
                            CHECK (sequence BETWEEN 1 AND 256),
                        backup_id TEXT NOT NULL UNIQUE
                            CHECK (length(backup_id) = 29),
                        recorded_at TEXT NOT NULL
                            CHECK (length(recorded_at) BETWEEN 1 AND 64),
                        file_sha256 TEXT NOT NULL
                            CHECK (length(file_sha256) = 64),
                        receipt_count INTEGER NOT NULL
                            CHECK (receipt_count BETWEEN 0 AND 512),
                        status_counts_json TEXT NOT NULL
                            CHECK (length(status_counts_json) BETWEEN 2 AND 512),
                        last_sequence INTEGER,
                        chain_head_digest TEXT,
                        predecessor_backup_id TEXT,
                        previous_hash TEXT,
                        record_hash TEXT NOT NULL UNIQUE
                            CHECK (length(record_hash) = 64)
                    );
                    CREATE TRIGGER observer_freshness_backup_receipts_no_update
                    BEFORE UPDATE ON observer_freshness_backup_receipts
                    BEGIN
                        SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_RECEIPT_APPEND_ONLY');
                    END;
                    CREATE TRIGGER observer_freshness_backup_receipts_no_delete
                    BEFORE DELETE ON observer_freshness_backup_receipts
                    BEGIN
                        SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_RECEIPT_APPEND_ONLY');
                    END;
                    PRAGMA user_version=1;
                    """
                )
                self._validate_schema()
            page_limit = self._connection.execute(
                "PRAGMA max_page_count=256"
            ).fetchone()[0]
            if page_limit > 256:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_TOO_LARGE")
            if self._path.is_symlink() or not self._path.is_file():
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PATH_CHANGED")
            os.chmod(self._path, 0o600)
        except ObserverFreshnessBackupReceiptError:
            self.close()
            raise
        except (OSError, sqlite3.Error):
            self.close()
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_OPEN_FAILED")

    def _validate_schema(self) -> None:
        try:
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            if version != 1:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_SCHEMA_VERSION_INVALID")
            tables = [
                row[0] for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            if tables != [_TABLE]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_TABLE_SCHEMA_INVALID")
            views = self._connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='view'"
            ).fetchone()[0]
            if views != 0:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_VIEW_FORBIDDEN")
            triggers = {
                row[0]: row[1] or "" for row in self._connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
                )
            }
            if set(triggers) != _TRIGGERS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_TRIGGER_SCHEMA_INVALID")
            for name, sql in triggers.items():
                normalized = " ".join(sql.upper().split())
                operation = "BEFORE UPDATE ON" if name.endswith("no_update") else "BEFORE DELETE ON"
                if (
                    operation + " " + _TABLE.upper() not in normalized
                    or "RAISE(ABORT" not in normalized
                    or "OBSERVER_FRESHNESS_BACKUP_RECEIPT_APPEND_ONLY" not in normalized
                ):
                    _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_TRIGGER_POLICY_INVALID")
            columns = tuple(
                row[1] for row in self._connection.execute(
                    f'PRAGMA table_info("{_TABLE}")'
                )
            )
            if columns != _COLUMNS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_COLUMN_SCHEMA_INVALID")
            count = self._connection.execute(
                f'SELECT COUNT(*) FROM "{_TABLE}"'
            ).fetchone()[0]
            if type(count) is not int or not 0 <= count <= MAX_BACKUP_RECEIPTS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CAPACITY_CORRUPT")
            pages = self._connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
            if type(pages) is not int or type(page_size) is not int:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PAGE_METADATA_INVALID")
            if pages * page_size > MAX_DATABASE_BYTES:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_DATABASE_TOO_LARGE")
        except ObserverFreshnessBackupReceiptError:
            raise
        except sqlite3.Error:
            _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_SCHEMA_INVALID")

    @staticmethod
    def _record_body(
        *, sequence: int, metadata: dict, recorded_at: str,
        predecessor_backup_id: str | None, previous_hash: str | None,
    ) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            **metadata,
            "recorded_at": recorded_at,
            "predecessor_backup_id": predecessor_backup_id,
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _response(status: str, row, *, created: bool, already_present: bool) -> dict:
        return {
            "status": status,
            "backup_count": row["sequence"],
            "backup_id": row["backup_id"],
            "file_sha256": row["file_sha256"],
            "source_receipt_count": row["receipt_count"],
            "last_source_sequence": row["last_sequence"],
            "source_chain_head_digest": row["chain_head_digest"],
            "predecessor_backup_id": row["predecessor_backup_id"],
            "record_hash": row["record_hash"],
            "created": created,
            "already_present": already_present,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def append_backup(self, backup_result: Mapping, *, recorded_at: str) -> dict:
        """Record one independently verified backup; duplicate file digests replay."""
        metadata = _normalize_backup_result(backup_result)
        normalized_at = _normalize_recorded_at(recorded_at)
        status_json = _canonical(metadata["status_counts"])

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self.verify()
            existing = self._connection.execute(
                f'SELECT * FROM "{_TABLE}" WHERE backup_id = ?',
                (metadata["backup_id"],),
            ).fetchone()
            if existing is not None:
                same = (
                    existing["file_sha256"] == metadata["file_sha256"]
                    and existing["receipt_count"] == metadata["receipt_count"]
                    and existing["status_counts_json"] == status_json
                    and existing["last_sequence"] == metadata["last_sequence"]
                    and existing["chain_head_digest"] == metadata["chain_head_digest"]
                )
                if not same:
                    _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_ID_CONFLICT")
                self._connection.commit()
                return self._response(
                    "OBSERVER_FRESHNESS_BACKUP_RECEIPT_REPLAYED",
                    existing, created=False, already_present=True,
                )

            previous = self._connection.execute(
                f'SELECT sequence, backup_id, recorded_at, record_hash FROM "{_TABLE}" '
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            count = self._connection.execute(
                f'SELECT COUNT(*) FROM "{_TABLE}"'
            ).fetchone()[0]
            if count >= MAX_BACKUP_RECEIPTS:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CAPACITY_REACHED")
            if previous is not None and normalized_at < previous["recorded_at"]:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED_AT_REGRESSION")
            sequence = count + 1
            predecessor = None if previous is None else previous["backup_id"]
            previous_hash = None if previous is None else previous["record_hash"]
            body = self._record_body(
                sequence=sequence, metadata=metadata, recorded_at=normalized_at,
                predecessor_backup_id=predecessor, previous_hash=previous_hash,
            )
            record_hash = _digest(body)
            self._connection.execute(
                f'INSERT INTO "{_TABLE}" '
                "(sequence, backup_id, recorded_at, file_sha256, receipt_count, "
                "status_counts_json, last_sequence, chain_head_digest, "
                "predecessor_backup_id, previous_hash, record_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    sequence, metadata["backup_id"], normalized_at,
                    metadata["file_sha256"], metadata["receipt_count"], status_json,
                    metadata["last_sequence"], metadata["chain_head_digest"],
                    predecessor, previous_hash, record_hash,
                ),
            )
            row = self._connection.execute(
                f'SELECT * FROM "{_TABLE}" WHERE backup_id = ?',
                (metadata["backup_id"],),
            ).fetchone()
            self._connection.commit()
            return self._response(
                "OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED",
                row, created=True, already_present=False,
            )
        except Exception:
            self._connection.rollback()
            raise

    def verify(self) -> dict:
        """Verify backup metadata, predecessor links, and the complete hash chain."""
        self._validate_schema()
        rows = self._connection.execute(
            f'SELECT * FROM "{_TABLE}" ORDER BY sequence'
        ).fetchall()
        if len(rows) > MAX_BACKUP_RECEIPTS:
            _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CAPACITY_CORRUPT")
        previous_hash = None
        previous_backup_id = None
        previous_at = None
        for expected, row in enumerate(rows, start=1):
            if row["sequence"] != expected:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_SEQUENCE_INVALID")
            if row["previous_hash"] != previous_hash:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CHAIN_LINK_INVALID")
            if row["predecessor_backup_id"] != previous_backup_id:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_PREDECESSOR_INVALID")
            if not isinstance(row["file_sha256"], str) or not _HEX_64.fullmatch(row["file_sha256"]):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_FILE_DIGEST_INVALID")
            if row["backup_id"] != "hqfb_" + row["file_sha256"][:24]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_ID_INVALID")
            if not _BACKUP_ID.fullmatch(row["backup_id"]):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_ID_INVALID")
            if type(row["receipt_count"]) is not int or not 0 <= row["receipt_count"] <= MAX_SOURCE_RECEIPTS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_COUNT_INVALID")
            try:
                normalized_at = _normalize_recorded_at(row["recorded_at"])
                counts = json.loads(row["status_counts_json"])
                if _canonical(counts) != row["status_counts_json"]:
                    _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_STATUS_ENCODING_INVALID")
            except (ObserverFreshnessBackupReceiptError, ValueError, TypeError):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_METADATA_INVALID")
            if normalized_at != row["recorded_at"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED_AT_INVALID")
            if previous_at is not None and normalized_at < previous_at:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORDED_AT_REGRESSION")
            if not isinstance(counts, dict) or any(
                not isinstance(key, str) or key not in _ALLOWED_FRESHNESS_STATUSES
                or type(value) is not int or value <= 0
                for key, value in counts.items()
            ) or sum(counts.values()) != row["receipt_count"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_STATUS_COUNTS_INVALID")
            if row["receipt_count"] == 0:
                if counts or row["last_sequence"] is not None or row["chain_head_digest"] is not None:
                    _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_EMPTY_SUMMARY_INVALID")
            elif (
                type(row["last_sequence"]) is not int
                or row["last_sequence"] != row["receipt_count"]
                or not isinstance(row["chain_head_digest"], str)
                or not _HEX_64.fullmatch(row["chain_head_digest"])
            ):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CHAIN_HEAD_INVALID")
            metadata = {
                "backup_id": row["backup_id"],
                "file_sha256": row["file_sha256"],
                "receipt_count": row["receipt_count"],
                "status_counts": dict(sorted(counts.items())),
                "last_sequence": row["last_sequence"],
                "chain_head_digest": row["chain_head_digest"],
            }
            body = self._record_body(
                sequence=expected, metadata=metadata, recorded_at=row["recorded_at"],
                predecessor_backup_id=row["predecessor_backup_id"],
                previous_hash=row["previous_hash"],
            )
            if not isinstance(row["record_hash"], str) or not _HEX_64.fullmatch(row["record_hash"]):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORD_HASH_INVALID")
            if _digest(body) != row["record_hash"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_RECORD_HASH_MISMATCH")
            previous_hash = row["record_hash"]
            previous_backup_id = row["backup_id"]
            previous_at = normalized_at

        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_RECEIPT_LEDGER_VALID",
            "backup_count": len(rows),
            "last_sequence": len(rows) if rows else None,
            "latest_backup_id": previous_backup_id,
            "chain_head_digest": previous_hash,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }


    def get_backup_receipt(self, backup_id: str) -> dict:
        """Return one verified aggregate lineage record without filesystem paths."""
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_ID_INVALID")
        self.verify()
        row = self._connection.execute(
            f'SELECT * FROM "{_TABLE}" WHERE backup_id = ?',
            (backup_id,),
        ).fetchone()
        if row is None:
            return {
                "status": "OBSERVER_FRESHNESS_BACKUP_RECEIPT_NOT_FOUND",
                "backup_id": backup_id,
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
            }
        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_RECEIPT_FOUND",
            "backup_count": row["sequence"],
            "backup_id": row["backup_id"],
            "file_sha256": row["file_sha256"],
            "source_receipt_count": row["receipt_count"],
            "source_status_counts": json.loads(row["status_counts_json"]),
            "last_source_sequence": row["last_sequence"],
            "source_chain_head_digest": row["chain_head_digest"],
            "predecessor_backup_id": row["predecessor_backup_id"],
            "record_hash": row["record_hash"],
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def list_backup_receipts(self) -> list[dict]:
        """Return a stable, verified snapshot of all backup lineage receipts.

        The result contains aggregate lineage metadata only. Recording timestamps,
        database paths, and backup payload bytes are deliberately omitted.
        """
        self._connection.execute("BEGIN")
        try:
            self.verify()
            rows = self._connection.execute(
                f'SELECT * FROM "{_TABLE}" ORDER BY sequence'
            ).fetchall()
            if len(rows) > MAX_BACKUP_RECEIPTS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_RECEIPT_CAPACITY_CORRUPT")
            result = [
                {
                    "backup_count": row["sequence"],
                    "backup_id": row["backup_id"],
                    "file_sha256": row["file_sha256"],
                    "source_receipt_count": row["receipt_count"],
                    "source_status_counts": json.loads(row["status_counts_json"]),
                    "last_source_sequence": row["last_sequence"],
                    "source_chain_head_digest": row["chain_head_digest"],
                    "predecessor_backup_id": row["predecessor_backup_id"],
                    "record_hash": row["record_hash"],
                    "execution_authorized": False,
                    "automatic_dispatch": False,
                    "automatic_retry": False,
                }
                for row in rows
            ]
            self._connection.commit()
            return result
        except Exception:
            self._connection.rollback()
            raise

    def recover_after_restart(self) -> dict:
        """Perform read-only integrity verification after reopening the ledger."""
        summary = self.verify()
        return {
            "recovery_status": "PASS",
            "backup_receipts_verified": summary["backup_count"],
            "last_sequence": summary["last_sequence"],
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
    "MAX_BACKUP_RECEIPTS",
    "ObserverFreshnessBackupReceiptCorruptionError",
    "ObserverFreshnessBackupReceiptError",
    "ObserverFreshnessBackupReceiptLedger",
]
