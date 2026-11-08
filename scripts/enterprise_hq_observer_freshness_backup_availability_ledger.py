"""Append-only history for read-only observer backup availability checks.

This ledger stores only bounded aggregate outcomes. It never stores caller paths,
raw backup bytes, source receipt payloads, or execution instructions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

SCHEMA_VERSION = 1
MAX_OBSERVATIONS = 512
MAX_DATABASE_BYTES = 1024 * 1024
_TABLE = "observer_freshness_backup_availability_observations"
_UPDATE_TRIGGER = "observer_freshness_backup_availability_no_update"
_DELETE_TRIGGER = "observer_freshness_backup_availability_no_delete"
_BACKUP_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_AVAILABILITY_STATUS = {
    "AVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
    "MISSING": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING",
    "UNAVAILABLE": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
    "INVALID": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_INVALID",
    "MISMATCH": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISMATCH",
    "UNKNOWN": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
}
_COMMON_FIELDS = {
    "status", "availability", "execution_authorized", "automatic_dispatch",
    "automatic_retry", "backup_id", "lineage_sequence", "lineage_record_hash",
}
_AVAILABLE_FIELDS = {
    "file_sha256", "source_receipt_count", "source_status_counts",
    "last_source_sequence", "source_chain_head_digest",
    "backup_integrity_verified", "lineage_match_verified",
}
_COLUMNS = (
    ("sequence", "INTEGER", 0, 1),
    ("observation_id", "TEXT", 1, 0),
    ("backup_id", "TEXT", 1, 0),
    ("availability", "TEXT", 1, 0),
    ("status", "TEXT", 1, 0),
    ("lineage_sequence", "INTEGER", 0, 0),
    ("lineage_record_hash", "TEXT", 0, 0),
    ("file_sha256", "TEXT", 0, 0),
    ("source_receipt_count", "INTEGER", 0, 0),
    ("source_status_counts_json", "TEXT", 0, 0),
    ("last_source_sequence", "INTEGER", 0, 0),
    ("source_chain_head_digest", "TEXT", 0, 0),
    ("recorded_at", "TEXT", 1, 0),
    ("previous_hash", "TEXT", 0, 0),
    ("record_hash", "TEXT", 1, 0),
)
_CREATE_TABLE = """CREATE TABLE observer_freshness_backup_availability_observations (
    sequence INTEGER PRIMARY KEY CHECK (sequence BETWEEN 1 AND 512),
    observation_id TEXT NOT NULL UNIQUE,
    backup_id TEXT NOT NULL,
    availability TEXT NOT NULL CHECK (availability IN
        ('AVAILABLE','MISSING','UNAVAILABLE','INVALID','MISMATCH','UNKNOWN')),
    status TEXT NOT NULL,
    lineage_sequence INTEGER,
    lineage_record_hash TEXT,
    file_sha256 TEXT,
    source_receipt_count INTEGER,
    source_status_counts_json TEXT,
    last_source_sequence INTEGER,
    source_chain_head_digest TEXT,
    recorded_at TEXT NOT NULL,
    previous_hash TEXT,
    record_hash TEXT NOT NULL UNIQUE
)"""
_CREATE_UPDATE_TRIGGER = """CREATE TRIGGER observer_freshness_backup_availability_no_update
BEFORE UPDATE ON observer_freshness_backup_availability_observations
BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_APPEND_ONLY'); END"""
_CREATE_DELETE_TRIGGER = """CREATE TRIGGER observer_freshness_backup_availability_no_delete
BEFORE DELETE ON observer_freshness_backup_availability_observations
BEGIN SELECT RAISE(ABORT, 'OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_APPEND_ONLY'); END"""


class ObserverFreshnessBackupAvailabilityLedgerError(ValueError):
    """Invalid availability observation or ledger operation."""


class ObserverFreshnessBackupAvailabilityLedgerCorruptionError(
    ObserverFreshnessBackupAvailabilityLedgerError
):
    """Persisted availability observation history failed verification."""


def _fail(code: str) -> None:
    raise ObserverFreshnessBackupAvailabilityLedgerError(code)


def _corrupt(code: str) -> None:
    raise ObserverFreshnessBackupAvailabilityLedgerCorruptionError(code)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _normalize_recorded_at(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECORDED_AT_INVALID")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECORDED_AT_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECORDED_AT_INVALID")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalize_result(result: Mapping) -> dict:
    if not isinstance(result, Mapping):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RESULT_INVALID")
    availability = result.get("availability")
    if availability not in _AVAILABILITY_STATUS:
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_STATUS_INVALID")
    expected = _COMMON_FIELDS | (_AVAILABLE_FIELDS if availability == "AVAILABLE" else set())
    if set(result) != expected:
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RESULT_SCHEMA_INVALID")
    if result.get("status") != _AVAILABILITY_STATUS[availability]:
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_STATUS_MISMATCH")
    if any(result.get(flag) is not False for flag in (
        "execution_authorized", "automatic_dispatch", "automatic_retry"
    )):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_AUTHORIZATION_INVALID")
    backup_id = result.get("backup_id")
    if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_ID_INVALID")

    lineage_sequence = result.get("lineage_sequence")
    lineage_hash = result.get("lineage_record_hash")
    if availability == "UNKNOWN":
        if lineage_sequence is not None or lineage_hash is not None:
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNKNOWN_LINEAGE_INVALID")
    elif (
        type(lineage_sequence) is not int or lineage_sequence < 1
        or not isinstance(lineage_hash, str) or not _HEX_64.fullmatch(lineage_hash)
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_LINEAGE_INVALID")

    normalized = {
        "backup_id": backup_id,
        "availability": availability,
        "status": result["status"],
        "lineage_sequence": lineage_sequence,
        "lineage_record_hash": lineage_hash,
    }
    if availability != "AVAILABLE":
        return normalized

    file_digest = result.get("file_sha256")
    count = result.get("source_receipt_count")
    counts = result.get("source_status_counts")
    last_sequence = result.get("last_source_sequence")
    chain_head = result.get("source_chain_head_digest")
    if (
        not isinstance(file_digest, str) or not _HEX_64.fullmatch(file_digest)
        or type(count) is not int or not 0 <= count <= 512
        or not isinstance(counts, dict)
        or any(
            not isinstance(key, str) or not re.fullmatch(r"[A-Z_]{1,32}", key)
            or type(value) is not int or value <= 0
            for key, value in counts.items()
        )
        or sum(counts.values()) != count
        or result.get("backup_integrity_verified") is not True
        or result.get("lineage_match_verified") is not True
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_EVIDENCE_INVALID")
    if count == 0:
        if counts or last_sequence is not None or chain_head is not None:
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_EMPTY_SUMMARY_INVALID")
    elif (
        type(last_sequence) is not int or last_sequence != count
        or not isinstance(chain_head, str) or not _HEX_64.fullmatch(chain_head)
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CHAIN_SUMMARY_INVALID")
    normalized.update({
        "file_sha256": file_digest,
        "source_receipt_count": count,
        "source_status_counts": dict(sorted(counts.items())),
        "last_source_sequence": last_sequence,
        "source_chain_head_digest": chain_head,
    })
    return normalized


def _observation_id(metadata: dict, recorded_at: str) -> str:
    identity = {"schema_version": SCHEMA_VERSION, **metadata, "recorded_at": recorded_at}
    return "hqba_" + _digest(identity)[:24]


def _record_body(
    sequence: int, observation_id: str, metadata: dict,
    recorded_at: str, previous_hash: str | None,
) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "observation_id": observation_id,
        **metadata,
        "recorded_at": recorded_at,
        "previous_hash": previous_hash,
    }


class ObserverFreshnessBackupAvailabilityLedger:
    """Bounded append-only ledger for sanitized backup availability observations."""

    def __init__(self, database: str):
        if not isinstance(database, (str, os.PathLike)):
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_INVALID")
        raw = os.fspath(database)
        if not raw or raw == ":memory:":
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_INVALID")
        self._path = Path(raw)
        try:
            parent = self._path.parent.lstat()
        except OSError:
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_PARENT_INVALID")
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_PARENT_INVALID")

        created = False
        try:
            metadata = self._path.lstat()
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    self._path,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR,
                    0o600,
                )
                os.close(descriptor)
                created = True
            except OSError:
                _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_CREATE_FAILED")
        except OSError:
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_UNAVAILABLE")

        try:
            metadata = self._path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not stat.S_IMODE(metadata.st_mode) & 0o600 == 0o600
                or metadata.st_size > MAX_DATABASE_BYTES
            ):
                _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_INVALID")
            uri = self._path.resolve(strict=True).as_uri() + "?mode=rw"
            self._connection = sqlite3.connect(uri, uri=True, timeout=5.0)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA busy_timeout = 5000")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA synchronous = FULL")
            if created:
                self._create_schema()
            else:
                self._validate_schema()
        except Exception:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            if created:
                try:
                    self._path.unlink()
                except OSError:
                    pass
            raise

    def _create_schema(self) -> None:
        self._connection.executescript(
            _CREATE_TABLE + ";" + _CREATE_UPDATE_TRIGGER + ";" + _CREATE_DELETE_TRIGGER + ";"
        )
        self._connection.commit()
        self._validate_schema()

    def _validate_schema(self) -> None:
        try:
            metadata = self._path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size > MAX_DATABASE_BYTES
            ):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_INVALID")
            objects = self._connection.execute(
                "SELECT type, name, sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            expected = {
                ("table", _TABLE),
                ("trigger", _UPDATE_TRIGGER),
                ("trigger", _DELETE_TRIGGER),
            }
            if {(row["type"], row["name"]) for row in objects} != expected:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_SCHEMA_INVALID")
            expected_sql = {
                ("table", _TABLE): _CREATE_TABLE,
                ("trigger", _UPDATE_TRIGGER): _CREATE_UPDATE_TRIGGER,
                ("trigger", _DELETE_TRIGGER): _CREATE_DELETE_TRIGGER,
            }
            for row in objects:
                actual = " ".join((row["sql"] or "").split()).rstrip(";")
                wanted = " ".join(expected_sql[(row["type"], row["name"])].split()).rstrip(";")
                if actual != wanted:
                    _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_SCHEMA_INVALID")
            columns = self._connection.execute(
                f"PRAGMA table_info({_TABLE})"
            ).fetchall()
            actual_columns = tuple(
                (row["name"], row["type"].upper(), row["notnull"], row["pk"])
                for row in columns
            )
            if actual_columns != _COLUMNS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_COLUMNS_INVALID")
            integrity = self._connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_SQLITE_INTEGRITY_FAILED")
            page_count = self._connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = self._connection.execute("PRAGMA page_size").fetchone()[0]
            if page_count * page_size > MAX_DATABASE_BYTES:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_DATABASE_LIMIT_EXCEEDED")
        except ObserverFreshnessBackupAvailabilityLedgerCorruptionError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError):
            _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_SCHEMA_INVALID")

    @staticmethod
    def _metadata_from_row(row) -> dict:
        metadata = {
            "backup_id": row["backup_id"],
            "availability": row["availability"],
            "status": row["status"],
            "lineage_sequence": row["lineage_sequence"],
            "lineage_record_hash": row["lineage_record_hash"],
        }
        if row["availability"] == "AVAILABLE":
            try:
                counts = json.loads(row["source_status_counts_json"])
            except (TypeError, ValueError):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_COUNTS_INVALID")
            if _canonical(counts) != row["source_status_counts_json"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_COUNTS_ENCODING_INVALID")
            metadata.update({
                "file_sha256": row["file_sha256"],
                "source_receipt_count": row["source_receipt_count"],
                "source_status_counts": counts,
                "last_source_sequence": row["last_source_sequence"],
                "source_chain_head_digest": row["source_chain_head_digest"],
            })
        elif any(row[field] is not None for field in (
            "file_sha256", "source_receipt_count", "source_status_counts_json",
            "last_source_sequence", "source_chain_head_digest",
        )):
            _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNEXPECTED_EVIDENCE")
        return metadata

    @staticmethod
    def _response(row, *, created: bool, replayed: bool) -> dict:
        result = {
            "status": (
                "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_OBSERVATION_RECORDED"
                if created else "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_OBSERVATION_REPLAYED"
            ),
            "observation_id": row["observation_id"],
            "backup_id": row["backup_id"],
            "availability": row["availability"],
            "sequence": row["sequence"],
            "record_hash": row["record_hash"],
            "recorded_at": row["recorded_at"],
            "created": created,
            "already_present": replayed,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }
        if row["availability"] == "AVAILABLE":
            result["file_sha256"] = row["file_sha256"]
            result["source_receipt_count"] = row["source_receipt_count"]
        return result

    def append_observation(self, result: Mapping, *, recorded_at: str) -> dict:
        """Append one normalized observation; an exact replay is idempotent."""
        metadata = _normalize_result(result)
        normalized_at = _normalize_recorded_at(recorded_at)
        observation_id = _observation_id(metadata, normalized_at)
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self.verify()
            existing = self._connection.execute(
                f"SELECT * FROM {_TABLE} WHERE observation_id = ?",
                (observation_id,),
            ).fetchone()
            if existing is not None:
                if (
                    self._metadata_from_row(existing) != metadata
                    or existing["recorded_at"] != normalized_at
                ):
                    _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_ID_CONFLICT")
                self._connection.commit()
                return self._response(existing, created=False, replayed=True)

            previous = self._connection.execute(
                f"SELECT sequence, record_hash, recorded_at FROM {_TABLE} "
                "ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            count = self._connection.execute(
                f"SELECT COUNT(*) FROM {_TABLE}"
            ).fetchone()[0]
            if count >= MAX_OBSERVATIONS:
                _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CAPACITY_REACHED")
            if previous is not None and normalized_at < previous["recorded_at"]:
                _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_TIME_REGRESSION")
            sequence = count + 1
            previous_hash = None if previous is None else previous["record_hash"]
            body = _record_body(
                sequence, observation_id, metadata, normalized_at, previous_hash
            )
            record_hash = _digest(body)
            counts_json = (
                _canonical(metadata["source_status_counts"])
                if metadata["availability"] == "AVAILABLE" else None
            )
            self._connection.execute(
                f"""INSERT INTO {_TABLE} (
                    sequence, observation_id, backup_id, availability, status,
                    lineage_sequence, lineage_record_hash, file_sha256,
                    source_receipt_count, source_status_counts_json,
                    last_source_sequence, source_chain_head_digest, recorded_at,
                    previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence, observation_id, metadata["backup_id"],
                    metadata["availability"], metadata["status"],
                    metadata["lineage_sequence"], metadata["lineage_record_hash"],
                    metadata.get("file_sha256"), metadata.get("source_receipt_count"),
                    counts_json, metadata.get("last_source_sequence"),
                    metadata.get("source_chain_head_digest"), normalized_at,
                    previous_hash, record_hash,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        row = self._connection.execute(
            f"SELECT * FROM {_TABLE} WHERE observation_id = ?", (observation_id,)
        ).fetchone()
        return self._response(row, created=True, replayed=False)

    def verify(self) -> dict:
        """Verify the complete append-only observation history."""
        self._validate_schema()
        rows = self._connection.execute(
            f"SELECT * FROM {_TABLE} ORDER BY sequence"
        ).fetchall()
        if len(rows) > MAX_OBSERVATIONS:
            _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CAPACITY_EXCEEDED")
        previous_hash = None
        previous_at = None
        counts = {key: 0 for key in _AVAILABILITY_STATUS}
        for expected_sequence, row in enumerate(rows, 1):
            if row["sequence"] != expected_sequence:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_SEQUENCE_INVALID")
            metadata = self._metadata_from_row(row)
            try:
                normalized = _normalize_result({
                    **metadata,
                    "execution_authorized": False,
                    "automatic_dispatch": False,
                    "automatic_retry": False,
                    **({
                        "backup_integrity_verified": True,
                        "lineage_match_verified": True,
                    } if metadata["availability"] == "AVAILABLE" else {}),
                })
                recorded_at = _normalize_recorded_at(row["recorded_at"])
            except ObserverFreshnessBackupAvailabilityLedgerError:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_METADATA_INVALID")
            if recorded_at != row["recorded_at"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_TIME_INVALID")
            if previous_at is not None and recorded_at < previous_at:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_TIME_REGRESSION")
            expected_id = _observation_id(normalized, recorded_at)
            if row["observation_id"] != expected_id:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_ID_INVALID")
            if row["previous_hash"] != previous_hash:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CHAIN_LINK_INVALID")
            body = _record_body(
                expected_sequence, expected_id, normalized, recorded_at, previous_hash
            )
            if not isinstance(row["record_hash"], str) or not _HEX_64.fullmatch(row["record_hash"]):
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECORD_HASH_INVALID")
            if _digest(body) != row["record_hash"]:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECORD_HASH_MISMATCH")
            previous_hash = row["record_hash"]
            previous_at = recorded_at
            counts[normalized["availability"]] += 1
        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_LEDGER_VALID",
            "observation_count": len(rows),
            "availability_counts": counts,
            "last_sequence": len(rows) if rows else None,
            "chain_head_hash": previous_hash,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def get_latest_for_backup(self, backup_id: str) -> dict:
        """Return the latest aggregate availability observation for one backup."""
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_ID_INVALID")
        self.verify()
        row = self._connection.execute(
            f"SELECT * FROM {_TABLE} WHERE backup_id = ? ORDER BY sequence DESC LIMIT 1",
            (backup_id,),
        ).fetchone()
        if row is None:
            return {
                "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_OBSERVATION_NOT_FOUND",
                "backup_id": backup_id,
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
            }
        result = self._response(row, created=False, replayed=False)
        result["status"] = "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_LATEST_OBSERVATION"
        return result

    def list_latest_observations(self) -> list[dict]:
        """Return one verified, aggregate-only latest observation per backup.

        The entire history is verified first. Results omit timestamps, paths, and
        raw payloads so callers can reconcile ledgers without exposing file details.
        """
        self._connection.execute("BEGIN")
        try:
            self.verify()
            rows = self._connection.execute(
                f"""SELECT * FROM {_TABLE}
                    WHERE sequence IN (
                        SELECT MAX(sequence) FROM {_TABLE} GROUP BY backup_id
                    )
                    ORDER BY backup_id"""
            ).fetchall()
            if len(rows) > MAX_OBSERVATIONS:
                _corrupt("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_CAPACITY_EXCEEDED")
            result = []
            for row in rows:
                result.append({
                    **self._metadata_from_row(row),
                    "observation_id": row["observation_id"],
                    "sequence": row["sequence"],
                    "record_hash": row["record_hash"],
                    "execution_authorized": False,
                    "automatic_dispatch": False,
                    "automatic_retry": False,
                })
            self._connection.commit()
            return result
        except Exception:
            self._connection.rollback()
            raise

    def recover_after_restart(self) -> dict:
        """Verify persisted availability history without resuming any operation."""
        summary = self.verify()
        return {
            "status": "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECOVERY_VERIFIED",
            "observation_count": summary["observation_count"],
            "last_sequence": summary["last_sequence"],
            "chain_head_hash": summary["chain_head_hash"],
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


__all__ = [
    "ObserverFreshnessBackupAvailabilityLedger",
    "ObserverFreshnessBackupAvailabilityLedgerError",
    "ObserverFreshnessBackupAvailabilityLedgerCorruptionError",
]
