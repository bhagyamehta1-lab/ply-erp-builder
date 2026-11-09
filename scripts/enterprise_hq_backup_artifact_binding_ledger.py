"""Persistent, append-only receipts for verified backup-artifact metadata bindings.

The ledger stores only aggregate verification metadata. It deliberately omits
inventory IDs, observer backup IDs, file digests, filesystem paths, timestamps
from source artifacts, and raw payloads. It does not inspect or copy artifacts.
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
from collections.abc import Mapping

SCHEMA_VERSION = "1.0.0"
MAX_BINDING_RECEIPTS = 512
MAX_DATABASE_BYTES = 1024 * 1024
MAX_RECORDED_AT_CHARS = 64
_TABLE = "backup_artifact_binding_receipts"
_UPDATE_TRIGGER = "backup_artifact_binding_receipts_no_update"
_DELETE_TRIGGER = "backup_artifact_binding_receipts_no_delete"
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_RECEIPT_ID = re.compile(r"^hqbr_[a-f0-9]{24}$")
_INPUT_FIELDS = frozenset({
    "status", "binding_status", "binding_basis", "binding_digest",
    "inventory_record_count", "inventory_generation",
    "observer_backup_sequence", "availability_observation_sequence",
    "availability", "inventory_artifact_presence", "artifact_bytes_verified",
    "execution_authorized", "automatic_dispatch", "automatic_retry",
})
_COLUMNS = (
    ("sequence", "INTEGER", 0, 1),
    ("receipt_id", "TEXT", 1, 0),
    ("binding_digest", "TEXT", 1, 0),
    ("binding_status", "TEXT", 1, 0),
    ("binding_basis", "TEXT", 1, 0),
    ("inventory_record_count", "INTEGER", 1, 0),
    ("inventory_generation", "INTEGER", 1, 0),
    ("observer_backup_sequence", "INTEGER", 1, 0),
    ("availability_observation_sequence", "INTEGER", 1, 0),
    ("availability", "TEXT", 1, 0),
    ("inventory_artifact_presence", "TEXT", 1, 0),
    ("artifact_bytes_verified", "INTEGER", 1, 0),
    ("execution_authorized", "INTEGER", 1, 0),
    ("automatic_dispatch", "INTEGER", 1, 0),
    ("automatic_retry", "INTEGER", 1, 0),
    ("recorded_at", "TEXT", 1, 0),
    ("previous_hash", "TEXT", 0, 0),
    ("record_hash", "TEXT", 1, 0),
)
_CREATE_TABLE = """CREATE TABLE backup_artifact_binding_receipts (
    sequence INTEGER PRIMARY KEY CHECK (sequence BETWEEN 1 AND 512),
    receipt_id TEXT NOT NULL UNIQUE,
    binding_digest TEXT NOT NULL UNIQUE,
    binding_status TEXT NOT NULL CHECK (binding_status = 'METADATA_ASSOCIATION_VERIFIED'),
    binding_basis TEXT NOT NULL CHECK (binding_basis = 'EXPLICIT_CALLER_ASSOCIATION'),
    inventory_record_count INTEGER NOT NULL CHECK (inventory_record_count BETWEEN 1 AND 256),
    inventory_generation INTEGER NOT NULL CHECK (inventory_generation BETWEEN 1 AND 256),
    observer_backup_sequence INTEGER NOT NULL CHECK (observer_backup_sequence BETWEEN 1 AND 256),
    availability_observation_sequence INTEGER NOT NULL CHECK (availability_observation_sequence BETWEEN 1 AND 512),
    availability TEXT NOT NULL CHECK (availability = 'AVAILABLE'),
    inventory_artifact_presence TEXT NOT NULL CHECK (inventory_artifact_presence = 'NOT_INSPECTED'),
    artifact_bytes_verified INTEGER NOT NULL CHECK (artifact_bytes_verified = 0),
    execution_authorized INTEGER NOT NULL CHECK (execution_authorized = 0),
    automatic_dispatch INTEGER NOT NULL CHECK (automatic_dispatch = 0),
    automatic_retry INTEGER NOT NULL CHECK (automatic_retry = 0),
    recorded_at TEXT NOT NULL,
    previous_hash TEXT,
    record_hash TEXT NOT NULL UNIQUE
)"""
_CREATE_UPDATE_TRIGGER = """CREATE TRIGGER backup_artifact_binding_receipts_no_update
BEFORE UPDATE ON backup_artifact_binding_receipts
BEGIN SELECT RAISE(ABORT, 'BACKUP_ARTIFACT_BINDING_RECEIPT_APPEND_ONLY'); END"""
_CREATE_DELETE_TRIGGER = """CREATE TRIGGER backup_artifact_binding_receipts_no_delete
BEFORE DELETE ON backup_artifact_binding_receipts
BEGIN SELECT RAISE(ABORT, 'BACKUP_ARTIFACT_BINDING_RECEIPT_APPEND_ONLY'); END"""


class BackupArtifactBindingLedgerError(ValueError):
    """Invalid binding receipt input or bounded persistence operation."""


class BackupArtifactBindingLedgerCorruptionError(BackupArtifactBindingLedgerError):
    """Persisted binding receipt history failed independent verification."""


def _fail(code: str) -> None:
    raise BackupArtifactBindingLedgerError(code)


def _corrupt(code: str) -> None:
    raise BackupArtifactBindingLedgerCorruptionError(code)


def _canonical(value) -> str:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_ENCODING_INVALID")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _normalize_recorded_at(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RECORDED_AT_CHARS:
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED_AT_INVALID")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (TypeError, ValueError, OverflowError):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED_AT_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED_AT_INVALID")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _normalize_binding(result: Mapping) -> dict:
    if not isinstance(result, Mapping) or set(result) != _INPUT_FIELDS:
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_SCHEMA_INVALID")
    if (
        result.get("status") != "BACKUP_ARTIFACT_BINDING_VERIFIED"
        or result.get("binding_status") != "METADATA_ASSOCIATION_VERIFIED"
        or result.get("binding_basis") != "EXPLICIT_CALLER_ASSOCIATION"
        or result.get("availability") != "AVAILABLE"
        or result.get("inventory_artifact_presence") != "NOT_INSPECTED"
    ):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_STATUS_INVALID")
    digest = result.get("binding_digest")
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_DIGEST_INVALID")
    bounds = {
        "inventory_record_count": (1, 256),
        "inventory_generation": (1, 256),
        "observer_backup_sequence": (1, 256),
        "availability_observation_sequence": (1, 512),
    }
    normalized = {"binding_digest": digest}
    for field, (minimum, maximum) in bounds.items():
        value = result.get(field)
        if type(value) is not int or not minimum <= value <= maximum:
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_COUNT_INVALID")
        normalized[field] = value
    for field in (
        "artifact_bytes_verified", "execution_authorized",
        "automatic_dispatch", "automatic_retry",
    ):
        if result.get(field) is not False:
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_AUTHORIZATION_INVALID")
    normalized.update({
        "binding_status": "METADATA_ASSOCIATION_VERIFIED",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "availability": "AVAILABLE",
        "inventory_artifact_presence": "NOT_INSPECTED",
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    })
    return normalized


def _receipt_id(binding_digest: str) -> str:
    material = ("enterprise-hq-binding-receipt:v1:" + binding_digest).encode("ascii")
    return "hqbr_" + hashlib.sha256(material).hexdigest()[:24]


def _record_body(sequence: int, receipt_id: str, metadata: dict,
                 recorded_at: str, previous_hash: str | None) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "sequence": sequence,
        "receipt_id": receipt_id,
        **metadata,
        "recorded_at": recorded_at,
        "previous_hash": previous_hash,
    }


class BackupArtifactBindingLedger:
    """Bounded local ledger of metadata-only backup-artifact binding receipts.

    One receipt is retained per unique binding digest. Replaying the same verified
    binding is idempotent even if the retry supplies a later wall-clock time.
    The ledger never stores source identifiers, file digests, paths, or payloads.
    """

    def __init__(self, database: str):
        self._database = str(database)
        self._connection: sqlite3.Connection | None = None
        self._memory = self._database == ":memory:"
        path = None if self._memory else Path(self._database)
        if path is not None:
            absolute = path.absolute()
            for parent in (absolute, *absolute.parents):
                if parent.is_symlink():
                    _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_PATH_SYMLINK")
            existed = absolute.exists()
            if existed:
                info = absolute.lstat()
                if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_FILE_INVALID")
                if info.st_size > MAX_DATABASE_BYTES:
                    _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_DATABASE_TOO_LARGE")
                if stat.S_IMODE(info.st_mode) & 0o077:
                    _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_PERMISSIONS_INVALID")
        else:
            existed = True
        try:
            self._connection = sqlite3.connect(self._database, timeout=5)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA max_page_count=256")
            if self._memory or not existed:
                self._connection.executescript(
                    _CREATE_TABLE + ";" + _CREATE_UPDATE_TRIGGER + ";" + _CREATE_DELETE_TRIGGER + ";"
                )
            if path is not None and not existed:
                os.chmod(path, 0o600)
            self._validate_database_file()
            self._validate_schema()
        except Exception:
            self.close()
            raise

    def _validate_database_file(self) -> None:
        if self._memory:
            return
        path = Path(self._database)
        if path.is_symlink() or not path.is_file():
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_FILE_INVALID")
        info = path.stat()
        if info.st_size > MAX_DATABASE_BYTES:
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_DATABASE_TOO_LARGE")
        if stat.S_IMODE(info.st_mode) & 0o077:
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_PERMISSIONS_INVALID")
        pages = self._connection.execute("PRAGMA page_count").fetchone()[0]
        if pages > 256:
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_PAGE_LIMIT_EXCEEDED")

    def _validate_schema(self) -> None:
        self._validate_database_file()
        integrity = self._connection.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_SQLITE_INTEGRITY_FAILED")
        tables = {
            row["name"] for row in self._connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if tables != {_TABLE}:
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TABLE_SET_INVALID")
        columns = tuple(
            (row["name"], row["type"].upper(), row["notnull"], row["pk"])
            for row in self._connection.execute(f"PRAGMA table_info({_TABLE})")
        )
        if columns != _COLUMNS:
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_COLUMNS_INVALID")
        table_sql = self._connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
        ).fetchone()
        normalize_sql = lambda value: " ".join((value or "").upper().split())
        if table_sql is None or normalize_sql(table_sql["sql"]) != normalize_sql(_CREATE_TABLE):
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TABLE_CONSTRAINTS_INVALID")
        triggers = {
            row["name"]: row["sql"] for row in self._connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='trigger'"
            )
        }
        if set(triggers) != {_UPDATE_TRIGGER, _DELETE_TRIGGER}:
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TRIGGER_SET_INVALID")
        for name, required in (
            (_UPDATE_TRIGGER, "BEFORE UPDATE ON " + _TABLE),
            (_DELETE_TRIGGER, "BEFORE DELETE ON " + _TABLE),
        ):
            sql = " ".join((triggers[name] or "").upper().split())
            if required.upper() not in sql or "RAISE(ABORT" not in sql:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TRIGGER_INVALID")
        custom_indexes = self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND sql IS NOT NULL"
        ).fetchall()
        if custom_indexes:
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_INDEX_SET_INVALID")

    @staticmethod
    def _metadata_from_row(row: sqlite3.Row) -> dict:
        for field in (
            "artifact_bytes_verified", "execution_authorized",
            "automatic_dispatch", "automatic_retry",
        ):
            if type(row[field]) is not int or row[field] != 0:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_AUTHORIZATION_INVALID")
        return {
            "binding_digest": row["binding_digest"],
            "binding_status": row["binding_status"],
            "binding_basis": row["binding_basis"],
            "inventory_record_count": row["inventory_record_count"],
            "inventory_generation": row["inventory_generation"],
            "observer_backup_sequence": row["observer_backup_sequence"],
            "availability_observation_sequence": row["availability_observation_sequence"],
            "availability": row["availability"],
            "inventory_artifact_presence": row["inventory_artifact_presence"],
            "artifact_bytes_verified": row["artifact_bytes_verified"] == 1,
            "execution_authorized": row["execution_authorized"] == 1,
            "automatic_dispatch": row["automatic_dispatch"] == 1,
            "automatic_retry": row["automatic_retry"] == 1,
        }

    def _response(self, row: sqlite3.Row, *, created: bool, replayed: bool) -> dict:
        return {
            "status": (
                "BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED" if created
                else "BACKUP_ARTIFACT_BINDING_RECEIPT_REPLAYED" if replayed
                else "BACKUP_ARTIFACT_BINDING_RECEIPT_FOUND"
            ),
            "receipt_id": row["receipt_id"],
            "sequence": row["sequence"],
            "binding_digest": row["binding_digest"],
            "record_hash": row["record_hash"],
            "recorded_at": row["recorded_at"],
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def append_verified_binding(self, result: Mapping, *, recorded_at: str | None = None) -> dict:
        """Persist one successful metadata association; never persist failed checks."""
        metadata = _normalize_binding(result)
        normalized_at = _normalize_recorded_at(
            recorded_at if recorded_at is not None
            else datetime.now(timezone.utc).isoformat()
        )
        self._validate_schema()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self.verify()
            existing = self._connection.execute(
                f"SELECT * FROM {_TABLE} WHERE binding_digest = ?",
                (metadata["binding_digest"],),
            ).fetchone()
            if existing is not None:
                if self._metadata_from_row(existing) != metadata:
                    _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_CONFLICT")
                self._connection.commit()
                return self._response(existing, created=False, replayed=True)
            previous = self._connection.execute(
                f"SELECT sequence, record_hash, recorded_at FROM {_TABLE} ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            count = self._connection.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()[0]
            if count >= MAX_BINDING_RECEIPTS:
                _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_CAPACITY_REACHED")
            sequence = count + 1
            if previous is not None and normalized_at < previous["recorded_at"]:
                _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_TIME_REGRESSION")
            receipt_id = _receipt_id(metadata["binding_digest"])
            previous_hash = None if previous is None else previous["record_hash"]
            body = _record_body(sequence, receipt_id, metadata, normalized_at, previous_hash)
            record_hash = _digest(body)
            self._connection.execute(
                f"""INSERT INTO {_TABLE} (
                    sequence, receipt_id, binding_digest, binding_status, binding_basis,
                    inventory_record_count, inventory_generation, observer_backup_sequence,
                    availability_observation_sequence, availability, inventory_artifact_presence,
                    artifact_bytes_verified, execution_authorized, automatic_dispatch,
                    automatic_retry, recorded_at, previous_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sequence, receipt_id, metadata["binding_digest"], metadata["binding_status"],
                    metadata["binding_basis"], metadata["inventory_record_count"],
                    metadata["inventory_generation"], metadata["observer_backup_sequence"],
                    metadata["availability_observation_sequence"], metadata["availability"],
                    metadata["inventory_artifact_presence"], 0, 0, 0, 0,
                    normalized_at, previous_hash, record_hash,
                ),
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        row = self._connection.execute(
            f"SELECT * FROM {_TABLE} WHERE binding_digest = ?",
            (metadata["binding_digest"],),
        ).fetchone()
        return self._response(row, created=True, replayed=False)

    def verify(self) -> dict:
        """Independently verify the complete append-only binding receipt history."""
        self._validate_schema()
        rows = self._connection.execute(f"SELECT * FROM {_TABLE} ORDER BY sequence").fetchall()
        if len(rows) > MAX_BINDING_RECEIPTS:
            _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_CAPACITY_EXCEEDED")
        previous_hash = None
        previous_at = None
        for expected_sequence, row in enumerate(rows, 1):
            if row["sequence"] != expected_sequence:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_SEQUENCE_INVALID")
            metadata = self._metadata_from_row(row)
            try:
                normalized = _normalize_binding({
                    "status": "BACKUP_ARTIFACT_BINDING_VERIFIED",
                    **metadata,
                })
                recorded_at = _normalize_recorded_at(row["recorded_at"])
            except BackupArtifactBindingLedgerError:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_METADATA_INVALID")
            if recorded_at != row["recorded_at"]:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TIME_INVALID")
            if previous_at is not None and recorded_at < previous_at:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_TIME_REGRESSION")
            expected_id = _receipt_id(normalized["binding_digest"])
            if row["receipt_id"] != expected_id:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_ID_INVALID")
            if row["previous_hash"] != previous_hash:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_CHAIN_LINK_INVALID")
            body = _record_body(expected_sequence, expected_id, normalized, recorded_at, previous_hash)
            if not isinstance(row["record_hash"], str) or not _HEX_64.fullmatch(row["record_hash"]):
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_HASH_INVALID")
            if _digest(body) != row["record_hash"]:
                _corrupt("BACKUP_ARTIFACT_BINDING_RECEIPT_HASH_MISMATCH")
            previous_hash = row["record_hash"]
            previous_at = recorded_at
        return {
            "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_LEDGER_VALID",
            "receipt_count": len(rows),
            "last_sequence": len(rows) if rows else None,
            "chain_head_hash": previous_hash,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def get_receipt(self, binding_digest: str) -> dict:
        """Return one aggregate-only receipt for a validated binding digest."""
        if not isinstance(binding_digest, str) or not _HEX_64.fullmatch(binding_digest):
            _fail("BACKUP_ARTIFACT_BINDING_RECEIPT_DIGEST_INVALID")
        self.verify()
        row = self._connection.execute(
            f"SELECT * FROM {_TABLE} WHERE binding_digest = ?", (binding_digest,)
        ).fetchone()
        if row is None:
            return {
                "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_NOT_FOUND",
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
            }
        return self._response(row, created=False, replayed=False)

    def list_receipts(self) -> list[dict]:
        """Return bounded receipt summaries after verifying the entire history."""
        self._connection.execute("BEGIN")
        try:
            self.verify()
            rows = self._connection.execute(f"SELECT * FROM {_TABLE} ORDER BY sequence").fetchall()
            result = [self._response(row, created=False, replayed=False) for row in rows]
            self._connection.commit()
            return result
        except Exception:
            self._connection.rollback()
            raise

    def export_verification_snapshot(self) -> dict:
        """Export a bounded, metadata-only snapshot for an independent verifier.

        The snapshot contains canonical receipt fields and hash-chain links, but
        never source backup identifiers, file digests, paths, or artifact bytes.
        A read transaction keeps the exported rows on one consistent snapshot.
        """
        self._connection.execute("BEGIN")
        try:
            self.verify()
            rows = self._connection.execute(
                f"SELECT * FROM {_TABLE} ORDER BY sequence"
            ).fetchall()
            records = []
            for row in rows:
                body = _record_body(
                    row["sequence"],
                    row["receipt_id"],
                    self._metadata_from_row(row),
                    row["recorded_at"],
                    row["previous_hash"],
                )
                records.append({**body, "record_hash": row["record_hash"]})
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        return {
            "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_SNAPSHOT_EXPORTED",
            "schema_version": SCHEMA_VERSION,
            "receipt_count": len(records),
            "records": records,
            "execution_authorized": False,
            "automatic_dispatch": False,
            "automatic_retry": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify persisted receipt history without resuming or dispatching work."""
        summary = self.verify()
        return {
            "status": "BACKUP_ARTIFACT_BINDING_RECEIPT_RECOVERY_VERIFIED",
            "receipt_count": summary["receipt_count"],
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
    "BackupArtifactBindingLedger",
    "BackupArtifactBindingLedgerError",
    "BackupArtifactBindingLedgerCorruptionError",
]
