"""Verified local SQLite backup and restore for sanitized observer-freshness history.

This module operates only on caller-supplied local paths. It performs no network
access, does not inspect private governance files, and never authorizes execution.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import tempfile
from pathlib import Path
from urllib.parse import quote

from scripts.enterprise_hq_observer_freshness_ledger import (
    MAX_DATABASE_BYTES,
    MAX_OBSERVER_FRESHNESS_RECEIPTS,
    ObserverFreshnessLedger,
)

_EXPECTED_TABLE = "observer_freshness_receipts"
_EXPECTED_TRIGGERS = {
    "observer_freshness_receipts_no_update",
    "observer_freshness_receipts_no_delete",
}
_EXPECTED_COLUMNS = (
    "sequence", "receipt_id", "recorded_at", "receipt_json",
    "decision_digest", "previous_hash", "record_hash",
)
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class ObserverFreshnessBackupError(ValueError):
    """Stable fail-closed error for local freshness-ledger backup and restore."""


def _fail(code: str) -> None:
    raise ObserverFreshnessBackupError(code)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.abspath(os.fspath(left)) == os.path.abspath(os.fspath(right))


def _new_destination(value, *, source: Path | None = None) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _fail("OBSERVER_FRESHNESS_BACKUP_DESTINATION_INVALID")
    raw = os.fspath(value)
    if not raw or raw == ":memory:":
        _fail("OBSERVER_FRESHNESS_BACKUP_DESTINATION_INVALID")
    path = Path(raw)
    if source is not None and _same_path(path, source):
        _fail("OBSERVER_FRESHNESS_BACKUP_SOURCE_DESTINATION_SAME")
    if path.is_symlink() or path.exists():
        _fail("OBSERVER_FRESHNESS_BACKUP_DESTINATION_EXISTS")
    if path.parent.is_symlink() or not path.parent.exists() or not path.parent.is_dir():
        _fail("OBSERVER_FRESHNESS_BACKUP_PARENT_INVALID")
    return path


def _existing_database_path(value) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_PATH_INVALID")
    raw = os.fspath(value)
    if not raw or raw == ":memory:":
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_PATH_INVALID")
    path = Path(raw)
    if path.is_symlink() or path.parent.is_symlink():
        _fail("OBSERVER_FRESHNESS_BACKUP_SYMLINK_FORBIDDEN")
    try:
        mode = path.lstat().st_mode
        size = path.stat().st_size
    except OSError:
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_UNAVAILABLE")
    if not stat.S_ISREG(mode):
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_NOT_REGULAR")
    if stat.S_IMODE(mode) & 0o077:
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_PERMISSIONS_INVALID")
    if size <= 0 or size > MAX_DATABASE_BYTES:
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_SIZE_INVALID")
    return path


def _validate_database_file(value) -> None:
    path = _existing_database_path(value)
    try:
        resolved = path.resolve(strict=True)
        uri = "file:" + quote(str(resolved), safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                _fail("OBSERVER_FRESHNESS_BACKUP_SQLITE_INTEGRITY_INVALID")
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != 1:
                _fail("OBSERVER_FRESHNESS_BACKUP_SCHEMA_VERSION_INVALID")
            tables = [
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            if tables != [_EXPECTED_TABLE]:
                _fail("OBSERVER_FRESHNESS_BACKUP_TABLE_SCHEMA_INVALID")
            views = connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='view'"
            ).fetchone()[0]
            if views != 0:
                _fail("OBSERVER_FRESHNESS_BACKUP_VIEW_FORBIDDEN")
            triggers = {
                row[0]: row[1] or "" for row in connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
                )
            }
            if set(triggers) != _EXPECTED_TRIGGERS:
                _fail("OBSERVER_FRESHNESS_BACKUP_TRIGGER_SCHEMA_INVALID")
            for name, sql in triggers.items():
                normalized = " ".join(sql.upper().split())
                operation = "BEFORE UPDATE ON" if name.endswith("no_update") else "BEFORE DELETE ON"
                if (
                    operation + " " + _EXPECTED_TABLE.upper() not in normalized
                    or "RAISE(ABORT" not in normalized
                    or "OBSERVER_FRESHNESS_LEDGER_APPEND_ONLY" not in normalized
                ):
                    _fail("OBSERVER_FRESHNESS_BACKUP_TRIGGER_POLICY_INVALID")
            columns = tuple(
                row[1] for row in connection.execute(
                    f'PRAGMA table_info("{_EXPECTED_TABLE}")'
                )
            )
            if columns != _EXPECTED_COLUMNS:
                _fail("OBSERVER_FRESHNESS_BACKUP_COLUMN_SCHEMA_INVALID")
            count = connection.execute(
                f'SELECT COUNT(*) FROM "{_EXPECTED_TABLE}"'
            ).fetchone()[0]
            if type(count) is not int or not 0 <= count <= MAX_OBSERVER_FRESHNESS_RECEIPTS:
                _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_COUNT_INVALID")
            page_count = connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            if type(page_count) is not int or type(page_size) is not int:
                _fail("OBSERVER_FRESHNESS_BACKUP_PAGE_METADATA_INVALID")
            if page_count * page_size > MAX_DATABASE_BYTES:
                _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_SIZE_INVALID")
        finally:
            connection.close()
    except ObserverFreshnessBackupError:
        raise
    except (OSError, sqlite3.Error, ValueError):
        _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_INVALID")


def _extract_summary(result: dict) -> dict:
    if not isinstance(result, dict) or result.get("status") != "OBSERVER_FRESHNESS_LEDGER_VALID":
        _fail("OBSERVER_FRESHNESS_BACKUP_LEDGER_VERIFICATION_FAILED")
    for flag in ("execution_authorized", "automatic_dispatch", "automatic_retry"):
        if result.get(flag) is not False:
            _fail("OBSERVER_FRESHNESS_BACKUP_AUTHORITY_INVARIANT_FAILED")
    count = result.get("receipt_count")
    counts = result.get("status_counts")
    last = result.get("last_sequence")
    head = result.get("chain_head_digest")
    if type(count) is not int or not 0 <= count <= MAX_OBSERVER_FRESHNESS_RECEIPTS:
        _fail("OBSERVER_FRESHNESS_BACKUP_RECEIPT_COUNT_INVALID")
    if not isinstance(counts, dict) or any(
        not isinstance(key, str) or type(value) is not int or value <= 0
        for key, value in counts.items()
    ) or sum(counts.values()) != count:
        _fail("OBSERVER_FRESHNESS_BACKUP_STATUS_COUNTS_INVALID")
    if count == 0:
        if last is not None or head is not None or counts:
            _fail("OBSERVER_FRESHNESS_BACKUP_EMPTY_SUMMARY_INVALID")
    elif (
        type(last) is not int or last != count
        or not isinstance(head, str) or not _HEX_64.fullmatch(head)
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_CHAIN_HEAD_INVALID")
    return {
        "receipt_count": count,
        "status_counts": dict(sorted(counts.items())),
        "last_sequence": last,
        "chain_head_digest": head,
    }


def _source_summary(ledger: ObserverFreshnessLedger) -> dict:
    if not isinstance(ledger, ObserverFreshnessLedger) or ledger._connection is None:
        _fail("OBSERVER_FRESHNESS_BACKUP_SOURCE_LEDGER_REQUIRED")
    _validate_database_file(ledger._path)
    try:
        return _extract_summary(ledger.verify())
    except ObserverFreshnessBackupError:
        raise
    except Exception:
        _fail("OBSERVER_FRESHNESS_BACKUP_SOURCE_VERIFICATION_FAILED")


def _verified_summary(path) -> dict:
    _validate_database_file(path)
    try:
        with ObserverFreshnessLedger(os.fspath(path)) as ledger:
            return _extract_summary(ledger.verify())
    except ObserverFreshnessBackupError:
        raise
    except Exception:
        _fail("OBSERVER_FRESHNESS_BACKUP_LEDGER_VERIFICATION_FAILED")


def _temporary_destination(destination: Path) -> Path:
    """Create an owner-only sibling file while keeping the final path absent."""
    descriptor = None
    name = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=".enterprise-hq-observer-freshness-",
            suffix=".tmp",
            dir=destination.parent,
        )
        os.close(descriptor)
        descriptor = None
        return Path(name)
    except OSError:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if name is not None:
            try:
                os.unlink(name)
            except OSError:
                pass
        _fail("OBSERVER_FRESHNESS_BACKUP_TEMPORARY_CREATE_FAILED")


def _publish_verified_destination(temporary: Path, destination: Path) -> None:
    """Atomically publish a verified file without replacing a racing destination."""
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError:
        _fail("OBSERVER_FRESHNESS_BACKUP_DESTINATION_EXISTS")
    except (NotImplementedError, OSError):
        _fail("OBSERVER_FRESHNESS_BACKUP_PUBLISH_FAILED")
    try:
        os.unlink(temporary)
    except OSError:
        try:
            temporary_stat = temporary.lstat()
            destination_stat = destination.lstat()
            if (
                temporary_stat.st_dev == destination_stat.st_dev
                and temporary_stat.st_ino == destination_stat.st_ino
            ):
                os.unlink(destination)
        except OSError:
            pass
        _fail("OBSERVER_FRESHNESS_BACKUP_PUBLISH_CLEANUP_FAILED")


def _copy_connection(source_connection, destination: Path) -> None:
    connection = None
    try:
        connection = sqlite3.connect(
            str(destination), timeout=5.0, isolation_level=None
        )
        source_connection.backup(connection, pages=64, sleep=0.01)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            _fail("OBSERVER_FRESHNESS_BACKUP_COPY_INTEGRITY_FAILED")
        connection.commit()
    except ObserverFreshnessBackupError:
        raise
    except sqlite3.Error:
        _fail("OBSERVER_FRESHNESS_BACKUP_COPY_FAILED")
    finally:
        if connection is not None:
            connection.close()
    try:
        os.chmod(destination, 0o600)
    except OSError:
        _fail("OBSERVER_FRESHNESS_BACKUP_PERMISSIONS_FAILED")


def _file_digest(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DATABASE_BYTES:
                _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_SIZE_INVALID")
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DATABASE_BYTES:
                    _fail("OBSERVER_FRESHNESS_BACKUP_DATABASE_SIZE_INVALID")
                digest.update(chunk)
            return digest.hexdigest()
        finally:
            os.close(descriptor)
    except ObserverFreshnessBackupError:
        raise
    except OSError:
        _fail("OBSERVER_FRESHNESS_BACKUP_DIGEST_FAILED")


def _cleanup_temporary(path: Path) -> None:
    if path.exists() and not path.is_symlink() and path.is_file():
        try:
            os.unlink(path)
        except OSError:
            pass


def _response(status: str, summary: dict, file_digest: str) -> dict:
    return {
        "status": status,
        "file_sha256": file_digest,
        **summary,
        "equivalence_verified": True,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


def create_verified_backup(
    source_ledger: ObserverFreshnessLedger, backup_path
) -> dict:
    """Verify a sibling temporary backup before atomically publishing it."""
    source_summary = _source_summary(source_ledger)
    destination = _new_destination(backup_path, source=source_ledger._path)
    temporary = _temporary_destination(destination)
    try:
        _copy_connection(source_ledger._connection, temporary)
        backup_summary = _verified_summary(temporary)
        if backup_summary != source_summary:
            _fail("OBSERVER_FRESHNESS_BACKUP_SOURCE_MISMATCH")
        file_digest = _file_digest(temporary)
        _publish_verified_destination(temporary, destination)
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_VERIFIED",
            backup_summary,
            file_digest,
        )
    except Exception:
        _cleanup_temporary(temporary)
        raise


def verify_backup_equivalence(
    source_ledger: ObserverFreshnessLedger, backup_path
) -> dict:
    """Compare a verified source ledger with an existing verified local backup."""
    source_summary = _source_summary(source_ledger)
    backup_summary = _verified_summary(backup_path)
    if backup_summary != source_summary:
        _fail("OBSERVER_FRESHNESS_BACKUP_SOURCE_MISMATCH")
    return _response(
        "OBSERVER_FRESHNESS_BACKUP_EQUIVALENCE_VERIFIED",
        backup_summary,
        _file_digest(Path(backup_path)),
    )


def restore_verified_backup(backup_path, restore_path) -> dict:
    """Restore to a verified sibling temporary file before atomic publication."""
    backup_summary = _verified_summary(backup_path)
    destination = _new_destination(restore_path, source=Path(backup_path))
    temporary = _temporary_destination(destination)
    try:
        with ObserverFreshnessLedger(os.fspath(backup_path)) as backup:
            if _extract_summary(backup.verify()) != backup_summary:
                _fail("OBSERVER_FRESHNESS_BACKUP_CHANGED_DURING_RESTORE")
            _copy_connection(backup._connection, temporary)
        restored_summary = _verified_summary(temporary)
        if restored_summary != backup_summary:
            _fail("OBSERVER_FRESHNESS_RESTORE_MISMATCH")
        file_digest = _file_digest(temporary)
        _publish_verified_destination(temporary, destination)
        return _response(
            "OBSERVER_FRESHNESS_RESTORE_VERIFIED",
            restored_summary,
            file_digest,
        )
    except Exception:
        _cleanup_temporary(temporary)
        raise


__all__ = [
    "ObserverFreshnessBackupError",
    "create_verified_backup",
    "restore_verified_backup",
    "verify_backup_equivalence",
]
