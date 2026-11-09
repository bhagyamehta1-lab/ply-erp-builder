"""Bounded, metadata-only inventory and retention evaluation for local ledger backups.

This module records caller-declared backup metadata only. It does not create,
copy, upload, read, or delete backup artifacts. Restore equivalence is checked
against the supplied integrity snapshots before an inventory record is accepted.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from scripts.enterprise_hq_evidence_ledger import EvidenceVerificationLedger
from scripts.enterprise_hq_ledger_restore_verifier import verify_ledger_restore_equivalence
from scripts.enterprise_hq_task_ledger import LedgerCorruptionError, LedgerError, _canonical_json, _utc_now

MAX_BACKUP_INVENTORY_RECORDS = 256
MAX_DECLARED_BACKUP_SIZE_BYTES = 256 * 1024 * 1024
MAX_BACKUP_RETENTION_DAYS = 90
MAX_RETENTION_EVALUATION_RECORDS = 1024
MAX_CREATED_AT_FUTURE_SKEW_SECONDS = 30

_BACKUP_ID = re.compile(r"^hqbk_[a-f0-9]{24}$")
_RETENTION_EVALUATION_ID = re.compile(r"^hqre_[a-f0-9]{24}$")
_LEDGER_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")
_ENTRY_FIELDS = frozenset({
    "backup_id", "ledger_type", "declared_size_bytes", "created_at",
    "retain_until", "generation", "predecessor_backup_id", "storage_scope",
})


class BackupInventoryError(LedgerError):
    """A backup inventory entry is invalid, conflicting, or outside policy."""


class BackupInventoryCorruptionError(LedgerCorruptionError):
    """Persisted backup inventory or its audit chain failed integrity checks."""


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed.astimezone(timezone.utc)


def _now_utc(value: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if value is None else value
    if (
        not isinstance(current, datetime)
        or current.tzinfo is None
        or current.utcoffset() != timedelta(0)
    ):
        raise BackupInventoryError("BACKUP_INVENTORY_CLOCK_INVALID")
    return current.astimezone(timezone.utc)


def _digest(value: Mapping) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class LedgerBackupInventory(EvidenceVerificationLedger):
    """Append-only local inventory of restore-verified backup metadata.

    Artifact existence, artifact bytes, and artifact digests are deliberately not
    inspected. Size is caller-declared. Retention evaluation never deletes records.
    """

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_backup_inventory (
                    backup_id TEXT PRIMARY KEY,
                    ledger_type TEXT NOT NULL,
                    source_snapshot_digest TEXT NOT NULL,
                    restored_snapshot_digest TEXT NOT NULL,
                    audit_chain_count INTEGER NOT NULL
                        CHECK (audit_chain_count BETWEEN 1 AND 32),
                    declared_size_bytes INTEGER NOT NULL
                        CHECK (declared_size_bytes BETWEEN 1 AND 268435456),
                    created_at TEXT NOT NULL,
                    retain_until TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    predecessor_backup_id TEXT
                        REFERENCES ledger_backup_inventory(backup_id),
                    storage_scope TEXT NOT NULL CHECK (storage_scope = 'LOCAL_ONLY'),
                    restore_status TEXT NOT NULL
                        CHECK (restore_status = 'RESTORE_EQUIVALENCE_VERIFIED'),
                    artifact_presence TEXT NOT NULL
                        CHECK (artifact_presence = 'NOT_INSPECTED'),
                    entry_digest TEXT NOT NULL UNIQUE,
                    UNIQUE (ledger_type, generation)
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_inventory_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    backup_id TEXT NOT NULL UNIQUE
                        REFERENCES ledger_backup_inventory(backup_id),
                    entry_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'BACKUP_METADATA_REGISTERED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_retention_evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    evaluated_at TEXT NOT NULL,
                    inventory_count INTEGER NOT NULL CHECK (inventory_count BETWEEN 0 AND 256),
                    retained_count INTEGER NOT NULL CHECK (retained_count BETWEEN 0 AND 256),
                    expired_count INTEGER NOT NULL CHECK (expired_count BETWEEN 0 AND 256),
                    inventory_digest TEXT NOT NULL,
                    evaluation_digest TEXT NOT NULL UNIQUE,
                    automatic_purge INTEGER NOT NULL CHECK (automatic_purge = 0),
                    records_deleted INTEGER NOT NULL CHECK (records_deleted = 0),
                    artifact_bytes_verified INTEGER NOT NULL CHECK (artifact_bytes_verified = 0),
                    execution_authorized INTEGER NOT NULL CHECK (execution_authorized = 0)
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_retention_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    evaluation_id TEXT NOT NULL UNIQUE
                        REFERENCES ledger_backup_retention_evaluations(evaluation_id),
                    evaluation_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'BACKUP_RETENTION_EVALUATED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS ledger_backup_retention_evaluated_at_idx
                    ON ledger_backup_retention_evaluations(evaluated_at);
                CREATE INDEX IF NOT EXISTS ledger_backup_inventory_type_generation_idx
                    ON ledger_backup_inventory(ledger_type, generation);
                """
            )
        except Exception:
            self.close()
            raise

    @staticmethod
    def _record_body(entry: Mapping, restore_result: Mapping) -> dict:
        return {
            "backup_id": entry["backup_id"],
            "ledger_type": entry["ledger_type"],
            "source_snapshot_digest": restore_result["source_snapshot_digest"],
            "restored_snapshot_digest": restore_result["restored_snapshot_digest"],
            "audit_chain_count": restore_result["audit_chain_count"],
            "declared_size_bytes": entry["declared_size_bytes"],
            "created_at": entry["created_at"],
            "retain_until": entry["retain_until"],
            "generation": entry["generation"],
            "predecessor_backup_id": entry["predecessor_backup_id"],
            "storage_scope": entry["storage_scope"],
            "restore_status": restore_result["status"],
            "artifact_presence": "NOT_INSPECTED",
        }

    def _append_backup_event(self, backup_id: str, entry_digest: str) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM ledger_backup_inventory_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        occurred_at = _utc_now()
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "backup_id": backup_id,
            "entry_digest": entry_digest,
            "event": "BACKUP_METADATA_REGISTERED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
        self._connection.execute(
            """INSERT INTO ledger_backup_inventory_audit_events
               (sequence, backup_id, entry_digest, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, 'BACKUP_METADATA_REGISTERED', ?, ?, ?)""",
            (sequence, backup_id, entry_digest, occurred_at, previous_hash, record_hash),
        )

    @staticmethod
    def _result(row, *, created: bool, already_present: bool) -> dict:
        return {
            "status": "BACKUP_METADATA_REGISTERED",
            "backup_id": row["backup_id"],
            "ledger_type": row["ledger_type"],
            "generation": row["generation"],
            "source_snapshot_digest": row["source_snapshot_digest"],
            "restored_snapshot_digest": row["restored_snapshot_digest"],
            "audit_chain_count": row["audit_chain_count"],
            "declared_size_bytes": row["declared_size_bytes"],
            "created_at": row["created_at"],
            "retain_until": row["retain_until"],
            "storage_scope": row["storage_scope"],
            "restore_status": row["restore_status"],
            "artifact_presence": "NOT_INSPECTED",
            "artifact_bytes_verified": False,
            "created": created,
            "already_present": already_present,
            "automatic_purge": False,
            "execution_authorized": False,
        }

    def record_backup(
        self,
        entry: Mapping,
        source_snapshot: Mapping,
        restored_snapshot: Mapping,
        *,
        now: datetime | None = None,
    ) -> dict:
        """Record bounded metadata after strict source/restore checkpoint comparison.

        No artifact path or bytes are accepted. The declared size and opaque backup
        ID are caller-provided metadata and are not proof that an artifact exists.
        """
        if not isinstance(entry, Mapping) or set(entry) != _ENTRY_FIELDS:
            raise BackupInventoryError("BACKUP_INVENTORY_SCHEMA_INVALID")
        if not isinstance(source_snapshot, Mapping) or not isinstance(restored_snapshot, Mapping):
            raise BackupInventoryError("BACKUP_RESTORE_SNAPSHOT_INVALID")
        current = _now_utc(now)
        backup_id = entry.get("backup_id")
        ledger_type = entry.get("ledger_type")
        size = entry.get("declared_size_bytes")
        created_at = _parse_utc(entry.get("created_at"))
        retain_until = _parse_utc(entry.get("retain_until"))
        generation = entry.get("generation")
        predecessor = entry.get("predecessor_backup_id")
        storage_scope = entry.get("storage_scope")

        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            raise BackupInventoryError("BACKUP_INVENTORY_ID_INVALID")
        if not isinstance(ledger_type, str) or not _LEDGER_TYPE.fullmatch(ledger_type):
            raise BackupInventoryError("BACKUP_INVENTORY_LEDGER_TYPE_INVALID")
        if type(size) is not int or not 1 <= size <= MAX_DECLARED_BACKUP_SIZE_BYTES:
            raise BackupInventoryError("BACKUP_INVENTORY_SIZE_INVALID")
        if created_at is None or created_at > current + timedelta(
            seconds=MAX_CREATED_AT_FUTURE_SKEW_SECONDS
        ):
            raise BackupInventoryError("BACKUP_INVENTORY_CREATED_AT_INVALID")
        if retain_until is None or retain_until <= current or retain_until <= created_at:
            raise BackupInventoryError("BACKUP_INVENTORY_RETENTION_INVALID")
        if retain_until - created_at > timedelta(days=MAX_BACKUP_RETENTION_DAYS):
            raise BackupInventoryError("BACKUP_INVENTORY_RETENTION_LIMIT_EXCEEDED")
        if type(generation) is not int or generation < 1:
            raise BackupInventoryError("BACKUP_INVENTORY_GENERATION_INVALID")
        if generation == 1:
            if predecessor is not None:
                raise BackupInventoryError("BACKUP_INVENTORY_PREDECESSOR_INVALID")
        elif not isinstance(predecessor, str) or not _BACKUP_ID.fullmatch(predecessor):
            raise BackupInventoryError("BACKUP_INVENTORY_PREDECESSOR_INVALID")
        if storage_scope != "LOCAL_ONLY":
            raise BackupInventoryError("BACKUP_INVENTORY_STORAGE_SCOPE_UNSUPPORTED")

        try:
            restore_result = verify_ledger_restore_equivalence(
                source_snapshot, restored_snapshot
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            raise BackupInventoryError("BACKUP_RESTORE_EQUIVALENCE_FAILED") from None
        if ledger_type != source_snapshot.get("ledger_type"):
            raise BackupInventoryError("BACKUP_INVENTORY_LEDGER_TYPE_MISMATCH")
        if set(restore_result) != {
            "status", "source_snapshot_digest", "restored_snapshot_digest",
            "audit_chain_count", "execution_authorized", "execution_resumed",
            "automatic_retry",
        }:
            raise BackupInventoryError("BACKUP_RESTORE_RESULT_SCHEMA_INVALID")
        if (
            restore_result["status"] != "RESTORE_EQUIVALENCE_VERIFIED"
            or restore_result["source_snapshot_digest"] != restore_result["restored_snapshot_digest"]
            or type(restore_result["audit_chain_count"]) is not int
            or not 1 <= restore_result["audit_chain_count"] <= 32
            or restore_result["execution_authorized"] is not False
            or restore_result["execution_resumed"] is not False
            or restore_result["automatic_retry"] is not False
        ):
            raise BackupInventoryError("BACKUP_RESTORE_RESULT_INVALID")

        body = self._record_body(entry, restore_result)
        entry_digest = _digest(body)
        with self._transaction():
            self.verify()
            existing = self._connection.execute(
                "SELECT * FROM ledger_backup_inventory WHERE backup_id = ?",
                (backup_id,),
            ).fetchone()
            if existing is not None:
                if existing["entry_digest"] != entry_digest:
                    raise BackupInventoryError("BACKUP_INVENTORY_ID_CONTENT_CONFLICT")
                return self._result(existing, created=False, already_present=True)

            latest = self._connection.execute(
                """SELECT backup_id, generation FROM ledger_backup_inventory
                   WHERE ledger_type = ? ORDER BY generation DESC LIMIT 1""",
                (ledger_type,),
            ).fetchone()
            expected_generation = 1 if latest is None else latest["generation"] + 1
            expected_predecessor = None if latest is None else latest["backup_id"]
            if generation != expected_generation or predecessor != expected_predecessor:
                raise BackupInventoryError("BACKUP_INVENTORY_LINEAGE_INVALID")
            count = self._connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_inventory"
            ).fetchone()[0]
            if count >= MAX_BACKUP_INVENTORY_RECORDS:
                raise BackupInventoryError("BACKUP_INVENTORY_CAPACITY_REACHED")

            self._connection.execute(
                """INSERT INTO ledger_backup_inventory
                   (backup_id, ledger_type, source_snapshot_digest,
                    restored_snapshot_digest, audit_chain_count, declared_size_bytes,
                    created_at, retain_until, generation, predecessor_backup_id,
                    storage_scope, restore_status, artifact_presence, entry_digest)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    backup_id, ledger_type, restore_result["source_snapshot_digest"],
                    restore_result["restored_snapshot_digest"],
                    restore_result["audit_chain_count"], size, entry["created_at"],
                    entry["retain_until"], generation, predecessor, storage_scope,
                    restore_result["status"], "NOT_INSPECTED", entry_digest,
                ),
            )
            self._append_backup_event(backup_id, entry_digest)
            row = self._connection.execute(
                "SELECT * FROM ledger_backup_inventory WHERE backup_id = ?",
                (backup_id,),
            ).fetchone()
            return self._result(row, created=True, already_present=False)

    def _append_retention_event(
        self, evaluation_id: str, evaluation_digest: str, occurred_at: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM ledger_backup_retention_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "evaluation_id": evaluation_id,
            "evaluation_digest": evaluation_digest,
            "event": "BACKUP_RETENTION_EVALUATED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            _canonical_json(body).encode("utf-8")
        ).hexdigest()
        self._connection.execute(
            """INSERT INTO ledger_backup_retention_audit_events
               (sequence, evaluation_id, evaluation_digest, event, occurred_at,
                previous_hash, record_hash)
               VALUES (?, ?, ?, 'BACKUP_RETENTION_EVALUATED', ?, ?, ?)""",
            (sequence, evaluation_id, evaluation_digest, occurred_at,
             previous_hash, record_hash),
        )

    @staticmethod
    def _retention_result(
        row, *, created: bool, already_present: bool
    ) -> dict:
        return {
            "status": "RETENTION_EVALUATED",
            "evaluation_id": row["evaluation_id"],
            "evaluation_digest": row["evaluation_digest"],
            "inventory_digest": row["inventory_digest"],
            "evaluated_at": row["evaluated_at"],
            "inventory_count": row["inventory_count"],
            "retained_count": row["retained_count"],
            "expired_count": row["expired_count"],
            "created": created,
            "already_present": already_present,
            "automatic_purge": False,
            "records_deleted": 0,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
        }

    def evaluate_retention(self, *, now: datetime | None = None) -> dict:
        """Persist a bounded metadata-only retention evaluation; never delete records."""
        current = _now_utc(now)
        evaluated_at = current.isoformat().replace("+00:00", "Z")
        with self._transaction():
            self.verify()
            rows = self._connection.execute(
                """SELECT backup_id, ledger_type, generation, retain_until, entry_digest
                   FROM ledger_backup_inventory ORDER BY ledger_type, generation"""
            ).fetchall()
            inventory_entries = [
                {
                    "backup_id": row["backup_id"],
                    "ledger_type": row["ledger_type"],
                    "generation": row["generation"],
                    "retain_until": row["retain_until"],
                    "entry_digest": row["entry_digest"],
                }
                for row in rows
            ]
            expired = sum(
                1 for row in rows if _parse_utc(row["retain_until"]) <= current
            )
            inventory_count = len(rows)
            retained = inventory_count - expired
            inventory_digest = _digest({"entries": inventory_entries})
            evaluation_body = {
                "evaluated_at": evaluated_at,
                "inventory_count": inventory_count,
                "retained_count": retained,
                "expired_count": expired,
                "inventory_digest": inventory_digest,
                "automatic_purge": False,
                "records_deleted": 0,
                "artifact_bytes_verified": False,
                "execution_authorized": False,
            }
            evaluation_digest = _digest(evaluation_body)
            evaluation_id = f"hqre_{evaluation_digest[:24]}"
            existing = self._connection.execute(
                "SELECT * FROM ledger_backup_retention_evaluations WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            if existing is not None:
                if existing["evaluation_digest"] != evaluation_digest:
                    raise BackupInventoryError(
                        "BACKUP_RETENTION_EVALUATION_ID_CONTENT_CONFLICT"
                    )
                return self._retention_result(
                    existing, created=False, already_present=True
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_retention_evaluations"
            ).fetchone()[0]
            if count >= MAX_RETENTION_EVALUATION_RECORDS:
                raise BackupInventoryError(
                    "BACKUP_RETENTION_EVALUATION_CAPACITY_REACHED"
                )
            self._connection.execute(
                """INSERT INTO ledger_backup_retention_evaluations
                   (evaluation_id, evaluated_at, inventory_count, retained_count,
                    expired_count, inventory_digest, evaluation_digest,
                    automatic_purge, records_deleted, artifact_bytes_verified,
                    execution_authorized)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0)""",
                (
                    evaluation_id, evaluated_at, inventory_count, retained,
                    expired, inventory_digest, evaluation_digest,
                ),
            )
            self._append_retention_event(
                evaluation_id, evaluation_digest, evaluated_at
            )
            saved = self._connection.execute(
                "SELECT * FROM ledger_backup_retention_evaluations WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            return self._retention_result(
                saved, created=True, already_present=False
            )


    def get_backup_metadata(self, backup_id: str) -> dict:
        """Return one verified inventory entry without paths or artifact bytes."""
        if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
            raise BackupInventoryError("BACKUP_INVENTORY_ID_INVALID")
        if self._connection is None:
            raise BackupInventoryError("BACKUP_INVENTORY_LEDGER_CLOSED")
        try:
            self._connection.execute("BEGIN")
            self.verify()
            row = self._connection.execute(
                """SELECT backup_id, ledger_type, source_snapshot_digest,
                          restored_snapshot_digest, audit_chain_count,
                          declared_size_bytes, generation, predecessor_backup_id,
                          storage_scope, restore_status, artifact_presence, entry_digest
                   FROM ledger_backup_inventory WHERE backup_id = ?""",
                (backup_id,),
            ).fetchone()
            if row is None:
                self._connection.commit()
                return {
                    "status": "BACKUP_METADATA_NOT_FOUND",
                    "backup_id": backup_id,
                    "execution_authorized": False,
                    "automatic_dispatch": False,
                    "automatic_retry": False,
                }
            result = {
                "status": "BACKUP_METADATA_FOUND",
                "backup_id": row["backup_id"],
                "ledger_type": row["ledger_type"],
                "source_snapshot_digest": row["source_snapshot_digest"],
                "restored_snapshot_digest": row["restored_snapshot_digest"],
                "audit_chain_count": row["audit_chain_count"],
                "declared_size_bytes": row["declared_size_bytes"],
                "generation": row["generation"],
                "predecessor_backup_id": row["predecessor_backup_id"],
                "storage_scope": row["storage_scope"],
                "restore_status": row["restore_status"],
                "artifact_presence": row["artifact_presence"],
                "entry_digest": row["entry_digest"],
                "artifact_bytes_verified": False,
                "execution_authorized": False,
                "automatic_dispatch": False,
                "automatic_retry": False,
            }
            self._connection.commit()
            return result
        except Exception:
            self._connection.rollback()
            raise

    def list_backup_metadata(self) -> list[dict]:
        """Return a stable, bounded metadata-only snapshot of every inventory row."""
        if self._connection is None:
            raise BackupInventoryError("BACKUP_INVENTORY_LEDGER_CLOSED")
        try:
            self._connection.execute("BEGIN")
            self.verify()
            rows = self._connection.execute(
                """SELECT backup_id, ledger_type, source_snapshot_digest,
                          restored_snapshot_digest, audit_chain_count,
                          declared_size_bytes, created_at, retain_until,
                          generation, predecessor_backup_id, storage_scope,
                          restore_status, artifact_presence, entry_digest
                   FROM ledger_backup_inventory
                   ORDER BY ledger_type, generation"""
            ).fetchall()
            if len(rows) > MAX_BACKUP_INVENTORY_RECORDS:
                raise BackupInventoryCorruptionError(
                    "BACKUP_INVENTORY_CAPACITY_INVARIANT_FAILED"
                )
            result = [
                {
                    "status": "BACKUP_METADATA_FOUND",
                    "backup_id": row["backup_id"],
                    "ledger_type": row["ledger_type"],
                    "source_snapshot_digest": row["source_snapshot_digest"],
                    "restored_snapshot_digest": row["restored_snapshot_digest"],
                    "audit_chain_count": row["audit_chain_count"],
                    "declared_size_bytes": row["declared_size_bytes"],
                    "created_at": row["created_at"],
                    "retain_until": row["retain_until"],
                    "generation": row["generation"],
                    "predecessor_backup_id": row["predecessor_backup_id"],
                    "storage_scope": row["storage_scope"],
                    "restore_status": row["restore_status"],
                    "artifact_presence": row["artifact_presence"],
                    "entry_digest": row["entry_digest"],
                    "artifact_bytes_verified": False,
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


    def verify(self) -> dict:
        """Verify inherited ledgers, backup metadata, lineage, and its audit chain."""
        base = super().verify()
        rows = self._connection.execute(
            """SELECT backup_id, ledger_type, source_snapshot_digest,
                      restored_snapshot_digest, audit_chain_count, declared_size_bytes,
                      created_at, retain_until, generation, predecessor_backup_id,
                      storage_scope, restore_status, artifact_presence, entry_digest
               FROM ledger_backup_inventory ORDER BY ledger_type, generation"""
        ).fetchall()
        if len(rows) > MAX_BACKUP_INVENTORY_RECORDS:
            raise BackupInventoryCorruptionError("BACKUP_INVENTORY_CAPACITY_INVARIANT_FAILED")

        row_map = {}
        latest_by_type = {}
        for row in rows:
            created_at = _parse_utc(row["created_at"])
            retain_until = _parse_utc(row["retain_until"])
            if (
                not isinstance(row["backup_id"], str)
                or not _BACKUP_ID.fullmatch(row["backup_id"])
                or not isinstance(row["ledger_type"], str)
                or not _LEDGER_TYPE.fullmatch(row["ledger_type"])
                or not isinstance(row["source_snapshot_digest"], str)
                or not _HEX_64.fullmatch(row["source_snapshot_digest"])
                or row["source_snapshot_digest"] != row["restored_snapshot_digest"]
                or type(row["audit_chain_count"]) is not int
                or not 1 <= row["audit_chain_count"] <= 32
                or type(row["declared_size_bytes"]) is not int
                or not 1 <= row["declared_size_bytes"] <= MAX_DECLARED_BACKUP_SIZE_BYTES
                or created_at is None
                or retain_until is None
                or retain_until <= created_at
                or retain_until - created_at > timedelta(days=MAX_BACKUP_RETENTION_DAYS)
                or type(row["generation"]) is not int
                or row["generation"] < 1
                or row["storage_scope"] != "LOCAL_ONLY"
                or row["restore_status"] != "RESTORE_EQUIVALENCE_VERIFIED"
                or row["artifact_presence"] != "NOT_INSPECTED"
            ):
                raise BackupInventoryCorruptionError("BACKUP_INVENTORY_RECORD_INVARIANT_FAILED")
            if row["generation"] == 1:
                if row["predecessor_backup_id"] is not None or row["ledger_type"] in latest_by_type:
                    raise BackupInventoryCorruptionError("BACKUP_INVENTORY_LINEAGE_INVALID")
            else:
                previous = latest_by_type.get(row["ledger_type"])
                if (
                    previous is None
                    or row["generation"] != previous["generation"] + 1
                    or row["predecessor_backup_id"] != previous["backup_id"]
                ):
                    raise BackupInventoryCorruptionError("BACKUP_INVENTORY_LINEAGE_INVALID")
            body = {
                "backup_id": row["backup_id"],
                "ledger_type": row["ledger_type"],
                "source_snapshot_digest": row["source_snapshot_digest"],
                "restored_snapshot_digest": row["restored_snapshot_digest"],
                "audit_chain_count": row["audit_chain_count"],
                "declared_size_bytes": row["declared_size_bytes"],
                "created_at": row["created_at"],
                "retain_until": row["retain_until"],
                "generation": row["generation"],
                "predecessor_backup_id": row["predecessor_backup_id"],
                "storage_scope": row["storage_scope"],
                "restore_status": row["restore_status"],
                "artifact_presence": row["artifact_presence"],
            }
            if row["entry_digest"] != _digest(body):
                raise BackupInventoryCorruptionError("BACKUP_INVENTORY_ENTRY_DIGEST_INVALID")
            latest_by_type[row["ledger_type"]] = {
                "backup_id": row["backup_id"], "generation": row["generation"]
            }
            row_map[row["backup_id"]] = row

        events = self._connection.execute(
            """SELECT sequence, backup_id, entry_digest, event, occurred_at,
                      previous_hash, record_hash
               FROM ledger_backup_inventory_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(events) != len(rows):
            raise BackupInventoryCorruptionError("BACKUP_INVENTORY_AUDIT_EVENT_COUNT_MISMATCH")
        previous_hash = None
        seen = set()
        for expected_sequence, event in enumerate(events, start=1):
            row = row_map.get(event["backup_id"])
            if (
                event["sequence"] != expected_sequence
                or row is None
                or event["backup_id"] in seen
                or event["entry_digest"] != row["entry_digest"]
                or event["event"] != "BACKUP_METADATA_REGISTERED"
                or _parse_utc(event["occurred_at"]) is None
                or event["previous_hash"] != previous_hash
            ):
                raise BackupInventoryCorruptionError("BACKUP_INVENTORY_AUDIT_CHAIN_STRUCTURE_INVALID")
            body = {
                "schema_version": "1.0.0",
                "sequence": event["sequence"],
                "backup_id": event["backup_id"],
                "entry_digest": event["entry_digest"],
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            expected_hash = hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()
            if event["record_hash"] != expected_hash:
                raise BackupInventoryCorruptionError("BACKUP_INVENTORY_AUDIT_CHAIN_HASH_INVALID")
            previous_hash = expected_hash
            seen.add(event["backup_id"])

        retention_rows = self._connection.execute(
            """SELECT evaluation_id, evaluated_at, inventory_count, retained_count,
                      expired_count, inventory_digest, evaluation_digest,
                      automatic_purge, records_deleted, artifact_bytes_verified,
                      execution_authorized
               FROM ledger_backup_retention_evaluations ORDER BY rowid"""
        ).fetchall()
        if len(retention_rows) > MAX_RETENTION_EVALUATION_RECORDS:
            raise BackupInventoryCorruptionError(
                "BACKUP_RETENTION_EVALUATION_CAPACITY_INVARIANT_FAILED"
            )
        retention_map = {}
        for row in retention_rows:
            evaluated_at = _parse_utc(row["evaluated_at"])
            counts = (
                row["inventory_count"], row["retained_count"], row["expired_count"]
            )
            if (
                not isinstance(row["evaluation_id"], str)
                or not _RETENTION_EVALUATION_ID.fullmatch(row["evaluation_id"])
                or evaluated_at is None
                or row["evaluated_at"] != evaluated_at.isoformat().replace("+00:00", "Z")
                or any(type(value) is not int for value in counts)
                or not 0 <= row["inventory_count"] <= MAX_BACKUP_INVENTORY_RECORDS
                or not 0 <= row["retained_count"] <= row["inventory_count"]
                or not 0 <= row["expired_count"] <= row["inventory_count"]
                or row["retained_count"] + row["expired_count"] != row["inventory_count"]
                or not isinstance(row["inventory_digest"], str)
                or not _HEX_64.fullmatch(row["inventory_digest"])
                or type(row["automatic_purge"]) is not int
                or row["automatic_purge"] != 0
                or type(row["records_deleted"]) is not int
                or row["records_deleted"] != 0
                or type(row["artifact_bytes_verified"]) is not int
                or row["artifact_bytes_verified"] != 0
                or type(row["execution_authorized"]) is not int
                or row["execution_authorized"] != 0
            ):
                raise BackupInventoryCorruptionError(
                    "BACKUP_RETENTION_EVALUATION_INVARIANT_FAILED"
                )
            evaluation_body = {
                "evaluated_at": row["evaluated_at"],
                "inventory_count": row["inventory_count"],
                "retained_count": row["retained_count"],
                "expired_count": row["expired_count"],
                "inventory_digest": row["inventory_digest"],
                "automatic_purge": False,
                "records_deleted": 0,
                "artifact_bytes_verified": False,
                "execution_authorized": False,
            }
            expected_digest = _digest(evaluation_body)
            if (
                row["evaluation_digest"] != expected_digest
                or row["evaluation_id"] != f"hqre_{expected_digest[:24]}"
            ):
                raise BackupInventoryCorruptionError(
                    "BACKUP_RETENTION_EVALUATION_DIGEST_INVALID"
                )
            retention_map[row["evaluation_id"]] = row

        retention_events = self._connection.execute(
            """SELECT sequence, evaluation_id, evaluation_digest, event,
                      occurred_at, previous_hash, record_hash
               FROM ledger_backup_retention_audit_events ORDER BY sequence"""
        ).fetchall()
        if len(retention_events) != len(retention_rows):
            raise BackupInventoryCorruptionError(
                "BACKUP_RETENTION_AUDIT_EVENT_COUNT_MISMATCH"
            )
        previous_retention_hash = None
        seen_evaluations = set()
        for expected_sequence, event in enumerate(retention_events, start=1):
            row = retention_map.get(event["evaluation_id"])
            if (
                event["sequence"] != expected_sequence
                or row is None
                or event["evaluation_id"] in seen_evaluations
                or event["evaluation_digest"] != row["evaluation_digest"]
                or event["event"] != "BACKUP_RETENTION_EVALUATED"
                or event["occurred_at"] != row["evaluated_at"]
                or event["previous_hash"] != previous_retention_hash
            ):
                raise BackupInventoryCorruptionError(
                    "BACKUP_RETENTION_AUDIT_CHAIN_STRUCTURE_INVALID"
                )
            event_body = {
                "schema_version": "1.0.0",
                "sequence": event["sequence"],
                "evaluation_id": event["evaluation_id"],
                "evaluation_digest": event["evaluation_digest"],
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            expected_hash = hashlib.sha256(
                _canonical_json(event_body).encode("utf-8")
            ).hexdigest()
            if event["record_hash"] != expected_hash:
                raise BackupInventoryCorruptionError(
                    "BACKUP_RETENTION_AUDIT_CHAIN_HASH_INVALID"
                )
            previous_retention_hash = expected_hash
            seen_evaluations.add(event["evaluation_id"])

        return {
            **base,
            "backup_inventory_count": len(rows),
            "backup_inventory_audit_event_count": len(events),
            "backup_inventory_chain": "VALID",
            "backup_retention_evaluation_count": len(retention_rows),
            "backup_retention_audit_event_count": len(retention_events),
            "backup_retention_chain": "VALID",
            "backup_artifact_bytes_verified": False,
            "backup_automatic_purge": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify inventory metadata after restart without restoring or deleting artifacts."""
        base = super().recover_after_restart()
        verified = self.verify()
        return {
            **base,
            "backup_inventory_records_recovered": verified["backup_inventory_count"],
            "backup_inventory_audit_events_recovered": verified["backup_inventory_audit_event_count"],
            "backup_retention_evaluations_recovered": verified["backup_retention_evaluation_count"],
            "backup_retention_audit_events_recovered": verified["backup_retention_audit_event_count"],
            "backup_artifact_payloads_retained": 0,
            "backup_automatic_purge": False,
            "execution_authorized": False,
            "execution_resumed": False,
            "automatic_retry": False,
        }


__all__ = [
    "BackupInventoryError", "BackupInventoryCorruptionError", "LedgerBackupInventory",
    "MAX_BACKUP_INVENTORY_RECORDS", "MAX_DECLARED_BACKUP_SIZE_BYTES",
    "MAX_BACKUP_RETENTION_DAYS", "MAX_RETENTION_EVALUATION_RECORDS",
]
