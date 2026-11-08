"""Metadata-only reconciliation of backup generations across ledger types.

This module groups already registered, restore-equivalent backup metadata into
bounded cross-ledger sets. It never opens, copies, uploads, reads, or deletes
backup artifacts and never authorizes execution.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import timedelta

from scripts.enterprise_hq_backup_inventory import (
    BackupInventoryCorruptionError,
    BackupInventoryError,
    LedgerBackupInventory,
    _digest,
    _now_utc,
    _parse_utc,
)

MAX_BACKUP_SET_RECORDS = 128
MAX_BACKUP_SET_LEDGER_TYPES = 16
MAX_BACKUP_SET_SKEW_SECONDS = 300

_BACKUP_SET_ID = re.compile(r"^hqbs_[a-f0-9]{24}$")
_LEDGER_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class BackupSetReconciliationError(BackupInventoryError):
    """A cross-ledger backup set is incomplete or outside policy."""


class BackupSetReconciliationCorruptionError(BackupInventoryCorruptionError):
    """Persisted cross-ledger backup-set history failed integrity checks."""


def _normalize_ledger_types(value) -> list[str]:
    if not isinstance(value, (list, tuple)) or not 2 <= len(value) <= MAX_BACKUP_SET_LEDGER_TYPES:
        raise BackupSetReconciliationError("BACKUP_SET_LEDGER_TYPES_INVALID")
    if any(not isinstance(item, str) or not _LEDGER_TYPE.fullmatch(item) for item in value):
        raise BackupSetReconciliationError("BACKUP_SET_LEDGER_TYPE_INVALID")
    if len(set(value)) != len(value):
        raise BackupSetReconciliationError("BACKUP_SET_LEDGER_TYPES_DUPLICATE")
    return sorted(value)


def _types_json(ledger_types: list[str]) -> str:
    return json.dumps(ledger_types, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class CrossLedgerBackupSetInventory(LedgerBackupInventory):
    """Append-only cross-ledger backup-set lineage over an existing local inventory."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_backup_sets (
                    backup_set_id TEXT PRIMARY KEY,
                    generation INTEGER NOT NULL CHECK (generation > 0),
                    ledger_types_json TEXT NOT NULL,
                    ledger_types_digest TEXT NOT NULL,
                    member_count INTEGER NOT NULL
                        CHECK (member_count BETWEEN 2 AND 16),
                    member_digest TEXT NOT NULL,
                    created_at_earliest TEXT NOT NULL,
                    created_at_latest TEXT NOT NULL,
                    max_skew_seconds INTEGER NOT NULL
                        CHECK (max_skew_seconds BETWEEN 0 AND 300),
                    predecessor_set_id TEXT
                        REFERENCES ledger_backup_sets(backup_set_id),
                    reconciled_at TEXT NOT NULL,
                    set_digest TEXT NOT NULL UNIQUE,
                    UNIQUE (generation, ledger_types_digest)
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_set_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    backup_set_id TEXT NOT NULL UNIQUE
                        REFERENCES ledger_backup_sets(backup_set_id),
                    set_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'BACKUP_SET_RECONCILED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ledger_backup_sets_generation_idx
                    ON ledger_backup_sets(ledger_types_digest, generation);
                """
            )
        except Exception:
            self.close()
            raise

    @staticmethod
    def _member_body(row) -> dict:
        return {
            "backup_id": row["backup_id"],
            "ledger_type": row["ledger_type"],
            "generation": row["generation"],
            "source_snapshot_digest": row["source_snapshot_digest"],
            "restored_snapshot_digest": row["restored_snapshot_digest"],
            "entry_digest": row["entry_digest"],
            "created_at": row["created_at"],
            "retain_until": row["retain_until"],
        }

    @staticmethod
    def _result(row, *, created: bool, already_present: bool) -> dict:
        return {
            "status": "BACKUP_SET_RECONCILED",
            "backup_set_id": row["backup_set_id"],
            "generation": row["generation"],
            "ledger_types": json.loads(row["ledger_types_json"]),
            "member_count": row["member_count"],
            "member_digest": row["member_digest"],
            "set_digest": row["set_digest"],
            "predecessor_set_id": row["predecessor_set_id"],
            "created_at_earliest": row["created_at_earliest"],
            "created_at_latest": row["created_at_latest"],
            "max_skew_seconds": row["max_skew_seconds"],
            "created": created,
            "already_present": already_present,
            "artifact_presence": "NOT_INSPECTED",
            "artifact_bytes_verified": False,
            "execution_authorized": False,
        }

    def _append_set_event(
        self, backup_set_id: str, set_digest: str, occurred_at: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash FROM ledger_backup_set_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        body = {
            "sequence": sequence,
            "backup_set_id": backup_set_id,
            "set_digest": set_digest,
            "event": "BACKUP_SET_RECONCILED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        self._connection.execute(
            """
            INSERT INTO ledger_backup_set_audit_events
                (sequence, backup_set_id, set_digest, event, occurred_at,
                 previous_hash, record_hash)
            VALUES (?, ?, ?, 'BACKUP_SET_RECONCILED', ?, ?, ?)
            """,
            (
                sequence, backup_set_id, set_digest, occurred_at,
                previous_hash, _digest(body),
            ),
        )

    def record_backup_set(
        self,
        ledger_types,
        generation: int,
        *,
        max_skew_seconds: int = 120,
        now=None,
    ) -> dict:
        """Persist a complete, bounded generation across at least two ledger types."""
        types = _normalize_ledger_types(ledger_types)
        if type(generation) is not int or generation < 1:
            raise BackupSetReconciliationError("BACKUP_SET_GENERATION_INVALID")
        if (
            type(max_skew_seconds) is not int
            or not 0 <= max_skew_seconds <= MAX_BACKUP_SET_SKEW_SECONDS
        ):
            raise BackupSetReconciliationError("BACKUP_SET_SKEW_LIMIT_INVALID")
        current = _now_utc(now)
        types_digest = _digest({"ledger_types": types})

        with self._transaction():
            self.verify()
            members = []
            for ledger_type in types:
                row = self._connection.execute(
                    """
                    SELECT backup_id, ledger_type, generation,
                           source_snapshot_digest, restored_snapshot_digest,
                           entry_digest, created_at, retain_until
                    FROM ledger_backup_inventory
                    WHERE ledger_type = ? AND generation = ?
                    """,
                    (ledger_type, generation),
                ).fetchone()
                if row is None:
                    raise BackupSetReconciliationError("BACKUP_SET_MEMBER_MISSING")
                members.append(row)

            member_bodies = [self._member_body(row) for row in members]
            member_digest = _digest({"members": member_bodies})
            created_values = [_parse_utc(row["created_at"]) for row in members]
            if any(value is None for value in created_values):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_MEMBER_TIMESTAMP_INVALID"
                )
            earliest = min(created_values)
            latest = max(created_values)
            earliest_text = earliest.isoformat().replace("+00:00", "Z")
            latest_text = latest.isoformat().replace("+00:00", "Z")
            observed_skew = (latest - earliest).total_seconds()

            predecessor_set_id = None
            if generation > 1:
                predecessor = self._connection.execute(
                    """
                    SELECT backup_set_id FROM ledger_backup_sets
                    WHERE generation = ? AND ledger_types_digest = ?
                    """,
                    (generation - 1, types_digest),
                ).fetchone()
                if predecessor is None:
                    raise BackupSetReconciliationError(
                        "BACKUP_SET_PREDECESSOR_SET_MISSING"
                    )
                predecessor_set_id = predecessor["backup_set_id"]

            existing = self._connection.execute(
                """
                SELECT * FROM ledger_backup_sets
                WHERE generation = ? AND ledger_types_digest = ?
                """,
                (generation, types_digest),
            ).fetchone()
            if existing is not None:
                same = (
                    existing["member_digest"] == member_digest
                    and existing["max_skew_seconds"] == max_skew_seconds
                    and existing["created_at_earliest"] == earliest_text
                    and existing["created_at_latest"] == latest_text
                    and existing["predecessor_set_id"] == predecessor_set_id
                )
                if not same:
                    raise BackupSetReconciliationError(
                        "BACKUP_SET_GENERATION_CONTENT_CONFLICT"
                    )
                return self._result(
                    existing, created=False, already_present=True
                )

            if any(_parse_utc(row["retain_until"]) <= current for row in members):
                raise BackupSetReconciliationError("BACKUP_SET_MEMBER_EXPIRED")
            if observed_skew > max_skew_seconds:
                raise BackupSetReconciliationError("BACKUP_SET_TIME_SKEW_EXCEEDED")

            identity = {
                "generation": generation,
                "ledger_types": types,
                "ledger_types_digest": types_digest,
                "member_count": len(members),
                "member_digest": member_digest,
                "created_at_earliest": earliest_text,
                "created_at_latest": latest_text,
                "max_skew_seconds": max_skew_seconds,
                "predecessor_set_id": predecessor_set_id,
            }
            backup_set_id = "hqbs_" + _digest(identity)[:24]
            reconciled_at = current.isoformat().replace("+00:00", "Z")
            set_body = {
                **identity,
                "backup_set_id": backup_set_id,
                "reconciled_at": reconciled_at,
            }
            set_digest = _digest(set_body)

            count = self._connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_sets"
            ).fetchone()[0]
            if count >= MAX_BACKUP_SET_RECORDS:
                raise BackupSetReconciliationError(
                    "BACKUP_SET_CAPACITY_REACHED"
                )

            self._connection.execute(
                """
                INSERT INTO ledger_backup_sets
                    (backup_set_id, generation, ledger_types_json,
                     ledger_types_digest, member_count, member_digest,
                     created_at_earliest, created_at_latest, max_skew_seconds,
                     predecessor_set_id, reconciled_at, set_digest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    backup_set_id, generation, _types_json(types),
                    types_digest, len(members), member_digest,
                    earliest_text, latest_text, max_skew_seconds,
                    predecessor_set_id, reconciled_at, set_digest,
                ),
            )
            self._append_set_event(backup_set_id, set_digest, reconciled_at)
            saved = self._connection.execute(
                "SELECT * FROM ledger_backup_sets WHERE backup_set_id = ?",
                (backup_set_id,),
            ).fetchone()
            return self._result(saved, created=True, already_present=False)

    def verify(self) -> dict:
        """Verify inherited ledgers plus complete cross-ledger set lineage."""
        base = super().verify()
        rows = self._connection.execute(
            """
            SELECT * FROM ledger_backup_sets
            ORDER BY ledger_types_digest, generation
            """
        ).fetchall()
        if len(rows) > MAX_BACKUP_SET_RECORDS:
            raise BackupSetReconciliationCorruptionError(
                "BACKUP_SET_CAPACITY_INVARIANT_FAILED"
            )

        seen = {}
        rows_by_id = {}
        for row in rows:
            try:
                types = json.loads(row["ledger_types_json"])
                normalized = _normalize_ledger_types(types)
            except Exception:
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_LEDGER_TYPES_CORRUPT"
                ) from None
            if types != normalized or row["ledger_types_json"] != _types_json(types):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_LEDGER_TYPES_NOT_CANONICAL"
                )
            types_digest = _digest({"ledger_types": types})
            if row["ledger_types_digest"] != types_digest:
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_LEDGER_TYPES_DIGEST_INVALID"
                )
            if (
                type(row["generation"]) is not int or row["generation"] < 1
                or type(row["member_count"]) is not int
                or row["member_count"] != len(types)
                or type(row["max_skew_seconds"]) is not int
                or not 0 <= row["max_skew_seconds"] <= MAX_BACKUP_SET_SKEW_SECONDS
                or not isinstance(row["backup_set_id"], str)
                or not _BACKUP_SET_ID.fullmatch(row["backup_set_id"])
                or not isinstance(row["set_digest"], str)
                or not _HEX_64.fullmatch(row["set_digest"])
            ):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_RECORD_INVARIANT_FAILED"
                )

            member_rows = []
            for ledger_type in types:
                member = self._connection.execute(
                    """
                    SELECT backup_id, ledger_type, generation,
                           source_snapshot_digest, restored_snapshot_digest,
                           entry_digest, created_at, retain_until
                    FROM ledger_backup_inventory
                    WHERE ledger_type = ? AND generation = ?
                    """,
                    (ledger_type, row["generation"]),
                ).fetchone()
                if member is None:
                    raise BackupSetReconciliationCorruptionError(
                        "BACKUP_SET_MEMBER_MISSING"
                    )
                member_rows.append(member)
            member_digest = _digest({
                "members": [self._member_body(member) for member in member_rows]
            })
            if member_digest != row["member_digest"]:
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_MEMBER_DIGEST_INVALID"
                )

            created_values = [_parse_utc(member["created_at"]) for member in member_rows]
            if any(value is None for value in created_values):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_MEMBER_TIMESTAMP_INVALID"
                )
            earliest = min(created_values).isoformat().replace("+00:00", "Z")
            latest = max(created_values).isoformat().replace("+00:00", "Z")
            skew = (max(created_values) - min(created_values)).total_seconds()
            if (
                earliest != row["created_at_earliest"]
                or latest != row["created_at_latest"]
                or skew > row["max_skew_seconds"]
            ):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_TIME_WINDOW_INVALID"
                )
            if _parse_utc(row["reconciled_at"]) is None:
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_RECONCILED_AT_INVALID"
                )

            key = (types_digest, row["generation"])
            if row["generation"] == 1:
                if row["predecessor_set_id"] is not None:
                    raise BackupSetReconciliationCorruptionError(
                        "BACKUP_SET_PREDECESSOR_INVALID"
                    )
            else:
                predecessor = seen.get((types_digest, row["generation"] - 1))
                if (
                    predecessor is None
                    or row["predecessor_set_id"] != predecessor["backup_set_id"]
                ):
                    raise BackupSetReconciliationCorruptionError(
                        "BACKUP_SET_LINEAGE_INVALID"
                    )

            identity = {
                "generation": row["generation"],
                "ledger_types": types,
                "ledger_types_digest": types_digest,
                "member_count": len(types),
                "member_digest": member_digest,
                "created_at_earliest": earliest,
                "created_at_latest": latest,
                "max_skew_seconds": row["max_skew_seconds"],
                "predecessor_set_id": row["predecessor_set_id"],
            }
            expected_id = "hqbs_" + _digest(identity)[:24]
            set_body = {
                **identity,
                "backup_set_id": expected_id,
                "reconciled_at": row["reconciled_at"],
            }
            if (
                row["backup_set_id"] != expected_id
                or _digest(set_body) != row["set_digest"]
            ):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_DIGEST_INVALID"
                )
            seen[key] = row
            rows_by_id[row["backup_set_id"]] = row

        events = self._connection.execute(
            """
            SELECT sequence, backup_set_id, set_digest, event, occurred_at,
                   previous_hash, record_hash
            FROM ledger_backup_set_audit_events ORDER BY sequence
            """
        ).fetchall()
        if len(events) != len(rows):
            raise BackupSetReconciliationCorruptionError(
                "BACKUP_SET_AUDIT_COUNT_MISMATCH"
            )
        previous_hash = None
        for expected_sequence, event in enumerate(events, start=1):
            saved = rows_by_id.get(event["backup_set_id"])
            body = {
                "sequence": event["sequence"],
                "backup_set_id": event["backup_set_id"],
                "set_digest": event["set_digest"],
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            if (
                event["sequence"] != expected_sequence
                or event["event"] != "BACKUP_SET_RECONCILED"
                or saved is None
                or event["set_digest"] != saved["set_digest"]
                or event["previous_hash"] != previous_hash
                or _parse_utc(event["occurred_at"]) is None
                or _digest(body) != event["record_hash"]
            ):
                raise BackupSetReconciliationCorruptionError(
                    "BACKUP_SET_AUDIT_CHAIN_INVALID"
                )
            previous_hash = event["record_hash"]

        return {
            **base,
            "backup_set_count": len(rows),
            "backup_set_chain": "VALID",
        }
