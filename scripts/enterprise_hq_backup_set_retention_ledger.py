"""Persistent, non-destructive retention history for cross-ledger backup sets.

An entire backup set is classified as expired when any member has passed its
declared retention deadline. This records aggregate metadata only and never
deletes inventory records or backup artifacts.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from collections.abc import Mapping

from scripts.enterprise_hq_backup_inventory import (
    BackupInventoryError,
    BackupInventoryCorruptionError,
    _digest,
    _now_utc,
    _parse_utc,
)
from scripts.enterprise_hq_backup_set_reconciliation import (
    MAX_BACKUP_SET_LEDGER_TYPES,
    MAX_BACKUP_SET_RECORDS,
)
from scripts.enterprise_hq_backup_set_restore_ledger import (
    BackupSetRestoreReceiptCorruptionError,
    BackupSetRestoreReceiptError,
    BackupSetRestoreReceiptLedger,
)

MAX_BACKUP_SET_RETENTION_EVALUATIONS = 512
MAX_BACKUP_SET_RETENTION_MEMBERS = (
    MAX_BACKUP_SET_RECORDS * MAX_BACKUP_SET_LEDGER_TYPES
)
_RETENTION_ID = re.compile(r"^hqbsre_[a-f0-9]{24}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class BackupSetRetentionError(BackupSetRestoreReceiptError):
    """A backup-set retention evaluation is invalid or outside policy."""


class BackupSetRetentionCorruptionError(BackupSetRestoreReceiptCorruptionError):
    """Persisted backup-set retention history failed integrity verification."""


class BackupSetRetentionLedger(BackupSetRestoreReceiptLedger):
    """Append-only aggregate retention history for cross-ledger backup sets."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_backup_set_retention_evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    evaluated_at TEXT NOT NULL,
                    backup_set_count INTEGER NOT NULL
                        CHECK (backup_set_count BETWEEN 0 AND 128),
                    retained_set_count INTEGER NOT NULL CHECK (retained_set_count >= 0),
                    expired_set_count INTEGER NOT NULL CHECK (expired_set_count >= 0),
                    partially_expired_set_count INTEGER NOT NULL
                        CHECK (partially_expired_set_count >= 0),
                    member_count INTEGER NOT NULL
                        CHECK (member_count BETWEEN 0 AND 2048),
                    retained_member_count INTEGER NOT NULL
                        CHECK (retained_member_count >= 0),
                    expired_member_count INTEGER NOT NULL
                        CHECK (expired_member_count >= 0),
                    set_inventory_digest TEXT NOT NULL,
                    evaluation_digest TEXT NOT NULL UNIQUE,
                    automatic_purge INTEGER NOT NULL CHECK (automatic_purge = 0),
                    records_deleted INTEGER NOT NULL CHECK (records_deleted = 0),
                    artifact_bytes_verified INTEGER NOT NULL
                        CHECK (artifact_bytes_verified = 0),
                    execution_authorized INTEGER NOT NULL
                        CHECK (execution_authorized = 0),
                    execution_resumed INTEGER NOT NULL CHECK (execution_resumed = 0),
                    automatic_retry INTEGER NOT NULL CHECK (automatic_retry = 0),
                    CHECK (retained_set_count + expired_set_count = backup_set_count),
                    CHECK (partially_expired_set_count <= expired_set_count),
                    CHECK (retained_member_count + expired_member_count = member_count)
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_set_retention_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    evaluation_id TEXT NOT NULL UNIQUE
                        REFERENCES ledger_backup_set_retention_evaluations(evaluation_id),
                    evaluation_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'BACKUP_SET_RETENTION_EVALUATED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS ledger_backup_set_retention_evaluated_at_idx
                    ON ledger_backup_set_retention_evaluations(evaluated_at);
                """
            )
        except Exception:
            self.close()
            raise

    @staticmethod
    def _evaluation_body(
        *,
        evaluated_at: str,
        backup_set_count: int,
        retained_set_count: int,
        expired_set_count: int,
        partially_expired_set_count: int,
        member_count: int,
        retained_member_count: int,
        expired_member_count: int,
        set_inventory_digest: str,
    ) -> dict:
        return {
            "evaluated_at": evaluated_at,
            "backup_set_count": backup_set_count,
            "retained_set_count": retained_set_count,
            "expired_set_count": expired_set_count,
            "partially_expired_set_count": partially_expired_set_count,
            "member_count": member_count,
            "retained_member_count": retained_member_count,
            "expired_member_count": expired_member_count,
            "set_inventory_digest": set_inventory_digest,
            "automatic_purge": False,
            "records_deleted": 0,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "execution_resumed": False,
            "automatic_retry": False,
        }

    @staticmethod
    def _retention_result(
        row, *, created: bool, already_present: bool
    ) -> dict:
        return {
            "status": "BACKUP_SET_RETENTION_EVALUATED",
            "evaluation_id": row["evaluation_id"],
            "evaluation_digest": row["evaluation_digest"],
            "set_inventory_digest": row["set_inventory_digest"],
            "evaluated_at": row["evaluated_at"],
            "backup_set_count": row["backup_set_count"],
            "retained_set_count": row["retained_set_count"],
            "expired_set_count": row["expired_set_count"],
            "partially_expired_set_count": row["partially_expired_set_count"],
            "member_count": row["member_count"],
            "retained_member_count": row["retained_member_count"],
            "expired_member_count": row["expired_member_count"],
            "created": created,
            "already_present": already_present,
            "automatic_purge": False,
            "records_deleted": 0,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "execution_resumed": False,
            "automatic_retry": False,
        }

    def _append_retention_event(
        self, evaluation_id: str, evaluation_digest: str, occurred_at: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash "
            "FROM ledger_backup_set_retention_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        body = {
            "schema_version": "1.0.0",
            "sequence": sequence,
            "evaluation_id": evaluation_id,
            "evaluation_digest": evaluation_digest,
            "event": "BACKUP_SET_RETENTION_EVALUATED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        self._connection.execute(
            """
            INSERT INTO ledger_backup_set_retention_audit_events
                (sequence, evaluation_id, evaluation_digest, event, occurred_at,
                 previous_hash, record_hash)
            VALUES (?, ?, ?, 'BACKUP_SET_RETENTION_EVALUATED', ?, ?, ?)
            """,
            (
                sequence,
                evaluation_id,
                evaluation_digest,
                occurred_at,
                previous_hash,
                _digest(body),
            ),
        )

    def evaluate_backup_set_retention(
        self, *, now: datetime | None = None
    ) -> dict:
        """Persist aggregate retention state; an expired member expires its set."""
        try:
            current = _now_utc(now)
        except BackupInventoryError as exc:
            raise BackupSetRetentionError(str(exc)) from None
        evaluated_at = current.isoformat().replace("+00:00", "Z")

        with self._transaction():
            self.verify()
            latest = self._connection.execute(
                "SELECT evaluated_at FROM ledger_backup_set_retention_evaluations "
                "ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            if latest is not None:
                previous_time = _parse_utc(latest["evaluated_at"])
                if previous_time is None:
                    raise BackupSetRetentionCorruptionError(
                        "BACKUP_SET_RETENTION_HISTORY_TIMESTAMP_INVALID"
                    )
                if current < previous_time:
                    raise BackupSetRetentionError(
                        "BACKUP_SET_RETENTION_CLOCK_ROLLBACK"
                    )

            sets = self._connection.execute(
                """
                SELECT backup_set_id, generation, ledger_types_json,
                       ledger_types_digest, member_count, set_digest
                FROM ledger_backup_sets
                ORDER BY ledger_types_digest, generation
                """
            ).fetchall()

            set_inventory = []
            backup_set_count = len(sets)
            retained_set_count = 0
            expired_set_count = 0
            partially_expired_set_count = 0
            member_count = 0
            retained_member_count = 0
            expired_member_count = 0

            for backup_set in sets:
                try:
                    ledger_types = json.loads(backup_set["ledger_types_json"])
                except (TypeError, ValueError):
                    raise BackupSetRetentionCorruptionError(
                        "BACKUP_SET_RETENTION_LEDGER_TYPES_INVALID"
                    ) from None
                if (
                    not isinstance(ledger_types, list)
                    or len(ledger_types) != backup_set["member_count"]
                    or not 2 <= len(ledger_types) <= MAX_BACKUP_SET_LEDGER_TYPES
                ):
                    raise BackupSetRetentionCorruptionError(
                        "BACKUP_SET_RETENTION_MEMBER_COUNT_INVALID"
                    )

                deadlines = []
                for ledger_type in ledger_types:
                    member = self._connection.execute(
                        """
                        SELECT retain_until FROM ledger_backup_inventory
                        WHERE ledger_type = ? AND generation = ?
                        """,
                        (ledger_type, backup_set["generation"]),
                    ).fetchone()
                    if member is None:
                        raise BackupSetRetentionCorruptionError(
                            "BACKUP_SET_RETENTION_MEMBER_MISSING"
                        )
                    deadline = _parse_utc(member["retain_until"])
                    if deadline is None:
                        raise BackupSetRetentionCorruptionError(
                            "BACKUP_SET_RETENTION_DEADLINE_INVALID"
                        )
                    deadlines.append(deadline)

                expired_for_set = sum(1 for deadline in deadlines if deadline <= current)
                retained_for_set = len(deadlines) - expired_for_set
                member_count += len(deadlines)
                retained_member_count += retained_for_set
                expired_member_count += expired_for_set

                if expired_for_set:
                    expired_set_count += 1
                    if retained_for_set:
                        partially_expired_set_count += 1
                else:
                    retained_set_count += 1

                set_inventory.append(
                    {
                        "set_digest": backup_set["set_digest"],
                        "generation": backup_set["generation"],
                        "ledger_types_digest": backup_set["ledger_types_digest"],
                        "member_count": len(deadlines),
                        "earliest_retain_until": min(deadlines).isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "latest_retain_until": max(deadlines).isoformat().replace(
                            "+00:00", "Z"
                        ),
                        "retained_member_count": retained_for_set,
                        "expired_member_count": expired_for_set,
                    }
                )

            set_inventory_digest = _digest({"sets": set_inventory})
            body = self._evaluation_body(
                evaluated_at=evaluated_at,
                backup_set_count=backup_set_count,
                retained_set_count=retained_set_count,
                expired_set_count=expired_set_count,
                partially_expired_set_count=partially_expired_set_count,
                member_count=member_count,
                retained_member_count=retained_member_count,
                expired_member_count=expired_member_count,
                set_inventory_digest=set_inventory_digest,
            )
            evaluation_digest = _digest(body)
            evaluation_id = "hqbsre_" + evaluation_digest[:24]

            existing = self._connection.execute(
                "SELECT * FROM ledger_backup_set_retention_evaluations "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            if existing is not None:
                if existing["evaluation_digest"] != evaluation_digest:
                    raise BackupSetRetentionError(
                        "BACKUP_SET_RETENTION_EVALUATION_CONFLICT"
                    )
                return self._retention_result(
                    existing, created=False, already_present=True
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_set_retention_evaluations"
            ).fetchone()[0]
            if count >= MAX_BACKUP_SET_RETENTION_EVALUATIONS:
                raise BackupSetRetentionError(
                    "BACKUP_SET_RETENTION_CAPACITY_REACHED"
                )

            self._connection.execute(
                """
                INSERT INTO ledger_backup_set_retention_evaluations
                    (evaluation_id, evaluated_at, backup_set_count,
                     retained_set_count, expired_set_count,
                     partially_expired_set_count, member_count,
                     retained_member_count, expired_member_count,
                     set_inventory_digest, evaluation_digest, automatic_purge,
                     records_deleted, artifact_bytes_verified,
                     execution_authorized, execution_resumed, automatic_retry)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0)
                """,
                (
                    evaluation_id,
                    evaluated_at,
                    backup_set_count,
                    retained_set_count,
                    expired_set_count,
                    partially_expired_set_count,
                    member_count,
                    retained_member_count,
                    expired_member_count,
                    set_inventory_digest,
                    evaluation_digest,
                ),
            )
            self._append_retention_event(
                evaluation_id, evaluation_digest, evaluated_at
            )
            saved = self._connection.execute(
                "SELECT * FROM ledger_backup_set_retention_evaluations "
                "WHERE evaluation_id = ?",
                (evaluation_id,),
            ).fetchone()
            return self._retention_result(
                saved, created=True, already_present=False
            )

    def verify(self) -> dict:
        """Verify inherited histories and the complete backup-set retention chain."""
        base = super().verify()
        rows = self._connection.execute(
            """
            SELECT evaluation_id, evaluated_at, backup_set_count,
                   retained_set_count, expired_set_count,
                   partially_expired_set_count, member_count,
                   retained_member_count, expired_member_count,
                   set_inventory_digest, evaluation_digest, automatic_purge,
                   records_deleted, artifact_bytes_verified,
                   execution_authorized, execution_resumed, automatic_retry
            FROM ledger_backup_set_retention_evaluations
            ORDER BY rowid
            """
        ).fetchall()
        if len(rows) > MAX_BACKUP_SET_RETENTION_EVALUATIONS:
            raise BackupSetRetentionCorruptionError(
                "BACKUP_SET_RETENTION_CAPACITY_INVARIANT_FAILED"
            )

        rows_by_id = {}
        for row in rows:
            evaluated = _parse_utc(row["evaluated_at"])
            counts = (
                row["backup_set_count"],
                row["retained_set_count"],
                row["expired_set_count"],
                row["partially_expired_set_count"],
                row["member_count"],
                row["retained_member_count"],
                row["expired_member_count"],
            )
            digests = (row["set_inventory_digest"], row["evaluation_digest"])
            if (
                not isinstance(row["evaluation_id"], str)
                or not _RETENTION_ID.fullmatch(row["evaluation_id"])
                or evaluated is None
                or row["evaluated_at"] != evaluated.isoformat().replace("+00:00", "Z")
                or any(type(value) is not int for value in counts)
                or not 0 <= row["backup_set_count"] <= MAX_BACKUP_SET_RECORDS
                or row["retained_set_count"] + row["expired_set_count"]
                    != row["backup_set_count"]
                or not 0 <= row["partially_expired_set_count"]
                    <= row["expired_set_count"]
                or not 0 <= row["member_count"] <= MAX_BACKUP_SET_RETENTION_MEMBERS
                or row["retained_member_count"] + row["expired_member_count"]
                    != row["member_count"]
                or any(not isinstance(value, str) or not _HEX_64.fullmatch(value)
                       for value in digests)
                or row["automatic_purge"] != 0
                or row["records_deleted"] != 0
                or row["artifact_bytes_verified"] != 0
                or row["execution_authorized"] != 0
                or row["execution_resumed"] != 0
                or row["automatic_retry"] != 0
            ):
                raise BackupSetRetentionCorruptionError(
                    "BACKUP_SET_RETENTION_EVALUATION_INVARIANT_FAILED"
                )

            body = self._evaluation_body(
                evaluated_at=row["evaluated_at"],
                backup_set_count=row["backup_set_count"],
                retained_set_count=row["retained_set_count"],
                expired_set_count=row["expired_set_count"],
                partially_expired_set_count=row["partially_expired_set_count"],
                member_count=row["member_count"],
                retained_member_count=row["retained_member_count"],
                expired_member_count=row["expired_member_count"],
                set_inventory_digest=row["set_inventory_digest"],
            )
            expected_digest = _digest(body)
            expected_id = "hqbsre_" + expected_digest[:24]
            if (
                row["evaluation_id"] != expected_id
                or row["evaluation_digest"] != expected_digest
            ):
                raise BackupSetRetentionCorruptionError(
                    "BACKUP_SET_RETENTION_EVALUATION_DIGEST_INVALID"
                )
            rows_by_id[row["evaluation_id"]] = row

        events = self._connection.execute(
            """
            SELECT sequence, evaluation_id, evaluation_digest, event,
                   occurred_at, previous_hash, record_hash
            FROM ledger_backup_set_retention_audit_events
            ORDER BY sequence
            """
        ).fetchall()
        if len(events) != len(rows):
            raise BackupSetRetentionCorruptionError(
                "BACKUP_SET_RETENTION_AUDIT_COUNT_MISMATCH"
            )

        previous_hash = None
        for expected_sequence, event in enumerate(events, start=1):
            saved = rows_by_id.get(event["evaluation_id"])
            body = {
                "schema_version": "1.0.0",
                "sequence": event["sequence"],
                "evaluation_id": event["evaluation_id"],
                "evaluation_digest": event["evaluation_digest"],
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            if (
                event["sequence"] != expected_sequence
                or event["event"] != "BACKUP_SET_RETENTION_EVALUATED"
                or saved is None
                or event["evaluation_digest"] != saved["evaluation_digest"]
                or event["occurred_at"] != saved["evaluated_at"]
                or event["previous_hash"] != previous_hash
                or _digest(body) != event["record_hash"]
            ):
                raise BackupSetRetentionCorruptionError(
                    "BACKUP_SET_RETENTION_AUDIT_CHAIN_INVALID"
                )
            previous_hash = event["record_hash"]

        return {
            **base,
            "backup_set_retention_evaluation_count": len(rows),
            "backup_set_retention_audit_event_count": len(events),
            "backup_set_retention_chain": "VALID",
            "backup_set_retention_automatic_purge": False,
            "backup_set_retention_artifact_bytes_verified": False,
        }

    def recover_after_restart(self) -> dict:
        """Verify retention metadata after restart; never purge or resume work."""
        base = super().recover_after_restart()
        verified = self.verify()
        return {
            **base,
            "backup_set_retention_evaluations_recovered": (
                verified["backup_set_retention_evaluation_count"]
            ),
            "backup_set_retention_audit_events_recovered": (
                verified["backup_set_retention_audit_event_count"]
            ),
            "backup_set_retention_automatic_purge": False,
            "backup_set_retention_payloads_retained": 0,
            "execution_authorized": False,
            "execution_resumed": False,
            "automatic_retry": False,
        }


__all__ = [
    "BackupSetRetentionError",
    "BackupSetRetentionCorruptionError",
    "BackupSetRetentionLedger",
    "MAX_BACKUP_SET_RETENTION_EVALUATIONS",
    "MAX_BACKUP_SET_RETENTION_MEMBERS",
]
