"""Persistent metadata-only receipts for cross-ledger backup-set restoration checks.

The receipt ledger records only digests, counts, and timestamps after the
specialized source/restored snapshot verifier succeeds. It never handles
backup artifacts or authorizes execution.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from scripts.enterprise_hq_backup_inventory import (
    BackupInventoryCorruptionError,
    BackupInventoryError,
    _digest,
    _now_utc,
    _parse_utc,
)
from scripts.enterprise_hq_backup_set_reconciliation import (
    CrossLedgerBackupSetInventory,
)
from scripts.enterprise_hq_backup_set_restore_verifier import (
    BackupSetRestoreEquivalenceError,
    verify_backup_set_restore_equivalence,
)

MAX_BACKUP_SET_RESTORE_RECEIPTS = 256
_RECEIPT_ID = re.compile(r"^hqbr_[a-f0-9]{24}$")
_HEX_64 = re.compile(r"^[a-f0-9]{64}$")


class BackupSetRestoreReceiptError(BackupInventoryError):
    """A restoration receipt is invalid, conflicting, or outside policy."""


class BackupSetRestoreReceiptCorruptionError(BackupInventoryCorruptionError):
    """Persisted restoration-receipt history failed integrity verification."""


class BackupSetRestoreReceiptLedger(CrossLedgerBackupSetInventory):
    """Append-only receipt history for verified cross-ledger backup restorations."""

    def __init__(self, database: str):
        super().__init__(database)
        try:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_backup_set_restore_receipts (
                    receipt_id TEXT PRIMARY KEY,
                    source_snapshot_digest TEXT NOT NULL,
                    restored_snapshot_digest TEXT NOT NULL,
                    backup_set_count INTEGER NOT NULL
                        CHECK (backup_set_count BETWEEN 1 AND 128),
                    audit_event_count INTEGER NOT NULL
                        CHECK (audit_event_count BETWEEN 1 AND 128),
                    source_audit_head_hash TEXT NOT NULL,
                    restored_audit_head_hash TEXT NOT NULL,
                    verified_at TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL UNIQUE,
                    execution_authorized INTEGER NOT NULL
                        CHECK (execution_authorized = 0),
                    execution_resumed INTEGER NOT NULL
                        CHECK (execution_resumed = 0),
                    automatic_retry INTEGER NOT NULL
                        CHECK (automatic_retry = 0)
                );
                CREATE TABLE IF NOT EXISTS ledger_backup_set_restore_audit_events (
                    sequence INTEGER PRIMARY KEY,
                    receipt_id TEXT NOT NULL UNIQUE
                        REFERENCES ledger_backup_set_restore_receipts(receipt_id),
                    receipt_digest TEXT NOT NULL,
                    event TEXT NOT NULL
                        CHECK (event = 'BACKUP_SET_RESTORE_VERIFIED'),
                    occurred_at TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS ledger_backup_set_restore_verified_at_idx
                    ON ledger_backup_set_restore_receipts(verified_at);
                """
            )
        except Exception:
            self.close()
            raise

    @staticmethod
    def _receipt_body(verification: Mapping, verified_at: str) -> dict:
        return {
            "source_snapshot_digest": verification["source_snapshot_digest"],
            "restored_snapshot_digest": verification["restored_snapshot_digest"],
            "backup_set_count": verification["backup_set_count"],
            "audit_event_count": verification["backup_set_audit_event_count"],
            "source_audit_head_hash": verification["source_audit_head_hash"],
            "restored_audit_head_hash": verification["restored_audit_head_hash"],
            "verified_at": verified_at,
        }

    @staticmethod
    def _receipt_result(row, *, created: bool, already_present: bool) -> dict:
        return {
            "status": "BACKUP_SET_RESTORE_RECEIPT_RECORDED",
            "receipt_id": row["receipt_id"],
            "backup_set_count": row["backup_set_count"],
            "audit_event_count": row["audit_event_count"],
            "source_snapshot_digest": row["source_snapshot_digest"],
            "restored_snapshot_digest": row["restored_snapshot_digest"],
            "source_audit_head_hash": row["source_audit_head_hash"],
            "restored_audit_head_hash": row["restored_audit_head_hash"],
            "verified_at": row["verified_at"],
            "created": created,
            "already_present": already_present,
            "artifact_bytes_verified": False,
            "execution_authorized": False,
            "execution_resumed": False,
            "automatic_retry": False,
        }

    def _append_restore_event(
        self, receipt_id: str, receipt_digest: str, occurred_at: str
    ) -> None:
        previous = self._connection.execute(
            "SELECT sequence, record_hash "
            "FROM ledger_backup_set_restore_audit_events "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if previous is None else previous["sequence"] + 1
        previous_hash = None if previous is None else previous["record_hash"]
        body = {
            "sequence": sequence,
            "receipt_id": receipt_id,
            "receipt_digest": receipt_digest,
            "event": "BACKUP_SET_RESTORE_VERIFIED",
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        self._connection.execute(
            """
            INSERT INTO ledger_backup_set_restore_audit_events
                (sequence, receipt_id, receipt_digest, event, occurred_at,
                 previous_hash, record_hash)
            VALUES (?, ?, ?, 'BACKUP_SET_RESTORE_VERIFIED', ?, ?, ?)
            """,
            (
                sequence,
                receipt_id,
                receipt_digest,
                occurred_at,
                previous_hash,
                _digest(body),
            ),
        )

    def record_restore_verification(
        self, source_snapshot: Mapping, restored_snapshot: Mapping, *, now=None
    ) -> dict:
        """Verify snapshots and atomically append a bounded metadata-only receipt."""
        try:
            current = _now_utc(now)
        except BackupInventoryError as exc:
            raise BackupSetRestoreReceiptError(str(exc)) from None
        verified_at = current.isoformat().replace("+00:00", "Z")

        with self._transaction():
            self.verify()
            try:
                verification = verify_backup_set_restore_equivalence(
                    source_snapshot, restored_snapshot
                )
            except BackupSetRestoreEquivalenceError:
                raise

            body = self._receipt_body(verification, verified_at)
            receipt_id = "hqbr_" + _digest(body)[:24]
            receipt_body = {"receipt_id": receipt_id, **body}
            receipt_digest = _digest(receipt_body)

            existing = self._connection.execute(
                "SELECT * FROM ledger_backup_set_restore_receipts "
                "WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if existing is not None:
                if existing["receipt_digest"] != receipt_digest:
                    raise BackupSetRestoreReceiptError(
                        "BACKUP_SET_RESTORE_RECEIPT_CONFLICT"
                    )
                return self._receipt_result(
                    existing, created=False, already_present=True
                )

            count = self._connection.execute(
                "SELECT COUNT(*) FROM ledger_backup_set_restore_receipts"
            ).fetchone()[0]
            if count >= MAX_BACKUP_SET_RESTORE_RECEIPTS:
                raise BackupSetRestoreReceiptError(
                    "BACKUP_SET_RESTORE_RECEIPT_CAPACITY_REACHED"
                )

            self._connection.execute(
                """
                INSERT INTO ledger_backup_set_restore_receipts
                    (receipt_id, source_snapshot_digest, restored_snapshot_digest,
                     backup_set_count, audit_event_count, source_audit_head_hash,
                     restored_audit_head_hash, verified_at, receipt_digest,
                     execution_authorized, execution_resumed, automatic_retry)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0)
                """,
                (
                    receipt_id,
                    body["source_snapshot_digest"],
                    body["restored_snapshot_digest"],
                    body["backup_set_count"],
                    body["audit_event_count"],
                    body["source_audit_head_hash"],
                    body["restored_audit_head_hash"],
                    verified_at,
                    receipt_digest,
                ),
            )
            self._append_restore_event(receipt_id, receipt_digest, verified_at)
            saved = self._connection.execute(
                "SELECT * FROM ledger_backup_set_restore_receipts "
                "WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            return self._receipt_result(
                saved, created=True, already_present=False
            )

    def verify(self) -> dict:
        """Verify inherited backup-set history and the complete receipt audit chain."""
        base = super().verify()
        rows = self._connection.execute(
            """
            SELECT receipt_id, source_snapshot_digest, restored_snapshot_digest,
                   backup_set_count, audit_event_count, source_audit_head_hash,
                   restored_audit_head_hash, verified_at, receipt_digest,
                   execution_authorized, execution_resumed, automatic_retry
            FROM ledger_backup_set_restore_receipts
            ORDER BY verified_at, receipt_id
            """
        ).fetchall()
        if len(rows) > MAX_BACKUP_SET_RESTORE_RECEIPTS:
            raise BackupSetRestoreReceiptCorruptionError(
                "BACKUP_SET_RESTORE_RECEIPT_CAPACITY_INVARIANT_FAILED"
            )

        rows_by_id = {}
        for row in rows:
            verified = _parse_utc(row["verified_at"])
            counts = (row["backup_set_count"], row["audit_event_count"])
            digests = (
                row["source_snapshot_digest"],
                row["restored_snapshot_digest"],
                row["source_audit_head_hash"],
                row["restored_audit_head_hash"],
                row["receipt_digest"],
            )
            if (
                not isinstance(row["receipt_id"], str)
                or not _RECEIPT_ID.fullmatch(row["receipt_id"])
                or verified is None
                or row["verified_at"] != verified.isoformat().replace("+00:00", "Z")
                or any(type(value) is not int for value in counts)
                or not 1 <= row["backup_set_count"] <= 128
                or row["audit_event_count"] != row["backup_set_count"]
                or any(not isinstance(value, str) or not _HEX_64.fullmatch(value)
                       for value in digests)
                or row["source_snapshot_digest"] != row["restored_snapshot_digest"]
                or row["source_audit_head_hash"] != row["restored_audit_head_hash"]
                or row["execution_authorized"] != 0
                or row["execution_resumed"] != 0
                or row["automatic_retry"] != 0
            ):
                raise BackupSetRestoreReceiptCorruptionError(
                    "BACKUP_SET_RESTORE_RECEIPT_INVARIANT_FAILED"
                )

            body = {
                "source_snapshot_digest": row["source_snapshot_digest"],
                "restored_snapshot_digest": row["restored_snapshot_digest"],
                "backup_set_count": row["backup_set_count"],
                "audit_event_count": row["audit_event_count"],
                "source_audit_head_hash": row["source_audit_head_hash"],
                "restored_audit_head_hash": row["restored_audit_head_hash"],
                "verified_at": row["verified_at"],
            }
            expected_id = "hqbr_" + _digest(body)[:24]
            expected_digest = _digest({"receipt_id": expected_id, **body})
            if (
                row["receipt_id"] != expected_id
                or row["receipt_digest"] != expected_digest
            ):
                raise BackupSetRestoreReceiptCorruptionError(
                    "BACKUP_SET_RESTORE_RECEIPT_DIGEST_INVALID"
                )
            rows_by_id[row["receipt_id"]] = row

        events = self._connection.execute(
            """
            SELECT sequence, receipt_id, receipt_digest, event, occurred_at,
                   previous_hash, record_hash
            FROM ledger_backup_set_restore_audit_events
            ORDER BY sequence
            """
        ).fetchall()
        if len(events) != len(rows):
            raise BackupSetRestoreReceiptCorruptionError(
                "BACKUP_SET_RESTORE_AUDIT_COUNT_MISMATCH"
            )

        previous_hash = None
        for expected_sequence, event in enumerate(events, start=1):
            saved = rows_by_id.get(event["receipt_id"])
            body = {
                "sequence": event["sequence"],
                "receipt_id": event["receipt_id"],
                "receipt_digest": event["receipt_digest"],
                "event": event["event"],
                "occurred_at": event["occurred_at"],
                "previous_hash": event["previous_hash"],
            }
            occurred = _parse_utc(event["occurred_at"])
            if (
                event["sequence"] != expected_sequence
                or event["event"] != "BACKUP_SET_RESTORE_VERIFIED"
                or saved is None
                or event["receipt_digest"] != saved["receipt_digest"]
                or event["occurred_at"] != saved["verified_at"]
                or occurred is None
                or event["previous_hash"] != previous_hash
                or _digest(body) != event["record_hash"]
            ):
                raise BackupSetRestoreReceiptCorruptionError(
                    "BACKUP_SET_RESTORE_AUDIT_CHAIN_INVALID"
                )
            previous_hash = event["record_hash"]

        return {
            **base,
            "backup_set_restore_receipt_count": len(rows),
            "backup_set_restore_receipt_chain": "VALID",
        }


__all__ = [
    "BackupSetRestoreReceiptError",
    "BackupSetRestoreReceiptCorruptionError",
    "BackupSetRestoreReceiptLedger",
    "MAX_BACKUP_SET_RESTORE_RECEIPTS",
]
