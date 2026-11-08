"""Read-only verification that a recorded freshness backup still exists and matches.

The verifier emits aggregate lineage metadata only. It never creates, modifies,
restores, deletes, uploads, or retries a backup and never authorizes execution.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from scripts.enterprise_hq_observer_freshness_backup import (
    MAX_DATABASE_BYTES,
    ObserverFreshnessBackupError,
    verify_backup_file,
)
from scripts.enterprise_hq_observer_freshness_backup_receipts import (
    ObserverFreshnessBackupReceiptLedger,
)

_BACKUP_ID = re.compile(r"^hqfb_[a-f0-9]{24}$")


class ObserverFreshnessBackupAvailabilityError(ValueError):
    """Invalid availability-verification input."""


def _fail(code: str) -> None:
    raise ObserverFreshnessBackupAvailabilityError(code)


def _response(status: str, availability: str, receipt: dict | None = None) -> dict:
    result = {
        "status": status,
        "availability": availability,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    if receipt is not None:
        result["backup_id"] = receipt["backup_id"]
        result["lineage_sequence"] = receipt.get("backup_count")
        result["lineage_record_hash"] = receipt.get("record_hash")
    return result


def verify_backup_availability(
    receipt_ledger: ObserverFreshnessBackupReceiptLedger,
    backup_id: str,
    backup_path,
) -> dict:
    """Verify a recorded backup file read-only against its verified lineage receipt.

    The receipt ledger is verified before the path is inspected. Missing and
    inaccessible files are reported separately; invalid files and metadata
    mismatches fail closed. The caller-supplied path is never returned.
    """
    if (
        not isinstance(receipt_ledger, ObserverFreshnessBackupReceiptLedger)
        or receipt_ledger._connection is None
    ):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_LEDGER_REQUIRED")
    if not isinstance(backup_id, str) or not _BACKUP_ID.fullmatch(backup_id):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_ID_INVALID")
    if not isinstance(backup_path, (str, os.PathLike)):
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_PATH_INVALID")
    raw_path = os.fspath(backup_path)
    if not raw_path or raw_path == ":memory:":
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_PATH_INVALID")
    path = Path(raw_path)

    receipt = receipt_ledger.get_backup_receipt(backup_id)
    if receipt["status"] == "OBSERVER_FRESHNESS_BACKUP_RECEIPT_NOT_FOUND":
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_NOT_FOUND",
            "UNKNOWN",
            receipt,
        )
    if receipt["status"] != "OBSERVER_FRESHNESS_BACKUP_RECEIPT_FOUND":
        _fail("OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_RECEIPT_INVALID")

    try:
        parent_metadata = os.lstat(path.parent)
        metadata = os.lstat(path)
    except FileNotFoundError:
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISSING", "MISSING", receipt
        )
    except PermissionError:
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
            "UNAVAILABLE",
            receipt,
        )
    except OSError:
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
            "UNAVAILABLE",
            receipt,
        )

    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size <= 0
        or metadata.st_size > MAX_DATABASE_BYTES
    ):
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_INVALID", "INVALID", receipt
        )

    try:
        verified = verify_backup_file(path)
    except ObserverFreshnessBackupError as error:
        if "UNAVAILABLE" in str(error):
            return _response(
                "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_UNAVAILABLE",
                "UNAVAILABLE",
                receipt,
            )
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_INVALID", "INVALID", receipt
        )

    expected = {
        "file_sha256": receipt["file_sha256"],
        "receipt_count": receipt["source_receipt_count"],
        "status_counts": receipt["source_status_counts"],
        "last_sequence": receipt["last_source_sequence"],
        "chain_head_digest": receipt["source_chain_head_digest"],
    }
    actual = {
        "file_sha256": verified["file_sha256"],
        "receipt_count": verified["receipt_count"],
        "status_counts": verified["status_counts"],
        "last_sequence": verified["last_sequence"],
        "chain_head_digest": verified["chain_head_digest"],
    }
    if (
        receipt["backup_id"] != backup_id
        or verified["status"] != "OBSERVER_FRESHNESS_BACKUP_FILE_VERIFIED"
        or verified["integrity_verified"] is not True
        or actual != expected
    ):
        return _response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_MISMATCH",
            "MISMATCH",
            receipt,
        )

    return {
        **_response(
            "OBSERVER_FRESHNESS_BACKUP_AVAILABILITY_VERIFIED",
            "AVAILABLE",
            receipt,
        ),
        "file_sha256": verified["file_sha256"],
        "source_receipt_count": verified["receipt_count"],
        "source_status_counts": verified["status_counts"],
        "last_source_sequence": verified["last_sequence"],
        "source_chain_head_digest": verified["chain_head_digest"],
        "backup_integrity_verified": True,
        "lineage_match_verified": True,
    }


__all__ = [
    "ObserverFreshnessBackupAvailabilityError",
    "verify_backup_availability",
]
