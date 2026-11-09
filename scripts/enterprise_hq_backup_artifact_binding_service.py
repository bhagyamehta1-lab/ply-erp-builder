"""Orchestrate explicit backup-artifact verification and its durable local receipt.

This helper records only a binding result that passed the three-ledger verifier,
then independently verifies and reads back the append-only receipt. It does not
inspect artifact bytes, restore files, dispatch tasks, or contact external systems.
"""
from __future__ import annotations

from collections.abc import Mapping

from scripts.enterprise_hq_backup_artifact_binding import (
    verify_backup_artifact_binding,
)
from scripts.enterprise_hq_backup_artifact_binding_ledger import (
    BackupArtifactBindingLedger,
    BackupArtifactBindingLedgerError,
)


class BackupArtifactBindingServiceError(ValueError):
    """The binding could not be safely verified and recorded."""


def _fail(code: str) -> None:
    raise BackupArtifactBindingServiceError(code)


def verify_and_record_backup_artifact_binding(
    inventory,
    receipt_ledger,
    availability_ledger,
    binding: Mapping,
    binding_ledger: BackupArtifactBindingLedger,
    *,
    recorded_at: str | None = None,
) -> dict:
    """Verify one explicit association, append it once, and verify its readback.

    The source verifier independently checks all three source-ledger snapshots.
    The binding receipt ledger then persists only its aggregate result. A second
    full receipt-history verification and digest lookup establish that the
    append (or idempotent replay) is present and hash-chain valid.

    The receipt is historical evidence of the verified snapshot. Later source
    changes do not rewrite or invalidate that historical receipt.
    """
    if not isinstance(binding_ledger, BackupArtifactBindingLedger):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_LEDGER_REQUIRED")
    if binding_ledger._connection is None:
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_LEDGER_NOT_OPEN")

    try:
        before = binding_ledger.verify()
    except Exception as exc:
        raise BackupArtifactBindingServiceError(
            "BACKUP_ARTIFACT_BINDING_SERVICE_INITIAL_HISTORY_INVALID"
        ) from exc
    if (
        not isinstance(before, Mapping)
        or before.get("status") != "BACKUP_ARTIFACT_BINDING_RECEIPT_LEDGER_VALID"
        or type(before.get("receipt_count")) is not int
        or before["receipt_count"] < 0
        or before["receipt_count"] > 512
        or before.get("execution_authorized") is not False
        or before.get("automatic_dispatch") is not False
        or before.get("automatic_retry") is not False
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_INITIAL_HISTORY_INVALID")

    verified = verify_backup_artifact_binding(
        inventory, receipt_ledger, availability_ledger, binding
    )
    if not isinstance(verified, Mapping):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_VERIFIER_RESULT_INVALID")

    try:
        appended = binding_ledger.append_verified_binding(
            verified, recorded_at=recorded_at
        )
    except BackupArtifactBindingLedgerError as exc:
        raise BackupArtifactBindingServiceError(
            "BACKUP_ARTIFACT_BINDING_SERVICE_APPEND_REJECTED"
        ) from exc

    digest = verified.get("binding_digest")
    if (
        not isinstance(appended, Mapping)
        or appended.get("status") not in {
            "BACKUP_ARTIFACT_BINDING_RECEIPT_RECORDED",
            "BACKUP_ARTIFACT_BINDING_RECEIPT_REPLAYED",
        }
        or appended.get("binding_digest") != digest
        or type(appended.get("sequence")) is not int
        or appended["sequence"] < 1
        or not isinstance(appended.get("receipt_id"), str)
        or not isinstance(appended.get("record_hash"), str)
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_APPEND_RESPONSE_INVALID")

    try:
        after = binding_ledger.verify()
        found = binding_ledger.get_receipt(digest)
    except Exception as exc:
        raise BackupArtifactBindingServiceError(
            "BACKUP_ARTIFACT_BINDING_SERVICE_POST_APPEND_HISTORY_INVALID"
        ) from exc

    if (
        not isinstance(after, Mapping)
        or after.get("status") != "BACKUP_ARTIFACT_BINDING_RECEIPT_LEDGER_VALID"
        or type(after.get("receipt_count")) is not int
        or after["receipt_count"] < before["receipt_count"]
        or after["receipt_count"] < appended["sequence"]
        or after["receipt_count"] > 512
        or not isinstance(found, Mapping)
        or found.get("status") != "BACKUP_ARTIFACT_BINDING_RECEIPT_FOUND"
        or found.get("receipt_id") != appended["receipt_id"]
        or found.get("sequence") != appended["sequence"]
        or found.get("binding_digest") != digest
        or found.get("record_hash") != appended["record_hash"]
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_RECEIPT_READBACK_MISMATCH")

    if (
        after.get("last_sequence") == appended["sequence"]
        and after.get("chain_head_hash") != appended["record_hash"]
    ):
        _fail("BACKUP_ARTIFACT_BINDING_SERVICE_CHAIN_HEAD_MISMATCH")

    replayed = appended["status"] == "BACKUP_ARTIFACT_BINDING_RECEIPT_REPLAYED"
    return {
        "status": (
            "BACKUP_ARTIFACT_BINDING_AUDIT_REPLAYED" if replayed
            else "BACKUP_ARTIFACT_BINDING_AUDIT_RECORDED"
        ),
        "binding_status": "METADATA_ASSOCIATION_VERIFIED",
        "binding_basis": "EXPLICIT_CALLER_ASSOCIATION",
        "receipt_status": "REPLAYED" if replayed else "RECORDED",
        "receipt_sequence": appended["sequence"],
        "receipt_count": after["receipt_count"],
        "source_binding_verified": True,
        "receipt_history_verified": True,
        "receipt_readback_verified": True,
        "availability": "AVAILABLE",
        "inventory_artifact_presence": "NOT_INSPECTED",
        "artifact_bytes_verified": False,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "BackupArtifactBindingServiceError",
    "verify_and_record_backup_artifact_binding",
]
