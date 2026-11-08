"""Bounded, deterministic integrity checks for sanitized company evidence bundles.

This module verifies content digests and proposal/receipt bindings only. It does
not inspect semantics, authenticate principals, read files, access networks, or
retain evidence payloads. Callers must supply only approved sanitized evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping


MAX_EVIDENCE_ITEMS = 16
MAX_SINGLE_EVIDENCE_BYTES = 256 * 1024
MAX_TOTAL_EVIDENCE_BYTES = 1024 * 1024
MAX_EVIDENCE_PATH_LENGTH = 240

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Z0-9][A-Z0-9._-]{2,63}$")
_ALLOWED_PATHS = (
    re.compile(r"^docs/enterprise-hq-[A-Za-z0-9._-]+\.md$"),
    re.compile(r"^scripts/enterprise_hq_[A-Za-z0-9_]+\.py$"),
    re.compile(r"^tests/test_enterprise_hq_[A-Za-z0-9_]+\.py$"),
    re.compile(r"^\.github/workflows/enterprise-hq-parent-company-observer\.yml$"),
)
_MANIFEST_FIELDS = {
    "schema_version",
    "task_id",
    "proposal_digest",
    "receipt_id",
    "evidence",
}
_EVIDENCE_FIELDS = {"path", "sha256", "size_bytes"}


class EvidenceVerificationError(ValueError):
    """Stable, fail-closed evidence-integrity error."""


def _canonical_json(value: Mapping) -> bytes:
    try:
        return json.dumps(
            dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    except (TypeError, ValueError):
        raise EvidenceVerificationError("EVIDENCE_MANIFEST_ENCODING_INVALID") from None


def _validate_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_EVIDENCE_PATH_LENGTH
        or "\\" in value
        or value.startswith("/")
        or "//" in value
    ):
        raise EvidenceVerificationError("EVIDENCE_PATH_INVALID")
    segments = value.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise EvidenceVerificationError("EVIDENCE_PATH_INVALID")
    if not any(pattern.fullmatch(value) for pattern in _ALLOWED_PATHS):
        raise EvidenceVerificationError("EVIDENCE_PATH_OUT_OF_SCOPE")
    return value


def verify_evidence_bundle(
    manifest: Mapping,
    payloads: Mapping[str, bytes],
    *,
    expected_task_id: str,
    expected_proposal_digest: str,
    expected_receipt_id: str,
) -> dict:
    """Verify bounded evidence bytes against an exact task and receipt binding.

    Payloads are consumed in memory and never returned or persisted. Only digest,
    count, size and binding metadata are returned. The manifest must list approved
    sanitized repository paths in lexicographic order.
    """
    if not isinstance(manifest, Mapping) or set(manifest) != _MANIFEST_FIELDS:
        raise EvidenceVerificationError("EVIDENCE_MANIFEST_SCHEMA_INVALID")
    if manifest.get("schema_version") != "1.0.0":
        raise EvidenceVerificationError("EVIDENCE_MANIFEST_VERSION_UNSUPPORTED")

    task_id = manifest.get("task_id")
    proposal_digest = manifest.get("proposal_digest")
    receipt_id = manifest.get("receipt_id")
    if not isinstance(task_id, str) or not _IDENTIFIER.fullmatch(task_id):
        raise EvidenceVerificationError("EVIDENCE_TASK_ID_INVALID")
    if not isinstance(receipt_id, str) or not _IDENTIFIER.fullmatch(receipt_id):
        raise EvidenceVerificationError("EVIDENCE_RECEIPT_ID_INVALID")
    if not isinstance(proposal_digest, str) or not _HEX_64.fullmatch(proposal_digest):
        raise EvidenceVerificationError("EVIDENCE_PROPOSAL_DIGEST_INVALID")

    if task_id != expected_task_id:
        raise EvidenceVerificationError("EVIDENCE_TASK_BINDING_MISMATCH")
    if proposal_digest != expected_proposal_digest:
        raise EvidenceVerificationError("EVIDENCE_PROPOSAL_BINDING_MISMATCH")
    if receipt_id != expected_receipt_id:
        raise EvidenceVerificationError("EVIDENCE_RECEIPT_BINDING_MISMATCH")

    entries = manifest.get("evidence")
    if not isinstance(entries, list) or not entries:
        raise EvidenceVerificationError("EVIDENCE_ITEMS_REQUIRED")
    if len(entries) > MAX_EVIDENCE_ITEMS:
        raise EvidenceVerificationError("EVIDENCE_ITEM_LIMIT_EXCEEDED")
    if not isinstance(payloads, Mapping):
        raise EvidenceVerificationError("EVIDENCE_PAYLOAD_MAP_INVALID")

    validated = []
    paths = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != _EVIDENCE_FIELDS:
            raise EvidenceVerificationError("EVIDENCE_ENTRY_SCHEMA_INVALID")
        path = _validate_path(entry.get("path"))
        digest = entry.get("sha256")
        size_bytes = entry.get("size_bytes")
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            raise EvidenceVerificationError("EVIDENCE_DIGEST_INVALID")
        if type(size_bytes) is not int or size_bytes <= 0:
            raise EvidenceVerificationError("EVIDENCE_SIZE_INVALID")
        if size_bytes > MAX_SINGLE_EVIDENCE_BYTES:
            raise EvidenceVerificationError("EVIDENCE_ITEM_SIZE_LIMIT_EXCEEDED")
        paths.append(path)
        validated.append((path, digest, size_bytes))

    if len(paths) != len(set(paths)):
        raise EvidenceVerificationError("EVIDENCE_PATH_DUPLICATE")
    if paths != sorted(paths):
        raise EvidenceVerificationError("EVIDENCE_PATH_ORDER_INVALID")
    if set(payloads) != set(paths):
        raise EvidenceVerificationError("EVIDENCE_PAYLOAD_SET_MISMATCH")

    total_bytes = 0
    for path, expected_digest, expected_size in validated:
        payload = payloads[path]
        if not isinstance(payload, bytes):
            raise EvidenceVerificationError("EVIDENCE_PAYLOAD_TYPE_INVALID")
        actual_size = len(payload)
        if actual_size <= 0 or actual_size != expected_size:
            raise EvidenceVerificationError("EVIDENCE_SIZE_MISMATCH")
        if actual_size > MAX_SINGLE_EVIDENCE_BYTES:
            raise EvidenceVerificationError("EVIDENCE_ITEM_SIZE_LIMIT_EXCEEDED")
        total_bytes += actual_size
        if total_bytes > MAX_TOTAL_EVIDENCE_BYTES:
            raise EvidenceVerificationError("EVIDENCE_TOTAL_SIZE_LIMIT_EXCEEDED")
        actual_digest = hashlib.sha256(payload).hexdigest()
        if actual_digest != expected_digest:
            raise EvidenceVerificationError("EVIDENCE_DIGEST_MISMATCH")

    manifest_digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    return {
        "status": "CONTENT_INTEGRITY_VERIFIED",
        "task_id": task_id,
        "proposal_digest": proposal_digest,
        "receipt_id": receipt_id,
        "manifest_digest": manifest_digest,
        "evidence_count": len(validated),
        "total_bytes": total_bytes,
        "raw_payloads_retained": False,
        "semantic_verification": "NOT_PERFORMED",
        "identity_authenticated": False,
        "execution_authorized": False,
    }
