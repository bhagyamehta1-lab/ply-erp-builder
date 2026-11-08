"""Deterministic, read-only freshness contract for periodic company observers."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"
DEFAULT_INTERVAL_SECONDS = 1800
DEFAULT_GRACE_SECONDS = 900
MAX_INTERVAL_SECONDS = 86400
MAX_GRACE_SECONDS = 86400
MAX_TIMESTAMP_CHARS = 64
MAX_FUTURE_SKEW_SECONDS = 60


class ObserverFreshnessError(ValueError):
    """A freshness input or receipt violates the bounded contract."""


def _fail(code: str) -> None:
    raise ObserverFreshnessError(code)


def _positive_integer(value, name: str, maximum: int, allow_zero: bool = False) -> int:
    if type(value) is not int:
        _fail(f"OBSERVER_FRESHNESS_{name}_INVALID")
    minimum = 0 if allow_zero else 1
    if value < minimum or value > maximum:
        _fail(f"OBSERVER_FRESHNESS_{name}_OUT_OF_RANGE")
    return value


def _parse_timestamp(value, name: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > MAX_TIMESTAMP_CHARS:
        _fail(f"OBSERVER_FRESHNESS_{name}_INVALID")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except (TypeError, ValueError):
        _fail(f"OBSERVER_FRESHNESS_{name}_INVALID")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _fail(f"OBSERVER_FRESHNESS_{name}_TIMEZONE_REQUIRED")
    return parsed.astimezone(timezone.utc)


def _canonical_digest(payload: dict) -> str:
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(rendered.encode("ascii")).hexdigest()


def evaluate_observer_freshness(
    last_success_at: str | None,
    observed_at: str,
    expected_interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    grace_seconds: int = DEFAULT_GRACE_SECONDS,
) -> dict:
    """Evaluate a supplied sanitized timestamp pair; never polls or dispatches work."""
    interval = _positive_integer(
        expected_interval_seconds, "INTERVAL", MAX_INTERVAL_SECONDS
    )
    grace = _positive_integer(
        grace_seconds, "GRACE", MAX_GRACE_SECONDS, allow_zero=True
    )
    observed = _parse_timestamp(observed_at, "OBSERVED_AT")

    age_seconds = None
    if last_success_at is None:
        status = "NEVER_OBSERVED"
    else:
        last_success = _parse_timestamp(last_success_at, "LAST_SUCCESS_AT")
        delta = (observed - last_success).total_seconds()
        if delta < -MAX_FUTURE_SKEW_SECONDS:
            status = "CLOCK_SKEW"
        else:
            age_seconds = max(0, int(delta))
            if age_seconds <= interval:
                status = "FRESH"
            elif age_seconds <= interval + grace:
                status = "GRACE_PERIOD"
            else:
                status = "MISSED"

    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "age_seconds": age_seconds,
        "expected_interval_seconds": interval,
        "grace_seconds": grace,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }
    return {**payload, "decision_digest": _canonical_digest(payload)}


def verify_observer_freshness_receipt(receipt: dict) -> dict:
    """Independently validate the bounded decision schema, invariants, and digest."""
    expected_keys = {
        "schema_version", "status", "age_seconds", "expected_interval_seconds",
        "grace_seconds", "execution_authorized", "automatic_dispatch",
        "automatic_retry", "decision_digest",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        _fail("OBSERVER_FRESHNESS_RECEIPT_SCHEMA_INVALID")
    if receipt["schema_version"] != SCHEMA_VERSION:
        _fail("OBSERVER_FRESHNESS_RECEIPT_VERSION_INVALID")
    interval = _positive_integer(
        receipt["expected_interval_seconds"], "INTERVAL", MAX_INTERVAL_SECONDS
    )
    grace = _positive_integer(
        receipt["grace_seconds"], "GRACE", MAX_GRACE_SECONDS, allow_zero=True
    )
    if any(receipt[name] is not False for name in (
        "execution_authorized", "automatic_dispatch", "automatic_retry"
    )):
        _fail("OBSERVER_FRESHNESS_RECEIPT_AUTHORITY_INVALID")

    status = receipt["status"]
    age = receipt["age_seconds"]
    if not isinstance(status, str):
        _fail("OBSERVER_FRESHNESS_RECEIPT_STATUS_INVALID")
    if status in {"NEVER_OBSERVED", "CLOCK_SKEW"}:
        if age is not None:
            _fail("OBSERVER_FRESHNESS_RECEIPT_AGE_INVALID")
    elif status in {"FRESH", "GRACE_PERIOD", "MISSED"}:
        if type(age) is not int or age < 0:
            _fail("OBSERVER_FRESHNESS_RECEIPT_AGE_INVALID")
        if status == "FRESH" and age > interval:
            _fail("OBSERVER_FRESHNESS_RECEIPT_STATUS_INVALID")
        if status == "GRACE_PERIOD" and not interval < age <= interval + grace:
            _fail("OBSERVER_FRESHNESS_RECEIPT_STATUS_INVALID")
        if status == "MISSED" and age <= interval + grace:
            _fail("OBSERVER_FRESHNESS_RECEIPT_STATUS_INVALID")
    else:
        _fail("OBSERVER_FRESHNESS_RECEIPT_STATUS_INVALID")

    digest = receipt["decision_digest"]
    if not isinstance(digest, str) or len(digest) != 64 or any(
        char not in "0123456789abcdef" for char in digest
    ):
        _fail("OBSERVER_FRESHNESS_RECEIPT_DIGEST_INVALID")
    payload = {key: receipt[key] for key in expected_keys if key != "decision_digest"}
    if _canonical_digest(payload) != digest:
        _fail("OBSERVER_FRESHNESS_RECEIPT_DIGEST_MISMATCH")
    return {
        "status": "OBSERVER_FRESHNESS_RECEIPT_VALID",
        "decision_status": status,
        "decision_digest": digest,
        "execution_authorized": False,
        "automatic_dispatch": False,
        "automatic_retry": False,
    }


__all__ = [
    "ObserverFreshnessError",
    "evaluate_observer_freshness",
    "verify_observer_freshness_receipt",
]
