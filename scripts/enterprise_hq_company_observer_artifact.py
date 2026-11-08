"""Validate the sanitized aggregate-only Enterprise-HQ observer artifact."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

MAX_REPORT_BYTES = 16 * 1024
EXPECTED_REPORT_NAME = "enterprise-hq-company-summary.json"
ALLOWED_STATUSES = frozenset({
    "NOT_STARTED", "PLANNED", "CONFIGURED", "SIMULATED", "GOVERNANCE_ONLY",
    "ISOLATED_QA", "REAL_TRANSACTION", "SUSTAINED_PRODUCTION", "BLOCKED", "ACCEPTED",
})
EXPECTED_CHECKS = {
    "company_register_scope": "PASS",
    "company_completion_register": "PASS",
    "company_workstream_set": "PASS",
}
EXPECTED_CAPABILITIES = {
    "company_task_execution": "NOT_IMPLEMENTED",
    "independent_agent_identity": "NOT_AUTHENTICATED",
    "continuous_24x7_uptime": "NOT_PROVEN",
}
EXPECTED_PRIVACY = {
    "private_file_contents": "NOT_EMITTED",
    "secrets_or_tokens": "NOT_EMITTED",
    "ceo_command_audit": "NOT_FETCHED_BY_PUBLIC_OBSERVER",
    "product_source": "NOT_READ",
}
EXPECTED_TOP_LEVEL = {
    "schema_version", "scope_status", "project_001_scope", "status",
    "checks", "counts", "capability_status", "privacy_status",
}


class ArtifactValidationError(ValueError):
    """A sanitized observer artifact failed its strict schema contract."""


def _fail(code: str) -> None:
    raise ArtifactValidationError(code)


def _exact_object(value, expected_keys, code):
    if not isinstance(value, dict) or set(value) != set(expected_keys):
        _fail(code)
    return value


def _unique_object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("ARTIFACT_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_json_constant(_value):
    _fail("ARTIFACT_JSON_CONSTANT_INVALID")


def validate_observer_report(report: object) -> dict:
    """Validate an already-parsed aggregate observer report."""
    _exact_object(report, EXPECTED_TOP_LEVEL, "ARTIFACT_TOP_LEVEL_SCHEMA_INVALID")
    if (
        report["schema_version"] != "1.0.0"
        or report["scope_status"] != "PARENT_COMPANY_ONLY"
        or report["project_001_scope"] != "EXCLUDED_BY_COMPANY_WORKER_POLICY"
        or report["status"] != "OBSERVED"
    ):
        _fail("ARTIFACT_COMPANY_SCOPE_INVALID")

    checks = _exact_object(report["checks"], EXPECTED_CHECKS, "ARTIFACT_CHECKS_INVALID")
    if checks != EXPECTED_CHECKS:
        _fail("ARTIFACT_CHECKS_INVALID")

    counts = _exact_object(
        report["counts"], {"workstreams", "workstreams_by_status"},
        "ARTIFACT_COUNTS_INVALID",
    )
    total = counts["workstreams"]
    if type(total) is not int or total != 11:
        _fail("ARTIFACT_WORKSTREAM_TOTAL_INVALID")

    status_counts = counts["workstreams_by_status"]
    if not isinstance(status_counts, dict):
        _fail("ARTIFACT_STATUS_COUNTS_INVALID")
    if any(status not in ALLOWED_STATUSES for status in status_counts):
        _fail("ARTIFACT_STATUS_VOCABULARY_INVALID")
    if any(type(value) is not int or value <= 0 for value in status_counts.values()):
        _fail("ARTIFACT_STATUS_COUNT_VALUE_INVALID")
    if sum(status_counts.values()) != total:
        _fail("ARTIFACT_STATUS_COUNT_SUM_INVALID")

    capabilities = _exact_object(
        report["capability_status"], EXPECTED_CAPABILITIES,
        "ARTIFACT_CAPABILITY_SCHEMA_INVALID",
    )
    if capabilities != EXPECTED_CAPABILITIES:
        _fail("ARTIFACT_CAPABILITY_CLAIMS_INVALID")

    privacy = _exact_object(
        report["privacy_status"], EXPECTED_PRIVACY, "ARTIFACT_PRIVACY_SCHEMA_INVALID"
    )
    if privacy != EXPECTED_PRIVACY:
        _fail("ARTIFACT_PRIVACY_CLAIMS_INVALID")

    canonical = json.dumps(
        report, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "status": "ARTIFACT_VALIDATED",
        "schema_version": "1.0.0",
        "report_sha256": hashlib.sha256(canonical).hexdigest(),
        "workstreams": total,
        "status_class_count": len(status_counts),
        "execution_authorized": False,
        "private_payload_emitted": False,
    }


def validate_observer_report_text(text: str) -> dict:
    """Parse bounded JSON with duplicate-key rejection, then validate its schema."""
    if not isinstance(text, str):
        _fail("ARTIFACT_TEXT_TYPE_INVALID")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError:
        _fail("ARTIFACT_TEXT_ENCODING_INVALID")
    if len(encoded) > MAX_REPORT_BYTES:
        _fail("ARTIFACT_REPORT_TOO_LARGE")
    try:
        report = json.loads(
            text,
            object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_json_constant,
        )
    except ArtifactValidationError:
        raise
    except (json.JSONDecodeError, UnicodeDecodeError):
        _fail("ARTIFACT_JSON_INVALID")
    return validate_observer_report(report)


def validate_report_file(report_path: str, runner_temp: str) -> dict:
    """Validate only the expected regular file directly inside RUNNER_TEMP."""
    if not isinstance(runner_temp, str) or not runner_temp:
        _fail("ARTIFACT_RUNNER_TEMP_MISSING")
    try:
        root = Path(runner_temp).resolve(strict=True)
        candidate = Path(report_path)
        if not root.is_dir() or not candidate.is_absolute():
            _fail("ARTIFACT_PATH_INVALID")
        if candidate.name != EXPECTED_REPORT_NAME or candidate.is_symlink():
            _fail("ARTIFACT_PATH_INVALID")
        resolved = candidate.resolve(strict=True)
        if resolved.parent != root:
            _fail("ARTIFACT_PATH_INVALID")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                _fail("ARTIFACT_FILE_TYPE_INVALID")
            raw = stream.read(MAX_REPORT_BYTES + 1)
    except ArtifactValidationError:
        raise
    except OSError:
        _fail("ARTIFACT_FILE_READ_FAILED")
    if len(raw) > MAX_REPORT_BYTES:
        _fail("ARTIFACT_REPORT_TOO_LARGE")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail("ARTIFACT_TEXT_ENCODING_INVALID")
    return validate_observer_report_text(text)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    try:
        summary = validate_report_file(args.report, runner_temp)
    except ArtifactValidationError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
