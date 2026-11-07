#!/usr/bin/env python3
"""Read-only, privacy-minimizing observer for the Enterprise-HQ parent company."""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

HQ_REPOSITORY = "bhagyamehta1-lab/Enterprise-HQ"
API = "https://api.github.com"
FILES = {
    "identity": "company_identity.json",
    "audit": "state/ceo_command_audit.json",
    "register": "state/company_completion_register.json",
}
ALLOWED_PRIVATE_PATHS = frozenset(FILES.values())
ALLOWED_WORKSTREAMS = {f"WS-{number:02d}" for number in range(1, 12)}
WORKSTREAM_STATUSES = frozenset({
    "NOT_STARTED", "PLANNED", "CONFIGURED", "SIMULATED", "GOVERNANCE_ONLY",
    "ISOLATED_QA", "REAL_TRANSACTION", "SUSTAINED_PRODUCTION", "BLOCKED", "ACCEPTED",
})
READINESS_STATUS_ALLOWLIST = {
    "company_operating_status": frozenset({"IN_DEVELOPMENT_NOT_CERTIFIED"}),
    "legal_entity_status": frozenset({"NOT_VERIFIED_FROM_REPOSITORY"}),
    "independent_ai_operations_status": frozenset({"NOT_CERTIFIED"}),
    "continuous_24x7_status": frozenset({"NOT_CERTIFIED"}),
}
REQUIRED_SAFETY_BOOLEAN_FIELDS = frozenset({
    "safe_hold", "execution_hold", "dispatch_enabled", "product_task_execution",
    "builds_enabled", "releases_enabled", "deployments_enabled", "public_releases_enabled",
    "production_migrations_enabled", "production_release_authorized",
})
MAX_PRIVATE_RECORD_BYTES = 512 * 1024
STATUS_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class ObserverError(RuntimeError):
    """A sanitized observer failure."""


def fetch_private_json(path: str, token: str) -> dict:
    if path not in ALLOWED_PRIVATE_PATHS:
        raise ObserverError("PRIVATE_RECORD_PATH_NOT_ALLOWED")
    encoded_path = urllib.parse.quote(path, safe="/")
    url = f"{API}/repos/{HQ_REPOSITORY}/contents/{encoded_path}?ref=main"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "enterprise-hq-parent-company-observer",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read(MAX_PRIVATE_RECORD_BYTES + 1)
        if len(raw) > MAX_PRIVATE_RECORD_BYTES:
            raise ObserverError("PRIVATE_RECORD_TOO_LARGE")
        envelope = json.loads(raw.decode("utf-8"))
        if not isinstance(envelope, dict) or not isinstance(envelope.get("content"), str):
            raise ObserverError("PRIVATE_RECORD_PARSE_FAILED")
        encoded_content = "".join(envelope["content"].split())
        content = base64.b64decode(encoded_content, validate=True).decode("utf-8")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
        return value
    except ObserverError:
        raise
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        raise ObserverError("PRIVATE_RECORD_READ_FAILED") from None
    except (KeyError, ValueError, UnicodeDecodeError):
        raise ObserverError("PRIVATE_RECORD_PARSE_FAILED") from None


def _validate_audit_envelope(audit: dict) -> None:
    if (audit.get("schema_version") != "1.0.0"
            or not isinstance(audit.get("enterprise_status"), str)
            or not STATUS_PATTERN.fullmatch(audit["enterprise_status"])
            or not isinstance(audit.get("safety"), dict)):
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")
    timestamp = audit.get("timestamp")
    if not isinstance(timestamp, str):
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID") from None
    if parsed.tzinfo is None:
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")

    safety = audit["safety"]
    if any(type(safety.get(key)) is not bool for key in REQUIRED_SAFETY_BOOLEAN_FIELDS):
        raise ObserverError("CEO_AUDIT_SAFETY_SCHEMA_INVALID")
    for key in ("active_in_progress_task_count", "active_dispatch_task_count"):
        value = safety.get(key)
        if type(value) is not int or value < 0:
            raise ObserverError("CEO_AUDIT_SAFETY_SCHEMA_INVALID")
    if not isinstance(safety.get("task_scoped_build_authorizations"), dict):
        raise ObserverError("CEO_AUDIT_SAFETY_SCHEMA_INVALID")


def summarize(records: dict) -> dict:
    if not isinstance(records, dict) or set(records) != set(FILES):
        raise ObserverError("PRIVATE_RECORD_SET_INVALID")
    identity = records["identity"]
    audit = records["audit"]
    register = records["register"]
    if not all(isinstance(row, dict) for row in (identity, audit, register)):
        raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")

    company = identity.get("company", {})
    portfolio = identity.get("project_portfolio", {})
    authority = register.get("authority", {})
    if not all(isinstance(row, dict) for row in (company, portfolio, authority)):
        raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
    first_project = portfolio.get("first_project", {})
    if not isinstance(first_project, dict):
        raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
    if (company.get("name") != "Enterprise-HQ"
            or company.get("canonical_repository") != HQ_REPOSITORY
            or company.get("is_product_app") is not False):
        raise ObserverError("PARENT_COMPANY_IDENTITY_CHECK_FAILED")
    if (first_project.get("project_id") != "PROJECT-001"
            or first_project.get("name") != "PLY ERP"
            or first_project.get("repository") != "bhagyamehta1-lab/PLY_ERP"):
        raise ObserverError("PROJECT_BOUNDARY_CHECK_FAILED")
    _validate_audit_envelope(audit)
    if (register.get("schema_version") != "1.0.0"
            or authority.get("scope") != "Enterprise-HQ parent company only"):
        raise ObserverError("COMPANY_REGISTER_SCOPE_INVALID")

    vocabulary = register.get("status_vocabulary")
    if not isinstance(vocabulary, list) or set(vocabulary) != WORKSTREAM_STATUSES:
        raise ObserverError("COMPANY_STATUS_VOCABULARY_INVALID")
    workstreams = register.get("workstreams", [])
    if not isinstance(workstreams, list) or len(workstreams) != len(ALLOWED_WORKSTREAMS):
        raise ObserverError("COMPANY_WORKSTREAM_COLLECTION_INVALID")
    workstream_ids = set()
    statuses = []
    for row in workstreams:
        if not isinstance(row, dict):
            raise ObserverError("COMPANY_WORKSTREAM_ROW_INVALID")
        workstream_id = row.get("workstream_id")
        status = row.get("status")
        if (not isinstance(workstream_id, str) or workstream_id not in ALLOWED_WORKSTREAMS
                or not isinstance(status, str) or status not in WORKSTREAM_STATUSES):
            raise ObserverError("COMPANY_WORKSTREAM_ROW_INVALID")
        workstream_ids.add(workstream_id)
        statuses.append(status)
    if workstream_ids != ALLOWED_WORKSTREAMS:
        raise ObserverError("COMPANY_WORKSTREAM_SET_INVALID")

    readiness = identity.get("readiness", {})
    if not isinstance(readiness, dict):
        raise ObserverError("COMPANY_READINESS_SCHEMA_INVALID")
    readiness_statuses = {}
    for key, allowed_values in READINESS_STATUS_ALLOWLIST.items():
        value = readiness.get(key)
        readiness_statuses[key] = value if isinstance(value, str) and value in allowed_values else "UNKNOWN"

    return {
        "schema_version": "1.0.0",
        "scope_status": "PARENT_COMPANY_ONLY",
        "status": "OBSERVED",
        "checks": {
            "parent_company_identity": "PASS",
            "project_001_boundary": "PASS",
            "ceo_audit_schema": "PASS",
            "company_completion_register": "PASS",
        },
        "counts": {
            "workstreams": len(workstreams),
            "workstreams_by_status": dict(sorted(Counter(statuses).items())),
        },
        "readiness": readiness_statuses,
        "capability_status": {
            "company_task_execution": "NOT_IMPLEMENTED",
            "independent_agent_identity": "NOT_AUTHENTICATED",
            "continuous_24x7_uptime": "NOT_PROVEN",
        },
        "privacy_status": {
            "private_file_contents": "NOT_EMITTED",
            "secrets_or_tokens": "NOT_EMITTED",
            "product_source": "NOT_READ",
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")
    if not token:
        print(json.dumps({"status": "BLOCKED", "reason": "READ_TOKEN_NOT_CONFIGURED"}))
        return 2
    try:
        records = {name: fetch_private_json(path, token) for name, path in FILES.items()}
        report = summarize(records)
    except ObserverError as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}))
        return 2
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
