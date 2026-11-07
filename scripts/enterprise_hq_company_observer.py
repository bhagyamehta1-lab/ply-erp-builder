#!/usr/bin/env python3
"""Read-only, privacy-minimizing observer for the Enterprise-HQ parent company."""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
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
MAX_PRIVATE_RECORD_BYTES = 512 * 1024


class ObserverError(RuntimeError):
    """A sanitized observer failure."""


def decode_private_envelope(raw_envelope: bytes) -> dict:
    try:
        envelope = json.loads(raw_envelope.decode("utf-8"))
        encoded_content = envelope.get("content")
        if not isinstance(encoded_content, str):
            raise ObserverError("PRIVATE_RECORD_ENVELOPE_INVALID")
        # GitHub's Contents API may wrap base64 in line breaks.
        compact_content = "".join(encoded_content.split())
        content = base64.b64decode(compact_content, validate=True)
        if len(content) > MAX_PRIVATE_RECORD_BYTES:
            raise ObserverError("PRIVATE_RECORD_TOO_LARGE")
        value = json.loads(content.decode("utf-8"))
        if not isinstance(value, dict):
            raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
        return value
    except ObserverError:
        raise
    except (KeyError, ValueError, UnicodeDecodeError):
        raise ObserverError("PRIVATE_RECORD_PARSE_FAILED") from None


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
        with urllib.request.urlopen(request, timeout=20) as response:
            raw_envelope = response.read(MAX_PRIVATE_RECORD_BYTES + 1)
        if len(raw_envelope) > MAX_PRIVATE_RECORD_BYTES:
            raise ObserverError("PRIVATE_RECORD_TOO_LARGE")
        return decode_private_envelope(raw_envelope)
    except ObserverError:
        raise
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ObserverError("PRIVATE_RECORD_READ_FAILED") from None
    except (KeyError, ValueError, UnicodeDecodeError):
        raise ObserverError("PRIVATE_RECORD_PARSE_FAILED") from None


def summarize(records: dict) -> dict:
    if not isinstance(records, dict) or any(
        not isinstance(records.get(name), dict)
        for name in ("identity", "audit", "register")
    ):
        raise ObserverError("PRIVATE_RECORD_SET_INVALID")

    identity = records["identity"]
    audit = records["audit"]
    register = records["register"]

    company = identity.get("company", {})
    first_project = identity.get("project_portfolio", {}).get("first_project", {})
    if (
        company.get("name") != "Enterprise-HQ"
        or company.get("canonical_repository") != HQ_REPOSITORY
        or company.get("is_product_app") is not False
    ):
        raise ObserverError("PARENT_COMPANY_IDENTITY_CHECK_FAILED")
    if (
        first_project.get("project_id") != "PROJECT-001"
        or first_project.get("name") != "PLY ERP"
        or first_project.get("repository") != "bhagyamehta1-lab/PLY_ERP"
    ):
        raise ObserverError("PROJECT_BOUNDARY_CHECK_FAILED")

    audit_timestamp = audit.get("timestamp")
    if not isinstance(audit_timestamp, str):
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")
    try:
        parsed_timestamp = datetime.fromisoformat(
            audit_timestamp.replace("Z", "+00:00")
        )
    except ValueError:
        raise ObserverError("CEO_AUDIT_TIMESTAMP_INVALID") from None
    if parsed_timestamp.tzinfo is None:
        raise ObserverError("CEO_AUDIT_TIMESTAMP_INVALID")

    audit_system_status = audit.get("system_status")
    enterprise_status = audit.get("enterprise_status")
    safety = audit.get("safety")
    if (
        not isinstance(audit_system_status, str)
        or not audit_system_status
        or not isinstance(enterprise_status, str)
        or not enterprise_status
        or not isinstance(safety, dict)
    ):
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")

    boolean_gates = [value for value in safety.values() if isinstance(value, bool)]
    if not boolean_gates:
        raise ObserverError("CEO_AUDIT_SAFETY_SCHEMA_INVALID")

    if register.get("authority", {}).get("scope") != "Enterprise-HQ parent company only":
        raise ObserverError("COMPANY_REGISTER_SCOPE_INVALID")

    workstreams = register.get("workstreams", [])
    if not isinstance(workstreams, list) or len(workstreams) != len(ALLOWED_WORKSTREAMS):
        raise ObserverError("COMPANY_WORKSTREAM_SET_INVALID")
    if any(not isinstance(row, dict) for row in workstreams):
        raise ObserverError("COMPANY_WORKSTREAM_RECORD_INVALID")

    workstream_ids = [row.get("workstream_id") for row in workstreams]
    if set(workstream_ids) != ALLOWED_WORKSTREAMS or len(set(workstream_ids)) != len(workstreams):
        raise ObserverError("COMPANY_WORKSTREAM_SET_INVALID")
    if any(not isinstance(row.get("status"), str) or not row["status"] for row in workstreams):
        raise ObserverError("COMPANY_WORKSTREAM_STATUS_INVALID")
    if any(not isinstance(row.get("evidence_refs", []), list) for row in workstreams):
        raise ObserverError("COMPANY_WORKSTREAM_EVIDENCE_SCHEMA_INVALID")

    status_counts = dict(
        sorted(Counter(row["status"] for row in workstreams).items())
    )
    with_evidence = sum(1 for row in workstreams if row.get("evidence_refs", []))
    readiness = identity.get("readiness", {})
    if not isinstance(readiness, dict):
        raise ObserverError("COMPANY_READINESS_SCHEMA_INVALID")

    return {
        "schema_version": "1.1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "company": "Enterprise-HQ",
        "scope": "PARENT_COMPANY_ONLY",
        "status": "OBSERVED",
        "checks": {
            "parent_company_identity": "PASS",
            "project_001_boundary": "PASS",
            "ceo_audit_schema": "PASS",
            "company_completion_register_scope": "PASS",
            "company_workstream_set": "PASS",
            "private_records_read": "PASS",
        },
        "company_control": {
            "audit_system_status": audit_system_status,
            "enterprise_status": enterprise_status,
            "boolean_safety_gate_count": len(boolean_gates),
            "enabled_boolean_gate_count": sum(boolean_gates),
            "disabled_boolean_gate_count": len(boolean_gates) - sum(boolean_gates),
        },
        "counts": {
            "private_governance_records_read": 3,
            "workstreams": len(workstreams),
            "workstreams_by_status": status_counts,
            "workstreams_with_evidence": with_evidence,
            "workstreams_without_evidence": len(workstreams) - with_evidence,
        },
        "readiness": {
            "company_operating_status": readiness.get(
                "company_operating_status", "UNKNOWN"
            ),
            "legal_entity_status": readiness.get(
                "legal_entity_status", "UNKNOWN"
            ),
            "independent_ai_operations_status": readiness.get(
                "independent_ai_operations_status", "UNKNOWN"
            ),
            "continuous_24x7_status": readiness.get(
                "continuous_24x7_status", "UNKNOWN"
            ),
        },
        "capability_truth": {
            "this_worker_is_read_only": True,
            "this_worker_executes_company_tasks": False,
            "this_worker_is_an_independent_ai_agent": False,
            "continuous_24x7_uptime_is_proven": False,
            "model_provider_is_authorized": False,
        },
        "privacy": {
            "private_file_contents_in_report": False,
            "secrets_or_tokens_in_report": False,
            "product_source_read": False,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.output and args.output.exists():
        args.output.unlink()

    token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")
    if not token:
        print(json.dumps({"status": "BLOCKED", "reason": "READ_TOKEN_NOT_CONFIGURED"}))
        return 2
    try:
        records = {
            name: fetch_private_json(path, token)
            for name, path in FILES.items()
        }
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
