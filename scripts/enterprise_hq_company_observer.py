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
    "departments": "state/company_department_register.json",
    "roles": "employees/company_role_contracts.json",
    "seed": "state/company_ops_seed_tasks.json",
}
ALLOWED_TASK_KINDS = {
    "INTERNAL_RESEARCH", "INTERNAL_DOCUMENTATION", "INTERNAL_CODE", "READ_ONLY_AUDIT"
}
ALLOWED_WORKSTREAMS = {f"WS-{number:02d}" for number in range(1, 12)}


class ObserverError(RuntimeError):
    """A sanitized observer failure."""


def fetch_private_json(path: str, token: str) -> dict:
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
            envelope = json.loads(response.read().decode("utf-8"))
        content = base64.b64decode(envelope["content"], validate=True).decode("utf-8")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
        return value
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        raise ObserverError("PRIVATE_RECORD_READ_FAILED") from None
    except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ObserverError("PRIVATE_RECORD_PARSE_FAILED") from None


def summarize(records: dict) -> dict:
    identity = records["identity"]
    audit = records["audit"]
    register = records["register"]
    departments = records["departments"]
    roles = records["roles"]
    seed = records["seed"]

    company = identity.get("company", {})
    first_project = identity.get("project_portfolio", {}).get("first_project", {})
    if (company.get("name") != "Enterprise-HQ"
            or company.get("canonical_repository") != HQ_REPOSITORY
            or company.get("is_product_app") is not False):
        raise ObserverError("PARENT_COMPANY_IDENTITY_CHECK_FAILED")
    if (first_project.get("project_id") != "PROJECT-001"
            or first_project.get("name") != "PLY ERP"
            or first_project.get("repository") != "bhagyamehta1-lab/PLY_ERP"):
        raise ObserverError("PROJECT_BOUNDARY_CHECK_FAILED")
    if not isinstance(audit.get("safety"), dict) or not isinstance(audit.get("timestamp"), str):
        raise ObserverError("CEO_AUDIT_SCHEMA_INVALID")
    if register.get("authority", {}).get("scope") != "Enterprise-HQ parent company only":
        raise ObserverError("COMPANY_REGISTER_SCOPE_INVALID")
    if departments.get("scope") != "ENTERPRISE_HQ_PARENT_COMPANY_ONLY":
        raise ObserverError("DEPARTMENT_REGISTER_SCOPE_INVALID")
    if roles.get("scope") != "ENTERPRISE_HQ_PARENT_COMPANY_ONLY":
        raise ObserverError("ROLE_REGISTER_SCOPE_INVALID")
    if seed.get("scope") != "ENTERPRISE_HQ_PARENT_COMPANY_ONLY":
        raise ObserverError("TASK_SEED_SCOPE_INVALID")

    workstreams = register.get("workstreams", [])
    department_rows = departments.get("departments", [])
    role_rows = roles.get("roles", [])
    task_rows = seed.get("tasks", [])
    if not all(isinstance(rows, list) for rows in (workstreams, department_rows, role_rows, task_rows)):
        raise ObserverError("COMPANY_RECORD_COLLECTION_INVALID")
    workstream_ids = {row.get("workstream_id") for row in workstreams if isinstance(row, dict)}
    if workstream_ids != ALLOWED_WORKSTREAMS or len(workstreams) != len(ALLOWED_WORKSTREAMS):
        raise ObserverError("COMPANY_WORKSTREAM_SET_INVALID")
    if any(not isinstance(task, dict)
           or task.get("workstream_id") not in ALLOWED_WORKSTREAMS
           or task.get("task_kind") not in ALLOWED_TASK_KINDS
           or task.get("approval_required", False)
           for task in task_rows):
        raise ObserverError("COMPANY_TASK_SEED_BOUNDARY_INVALID")

    software_roles = [row for row in role_rows if row.get("role_id") != "CEO-01"]
    workstream_counts = dict(sorted(Counter(row.get("status", "UNKNOWN") for row in workstreams).items()))
    task_kind_counts = dict(sorted(Counter(row.get("task_kind", "UNKNOWN") for row in task_rows).items()))
    readiness = identity.get("readiness", {})
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "company": "Enterprise-HQ",
        "scope": "PARENT_COMPANY_ONLY",
        "status": "OBSERVED",
        "source_audit_timestamp": audit["timestamp"],
        "checks": {
            "parent_company_identity": "PASS",
            "project_001_boundary": "PASS",
            "company_workstream_allowlist": "PASS",
            "internal_task_seed_allowlist": "PASS",
            "private_records_read": "PASS",
        },
        "counts": {
            "workstreams": len(workstreams),
            "workstreams_by_status": workstream_counts,
            "departments": len(department_rows),
            "operational_departments": sum(
                1 for row in department_rows if row.get("status") == "OPERATIONAL"
            ),
            "software_roles": len(software_roles),
            "active_software_roles": sum(
                1 for row in software_roles if row.get("status") == "ACTIVE"
            ),
            "internal_seed_tasks": len(task_rows),
            "internal_seed_task_kinds": task_kind_counts,
        },
        "readiness": {
            "company_operating_status": readiness.get("company_operating_status", "UNKNOWN"),
            "legal_entity_status": readiness.get("legal_entity_status", "UNKNOWN"),
            "independent_ai_operations_status": readiness.get("independent_ai_operations_status", "UNKNOWN"),
            "continuous_24x7_status": readiness.get("continuous_24x7_status", "UNKNOWN"),
        },
        "capability_truth": {
            "this_worker_is_read_only": True,
            "this_worker_executes_company_tasks": False,
            "this_worker_is_an_independent_ai_agent": False,
            "continuous_24x7_uptime_is_proven": False,
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
