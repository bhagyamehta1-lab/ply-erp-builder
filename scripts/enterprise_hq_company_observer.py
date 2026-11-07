#!/usr/bin/env python3
"""Read-only, privacy-minimizing observer for the Enterprise-HQ parent company."""
from __future__ import annotations

import argparse
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

HQ_REPOSITORY = "bhagyamehta1-lab/Enterprise-HQ"
API = "https://api.github.com"
FILES = {
    "register": "state/company_completion_register.json",
}
ALLOWED_PRIVATE_PATHS = frozenset(FILES.values())
ALLOWED_WORKSTREAMS = {f"WS-{number:02d}" for number in range(1, 12)}
WORKSTREAM_STATUSES = frozenset({
    "NOT_STARTED", "PLANNED", "CONFIGURED", "SIMULATED", "GOVERNANCE_ONLY",
    "ISOLATED_QA", "REAL_TRANSACTION", "SUSTAINED_PRODUCTION", "BLOCKED", "ACCEPTED",
})
MAX_PRIVATE_RECORD_BYTES = 512 * 1024


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


def summarize(records: dict) -> dict:
    if not isinstance(records, dict) or set(records) != {"register"}:
        raise ObserverError("PRIVATE_RECORD_SET_INVALID")
    register = records["register"]
    if not isinstance(register, dict):
        raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
    authority = register.get("authority", {})
    if not isinstance(authority, dict):
        raise ObserverError("PRIVATE_RECORD_SCHEMA_INVALID")
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

    return {
        "schema_version": "1.0.0",
        "scope_status": "PARENT_COMPANY_ONLY",
        "project_001_scope": "EXCLUDED_BY_COMPANY_WORKER_POLICY",
        "status": "OBSERVED",
        "checks": {
            "company_register_scope": "PASS",
            "company_completion_register": "PASS",
            "company_workstream_set": "PASS",
        },
        "counts": {
            "workstreams": len(workstreams),
            "workstreams_by_status": dict(sorted(Counter(statuses).items())),
        },
        "capability_status": {
            "company_task_execution": "NOT_IMPLEMENTED",
            "independent_agent_identity": "NOT_AUTHENTICATED",
            "continuous_24x7_uptime": "NOT_PROVEN",
        },
        "privacy_status": {
            "private_file_contents": "NOT_EMITTED",
            "secrets_or_tokens": "NOT_EMITTED",
            "ceo_command_audit": "NOT_FETCHED_BY_PUBLIC_OBSERVER",
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
