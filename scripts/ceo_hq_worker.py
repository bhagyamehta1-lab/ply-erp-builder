#!/usr/bin/env python3
"""Public-runner CEO inbox processor. Private payloads stay in /dev/shm and never enter logs."""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REPO = "bhagyamehta1-lab/Enterprise-HQ"
OWNER = "bhagyamehta1-lab"
API = "https://api.github.com"
WORKSPACE = Path(os.environ.get("WORKSPACE", "/dev/shm/enterprise_workspace"))
READ_TOKEN = os.environ.get("ENTERPRISE_HQ_READ_TOKEN", "")
WRITE_TOKEN = os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
PLY_READ_TOKEN = os.environ.get("HQ_TO_PLY_ERP_TOKEN", "")


class SafeFailure(Exception):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def request_json(method: str, path: str, token: str, payload=None):
    if not token:
        raise SafeFailure("Required credential is not configured.")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ply-erp-builder-ceo-command-engine",
    }
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return json.loads(raw.decode("utf-8")) if raw else {}
    except urllib.error.HTTPError as exc:
        # Never print response bodies, request URLs containing private data, or tokens.
        raise SafeFailure(f"GitHub API request failed with HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        raise SafeFailure("GitHub API request failed; details suppressed.") from None


def get_file(path: str, token: str):
    encoded = urllib.parse.quote(path, safe="/")
    doc = request_json("GET", f"/repos/{REPO}/contents/{encoded}?ref=main", token)
    if doc.get("type") != "file" or "content" not in doc or "sha" not in doc:
        raise SafeFailure("Expected HQ file was unavailable.")
    try:
        raw = base64.b64decode(doc["content"], validate=False)
        return raw.decode("utf-8"), doc["sha"]
    except (ValueError, UnicodeDecodeError):
        raise SafeFailure("HQ file could not be decoded.") from None


def put_file(path: str, content: str, message: str, token: str):
    # Read the latest blob SHA with the write credential to avoid stale updates.
    _, sha = get_file(path, token)
    encoded = urllib.parse.quote(path, safe="/")
    result = request_json(
        "PUT",
        f"/repos/{REPO}/contents/{encoded}",
        token,
        {
            "message": message,
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "sha": sha,
            "branch": "main",
        },
    )
    return result.get("content", {}).get("sha")


def json_from_file(path: str, token: str):
    content, sha = get_file(path, token)
    try:
        return json.loads(content), sha
    except json.JSONDecodeError:
        raise SafeFailure("HQ state JSON is invalid.") from None


def command_kind(body: str):
    raw = (body or "").strip()
    upper = raw.upper()
    if upper == "STATUS" or raw.casefold() in ("status report", "status batao"):
        return "STATUS"
    if upper.startswith("INSPECT:") or upper.startswith("ASK:"):
        return "INSPECT"
    if upper.startswith("ADD:"):
        return "ADD"
    if upper.startswith("MODIFY:"):
        return "MODIFY"
    return "BOARDROOM" if raw else None


def legacy_processed_issue_ids(audit):
    found = set()
    for item in audit.get("commands", []):
        trigger = str(item.get("trigger", ""))
        match = re.search(r"issue\s*#(\d+)", trigger, re.I)
        if match:
            found.add(int(match.group(1)))
        if item.get("source_issue_number") is not None:
            try:
                found.add(int(item["source_issue_number"]))
            except (TypeError, ValueError):
                pass
    return found


def inquiry_for_issue(backlog, issue_number, updated_at):
    for item in backlog.get("ceo_inquiries", []):
        if item.get("source_issue_number") == issue_number and item.get("source_issue_updated_at") == updated_at:
            return item
    return None


def marker(issue_number: int, updated_at: str) -> str:
    return f"<!-- CEO_DESK_PROCESSED:ISSUE:{issue_number}:UPDATED:{updated_at} -->"


def comments_for_issue(issue_number: int, token: str):
    return request_json(
        "GET",
        f"/repos/{REPO}/issues/{issue_number}/comments?per_page=100",
        token,
    )


def post_issue_comment(issue_number: int, body: str, token: str):
    request_json(
        "POST",
        f"/repos/{REPO}/issues/{issue_number}/comments",
        token,
        {"body": body},
    )


def main() -> int:
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    os.chmod(WORKSPACE, 0o700)
    if not READ_TOKEN:
        raise SafeFailure("ENTERPRISE_HQ_READ_TOKEN is not configured.")

    repo_meta = request_json("GET", f"/repos/{REPO}", READ_TOKEN)
    if repo_meta.get("full_name", "").casefold() != REPO.casefold() or repo_meta.get("private") is not True:
        raise SafeFailure("Enterprise-HQ repository identity/private check failed.")

    roadmap_text, _ = get_file("state/enterprise_roadmap.json", READ_TOKEN)
    backlog_text, _ = get_file("projects/ply_erp_backlog.json", READ_TOKEN)
    orchestrator_text, _ = get_file("scripts/autonomous_orchestrator.py", READ_TOKEN)
    audit_text, _ = get_file("state/ceo_command_audit.json", READ_TOKEN)
    minutes, _ = json_from_file("state/minutes_of_meeting.json", READ_TOKEN)
    codebase_index, _ = json_from_file("state/codebase_index.json", READ_TOKEN)

    try:
        roadmap = json.loads(roadmap_text)
        backlog = json.loads(backlog_text)
        audit = json.loads(audit_text)
    except json.JSONDecodeError:
        raise SafeFailure("HQ state JSON could not be parsed.") from None

    try:
        compile(orchestrator_text, "autonomous_orchestrator.py", "exec")
    except SyntaxError:
        raise SafeFailure("HQ orchestrator syntax validation failed; details suppressed.") from None

    status = roadmap.get("system_status", roadmap.get("status"))
    safe_hold = (
        status == "SAFE_HOLD"
        and roadmap.get("safety", {}).get("execution_hold") is True
        and roadmap.get("safety", {}).get("dispatch_enabled") is False
        and roadmap.get("bridge", {}).get("dispatch_enabled") is False
        and backlog.get("enterprise_status") == "SAFE_HOLD"
    )
    authorized = [item for item in backlog.get("requirements", []) if item.get("dispatch_authorized") is True]
    active_operations = (
        status == "ACTIVE_OPERATIONS"
        and roadmap.get("safety", {}).get("execution_hold") is False
        and roadmap.get("safety", {}).get("dispatch_enabled") is True
        and roadmap.get("bridge", {}).get("dispatch_enabled") is True
        and backlog.get("enterprise_status") == "ACTIVE_OPERATIONS"
    )
    if not (safe_hold or active_operations):
        raise SafeFailure("HQ state failed SAFE_HOLD/ACTIVE_OPERATIONS scope validation; inbox processing stopped.")

    # All downloaded private state and orchestration code is confined to tmpfs.
    files = {
        "state/enterprise_roadmap.json": roadmap_text,
        "projects/ply_erp_backlog.json": backlog_text,
        "scripts/autonomous_orchestrator.py": orchestrator_text,
    }
    for relative, content in files.items():
        target = WORKSPACE / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        os.chmod(target, 0o600)

    issues = request_json("GET", f"/repos/{REPO}/issues?state=open&per_page=100", READ_TOKEN)
    if not isinstance(issues, list):
        raise SafeFailure("CEO Issue inbox response was invalid.")

    owner_issues = [
        issue for issue in issues
        if "pull_request" not in issue
        and (issue.get("user") or {}).get("login") == OWNER
    ]

    processed_legacy = legacy_processed_issue_ids(audit)
    commands_processed = 0
    comments_posted = 0
    duplicates_skipped = 0
    write_enabled = bool(WRITE_TOKEN)

    # Without a separate write credential, this remains a strictly read-only poll.
    if write_enabled:
        for issue in owner_issues:
            number = int(issue["number"])
            updated_at = str(issue.get("updated_at", ""))
            body = str(issue.get("body") or "")
            kind = command_kind(body)
            if not kind:
                continue

            comments = comments_for_issue(number, READ_TOKEN)
            marker_text = marker(number, updated_at)
            if any(marker_text in str(c.get("body", "")) for c in comments):
                duplicates_skipped += 1
                continue

            existing = inquiry_for_issue(backlog, number, updated_at)
            if existing is not None:
                result_text = str(existing.get("answer_summary", "CEO command was already recorded in HQ backlog."))
            elif number in processed_legacy:
                duplicates_skipped += 1
                continue
            elif kind == "BOARDROOM":
                locked = bool(re.search(r"\\b(lock this|implement this|lock|implement)\\b", body, re.I))
                meeting_id = f"BRM-ISSUE-{number}-{re.sub(r'[^0-9A-Za-z]+', '', updated_at)[:20]}"
                task_id = None
                if locked:
                    existing_ids = [int(m.group(1)) for item in backlog.get("requirements", [])
                                    if (m := re.fullmatch(r"PLY-(\\d+)", str(item.get("task_id", ""))))]
                    task_id = f"PLY-{max(existing_ids, default=0)+1:04d}"
                    backlog.setdefault("requirements", []).append({
                        "task_id": task_id,
                        "title": (body.strip().splitlines()[0][:120] or "CEO boardroom decision"),
                        "details": body.strip(),
                        "status": "BLOCKED_PENDING_ARCHITECTURE_SCOPE",
                        "approval_state": "APPROVED",
                        "created_at": utc_now(),
                        "updated_at": utc_now(),
                        "dispatch_authorized": False,
                        "explicit_file_allowlist": [],
                        "scope_pending": True,
                        "task_scoped_authorization": "NOT_GRANTED",
                        "revision_count": 0,
                        "revision_history": [],
                        "blocker": "CEO decision is recorded; EMP-01 must produce and validate an exact file-by-file allowlist before dispatch."
                    })
                record = {
                    "meeting_id": meeting_id,
                    "timestamp": utc_now(),
                    "source": "Enterprise-HQ GitHub Issue",
                    "source_issue_number": number,
                    "source_issue_updated_at": updated_at,
                    "ceo_request": body.strip(),
                    "product_repository": "bhagyamehta1-lab/PLY_ERP",
                    "product_commit": codebase_index.get("last_verified_commit"),
                    "participants": [
                        {"name":"Vikram","role":"Chief Architect — Systems & Rust/SQLite","persona_type":"AI_ROLE_SIMULATION"},
                        {"name":"Aditi","role":"Product & ERP Domain Lead — Plywood Manufacturing","persona_type":"AI_ROLE_SIMULATION"},
                        {"name":"Rohan","role":"Lead Frontend & UX Engineer — React/TypeScript","persona_type":"AI_ROLE_SIMULATION"},
                        {"name":"Kabir","role":"QA & Security Lead","persona_type":"AI_ROLE_SIMULATION"}
                    ],
                    "decision": "LOCKED_SCOPE_PENDING" if locked else "DISCUSSION_OPEN",
                    "task_id": task_id,
                    "revision_number": 0,
                    "explicit_file_allowlist": [],
                    "policy_evaluation": {
                        "global_build_gate": roadmap.get("safety", {}).get("builds_enabled") is True,
                        "execution_hold": roadmap.get("safety", {}).get("execution_hold"),
                        "task_scoped_grant": "NOT_GRANTED",
                        "dispatch_authorized": False
                    },
                    "role_advice": {
                        "Vikram":"Architecture aur encrypted local data boundaries ko pehle map karna hoga; exact files EMP-01 blueprint se decide honge.",
                        "Aditi":"Plywood factory ke operator steps, approvals aur exception cases acceptance criteria mein likhne honge.",
                        "Rohan":"Screen flow, form validation, empty/error/loading states aur responsive behavior define karenge.",
                        "Kabir":"Har critical action ke positive, negative, audit aur privacy tests honge; CEO sign-off se pehle task close nahi hoga."
                    },
                    "blocker":"Exact file allowlist and candidate SHA must be established before dispatch." if locked else None
                }
                minutes.setdefault("records", []).append(record)
                put_file("state/minutes_of_meeting.json", json.dumps(minutes, ensure_ascii=False, indent=2)+"\\n",
                         f"Boardroom minutes for CEO issue #{number}", WRITE_TOKEN)
                if locked:
                    backlog["enterprise_status"] = "ACTIVE_OPERATIONS"
                    put_file("projects/ply_erp_backlog.json", json.dumps(backlog, ensure_ascii=False, indent=2)+"\\n",
                             f"CEO locked boardroom task {task_id}", WRITE_TOKEN)
                    result_text = f"Boardroom decision recorded. {task_id} is approved but BLOCKED_PENDING_ARCHITECTURE_SCOPE; no code was dispatched. EMP-01 must produce the exact allowlist and a new matching task grant before execution."
                else:
                    result_text = "BOARDROOM MEETING MODE: Vikram, Aditi, Rohan and Kabir have recorded the discussion. Nothing was dispatched. Reply with 'Lock this' or 'Implement this' when you want a scoped requirement created."
                audit.setdefault("commands", []).append({
                    "command":"BOARDROOM", "source_issue_number":number,
                    "source_issue_updated_at":updated_at, "meeting_id":meeting_id,
                    "task_id":task_id, "result":"LOCKED_SCOPE_PENDING" if locked else "DISCUSSION_OPEN",
                    "timestamp":utc_now()
                })
                audit["timestamp"] = utc_now()
                audit.setdefault("worker", {})["last_inbox_sync"] = utc_now()
                audit["worker"]["last_inbox_sync_result"] = "BOARDROOM_MINUTES_RECORDED"
                audit.setdefault("safety", {}).update({
                    "safe_hold": status == "SAFE_HOLD",
                    "execution_hold": roadmap.get("safety", {}).get("execution_hold"),
                    "dispatch_enabled": roadmap.get("safety", {}).get("dispatch_enabled"),
                    "product_task_execution": False,
                    "builds_enabled": roadmap.get("safety", {}).get("builds_enabled"),
                    "releases_enabled": roadmap.get("safety", {}).get("releases_enabled"),
                    "deployments_enabled": roadmap.get("safety", {}).get("deployments_enabled")
                })
                put_file("state/ceo_command_audit.json", json.dumps(audit, ensure_ascii=False, indent=2)+"\\n",
                         f"Audit boardroom issue #{number}", WRITE_TOKEN)
                commands_processed += 1
            else:
                child_env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": str(WORKSPACE),
                    "TMPDIR": str(WORKSPACE),
                }
                if PLY_READ_TOKEN:
                    child_env["HQ_TO_PLY_ERP_TOKEN"] = PLY_READ_TOKEN
                if os.environ.get("GITHUB_TOKEN"):
                    child_env["GITHUB_TOKEN"] = os.environ["GITHUB_TOKEN"]
                if os.environ.get("HQ_ENABLE_MODEL_BRAIN"):
                    child_env["HQ_ENABLE_MODEL_BRAIN"] = os.environ["HQ_ENABLE_MODEL_BRAIN"]
                if os.environ.get("GH_MODELS_MODEL"):
                    child_env["GH_MODELS_MODEL"] = os.environ["GH_MODELS_MODEL"]
                try:
                    result = subprocess.run(
                        [sys.executable, str(WORKSPACE / "scripts/autonomous_orchestrator.py"),
                         "--command-text", body],
                        cwd=str(WORKSPACE),
                        env=child_env,
                        capture_output=True,
                        text=True,
                        timeout=60,
                        check=False,
                    )
                except (subprocess.SubprocessError, OSError):
                    raise SafeFailure("CEO orchestrator invocation failed; private details suppressed.") from None

                if result.returncode != 0:
                    # The issue is private; keep the generic failure out of public logs.
                    result_text = "CEO command was rejected by the HQ orchestrator. No task was dispatched; SAFE_HOLD remains active."
                else:
                    result_text = (result.stdout or "").strip() or "CEO command completed."
                    try:
                        backlog = json.loads((WORKSPACE / "projects/ply_erp_backlog.json").read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        raise SafeFailure("Orchestrator output backlog was invalid.") from None
                    inquiries = backlog.get("ceo_inquiries", [])
                    if inquiries:
                        inquiries[-1]["source_issue_number"] = number
                        inquiries[-1]["source_issue_updated_at"] = updated_at
                    enterprise_state = "ACTIVE_OPERATIONS" if active_operations else "SAFE_HOLD"
                    backlog["enterprise_status"] = enterprise_state
                    new_backlog = json.dumps(backlog, ensure_ascii=False, indent=2) + "\n"
                    put_file("projects/ply_erp_backlog.json", new_backlog,
                             f"CEO inbox command #{number} ({kind}) — {enterprise_state}", WRITE_TOKEN)
                    (WORKSPACE / "projects/ply_erp_backlog.json").write_text(new_backlog, encoding="utf-8")
                    commands_processed += 1

                    audit.setdefault("commands", []).append({
                        "command": kind,
                        "source_issue_number": number,
                        "source_issue_updated_at": updated_at,
                        "worker": "bhagyamehta1-lab/ply-erp-builder",
                        "result": "RECORDED_UNDER_ACTIVE_OPERATIONS" if active_operations else "RECORDED_UNDER_SAFE_HOLD",
                        "timestamp": utc_now(),
                    })
                    audit["timestamp"] = utc_now()
                    audit["enterprise_status"] = enterprise_state
                    audit.setdefault("worker", {})["last_inbox_sync"] = utc_now()
                    audit["worker"]["last_inbox_sync_result"] = "ACTIVE_OPERATIONS_SCOPED_READ_AND_BACKLOG_WRITE" if active_operations else "SAFE_HOLD_READ_AND_BACKLOG_WRITE"
                    audit["safety"] = {
                        "safe_hold": not active_operations,
                        "execution_hold": not active_operations,
                        "dispatch_enabled": active_operations,
                        "product_task_execution": active_operations,
                    }
                    put_file("state/ceo_command_audit.json",
                             json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
                             f"Audit CEO inbox command #{number}", WRITE_TOKEN)

            # Issue comments are private to the Enterprise-HQ repository.
            policy_note = ("Inbox consultation is read-only unless a separate task-scoped dispatch gate passes; this issue sync did not dispatch product code." if active_operations else "SAFE_HOLD remains active. Meeting minutes only; no PLY_ERP task was dispatched.")
            comment_body = (
                f"CEO Command Desk result\n\n{result_text}\n\n"
                f"{policy_note}\n\n{marker_text}"
            )
            post_issue_comment(number, comment_body, WRITE_TOKEN)
            comments_posted += 1

    print("HQ_READ_AUTH=PASS")
    print("HQ_REPOSITORY_IDENTITY=PRIVATE_ENTERPRISE_HQ_CONFIRMED")
    print("HQ_POLICY=" + ("ACTIVE_OPERATIONS_PLY_0001_SCOPED" if active_operations else "SAFE_HOLD"))
    print(f"OPEN_ISSUES_COUNT={len(issues)}")
    print(f"OWNER_AUTHORED_OPEN_ISSUES_COUNT={len(owner_issues)}")
    print(f"SUPPORTED_COMMANDS_PROCESSED={commands_processed}")
    print(f"ISSUE_COMMENTS_POSTED={comments_posted}")
    print(f"DUPLICATES_SKIPPED={duplicates_skipped}")
    print("WRITE_BACK_AUTH=" + ("CONFIGURED" if write_enabled else "NOT_CONFIGURED_READ_ONLY_POLL"))
    print("PRIVATE_PAYLOADS_OR_SECRETS_IN_LOGS=NO")
    print("PLY_ERP_SOURCE_CHECKOUT=NO")
    print("PRODUCT_TASK_DISPATCH=NO")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SafeFailure:
        print("CEO_ENGINE_RESULT=SAFE_FAILURE_DETAILS_SUPPRESSED")
        raise SystemExit(2)
