#!/usr/bin/env python3
"""Policy-gated background verifier for Enterprise-HQ.

Pipeline nudge: consume the newly promoted PLY-0004 task on the next push run.
Implementation candidate is pinned to the scoped PLY-0004 branch head; verify only its six-file allowlist.
Reauthorized after exact-scope source diff review; proceed only when global and task grants both match.
Controlled PLY-0003 sparse-read-boundary verification authorized; exact 34-file materialization only.
Next active task PLY-0004 has a six-file write allowlist and 82-file verification read allowlist, including all Tauri build inputs and repository ignore rules.

Reads the alignment DNA before any other HQ state. It never edits product source,
never applies model-generated patches, and fails closed when authorization is absent.
"""
from __future__ import annotations

import argparse
import time
import base64
import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HQ = "bhagyamehta1-lab/Enterprise-HQ"
PRODUCT = "bhagyamehta1-lab/PLY_ERP"
API = "https://api.github.com"
CHECKPOINT_PATH = "state/autonomous_shift_checkpoints.json"
AUDIT_PATH = "state/ceo_command_audit.json"
PORTFOLIO_PATH = "projects/portfolio_registry.json"
ROSTER_PATH = "employees/department_roster.json"
BRAIN_PATH = "state/universal_employee_brain.json"
CAPSULES_PATH = "state/project_knowledge_capsules.json"
GRAPH_PATH = "state/department_knowledge_graph.json"
INDEX_PATH = "state/codebase_index.json"
HEURISTICS_PATH = "state/learned_heuristics.json"
DNA_PATH = "protocols/enterprise_alignment_dna.md"

# This runner may persist only these Enterprise-HQ governance records. It never
# writes to a product repository, worker repository, workflow, grant, or release path.
HQ_WRITE_PATHS = frozenset({
    CHECKPOINT_PATH,
    AUDIT_PATH,
    INDEX_PATH,
    HEURISTICS_PATH,
})


def validate_hq_write_target(repository: str, path: str) -> str:
    if repository != HQ:
        raise RunnerError("Write rejected: repository is outside the Enterprise-HQ governance boundary.")
    if not isinstance(path, str) or not path or "\\\\" in path:
        raise RunnerError("Write rejected: invalid repository path.")
    candidate = pathlib.PurePosixPath(path)
    if candidate.is_absolute() or any(part in ("", ".", "..") for part in candidate.parts):
        raise RunnerError("Write rejected: path traversal or non-canonical path.")
    normalized = candidate.as_posix()
    if normalized != path or normalized not in HQ_WRITE_PATHS:
        raise RunnerError("Write rejected: path is not in the explicit Enterprise-HQ governance allowlist.")
    return normalized


def self_test_write_path_guards() -> None:
    assert validate_hq_write_target(HQ, CHECKPOINT_PATH) == CHECKPOINT_PATH
    blocked = (
        (PRODUCT, CHECKPOINT_PATH),
        (HQ, "state/task_grants.json"),
        (HQ, "state/../ceo_command_audit.json"),
        (HQ, ".github/workflows/public_worker_executor.yml"),
        (HQ, "src-tauri/src/storage.rs"),
        ("bhagyamehta1-lab/ply-erp-builder", CHECKPOINT_PATH),
    )
    for repository, path in blocked:
        try:
            validate_hq_write_target(repository, path)
        except RunnerError:
            continue
        raise RunnerError("Write-path security self-test failed: an unauthorized target was accepted.")
    try:
        request_json("PUT", f"{API}/repos/{PRODUCT}/contents/src/App.tsx", "", {})
    except RunnerError:
        pass
    else:
        raise RunnerError("Write-path security self-test failed: unauthorized GitHub write was not rejected before network access.")


class RunnerError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def request_json(method: str, url: str, token: str, payload=None):
    # All mutating API calls must be Enterprise-HQ Contents writes to an exact
    # governance allowlist path. Reject before constructing/sending a request.
    if method.upper() not in ("GET", "HEAD"):
        parsed = urllib.parse.urlsplit(url)
        prefix = f"/repos/{HQ}/contents/"
        if method.upper() != "PUT" or parsed.netloc.casefold() != "api.github.com" or not parsed.path.startswith(prefix):
            raise RunnerError("GitHub write rejected: only allowlisted Enterprise-HQ governance Contents writes are permitted.")
        encoded_path = parsed.path[len(prefix):]
        decoded_path = urllib.parse.unquote(encoded_path)
        validate_hq_write_target(HQ, decoded_path)
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "enterprise-kaizen-shift-runner",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as response:
            raw = response.read()
            return None if not raw else json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise RunnerError(f"GitHub API request failed with HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RunnerError(f"GitHub API request failed ({type(exc).__name__}).") from exc


def get_contents(path: str, token: str):
    result = request_json("GET", f"{API}/repos/{HQ}/contents/{path}?ref=main", token)
    if result is None:
        raise RunnerError(f"Required HQ file is missing: {path}")
    try:
        content = base64.b64decode(result["content"]).decode("utf-8")
    except (KeyError, ValueError, UnicodeDecodeError) as exc:
        raise RunnerError(f"Could not decode required HQ file: {path}") from exc
    return content, result.get("sha")


def get_json(path: str, token: str):
    content, sha = get_contents(path, token)
    try:
        value = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"Invalid JSON in HQ file: {path}") from exc
    return value, sha


def put_contents(path: str, value, token: str, sha=None, message="autonomy: record sanitized checkpoint"):
    validate_hq_write_target(HQ, path)
    if path == AUDIT_PATH:
        current, _ = get_json(AUDIT_PATH, token)
        if (value.get("system_status") != current.get("system_status")
                or value.get("enterprise_status") != current.get("enterprise_status")
                or value.get("safety") != current.get("safety")):
            raise RunnerError("Audit write rejected: shift telemetry may not alter CEO status or global safety gates.")
    content = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    payload = {
        "message": message,
        "content": base64.b64encode(content).decode("ascii"),
        "branch": "main",
    }
    if sha:
        payload["sha"] = sha
    request_json("PUT", f"{API}/repos/{HQ}/contents/{path}", token, payload)


def append_checkpoint(record, token: str):
    """Append a checkpoint with bounded optimistic-concurrency retries."""
    for attempt in range(4):
        try:
            existing, sha = get_json(CHECKPOINT_PATH, token)
            if not isinstance(existing, dict) or not isinstance(existing.get("checkpoints"), list):
                raise RunnerError("Checkpoint store schema is invalid.")
        except RunnerError as exc:
            if "Required HQ file is missing" not in str(exc):
                raise
            existing, sha = {"schema_version": "1.0.0", "checkpoints": []}, None

        checkpoints = existing["checkpoints"]
        prior = next((i for i, item in enumerate(checkpoints)
                      if str(item.get("run_id")) == str(record.get("run_id"))
                      and item.get("task_id") == record.get("task_id")), None)
        if prior is None:
            checkpoints.append(record)
        else:
            checkpoints[prior] = record
        existing["checkpoints"] = checkpoints[-100:]

        try:
            put_contents(CHECKPOINT_PATH, existing, token, sha)
            return
        except RunnerError as exc:
            if "HTTP 409" not in str(exc) or attempt == 3:
                raise
            time.sleep(0.4 * (attempt + 1))
    raise RunnerError("Checkpoint update exhausted its concurrency retries.")



def put_index_with_retry(value, token, sha, message):
    """Merge verified-index fields onto the latest HQ index after HTTP 409."""
    merge_keys=("last_verified_commit","last_verified_run_id","last_verified_runner_id","last_verified_at","last_verified_task_id","indexed_files","tauri_commands")
    for attempt in range(4):
        try:
            put_contents(INDEX_PATH,value,token,sha,message)
            return
        except RunnerError as exc:
            if "HTTP 409" not in str(exc) or attempt==3:
                raise
            latest, latest_sha=get_json(INDEX_PATH,token)
            for key in merge_keys:
                if key in value:
                    latest[key]=value[key]
            value,sha=latest,latest_sha
            time.sleep(0.4*(attempt+1))
    raise RunnerError("Codebase index update exhausted its concurrency retries.")


def append_verified_heuristic(rule, token: str):
    required = ("id", "trigger_pattern", "root_cause", "mandatory_fix", "verified_in_run")
    if not isinstance(rule, dict) or any(not isinstance(rule.get(k), str) or not rule[k].strip() for k in required):
        raise RunnerError("QA heuristic candidate does not match the required five-field schema.")
    data, sha = get_json(HEURISTICS_PATH, token)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RunnerError("Learned heuristics store schema is invalid.")
    if any(item.get("id") == rule["id"] for item in data["rules"]):
        return
    data["rules"].append({key: rule[key].strip() for key in required})
    put_contents(HEURISTICS_PATH, data, token, sha, "kaizen: append QA fix verified by green worker run")


def output(values):
    target = os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={str(value).lower() if isinstance(value, bool) else value}\n")


def preflight():
    read_token = os.environ.get("ENTERPRISE_HQ_READ_TOKEN") or os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
    write_token = os.environ.get("ENTERPRISE_HQ_AUDIT_APPEND_TOKEN") or os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
    if not read_token or not write_token:
        raise RunnerError("HQ read/write credentials are unavailable; autonomous execution is blocked.")

    # The alignment DNA is deliberately the first HQ file read in every worker run.
    dna, _ = get_contents(DNA_PATH, read_token)
    if "## Session bootstrap" not in dna or "## Five behavioral gaps" not in dna:
        raise RunnerError("Enterprise alignment DNA is incomplete; refusing to continue.")

    orchestrator, _ = get_contents("scripts/autonomous_orchestrator.py", read_token)
    try:
        compile(orchestrator, "Enterprise-HQ/scripts/autonomous_orchestrator.py", "exec")
    except SyntaxError as exc:
        raise RunnerError(f"HQ orchestrator syntax validation failed at line {exc.lineno}: {exc.msg}.") from exc
    if "--prepare-shift" not in orchestrator or "--record-qa-heuristic" not in orchestrator:
        raise RunnerError("HQ orchestrator does not expose the required shift-memory interface.")

    index, _ = get_json(INDEX_PATH, read_token)
    heuristics, _ = get_json(HEURISTICS_PATH, read_token)
    roadmap, _ = get_json("state/enterprise_roadmap.json", read_token)
    backlog, _ = get_json("projects/ply_erp_backlog.json", read_token)
    audit, _ = get_json(AUDIT_PATH, read_token)
    portfolio, _ = get_json(PORTFOLIO_PATH, read_token)
    roster, _ = get_json(ROSTER_PATH, read_token)
    brain, _ = get_json(BRAIN_PATH, read_token)
    capsules, _ = get_json(CAPSULES_PATH, read_token)
    graph, _ = get_json(GRAPH_PATH, read_token)
    checkpoints, _ = get_json(CHECKPOINT_PATH, read_token)
    finance, _ = get_json("finance_and_resource_ledger.json", read_token)
    legal, _ = get_json("legal_and_compliance_registry.json", read_token)
    delivery, _ = get_json("customer_and_delivery_operations.json", read_token)
    charter, _ = get_json("human_accountability_charter.json", read_token)
    department_bindings, _ = get_json("department_workflow_bindings.json", read_token)

    if (not isinstance(audit, dict) or not isinstance(portfolio.get("ventures"), list)
            or not portfolio["ventures"] or not isinstance(roster.get("employees"), list)
            or not roster["employees"] or not isinstance(brain.get("employee_memory_nodes"), dict)
            or not isinstance(capsules.get("projects"), dict) or "PLY_ERP" not in capsules["projects"]
            or not isinstance(graph, dict) or not isinstance(checkpoints.get("checkpoints"), list)
            or finance.get("policy", {}).get("external_cloud_spend_limit") != 0
            or finance.get("policy", {}).get("external_cloud_spend_allowed") is not False
            or roadmap.get("safety", {}).get("governance_change", {}).get("builds_enabled") is not False
            or roadmap.get("safety", {}).get("governance_change", {}).get("releases_enabled") is not False
            or legal.get("privacy_security", {}).get("offline_first_required") is not True
            or legal.get("privacy_security", {}).get("zero_pii_exfiltration") is not True
            or delivery.get("release_integrity", {}).get("sha256_manifest_required") is not True
            or charter.get("human_ceo", {}).get("github_identity") != "bhagyamehta1-lab"
            or {x.get("employee_id") for x in department_bindings.get("workflows", [])} != {"EMP-01", "EMP-02", "EMP-03", "EMP-04", "EMP-05"}
            or any(not any(e.get("employee_id") == w.get("employee_id") and e.get("operational_workflow") == w.get("workflow") and e.get("mandatory_output_artifact") == w.get("mandatory_output") for e in roster["employees"]) for w in department_bindings.get("workflows", []))):
        raise RunnerError("Canonical governance record or schema validation failed.")

    missing_memory = [
        employee.get("employee_id") for employee in roster["employees"]
        if employee.get("employee_id") + "_universal_memory" not in brain["employee_memory_nodes"]
    ]
    if missing_memory:
        raise RunnerError("A roster employee is missing a dedicated universal memory node.")

    preview_task = next((item for item in backlog.get("requirements", []) if item.get("task_id") == "PLY-0003"), None)
    preview_grant = roadmap.get("safety", {}).get("task_scoped_build_authorizations", {}).get("PLY-0003", {})
    if not preview_task or not preview_grant or preview_task.get("verification_mode") != "PREVIEW_ONLY":
        raise RunnerError("PLY-0003 preview-only task/grant schema is missing.")
    preview_reads = preview_task.get("read_file_allowlist")
    preview_destinations = preview_task.get("preview_destination_allowlist")
    if (preview_task.get("explicit_file_allowlist") != []
            or preview_task.get("authorization", {}).get("explicit_file_allowlist") != []
            or preview_grant.get("explicit_file_allowlist") != []
            or not isinstance(preview_reads, list) or len(preview_reads) != 34
            or len(preview_reads) != len(set(preview_reads))
            or preview_grant.get("read_file_allowlist") != preview_reads
            or not isinstance(preview_destinations, list) or len(preview_destinations) != 3
            or preview_grant.get("preview_destination_allowlist") != preview_destinations):
        raise RunnerError("PLY-0003 PREVIEW_ONLY schema must enforce 34 reads, zero product writes and three exact private preview destinations.")

    for approved_task in backlog.get("requirements", []):
        if approved_task.get("approval_state") != "APPROVED" or approved_task.get("status") not in ("IN_PROGRESS", "IN_PROGRESS_BLOCKED", "APPROVED_QUEUED"):
            continue
        task_id_check = approved_task.get("task_id")
        grant_check = roadmap.get("safety", {}).get("task_scoped_build_authorizations", {}).get(task_id_check, {})
        read_check = approved_task.get("read_file_allowlist")
        write_check = approved_task.get("explicit_file_allowlist")
        if (not isinstance(read_check, list) or not read_check
                or len(read_check) != len(set(read_check))
                or not isinstance(write_check, list)
                or grant_check.get("read_file_allowlist") != read_check
                or grant_check.get("explicit_file_allowlist") != write_check):
            raise RunnerError("Approved task read/write allowlists are missing, duplicated or differ from the exact grant.")
        if approved_task.get("verification_mode") == "PREVIEW_ONLY":
            if write_check != []:
                raise RunnerError("PREVIEW_ONLY task has a non-empty product write allowlist.")
        elif not write_check or not set(write_check).issubset(set(read_check)):
            raise RunnerError("Implementation task write allowlist must be non-empty and a subset of the exact read allowlist.")

    required_heuristic_fields = {"id", "trigger_pattern", "root_cause", "mandatory_fix", "verified_in_run"}
    if (not isinstance(index, dict) or not index.get("last_verified_commit")
            or index.get("storage_schema_version") != 5
            or not isinstance(heuristics, dict) or not isinstance(heuristics.get("rules"), list)
            or any(not isinstance(rule, dict) or not required_heuristic_fields.issubset(rule) for rule in heuristics["rules"])):
        raise RunnerError("Codebase index or learned heuristics schema is invalid.")

    audit_safety = audit.get("safety", {})
    audit_hold = (
        os.environ.get("CEO_AUDIT_GATE_HOLD", "").casefold() == "true"
        or audit.get("system_status") == "SAFE_HOLD"
        or audit_safety.get("safe_hold") is True
        or audit_safety.get("execution_hold") is True
        or audit_safety.get("builds_enabled") is not True
        or audit_safety.get("dispatch_enabled") is not True
    )
    if audit_hold and any(grant_item.get("authorized") is True for grant_item in roadmap.get("safety", {}).get("task_scoped_build_authorizations", {}).values()):
        raise RunnerError("CEO audit SAFE_HOLD conflicts with an active task grant; fail closed.")

    active_tasks = [item for item in backlog.get("requirements", [])
                    if item.get("status") == "IN_PROGRESS" and item.get("dispatch_authorized") is True]
    task = active_tasks[0] if len(active_tasks) == 1 else None
    task_id = task.get("task_id") if task else None
    safety = roadmap.get("safety", {})
    grant = safety.get("task_scoped_build_authorizations", {}).get(task_id, {}) if task_id else {}
    expected_candidate = task.get("candidate_commit") or index.get("last_verified_commit") if task else None
    candidate_branch = grant.get("allowed_branch", "main") if task else "main"
    candidate_sha = grant.get("candidate_sha") or expected_candidate or ""
    file_allowlist = task.get("explicit_file_allowlist", []) if task else []
    read_file_allowlist = grant.get("read_file_allowlist", task.get("read_file_allowlist", [])) if task else []
    read_allowlist_valid = (
        isinstance(read_file_allowlist, list) and bool(read_file_allowlist)
        and all(isinstance(path, str) and path and not path.startswith("/") and ".." not in pathlib.PurePosixPath(path).parts for path in read_file_allowlist)
        and set(file_allowlist).issubset(set(read_file_allowlist))
    )
    verification_mode = task.get("verification_mode", "TASK_BUILD") if task else "NONE"
    preview_only = verification_mode == "PREVIEW_ONLY"
    if preview_only:
        destinations = task.get("preview_destination_allowlist", [])
        write_boundary_valid = (
            file_allowlist == []
            and grant.get("explicit_file_allowlist") == []
            and grant.get("preview_destination_allowlist") == destinations
            and len(destinations) == 3
            and all(path.startswith("previews/PLY-0003/" + str(expected_candidate) + "/") for path in destinations)
        )
    else:
        write_boundary_valid = bool(file_allowlist) and set(file_allowlist).issubset(set(read_file_allowlist))
    scoped_build = (
        grant.get("authorized") is True
        and grant.get("task_id") == task_id
        and grant.get("allowed_repository") == PRODUCT
        and bool(grant.get("allowed_branch"))
        and write_boundary_valid
        and grant.get("candidate_sha") == expected_candidate
        and grant.get("explicit_file_allowlist") == task.get("explicit_file_allowlist")
        and read_allowlist_valid
        and grant.get("read_file_allowlist") == read_file_allowlist
        and task.get("read_file_allowlist") == read_file_allowlist
    )
    # Global and task-scoped authorization are conjunctive; neither can override the other.
    build_allowed = (safety.get("builds_enabled") is True and safety.get("dispatch_enabled") is True
                     and roadmap.get("bridge", {}).get("dispatch_enabled") is True
                     and roadmap.get("bridge", {}).get("verified_read") is True
                     and roadmap.get("bridge", {}).get("verified_write") is True and scoped_build)
    event = os.environ.get("GITHUB_EVENT_NAME", "unknown")
    authorized = False
    state = "BLOCKED_UNKNOWN_STATE"
    reason = "No single approved active task has matching authorization."

    if audit_hold:
        state, reason = "BLOCKED_CEO_AUDIT_SAFE_HOLD", "The CEO Command Audit is the master state and explicitly denies execution."
    elif len(active_tasks) == 0:
        state, reason = "BLOCKED_NO_ACTIVE_TASK", "No IN_PROGRESS dispatch-authorized task exists in the HQ backlog."
    elif len(active_tasks) > 1:
        state, reason = "BLOCKED_AMBIGUOUS_TASK_SCOPE", "More than one active task is dispatch-authorized."
    elif index.get("last_verified_task_id") == task_id and index.get("last_verified_commit"):
        state, reason = "SKIPPED_TASK_ALREADY_VERIFIED", f"{task_id} already has a verified product commit in the codebase index."
    elif not build_allowed:
        state, reason = "BLOCKED_BUILD_AUTHORIZATION", "Neither the global build gate nor an exact task-scoped build grant authorizes this task."
    elif safety.get("execution_hold") is not False:
        state, reason = "BLOCKED_EXECUTION_HOLD", "The live roadmap execution hold is active."
    elif roadmap.get("system_status", roadmap.get("status")) != "ACTIVE_OPERATIONS" or backlog.get("enterprise_status") != "ACTIVE_OPERATIONS":
        state, reason = "BLOCKED_ENTERPRISE_STATE", "Roadmap and backlog are not both ACTIVE_OPERATIONS."
    elif task.get("approval_state") != "APPROVED" or task.get("dispatch_authorized") is not True:
        state, reason = "BLOCKED_TASK_AUTHORIZATION", f"{task_id} is not approved and explicitly dispatch-authorized."
    elif event not in ("push", "schedule"):
        state, reason = "SKIPPED_UNSUPPORTED_EVENT", "Only main push and scheduled events may start an autonomous verification."
    else:
        authorized = True
        state, reason = "AUTHORIZED_VERIFICATION", f"Live policy permits scoped verification for {task_id}."

    record = {
        "timestamp": now(),
        "event": event,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "worker_commit": os.environ.get("GITHUB_SHA"),
        "task_id": task_id,
        "candidate_branch": candidate_branch,
        "explicit_file_allowlist": task.get("explicit_file_allowlist", []) if task else [],
        "read_file_allowlist": read_file_allowlist,
        "read_allowlist_count": len(read_file_allowlist) if isinstance(read_file_allowlist, list) else 0,
        "state": state,
        "authorized": authorized,
        "reason": reason,
        "codebase_index_commit": index.get("last_verified_commit"),
        "loaded_heuristic_count": len(heuristics["rules"]),
        "ceo_audit_system_status": audit.get("system_status"),
        "ceo_audit_execution_hold": audit_safety.get("execution_hold"),
        "private_source_checked_out": False,
        "model_patch_applied": False,
    }
    append_checkpoint(record, write_token)
    output({"authorized": authorized, "policy_state": state, "loaded_heuristics": len(heuristics["rules"]), "task_id": task_id or "", "candidate_branch": candidate_branch, "baseline_sha": index.get("last_verified_commit", ""), "candidate_sha": candidate_sha, "file_allowlist": json.dumps(file_allowlist, separators=(",", ":")), "read_file_allowlist": json.dumps(read_file_allowlist, separators=(",", ":")), "verification_mode": verification_mode})
    print(f"AUTONOMY_POLICY={state}")
    print(f"AUTONOMY_TASK_ID={task_id or 'NONE'}")
    print(f"AUTONOMY_VERIFICATION_AUTHORIZED={'YES' if authorized else 'NO'}")
    print(f"KAIZEN_RULES_LOADED={len(heuristics['rules'])}")
    print("PRIVATE_SOURCE_CHECKOUT=DEFERRED_UNTIL_POLICY_AUTHORIZATION")
    return 0


def checkpoint():
    token = os.environ.get("ENTERPRISE_HQ_AUDIT_APPEND_TOKEN") or os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
    if not token:
        raise RunnerError("HQ audit-append credential unavailable; governance checkpoint cannot be recorded.")
    outcomes = {
        "private_checkout": os.environ.get("PRIVATE_CHECKOUT_OUTCOME", "skipped"),
        "frontend": os.environ.get("FRONTEND_OUTCOME", "skipped"),
        "sql": os.environ.get("SQL_OUTCOME", "skipped"),
        "native_dependencies": os.environ.get("NATIVE_DEPS_OUTCOME", "skipped"),
        "rust": os.environ.get("RUST_OUTCOME", "skipped"),
        "publish_identity": os.environ.get("PUBLISH_OUTCOME", "skipped"),
        "runner_identity": os.environ.get("RUNNER_ID_OUTCOME", "skipped"),
        "read_allowlist": os.environ.get("READ_ALLOWLIST_OUTCOME", "skipped"),
    }
    preview_required = os.environ.get("VERIFICATION_MODE", "") == "PREVIEW_ONLY"
    preview_bundle_outcome = os.environ.get("PREVIEW_BUNDLE_OUTCOME", "skipped")
    preview_artifact_outcome = os.environ.get("PREVIEW_ARTIFACT_OUTCOME", "skipped")
    authorized = os.environ.get("AUTONOMY_AUTHORIZED", "").casefold() == "true"
    run_id = os.environ.get("GITHUB_RUN_ID")
    source_sha_path = pathlib.Path("/dev/shm/enterprise_workspace/PLY_ERP_COMMIT_SHA")
    source_sha = source_sha_path.read_text(encoding="utf-8").strip() if source_sha_path.is_file() else None
    runner_id = None
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if github_token and run_id and run_id.isdigit():
        jobs = request_json("GET", f"{API}/repos/{os.environ.get('GITHUB_REPOSITORY', 'bhagyamehta1-lab/ply-erp-builder')}/actions/runs/{run_id}/jobs", github_token) or {}
        job = next((item for item in jobs.get("jobs", []) if item.get("name") == "Public CEO command and worker engine"), None)
        if job and isinstance(job.get("runner_id"), int):
            runner_id = job["runner_id"]
    passed = (
        authorized
        and all(value == "success" for key, value in outcomes.items() if key != "rust" or not preview_required)
        and (not preview_required or (preview_bundle_outcome == "success" and preview_artifact_outcome == "success"))
        and bool(source_sha)
        and isinstance(runner_id, int)
        and runner_id > 0
    )
    policy_state = os.environ.get("AUTONOMY_POLICY_STATE", "")
    blocked_state = policy_state if policy_state.startswith("BLOCKED_") or policy_state.startswith("SKIPPED_") else ""
    checkpoint_state = "VERIFIED_PASS" if passed else (blocked_state or "VERIFICATION_FAILED")
    record = {
        "timestamp": now(),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "run_id": run_id,
        "worker_commit": os.environ.get("GITHUB_SHA"),
        "task_id": os.environ.get("AUTONOMY_TASK_ID", "UNKNOWN") or None,
        "state": checkpoint_state,
        "authorized": authorized,
        "product_commit": source_sha,
        "runner_id": runner_id,
        "step_outcomes": {**outcomes, "preview_bundle": preview_bundle_outcome, "preview_artifact": preview_artifact_outcome},
        "private_source_in_public_logs": False,
        "model_patch_applied": False,
        "allowlist_enforced": outcomes["read_allowlist"] == "success",
        "read_allowlist_enforced": outcomes["read_allowlist"] == "success",
        "workflow_conclusion_at_checkpoint": "IN_PROGRESS",
        "workspace_cleanup": "PENDING_FINAL_ALWAYS_STEP",
        "materialized_source_files": json.loads(os.environ.get("READ_FILE_ALLOWLIST_JSON", "[]")) if outcomes["read_allowlist"] == "success" else [],
    }
    append_checkpoint(record, token)

    # Append governance telemetry with the HQ-only writer; never mutate execution gates.
    audit, audit_sha = get_json(AUDIT_PATH, token)
    audit.setdefault("commands", []).append({
        "command": "GOVERNANCE_ONLY_SHIFT_WATCH_TELEMETRY",
        "trigger": "public worker post-policy checkpoint",
        "workflow_run_id": int(run_id) if run_id and run_id.isdigit() else None,
        "runner_id": runner_id,
        "result": checkpoint_state,
        "product_source_checkout": "SKIPPED" if not authorized else "AUTHORIZED_BY_SEPARATE_POLICY",
        "timestamp": now(),
        "safety_state_preserved": audit.get("system_status") == "SAFE_HOLD",
    })
    audit["timestamp"] = now()
    audit["latest_shift_watch"] = {
        "mode": "GOVERNANCE_ONLY",
        "system_status": audit.get("system_status"),
        "execution_hold": audit.get("safety", {}).get("execution_hold"),
        "builds_enabled": audit.get("safety", {}).get("builds_enabled"),
        "dispatch_enabled": audit.get("safety", {}).get("dispatch_enabled"),
        "latest_worker_run_id": int(run_id) if run_id and run_id.isdigit() else None,
        "latest_worker_runner_id": runner_id,
        "latest_worker_conclusion": "IN_PROGRESS_AT_AUDIT_APPEND",
        "worker_checkpoint": checkpoint_state,
        "private_source_checkout": False if not authorized else "NOT_YET_PERFORMED",
        "public_actions_artifacts": 0,
        "meera_employee_id": "EMP-05",
        "qa_transition_called": False,
        "ceo_uat": "PENDING",
        "deployments_enabled": audit.get("safety", {}).get("deployments_enabled"),
    }
    put_contents(AUDIT_PATH, audit, token, audit_sha, "audit: append governance-only shift telemetry")

    if passed:
        index, sha = get_json(INDEX_PATH, token)
        index["last_verified_commit"] = source_sha
        index["last_verified_run_id"] = int(run_id) if run_id and run_id.isdigit() else None
        index["last_verified_runner_id"] = runner_id
        index["last_verified_at"] = now()
        index["last_verified_task_id"] = os.environ.get("AUTONOMY_TASK_ID", "UNKNOWN")
        product_root = pathlib.Path("/dev/shm/enterprise_workspace/PLY_ERP")
        if product_root.is_dir():
            tracked = subprocess.check_output(
                ["git", "-C", str(product_root), "ls-tree", "-r", "HEAD"],
                text=True,
            ).splitlines()
            blob_by_path = {}
            for line in tracked:
                metadata, path = line.split("\t", 1)
                blob_by_path[path] = metadata.split()[2]
            paths = [
                "src/platform/storage/contracts.ts",
                "src/platform/storage/migrations/registry.ts",
                "src/platform/storage/migrations/003_flexible_production_masters.sql",
                "src/platform/storage/migrations/005_inventory_movements_and_dispatch.sql",
                "src-tauri/src/storage.rs",
                "src-tauri/src/lib.rs",
                "src/components/DashboardSummary.tsx",
                "src/components/InventoryDispatchManager.tsx",
                "src/App.tsx",
                "src/styles.css",
            ]
            index["indexed_files"] = [
                {"path": path, "blob_sha": blob_by_path[path]}
                for path in paths if path in blob_by_path
            ]
            index["tauri_commands"] = [
                {"name": name, "source": "src-tauri/src/lib.rs"}
                for name in (
                    "initialize_local_storage", "check_local_storage_integrity",
                    "get_dashboard_summary", "post_production_voucher",
                    "record_inventory_movement", "create_dispatch_order",
                    "update_dispatch_order_status", "list_inventory_item_options",
                    "list_dispatch_orders", "list_production_processes",
                    "save_production_process", "set_production_process_active",
                    "list_inventory_items", "save_inventory_item",
                    "set_inventory_item_active", "list_process_material_requirements",
                    "save_process_material_requirement", "replace_process_material_requirements",
                    "delete_process_material_requirement",
                )
            ]
        put_index_with_retry(index, token, sha, "index: refresh codebase cache after green verification")

        candidate = os.environ.get("QA_HEURISTIC_JSON", "")
        if candidate:
            rule = json.loads(candidate)
            if not isinstance(rule, dict) or rule.get("verified_in_run") != str(run_id):
                raise RunnerError("A QA heuristic may be learned only when its evidence names this green run.")
            append_verified_heuristic(rule, token)

    print("AUTONOMY_TASK_ID=" + os.environ.get("AUTONOMY_TASK_ID", "UNKNOWN"))
    print("AUTONOMY_CHECKPOINT=" + ("PASS" if passed else "FAIL"))
    print("PRIVATE_SOURCE_CONTENT_IN_LOGS=NO")
    return 0 if passed or not authorized else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "checkpoint"))
    args = parser.parse_args()
    try:
        self_test_write_path_guards()
        return preflight() if args.mode == "preflight" else checkpoint()
    except (RunnerError, OSError, ValueError, KeyError, TypeError) as exc:
        safe_message = str(exc).replace("\n", " ")[:400]
        print(f"AUTONOMY_RUNNER_ERROR={type(exc).__name__}: {safe_message}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
