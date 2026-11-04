#!/usr/bin/env python3
"""Policy-gated background verifier for Enterprise-HQ.

Reads the alignment DNA before any other HQ state. It never edits product source,
never applies model-generated patches, and fails closed when authorization is absent.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

HQ = "bhagyamehta1-lab/Enterprise-HQ"
PRODUCT = "bhagyamehta1-lab/PLY_ERP"
API = "https://api.github.com"
CHECKPOINT_PATH = "state/autonomous_shift_checkpoints.json"
INDEX_PATH = "state/codebase_index.json"
HEURISTICS_PATH = "state/learned_heuristics.json"
DNA_PATH = "protocols/enterprise_alignment_dna.md"


class RunnerError(RuntimeError):
    pass


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def request_json(method: str, url: str, token: str, payload=None):
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
    try:
        existing, sha = get_json(CHECKPOINT_PATH, token)
        if not isinstance(existing, dict) or not isinstance(existing.get("checkpoints"), list):
            raise RunnerError("Checkpoint store schema is invalid.")
    except RunnerError as exc:
        if "Required HQ file is missing" not in str(exc):
            raise
        existing, sha = {"schema_version": "1.0.0", "checkpoints": []}, None
    existing["checkpoints"].append(record)
    existing["checkpoints"] = existing["checkpoints"][-100:]
    put_contents(CHECKPOINT_PATH, existing, token, sha)


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
    write_token = os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
    if not read_token or not write_token:
        raise RunnerError("HQ read/write credentials are unavailable; autonomous execution is blocked.")

    # The alignment DNA is deliberately the first HQ file read in every worker run.
    dna, _ = get_contents(DNA_PATH, read_token)
    if "## Session bootstrap" not in dna or "## Five behavioral gaps" not in dna:
        raise RunnerError("Enterprise alignment DNA is incomplete; refusing to continue.")

    orchestrator, _ = get_contents("scripts/autonomous_orchestrator.py", read_token)
    compile(orchestrator, "Enterprise-HQ/scripts/autonomous_orchestrator.py", "exec")
    if "--prepare-shift" not in orchestrator or "--record-qa-heuristic" not in orchestrator:
        raise RunnerError("HQ orchestrator does not expose the required shift-memory interface.")

    index, _ = get_json(INDEX_PATH, read_token)
    heuristics, _ = get_json(HEURISTICS_PATH, read_token)
    roadmap, _ = get_json("state/enterprise_roadmap.json", read_token)
    backlog, _ = get_json("projects/ply_erp_backlog.json", read_token)

    required_heuristic_fields = {"id", "trigger_pattern", "root_cause", "mandatory_fix", "verified_in_run"}
    if (not isinstance(index, dict) or not index.get("last_verified_commit")
            or index.get("storage_schema_version") != 5
            or not isinstance(heuristics, dict) or not isinstance(heuristics.get("rules"), list)
            or any(not isinstance(rule, dict) or not required_heuristic_fields.issubset(rule) for rule in heuristics["rules"])):
        raise RunnerError("Codebase index or learned heuristics schema is invalid.")

    task = next((item for item in backlog.get("requirements", []) if item.get("task_id") == "PLY-0001"), None)
    safety = roadmap.get("safety", {})
    event = os.environ.get("GITHUB_EVENT_NAME", "unknown")
    authorized = False
    state = "BLOCKED_UNKNOWN_STATE"
    reason = "Required PLY-0001 authorization conditions were not met."

    if task is None:
        state, reason = "BLOCKED_TASK_NOT_FOUND", "PLY-0001 is absent from the live HQ backlog."
    elif task.get("status") == "COMPLETED":
        state, reason = "SKIPPED_TASK_COMPLETED", "PLY-0001 is already completed; no product checkout or build is needed."
    elif safety.get("builds_enabled") is not True:
        state, reason = "BLOCKED_GLOBAL_BUILD_GATE", "The live roadmap has builds_enabled=false."
    elif safety.get("execution_hold") is not False:
        state, reason = "BLOCKED_EXECUTION_HOLD", "The live roadmap execution hold is active."
    elif roadmap.get("status") != "ACTIVE_OPERATIONS" or backlog.get("enterprise_status") != "ACTIVE_OPERATIONS":
        state, reason = "BLOCKED_ENTERPRISE_STATE", "Roadmap and backlog are not both ACTIVE_OPERATIONS."
    elif task.get("status") != "IN_PROGRESS" or task.get("approval_state") != "APPROVED" or task.get("dispatch_authorized") is not True:
        state, reason = "BLOCKED_TASK_AUTHORIZATION", "PLY-0001 is not approved, in progress and explicitly dispatch-authorized."
    elif event not in ("push", "schedule"):
        state, reason = "SKIPPED_UNSUPPORTED_EVENT", "Only main push and scheduled events may start an autonomous verification."
    else:
        authorized = True
        state, reason = "AUTHORIZED_VERIFICATION", "Live policy explicitly permits scoped PLY-0001 verification."

    record = {
        "timestamp": now(),
        "event": event,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "worker_commit": os.environ.get("GITHUB_SHA"),
        "task_id": "PLY-0001",
        "state": state,
        "authorized": authorized,
        "reason": reason,
        "codebase_index_commit": index.get("last_verified_commit"),
        "loaded_heuristic_count": len(heuristics["rules"]),
        "private_source_checked_out": False,
        "model_patch_applied": False,
    }
    append_checkpoint(record, write_token)
    output({"authorized": authorized, "policy_state": state, "loaded_heuristics": len(heuristics["rules"])})
    print(f"AUTONOMY_POLICY={state}")
    print(f"PLY_0001_VERIFICATION_AUTHORIZED={'YES' if authorized else 'NO'}")
    print(f"KAIZEN_RULES_LOADED={len(heuristics['rules'])}")
    print("PRIVATE_SOURCE_CHECKOUT=DEFERRED_UNTIL_POLICY_AUTHORIZATION")
    return 0


def checkpoint():
    token = os.environ.get("ENTERPRISE_HQ_WRITE_TOKEN", "")
    if not token:
        raise RunnerError("HQ write credential unavailable; verification checkpoint cannot be recorded.")
    outcomes = {
        "private_checkout": os.environ.get("PRIVATE_CHECKOUT_OUTCOME", "skipped"),
        "frontend": os.environ.get("FRONTEND_OUTCOME", "skipped"),
        "sql": os.environ.get("SQL_OUTCOME", "skipped"),
        "native_dependencies": os.environ.get("NATIVE_DEPS_OUTCOME", "skipped"),
        "rust": os.environ.get("RUST_OUTCOME", "skipped"),
        "publish_identity": os.environ.get("PUBLISH_OUTCOME", "skipped"),
        "runner_identity": os.environ.get("RUNNER_ID_OUTCOME", "skipped"),
    }
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
    passed = authorized and all(value == "success" for value in outcomes.values()) and bool(source_sha) and isinstance(runner_id, int) and runner_id > 0
    record = {
        "timestamp": now(),
        "event": os.environ.get("GITHUB_EVENT_NAME"),
        "run_id": run_id,
        "worker_commit": os.environ.get("GITHUB_SHA"),
        "task_id": "PLY-0001",
        "state": "VERIFIED_PASS" if passed else "VERIFICATION_FAILED",
        "authorized": authorized,
        "product_commit": source_sha,
        "runner_id": runner_id,
        "step_outcomes": outcomes,
        "private_source_in_public_logs": False,
        "model_patch_applied": False,
    }
    append_checkpoint(record, token)

    if passed:
        index, sha = get_json(INDEX_PATH, token)
        index["last_verified_commit"] = source_sha
        index["last_verified_run_id"] = int(run_id) if run_id and run_id.isdigit() else None
        index["last_verified_runner_id"] = runner_id
        index["last_verified_at"] = now()
        put_contents(INDEX_PATH, index, token, sha, "index: refresh codebase cache after green verification")

        candidate = os.environ.get("QA_HEURISTIC_JSON", "")
        if candidate:
            rule = json.loads(candidate)
            if not isinstance(rule, dict) or rule.get("verified_in_run") != str(run_id):
                raise RunnerError("A QA heuristic may be learned only when its evidence names this green run.")
            append_verified_heuristic(rule, token)

    print("AUTONOMY_CHECKPOINT=" + ("PASS" if passed else "FAIL"))
    print("PRIVATE_SOURCE_CONTENT_IN_LOGS=NO")
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("preflight", "checkpoint"))
    args = parser.parse_args()
    try:
        return preflight() if args.mode == "preflight" else checkpoint()
    except (RunnerError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"AUTONOMY_RUNNER_ERROR={type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
