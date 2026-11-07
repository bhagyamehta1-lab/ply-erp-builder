#!/usr/bin/env python3
"""External heartbeat watchdog for the Public Worker Executor.

This process is intended for an external cron service (Render Cron).
It only dispatches workflow_dispatch mode=health_check. It never polls HQ,
syncs the CEO inbox, or executes product tasks.
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

REPOSITORY = "bhagyamehta1-lab/ply-erp-builder"
WORKFLOW = "public_worker_executor.yml"
BRANCH = "main"
STALE_AFTER = timedelta(minutes=30)
DISPATCH_COOLDOWN = timedelta(minutes=25)
API_ROOT = "https://api.github.com"


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def is_stale(last_scheduled_at: datetime | None, now: datetime) -> bool:
    return last_scheduled_at is None or now - last_scheduled_at > STALE_AFTER


def has_active_run(runs: list[dict]) -> bool:
    return any(run.get("status") in {"queued", "in_progress"} for run in runs)


def has_recent_dispatch(runs: list[dict], now: datetime) -> bool:
    for run in runs:
        if run.get("event") != "workflow_dispatch":
            continue
        created = run.get("created_at")
        if created and now - parse_timestamp(created) < DISPATCH_COOLDOWN:
            return True
    return False


def request_json(url: str, token: str, method: str = "GET", payload: dict | None = None):
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "enterprise-hq-external-worker-watchdog",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20) as response:
            body = response.read()
            return json.loads(body.decode("utf-8")) if body else None
    except HTTPError as exc:
        # Do not print request headers or credential material.
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail}") from None
    except URLError as exc:
        raise RuntimeError(f"GitHub API connection failed: {exc.reason}") from None


def main() -> int:
    token = os.environ.get("GH_ACTIONS_TOKEN", "").strip()
    if not token:
        print("WATCHDOG=ERROR reason=GH_ACTIONS_TOKEN_missing", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    runs_url = (
        f"{API_ROOT}/repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/runs?per_page=50"
    )
    try:
        result = request_json(runs_url, token)
        runs = result.get("workflow_runs", []) if isinstance(result, dict) else []
        scheduled = [
            run for run in runs
            if run.get("event") == "schedule" and run.get("created_at")
        ]
        last_scheduled_at = (
            max(parse_timestamp(run["created_at"]) for run in scheduled)
            if scheduled else None
        )

        if has_active_run(runs):
            print("WATCHDOG=NOOP reason=workflow_run_active")
            return 0

        if not is_stale(last_scheduled_at, now):
            age = now - last_scheduled_at
            print(f"WATCHDOG=HEALTHY last_schedule_age_seconds={int(age.total_seconds())}")
            return 0

        if has_recent_dispatch(runs, now):
            print("WATCHDOG=NOOP reason=recent_health_dispatch_cooldown")
            return 0

        dispatch_url = (
            f"{API_ROOT}/repos/{REPOSITORY}/actions/workflows/{WORKFLOW}/dispatches"
        )
        request_json(
            dispatch_url,
            token,
            method="POST",
            payload={"ref": BRANCH, "inputs": {"mode": "health_check"}},
        )
        previous = last_scheduled_at.isoformat() if last_scheduled_at else "none"
        print(
            "WATCHDOG=DISPATCHED mode=health_check "
            f"last_schedule={previous} stale_after_minutes={int(STALE_AFTER.total_seconds() / 60)}"
        )
        return 0
    except (RuntimeError, ValueError, TypeError, KeyError) as exc:
        print(f"WATCHDOG=ERROR reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
