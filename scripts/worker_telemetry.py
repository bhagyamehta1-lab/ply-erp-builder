#!/usr/bin/env python3
"""Privacy-preserving, best-effort runner resource snapshots.

Only aggregate host/cgroup counters are recorded. No prompts, source contents,
environment values, credentials, customer records, or request payloads are read.
Snapshots are intended for private Enterprise-HQ checkpoint ingestion.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import tempfile
from datetime import datetime, timezone

SCHEMA_VERSION = "1.0.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_int(path: pathlib.Path) -> int | None:
    try:
        raw = path.read_text(encoding="ascii").strip()
        return int(raw) if raw and raw != "max" else None
    except (OSError, ValueError):
        return None


def read_key_value(path: pathlib.Path) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        for line in path.read_text(encoding="ascii").splitlines():
            parts = line.split()
            if len(parts) == 2:
                try:
                    result[parts[0]] = int(parts[1])
                except ValueError:
                    continue
    except OSError:
        pass
    return result


def cgroup_snapshot() -> dict:
    root = pathlib.Path("/sys/fs/cgroup")
    cpu_stat = read_key_value(root / "cpu.stat")
    memory_current = read_int(root / "memory.current")
    memory_peak = read_int(root / "memory.peak")
    if cpu_stat or memory_current is not None or memory_peak is not None:
        return {
            "source": "cgroup_v2_root",
            "scope": "runner_cgroup_or_host_cgroup; exact isolation not guaranteed",
            "cpu_usage_usec": cpu_stat.get("usage_usec"),
            "memory_current_bytes": memory_current,
            "memory_peak_bytes": memory_peak,
        }

    cpu_ns = read_int(pathlib.Path("/sys/fs/cgroup/cpuacct/cpuacct.usage"))
    mem_current = read_int(pathlib.Path("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
    mem_peak = read_int(pathlib.Path("/sys/fs/cgroup/memory/memory.max_usage_in_bytes"))
    if cpu_ns is not None or mem_current is not None or mem_peak is not None:
        return {
            "source": "cgroup_v1_root",
            "scope": "runner_cgroup_or_host_cgroup; exact isolation not guaranteed",
            "cpu_usage_usec": cpu_ns // 1000 if cpu_ns is not None else None,
            "memory_current_bytes": mem_current,
            "memory_peak_bytes": mem_peak,
        }
    return {"source": "unavailable", "scope": "unavailable",
            "cpu_usage_usec": None, "memory_current_bytes": None,
            "memory_peak_bytes": None}


def host_snapshot() -> dict:
    total = available = None
    try:
        mem = read_key_value(pathlib.Path("/proc/meminfo"))
        total = mem.get("MemTotal")
        available = mem.get("MemAvailable")
        if total is not None:
            total *= 1024
        if available is not None:
            available *= 1024
    except OSError:
        pass
    try:
        load = list(os.getloadavg())
    except (OSError, AttributeError):
        load = None
    return {
        "cpu_count": os.cpu_count(),
        "load_average_1_5_15": load,
        "memory_total_bytes": total,
        "memory_available_bytes": available,
    }


def snapshot(workspace: str | None = None) -> dict:
    disk = None
    if workspace:
        try:
            usage = shutil.disk_usage(workspace)
            disk = {"total_bytes": usage.total, "used_bytes": usage.used,
                    "free_bytes": usage.free}
        except OSError:
            disk = None
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp_utc": utc_now(),
        "host": host_snapshot(),
        "cgroup": cgroup_snapshot(),
        "workspace_disk": disk,
    }


def write_snapshot(path: str, workspace: str | None = None) -> None:
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(snapshot(workspace), sort_keys=True, separators=(",", ":"))
    fd, tmp_name = tempfile.mkstemp(prefix=".telemetry-", dir=str(target.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
        os.replace(tmp_name, target)
        os.chmod(target, 0o600)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def summarize_snapshots(start: dict | None, end: dict | None) -> dict:
    if not isinstance(start, dict) or not isinstance(end, dict):
        return {"status": "PARTIAL_OR_UNAVAILABLE", "sample_count": int(start is not None) + int(end is not None)}
    start_cg, end_cg = start.get("cgroup", {}), end.get("cgroup", {})
    cpu_delta = None
    if (start_cg.get("source") == end_cg.get("source")
            and isinstance(start_cg.get("cpu_usage_usec"), int)
            and isinstance(end_cg.get("cpu_usage_usec"), int)):
        delta = end_cg["cpu_usage_usec"] - start_cg["cpu_usage_usec"]
        cpu_delta = max(0, delta) / 1_000_000
    try:
        t0 = datetime.fromisoformat(start["timestamp_utc"].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(end["timestamp_utc"].replace("Z", "+00:00"))
        elapsed = max(0.0, (t1 - t0).total_seconds())
    except (KeyError, TypeError, ValueError):
        elapsed = None
    return {
        "status": "MEASURED_WITH_SCOPE_CAVEAT",
        "sample_count": 2,
        "snapshot_elapsed_seconds": elapsed,
        "cgroup_source": end_cg.get("source", "unavailable"),
        "cgroup_scope": end_cg.get("scope", "unavailable"),
        "cgroup_cpu_seconds_delta": cpu_delta,
        "cgroup_memory_current_bytes_at_end": end_cg.get("memory_current_bytes"),
        "cgroup_memory_peak_bytes_at_end": end_cg.get("memory_peak_bytes"),
        "host_at_start": start.get("host", {}),
        "host_at_end": end.get("host", {}),
        "workspace_disk_at_end": end.get("workspace_disk"),
        "limitations": [
            "cgroup counters may cover the runner or host cgroup, not only this job",
            "memory peak may include activity before the start snapshot",
            "host load and memory are host-wide snapshots, not task-attributed",
        ],
    }


def load_pair(start_path: str, end_path: str) -> dict:
    def load(path: str):
        try:
            value = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else None
        except (OSError, json.JSONDecodeError):
            return None
    return summarize_snapshots(load(start_path), load(end_path))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("output")
    snap.add_argument("--workspace", default=os.environ.get("WORKSPACE"))
    args = parser.parse_args()
    if args.command == "snapshot":
        write_snapshot(args.output, args.workspace)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
