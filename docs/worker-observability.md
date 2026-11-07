# Worker observability and privacy contract

## Purpose

Measure whether the PLY ERP worker is doing useful, verified work—not merely starting a scheduled GitHub Actions run. A green health check is not a completed product task.

## Measurement layers

1. **Schedule/run layer** — event type, scheduled/start/completion timestamps, run gap, queue delay, run conclusion.
2. **Workflow-step layer** — step name, status/conclusion and elapsed time from GitHub Actions job metadata.
3. **Runner-resource layer** — best-effort cgroup CPU counter delta, cgroup memory current/peak, host load/memory snapshots, and workspace disk snapshot.
4. **Task layer (future instrumentation)** — task ID, role, task type, enqueue/start/end, attempt, outcome, verification result and error class.
5. **Model-call layer (future supported provider)** — provider/model, request latency, provider-returned input/output tokens, retries and verified billing data.

Never combine these layers into one “work duration.” In particular, a 30-second workflow is not evidence of 30 seconds of productive task work.

## Metric interpretation

- MEASURED: direct timestamp/counter/provider value with a documented scope.
- ESTIMATED: derived value with the derivation and assumptions stated.
- UNAVAILABLE: not returned or not instrumented. Never replace it with zero.
- MEASURED_WITH_SCOPE_CAVEAT: a counter was read, but its isolation boundary is not guaranteed.

The first resource snapshot implementation reads the root cgroup and host /proc values. Depending on runner isolation, cgroup values may cover a runner or broader host cgroup. The memory peak can include activity before the start snapshot. These are therefore runner-level indicators, not task-attributed CPU/RAM measurements.

## Privacy contract

- Keep snapshots in the runner's mode-0700 /dev/shm/enterprise_workspace.
- Send aggregate telemetry only to the private Enterprise-HQ checkpoint using the existing credential.
- Do not upload telemetry artifacts to the public worker repository.
- Never record prompts, model outputs, source contents, customer records, environment variables, authorization headers, tokens, or raw API response bodies.
- Public workflow logs may expose step names, statuses and the marker that a private snapshot was captured; they must not print metric payloads.
- Do not add third-party observability SaaS without an explicit privacy/data-processing review.

## Productivity and reliability metrics

Use the SRE golden-signal framing—latency, traffic, errors and saturation—alongside task-specific output and quality:
- Throughput: verified completed tasks / active task-processing hour.
- Completion rate: verified completed tasks / tasks actually started.
- Rework rate: tasks reopened or repeated after failed QA / tasks reaching QA.
- Error rate: failed task attempts / all task attempts; report error classes separately.
- Queue wait: task start minus enqueue time.
- End-to-end task time: verified completion minus enqueue time.
- Resource efficiency: verified completed tasks per measured CPU-second, only when CPU scope is task-attributable.
- Cost per verified task: only when provider billing/cost data is available and attributable.

Always report numerator, denominator, sample count and observation window. Split schedule, push, pull-request and manual events. A blocked task is not a failed task; a health check is not product output.

## Current instrumentation gaps

This increment records run-level resource snapshots and workflow-step durations. It does not yet provide reliable task-level CPU/RAM, task queue wait, task execution time, provider token usage, API call count, per-task cost, or EMP-01..EMP-05 output attribution. Those fields must remain unavailable until instrumented at the task/model-call boundary.

## Acceptance checks

- Missing snapshots do not become zero-valued metrics.
- Cgroup counter resets never create negative CPU usage.
- A cgroup source mismatch disables CPU delta calculation.
- Private telemetry is not printed or uploaded as a public artifact.
- Resource telemetry collection failure does not mask the worker's real task outcome.
- Existing CEO audit, authorization, SAFE_HOLD, task grants, product source and release/deployment gates remain unchanged.
