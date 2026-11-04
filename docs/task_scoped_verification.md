# Task-scoped PLY ERP verification

The public worker is execution infrastructure only. Private PLY_ERP source is cloned only to `/dev/shm/enterprise_workspace` after the DNA-first preflight has loaded the Enterprise-HQ codebase index and learned heuristics.

For PLY-0002, the worker requires all of the following live facts:
- Exactly one Enterprise-HQ backlog task is `IN_PROGRESS`, `APPROVED`, and `dispatch_authorized: true`.
- The roadmap contains a matching `safety.task_scoped_build_authorizations.PLY-0002` grant.
- The grant names the private product repository and candidate branch.
- The candidate diff from the last verified product commit is contained in the seven-file PLY-0002 allowlist.
- Frontend build, SQL migrations, Rust formatting and unit tests, positive runner identity, sanitized logging, and tmpfs cleanup pass before completion is recorded.

The global `builds_enabled` flag remains false; this grant is task-specific. Releases and deployments remain disabled. A task is never marked complete from a worker health check or a failed/skipped preflight.
