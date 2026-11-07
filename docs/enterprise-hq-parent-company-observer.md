# Enterprise-HQ parent-company observer

## Scope

This is a deterministic, read-only status observer for the Enterprise-HQ parent company. It is not the PLY ERP worker lane, a task dispatcher, or an independent AI agent.

The observer reads only three JSON records from the private Enterprise-HQ `main` branch:

- Parent-company identity and readiness.
- The CEO command audit, for top-level status and aggregate safety-gate counts.
- The company completion register, for workstream status and evidence counts.

It does not read product source, task seed records, department rosters, role contracts, customer/vendor records, or private prompts. It never writes to the private repository.

## Public output and privacy

The public artifact contains only aggregate counts and status fields. It excludes private file contents, audit timestamps, task identifiers, grant identifiers, raw safety-gate values, secrets, and product source. A fixed path allowlist, a 512 KiB per-record response cap, and sanitized error codes make the read boundary explicit.

The read token is exposed only to the single metadata-read step. The job declares `contents: read`, checkout credentials are not persisted, and the only artifact is the aggregate JSON summary with one-day retention.

## Execution and recovery

- Python 3.12 on a GitHub-hosted Ubuntu runner.
- Five-minute job timeout.
- Scheduled observation at minutes 17 and 47 of each hour.
- A push trigger is restricted to the dedicated company-observer hardening branch; manual dispatch remains available.
- A failed read fails closed with a sanitized reason. There is no automatic task retry, dispatch, or private write. A later scheduled invocation can attempt another read.
- The schedule is periodic; it is not an always-on process and does not establish 24/7 reliability.

## Capability truth

The observer verifies metadata and reports counts. It does not execute company tasks, provide durable worker identity, independently review task output, or call an LLM provider. No model provider is authorized or configured by this change. No third-party service or paid runtime is introduced.
