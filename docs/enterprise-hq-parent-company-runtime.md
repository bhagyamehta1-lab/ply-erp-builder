# Enterprise-HQ parent-company runtime foundation

## Scope

This is a separate parent-company lane. It does not execute PLY ERP work, read product source, dispatch product tasks, or alter product grants. Project 001 remains outside this lane. The implementation is deterministic software, not an LLM-backed workforce.

## Read-only observer

The observer reads exactly three private governance records from Enterprise-HQ main:

- company identity metadata, to confirm the parent-company and Project 001 boundary;
- CEO audit metadata, to validate the audit envelope and safety-field types without emitting gate values;
- the company completion register, to count workstreams and their statuses.

It enforces an exact private-path allowlist and a 512 KiB response cap. Base64 whitespace is normalized before strict decoding. Workstream statuses are restricted to the register's known vocabulary. Readiness values are emitted only when they match the small, currently approved status allowlist; unknown values become `UNKNOWN`. Public output omits private timestamps, identifiers, file contents, prompts, grants, task payloads, and safety-gate values. The GitHub read token is available only to the one workflow step that reads those records. The aggregate artifact is retained for one day.

## Deterministic task contract

`scripts/enterprise_hq_task_contract.py` is a pure validation library:

- accepts only HQ task IDs and WS-01 through WS-11;
- accepts only internal research, internal documentation, internal code, and read-only audit task kinds;
- rejects extra payload fields, product workstream IDs, external effects, unapproved task plans, and non-zero initial attempts;
- caps a batch at eight tasks and applies per-task and per-batch byte limits;
- routes task kinds to deterministic logical roles;
- derives stable SHA-256 idempotency keys;
- creates hash-chained metadata audit records;
- produces a distinct logical verifier assignment and a bounded recovery decision.

These are logical roles, not authenticated people or worker processes. The verifier identity is explicitly marked `NOT_AUTHENTICATED`. A hash chain detects mutation relative to the supplied chain, but is not a signature, external timestamp, durable append-only store, or proof of authorship.

## Local durable proposal ledger

`scripts/enterprise_hq_task_ledger.py` adds a bounded SQLite proposal ledger using only Python's standard library:

- persists up to 256 validated task proposals;
- uses SQLite transactions (`BEGIN IMMEDIATE`) so a proposal and its audit event commit or roll back together;
- treats identical proposals as idempotent and rejects a task ID reused with different content;
- stores only the strict task-contract fields and deterministic logical role;
- records a sequenced SHA-256 event chain and verifies it on reopen;
- checks SQLite integrity, task schema, idempotency keys, event count, event ordering, role attribution and chain hashes;
- keeps every task in `PROPOSED` / human-review-required state.

The restart check proves only that local proposal records and their audit chain can be reopened and verified. It does not recover a running worker, renew a lease, authenticate an actor, resume a task, or retry work. The ledger has no claim, execution, dispatch, network, or result-verification API. The database is a local runtime component and has not been provisioned as a shared or production service.

## Execution and verification limits

The runtime does not claim to execute tasks, acquire distributed leases, perform semantic result verification, or dispatch retries. A `RETRY_ELIGIBLE` result from the pure contract is only a decision value; it does not enqueue or execute anything. Logical reviewer roles are not authenticated identities. A separately authenticated runtime, durable shared storage, independent verifier identity and explicit authorization would be required before any execution capability could be considered.

No LLM provider is configured or authorized. No model API, cloud service, paid dependency, or remote worker is invoked. The current GitHub Actions workflow remains a periodic, read-only observer, not an always-on service or a 24/7 reliability guarantee.

## Local verification

Run:

```sh
python -m unittest discover -s tests -p 'test_enterprise_hq_company_observer.py'
python -m unittest discover -s tests -p 'test_enterprise_hq_task_contract.py'
python -m unittest discover -s tests -p 'test_enterprise_hq_task_ledger.py'
```

All suites are pure local tests and require no network, secrets, provider, paid service, or external system.
