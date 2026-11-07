# Enterprise-HQ parent-company runtime foundation

## Scope

This is a separate parent-company lane. It does not execute PLY ERP work, read product source, dispatch product tasks, or alter product grants. Project 001 remains outside this lane.

## Read-only observer

The observer reads exactly three private governance records from Enterprise-HQ main:

- company identity metadata, to confirm the parent-company and Project 001 boundary;
- CEO audit metadata, to validate the audit envelope;
- the company completion register, to count workstreams and their statuses.

It enforces an exact private-path allowlist and a 512 KiB response cap. Base64 whitespace is normalized before strict decoding. Public output is restricted to aggregate counts and status fields; it omits private timestamps, identifiers, file contents, prompts, grants, and task payloads. The GitHub read token is available only to the one workflow step that reads those records. The aggregate artifact is retained for one day.

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

These are logical roles, not authenticated people or worker processes. The verifier identity is explicitly marked NOT_AUTHENTICATED. A hash chain detects accidental or subsequent mutation relative to the supplied chain, but is not a signature, external timestamp, durable append-only store, or proof of authorship.

## Execution and verification limits

The library does not claim to run tasks, persist queue state, acquire distributed leases, perform semantic result verification, or dispatch retries. A RETRY_ELIGIBLE result is only a decision value; it does not enqueue or execute anything. A separate authenticated runtime, durable storage, independently authenticated verifier identity, and explicit authorization would be required before any execution capability could be considered.

No LLM provider is configured or authorized. No model API, cloud service, paid dependency, or remote worker is invoked. The current workflow remains a periodic, read-only GitHub Actions observer, not an always-on service or a 24/7 reliability guarantee.

## Local verification

Run:

```sh
python -m unittest discover -s tests -p 'test_enterprise_hq_company_observer.py'
python -m unittest discover -s tests -p 'test_enterprise_hq_task_contract.py'
```

Both suites are pure local tests and require no network, secrets, provider, or external services.
