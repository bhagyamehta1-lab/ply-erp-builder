# Parallel Workstream: Shared architecture & integration

## Purpose
This public repository coordinates generic shared contracts and integration rules for the PlyMetrix ERP workstreams. It is not an ERP source repository or a private application build runner.

## Assigned scope
Own sanitized interfaces, generic integration rules, migration-sequencing proposals, cross-platform acceptance matrices, and coordination. Use synthetic fixtures only. Do not checkout, clone, import, execute, build, test, or package private application source from this public repository.

## Non-negotiable project constraints
- Offline/local-first operation; no cloud sync, telemetry, or external AI upload.
- Windows, Android tablet, and Android phone feature parity.
- Shared deterministic domain rules; auditable calculations and append-only posted ledgers.
- Database changes must be versioned migrations with rollback/safety consideration.
- Enforce encryption/key readiness before accessing business data.
- Preserve the complete master blueprint; do not remove or reduce requirements.
- No production-readiness claim without end-to-end acceptance on target platforms.
- Never commit credentials, private source, private schemas, encryption keys, live factory data, customer/supplier information, private artifacts, or unredacted private logs.

## Public runner boundary
- Only sanitized synthetic contract tests may execute in this public repository.
- No workflow may use secret-backed checkout of a non-public repository or publish application artifacts/releases.
- Private source validation and its logs must remain within the private repository's own CI.
- A successful public contract test is isolated lane evidence only; it is not private application integration or platform acceptance.

## Delivery rules
1. Inspect this repository and document assumptions before implementation.
2. Keep work limited to generic contracts and synthetic fixtures.
3. Add focused contract tests for each public-lane change.
4. Run relevant public tests and record the exact public commit SHA and results.
5. Do not merge untested changes into the integration lane.
6. Treat sample values as synthetic and label them clearly.

## Current status
The public lane is limited to sanitized contracts and synthetic tests. Private application implementation and platform verification are out of scope for this repository.
