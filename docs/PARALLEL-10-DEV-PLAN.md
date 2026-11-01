# PlyMetrix Parallel-10 Development Plan

Status: coordination scaffold initialized; controlled integration not yet configured
Date: 2026-11-01

## Non-negotiable repository boundary

- The private PlyMetrix ERP repository remains the only source of truth for application source code, business data, secrets, release signing material, and production history.
- Public builder repositories contain only approved, non-sensitive task specifications, generic tooling, synthetic fixtures, and independently authored code that is safe to publish.
- Never mirror, fork, push, or paste private ERP source, database files, customer/vendor records, real invoices, credentials, tokens, signing keys, environment files, or private commit history into a public repository.
- Public-lane work is not integrated automatically. It is reviewed, security-scanned, tested, and selectively ported/merged into a private integration branch.
- Do not grant public-lane workflows write access to the private repository. No PAT or repository secret is required in the public builder repositories.

## Ten builder repositories and responsibilities

| Builder repository | Lane | Responsibility |
|---|---|---|
| ply-erp-builder | 01 | Build & CI coordination; existing private-source build workflow remains here |
| ply-erp-builder-2 | 02 | Inventory & Stock |
| ply-erp-builder-3 | 03 | Purchase & GRN |
| ply-erp-builder-4 | 04 | Production & BOM |
| ply-erp-builder-5 | 05 | Batch Costing & Yield |
| ply-erp-builder-6 | 06 | Quality & Grades |
| ply-erp-builder-7 | 07 | Sales & Orders |
| ply-erp-builder-8 | 08 | Billing, GST & Dispatch |
| ply-erp-builder-9 | 09 | Accounts & Ledger |
| ply-erp-builder-10 | 10 | Reports, Backup, Offline & QA |

The nine newly created empty repositories have received lane-specific README instructions only. Builder 1 already had existing build/CI content; this plan was added there. No application source or credentials were copied to the new repositories.

## Pilot sequence

Start with three module lanes, while builder 1 remains the existing build/CI coordinator:

1. Builder 2 — Inventory & Stock
2. Builder 3 — Purchase & GRN
3. Builder 4 — Production & BOM

Pilot success criteria:
- All three use the same approved domain/API/schema contracts.
- No duplicate stock mutation path is introduced.
- Purchase receipt, raw-material availability, BOM issue, consumption posting, and production posting are tested as one end-to-end flow.
- Production is blocked when required material is unavailable or consumption posting fails.
- All corrections use auditable reversals; no silent stock edits.
- Tests run in isolation with synthetic data.
- A reviewed integration change lands only in a private feature/integration branch.

## Shared contracts required before parallel coding

The private integration owner must approve and version:
- Entity identifiers and ownership.
- Unit-of-measure and decimal precision rules.
- Stock movement and reversal semantics.
- Transaction boundaries and idempotency keys.
- API/event payload schemas and error conventions.
- Migration ownership, ordering, and rollback policy.
- Permission checks and audit event requirements.
- Synthetic fixture format and acceptance tests.

No lane may independently redefine shared tables, migrations, stock posting rules, or common API contracts.

## Integration and release gates

1. Task brief approved; files/modules and interfaces assigned.
2. Public content checked for private data, secrets, and copied proprietary source.
3. Automated lint, typecheck, unit tests, dependency/security scan.
4. Contract and integration tests against synthetic fixtures.
5. Human review of the diff and migration impact.
6. Port/merge into a private feature branch; never directly to private main.
7. Full ERP regression tests and Windows/Android build verification.
8. Physical-device, backup/restore, and offline checks before release claims.

## Parallelism limits and scaling

Ten repositories are ten workspaces, not proof of ten simultaneously running AI agents or tenfold speed. Actual concurrency depends on available workers, compute, API quotas, task independence, and review capacity. Keep active implementation concurrency at three during the pilot; move to five after a clean end-to-end integration; enable all ten only after contracts and integration throughput are stable.

## Current implementation status

The repository list and default branches were checked. The nine new repositories are public and were empty before initialization; each now contains a lane-specific README. Builder 1 already contained existing build/CI material and now also contains this coordination plan.

No PAT, GitHub App, deploy key, repository secret, runner, cross-repository permission, private-source mirroring, or automatic private integration has been configured. Those are intentionally not enabled. This plan does not claim that ten AI workers are running.

## Initial work-item template

Each lane task should specify:
- Goal and explicit non-goals
- Allowed files/repository and prohibited private material
- Approved contract/schema version
- Acceptance criteria and synthetic test cases
- Dependencies and owner
- Required tests and evidence
- Port/merge plan and rollback plan
