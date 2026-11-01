# PlyMetrix Parallel-10 Development Plan

Status: proposal / safe coordination scaffold
Date: 2026-11-01

## Non-negotiable repository boundary

- The private PlyMetrix ERP repository remains the only source of truth for application source code, business data, secrets, release signing material, and production history.
- Public repositories must contain only approved, non-sensitive task specifications, generic tooling, synthetic fixtures, and independently authored code that is safe to publish.
- Never mirror, fork, push, or paste private ERP source, database files, customer/vendor records, real invoices, credentials, tokens, signing keys, environment files, or private commit history into a public repository.
- Public-lane work is not integrated automatically. It is reviewed, security-scanned, tested, and selectively ported/merged into a private integration branch.
- Do not grant public-lane workflows write access to the private repository. Use narrowly scoped, short-lived credentials only in a controlled private integration workflow.

## Proposed ten work lanes

| Lane | Responsibility | Main boundary / deliverable |
|---|---|---|
| 01 | Inventory & Stock | Stock ledger contracts, item/unit rules, reservations-aware availability tests |
| 02 | Purchase & GRN | Purchase order/receipt workflows, supplier and GRN contracts |
| 03 | Production & BOM | BOM validation, material issue/consumption, production posting contracts |
| 04 | Batch Costing & Yield | Batch cost model, actual-vs-planned variance, yield/wastage calculations |
| 05 | Quality & Grades | QC checks, grade allocation, rejection and return reason catalogues |
| 06 | Sales & Orders | Orders, reservations, sellable-stock checks, order lifecycle |
| 07 | Billing, GST & Dispatch | Invoice/dispatch contracts, batch-linked dispatch, statutory validation |
| 08 | Accounts & Ledger | Financial posting contracts, reversals, reconciliation and auditability |
| 09 | Reports, Backup & Offline | Reporting/export specifications, backup/restore and offline acceptance tests |
| 10 | QA, Security & Build | Cross-module test strategy, security checks, Windows/Android build and device validation |

## Pilot sequence

Start with three lanes only; expand after the integration contract is proven:

1. Lane 01 Inventory & Stock
2. Lane 02 Purchase & GRN
3. Lane 03 Production & BOM

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

Ten lanes are ten workstreams, not proof of ten simultaneously running AI agents or tenfold speed. Actual concurrency depends on available workers, compute, API quotas, task independence, and review capacity. Keep concurrency at three during the pilot; move to five after a clean end-to-end integration; enable all ten only after contracts and integration throughput are stable.

## Current implementation status

This file records a proposed workflow only. It does not create ten GitHub repositories, provision agents/runners, grant repository permissions, configure secrets, or change the private ERP source. Those actions require separately available GitHub administration capabilities and explicit safe configuration.

## Initial work-item template

Each lane task should specify:
- Goal and explicit non-goals
- Allowed files/repository and prohibited private material
- Approved contract/schema version
- Acceptance criteria and synthetic test cases
- Dependencies and owner
- Required tests and evidence
- Port/merge plan and rollback plan
