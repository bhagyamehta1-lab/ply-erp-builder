# Parallel Workstream: Shared architecture & integration

## Purpose
This repository is an independently developed workstream for the PlyMetrix ERP project.

## Assigned scope
Own shared contracts, integration rules, migration sequencing, cross-platform acceptance matrix, and integration coordination. Do not copy private credentials, factory data, encryption keys, or confidential customer data.

## Non-negotiable project constraints
- Offline/local-first operation; no cloud sync, telemetry, or external AI upload.
- Windows, Android tablet, and Android phone feature parity.
- Shared deterministic domain rules; auditable calculations and append-only posted ledgers.
- Database changes must be versioned migrations with rollback/safety consideration.
- Enforce encryption/key readiness before accessing business data.
- Preserve the complete master blueprint; do not remove or reduce requirements.
- No production-readiness claim without end-to-end acceptance on target platforms.
- Never commit PATs, passwords, encryption keys, live factory data, or customer secrets.

## Delivery rules
1. Inspect the current repository state and document assumptions before implementation.
2. Keep work limited to this lane; publish interfaces/contracts for integration.
3. Add unit, integration, migration, and failure/rollback tests for each meaningful workflow.
4. Run relevant checks and record exact commit SHA and results.
5. Do not merge untested changes into the integration repository.
6. Treat sample values as mock data and label them clearly.

## Current status
Workstream brief initialized. Implementation and CI verification are not yet claimed.
