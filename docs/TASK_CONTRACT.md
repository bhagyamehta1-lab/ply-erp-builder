# Worker task contract — ply-erp-builder

## Objective
Integration controller; Windows/Android build and release smoke.

## Source of truth
- Product source of truth: private `bhagyamehta1-lab/PLY_ERP`.
- Work must be pinned to one explicit private source commit SHA before any source-level test is reported.
- Never copy private source, customer/factory data, credentials, tokens, database files or confidential reports into this public repository.
- No private-source credential is configured by this contract. Until a safe, minimum-permission GitHub App or equivalent is approved and configured outside public workflow code, mark private-source verification as **blocked**.

## Scope and acceptance
Verify exact source SHA, build matrix, release evidence; never publish a release without owner approval.
- Tests must import or execute the actual private-source implementation at the pinned SHA; copied business-rule tests alone are not acceptance evidence.
- Record unit, integration, migration and relevant end-to-end results separately.
- A module is not complete until its end-to-end workflow, permissions, audit trail, reports and business-owner acceptance pass.

## Required task result
Every task result must include:
- task_id, worker_repo, module, private_source_sha (or null while blocked)
- changed_files, commit_sha, test_commands, test_results
- acceptance_total, acceptance_passed, acceptance_failed, acceptance_not_tested
- blockers, risks, rollback_note, evidence_links, updated_at
- status: Not started / In progress / Blocked / In review / Passed / Merged / Accepted

## Safety and integration
- Public repository contains only sanitized code, contracts and non-sensitive status.
- One coherent feature per private integration PR; never push directly to production/main.
- No private PR, merge, production data change, credential rotation or release without owner approval.
- Offline data model: each device has its own local database. Device transfer is explicit encrypted backup export/import; no cloud or automatic sync.
