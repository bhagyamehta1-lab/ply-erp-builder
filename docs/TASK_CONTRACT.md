# Builder-1 public coordination contract

## Objective
Integration/build coordination and sanitized synthetic contract verification only.

## Source-of-truth boundary
- The application source of truth is maintained in an owner-controlled private repository.
- This public repository must never checkout, clone, import, execute, build, test, package, or publish artifacts from a private repository.
- Do not add private-source credentials, PATs, GitHub App tokens, deployment keys, or repository secrets to this public lane.
- Private implementation validation must run only in workflows owned by the private repository. If that validation is unavailable, report it as blocked; do not route it through this public runner.
- Do not publish private source SHAs, branch names, file paths, schemas, business rules, customer/supplier data, private artifacts, or unredacted private build logs here.

## Scope and acceptance
- Maintain generic interfaces, synthetic fixtures, and independently authored contract tests.
- Public-lane tests may validate only the public synthetic contracts. They are not evidence that the private application implementation or platform builds pass.
- Record unit/contract results separately from private application integration and platform acceptance.
- Never upload application artifacts or create releases from this public lane.

## Required task result
Every task result must include:
- task_id, worker_repo, module, synthetic_contract_version
- changed_files, public_commit_sha, test_commands, test_results
- acceptance_total, acceptance_passed, acceptance_failed, acceptance_not_tested
- blockers, risks, rollback_note, public_evidence_links, updated_at
- status: Not started / In progress / Blocked / In review / Passed / Accepted

Do not include private repository identifiers, source SHAs, private file paths, or private logs in public task results.

## Safety and integration
- This public repository contains only sanitized coordination material, generic contracts, synthetic fixtures, and non-sensitive status.
- Private application changes are reviewed and integrated only through private feature branches and private pull requests.
- No production data changes, credential rotation, release publication, or private-source access is performed from this public lane.
- Offline data model: each device has its own local database. Device transfer is explicit encrypted backup export/import; no cloud or automatic sync.
