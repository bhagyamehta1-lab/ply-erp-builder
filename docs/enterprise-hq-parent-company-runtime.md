

## Persistent successor-lease recovery proposals (local, review-only)

scripts/enterprise_hq_recovery_ledger.py extends the unified task, budget, lease, and untrusted-receipt ledger with a recovery_proposals table and a separate recovery_audit_events chain.

- requires the exact task proposal and exact expired first-attempt lease envelope to exist in the same local ledger;
- validates the successor with the pure recovery contract, requiring attempt 2, a distinct lease ID, no overlap with the previous lease, an expired prior lease, and side_effects_started=false;
- derives a deterministic recovery ID from the task, prior lease, successor lease ID, and successor-envelope digest;
- persists at most one successor proposal per task and at most 256 recovery proposals;
- treats an identical proposal as idempotent and rejects a different successor for the same task;
- atomically writes the recovery proposal and its own sequenced SHA-256 audit event;
- verifies all inherited task, budget, lease, receipt, and recovery chains before appending and after restart;
- refuses to extend a corrupted recovery chain;
- keeps the row PROPOSED_FOR_HUMAN_REVIEW, with successor_lease_issued=false, automatic_retry=false, and execution_authorized=false.

The persisted successor is a proposal only. It is not inserted into the active lease table, does not claim or renew a lease, and does not resume a task. The local owner-supplied logical identity remains unauthenticated. This is not a distributed lock service or multi-host recovery coordinator.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_recovery_ledger.py'


## Fail-closed principal attestation contract (adapter required)

scripts/enterprise_hq_principal_contract.py defines task-bound worker and reviewer
attestation envelopes. Worker assertions bind to the exact task proposal and lease;
reviewer assertions bind to the exact task proposal and verification receipt.

- validates exact schema, task/proposal binding, role, audience, issuer/key identifiers,
  Ed25519 signature encoding, nonce syntax, timezone-aware validity window, and a
  maximum 15-minute attestation lifetime;
- delegates cryptographic signature and trust-chain checks to an injected verifier
  adapter; the module contains no trust store, key retrieval, network client, or default
  verifier;
- fails closed with IDENTITY_VERIFIER_UNAVAILABLE when no adapter is configured;
- sanitizes adapter exceptions and rejects false or non-boolean adapter results;
- returns only task/role/binding status and always keeps execution_authorized=false.

The test suite uses a synthetic verifier only. It does not establish production
authentication, key custody, nonce replay prevention, identity lifecycle management,
or independent reviewer independence. A trusted adapter and persistent replay store
must be separately reviewed and authorized before operational use.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_principal_contract.py'


## Persistent principal nonce replay protection (local, fail-closed)

scripts/enterprise_hq_principal_replay_ledger.py extends the task, budget, lease,
receipt, recovery, and principal-attestation contracts with a durable one-time nonce
ledger.

- verifies the task-bound principal attestation through the explicitly injected
  verifier adapter before attempting nonce consumption;
- requires the referenced task and worker lease proposal, or reviewer receipt claim,
  to exist in the same local ledger with the exact task proposal digest;
- scopes nonce uniqueness to issuer and principal ID, so a previously accepted nonce
  cannot be reused by that principal across tasks;
- permits only one accepted worker identity per lease proposal and one reviewer
  identity per receipt claim;
- rejects the same issuer/principal ID from occupying both WORKER and REVIEWER roles
  for the same task, with the check serialized in the nonce-consumption transaction;
- verifies the cross-role identity invariant during ledger integrity checks;
- serializes concurrent consumers with the inherited SQLite BEGIN IMMEDIATE
  transaction and unique constraints;
- persists only a SHA-256 nonce fingerprint and attestation digest, never the raw
  nonce, signature, subject, or full attestation payload;
- writes a separate sequenced SHA-256 audit chain and verifies all inherited chains
  before append and after restart;
- caps retained nonce uses at 1,024 and fails closed when capacity is reached;
- never deletes expired records automatically, so replay history is not silently
  discarded;
- keeps execution_authorized=false and never issues a lease or resumes a task.

The cross-role guard prevents direct reuse of the same issuer/principal ID for
worker and reviewer claims on one task. It does not prove human or agent independence:
one person could still use different IDs, aliases, or issuer namespaces. The guard is
a deterministic anti-self-review invariant, not independent-agent authentication.

The replay ledger is local SQLite state, not a distributed replay cache. Its hash
chain detects inconsistent or accidental modification but is not a keyed tamper-proof
seal against an attacker who can rewrite the entire database. The synthetic verifier
used by tests is not a production identity provider. Production key custody, trusted
issuer registration, revocation, cross-host replay coordination, and independently
authenticated reviewer identity remain unimplemented.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_principal_replay_ledger.py'


## Principal trust-policy envelope (structural, not a trust store)

`scripts/enterprise_hq_principal_trust_policy.py` adds a pure, fail-closed matcher
for an explicitly supplied issuer/key policy envelope. It checks exact schema,
issuer and key identifiers, Ed25519 algorithm label, SHA-256 key-fingerprint
format, audience and principal-type allowlists, policy status, revocation state,
timezone-aware validity, and that the complete attestation lifetime fits inside
the policy lifetime.

- unknown fields and missing policy fields are rejected;
- DISABLED and REVOKED policy states fail closed;
- a caller-supplied key fingerprint is only a reference string, not key material
  and is not cryptographically verified by this module;
- the returned status is MATCHED_UNTRUSTED_POLICY_ENVELOPE;
- cryptographic verification remains NOT_PERFORMED, identity_authenticated is
  false, and execution_authorized is false.

This is a structural pre-verification contract only. It is not yet wired into the
principal verifier pipeline, has no authenticated policy source or trust store,
does not load keys, and does not establish issuer ownership, key custody, or
reviewer independence. The test policy is synthetic and must not be used as a
production trust anchor.

Run the focused suite with:

```bash
python -m unittest discover -s tests -p 'test_enterprise_hq_principal_trust_policy.py'
```


## Policy-bound principal verifier adapter (read-only source contract)

scripts/enterprise_hq_principal_policy_source.py composes the structural trust-policy
matcher with two explicitly injected adapters: a read-only policy source and a
cryptographic signature verifier. It implements the PrincipalVerifier interface used
by the task-bound principal attestation contract.

- retrieves a policy snapshot by the exact attestation issuer and key identifier on
  every verification; no policy cache or network client is included;
- requires an exact snapshot schema, a source identifier/version, an adapter-asserted
  authenticated/read-only assurance marker, and a timezone-aware retrieval timestamp;
- rejects snapshots older than five minutes or more than thirty seconds in the future;
- recomputes the canonical policy SHA-256 digest and rejects a mismatched source pin;
- evaluates issuer, key, audience, principal type, status, revocation and validity
  before invoking the cryptographic signature adapter;
- passes the key fingerprint, policy digest, policy ID, source version and source ID
  to the cryptographic adapter so it can verify the actual key against the policy pin;
- sanitizes source, clock and cryptographic adapter exceptions;
- performs no writes, key retrieval, credential handling, network access or task
  execution; execution authorization remains false in the outer principal contract.

The source assurance string is an adapter assertion, not proof of source authenticity.
The injected policy-source implementation must itself be independently authenticated
and read-only. The cryptographic adapter must verify the signature and confirm that
the actual public key matches the policy fingerprint and digest. Neither adapter is
configured in this repository. Tests use synthetic adapters only. The wrapper is a
conformance boundary, not a production trust store or authenticated identity service.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_principal_policy_source.py'


## Persistent principal policy-version history (local, untrusted)

`scripts/enterprise_hq_principal_policy_ledger.py` adds append-only policy history
to the task, lease, receipt, recovery and principal nonce ledgers.

- stores source ID/version/revision, issuer/key ID, policy ID, policy digest,
  key fingerprint, status, revocation timestamp and audit records only;
- stores no key material, signatures, tokens, raw attestations, full policy payloads
  or source credentials;
- rejects source-revision rollback, revision gaps, same-revision digest conflicts,
  reused source versions, key-fingerprint changes under the same key ID, and
  policy-ID changes under the same key ID;
- records DISABLED and REVOKED snapshots before the structural policy matcher runs,
  so a later snapshot cannot silently roll a revoked key back to ACTIVE;
- allows DISABLED-to-ACTIVE only through the next contiguous revision;
- treats REVOKED as terminal for that source/issuer/key ID; key rotation requires a
  new key ID;
- writes a separate sequenced SHA-256 audit chain and verifies inherited chains
  before append and after restart;
- serializes concurrent writers with SQLite `BEGIN IMMEDIATE`;
- caps history at 1,024 snapshots and fails closed at capacity;
- never authenticates a policy source, loads keys, authorizes execution or resumes work.

The source revision is supplied by the injected adapter and is not independently
authenticated by this local ledger. A caller-supplied or compromised source can
still present a malicious higher revision. The local hash chain detects inconsistent
records but is not a keyed tamper-proof seal or a distributed anti-rollback service.
Production source authentication, trusted key custody, revocation distribution
and cross-host history remain outstanding.

Run the focused suites with:

```bash
python -m unittest discover -s tests -p 'test_enterprise_hq_principal_policy_ledger.py'
python -m unittest discover -s tests -p 'test_enterprise_hq_principal_policy_source.py'
```


## Bounded company evidence integrity verifier

`scripts/enterprise_hq_evidence_verifier.py` provides deterministic content-integrity
checks for explicitly supplied, sanitized evidence bundles.

- binds a manifest to an exact task ID, proposal digest and verification receipt ID;
- accepts only approved Enterprise-HQ documentation, scripts, tests and the dedicated
  parent-company observer workflow path;
- rejects traversal, absolute paths, backslashes, duplicate paths, unsorted entries,
  unknown fields and payload-set mismatches;
- caps bundles at 16 entries, 256 KiB per entry and 1 MiB total;
- verifies exact byte lengths and SHA-256 content digests;
- returns only a canonical manifest digest, count, total byte count and binding
  metadata; payload bytes are neither returned nor persisted;
- does not access the filesystem or network and does not inspect evidence semantics;
- explicitly leaves identity authentication and execution authorization false.

The verifier is an integrity primitive, not an independent semantic reviewer. Callers
must never pass private source, customer/vendor material, secrets or raw private
governance payloads into the public worker repository or its Actions workflow.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_evidence_verifier.py'`


## Persistent evidence-integrity outcomes (local, metadata-only)

`scripts/enterprise_hq_evidence_ledger.py` extends the unified task and
verification-receipt ledger with persistent evidence-integrity outcomes.

- re-runs the bounded evidence verifier in memory for every submission;
- requires the exact task proposal and identical untrusted verification receipt
  to exist in the same local ledger;
- requires the receipt's evidence digest to equal the canonical manifest digest;
- stores only task/receipt references, digests, evidence count, byte count, status,
  timestamps and audit metadata; no raw evidence bytes, paths or manifest payloads;
- treats identical outcomes as idempotent and rejects conflicting content;
- writes a separate sequenced SHA-256 evidence audit chain atomically with the
  verification record;
- verifies inherited task, budget, lease, receipt and evidence chains before append
  and after restart;
- caps retained evidence outcomes at 256 and fails closed at capacity;
- keeps semantic verification NOT_PERFORMED, identity authentication false,
  reviewer independence NOT_ESTABLISHED and execution_authorized=false;
- restart recovery verifies metadata only and never resumes or retries work.

This ledger proves that supplied bytes matched a manifest digest at verification
time. It does not persist or independently re-read the bytes later, inspect meaning,
authenticate a reviewer, establish human/agent independence, or authorize execution.
The SHA-256 chain is local integrity evidence, not a keyed tamper-proof seal or a
distributed ledger.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_evidence_ledger.py'`


## Reviewer-attestation-bound evidence verification (local, adapter-accepted claim)

The evidence verification ledger now extends the persistent principal replay ledger
and requires a previously consumed REVIEWER nonce claim bound to the exact task,
proposal digest, and verification receipt before recording evidence integrity.

- evidence verification is rejected unless exactly one persisted reviewer nonce claim
  exists for the same task/proposal/receipt;
- the reviewer principal ID must match the receipt's logical verifier reference;
- the reviewer claim must have passed the injected principal-verifier adapter and
  one-time nonce consumption in the inherited ledger;
- a separate reviewer-binding table and SHA-256 audit chain are written atomically
  with the evidence-verification record and its existing audit event;
- restart verification checks the reviewer binding against the inherited principal
  nonce record and verifies the complete reviewer audit chain;
- missing, conflicting, or tampered reviewer bindings fail closed;
- no raw signature, nonce, subject, attestation, evidence path, manifest, or payload
  bytes are persisted by the evidence-verification subsystem.

The synthetic verifier used by tests is not production authentication. The status
EXTERNAL_ADAPTER_ASSERTED means only that the injected verifier adapter accepted the
attestation. It does not prove the adapter is independently trusted, the reviewer is
a different human/agent, or the evidence is semantically correct. Reviewer
independence remains NOT_ESTABLISHED, identity authentication remains false at the
evidence-result boundary, and execution_authorized remains false.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_evidence_ledger.py'`


## Deterministic metadata-only unified ledger integrity checkpoint

`scripts/enterprise_hq_ledger_integrity_snapshot.py` creates a read-only,
reproducible checkpoint after the unified ledger's `verify()` and
`recover_after_restart()` checks both pass.

- inventories the SQLite audit tables and records only each chain's table name,
  event count, final sequence number, and final SHA-256 record hash;
- includes only bounded count fields and validated chain-status fields from the
  ledger verification summary;
- includes recovery status and explicit false values for execution authorization,
  execution resumption, and automatic retry;
- uses canonical JSON and an unkeyed SHA-256 digest, so unchanged database state
  yields the same checkpoint digest;
- rejects malformed audit-table schemas, missing chain statuses, invalid heads,
  oversized inventories, corrupted ledgers, and recovery results that claim
  execution or retry;
- performs no database writes, filesystem reads, network access, payload export,
  or task dispatch.

The checkpoint is metadata-only and contains no task identifiers, evidence paths,
manifests, signatures, or payload bytes. It is labelled
`LOCAL_SQLITE_UNSEALED`: its unkeyed digest detects accidental checkpoint
alteration but does not authenticate its origin or protect against an attacker
able to rewrite both the database and checkpoint. It is not a backup, distributed
consensus record, tamper-proof seal, semantic review, or execution authorization.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_ledger_integrity_snapshot.py'`


## Metadata-only ledger backup/restore equivalence verification

scripts/enterprise_hq_ledger_restore_verifier.py compares two independently
validated unified-ledger integrity snapshots. It does not create, copy, restore,
or persist database backups.

- validates both source and restored snapshots with the strict checkpoint verifier;
- requires the same ledger type and audit-chain inventory count;
- requires identical canonical SHA-256 snapshot digests, covering verification
  summaries, recovery summaries, audit-chain names, event counts, sequence numbers,
  and chain-head hashes;
- returns only the two checkpoint digests, audit-chain count, and explicit false
  values for execution authorization, resumption, and automatic retry;
- rejects invalid, tampered, differently typed, or non-equivalent snapshots;
- performs no database writes, filesystem reads, network access, payload export,
  task dispatch, or automatic recovery.

The focused tests use SQLite's local backup API to create a synthetic backup,
open the restored database, and compare independently generated checkpoints.
This verifies metadata equivalence for the test fixture; it is not a production
backup service, off-host backup, disaster-recovery guarantee, or proof that external
evidence payloads were restored. Checkpoints remain LOCAL_SQLITE_UNSEALED and use
an unkeyed digest; they do not authenticate the source or protect against an actor
able to rewrite both database and checkpoint.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_ledger_restore_verifier.py'


## Bounded metadata-only backup inventory and retention evaluation

`scripts/enterprise_hq_backup_inventory.py` adds a local append-only inventory for
backup metadata. A record is accepted only after the supplied source and restored
integrity snapshots independently pass the restore-equivalence verifier.

- binds an opaque backup identifier to ledger type, source/restored snapshot digests,
  audit-chain count, declared size, creation time, retention deadline, generation,
  predecessor, and LOCAL_ONLY storage scope;
- enforces contiguous per-ledger backup generations and exact predecessor linkage;
- records a separate sequenced SHA-256 audit chain atomically with each inventory
  entry and verifies the full lineage after restart;
- caps the inventory at 256 records, declared size at 256 MiB, and the technical
  retention window at 90 days; these are engineering bounds, not an adopted
  enterprise records-retention schedule;
- evaluates retained versus expired metadata without deleting records or artifacts;
- stores no filesystem path, URL, backup bytes, private payload, or artifact digest.

Artifact existence and bytes are NOT_INSPECTED; declared size is caller-supplied and
not independently measured by this inventory. The ledger records restore-equivalence
metadata only and is not a backup creator, backup store, off-host copy, or disaster
recovery service. Automatic purge, execution, and task resumption remain false.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_inventory.py'`

## Persistent backup-retention evaluation history (local, metadata-only)

`LedgerBackupInventory.evaluate_retention()` now records a bounded history of
non-destructive retention evaluations.

- computes a canonical digest of the current backup-inventory metadata (opaque backup
  IDs, ledger types, generations, retention deadlines, and entry digests only);
- derives an opaque evaluation ID from the canonical evaluation digest;
- persists evaluated time, inventory/retained/expired counts, and the inventory digest;
- treats an identical evaluation of the same inventory at the same timestamp as
  idempotent; a changed inventory or timestamp creates a distinct evaluation;
- appends a separate sequenced SHA-256 retention-audit event atomically with the
  evaluation record;
- verifies evaluation digests, audit sequence, predecessor hashes, and event counts
  during every inherited ledger verification and restart recovery;
- caps retained evaluation records at 1,024 and fails closed at capacity;
- never deletes inventory records or backup artifacts, never inspects artifact bytes,
  and never authorizes execution.

The history is local SQLite metadata with an unkeyed hash chain. It detects inconsistent
records but is not a keyed tamper-proof seal, distributed retention service, or proof
that any backup artifact exists. Retention deadlines remain technical metadata; this
module does not establish a corporate records-retention policy.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_inventory.py'`


## Cross-ledger backup-set reconciliation

The parent-company lane now includes `CrossLedgerBackupSetInventory`, a metadata-only
reconciliation layer over the existing local backup inventory.

A backup set groups one registered backup generation from each of at least two
distinct ledger types. It accepts no artifact paths or bytes. Before recording a
set, it verifies the inherited inventory and requires every requested member to
exist, remain within its declared retention window, and fall within a bounded
creation-time skew (default 120 seconds; hard maximum 300 seconds).

Cross-ledger generations are append-only. Generation 1 has no predecessor.
Each later generation must reference the previously reconciled set for the exact
same sorted ledger-type collection. A missing member, missing predecessor set,
excessive time skew, expired member, duplicate type, or conflicting generation
fails closed.

The set record stores only opaque IDs, ledger-type names, counts, timestamps,
and SHA-256 digests. A separate `ledger_backup_set_audit_events` chain records
each reconciliation. The inventory's `verify()` and restart-recovery paths
validate set membership, per-type generation alignment, predecessor lineage,
set digests, and the new audit chain.

This is a consistency check over declared local metadata, not proof that backup
artifacts exist, that their bytes were copied, or that separate ledgers represent
the same transactionally frozen point in time. The snapshots remain
`LOCAL_SQLITE_UNSEALED`; hashes are unkeyed and do not authenticate their origin.
No artifact is created, read, uploaded, or deleted. No task is resumed or
authorized by this component.


## Cross-ledger backup-set restoration equivalence

`scripts/enterprise_hq_backup_set_restore_verifier.py` adds a specialized,
metadata-only restoration check for non-empty cross-ledger backup-set history.

- independently validates source and restored integrity snapshots;
- requires the `CrossLedgerBackupSetInventory` ledger type;
- requires a non-empty backup-set count within the 128-record engineering bound;
- requires the dedicated `ledger_backup_set_audit_events` chain to be present,
  valid, and to have an event count and final sequence matching the backup-set count;
- compares source and restored backup-set counts and audit-chain heads;
- delegates complete ledger checkpoint equivalence to the general restore verifier;
- returns only counts and digests, with execution authorization, resumption, and
  automatic retry explicitly false.

This verifies that the declared local backup-set metadata and its audit-chain head
survive a synthetic database restoration unchanged. It does not create or inspect
backup artifacts, verify artifact bytes, prove off-host durability, or authenticate
the unkeyed LOCAL_SQLITE_UNSEALED checkpoints. It is not a production disaster-
recovery service.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_set_restore_verifier.py'`

## Persistent cross-ledger backup-set restoration receipts

`scripts/enterprise_hq_backup_set_restore_ledger.py` adds a bounded, append-only
receipt ledger for completed cross-ledger backup-set restoration-equivalence
checks.

- runs the specialized source/restored snapshot verifier inside a serialized
  SQLite write transaction before accepting a receipt;
- records only source/restored snapshot digests, backup-set and audit-event
  counts, audit-chain head digests, and a UTC verification timestamp;
- derives an opaque deterministic receipt ID and canonical receipt digest;
- treats an identical snapshot pair at the same timestamp as idempotent and
  rejects conflicting receipt content;
- appends a separate sequenced SHA-256 audit event atomically with the receipt;
- verifies receipt schemas, digest derivation, audit sequence, predecessor
  hashes, event counts, and restart integrity as part of the inherited ledger
  verification path;
- caps retained receipts at 256 and fails closed at capacity;
- never stores backup-set IDs, member IDs, artifact paths, artifact bytes,
  private payloads, or credentials;
- never creates, copies, uploads, reads, or deletes backup artifacts and never
  authorizes execution, resumes a task, or retries automatically.

The receipt proves only that the deterministic local verifier accepted the
provided, integrity-valid snapshots at the recorded time. The snapshots remain
unkeyed local SQLite metadata; this is not a signed attestation, off-host backup
service, proof of artifact existence, or production disaster-recovery
certification.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_set_restore_ledger.py'`

The specialized backup-set restore verifier also accepts the persistent
`BackupSetRestoreReceiptLedger` subclass, whose integrity snapshots include
the same cross-ledger backup-set audit chain plus its append-only restoration
receipt history. Complete snapshot equivalence still applies to every chain.


## Persistent cross-ledger backup-set retention history

`scripts/enterprise_hq_backup_set_retention_ledger.py` adds append-only, aggregate-only
retention evaluations over the existing cross-ledger backup-set inventory.

- evaluates every reconciled backup set against the declared retention deadline of
  each member; a set is classified as expired if any member has expired;
- distinguishes retained, expired, and partially expired sets, plus aggregate
  retained/expired member counts;
- hashes only set digests, generation metadata, ledger-type digests, member counts,
  and earliest/latest retention deadlines; it stores no backup-set IDs, member IDs,
  filesystem paths, artifact bytes, or private payloads;
- derives deterministic evaluation IDs and canonical SHA-256 evaluation digests;
- treats an identical evaluation at the same timestamp as idempotent and rejects
  clock rollback relative to the latest persisted evaluation;
- appends a separate sequential SHA-256 audit chain atomically with each evaluation;
- verifies evaluation schemas, aggregate count invariants, digest derivation,
  audit sequence, predecessor hashes, event counts, and restart integrity;
- caps history at 512 evaluations and fails closed at capacity;
- never deletes inventory records or backup artifacts; automatic purge, artifact-byte
  verification, execution authorization, resumption, and automatic retry remain false.

An expired set means at least one declared member retention deadline has elapsed.
This does not prove whether any artifact exists or whether its bytes remain available.
The retention evaluation is local SQLite metadata with an unkeyed hash chain; it is
not a signed retention attestation, a corporate records-retention policy, an artifact
store, or a production disaster-recovery service.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_set_retention_ledger.py'`


## Cross-ledger backup-set retention restoration verification (metadata-only)

`scripts/enterprise_hq_backup_set_retention_restore_verifier.py` verifies that
persistent retention-evaluation history survives a local SQLite restoration.

- accepts only `BackupSetRetentionLedger` integrity snapshots;
- independently validates both bounded integrity checkpoints before comparing them;
- requires the retention evaluation count and dedicated retention chain status;
- requires exactly one `ledger_backup_set_retention_audit_events` inventory entry;
- checks evaluation count, event count, final sequence, and audit-head shape;
- permits an empty retention history only when the dedicated audit chain is also
  empty (zero events, null sequence, null head);
- compares source and restored retention counts and audit-head hashes;
- delegates complete cross-ledger backup-set lineage equivalence to the existing
  specialized restore verifier;
- returns digests, counts, and audit-head hashes only;
- keeps execution authorization, execution resumption, automatic retry, automatic
  purge, and artifact-byte verification false.

This is a metadata comparison over locally generated, unkeyed SQLite integrity
snapshots. It does not inspect backup artifacts, authenticate the snapshot source,
prove off-host durability, or provide a production disaster-recovery service.
An attacker able to rewrite the complete local database and both snapshots is
outside this verifier's assurance boundary.

Run the focused suite with:

```bash
python -m unittest discover -s tests -p 'test_enterprise_hq_backup_set_retention_restore_verifier.py'
```


## Static safety contract for the company observer

`scripts/enterprise_hq_company_observer_policy.py` validates the checked-in
company observer workflow and observer source without executing either.

The contract requires:
- one dedicated company-branch push target, a no-input manual observation, and
  the existing periodic schedule;
- one bounded Ubuntu job with a five-minute timeout;
- repository permission limited to `contents: read`;
- an allowlist of the three existing GitHub Actions used by the observer;
- checkout with persistent credentials disabled;
- exactly one step-scoped `ENTERPRISE_HQ_READ_TOKEN` reference;
- only Enterprise-HQ test modules before the aggregate observer;
- one aggregate-only report written under the runner temporary directory and
  uploaded with one-day retention;
- an AST-checked private-file allowlist containing only
  `state/company_completion_register.json`;
- a bounded private response, guarded network access, and fixed aggregate-only
  report fields that explicitly exclude Project 001 and do not claim 24/7 uptime.

The focused contract suite uses mutation tests to reject broader triggers,
permissions, actions, secret scope, private paths, imports, network calls, file
operations, and output claims.

This is a static regression guard for the checked-in source. It does not prove
GitHub-hosted runner isolation, actual secret permissions, GitHub App token scope,
third-party action supply-chain integrity, or protection against changes outside
the checked files.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_company_observer_policy.py'`


## Sanitized observer artifact validation

`scripts/enterprise_hq_company_observer_artifact.py` validates the observer's
aggregate JSON report before GitHub Actions uploads it.

- accepts only the fixed parent-company summary schema and exact Project 001
  exclusion marker;
- requires the three company-register checks to be `PASS`;
- requires exactly 11 workstreams and validates status vocabulary, positive
  per-status counts, and the aggregate sum;
- requires the fixed non-execution, unauthenticated-agent, and
  `NOT_PROVEN` uptime capability declarations;
- requires the fixed privacy declarations and rejects additional fields;
- rejects duplicate JSON keys, non-standard JSON constants, malformed JSON,
  and reports larger than 16 KiB;
- reads only the expected regular report file directly inside `RUNNER_TEMP`,
  rejects symlinks and paths outside that directory, and performs no network
  access or file writes;
- prints only a canonical SHA-256 digest, aggregate counts, and fixed
  non-authorization flags;
- gates artifact upload on successful validation rather than uploading after
  a failed observer or validator step.

The digest is an unkeyed integrity identifier for the canonical report, not a
signature or proof of origin. The validator checks the report schema and
aggregate invariants; it does not independently re-fetch private governance
data or authenticate GitHub runner isolation.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_company_observer_artifact.py'`


## Public workflow separation inventory

scripts/enterprise_hq_public_workflow_boundary.py performs a read-only inventory of
direct YAML workflow files in the public repository workflow directory.

- requires exactly one company observer workflow and validates it with the existing
  observer policy contract;
- classifies other public workflow definitions using bounded static indicators for
  private-source access, private-governance references, product execution/dispatch,
  privileged capabilities, and overlap with the company observer boundary;
- emits aggregate counts and signal counts only; workflow names and source text are
  never included in its report;
- marks repository-wide status as REVIEW_REQUIRED when any legacy restricted
  workflow is present, while separately reporting whether the dedicated company
  observer remains isolated;
- rejects symlinks, non-regular files, invalid UTF-8, oversized files, more than 64
  workflow definitions, and missing or invalid observer policy;
- performs no network access, private metadata fetch, workflow execution, or writes.

This is a conservative static inventory, not a YAML execution engine or a complete
security proof. Text indicators can produce false positives or miss indirect
capabilities. REVIEW_REQUIRED is intentionally non-blocking for the company-only
test suite: it records existing repository-wide risks without changing or triggering
those workflows. No legacy workflow is modified by this audit.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_public_workflow_boundary.py'


## Expanded public workflow risk signals (static, aggregate-only)

The public workflow boundary inventory additionally counts these review indicators
without emitting workflow names or source text:

- untrusted event contexts (pull_request, pull_request_target, issue_comment,
  and workflow_run);
- manual or external dispatch triggers (workflow_dispatch and
  repository_dispatch);
- action references that use mutable tags rather than a 40-character commit SHA;
- workflow- or job-level secret environments (step-scoped secret environments are
  distinguished and are not classified as broad scope);
- unconditional artifact uploads using if: always();
- network and dependency-install commands such as curl, wget, pip install,
  and npm install.

These are conservative text/indentation heuristics, not a complete YAML parser or
proof of exploitability. A positive count means human review is required; it does
not prove that a workflow ran or that a vulnerability was exploited. The inventory
never executes workflow commands, modifies workflow definitions, accesses private
source, or authorizes task execution.

## Deterministic observer freshness decision contract

`scripts/enterprise_hq_observer_freshness.py` evaluates a supplied pair of
timezone-aware timestamps against a bounded periodic-observation interval. It
does not query GitHub, poll workflow runs, create schedules, or dispatch work.

- classifies the observation as `NEVER_OBSERVED`, `CLOCK_SKEW`, `FRESH`,
  `GRACE_PERIOD`, or `MISSED`;
- uses a default 30-minute interval and 15-minute grace period, matching the
  observer's periodic cadence without claiming continuous availability;
- rejects naive, malformed, oversized, or out-of-range inputs and clamps only
  future skew of at most 60 seconds to zero age;
- returns aggregate decision metadata without echoing timestamps, repository
  identifiers, workflow names, or run payloads;
- seals the decision fields with a canonical unkeyed SHA-256 digest and provides
  a separate verifier for schema, age/status consistency, non-authorization
  flags, and digest integrity;
- keeps execution authorization, automatic dispatch, and automatic retry false.

This is a deterministic decision contract over caller-supplied sanitized
timestamps, not a live missed-run monitor. No Actions API permission was added
to collect run history. The digest detects accidental alteration but is not a
signature, authenticated receipt, durable audit record, or proof of run origin.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness.py'`


## Persistent observer freshness receipt ledger

`scripts/enterprise_hq_observer_freshness_ledger.py` provides a bounded local
SQLite history for already-sanitized observer freshness decision receipts.

- accepts only receipts that pass the independent freshness receipt verifier;
- requires a caller-supplied 64-character lowercase hexadecimal idempotency key,
  stores only its SHA-256-derived opaque receipt identifier, and treats exact
  replays as idempotent while rejecting key reuse with different content;
- records a timezone-aware caller-supplied recording time, normalized to UTC;
- verifies the existing chain before every append, then chains records with
  canonical SHA-256 hashes and verifies sequence continuity, monotonic recording
  time, receipt digests, and every previous-hash link;
- enforces append-only SQLite triggers, owner-only database file permissions,
  a 512-receipt limit, and a 1 MiB database page bound;
- refuses new records at capacity and never automatically prunes or deletes
  prior receipts;
- returns aggregate status counts and a chain-head digest without timestamps,
  repository names, workflow names, run identifiers, or idempotency keys;
- keeps execution authorization, automatic dispatch, and automatic retry false.

The ledger is a local persistence component, not a remote or cross-run storage
service. GitHub-hosted runner filesystems are ephemeral; the company observer
workflow runs this ledger's tests only and does not create, upload, or retain a
database. A future runtime must explicitly provide an approved durable local
volume before using the ledger operationally. The SHA-256 chain detects
accidental or unsophisticated tampering but is not keyed authentication,
non-repudiation, or proof of origin.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_ledger.py'`


## Verified observer freshness ledger backup and restoration

`scripts/enterprise_hq_observer_freshness_backup.py` adds a local-only SQLite
backup and restore path for the sanitized freshness receipt ledger.

- verifies the source ledger and its SQLite integrity before copying;
- writes to an owner-only sibling temporary file and keeps the final
  destination absent until schema, integrity, and ledger-equivalence checks pass;
- publishes the verified file with an atomic no-overwrite hard link, so a racing
  destination is never replaced;
- removes interrupted temporary files without deleting a pre-existing destination;
- uses SQLite's online backup API rather than copying a live database file;
- validates the exact table, column, trigger, schema-version, permission, page,
  and receipt-count bounds of an existing backup;
- independently verifies the copied hash chain and compares aggregate source and
  backup summaries before reporting equivalence;
- restores only to a new destination and verifies the restored chain against the
  verified backup before returning success;
- returns only a file digest, receipt counts, status counts, chain-head digest,
  and fixed non-authorization flags; filesystem paths and receipt payloads are
  never emitted;
- removes only a partial destination created by the current failed operation;
- keeps execution authorization, automatic dispatch, and automatic retry false.

Crash-interruption and destination-race tests verify that partial temporary files are
removed and competing destination files are never overwritten. This is a local
filesystem recovery primitive exercised with temporary test databases. It is not connected to GitHub Actions runtime storage, an off-host
backup service, or a durable company-wide volume. The file SHA-256 digest and
ledger hash chain are unkeyed integrity checks, not authenticated signatures.
No private governance data is read and no task is resumed or authorized.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_backup.py'`

## Persistent observer freshness backup lineage receipts

`scripts/enterprise_hq_observer_freshness_backup_receipts.py` records a
bounded local lineage for backups that have already passed the independent
SQLite/schema/hash-chain equivalence checks.

- accepts only the exact aggregate result from a verified freshness backup;
- derives an opaque backup identifier from the backup file SHA-256 digest;
- records the source receipt count, status counts, sequence, chain-head digest,
  recording time, and predecessor backup identifier;
- treats an exact backup-file replay as idempotent and rejects digest reuse with
  conflicting metadata;
- verifies the full predecessor chain, monotonic recording time, canonical
  status counts, record digests, schema, and append-only triggers before every
  append;
- validates the existing schema on reopen rather than silently recreating a
  missing trigger or unexpected table;
- enforces owner-only database permissions, a 256-backup limit, and a 1 MiB
  SQLite page bound;
- exposes a read-only restart-recovery check that verifies history and never
  authorizes execution, dispatch, or automatic retry;
- emits only aggregate backup metadata and digests; no filesystem paths or
  source receipt payloads are stored.

The receipt ledger records that a local backup verification completed; it does
not prove that the backup file remains present or provide off-host durability.
The database is exercised only with temporary test files. GitHub-hosted runner
storage remains ephemeral, and no shared durable volume is configured.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_backup_receipts.py'`


## Read-only observer freshness backup availability verification

`scripts/enterprise_hq_observer_freshness_backup_availability.py` verifies
whether a backup recorded in the freshness-backup lineage ledger is still
available as a valid local file.

- verifies the complete append-only backup-lineage ledger before inspecting a
  caller-supplied path;
- distinguishes missing, inaccessible, invalid, mismatched, and available
  backup files without returning the path;
- checks regular-file type, symlink boundaries, owner-only permissions, and
  the one-MiB database bound;
- verifies SQLite integrity, the exact freshness-ledger schema, append-only
  triggers, every receipt, and the internal receipt hash chain through a
  read-only SQLite connection;
- compares the file digest and aggregate source-ledger summary with the
  previously recorded backup-lineage receipt;
- checks file identity, size, and modification time before and after
  verification to detect replacement during the read;
- emits only opaque backup identity, aggregate counts, and digests;
- never changes file permissions, creates or restores files, writes ledger
  records, deletes artifacts, retries work, or authorizes execution.

This is a local read-only availability check. It does not prove off-host
durability, authenticate the original backup producer, or provide a production
disaster-recovery service. The lineage digest is unkeyed integrity metadata.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_backup_availability.py'`


## Persistent observer freshness backup availability history

`scripts/enterprise_hq_observer_freshness_backup_availability_ledger.py`
records bounded history for read-only availability checks.

- accepts only the exact aggregate result from the availability verifier;
- distinguishes AVAILABLE, MISSING, UNAVAILABLE, INVALID, MISMATCH, and
  UNKNOWN observations;
- records only opaque backup identity, lineage sequence and digest, status,
  and UTC observation time; filesystem paths and raw backup payloads are
  rejected;
- derives an idempotent observation identifier from canonical metadata and
  recording time;
- preserves availability transitions as separate append-only records;
- verifies sequence continuity, monotonic timestamps, observation identity,
  record hashes, schema, and append-only triggers before every append;
- provides read-only latest-observation lookup and restart recovery;
- enforces owner-only database permissions, a 512-observation limit, and a
  one-MiB SQLite database bound;
- keeps execution authorization, automatic dispatch, and automatic retry
  false.

This is a local audit-history primitive. It does not schedule file scans,
persist filesystem paths, provide off-host durability, or authorize restoration.
The ledger is exercised only with temporary test databases; GitHub-hosted
runner storage remains ephemeral and no shared durable volume is configured.
The hash chain is unkeyed integrity metadata, not authenticated provenance.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_observer_freshness_backup_availability_ledger.py'`

## Read-only backup receipt and availability reconciliation

`scripts/enterprise_hq_backup_availability_reconciliation.py` compares the verified
freshness-backup receipt ledger with the latest persistent availability observation
for every backup.

- exposes bounded, stable enumeration methods on both source ledgers; each method
  verifies its complete append-only history before returning metadata-only rows;
- compares backup sequence and receipt hash for every non-UNKNOWN observation;
- for AVAILABLE observations, also compares file SHA-256, source receipt count,
  canonical status counts, last source sequence, and source chain-head digest;
- distinguishes missing observations, orphan observations, UNKNOWN observations,
  lineage mismatches, and evidence mismatches;
- uses the latest observation per backup for current availability while retaining
  the complete history count;
- re-verifies both source ledgers after enumeration and rejects a report if either
  append-only chain changes during reconciliation;
- returns aggregate counts only, with no backup identifiers, file digests, paths,
  timestamps, or raw payloads;
- performs no filesystem access, writes, restoration, retries, or task dispatch.

A RECONCILED result means the two ledgers agree; it does not mean every artifact is
available. Artifact availability is reported separately as ALL_AVAILABLE,
PARTIAL_OR_UNAVAILABLE, or NO_BACKUPS. UNKNOWN observations remain incomplete until
a later verified observation replaces them. The explicit association gap is addressed by
`scripts/enterprise_hq_backup_artifact_binding.py`. Its
`verify_backup_artifact_binding()` function requires the caller to supply the
exact inventory backup ID and entry digest together with the observer backup ID
and expected file SHA-256. It then independently verifies the inventory,
freshness-backup receipt ledger, and availability ledger.

- requires a restore-equivalent, LOCAL_ONLY inventory record whose entry digest
  matches the caller's explicit association;
- requires the observer receipt's file digest to match the caller's expected
  digest;
- requires the latest observation to be AVAILABLE and to match the receipt's
  lineage sequence, record hash, file digest, source counts, and source chain head;
- re-verifies all three source ledgers after reading and fails closed if any
  ledger snapshot changes;
- returns a deterministic binding digest and bounded status metadata only;
- performs no filesystem access, artifact reads, writes, restoration, retries,
  or task dispatch.

This is an explicit metadata association, not proof that the inventory artifact
and observer backup are the same bytes. The inventory continues to report
`artifact_presence=NOT_INSPECTED`; `artifact_bytes_verified=false` is
preserved. The binding digest is unkeyed integrity metadata, not authenticated
provenance. No paths or artifact payloads are stored or returned.

Run the focused suites with:

```bash
python -m unittest discover -s tests -p 'test_enterprise_hq_backup_availability_reconciliation.py'
python -m unittest discover -s tests -p 'test_enterprise_hq_backup_artifact_binding.py'
```



## Persistent backup-artifact binding receipt ledger

`scripts/enterprise_hq_backup_artifact_binding_ledger.py` stores a bounded,
append-only receipt for a successful explicit metadata association.

- accepts only the exact successful result from
  `verify_backup_artifact_binding()`;
- stores an opaque receipt ID, binding digest, domain-separated SHA-256
  commitments for the inventory and observer identities, bounded
  generation/sequence counts, status classifications, UTC recording time,
  predecessor hash, and receipt hash;
- deliberately omits inventory IDs, observer backup IDs, file digests,
  filesystem paths, source timestamps, and raw payloads;
- is idempotent by binding digest and rejects conflicting metadata for a
  previously recorded digest;
- independently verifies canonical metadata, deterministic receipt IDs,
  monotonic timestamps, sequence continuity, schema constraints, SQLite
  integrity, append-only triggers, and the SHA-256 receipt chain;
- rejects a previously recorded inventory identity paired with a different
  observer identity, and rejects an observer identity paired with a different
  inventory identity; repeated verification of the same pair remains allowed;
- supports aggregate-only lookup, bounded enumeration, and read-only restart
  recovery;
- rejects symlinked or permissively readable database files and enforces
  owner-only permissions, a 512-receipt bound, and a one-MiB database limit;
- keeps artifact-byte verification, execution authorization, automatic
  dispatch, and automatic retry false.

The ledger persists only metadata association evidence. Schema 1.1.0 adds
domain-separated identity commitments and a conflict-rejection trigger; older
schema 1.0.0 databases are rejected rather than silently migrated. The current
test/runtime lane uses temporary databases only, so no deployed database is
migrated. The commitments are unkeyed hashes of high-entropy opaque identifiers,
not authenticated provenance. The ledger does not establish byte equivalence
between the inventory artifact and observer backup, does not read or copy
artifacts, and does not provide off-host durability.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_artifact_binding_ledger.py'`

## Verified backup-artifact binding receipt orchestration

`scripts/enterprise_hq_backup_artifact_binding_service.py` provides a
bounded caller interface that connects the explicit three-ledger binding
verifier to the persistent binding receipt ledger.

- verifies the existing binding receipt history before starting;
- calls `verify_backup_artifact_binding()` with the caller's explicit inventory,
  freshness-receipt, availability-ledger objects, and exact association;
- appends only the exact successful aggregate result accepted by the receipt
  ledger; failed source verification never creates a receipt;
- independently verifies the complete receipt history after append and reads
  the receipt back by its binding digest;
- checks the receipt identifier, sequence, digest, record hash, and chain-head
  relationship against the append response;
- treats an exact replay as idempotent and reports RECORDED versus REPLAYED;
- returns only aggregate receipt sequence/count and fixed verification flags;
- keeps artifact-byte verification, execution authorization, automatic
  dispatch, and automatic retry false.

The receipt is historical evidence of the source snapshot that passed the
three-ledger verifier. Later source-ledger changes do not rewrite that
historical receipt. The service does not create source backups, inspect
inventory artifact bytes, restore files, or contact external systems. The
receipt database remains caller-supplied local storage; GitHub-hosted runner
storage is ephemeral and is used only for temporary test fixtures.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_artifact_binding_service.py'`



## Independent backup-artifact binding receipt snapshot verification

The persistent binding receipt ledger now exports a bounded verification snapshot
containing only its canonical aggregate receipt fields, previous-hash links, and
record hashes. The export is read from one SQLite read transaction and excludes
source backup identifiers, file digests, filesystem paths, and artifact bytes.

The separate `enterprise_hq_backup_artifact_binding_snapshot.py` verifier does
not import the ledger implementation. It independently validates the snapshot
schema, schema version, receipt count, deterministic receipt identifiers,
unique binding digests, sequential numbering, canonical UTC timestamps,
monotonic time, authorization invariants, previous-hash continuity, and every
record SHA-256 digest.

The binding service now requires agreement between the ledger's own full-history
verification and this independent snapshot verifier before returning success.
A mismatch or verifier error fails closed. The returned result contains only
aggregate counts and boolean verification status.

This remains a local integrity check, not authenticated provenance or off-host
durability. The snapshot does not prove artifact-byte equivalence; inventory
artifact presence remains `NOT_INSPECTED` and `artifact_bytes_verified`
remains false. The verifier does not authorize execution, dispatch, retry,
restoration, or external actions.


## Cross-ledger backup-generation continuity

`scripts/enterprise_hq_backup_generation_continuity.py` correlates three
already-verified local sources: the metadata-only backup inventory, observer
freshness-backup lineage receipts, and persistent backup-artifact binding
receipts.

- `LedgerBackupInventory.list_backup_metadata()` exports a stable, bounded
  metadata-only inventory snapshot with entry digests, generation numbers, and
  predecessor references; it emits no filesystem paths or artifact payloads;
- the continuity verifier independently recomputes each inventory entry digest
  and checks per-ledger generation continuity from generation 1 through the
  latest record, including exact predecessor references;
- observer backup receipts are checked for sequential backup numbers,
  file-digest-derived opaque IDs, source-summary consistency, and exact
  predecessor links;
- binding receipts are independently hash-verified by the separate binding
  snapshot verifier, then matched to inventory and observer records using their
  domain-separated identity commitments;
- each binding's recorded inventory generation and observer backup sequence
  must match the current source records; references to missing or conflicting
  records fail closed;
- unbound inventory or observer records are reported as NONE/PARTIAL coverage
  rather than silently described as fully associated;
- source-ledger summaries are compared before and after enumeration so a
  concurrent append or changed chain head rejects the mixed snapshot;
- the returned result contains aggregate counts and fixed non-authorization
  flags only; source identifiers, entry digests, file digests, paths, and
  receipt payloads are not returned.

This is a deterministic metadata-lineage check over local ledger snapshots.
It does not inspect backup files, prove byte equivalence, authenticate the
producer, or provide off-host durability. The observer workflow runs only the
synthetic regression suite; it does not create or retain these ledgers on the
GitHub-hosted runner. No task is resumed, dispatched, restored, or authorized.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_generation_continuity.py'`



## Backup predecessor availability verification

\`scripts/enterprise_hq_backup_predecessor_availability.py\` verifies the latest
availability evidence for every observer backup and, critically, every
predecessor referenced by a later backup. It consumes only the bounded receipt
list and the availability ledger's latest-observation snapshot.

- observer receipt sequence, opaque backup identity, predecessor links, source
  summary bounds, and non-authorization flags are checked before correlation;
- each latest availability observation must have the exact bounded schema,
  expected status, unique backup identity and observation sequence, and
  non-authorization flags;
- non-UNKNOWN observations must match the observer receipt's sequence and
  record hash; AVAILABLE observations must also match the file digest and
  source-chain summary;
- a predecessor without an observation, with UNKNOWN/MISSING/UNAVAILABLE
  status, or with mismatched lineage/evidence blocks recovery-chain readiness;
- the result reports aggregate current-availability and predecessor counts,
  with no backup IDs, file digests, paths, or raw evidence;
- the verifier never reads backup bytes and keeps artifact-byte verification,
  execution, dispatch, and automatic retry false.

\`reconcile_backup_generation_continuity()\` accepts an optional fourth
availability-ledger argument. When supplied, it verifies the ledger before and
after reading latest observations and includes predecessor availability in the
continuity result. Without that ledger, predecessor availability is explicitly
reported as \`NOT_CHECKED\`; the function never implies a complete recovery chain.

The latest-observation snapshot is correlated with receipt metadata after the
availability ledger's own full-history hash-chain verifier runs. This does not
replace that ledger verifier or prove physical artifact bytes. It is a local,
read-only metadata check, not a production restore or off-host durability claim.

Run the focused suite with:

\`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_predecessor_availability.py'\`


## Aggregate backup recovery readiness

\`scripts/enterprise_hq_backup_recovery_readiness.py\` provides a bounded caller
adapter and aggregate-only readiness report over the four existing local ledgers:
backup inventory, observer backup receipts, binding receipts, and availability
history.

- the adapter always supplies all four ledgers to
  \`reconcile_backup_generation_continuity()\`; an omitted availability ledger is
  rejected rather than silently treating predecessor checks as complete;
- the underlying continuity reconciler verifies each source ledger before and
  after metadata enumeration and rejects a changed snapshot;
- the readiness summarizer requires exactly four successful source-ledger
  verifications, complete inventory/observer association coverage, matching
  receipt and observation totals, zero orphan/missing/unknown/mismatched
  availability evidence, and a COMPLETE recovery-chain result;
- predecessor availability must be VERIFIED when predecessor links exist;
  a single genesis backup may report NOT_APPLICABLE because it has no predecessor;
- empty histories, partial associations, unavailable backups, and incomplete
  predecessor evidence return NOT_READY with stable blocker codes;
- unexpected fields, inconsistent counters, unverified source integrity,
  unstable snapshots, or any execution/dispatch/retry authorization claim fail
  closed;
- output contains aggregate counts and fixed status codes only; no backup IDs,
  file digests, filesystem paths, source timestamps, or receipt payloads are
  returned.

A READY result is strictly METADATA_ONLY. It confirms that the four local
metadata ledgers agree and that their recorded availability observations report
the complete chain as available. It does not read original backup bytes, prove
byte equivalence, authenticate a producer, demonstrate an actual restore, or
provide off-host durability. Artifact-byte verification and all execution,
dispatch, and automatic-retry flags remain false. The current test workflow
uses synthetic fixtures and temporary local databases; no live company backup
database or durable shared storage is connected.

Run the focused suite with:

\`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness.py'\`


## Persistent aggregate recovery-readiness history

`scripts/enterprise_hq_backup_recovery_readiness_ledger.py` records bounded
METADATA_ONLY readiness reports in a local append-only SQLite history. The
ledger accepts an exact allowlist of aggregate counts, fixed status values,
ordered blocker codes, and false authorization flags. It rejects backup IDs,
file digests, paths, raw receipts, unexpected fields, unstable source snapshots,
and reports that claim artifact-byte verification or execution authority.

- reports are canonicalized and assigned deterministic digests and evaluation IDs;
- an exact timestamp/report replay is idempotent, while a later evaluation is
  a new history entry;
- every entry is linked to its predecessor by a SHA-256 record chain;
- immutable-record triggers reject ordinary UPDATE and DELETE operations;
- a separately persisted sequence and chain-head checkpoint detects history
  tail truncation when the record table is shortened independently;
- the history is bounded at 512 evaluations and rejects clock rollback;
- `recover_after_restart()` reopens no external service and verifies the
  persisted chain before returning aggregate recovery status;
- the snapshot export contains only the bounded readiness report and integrity
  metadata; no backup identifiers, file digests, filesystem paths, or source
  receipt payloads are stored.

`scripts/enterprise_hq_backup_recovery_readiness_snapshot.py` independently
recomputes each report digest, deterministic evaluation ID, canonical UTC
timestamp, record hash, sequence, and predecessor link. The verifier does not
import the SQLite ledger implementation and returns aggregate counts only.

This is local integrity and restart verification, not authenticated provenance,
tamper-proof external anchoring, physical backup validation, or off-host
durability. The persisted sequence/head checkpoint detects accidental or
partial tail truncation when the checkpoint remains intact; an attacker able to
rewrite both the database history and its checkpoint is outside this local
hash-chain trust model. No live company backup database is connected, and the
observer workflow uses temporary synthetic databases only.

Run the focused suites with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_ledger.py'`

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_snapshot.py'`

## Persistent recovery-readiness evaluation service

The service adapter `evaluate_and_record_backup_recovery_readiness()` connects the
four-ledger metadata reconciler to the persistent aggregate history ledger. It
requires the inventory, observer receipt, binding receipt, availability, and
recovery-readiness history interfaces. It first obtains a stable four-ledger
report, then records only the validated aggregate report.

After the append, the service exports the bounded history snapshot and invokes
the independent snapshot verifier. It compares the independent result with the
ledger's own verification result and checks that the last persisted record
matches the returned evaluation identifier, report digest, sequence,
classification, blocker count, and aggregate report. The public result contains
counts, status codes, the evaluation digest, and the verified chain head only.

Both READY and NOT_READY evaluations are recorded. A NOT_READY report is never
promoted. Exact timestamp/report replay remains idempotent. The result always
preserves `artifact_bytes_verified=false`, `execution_authorized=false`,
`automatic_dispatch=false`, and `automatic_retry=false`.

A failure after the append but before independent readback is reported as a
service error; the append-only record is not rolled back. The caller must inspect
the history before retrying. This service verifies the current database
connection; it does not claim a process restart. Restart verification remains
a separate close/reopen operation using `recover_after_restart()`.

The service is currently exercised with synthetic four-ledger reports and
temporary SQLite databases in the company-only test workflow. It is not wired
to a production backup database or external storage service.


## Independent recovery-readiness transition history

`scripts/enterprise_hq_backup_recovery_readiness_transitions.py` independently
verifies the complete bounded readiness-history snapshot before summarizing
adjacent evaluation transitions.

- classifies READY→READY, READY→NOT_READY, NOT_READY→READY, and
  NOT_READY→NOT_READY transitions;
- counts blocker-addition and blocker-resolution events between adjacent
  reports, without returning blocker names;
- checks that a READY→NOT_READY transition introduces at least one blocker and
  that a NOT_READY→READY transition resolves at least one blocker;
- reports aggregate record, transition, classification-change, and latest
  blocker counts only;
- rejects invalid history hashes, sequence gaps, timestamp regressions,
  malformed reports, raw identifiers, and authorization escalation;
- preserves artifact-byte verification, execution, dispatch, and automatic
  retry flags as false.

Blocker event counts are per transition, not unique blocker counts across the
entire history. The report is descriptive and does not infer causality, trigger
alerts, authorize tasks, or perform writes. It does not change the append-only
history and does not claim a process restart. All tests use synthetic reports
and temporary in-memory SQLite ledgers.


## Close/reopen recovery-readiness restart adapter

`scripts/enterprise_hq_backup_recovery_readiness_restart.py` adds a file-backed
integration boundary around the four-ledger readiness service and persistent
history ledger.

The adapter:

- requires all four source ledgers and a file-backed SQLite database path;
- records the aggregate readiness evaluation through the existing service;
- closes the first SQLite connection before opening a second connection;
- calls `recover_after_restart()` on the reopened ledger;
- independently verifies the exported history snapshot and adjacent transition
  summary;
- compares the reopened record count, sequence, chain head, READY/NOT_READY
  counts, blocker totals, and latest evaluation against the original service
  result;
- rejects any disagreement or authorization-flag escalation;
- returns aggregate counts and status only, omitting evaluation identifiers,
  report digests, blocker names, and source payloads.

The adapter does not restore backup bytes, create external copies, authorize
execution, dispatch tasks, or retry work. Tests use synthetic four-ledger
reports and temporary file-backed SQLite databases. This proves a local
close/reopen boundary only; it does not prove off-host durability or production
backup recovery.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_restart.py'`


## Interrupted recovery-readiness append reconciliation

The new interruption reconciliation module adds a read-only recovery path for
an evaluation whose caller may have been interrupted around the SQLite commit
boundary.

The ledger supports an explicit read-only connection mode. It opens an existing
database with SQLite mode=ro and query_only enabled, validates the schema
without creating tables or changing permissions, and rejects all write
transactions. The exact original report and timezone-aware timestamp are
required to identify the deterministic evaluation key.

The reconciliation operation opens only an existing file-backed history
database in read-only mode, checks whether the exact report/timestamp evaluation
is present, verifies the complete persistent history and state checkpoint,
runs independent snapshot and transition verification, and cross-checks
recovery counts, sequence and chain head.

It reports COMMITTED when the exact append exists and NOT_COMMITTED when it
does not. It never appends, retries, authorizes or dispatches work. A
NOT_COMMITTED result requires manual review before any separate retry decision.

Focused tests inject a rollback before commit and simulate a caller losing the
result after a successful commit. These are deterministic SQLite fault
simulations, not process-kill, host-crash, power-loss or off-host durability
tests. Production storage is not connected.

Run the focused suite with:

python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_interruption.py'


## Recovery-readiness SQLite crash-point verification

`tests/test_enterprise_hq_backup_recovery_readiness_crash_points.py` injects
deterministic failures at the readiness-history write boundaries:

- before the record insert;
- immediately after the record insert;
- immediately after the state-checkpoint update;
- when SQLite commit fails before committing;
- after SQLite commits but the caller loses the commit acknowledgement.

For failures before a successful commit, the test reopens the database through
the read-only interruption reconciler and verifies that neither the record nor
the sequence/chain-head checkpoint advanced. When the commit succeeded but its
acknowledgement was lost, reconciliation reports COMMITTED; an exact replay is
then verified as idempotent and the history remains at one record.

These tests exercise SQLite transaction and acknowledgement boundaries using
synthetic local databases. They do not simulate operating-system process
termination, host failure, power loss, filesystem corruption, or off-host
durability. The reconciler remains read-only and never retries automatically.
No production database or external storage is connected.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_crash_points.py'`


## Existing-history SQLite crash-point recovery

`tests/test_enterprise_hq_backup_recovery_readiness_existing_history_crash_points.py`
extends transaction-boundary fault injection to a database that already contains
a verified multi-record history.

The focused suite creates two committed synthetic readiness evaluations, then
injects failures while attempting a third evaluation at the following boundaries:

- before the record insert;
- after the record insert;
- after the sequence/chain-head checkpoint update;
- immediately before SQLite commit;
- after commit succeeds but the caller loses the acknowledgement.

For every pre-commit failure, read-only reconciliation must report
NOT_COMMITTED while preserving both earlier records, their sequence, and the
original chain head. The lost-acknowledgement case must report COMMITTED with
exactly one additional record; an exact replay must remain idempotent.

A separate checkpoint-corruption test changes only the stored chain head in a
temporary database and confirms that read-only verification fails closed
without repairing or rewriting the checkpoint.

All cases use synthetic aggregate reports and temporary local SQLite files.
They do not use company backup data, simulate host/power failure, prove
off-host durability, authorize retry, or dispatch work.

Run the focused suite with:

`python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_existing_history_crash_points.py'`


## Atomic recovery-readiness schema initialization

The persistent recovery-readiness ledger now creates its tables, index, immutability
triggers, schema-version row, and initial state checkpoint inside one explicit
SQLite `BEGIN IMMEDIATE` transaction. The initialization transaction is committed
only after the schema version and required state row have been validated. If any
initialization step raises, the connection rolls back the open transaction before
closing.

The dedicated schema-initialization crash suite injects failures after each of the
seven DDL statements, after each seed-row insertion, and immediately before the
initialization commit. It verifies that no partial schema objects survive and that
a later normal open can initialize and independently verify an empty ledger.
A separate test confirms that reopening a populated ledger preserves its records
and chain head.

The tests use temporary synthetic SQLite databases only. They do not inspect or
modify production backup files, private governance state, task grants, or product
data. This is deterministic local persistence verification, not a machine-crash
or power-loss durability certification.

Run the focused suite with:

```bash
python -m unittest discover -s tests -p 'test_enterprise_hq_backup_recovery_readiness_schema_init_crash_points.py'
```
