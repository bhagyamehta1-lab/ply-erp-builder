

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
