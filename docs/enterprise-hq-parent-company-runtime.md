

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
