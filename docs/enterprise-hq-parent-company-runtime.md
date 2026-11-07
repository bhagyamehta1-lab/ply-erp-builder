

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
