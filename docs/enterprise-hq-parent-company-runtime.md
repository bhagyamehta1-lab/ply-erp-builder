

## Persistent lease-proposal ledger (local, review-only)

\`scripts/enterprise_hq_lease_ledger.py\` extends the local SQLite proposal ledger with separate \`lease_proposals\` and \`lease_audit_events\` tables:

- requires the exact parent-company task proposal to exist in the same ledger before a lease proposal can be recorded;
- accepts only a future first-attempt lease envelope (\`NOT_YET_VALID\` at the supplied evaluation time), so recording cannot activate an already active or expired lease;
- enforces one proposal per task and attempt, unique lease IDs, the existing two-attempt ceiling, and the existing 15-minute lease-window limit;
- persists the lease envelope as \`PROPOSED\` and appends a separate sequenced SHA-256 audit chain in the same SQLite transaction;
- treats identical lease proposals as idempotent and rejects conflicting reuse;
- verifies both the original task proposal chain and the lease proposal chain before any append and after restart;
- refuses to extend a corrupted lease audit chain;
- keeps the task status at \`PROPOSED\` and returns \`lease_issued=false\`, \`execution_authorized=false\`, and \`automatic_retry=false\`.

This stage persists only initial attempt-1 lease proposals. Successor lease validation remains a separate pure contract and is not persisted by this component. The store is local, bounded to 256 lease proposals, and inherits the proposal ledger's 8 MiB database cap and owner-only file checks. It is not encrypted or shared across machines. A persisted row is a future lease proposal for human review, not an issued lease, authenticated worker claim, distributed lock, or execution authorization. No claims, renewals, automatic retries, or task resumption are implemented.

Run the focused suite with:

\`\`\`sh
python -m unittest discover -s tests -p 'test_enterprise_hq_lease_ledger.py'
\`\`\`
