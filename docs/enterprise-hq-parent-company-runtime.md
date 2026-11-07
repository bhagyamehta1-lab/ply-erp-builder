

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
