# Shared Domain Contract — Pilot 2/3/4
Status: DRAFT PROPOSAL v0.1 — NOT APPROVED FOR IMPLEMENTATION
Date: 2026-11-01
Applies to: Inventory & Stock (Builder 2), Purchase & GRN (Builder 3), Production & BOM (Builder 4)

This is an interface proposal for review only. The private ERP integration owner must approve and version it before any lane implements database migrations, shared tables, posting logic, or cross-module APIs.

## 1. Stable identity
- Every persisted business entity has an immutable UUID primary identifier.
- Human-readable document numbers are separate, unique display identifiers; never use them as foreign keys.
- Every posted operation carries an idempotency key and a source-document reference.
- IDs in examples are synthetic placeholders only.

## 2. Quantities and units
- Preserve entered precision; do not round quantities during intermediate calculations.
- Store canonical quantities as fixed-precision decimal values, not binary floating point.
- A quantity always travels with an explicit UOM code.
- Sheet, square-foot and square-metre conversions must be explicit, dimension-aware and versioned; do not assume every sheet has identical dimensions.
- Proposed baseline for review: quantity DECIMAL(20,4); rates/costs DECIMAL(20,6); currency amounts DECIMAL(20,2). Integration owner must confirm scale and rounding policy.

## 3. Stock movement semantics
- Posted stock is derived from one authoritative movement journal; module-specific screens must not maintain competing writable balances.
- Movement record proposal: movement_id, item_id, lot_id, quantity_delta, uom, movement_type, source_type, source_id, idempotency_key, occurred_at, posted_at, actor_id, reversal_of, audit_metadata.
- Receipts/issues/dispatch/returns/adjustments are append-only posted movements.
- Corrections create linked compensating reversals; never edit or delete a posted movement.
- Draft documents do not affect on-hand or sellable stock.
- Available-to-promise = posted on-hand minus active reservations and other approved holds. A reservation must be consumed/released exactly once.

## 4. Purchase and GRN boundary
- Purchase order is not stock.
- Only a successfully posted GRN creates raw-material lot(s) and receipt movement(s).
- GRN posting must be atomic: header/lines, lot traceability, movement and audit event either all commit or none commit.
- Lot identity is preserved through material issue and production consumption.

## 5. BOM and production boundary
- BOM is a versioned requirement definition; production batch snapshots the BOM version used.
- Before production starts/posts, validate all required components against eligible, unreserved lot quantities.
- Material issue/consumption must post atomically and idempotently.
- Production receipt is prohibited unless required consumption posting succeeded.
- Failed or insufficient issue leaves no partial consumption and no finished-goods receipt.
- Production receipt links finished goods to the production batch and consumed input lots.

## 6. Transactions, concurrency and errors
- A business posting is one transaction boundary; use row/version checks or equivalent concurrency control.
- Repeated requests with the same idempotency key return the original result and do not post twice.
- Use stable machine-readable error codes, including INSUFFICIENT_STOCK, RESERVATION_CONFLICT, BOM_VERSION_MISMATCH, DUPLICATE_POSTING and POSTING_REVERSED.
- Never silently retry a non-idempotent operation.

## 7. Audit and permissions
- Record actor, timestamp, source document, reason and before/after references for every posting/reversal.
- Permission checks occur server/domain-side at the posting boundary, not only in UI.
- Public builder fixtures must be synthetic and contain no real vendor/customer, invoice, inventory or employee data.

## 8. Migration and integration ownership
- Only the private integration owner approves shared schema/migrations, migration ordering, rollback and API versioning.
- Lane repositories may submit proposals and isolated tests; they must not create competing canonical stock tables.
- No public builder workflow gets private repository write access.
- Integration is a reviewed, selective port to a private feature branch, never direct to private main.

## 9. Synthetic acceptance flow
1. Post a synthetic GRN for item RM-PLY-01 and create a traceable lot.
2. Read eligible on-hand and reserve nothing by default.
3. Submit a BOM requiring more than available: expect INSUFFICIENT_STOCK and zero movement changes.
4. Submit a BOM within available quantity: issue/consumption posts once.
5. Retry same idempotency key: same result, no duplicate movement.
6. Post production receipt only after successful consumption.
7. Reverse a test posting: append a linked reversal and retain original audit trail.

## 10. Approval checklist
- [ ] Integration owner confirms UUID and document-number conventions.
- [ ] Integration owner confirms decimal scales, rounding and UOM conversion policy.
- [ ] Integration owner confirms the single stock source of truth and movement schema.
- [ ] Integration owner approves transaction/idempotency and reversal semantics.
- [ ] Integration owner approves API/error contract, migration ownership and audit fields.
- [ ] Contract receives an approved version before implementation begins.

Until all relevant items are approved, treat all field names, scales and examples here as proposals, not implemented facts.
