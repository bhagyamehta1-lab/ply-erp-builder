import test from 'node:test';
import assert from 'node:assert/strict';

export const DOCUMENT_STATES = Object.freeze(['draft','submitted','approved','posted','closed']);
export const ALLOWED_TRANSITIONS = Object.freeze({
  draft: ['submitted'],
  submitted: ['approved','draft'],
  approved: ['posted','draft'],
  posted: ['closed'],
  closed: []
});
export function transitionDocument(document, nextState) {
  if (!document?.id || !DOCUMENT_STATES.includes(document.state)) throw new Error('Invalid document');
  if (!ALLOWED_TRANSITIONS[document.state].includes(nextState)) throw new Error(`Invalid transition: ${document.state} -> ${nextState}`);
  return Object.freeze({...document, state: nextState});
}
export function makeAuditEvent({id, actorId, action, entityType, entityId, occurredAt, reason = null}) {
  if (![id,action,entityType,entityId,occurredAt].every(v => typeof v === 'string' && v.trim())) throw new Error('Audit event required fields missing');
  return Object.freeze({id, actorId: actorId ?? null, action, entityType, entityId, occurredAt, reason});
}
export function makeLedgerReversal(original, reversal) {
  if (!original?.id || original.reversedBy) throw new Error('Original entry missing or already reversed');
  if (!reversal?.id || !reversal.occurredAt) throw new Error('Reversal identity and timestamp required');
  return Object.freeze({...reversal, reversesEntryId: original.id});
}
test('document lifecycle rejects skipping approval and reopening closed docs',()=>{
 assert.throws(()=>transitionDocument({id:'D1',state:'draft'},'posted'));
 assert.equal(transitionDocument({id:'D1',state:'draft'},'submitted').state,'submitted');
 assert.throws(()=>transitionDocument({id:'D1',state:'closed'},'draft'));
});
test('audit events require traceable entity and action',()=>{
 assert.equal(makeAuditEvent({id:'A1',action:'create',entityType:'PO',entityId:'P1',occurredAt:'2026-11-01T00:00:00Z'}).actorId,null);
 assert.throws(()=>makeAuditEvent({id:'A2',action:'',entityType:'PO',entityId:'P1',occurredAt:'now'}));
});
test('posted corrections are represented as linked reversals',()=>{
 const r=makeLedgerReversal({id:'L1'},{id:'L2',occurredAt:'now'});
 assert.equal(r.reversesEntryId,'L1');
 assert.throws(()=>makeLedgerReversal({id:'L1',reversedBy:'L2'},{id:'L3',occurredAt:'now'}));
});