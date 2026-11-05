import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';

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
test('sparse checkout materializes only exact approved read paths',()=>{
 const root=mkdtempSync(join(tmpdir(),'ply-sparse-read-'));
 try {
  execFileSync('git',['init','--quiet'],{cwd:root});
  execFileSync('git',['config','user.email','worker-test@example.invalid'],{cwd:root});
  execFileSync('git',['config','user.name','Worker Policy Test'],{cwd:root});
  mkdirSync(join(root,'src'),{recursive:true});
  mkdirSync(join(root,'private'),{recursive:true});
  writeFileSync(join(root,'src','allowed.ts'),'export const allowed = true;');
  writeFileSync(join(root,'private','unapproved.ts'),'export const privateValue = true;');
  writeFileSync(join(root,'README.md'),'readme');
  execFileSync('git',['add','.'],{cwd:root});
  execFileSync('git',['commit','--quiet','-m','fixture'],{cwd:root});
  execFileSync('git',['sparse-checkout','init','--no-cone'],{cwd:root});
  const patterns=join(root,'patterns.txt');
  writeFileSync(patterns,'/src/allowed.ts\n/README.md\n');
  execFileSync('git',['sparse-checkout','set','--no-cone','--stdin'],{cwd:root,input:'/src/allowed.ts\n/README.md\n'});
  execFileSync('git',['checkout','--quiet','--detach','HEAD'],{cwd:root});
  const materialized=[];
  const walk=(dir)=>{for(const entry of readdirSync(dir,{withFileTypes:true})){if(entry.name==='.git'||entry.name==='patterns.txt')continue;const path=join(dir,entry.name);if(entry.isDirectory())walk(path);else materialized.push(relative(root,path).replaceAll('\\\\','/'));}};
  walk(root);
  assert.deepEqual(materialized.sort(),['README.md','src/allowed.ts']);
  assert.equal(requireFile(join(root,'private','unapproved.ts')),false);
 } finally { rmSync(root,{recursive:true,force:true}); }
});
function requireFile(path){ try { return readdirSync(path).length>=0; } catch { return false; } }
test('worker workflow has no public artifact upload and verifies physical read boundary',()=>{
 const workflow=readFileSync('.github/workflows/public_worker_executor.yml','utf8');
 const runner=readFileSync('scripts/autonomous_shift_runner.py','utf8');
 assert.match(workflow,/git fetch --quiet --filter=blob:none/);
 assert.match(workflow,/git sparse-checkout init --no-cone/);
 assert.match(workflow,/materialized != read_allowed/);
 assert.doesNotMatch(workflow,/actions\\/upload-artifact/);
 assert.match(runner,/read_file_allowlist/);
 assert.match(runner,/materialized_source_files/);
});
