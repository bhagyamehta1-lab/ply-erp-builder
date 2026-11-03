import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { test } from 'node:test';

const workflowDirectory = new URL('../.github/workflows/', import.meta.url);

test('Builder-1 exposes only the sanitized synthetic contract workflow', async () => {
  const workflows = (await readdir(workflowDirectory))
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .sort();

  assert.deepEqual(workflows, ['domain-tests.yml']);

  const workflow = await readFile(new URL('../.github/workflows/domain-tests.yml', import.meta.url), 'utf8');
  assert.match(workflow, /node --test src\/\*\.test\.mjs/);
  assert.doesNotMatch(workflow, /\bsecrets\./i);
  assert.doesNotMatch(workflow, /actions\/upload-artifact@/i);
  assert.doesNotMatch(workflow, /\bgh\s+release\s+create\b/i);
});
