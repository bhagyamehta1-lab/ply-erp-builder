import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const workflow = readFileSync('.github/workflows/build-private-apps.yml', 'utf8');
const approval = "if: ${{ github.event_name == 'workflow_dispatch' && inputs.publish_private_release == true }}";

test('private release publication is opt-in and defaults to disabled', () => {
  assert.match(
    workflow,
    /publish_private_release:\s*\n\s+description:.*\n\s+required: true\n\s+type: boolean\n\s+default: false/
  );
});

test('both private release upload steps require explicit manual approval', () => {
  const windowsStart = workflow.indexOf('      - name: Publish Windows installer and smoke screenshot to private ERP release');
  const androidStart = workflow.indexOf('      - name: Publish Android APK and smoke screenshot to private ERP release');
  const postSmokeStart = workflow.indexOf('  post-smoke-validation:');
  assert.ok(windowsStart >= 0 && androidStart > windowsStart && postSmokeStart > androidStart);
  const windowsStep = workflow.slice(windowsStart, androidStart);
  const androidStep = workflow.slice(androidStart, postSmokeStart);
  assert.ok(windowsStep.includes(approval));
  assert.ok(androidStep.includes(approval));
  assert.equal((workflow.match(/gh release create/g) || []).length, 2);
});
