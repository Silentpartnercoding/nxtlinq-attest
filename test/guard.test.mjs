import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { runInit } from '../dist/commands/init.js';
import { runSign } from '../dist/commands/sign.js';
import { authorizeOperation, guardOperation } from '../dist/guard.js';

function signedProject(scope) {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-guard-'));
  writeFileSync(join(root, 'agent.js'), 'export const agent = true;\n');
  runInit(root);
  const manifestPath = join(root, 'nxtlinq', 'agent.manifest.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.scope = scope;
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  runSign(root);
  return root;
}

test('allowed operation reaches the protected downstream handler', async () => {
  const root = signedProject(['tool:write']);
  let calls = 0;

  const result = await guardOperation(
    { capability: 'tool:write', protocol: 'acp', resource: 'src/allowed.ts' },
    () => {
      calls += 1;
      return 'written';
    },
    { cwd: root },
  );

  assert.equal(result.executed, true);
  assert.equal(result.decision.outcome, 'allow');
  assert.equal(result.value, 'written');
  assert.equal(calls, 1);
  assert.equal(result.decision.evidence.manifestDigest.length, 64);
});

test('denied operation never reaches the protected downstream handler', async () => {
  const root = signedProject(['tool:read']);
  let calls = 0;

  const result = await guardOperation(
    { capability: 'tool:write', protocol: 'acp', resource: 'src/blocked.ts' },
    () => {
      calls += 1;
      return 'should-not-run';
    },
    { cwd: root },
  );

  assert.equal(result.executed, false);
  assert.equal(result.decision.outcome, 'deny');
  assert.equal(result.decision.code, 'out_of_scope');
  assert.equal(calls, 0, 'deny must prevent downstream execution');
});

test('altered covered artifact fails closed before downstream execution', async () => {
  const root = signedProject(['tool:write']);
  writeFileSync(join(root, 'agent.js'), 'export const agent = false;\n');
  let calls = 0;

  const result = await guardOperation(
    { capability: 'tool:write' },
    () => {
      calls += 1;
    },
    { cwd: root },
  );

  assert.equal(result.executed, false);
  assert.equal(result.decision.code, 'artifact_digest_mismatch');
  assert.equal(calls, 0);
});

test('invalid signature fails closed before downstream execution', async () => {
  const root = signedProject(['tool:write']);
  writeFileSync(join(root, 'nxtlinq', 'agent.manifest.sig'), '00'.repeat(64));
  let calls = 0;

  const result = await guardOperation(
    { capability: 'tool:write' },
    () => {
      calls += 1;
    },
    { cwd: root },
  );

  assert.equal(result.executed, false);
  assert.equal(result.decision.code, 'invalid_signature');
  assert.equal(calls, 0);
});

test('authorization returns only digest evidence, not request arguments or secrets', () => {
  const root = signedProject(['tool:exec']);
  const decision = authorizeOperation(
    { capability: 'tool:exec', protocol: 'acp', sessionId: 'session-1' },
    { cwd: root },
  );

  assert.equal(decision.outcome, 'allow');
  assert.equal('arguments' in decision, false);
  assert.equal('sessionId' in decision, false);
});
