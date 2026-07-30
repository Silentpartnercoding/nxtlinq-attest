import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  clearAttestScopeCache,
  isToolInAttestScope,
} from '../dist/runtime.js';

function fixture(manifest) {
  const root = mkdtempSync(join(tmpdir(), 'nxtlinq-attest-runtime-'));
  if (manifest !== undefined) {
    mkdirSync(join(root, 'nxtlinq'));
    writeFileSync(
      join(root, 'nxtlinq', 'agent.manifest.json'),
      typeof manifest === 'string' ? manifest : JSON.stringify(manifest),
    );
  }
  return root;
}

test('missing manifest fails closed', () => {
  const root = fixture();
  assert.equal(isToolInAttestScope('Search', root), false);
});

test('invalid manifest fails closed', () => {
  const root = fixture('{not-json');
  assert.equal(isToolInAttestScope('Search', root), false);
});

test('missing or empty scope fails closed', () => {
  const missing = fixture({});
  const empty = fixture({ scope: [] });
  assert.equal(isToolInAttestScope('Search', missing), false);
  assert.equal(isToolInAttestScope('Search', empty), false);
});

test('only tools in a non-empty scope are allowed', () => {
  const root = fixture({ scope: ['tool:Search'] });
  assert.equal(isToolInAttestScope('Search', root), true);
  assert.equal(isToolInAttestScope('tool:Search', root), true);
  assert.equal(isToolInAttestScope('Exec', root), false);
});

test('legacy permissive behavior requires an explicit opt-in', () => {
  const root = fixture({ scope: [] });
  assert.equal(
    isToolInAttestScope('Search', root, { allowEmptyScope: true }),
    true,
  );
});

test('scope cache can be cleared after a manifest is repaired', () => {
  const root = fixture({ scope: [] });
  assert.equal(isToolInAttestScope('Search', root), false);
  writeFileSync(
    join(root, 'nxtlinq', 'agent.manifest.json'),
    JSON.stringify({ scope: ['tool:Search'] }),
  );
  assert.equal(isToolInAttestScope('Search', root), false);
  clearAttestScopeCache(root);
  assert.equal(isToolInAttestScope('Search', root), true);
});
