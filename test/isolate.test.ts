// The tests never use the real key or vault of whoever runs them.
import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { defaultKeyPath } from '../src/vault.ts';
import { TEST_HOME } from './isolate.ts';

test('the default key and vault live in the temp home during tests', () => {
  assert.ok(resolve(defaultKeyPath()).toLowerCase().startsWith(resolve(TEST_HOME).toLowerCase()), defaultKeyPath());
  for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'LLM_REDACT_HOME']) assert.equal(process.env[name], undefined, name);
});
