import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { envText } from '../src/cli.ts';
import { RedactCache, redactText } from '../src/redact.ts';
import { Vault, writePrivate } from '../src/vault.ts';

describe('env', () => {
  it('points each client at the proxy, with the token when there is one', () => {
    const t = envText('all', 8787, 'bash', {}, 'ab'.repeat(16));
    assert.match(t, /^export ANTHROPIC_BASE_URL=http:\/\/127\.0\.0\.1:8787\/(ab){16}\/anthropic$/m);
    assert.match(t, /^export OPENAI_BASE_URL=http:\/\/127\.0\.0\.1:8787\/(ab){16}\/openai\/v1$/m);
    assert.match(t, /base_url = "http:\/\/127\.0\.0\.1:8787\/(ab){16}\/openai\/v1"/);
  });
  it('keeps requests to the proxy away from HTTP proxies, keeping what NO_PROXY had', () => {
    assert.match(envText('claude', 8787, 'bash', {}), /^export NO_PROXY=127\.0\.0\.1,localhost$/m);
    assert.match(envText('claude', 8787, 'bash', {}), /^export no_proxy=127\.0\.0\.1,localhost$/m);
    assert.match(envText('codex', 8787, 'bash', { NO_PROXY: 'corp.internal, localhost' }), /^export NO_PROXY=127\.0\.0\.1,localhost,corp\.internal$/m);
    const ps = envText('codex', 8787, 'powershell', {});
    assert.match(ps, /^\$env:NO_PROXY = "127\.0\.0\.1,localhost"$/m);
    assert.ok(!/no_proxy/.test(ps), 'one variable on Windows: names are case-insensitive there');
  });
  it('notices an existing gateway and says how to keep it', () => {
    assert.match(envText('claude', 8787, 'bash', { ANTHROPIC_BASE_URL: 'https://gateway.example/api' }), /--upstream anthropic=https:\/\/gateway\.example\/api/);
    assert.ok(!/--upstream/.test(envText('claude', 8787, 'bash', { ANTHROPIC_BASE_URL: 'https://api.anthropic.com/' })));
  });
  it('rejects an unknown client', () => assert.throws(() => envText('nope', 8787, 'bash', {}), /unknown client/));
});

describe('private files (key, token)', () => {
  it('are readable by the owner only', () => {
    const dir = mkdtempSync(join(tmpdir(), 'llm-redact-acl-'));
    try {
      const f = join(dir, 'sub', 'key');
      assert.equal(writePrivate(f, 'secret\n'), true);
      if (process.platform === 'win32') {
        const acl = execFileSync('icacls', [f], { encoding: 'utf8' });
        // Exactly one entry, not inherited from the folder.
        const entries = acl.split(/\r?\n/).filter((l) => /:\(/.test(l));
        assert.equal(entries.length, 1, acl);
        assert.ok(!/\(I\)/.test(acl), acl);
      } else assert.equal(statSync(f).mode & 0o777, 0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('redaction cache', () => {
  const v = new Vault(Buffer.alloc(32, 2));
  const long = (n: number) => `log line ${n}\n`.repeat(200) + `key sk-proj-${'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2)} mail li.wei${n}@corp-mail.cn\n`;
  it('gives the same result as without it, and hits on the second call', () => {
    const cache = new RedactCache();
    const plain = redactText(long(1), v);
    const first = redactText(long(1), v, { cache });
    const second = redactText(long(1), v, { cache });
    assert.deepEqual(first, plain);
    assert.deepEqual(second, plain);
    assert.equal(cache.entries, 1);
  });
  it('returns copies: changing a result does not change the cache', () => {
    const cache = new RedactCache();
    redactText(long(2), v, { cache }).hits[0]!.placeholder = 'tampered';
    assert.notEqual(redactText(long(2), v, { cache }).hits[0]!.placeholder, 'tampered');
  });
  it('skips short texts and stays within its size bound', () => {
    const cache = new RedactCache(64 * 1024);
    redactText('short sk-proj-' + 'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2), v, { cache });
    assert.equal(cache.entries, 0);
    for (let i = 0; i < 100; i++) redactText(long(i), v, { cache });
    const per = long(0).length * 2;
    assert.ok(cache.entries <= Math.ceil((64 * 1024) / per) + 1, String(cache.entries));
    assert.ok(cache.entries > 1);
  });
});
