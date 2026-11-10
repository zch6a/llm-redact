import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { redactRequest } from '../src/body.ts';
import { bodyChanges, didYouMean, envText, guessApi, main } from '../src/cli.ts';
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

describe('errors a user can fix', () => {
  it('near misses get a suggestion, far ones do not', () => {
    assert.equal(didYouMean('emial', ['email', 'phone']), ' (did you mean "email"?)');
    assert.equal(didYouMean('scna', ['start', 'scan']), ' (did you mean "scan"?)');
    assert.equal(didYouMean('frobnicate', ['start', 'scan']), '');
    assert.equal(didYouMean('x', ['ab']), '');
  });
  it('an unreadable file is one line and exit code 1, not a stack trace', async () => {
    const errors: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => void errors.push(a.join(' '));
    try {
      assert.equal(await main(['scan', join(tmpdir(), 'llm-redact-no-such-file.txt')]), 1);
      assert.equal(await main(['scan', tmpdir()]), 1);
      assert.equal(await main(['scna']), 2);
    } finally {
      console.error = orig;
    }
    assert.match(errors[0] ?? '', /^cannot read .*: no such file$/);
    assert.match(errors[1] ?? '', /: it is a directory$/);
    assert.match(errors[2] ?? '', /did you mean "scan"/);
    assert.ok(!errors.some((e) => /\n\s+at /.test(e)), 'no stack traces');
  });
});

describe('scan --body', () => {
  const v = new Vault(Buffer.alloc(32, 4));
  it('guesses the wire format from the shape', () => {
    assert.equal(guessApi({ model: 'm', input: [] }), 'responses');
    assert.equal(guessApi({ model: 'm', messages: [{ role: 'system', content: 'x' }, { role: 'user', content: 'y' }] }), 'chat');
    assert.equal(guessApi({ model: 'm', messages: [{ role: 'assistant', tool_calls: [] }] }), 'chat');
    assert.equal(guessApi({ model: 'm', system: 'x', messages: [{ role: 'user', content: 'y' }] }), 'anthropic');
    assert.equal(guessApi({ contents: [] }), 'other');
  });
  it('lists the fields that change and what was redacted in each; the note is an addition', () => {
    const body = JSON.parse(readFileSync(new URL('../docs/example-request.json', import.meta.url), 'utf8'));
    const r = redactRequest(body, v, 'anthropic');
    assert.deepEqual(bodyChanges(body, r.body), [
      { path: 'system[1]', redacted: [], added: true },
      { path: 'messages[2].content[0].content', redacted: ['openai_key', 'url_password', 'email'] },
    ]);
  });
  it('reports redacted object keys, and ignores placeholders that were already there', () => {
    const ph = v.placeholderFor('email', 'old@corp-mail.cn');
    const body = { model: 'm', messages: [{ role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'n', input: { 'li.wei@corp-mail.cn': 'admin', note: `${ph} and li.wei@corp-mail.cn` } }] }] };
    const changes = bodyChanges(body, redactRequest(body, v, 'anthropic', { note: false }).body);
    assert.deepEqual(changes, [
      { path: 'messages[0].content[0].input."[[REDACTED:email:' + /email:([0-9a-f]{8})/.exec(v.placeholderFor('email', 'li.wei@corp-mail.cn'))![1] + ']]"', redacted: ['email'] },
      { path: 'messages[0].content[0].input.note', redacted: ['email'] },
    ]);
  });
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

describe('vault memory', () => {
  it('is bounded, least recently used out first; a value seen again gets its placeholder back', () => {
    const v = new Vault(Buffer.alloc(32, 3), 100);
    const first = v.placeholderFor('email', 'keep@corp-mail.cn');
    for (let i = 0; i < 1000; i++) {
      v.placeholderFor('email', `u${i}@corp-mail.cn`);
      if (i % 50 === 0) v.placeholderFor('email', 'keep@corp-mail.cn'); // in use: stays
    }
    assert.equal(v.size, 100);
    assert.equal(v.valueOf(first), 'keep@corp-mail.cn');
    const gone = v.placeholderFor('email', 'u0@corp-mail.cn'); // forgotten long ago, back the same
    assert.match(gone, /^\[\[REDACTED:email:[0-9a-f]{8}\]\]$/);
    assert.equal(new Vault(Buffer.alloc(32, 3)).placeholderFor('email', 'u0@corp-mail.cn'), gone);
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
  it('a hit puts its values back into a vault that had forgotten them', () => {
    const small = new Vault(Buffer.alloc(32, 2), 3);
    const cache = new RedactCache();
    const first = redactText(long(7), small, { cache });
    const ph = first.hits.find((h) => h.detector === 'openai_key')!.placeholder;
    for (let i = 0; i < 5; i++) small.placeholderFor('email', `other${i}@corp-mail.cn`); // push it out
    assert.equal(small.valueOf(ph), undefined);
    assert.equal(redactText(long(7), small, { cache }).text, first.text);
    assert.ok(small.valueOf(ph)?.startsWith('sk-proj-'), 'restorable again');
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
