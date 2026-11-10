/**
 * Regression tests for the round-1 leak review: every finding gets a test that failed before its
 * fix. All values are synthetic.
 */
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { apiFor, redactRequest, restoreResponse } from '../src/body.ts';
import { createProxy } from '../src/proxy.ts';
import { redactText } from '../src/redact.ts';
import { SseRestorer } from '../src/sse.ts';
import { Vault } from '../src/vault.ts';

const v = new Vault(Buffer.alloc(32, 5));
const EMAIL = 'li.wei@corp-mail.cn';
const SECRET = 'sk-proj-' + 'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2);
const PH = /\[\[REDACTED:[a-z_]+:[0-9a-f]{8}\]\]/;

const sent = (body: unknown, api: 'anthropic' | 'chat' | 'responses' = 'anthropic') => JSON.stringify(redactRequest(body, v, api).body);
const noLeak = (s: string, ...values: string[]) => {
  for (const x of values) assert.ok(!s.includes(x), `leaked ${x.slice(0, 24)}… in ${s.slice(0, 300)}`);
};
const toolUse = (input: unknown) => ({ model: 'm', messages: [{ role: 'assistant', content: [{ type: 'tool_use', id: 'tu_1', name: 'mcp__crm__update', input }] }] });

describe('walker: tool inputs are data, whatever their keys are called', () => {
  const cases: [string, unknown, string][] = [
    ['user', { user: EMAIL }, EMAIL],
    ['name', { name: EMAIL }, EMAIL],
    ['id', { id: SECRET }, SECRET],
    ['metadata', { metadata: { note: `key ${SECRET}` } }, SECRET],
    ['container', { container: { env: `OPENAI_API_KEY=${SECRET}` } }, SECRET],
    ['type: file', { files: [{ type: 'file', path: '.env', content: `OPENAI_API_KEY=${SECRET}` }] }, SECRET],
    ['url is a data: URL without base64', { url: 'data:text/plain,hi', body: `mail ${EMAIL}` }, EMAIL],
    ['signed-looking type inside input', { type: 'thinking', thinking: `mail ${EMAIL}` }, EMAIL],
  ];
  for (const [label, input, value] of cases) it(`tool_use.input with ${label}`, () => noLeak(sent(toolUse(input)), value));

  it('object keys inside tool inputs are redacted too', () => {
    const s = sent(toolUse({ roles: { [EMAIL]: 'admin' } }));
    noLeak(s, EMAIL);
    assert.match(s, PH);
  });
  it('the envelope keeps its structure (ids, names, roles untouched)', () => {
    const b = JSON.parse(sent(toolUse({ q: EMAIL })));
    assert.equal(b.messages[0].content[0].id, 'tu_1');
    assert.equal(b.messages[0].content[0].name, 'mcp__crm__update');
    assert.equal(b.messages[0].role, 'assistant');
  });
  it('chat tool-call arguments: structural-named keys and object keys', () => {
    const body = { model: 'm', messages: [{ role: 'assistant', tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: JSON.stringify({ user: EMAIL, [SECRET]: 1 }) } }] }] };
    const s = sent(body, 'chat');
    noLeak(s, EMAIL, SECRET);
    const call = JSON.parse(s).messages.find((m: { tool_calls?: unknown }) => m.tool_calls).tool_calls[0];
    assert.doesNotThrow(() => JSON.parse(call.function.arguments), 'arguments are still JSON');
  });
  it('legacy assistant.function_call.arguments', () => {
    const body = { model: 'm', messages: [{ role: 'assistant', content: null, function_call: { name: 'f', arguments: JSON.stringify({ key: SECRET, to: EMAIL }) } }] };
    noLeak(sent(body, 'chat'), SECRET, EMAIL);
  });
  it('a secret under a secret-named key in tool input is redacted whole', () => {
    noLeak(sent(toolUse({ password: 'Xy7pQ2rL9zW' })), 'Xy7pQ2rL9zW');
  });
  it('mcp_servers authorization_token is left for the provider', () => {
    const body = { model: 'm', mcp_servers: [{ type: 'url', url: 'https://mcp.example/sse', name: 'x', authorization_token: SECRET }], messages: [{ role: 'user', content: 'hi' }] };
    assert.ok(sent(body).includes(SECRET));
  });
  it('nesting deeper than any API request is refused, not a stack overflow', () => {
    let deep: unknown = 'x';
    for (let i = 0; i < 5000; i++) deep = [deep];
    assert.throws(() => redactRequest({ messages: deep }, v, 'anthropic'), /nested deeper/);
  });
  it('non-streamed restore reaches tool inputs, structural-named keys and object keys', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const out = JSON.stringify(restoreResponse({ content: [{ type: 'tool_use', id: 'tu', name: 'n', input: { user: ph, map: { [ph]: 'admin' } } }] }, v));
    assert.ok(!out.includes('[[REDACTED:'), out);
    assert.equal((out.match(/li\.wei@corp-mail\.cn/g) ?? []).length, 2);
  });
  it('thinking stays signed: not changed in either direction', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const block = { type: 'thinking', thinking: `about ${ph} and ${EMAIL}`, signature: 'sig' };
    assert.deepEqual(JSON.parse(sent({ messages: [{ role: 'assistant', content: [block] }] })).messages[0].content[0], block);
    assert.deepEqual((restoreResponse({ content: [block] }, v) as { content: unknown[] }).content[0], block);
  });
});

describe('engine: escaped and encoded text', () => {
  it('JSON inside a string (one level of escaping)', () => {
    const t = JSON.stringify({ password: 'Xy7pQ2rL9zW' });
    const r = redactText(JSON.stringify({ msg: t }), v);
    noLeak(r.text, 'Xy7pQ2rL9zW');
    assert.doesNotThrow(() => JSON.parse(JSON.parse(r.text).msg), 'still valid JSON at both levels');
  });
  it('double-encoded JSON', () => {
    const t = JSON.stringify(JSON.stringify({ msg: JSON.stringify({ api_key: 'Zr8kWq3nLp6t' }) }));
    noLeak(redactText(t, v).text, 'Zr8kWq3nLp6t');
  });
  it('more matches than the old per-text cap are all redacted', () => {
    const t = Array.from({ length: 12000 }, (_, i) => `user${i}@corp-mail.cn`).join('\n');
    const r = redactText(t, v);
    assert.equal(r.hits.length, 12000);
    assert.ok(!/@corp-mail\.cn/.test(r.text));
  });
  it('a ReDoS-shaped input finishes quickly', () => {
    const t0 = Date.now();
    redactText('token=;'.repeat(60) + ';'.repeat(1_000_000) + 'x', v);
    assert.ok(Date.now() - t0 < 1500, `${Date.now() - t0} ms`);
  });
});

describe('detectors: spans and shapes from the review', () => {
  it('url_password redacts the password even when the host repeats it', () => {
    const r = redactText('postgres://postgres:Pg-Pass9x@Pg-Pass9x.db.internal:5432/app', v);
    assert.match(r.text, /^postgres:\/\/postgres:\[\[REDACTED:url_password:[0-9a-f]{8}\]\]@Pg-Pass9x\.db\.internal:5432\/app$/);
  });
  it('a URL with credentials does not swallow an e-mail after it', () => {
    const r = redactText(`postgres://app:Secr3tPw9@db.internal,${EMAIL}`, v);
    noLeak(r.text, 'Secr3tPw9', EMAIL);
  });
  it('a card number followed by a CVV', () => {
    noLeak(redactText('card 4111111111111111 123 exp 12/29', v).text, '4111111111111111');
    noLeak(redactText('4111 1111 1111 1111, 123', v).text, '4111 1111 1111 1111');
  });
  it('a private key block cut off before its END line', () => {
    const body = Array.from({ length: 6 }, () => 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7').join('\n');
    const r = redactText(`-----BEGIN PRIVATE KEY-----\n${body}\n(truncated)`, v);
    noLeak(r.text, 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7');
  });
  it('a long variable name before the secret', () => {
    const name = 'MY_COMPANY_PRODUCTION_BILLING_SERVICE_PRIMARY_REGION_EU_WEST_API_KEY';
    noLeak(redactText(`${name}=Zr8kWq3nLp6tVb2x`, v).text, 'Zr8kWq3nLp6tVb2x');
  });
});

describe('API detection', () => {
  it('Vertex AI rawPredict / streamRawPredict, trailing slashes and query strings', () => {
    assert.equal(apiFor('/v1/projects/p/locations/l/publishers/anthropic/models/claude-x:streamRawPredict'), 'anthropic');
    assert.equal(apiFor('/v1/projects/p/locations/l/publishers/anthropic/models/claude-x:rawPredict'), 'anthropic');
    assert.equal(apiFor('/v1/messages/?beta=true'), 'anthropic');
    assert.equal(apiFor('/v1/chat/completions/'), 'chat');
    assert.equal(apiFor('/v1/responses?x=1'), 'responses');
    assert.equal(apiFor('/v1/messages/count_tokens'), 'other');
  });
  const restoreStream = (api: 'other' | 'anthropic', events: unknown[]) => {
    const r = new SseRestorer(v, api);
    const out = events.flatMap((d) => r.transform({ head: [], data: JSON.stringify(d) }));
    out.push(...r.finish());
    return out.map((e) => e.data ?? '').join('\n');
  };
  it('a stream on an unknown path is recognised by its first event (chat)', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const chunks = [ph.slice(0, 9), ph.slice(9, 20), ph.slice(20), ' ok'].map((c) => ({ object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: c } }] }));
    const out = restoreStream('other', chunks);
    const text = out.split('\n').map((l) => JSON.parse(l).choices[0]?.delta?.content ?? '').join('');
    assert.equal(text, `${EMAIL} ok`);
  });
  it('Anthropic error events (and other event types) are restored too', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const out = restoreStream('anthropic', [{ type: 'error', error: { type: 'invalid_request_error', message: `bad address ${ph}` } }]);
    assert.ok(out.includes(EMAIL) && !out.includes('[[REDACTED:'), out);
  });
});

// ---- through the proxy --------------------------------------------------------------------------
let upstream: Server;
let up = '';
let lastRaw = '';
const proxies: Server[] = [];
async function start(opts: Partial<Parameters<typeof createProxy>[0]> = {}): Promise<string> {
  const p = createProxy({ vault: v, upstreams: { mock: up }, redact: {}, ...opts });
  await new Promise<void>((r) => p.listen(0, '127.0.0.1', r));
  proxies.push(p);
  return `http://127.0.0.1:${(p.address() as AddressInfo).port}`;
}
let px = '';

before(async () => {
  upstream = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    lastRaw = Buffer.concat(chunks).toString('utf8');
    const path = (req.url ?? '').split('?')[0];
    if (path === '/redirect-same') return res.writeHead(307, { location: '/v1/other' }).end();
    if (path === '/redirect-away') return res.writeHead(307, { location: 'https://elsewhere.example/collect' }).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ ok: true, path }));
  });
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  up = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  px = await start();
});
after(() => {
  upstream.close();
  for (const p of proxies) p.close();
});

const post = (base: string, path: string, body: string | Uint8Array, headers: Record<string, string> = {}) => fetch(base + path, { method: 'POST', headers, body, redirect: 'manual' });
const msg = JSON.stringify({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: `key ${SECRET}, mail ${EMAIL}` }] });

describe('proxy: fails closed', () => {
  it('a JSON body with a BOM is redacted, not forwarded as it came', async () => {
    lastRaw = '';
    const res = await post(px, '/mock/v1/messages', String.fromCharCode(0xfeff) + msg, { 'content-type': 'application/json' });
    assert.equal(res.status, 200);
    noLeak(lastRaw, SECRET, EMAIL);
    assert.match(lastRaw, PH);
  });
  it('invalid JSON is refused (400) and nothing reaches the upstream', async () => {
    lastRaw = 'untouched';
    const res = await post(px, '/mock/v1/messages', `{"messages": "${SECRET}"`, { 'content-type': 'application/json' });
    assert.equal(res.status, 400);
    assert.equal(lastRaw, 'untouched');
  });
  it('text/plain bodies are redacted as text', async () => {
    const res = await post(px, '/mock/v1/notes', `key ${SECRET}`, { 'content-type': 'text/plain' });
    assert.equal(res.status, 200);
    noLeak(lastRaw, SECRET);
  });
  it('multipart uploads are refused (415) unless --allow-unredacted', async () => {
    lastRaw = 'untouched';
    const form = new FormData();
    form.append('file', new Blob([`OPENAI_API_KEY=${SECRET}`]), '.env');
    const refused = await fetch(px + '/mock/v1/files', { method: 'POST', body: form });
    assert.equal(refused.status, 415);
    assert.equal(lastRaw, 'untouched');
    const open = await start({ allowUnredacted: true });
    const ok = await fetch(open + '/mock/v1/files', { method: 'POST', body: form });
    assert.equal(ok.status, 200);
    assert.ok(lastRaw.includes(SECRET), 'forwarded as is when the user asked for it');
  });
  it('deep nesting is refused (413), not forwarded and not a crash', async () => {
    const deep = '['.repeat(10000) + ']'.repeat(10000);
    const res = await post(px, '/mock/v1/messages', `{"messages":${deep}}`, { 'content-type': 'application/json' });
    assert.equal(res.status, 413);
    assert.equal((await fetch(px + '/')).status, 200, 'still serving');
  });
  it('a gzip bomb is refused (413) without inflating it', async () => {
    const small = await start({ maxBody: 1024 * 1024 });
    const bomb = gzipSync(Buffer.alloc(64 * 1024 * 1024));
    const res = await post(small, '/mock/v1/messages', new Uint8Array(bomb), { 'content-type': 'application/json', 'content-encoding': 'gzip' });
    assert.equal(res.status, 413);
  });
});

describe('proxy: redirects', () => {
  it('a redirect within the upstream is pointed back through the proxy', async () => {
    const res = await post(px, '/mock/redirect-same', msg, { 'content-type': 'application/json' });
    assert.equal(res.status, 307);
    assert.equal(res.headers.get('location'), `${px}/mock/v1/other`);
  });
  it('a redirect anywhere else is refused: the client would re-send its unredacted body there', async () => {
    const res = await post(px, '/mock/redirect-away', msg, { 'content-type': 'application/json' });
    assert.equal(res.status, 502);
    assert.equal(res.headers.get('location'), null);
  });
});

describe('proxy: hostile requests', () => {
  const raw = (base: string, path: string) =>
    new Promise<number>((resolve) => {
      const u = new URL(base);
      const r = request({ host: u.hostname, port: u.port, path, method: 'GET' }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      r.on('error', () => resolve(-1));
      r.end();
    });
  it('/__proto__ and /constructor are not upstreams', async () => {
    assert.equal(await raw(px, '/__proto__/x'), 404);
    assert.equal(await raw(px, '/constructor/x'), 404);
  });
  it('a malformed URL gets an error, and the proxy keeps serving', async () => {
    const status = await raw(px, '//[');
    assert.ok(status >= 400 && status < 500, String(status));
    assert.equal((await fetch(px + '/')).status, 200);
  });
});

describe('proxy: --require-token', () => {
  const TOKEN = '0123456789abcdef0123456789abcdef';
  it('answers only under its token; redirects keep the token', async () => {
    const base = await start({ token: TOKEN });
    assert.equal((await fetch(base + '/')).status, 403);
    assert.equal((await post(base, '/mock/v1/messages', msg, { 'content-type': 'application/json' })).status, 403);
    assert.equal((await post(base, '/' + TOKEN.replace(/.$/, '0') + '/mock/v1/messages', msg, { 'content-type': 'application/json' })).status, 403);
    assert.equal((await fetch(`${base}/${TOKEN}/`)).status, 200);
    const ok = await post(base, `/${TOKEN}/mock/v1/messages`, msg, { 'content-type': 'application/json' });
    assert.equal(ok.status, 200);
    noLeak(lastRaw, SECRET, EMAIL);
    const red = await post(base, `/${TOKEN}/mock/redirect-same`, msg, { 'content-type': 'application/json' });
    assert.equal(red.headers.get('location'), `${base}/${TOKEN}/mock/v1/other`);
  });
});
