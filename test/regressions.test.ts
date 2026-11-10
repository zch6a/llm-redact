/**
 * Regression tests for the round-1 leak review: every finding gets a test that failed before its
 * fix. All values are synthetic.
 */
import assert from 'node:assert/strict';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { apiFor, parseJson, redactForm, redactRequest, restoreResponse } from '../src/body.ts';
import { createProxy } from '../src/proxy.ts';
import { RedactLimitError, redactText } from '../src/redact.ts';
import { NdjsonRestorer, SseParser, SseRestorer } from '../src/sse.ts';
import { Vault } from '../src/vault.ts';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>;
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
  it('url_password redacts the password span even when the host repeats it', () => {
    // The password span is found by position (not by searching for the value); its other
    // occurrence — here, absurdly, in the host — is then a known secret and redacted too.
    const r = redactText('postgres://postgres:Pg-Pass9x@Pg-Pass9x.db.internal:5432/app', new Vault(Buffer.alloc(32, 11)));
    assert.match(r.text, /^postgres:\/\/postgres:(\[\[REDACTED:url_password:[0-9a-f]{8}\]\])@\1\.db\.internal:5432\/app$/);
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
let lastBytes = Buffer.alloc(0);

before(async () => {
  upstream = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    lastBytes = Buffer.concat(chunks);
    lastRaw = lastBytes.toString('utf8');
    const path = (req.url ?? '').split('?')[0];
    if (path === '/api/chat') {
      // Ollama-style NDJSON: the first placeholder of the request, split across three lines.
      const ph = PH.exec(lastRaw)?.[0] ?? '';
      const line = (content: string, done = false) => JSON.stringify({ model: 'm', message: { role: 'assistant', content }, done }) + '\n';
      res.writeHead(200, { 'content-type': 'application/x-ndjson' });
      res.write(line('pw: ' + ph.slice(0, 7)));
      res.write(line(ph.slice(7, 20)));
      res.write(line(ph.slice(20) + ' ok'));
      return res.end(line('', true));
    }
    // ---- round 3 (response side)
    const firstPh = /\[\[REDACTED:secret_assignment:[0-9a-f]{8}\]\]/.exec(lastRaw)?.[0] ?? PH.exec(lastRaw)?.[0] ?? '';
    if (path === '/r3/psql') return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ id: 'm', type: 'message', role: 'assistant', content: [{ type: 'text', text: `Running psql with ${firstPh}.` }] }));
    if (path === '/r3/numbers') return res.writeHead(200, { 'content-type': 'application/json' }).end(`{"content":[{"type":"tool_use","id":"t","name":"x","input":{"order":12345678901234567890,"price":1.10,"k":"${firstPh}"}}]}`);
    if (path === '/r3/cookies') return res.writeHead(200, [['content-type', 'application/json'], ['content-length', '2'], ['set-cookie', 'a=1; path=/'], ['set-cookie', 'b=2; path=/']]).end(req.method === 'HEAD' ? undefined : '{}');
    if (path === '/r3/untyped') return res.writeHead(200).end(JSON.stringify({ text: firstPh }));
    if (path === '/r3/text') return res.writeHead(500, { 'content-type': 'text/plain' }).end(`bad value ${firstPh}`);
    if (path === '/r3/compress') return res.writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'compress' }).end(Buffer.from([31, 157, 1, 2, 3]));
    if (path === '/r3/huge') return res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ x: 'y'.repeat(2 * 1024 * 1024) }));
    if (path === '/r3/endless') {
      res.writeHead(200, { 'content-type': 'text/event-stream' });
      res.write('data: ');
      const chunk = 'z'.repeat(64 * 1024);
      let n = 0;
      const t = setInterval(() => {
        if (res.destroyed || n++ > 100) return clearInterval(t), res.end();
        res.write(chunk);
      }, 1);
      return;
    }
    if (path === '/r3/cut') return res.writeHead(200, { 'content-type': 'text/event-stream' }).end(`data: {"type":"message_stop"}\n\ndata: {"partial": "${firstPh}`);
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

// ==== Round 2 leak review ========================================================================
// (numbers are the review's finding numbers)

const TRICKY = 'P"a\\ss-W0rd-9xQz';
const chatBody = (extra: Record<string, unknown>) => ({ model: 'm', messages: [{ role: 'user', content: 'hi' }], ...extra });

describe('round 2: walker', () => {
  it('#1 Predicted Outputs content is redacted (it is the file being rewritten)', () => {
    noLeak(sent(chatBody({ prediction: { type: 'content', content: `OPENAI_API_KEY=${SECRET}\nADMIN=${EMAIL}` } }), 'chat'), SECRET, EMAIL);
    noLeak(sent(chatBody({ prediction: { type: 'content', content: [{ type: 'text', text: `k ${SECRET}` }] } }), 'chat'), SECRET);
  });
  it('#11 metadata is redacted (providers store it); a message participant name too', () => {
    noLeak(sent(chatBody({ metadata: { owner: EMAIL } }), 'chat'), EMAIL);
    const s = sent({ model: 'm', messages: [{ role: 'user', name: 'AKIAQWERTYUIOP234567', content: 'hi' }] }, 'chat');
    noLeak(s, 'AKIAQWERTYUIOP234567');
  });
  it('#11 a block is signed only when it carries a signature', () => {
    noLeak(sent({ model: 'm', messages: [{ role: 'user', content: [{ type: 'thinking', thinking: `key ${SECRET}` }] }] }), SECRET);
    const signed = { type: 'thinking', thinking: `key ${SECRET}`, signature: 'sig' };
    assert.deepEqual(JSON.parse(sent({ model: 'm', messages: [{ role: 'assistant', content: [signed] }] })).messages[0].content[0], signed);
    // OpenRouter reasoning details with a signature: byte for byte.
    const detail = { type: 'reasoning.text', text: `about ${EMAIL}`, signature: 'sig2' };
    assert.deepEqual(JSON.parse(sent(chatBody({ messages: [{ role: 'assistant', content: 'x', reasoning_details: [detail] }] }), 'chat')).messages.at(-1).reasoning_details[0], detail);
  });
  it('#4 a string that merely starts like a data: URL is text', () => {
    noLeak(sent({ model: 'm', messages: [{ role: 'user', content: `data:text/plain;base64,aGk= <- what is this? my key is ${SECRET}` }] }), SECRET);
  });
  it('#7 base64-looking start under a "data" key does not hide what follows', () => {
    const hashes = Array.from({ length: 70 }, (_, i) => (i * 2654435761).toString(16).padStart(40, 'a')).join('\n');
    noLeak(sent({ model: 'm', messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'text', media_type: 'text/plain', data: `${hashes}\nOPENAI_API_KEY=${SECRET}` } }] }] }), SECRET);
  });
  it('text files sent as base64 are decoded and redacted; binary files are left alone', () => {
    const file = Buffer.from(`OPENAI_API_KEY=${SECRET}\n`).toString('base64');
    const a = JSON.parse(sent({ model: 'm', input: [{ role: 'user', content: [{ type: 'input_file', filename: '.env', file_data: `data:text/plain;base64,${file}` }] }] }, 'responses'));
    const decodedA = Buffer.from(a.input[0].content[0].file_data.split(',')[1], 'base64').toString();
    assert.match(decodedA, /^OPENAI_API_KEY=\[\[REDACTED:openai_key:[0-9a-f]{8}\]\]\n$/);
    const b = JSON.parse(sent({ model: 'm', messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'base64', media_type: 'text/plain', data: file } }] }] }));
    noLeak(Buffer.from(b.messages[0].content[0].source.data, 'base64').toString(), SECRET);
    const png = 'data:image/png;base64,' + Buffer.from(`\x89PNG ${SECRET}`, 'latin1').toString('base64');
    assert.ok(sent({ model: 'm', messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: png } }] }] }, 'chat').includes(png));
  });
  it('#5 card and phone numbers written as JSON numbers are redacted', () => {
    noLeak(sent(toolUse({ card: 4111111111111111, phone: 13912345678, qty: 3, ts: 1731300000 })), '4111111111111111', '13912345678');
    const body = { model: 'm', messages: [{ role: 'assistant', tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: '{"card": 4111111111111111, "n": 2}' } }] }] };
    noLeak(sent(body, 'chat'), '4111111111111111');
    assert.match(sent(toolUse({ ts: 1731300000 })), /"ts":1731300000/);
  });
  // Exact numbers need JSON.rawJSON (every supported Node has it; CI also runs the suite without it).
  it('#14 numbers are kept exactly as written; "__proto__" keys are kept', { skip: typeof (JSON as { rawJSON?: unknown }).rawJSON !== 'function' && 'needs JSON.rawJSON' }, () => {
    const raw = '{"model":"m","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t","name":"n","input":{"order_id":12345678901234567890,"price":1.10,"__proto__":{"x":1},"mail":"' + EMAIL + '"}}]}]}';
    const s = JSON.stringify(redactRequest(parseJson(raw), v, 'anthropic').body);
    assert.match(s, /"order_id":12345678901234567890,"price":1\.10,"__proto__":\{"x":1\}/);
    noLeak(s, EMAIL);
    const args = '{"order_id": 12345678901234567890, "price": 1.10, "mail": "' + EMAIL + '"}';
    const out = JSON.parse(sent({ model: 'm', messages: [{ role: 'assistant', tool_calls: [{ id: 'c', type: 'function', function: { name: 'f', arguments: args } }] }] }, 'chat'));
    assert.match(out.messages.find((m: { tool_calls?: unknown }) => m.tool_calls).tool_calls[0].function.arguments, /12345678901234567890.*1\.10/);
  });
  it('#6 unknown APIs: every string and key is data (Ollama, Gemini)', () => {
    const ollama = { model: 'm', messages: [{ role: 'assistant', tool_calls: [{ function: { name: 'f', arguments: { id: SECRET, name: EMAIL, [EMAIL]: 'owner' } } }] }] };
    noLeak(JSON.stringify(redactRequest(ollama, v, 'other').body), SECRET, EMAIL);
    const gemini = { contents: [{ role: 'model', parts: [{ functionCall: { name: 'f', args: { id: SECRET } } }, { functionResponse: { name: 'f', response: { user: EMAIL } } }] }] };
    noLeak(JSON.stringify(redactRequest(gemini, v, 'other').body), SECRET, EMAIL);
    noLeak(JSON.stringify(redactRequest({ text: `k ${SECRET}`, metadata: { m: EMAIL } }, v, 'other').body), SECRET, EMAIL);
  });
  it('tool results are data, whatever the objects in them are called', () => {
    noLeak(sent({ model: 'm', messages: [{ role: 'user', content: [{ type: 'tool_result', tool_use_id: 't', content: [{ name: 'x', id: SECRET, type: 'row' }] }] }] }), SECRET);
  });
});

describe('round 2: engine', () => {
  it('#2 other serializers\' escapes: Go \\u0026 / \\u003c, .NET \\u002B, Python \\u00e4, HTML entities, CSV quotes, percent-encoding', () => {
    const cases: [string, string][] = [
      [String.raw`"{\"password\":\"Ab3\u0026xYz9Qw7\"}"`, 'Ab3'],
      [String.raw`"{\"password\":\"Zq\u003c9xYz9Qw7\"}"`, 'Zq'],
      [String.raw`{\"aws_secret_access_key\":\"wJalrXUtnFEMI\u002FK7MDENG\u002BbPxRfiCYEXAMPLEKEYzz\"}`, 'wJalr'],
      [String.raw`{\"password\": \"P\u00e4ssw0rd-9xQz\"}`, 'ssw0rd'],
      ['{&quot;api_key&quot;:&quot;Zr8kWq3nLp6tVb2x&quot;}', 'Zr8kWq3n'],
      ['"{""api_key"":""Zr8kWq3nLp6tVb2x""}"', 'Zr8kWq3n'],
      ['message=contact+li.wei%40corp-mail.cn&x=1', 'li.wei'],
    ];
    for (const [t, piece] of cases) noLeak(redactText(t, v).text, piece);
  });
  it('#10 pass / pw in JSON text, not inside other words', () => {
    noLeak(redactText('{"db":{"pass":"Xy7pQ2rL9zW"}}', v).text, 'Xy7pQ2rL9zW');
    noLeak(redactText('{"db":{"pw":"Xy7pQ2rL9zW"}}', v).text, 'Xy7pQ2rL9zW');
    // A fresh vault: the shared one already knows Xy7pQ2rL9zW as a password, and would rightly redact it anywhere.
    const fresh = new Vault(Buffer.alloc(32, 12));
    for (const t of ['bypass = Xy7pQ2rL9zW1', 'compass: "Xy7pQ2rL9zW1"', '"pass_rate": f"{delta:+.1f}"']) assert.equal(redactText(t, fresh).text, t);
  });
  it('#12 placeholders already in the text are never redacted again', () => {
    // Labels that name secrets, and tags of 8 distinct characters, were the case that broke.
    for (const ph of ['[[REDACTED:github_token:dc0138f4]]', '[[REDACTED:secret_assignment:f5220cb8]]', '[[REDACTED:openai_key:a3b4c5d6]]']) {
      for (const t of [ph, `token=${ph}`, `I will use ${ph} here`, JSON.stringify({ password: ph })]) assert.equal(redactText(t, v).text, t);
    }
  });
  it('#15 the label depends on the value, not on what saw it first', () => {
    const a = new Vault(Buffer.alloc(32, 8));
    const b = new Vault(Buffer.alloc(32, 8));
    redactText(`password = ${SECRET}`, a); // first seen through the generic rule
    assert.equal(redactText(`key ${SECRET}`, a).text, redactText(`key ${SECRET}`, b).text);
    assert.match(redactText(`password = ${SECRET}`, b).text, /openai_key/);
    // Under a secret-named JSON key (a fresh vault: a vault returns what it already gave a value).
    assert.match(JSON.stringify(redactRequest(toolUse({ password: SECRET }), new Vault(Buffer.alloc(32, 9)), 'anthropic').body), /\[\[REDACTED:openai_key:/);
  });
  it('#3 too many values is a refusal, not a partial redaction', () => {
    assert.throws(() => redactText('a.b@corp-mail.cn '.repeat(1_000_001), v), RedactLimitError);
    const t = 'a.b@corp-mail.cn '.repeat(100_001) + EMAIL;
    noLeak(redactText(t, v).text, EMAIL);
    noLeak(redactText('x@1.2.cc '.repeat(300_000) + EMAIL, v).text, EMAIL);
  });
  it('#17 #18 no quadratic work: escaped text and many distinct values', () => {
    let t0 = Date.now();
    redactText('\\"' + `${EMAIL} `.repeat(40_000), v);
    // Generous bounds (other tests run alongside); the quadratic versions took 13 s and 9.7 s.
    assert.ok(Date.now() - t0 < 4000, `escaped: ${Date.now() - t0} ms`);
    t0 = Date.now();
    redactText(Array.from({ length: 100_000 }, (_, i) => `u${i}@corp-mail.cn`).join(' '), v);
    assert.ok(Date.now() - t0 < 5000, `distinct: ${Date.now() - t0} ms`);
  });
});

describe('round 2: streams', () => {
  it('#16 reasoning summaries are not restored (they go back verbatim, next to encrypted content)', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const r = new SseRestorer(v, 'responses');
    for (const d of [
      { type: 'response.reasoning_summary_text.delta', item_id: 'rs_1', summary_index: 0, delta: `Mail ${ph}` },
      { type: 'response.reasoning_summary_part.done', item_id: 'rs_1', summary_index: 0, part: { type: 'summary_text', text: `Mail ${ph}` } },
      { type: 'response.output_item.done', output_index: 0, item: { type: 'reasoning', id: 'rs_1', summary: [{ type: 'summary_text', text: `Mail ${ph}` }] } },
    ])
      for (const e of r.transform({ head: [], data: JSON.stringify(d) })) noLeak(e.data ?? '', EMAIL);
  });
  it('DeepSeek reasoning_content is restored like text (it is not signed)', () => {
    const ph = v.placeholderFor('email', EMAIL);
    const r = new SseRestorer(v, 'chat');
    const chunks = [ph.slice(0, 10), ph.slice(10)].map((p) => ({ object: 'chat.completion.chunk', choices: [{ index: 0, delta: { reasoning_content: p } }] }));
    const out = [...chunks.flatMap((d) => r.transform({ head: [], data: JSON.stringify(d) })), ...r.finish()];
    assert.equal(out.map((e) => JSON.parse(e.data ?? '{}').choices?.[0]?.delta?.reasoning_content ?? '').join(''), EMAIL);
  });
  it('#19 SSE: a 16 MB event is not re-scanned per chunk; CR-only line ends work', () => {
    const p = new SseParser();
    const ev = 'data: ' + 'x'.repeat(16 * 1024 * 1024) + '\n\n';
    const t0 = Date.now();
    let n = 0;
    for (let i = 0; i < ev.length; i += 16384) n += p.feed(ev.slice(i, i + 16384)).length;
    assert.equal(n, 1);
    assert.ok(Date.now() - t0 < 1000, `${Date.now() - t0} ms`);
    const q = new SseParser();
    const evs = [...q.feed('data: 1\r\rdata: 2\r'), ...q.feed('\n\r\n')];
    assert.deepEqual(evs.map((e) => e.data), ['1', '2']);
    assert.deepEqual(q.end(), { events: [], rest: '' });
  });
});

describe('round 2: proxy', () => {
  it('#8 form bodies: percent-encoded values are found', () => {
    const r = redactForm(`message=contact+li.wei%40corp-mail.cn&dsn=postgres%3A%2F%2Fapp%3ASecr3tPw9%40db.internal%2Fx&n=1`, v);
    const decoded = decodeURIComponent(r.text.replace(/\+/g, ' '));
    noLeak(decoded, EMAIL, 'Secr3tPw9');
    assert.ok(r.text.endsWith('&n=1'), 'untouched fields stay as they were');
  });
  it('#8 through the proxy: fields are decoded the way the server will decode them ("+" is a space)', async () => {
    const res = await post(px, '/mock/v1/form', 'message=contact+li.wei%40corp-mail.cn&note=password+%3D+Xy7pQ2rL9zW', { 'content-type': 'application/x-www-form-urlencoded' });
    assert.equal(res.status, 200);
    const decoded = decodeURIComponent(lastRaw.replace(/\+/g, ' '));
    noLeak(decoded, EMAIL, 'Xy7pQ2rL9zW');
  });
  it('#9 text in a charset other than UTF-8 is refused; with --allow-unredacted it goes out byte for byte', async () => {
    const utf16 = Buffer.from(`key ${SECRET}`, 'utf16le');
    lastRaw = 'untouched';
    assert.equal((await post(px, '/mock/v1/notes', new Uint8Array(utf16), { 'content-type': 'text/plain; charset=utf-16le' })).status, 415);
    assert.equal(lastRaw, 'untouched');
    const open = await start({ allowUnredacted: true });
    assert.equal((await post(open, '/mock/v1/notes', new Uint8Array(utf16), { 'content-type': 'text/plain; charset=utf-16le' })).status, 200);
    assert.ok(lastBytes.equals(utf16));
  });
  it('#13 NDJSON streams (Ollama) are restored line by line and stay valid JSON', async () => {
    const res = await post(px, '/mock/api/chat', JSON.stringify({ model: 'm', messages: [{ role: 'user', content: `DB_PASSWORD=${TRICKY}` }] }), { 'content-type': 'application/json' });
    const lines = (await res.text()).split('\n').filter(Boolean).map((l) => JSON.parse(l) as { message: { content: string } });
    assert.equal(lines.map((l) => l.message.content).join(''), `pw: ${TRICKY} ok`);
    noLeak(lastRaw, 'W0rd-9xQz');
  });
  it('#20 Expect: 100-continue (curl) works', async () => {
    const u = new URL(px);
    const status = await new Promise<number>((resolve) => {
      const r = request({ host: u.hostname, port: u.port, path: '/mock/v1/messages', method: 'POST', headers: { 'content-type': 'application/json', expect: '100-continue' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      r.on('continue', () => r.end(msg));
      r.on('error', () => resolve(-1));
    });
    assert.equal(status, 200);
    noLeak(lastRaw, SECRET);
  });
});
// ==== Round 3 review: the response side =========================================================

describe('round 3: values restored once are never sent in clear again', () => {
  it('#1 a password found by its context, restored, then written elsewhere by the model, stays redacted next turn', async () => {
    const base = await start({ vault: new Vault(Buffer.alloc(32, 31)) });
    const turn1 = [{ role: 'user', content: 'Connect with DB_PASSWORD=Tr0ub4dor-zq9x please' }];
    const r1 = await post(base, '/mock/r3/psql', JSON.stringify({ model: 'm', max_tokens: 1, messages: turn1 }), { 'content-type': 'application/json' });
    noLeak(lastRaw, 'Tr0ub4dor-zq9x');
    const reply = (await r1.json()) as { content: { type: string; text: string }[] };
    assert.equal(reply.content[0]?.text, 'Running psql with Tr0ub4dor-zq9x.', 'the client gets the real value');
    // Turn 2: the client sends its history back — the model's reply now holds the bare value.
    const turn2 = [...turn1, { role: 'assistant', content: reply.content }, { role: 'user', content: 'and now as psql -W Tr0ub4dor-zq9x' }];
    await post(base, '/mock/r3/psql', JSON.stringify({ model: 'm', max_tokens: 1, messages: turn2 }), { 'content-type': 'application/json' });
    noLeak(lastRaw, 'Tr0ub4dor-zq9x');
    assert.equal((lastRaw.match(/\[\[REDACTED:secret_assignment:[0-9a-f]{8}\]\]/g) ?? []).length >= 3, true, 'same placeholder in all three places');
  });
  it('known values are found in the same text that taught them, and in encoded forms', () => {
    const fresh = new Vault(Buffer.alloc(32, 32));
    const r = redactText('API_TOKEN=Zq8-mW3pL7vT2k\nthen curl -H "X-Key: Zq8-mW3pL7vT2k"', fresh);
    noLeak(r.text, 'Zq8-mW3pL7vT2k');
    noLeak(redactText(JSON.stringify(JSON.stringify({ k: 'Zq8-mW3pL7vT2k' })), fresh).text, 'Zq8-mW3pL7vT2k');
    // Short values are not searched for everywhere (they would match ordinary text).
    redactText('PASSWORD=Ab1-x9Q', fresh);
    assert.equal(redactText('Ab1-x9Q is a SKU', fresh).text, 'Ab1-x9Q is a SKU');
  });
});

describe('round 3: response bodies', () => {
  it('#4 numbers in a restored response are exactly as the upstream wrote them', { skip: typeof (JSON as { rawJSON?: unknown }).rawJSON !== 'function' && 'needs JSON.rawJSON' }, async () => {
    await post(px, '/mock/v1/messages', JSON.stringify({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: `DB_PASSWORD=${TRICKY}` }] }), { 'content-type': 'application/json' });
    const res = await post(px, '/mock/r3/numbers', JSON.stringify({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: `DB_PASSWORD=${TRICKY}` }] }), { 'content-type': 'application/json' });
    const text = await res.text();
    assert.match(text, /"order":12345678901234567890,"price":1\.10/);
    assert.equal(JSON.parse(text).content[0].input.k, TRICKY);
  });
  it('#7 a tool parameter called "arguments" is not JSON-escaped twice', () => {
    const ph = v.placeholderFor('secret_assignment', TRICKY);
    const out = restoreResponse({ content: [{ type: 'tool_use', id: 't', name: 'run', input: { arguments: ph } }] }, v, 'anthropic') as { content: { input: { arguments: string } }[] };
    assert.equal(out.content[0]?.input.arguments, TRICKY);
    // …while the envelope's own JSON-text arguments are escaped (they are JSON text).
    const chat = restoreResponse({ choices: [{ message: { tool_calls: [{ function: { name: 'f', arguments: `{"p":"${ph}"}` } }] } }] }, v, 'chat') as Json;
    assert.equal(JSON.parse(chat.choices[0].message.tool_calls[0].function.arguments).p, TRICKY);
  });
  it('#16 every Set-Cookie survives; HEAD keeps its length; untyped JSON and text/plain are restored', async () => {
    const body = JSON.stringify({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: `DB_PASSWORD=${TRICKY}` }] });
    const c = await post(px, '/mock/r3/cookies', body, { 'content-type': 'application/json' });
    assert.deepEqual(c.headers.getSetCookie(), ['a=1; path=/', 'b=2; path=/']);
    const head = await fetch(px + '/mock/r3/cookies', { method: 'HEAD' });
    assert.equal(head.headers.get('content-length'), '2');
    assert.equal(((await (await post(px, '/mock/r3/untyped', body, { 'content-type': 'application/json' })).json()) as { text: string }).text, TRICKY);
    assert.equal(await (await post(px, '/mock/r3/text', body, { 'content-type': 'application/json' })).text(), `bad value ${TRICKY}`);
  });
  it('#16 a content-encoding fetch cannot undo goes through untouched, header and bytes', async () => {
    const res = await post(px, '/mock/r3/compress', msg, { 'content-type': 'application/json' });
    assert.equal(res.headers.get('content-encoding'), 'compress');
    assert.deepEqual([...new Uint8Array(await res.arrayBuffer())], [31, 157, 1, 2, 3]);
  });
  it('#6 response size is bounded: a huge JSON body or an endless SSE event ends the response, not the proxy', async () => {
    const small = await start({ maxBody: 1024 * 1024 });
    assert.equal((await post(small, '/mock/r3/huge', msg, { 'content-type': 'application/json' })).status, 502);
    const endless = await post(small, '/mock/r3/endless', msg, { 'content-type': 'application/json' });
    await assert.rejects(endless.text());
    assert.equal((await fetch(small + '/')).status, 200, 'still serving');
  });
  it('#14 an event cut off at the end goes out as the bytes it was (a client discards it)', async () => {
    const res = await post(px, '/mock/r3/cut', JSON.stringify({ model: 'm', max_tokens: 1, stream: true, messages: [{ role: 'user', content: `DB_PASSWORD=${TRICKY}` }] }), { 'content-type': 'application/json' });
    const text = await res.text();
    assert.ok(text.endsWith('data: {"partial": "[[REDACTED:secret_assignment:' + /secret_assignment:([0-9a-f]{8})/.exec(text)![1] + ']]'), text);
  });
  it('#15 invalid JSON is passed through as it came, not blindly restored (signed thinking stays intact)', () => {
    // The proxy's JSON fallback: nothing to test here beyond restoreResponse refusing deep bodies.
    let deep: unknown = { type: 'text', text: v.placeholderFor('email', EMAIL) };
    for (let i = 0; i < 1000; i++) deep = [deep];
    assert.throws(() => restoreResponse(deep, v, 'anthropic'), /nested deeper/);
  });
});

describe('round 3: streams', () => {
  const ph = () => v.placeholderFor('secret_assignment', TRICKY);
  const through = (api: 'anthropic' | 'chat' | 'responses' | 'other', events: unknown[], heads?: string[][]) => {
    const r = new SseRestorer(v, api);
    const out = events.flatMap((d, i) => r.transform({ head: heads?.[i] ?? [], data: JSON.stringify(d) }));
    out.push(...r.finish());
    return out;
  };
  const datas = (out: { data: string | null }[]) => out.map((e) => JSON.parse(e.data ?? 'null') as Json);
  it('#8 Responses: error, refusal, MCP arguments, annotations are restored', () => {
    const p = ph();
    const out = datas(through('responses', [
      { type: 'response.refusal.delta', item_id: 'm', output_index: 0, content_index: 0, delta: `no: ${p}` },
      { type: 'response.refusal.done', item_id: 'm', output_index: 0, content_index: 0, refusal: `no: ${p}` },
      { type: 'response.mcp_call_arguments.delta', item_id: 'c', output_index: 1, delta: `{"k":"${p}"}` },
      { type: 'response.mcp_call_arguments.done', item_id: 'c', output_index: 1, arguments: `{"k":"${p}"}` },
      { type: 'response.output_text.annotation.added', item_id: 'm', annotation: { type: 'url_citation', title: p } },
      { type: 'error', code: 'x', message: `bad ${p}` },
    ]));
    const s = JSON.stringify(out);
    assert.ok(!s.includes('[[REDACTED:'), s);
    assert.equal(JSON.parse(out[3]!.arguments).k, TRICKY);
  });
  it('#9 Anthropic citations are restored when streamed', () => {
    const out = datas(through('anthropic', [{ type: 'content_block_delta', index: 0, delta: { type: 'citations_delta', citation: { type: 'char_location', cited_text: `see ${ph()}` } } }]));
    assert.equal(out[0]!.delta.citation.cited_text, `see ${TRICKY}`);
  });
  it('#10 held-back text is flushed when a Responses stream ends without its done event', () => {
    const out = datas(through('responses', [{ type: 'response.output_text.delta', item_id: 'm', output_index: 0, content_index: 0, delta: 'see x[', sequence_number: 3 }]));
    assert.equal(out.map((d) => d.delta).join(''), 'see x[');
  });
  it('#11 a made-up tail event has no id: line and its own sequence number', () => {
    const out = through('responses', [
      { type: 'response.output_text.delta', item_id: 'm', output_index: 0, content_index: 0, delta: 'x[[RED', sequence_number: 5 },
      { type: 'response.output_text.done', item_id: 'm', output_index: 0, content_index: 0, text: 'x[[RED', sequence_number: 6 },
    ], [['id: 41', 'event: response.output_text.delta'], ['id: 42', 'event: response.output_text.done']]);
    assert.deepEqual(out.map((e) => e.head), [['id: 41', 'event: response.output_text.delta'], ['event: response.output_text.delta'], ['id: 42', 'event: response.output_text.done']]);
    assert.deepEqual(datas(out).map((d) => d.sequence_number), [5, 6, 7]);
  });
  it('#12 Chat: the tail goes into the finish chunk; usage is not repeated', () => {
    const out = datas(through('chat', [
      { id: 'c', choices: [{ index: 0, delta: { content: 'ends with [' }, finish_reason: null }] },
      { id: 'c', choices: [{ index: 0, finish_reason: 'stop' }] },
      { id: 'c', choices: [], usage: { total_tokens: 10 } },
    ]));
    assert.equal(out.length, 3);
    assert.equal(out[1]!.choices[0].delta.content, '[');
    assert.equal(out.filter((d) => d.usage).length, 1);
  });
  it('#12 a flush chunk never copies usage (streams that report usage in every chunk)', () => {
    const out = datas(through('chat', [
      { id: 'c', choices: [{ index: 0, delta: { content: 'cut at [' }, finish_reason: null }], usage: { total_tokens: 7 } },
    ]));
    assert.equal(out.length, 2, 'the chunk, then the flushed tail');
    assert.equal(out[1]!.choices[0].delta.content, '[');
    assert.equal(out[1]!.usage, undefined);
  });
  it('#4 numbers in streamed events are exactly as the upstream wrote them', { skip: typeof (JSON as { rawJSON?: unknown }).rawJSON !== 'function' && 'needs JSON.rawJSON' }, () => {
    const out = through('anthropic', [{ type: 'message_delta', delta: { stop_reason: 'end_turn' }, usage: { output_tokens: 5 }, x: 12345678901234567890, y: 1.1 }]);
    const r = new SseRestorer(v, 'anthropic');
    const raw = '{"type":"message_delta","usage":{"output_tokens":5},"x":12345678901234567890,"y":1.10}';
    assert.equal(r.transform({ head: [], data: raw })[0]?.data, raw);
    assert.equal(out.length, 1);
  });
  it('#13 server and MCP tool blocks: input restored at the start, tails as JSON deltas', () => {
    const out = datas(through('anthropic', [
      { type: 'content_block_start', index: 0, content_block: { type: 'mcp_tool_use', id: 'x', name: 'n', server_name: 's', input: { k: ph() } } },
      { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: '{"a":[' } },
      { type: 'content_block_stop', index: 0 },
    ]));
    assert.equal(out[0]!.content_block.input.k, TRICKY);
    assert.equal(out[2]!.delta.type, 'input_json_delta');
  });
  it('#15 an event the proxy cannot process goes through as it came; the stream goes on', () => {
    let deep = '"x"';
    for (let i = 0; i < 1000; i++) deep = `[${deep}]`;
    const r = new SseRestorer(v, 'anthropic');
    const odd = `{"type":"message_delta","deep":${deep}}`;
    assert.deepEqual(r.transform({ head: [], data: odd }), [{ head: [], data: odd }]);
    assert.equal(r.transform({ head: [], data: '{"type":"message_stop"}' }).length, 1);
  });
  it('#18 #19 #20 reasoning is never restored, streamed or not, in any format', () => {
    const p = ph();
    const s = (x: unknown) => JSON.stringify(x);
    // Responses: reasoning_text content parts.
    assert.ok(s(datas(through('responses', [{ type: 'response.content_part.done', item_id: 'r', part: { type: 'reasoning_text', text: p } }]))).includes(p));
    // OpenRouter reasoning summary in a non-streamed Chat body.
    assert.ok(s(restoreResponse({ choices: [{ message: { content: 'x', reasoning_details: [{ type: 'reasoning.summary', summary: p }] } }] }, v, 'chat')).includes(p));
    // Unsigned Anthropic thinking, non-streamed (it is not restored as thinking_delta either).
    assert.ok(s(restoreResponse({ content: [{ type: 'thinking', thinking: p }] }, v, 'anthropic')).includes(p));
    // NDJSON: a signed thinking line.
    const line = JSON.stringify({ type: 'thinking', thinking: p, signature: 'sig' });
    assert.equal(new NdjsonRestorer(v).feed(line + '\n'), line + '\n');
  });
  it('#5 NDJSON lines are not rescanned per chunk (8 MB line in 1 KB chunks)', () => {
    const nd = new NdjsonRestorer(v);
    const line = JSON.stringify({ message: { content: 'y'.repeat(8 * 1024 * 1024) }, done: true }) + '\n';
    const t0 = Date.now();
    let out = '';
    for (let i = 0; i < line.length; i += 1024) out += nd.feed(line.slice(i, i + 1024));
    assert.ok(Date.now() - t0 < 2000, `${Date.now() - t0} ms`);
    assert.equal(out.length, line.length);
  });
});