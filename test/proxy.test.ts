/**
 * End to end, no network: client → llm-redact → mock upstream (Anthropic, OpenAI Chat, OpenAI
 * Responses; streamed and not). The two invariants: the upstream never sees a real value, and
 * the client always gets it back — in text, in tool-call arguments, however the stream is split.
 */
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import { gzipSync } from 'node:zlib';
import { NOTE } from '../src/body.ts';
import { createProxy } from '../src/proxy.ts';
import { Vault } from '../src/vault.ts';

const SECRET = 'sk-proj-' + 'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2);
const TRICKY = 'P"a\\ss-W0rd-9xQz'; // quotes and a backslash: must survive JSON escaping
const EMAIL = 'li.wei@corp-mail.cn';
const SIGNATURE = 'EqQBCkYIBxgCKkDsig'; // opaque: must come back byte for byte

let upstream: Server;
let proxy: ReturnType<typeof createProxy>;
let up = '';
let px = '';
let lastBody: any = null;
let lastHeaders: Record<string, unknown> = {};
const log: string[] = [];

/** Chop a string into n-character pieces (the stream's deltas). */
const pieces = (s: string, n: number) => Array.from({ length: Math.ceil(s.length / n) }, (_, i) => s.slice(i * n, i * n + n));
const sse = (events: [string | null, unknown][]) => events.map(([ev, d]) => `${ev ? `event: ${ev}\n` : ''}data: ${typeof d === 'string' ? d : JSON.stringify(d)}\n\n`).join('');

/** The mock model: it repeats the first placeholder it was given, in text and in a tool call. */
function reply(body: any): { text: string; args: string; ph: string } {
  const ph = /\[\[REDACTED:[a-z_]+:[0-9a-f]{8}\]\]/.exec(JSON.stringify(body))?.[0] ?? '(none)';
  const pw = /\[\[REDACTED:secret_assignment:[0-9a-f]{8}\]\]/.exec(JSON.stringify(body))?.[0] ?? '(none)';
  return { ph, text: `Saved. Your key is ${ph} — keep it safe.`, args: JSON.stringify({ path: '.env', content: `OPENAI_API_KEY=${ph}\nDB_PASSWORD=${pw}\n` }) };
}

function handle(path: string, body: any, custom = false): { type: string; payload: string } {
  const r = reply(body);
  if (path === '/v1/messages') {
    if (!body.stream)
      return { type: 'application/json', payload: JSON.stringify({ id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'thinking', thinking: `I should repeat ${r.ph}`, signature: SIGNATURE }, { type: 'text', text: r.text }, { type: 'tool_use', id: 'tu_1', name: 'write_file', input: JSON.parse(r.args) }], stop_reason: 'tool_use' }) };
    return {
      type: 'text/event-stream',
      payload: sse([
        ['message_start', { type: 'message_start', message: { id: 'msg_1', role: 'assistant', content: [] } }],
        ['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'thinking', thinking: '' } }],
        ...pieces(`I should repeat ${r.ph}`, 5).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'thinking_delta', thinking: p } }] as [string, unknown]),
        ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'signature_delta', signature: SIGNATURE } }],
        ['content_block_stop', { type: 'content_block_stop', index: 0 }],
        ['content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'text', text: '' } }],
        ...pieces(r.text, 3).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'text_delta', text: p } }] as [string, unknown]),
        ['content_block_stop', { type: 'content_block_stop', index: 1 }],
        ['content_block_start', { type: 'content_block_start', index: 2, content_block: { type: 'tool_use', id: 'tu_1', name: 'write_file', input: {} } }],
        ...pieces(r.args, 4).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 2, delta: { type: 'input_json_delta', partial_json: p } }] as [string, unknown]),
        ['content_block_stop', { type: 'content_block_stop', index: 2 }],
        ['message_delta', { type: 'message_delta', delta: { stop_reason: 'tool_use' } }],
        ['message_stop', { type: 'message_stop' }],
      ]),
    };
  }
  if (path === '/v1/chat/completions') {
    if (!body.stream)
      return { type: 'application/json', payload: JSON.stringify({ id: 'c1', object: 'chat.completion', choices: [{ index: 0, message: { role: 'assistant', content: r.text, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'write_file', arguments: r.args } }] }, finish_reason: 'tool_calls' }] }) };
    const base = { id: 'c1', object: 'chat.completion.chunk', model: 'm' };
    return {
      type: 'text/event-stream',
      payload: sse([
        ...pieces(r.text, 3).map((p) => [null, { ...base, choices: [{ index: 0, delta: { content: p }, finish_reason: null }] }] as [null, unknown]),
        [null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'write_file', arguments: '' } }] }, finish_reason: null }] }],
        ...pieces(r.args, 4).map((p) => [null, { ...base, choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: p } }] }, finish_reason: null }] }] as [null, unknown]),
        [null, { ...base, choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] }],
        [null, '[DONE]'],
      ]),
    };
  }
  if (path === '/v1/responses' && custom) {
    // Codex's apply_patch is a custom (freeform) tool: its input streams as plain text.
    const patch = `*** Begin Patch\n*** Add File: .env\n+OPENAI_API_KEY=${r.ph}\n*** End Patch`;
    let seq = 0;
    const ev = (d: Record<string, unknown>) => [String(d.type), { ...d, sequence_number: seq++ }] as [string, unknown];
    const item = { id: 'ctc_1', type: 'custom_tool_call', call_id: 'call_9', name: 'apply_patch', input: patch };
    return {
      type: 'text/event-stream',
      payload: sse([
        ev({ type: 'response.output_item.added', output_index: 0, item: { ...item, input: '' } }),
        ...pieces(patch, 5).map((p) => ev({ type: 'response.custom_tool_call_input.delta', item_id: 'ctc_1', output_index: 0, delta: p })),
        ev({ type: 'response.custom_tool_call_input.done', item_id: 'ctc_1', output_index: 0, input: patch }),
        ev({ type: 'response.output_item.done', output_index: 0, item }),
        ev({ type: 'response.completed', response: { id: 'resp_2', output: [item] } }),
      ]),
    };
  }
  if (path === '/v1/responses') {
    const item = { id: 'fc_1', type: 'function_call', call_id: 'call_1', name: 'write_file', arguments: r.args };
    const msg = { id: 'msg_1', type: 'message', role: 'assistant', content: [{ type: 'output_text', text: r.text }] };
    const reasoning = { id: 'rs_1', type: 'reasoning', encrypted_content: `enc:${r.ph}`, summary: [] };
    if (!body.stream) return { type: 'application/json', payload: JSON.stringify({ id: 'resp_1', object: 'response', output: [reasoning, msg, item] }) };
    let seq = 0;
    const ev = (d: Record<string, unknown>) => [String(d.type), { ...d, sequence_number: seq++ }] as [string, unknown];
    return {
      type: 'text/event-stream',
      payload: sse([
        ev({ type: 'response.created', response: { id: 'resp_1', output: [] } }),
        ev({ type: 'response.output_item.added', output_index: 0, item: reasoning }),
        ...pieces(r.text, 3).map((p) => ev({ type: 'response.output_text.delta', item_id: 'msg_1', output_index: 1, content_index: 0, delta: p })),
        ev({ type: 'response.output_text.done', item_id: 'msg_1', output_index: 1, content_index: 0, text: r.text }),
        ...pieces(r.args, 4).map((p) => ev({ type: 'response.function_call_arguments.delta', item_id: 'fc_1', output_index: 2, delta: p })),
        ev({ type: 'response.function_call_arguments.done', item_id: 'fc_1', output_index: 2, arguments: r.args }),
        ev({ type: 'response.completed', response: { id: 'resp_1', output: [reasoning, msg, item] } }),
      ]),
    };
  }
  return { type: 'text/plain', payload: `echo ${path}` };
}

before(async () => {
  upstream = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString('utf8');
    lastHeaders = req.headers;
    try {
      lastBody = raw ? JSON.parse(raw) : null;
    } catch {
      lastBody = raw;
    }
    const { type, payload } = handle((req.url ?? '').split('?')[0] as string, lastBody ?? {}, (req.url ?? '').includes('custom=1'));
    res.writeHead(200, { 'content-type': type });
    // Stream the payload in awkward 7-byte network chunks, so SSE events split across reads.
    for (const p of pieces(payload, 7)) res.write(p);
    res.end();
  });
  await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
  up = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  proxy = createProxy({ vault: new Vault(Buffer.alloc(32, 3)), upstreams: { mock: up, dead: 'http://127.0.0.1:9' }, redact: {}, log: (l) => log.push(l) });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
  px = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}/mock`;
});
after(() => {
  upstream.close();
  proxy.close();
});

const userMessage = `Please write my .env:\nOPENAI_API_KEY=${SECRET}\nDB_PASSWORD=${TRICKY}\nAnd mail ${EMAIL} when done.`;

async function call(path: string, body: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(px + path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'test-key-not-secret', ...headers }, body: JSON.stringify(body) });
  return { res, text: await res.text() };
}

/** Parse an SSE body into data payloads. */
const events = (text: string) => text.split(/\n\n/).filter(Boolean).map((b) => b.split('\n').find((l) => l.startsWith('data: '))?.slice(6) ?? '').filter((d) => d && d !== '[DONE]').map((d) => JSON.parse(d));

function upstreamNeverSawSecrets(): string {
  const sent = JSON.stringify(lastBody);
  for (const v of [SECRET, EMAIL, 'W0rd-9xQz']) assert.ok(!sent.includes(v), `upstream saw ${v}`);
  assert.match(sent, /\[\[REDACTED:openai_key:[0-9a-f]{8}\]\]/);
  return sent;
}

function checkRestored(text: string, args: string) {
  assert.ok(text.includes(SECRET), `text not restored: ${text}`);
  const a = JSON.parse(args);
  assert.equal(a.content, `OPENAI_API_KEY=${SECRET}\nDB_PASSWORD=${TRICKY}\n`, 'tool arguments restored and still valid JSON');
}

describe('Anthropic Messages', () => {
  it('non-streamed: redacted upstream, restored for the client, thinking untouched, note in system', async () => {
    const { res, text } = await call('/v1/messages', { model: 'claude-x', max_tokens: 100, system: 'You are helpful.', messages: [{ role: 'user', content: userMessage }] });
    assert.equal(res.status, 200);
    const sent = upstreamNeverSawSecrets();
    assert.equal(lastHeaders['x-api-key'], 'test-key-not-secret', 'headers pass through');
    assert.ok(lastBody.system.endsWith(NOTE) && lastBody.system.startsWith('You are helpful.'), 'note appended to the system prompt');
    assert.ok(sent.includes('claude-x'));
    const body = JSON.parse(text);
    checkRestored(body.content[1].text, JSON.stringify(body.content[2].input));
    assert.equal(body.content[0].signature, SIGNATURE);
    assert.match(body.content[0].thinking, /\[\[REDACTED:/, 'thinking is signed: left as the model wrote it');
  });
  it('streamed: text and tool-call JSON restored across 3- and 4-character deltas and 7-byte network chunks', async () => {
    const { res, text } = await call('/v1/messages', { model: 'claude-x', max_tokens: 100, stream: true, messages: [{ role: 'user', content: userMessage }] });
    assert.match(res.headers.get('content-type') ?? '', /event-stream/);
    upstreamNeverSawSecrets();
    const evs = events(text);
    const txt = evs.filter((e) => e.type === 'content_block_delta' && e.delta.type === 'text_delta').map((e) => e.delta.text).join('');
    const args = evs.filter((e) => e.type === 'content_block_delta' && e.delta.type === 'input_json_delta').map((e) => e.delta.partial_json).join('');
    checkRestored(txt, args);
    const thinking = evs.filter((e) => e.delta?.type === 'thinking_delta').map((e) => e.delta.thinking).join('');
    assert.match(thinking, /\[\[REDACTED:/);
    assert.ok(evs.some((e) => e.delta?.signature === SIGNATURE));
    assert.ok(evs.at(-1).type === 'message_stop');
  });
  it('the next turn: the real values the client got back are redacted to the same placeholders; signed thinking is passed through byte for byte', async () => {
    await call('/v1/messages', { model: 'm', max_tokens: 10, messages: [{ role: 'user', content: userMessage }] });
    const first = JSON.stringify(lastBody);
    const ph = /\[\[REDACTED:openai_key:[0-9a-f]{8}\]\]/.exec(first)?.[0];
    const thinking = { type: 'thinking', thinking: `I should repeat ${ph}`, signature: SIGNATURE };
    await call('/v1/messages', {
      model: 'm',
      max_tokens: 10,
      messages: [
        { role: 'user', content: userMessage },
        { role: 'assistant', content: [thinking, { type: 'text', text: `Your key is ${SECRET}` }, { type: 'tool_use', id: 'tu_1', name: 'write_file', input: { content: `KEY=${SECRET}` } }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: 'tu_1', content: `wrote KEY=${SECRET}` }] },
      ],
    });
    upstreamNeverSawSecrets();
    const sent = JSON.stringify(lastBody);
    assert.equal(sent.split(ph as string).length - 1, 5, 'one placeholder everywhere: user text, thinking, assistant text, tool input, tool result');
    assert.deepEqual(lastBody.messages[1].content[0], thinking, 'thinking block unchanged');
    assert.equal(lastBody.messages[1].content[2].id, 'tu_1');
  });
});

describe('OpenAI Chat Completions', () => {
  it('non-streamed: arguments are a JSON string and stay valid after restoring a value with quotes', async () => {
    const { text } = await call('/v1/chat/completions', { model: 'gpt-x', messages: [{ role: 'system', content: 'Be brief.' }, { role: 'user', content: userMessage }] });
    upstreamNeverSawSecrets();
    assert.equal(lastBody.messages[1].role, 'system');
    assert.equal(lastBody.messages[1].content, NOTE, 'note added after the existing system message');
    const msg = JSON.parse(text).choices[0].message;
    checkRestored(msg.content, msg.tool_calls[0].function.arguments);
  });
  it('streamed', async () => {
    const { text } = await call('/v1/chat/completions', { model: 'gpt-x', stream: true, messages: [{ role: 'user', content: userMessage }] });
    upstreamNeverSawSecrets();
    const evs = events(text);
    const txt = evs.map((e) => e.choices?.[0]?.delta?.content ?? '').join('');
    const args = evs.map((e) => e.choices?.[0]?.delta?.tool_calls?.[0]?.function?.arguments ?? '').join('');
    checkRestored(txt, args);
    assert.ok(text.trim().endsWith('data: [DONE]'));
  });
  it('earlier tool-call arguments in the history are redacted inside the JSON, not as escaped text', async () => {
    await call('/v1/chat/completions', { model: 'm', messages: [{ role: 'assistant', content: null, tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'w', arguments: JSON.stringify({ pw: TRICKY, key: SECRET }) } }] }] });
    upstreamNeverSawSecrets();
    const args = JSON.parse(lastBody.messages.at(-1).tool_calls[0].function.arguments);
    assert.match(args.key, /^\[\[REDACTED:openai_key:/);
    assert.equal(lastBody.messages.at(-1).tool_calls[0].function.name, 'w');
  });
});

describe('OpenAI Responses (Codex)', () => {
  it('non-streamed, with encrypted reasoning passed through', async () => {
    const { text } = await call('/v1/responses', { model: 'gpt-x', instructions: 'Be brief.', input: [{ role: 'user', content: [{ type: 'input_text', text: userMessage }] }] });
    upstreamNeverSawSecrets();
    assert.ok(lastBody.instructions.endsWith(NOTE));
    const out = JSON.parse(text).output;
    checkRestored(out[1].content[0].text, out[2].arguments);
    assert.match(out[0].encrypted_content, /^enc:\[\[REDACTED:/, 'reasoning is opaque');
  });
  it('streamed', async () => {
    const { text } = await call('/v1/responses', { model: 'gpt-x', stream: true, input: userMessage });
    upstreamNeverSawSecrets();
    const evs = events(text);
    const txt = evs.filter((e) => e.type === 'response.output_text.delta').map((e) => e.delta).join('');
    const args = evs.filter((e) => e.type === 'response.function_call_arguments.delta').map((e) => e.delta).join('');
    checkRestored(txt, args);
    checkRestored(evs.find((e) => e.type === 'response.output_text.done').text, evs.find((e) => e.type === 'response.function_call_arguments.done').arguments);
    const done = evs.find((e) => e.type === 'response.completed').response.output;
    checkRestored(done[1].content[0].text, done[2].arguments);
  });
});

describe('OpenAI Responses: custom tools (Codex apply_patch)', () => {
  it('a streamed freeform tool input is restored as text, so the patch writes the real key', async () => {
    const { text } = await call('/v1/responses?custom=1', { model: 'gpt-x', stream: true, input: userMessage });
    upstreamNeverSawSecrets();
    const evs = events(text);
    const patch = evs.filter((e) => e.type === 'response.custom_tool_call_input.delta').map((e) => e.delta).join('');
    assert.ok(patch.includes(`+OPENAI_API_KEY=${SECRET}\n`), patch);
    assert.ok(!patch.includes('[[REDACTED'), 'no placeholder written to disk');
    assert.equal(evs.find((e) => e.type === 'response.custom_tool_call_input.done').input, patch);
    assert.equal(evs.find((e) => e.type === 'response.output_item.done').item.input, patch);
  });
});

describe('proxy behaviour', () => {
  it('placeholders are stable across requests (prompt caches keep hitting)', async () => {
    await call('/v1/messages', { model: 'm', max_tokens: 1, messages: [{ role: 'user', content: userMessage }] });
    const a = JSON.stringify(lastBody);
    await call('/v1/messages', { model: 'm', max_tokens: 1, messages: [{ role: 'user', content: userMessage }] });
    assert.equal(JSON.stringify(lastBody), a);
  });
  it('gzip request bodies are decompressed, redacted and forwarded uncompressed', async () => {
    const res = await fetch(px + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' }, body: gzipSync(JSON.stringify({ model: 'm', max_tokens: 1, messages: [{ role: 'user', content: userMessage }] })) });
    assert.equal(res.status, 200);
    await res.text();
    upstreamNeverSawSecrets();
    assert.equal(lastHeaders['content-encoding'], undefined);
  });
  it('refuses requests not addressed to localhost (DNS rebinding)', async () => {
    const { request } = await import('node:http');
    const port = (proxy.address() as AddressInfo).port;
    const status = await new Promise<number>((resolve) => {
      const r = request({ host: '127.0.0.1', port, path: '/mock/v1/messages', method: 'POST', headers: { host: 'evil.example:80', 'content-type': 'application/json' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      r.end('{}');
    });
    assert.equal(status, 403);
  });
  it('status page, unknown upstream, unreachable upstream', async () => {
    const root = (await (await fetch(px.replace('/mock', '/'))).json()) as { name: string; upstreams: string[] };
    assert.equal(root.name, 'llm-redact');
    assert.ok(root.upstreams.includes('mock'));
    assert.equal((await fetch(px.replace('/mock', '/nope') + '/v1/messages', { method: 'POST', body: '{}' })).status, 404);
    assert.equal((await fetch(px.replace('/mock', '/dead') + '/v1/messages', { method: 'POST', body: '{}' })).status, 502);
  });
  it('the log carries counts, never values', () => {
    const all = log.join('\n');
    assert.match(all, /redacted .*openai_key x\d/);
    for (const v of [SECRET, EMAIL, TRICKY]) assert.ok(!all.includes(v));
  });
});
