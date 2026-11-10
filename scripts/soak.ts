/**
 * Soak test: several agents on one proxy, many turns each, the way real sessions go.
 *
 *   node scripts/soak.ts [--agents 4] [--turns 150] [--compact 50]
 *
 * Each agent sends its whole (growing) history every turn, with tool results of ~20 KB that bring
 * new secrets every few turns — some recognisable by shape (`sk-proj-…`), some only by context
 * (`DB_PASSWORD=…`). The mock model echoes placeholders back in prose and in tool commands
 * (`psql -W …`), so restored values come back in the next turn's history; every `--compact` turns
 * the history is replaced by a summary that quotes restored values in prose.
 *
 * Checked every turn: the upstream never sees any real value the agent has ever been given, and the
 * client never sees a placeholder. Reported: latency (proxy overhead), request size, memory, vault
 * size and cache entries over time. Everything is synthetic and local.
 */
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { parseArgs } from 'node:util';
import { createProxy } from '../src/proxy.ts';
import { Vault } from '../src/vault.ts';

const { values: o } = parseArgs({ options: { agents: { type: 'string', default: '4' }, turns: { type: 'string', default: '150' }, compact: { type: 'string', default: '50' } } });
const AGENTS = Number(o.agents);
const TURNS = Number(o.turns);
const COMPACT = Number(o.compact);
const PH = /\[\[REDACTED:[a-z0-9_]+:[0-9a-f]{8}\]\]/g;

// ---- the mock model: echoes the placeholders of the last user message, in prose and in a command
let upstreamBytes = 0;
const seen: string[] = []; // bodies of the current round (checked against every agent's secrets, then dropped)
const upstream = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  upstreamBytes += raw.length;
  seen.push(raw);
  const body = JSON.parse(raw) as { messages: { role: string; content: unknown }[] };
  const last = JSON.stringify(body.messages.at(-1));
  const phs = [...new Set(last.match(PH) ?? [])].slice(0, 3);
  const text = phs.length ? `Using ${phs.join(' and ')}. I will run psql -W ${phs[0]} next.` : 'Nothing to do.';
  const input = JSON.stringify({ command: phs.length ? `PGPASSWORD='${phs[0]}' psql -h db -c 'select 1'` : 'true' });
  const ev = (type: string, d: object) => `event: ${type}\ndata: ${JSON.stringify({ type, ...d })}\n\n`;
  const pieces = (s: string, n: number) => s.match(new RegExp(`[\\s\\S]{1,${n}}`, 'g')) ?? [];
  res.writeHead(200, { 'content-type': 'text/event-stream' });
  res.end(
    ev('message_start', { message: { id: 'msg', type: 'message', role: 'assistant', model: 'mock', content: [], usage: { input_tokens: 1, output_tokens: 1 } } }) +
      ev('content_block_start', { index: 0, content_block: { type: 'text', text: '' } }) +
      pieces(text, 7).map((p) => ev('content_block_delta', { index: 0, delta: { type: 'text_delta', text: p } })).join('') +
      ev('content_block_stop', { index: 0 }) +
      ev('content_block_start', { index: 1, content_block: { type: 'tool_use', id: `tu_${Math.random().toString(36).slice(2)}`, name: 'Bash', input: {} } }) +
      pieces(input, 9).map((p) => ev('content_block_delta', { index: 1, delta: { type: 'input_json_delta', partial_json: p } })).join('') +
      ev('content_block_stop', { index: 1 }) +
      ev('message_delta', { delta: { stop_reason: 'tool_use' }, usage: { output_tokens: 10 } }) +
      ev('message_stop', {}),
  );
});
await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));

const vault = new Vault(randomBytes(32));
const proxy = createProxy({ vault, upstreams: { anthropic: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}` }, redact: {} });
await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}/anthropic/v1/messages`;

// ---- synthetic tool output
const alnum = (n: number) => randomBytes(n * 2).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, n);
const filler = (n: number) => {
  const lines = ['function handler(req, res) {', '  const msg = "line\\n" + req.body.name;', '  return res.send(JSON.stringify({ ok: true }));', '}', 'INFO request done in 12ms', 'Some prose about the change, nothing secret here.'];
  let s = '';
  while (s.length < n) s += lines[Math.floor(Math.random() * lines.length)] + '\n';
  return s;
};

interface Msg {
  role: 'user' | 'assistant';
  content: unknown;
}
interface Agent {
  id: number;
  history: Msg[];
  secrets: string[];
  lastToolId: string;
}

let leaks = 0;
let placeholdersSeen = 0;
const latencies: number[] = [];
const sizes: number[] = [];

async function turn(a: Agent, t: number): Promise<void> {
  // Tool output, with new secrets every 3 turns: one by shape, one only by its context.
  let out = filler(20_000);
  if (t % 3 === 0) {
    const shape = `sk-proj-${alnum(48)}`;
    const context = `${alnum(6)}-${alnum(6)}-${alnum(4)}`;
    a.secrets.push(shape, context);
    out += `OPENAI_API_KEY=${shape}\nDB_PASSWORD=${context}\n`;
  }
  const content = a.lastToolId ? [{ type: 'tool_result', tool_use_id: a.lastToolId, content: out }] : out;
  a.history.push({ role: 'user', content });
  const body = JSON.stringify({ model: 'mock', max_tokens: 1024, stream: true, system: 'You are a coding agent.', messages: a.history });
  sizes.push(body.length);
  const t0 = performance.now();
  const res = await fetch(base, { method: 'POST', headers: { 'content-type': 'application/json', 'x-agent': String(a.id) }, body });
  const text = await res.text();
  latencies.push(performance.now() - t0);
  // What the client got: rebuild the assistant message from the stream.
  let reply = '';
  let json = '';
  for (const block of text.split('\n\n')) {
    const data = block.split('\n').find((l) => l.startsWith('data: '))?.slice(6);
    if (!data) continue;
    const d = JSON.parse(data) as { type: string; delta?: { type: string; text?: string; partial_json?: string }; content_block?: { id?: string } };
    if (d.delta?.type === 'text_delta') reply += d.delta.text;
    if (d.delta?.type === 'input_json_delta') json += d.delta.partial_json;
    if (d.content_block?.id) a.lastToolId = d.content_block.id;
  }
  if (PH.test(reply + json)) placeholdersSeen++;
  PH.lastIndex = 0;
  a.history.push({ role: 'assistant', content: [{ type: 'text', text: reply }, { type: 'tool_use', id: a.lastToolId, name: 'Bash', input: JSON.parse(json || '{}') }] });
  // Compaction: the history becomes a summary that quotes restored values in prose.
  if (COMPACT && t > 0 && t % COMPACT === 0) {
    const recent = a.secrets.slice(-4);
    a.history = [{ role: 'user', content: `Summary of the session so far: we deployed the app; the database password is ${recent[1] ?? '-'} and the key ${recent[0] ?? '-'} is in .env. Continue.` }];
    a.lastToolId = '';
  }
}

/** Every body sent upstream this round, against every secret any agent has: nothing may leak, across sessions either. */
function check(all: Agent[]): void {
  const secrets = all.flatMap((a) => a.secrets);
  for (const raw of seen.splice(0)) for (const s of secrets) if (raw.includes(s)) leaks++;
}

const agents: Agent[] = Array.from({ length: AGENTS }, (_, id) => ({ id, history: [], secrets: [], lastToolId: '' }));
const mb = (n: number) => `${(n / 1024 / 1024).toFixed(0)} MB`;
/** Live heap after a full collection (run with node --expose-gc): what is really retained. */
const heap = () => {
  const gc = (globalThis as { gc?: () => void }).gc;
  if (!gc) return '';
  gc();
  return `, live heap ${mb(process.memoryUsage().heapUsed)}`;
};
console.log(`soak: ${AGENTS} agents x ${TURNS} turns, compaction every ${COMPACT}`);
const t0 = performance.now();
for (let t = 0; t < TURNS; t++) {
  await Promise.all(agents.map((a) => turn(a, t)));
  check(agents);
  if ((t + 1) % 25 === 0 || t === TURNS - 1) {
    const recent = latencies.slice(-AGENTS * 25).sort((x, y) => x - y);
    const p = (q: number) => (recent[Math.floor(q * (recent.length - 1))] ?? 0).toFixed(0);
    console.log(`turn ${String(t + 1).padStart(4)}: request ${(sizes.at(-1)! / 1024 / 1024).toFixed(2)} MB, latency p50 ${p(0.5)} ms p95 ${p(0.95)} ms, rss ${mb(process.memoryUsage().rss)}${heap()}, vault ${vault.size}, leaks ${leaks}, placeholders at client ${placeholdersSeen}`);
  }
}
console.log(`done in ${((performance.now() - t0) / 1000).toFixed(1)} s; ${(upstreamBytes / 1024 / 1024).toFixed(0)} MB sent upstream; ${agents.reduce((n, a) => n + a.secrets.length, 0)} secrets`);
proxy.close();
upstream.close();
if (leaks || placeholdersSeen) {
  console.log(`FAIL: ${leaks} leaks, ${placeholdersSeen} replies with placeholders`);
  process.exit(1);
}
process.exit(0);
