/**
 * End-to-end smoke test with the real agent CLIs — no tokens spent, nothing leaves the machine:
 *
 *   claude -p / codex exec  →  llm-redact (in process)  →  a mock API on 127.0.0.1
 *
 * Each CLI runs twice: once straight to the mock (what it sends without llm-redact), once through
 * the proxy. The mock echoes the placeholders it receives. Passing means: the mock never saw the
 * synthetic secret or e-mail, the CLI printed the real values (restored on the way back), and the
 * proxied request is byte-for-byte the direct one once placeholders and the note are undone — so
 * tools, system prompt, cache_control and key order are untouched.
 *
 *   node scripts/smoke.ts [claude|codex]...     (default: both; a CLI that is not installed is skipped)
 *
 * The CLIs run with a fake API key, a throwaway home and config directory and a minimal
 * environment, so your own login, settings, history and identity are not used.
 */
import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { NOTE } from '../src/body.ts';
import { createProxy } from '../src/proxy.ts';
import { Vault } from '../src/vault.ts';

const SECRET = 'sk-proj-' + 'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2);
const EMAIL = 'li.wei@corp-mail.cn';
const PH = /\[\[REDACTED:[a-z_]+:[0-9a-f]{8}\]\]/g; // only for match(), never .test()
type Json = Record<string, any>;

// ---- the mock API ------------------------------------------------------------------------------
const seen: string[] = [];
const sse = (events: Json[]) => events.map((e) => `event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join('');
/** Small deltas, so placeholders cross delta boundaries. */
const pieces = (s: string) => s.match(/[\s\S]{1,5}/g) ?? [];

function anthropic(body: Json): { type: string; payload: string } {
  // Placeholders from the conversation only: the system prompt's note contains an example one.
  const phs = [...new Set(JSON.stringify(body.messages ?? []).match(PH) ?? [])];
  const text = `Echo: ${phs.join(' ') || '(none)'}`;
  const message = { id: 'msg_mock', type: 'message', role: 'assistant', model: body.model ?? 'mock', content: [] as unknown[], stop_reason: null, stop_sequence: null, usage: { input_tokens: 10, output_tokens: 1 } };
  if (!body.stream) return { type: 'application/json', payload: JSON.stringify({ ...message, content: [{ type: 'text', text }], stop_reason: 'end_turn' }) };
  return {
    type: 'text/event-stream',
    payload: sse([
      { type: 'message_start', message },
      { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
      ...pieces(text).map((d) => ({ type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: d } })),
      { type: 'content_block_stop', index: 0 },
      { type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 5 } },
      { type: 'message_stop' },
    ]),
  };
}

function responses(body: Json): { type: string; payload: string } {
  const phs = [...new Set(JSON.stringify(body.input ?? []).match(PH) ?? [])];
  const text = `Echo: ${phs.join(' ') || '(none)'}`;
  const usage = { input_tokens: 10, input_tokens_details: { cached_tokens: 0 }, output_tokens: 5, output_tokens_details: { reasoning_tokens: 0 }, total_tokens: 15 };
  const msg = (t: string) => ({ id: 'msg_mock', type: 'message', role: 'assistant', status: 'completed', content: [{ type: 'output_text', text: t, annotations: [] }] });
  let seq = 0;
  const ev = (d: Json) => ({ ...d, sequence_number: seq++ });
  const response = (status: string, output: unknown[]) => ({ id: 'resp_mock', object: 'response', created_at: 1731300000, status, model: body.model ?? 'mock', output, usage: status === 'completed' ? usage : null });
  return {
    type: 'text/event-stream',
    payload: sse([
      ev({ type: 'response.created', response: response('in_progress', []) }),
      ev({ type: 'response.output_item.added', output_index: 0, item: { ...msg(''), status: 'in_progress', content: [] } }),
      ev({ type: 'response.content_part.added', item_id: 'msg_mock', output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } }),
      ...pieces(text).map((d) => ev({ type: 'response.output_text.delta', item_id: 'msg_mock', output_index: 0, content_index: 0, delta: d })),
      ev({ type: 'response.output_text.done', item_id: 'msg_mock', output_index: 0, content_index: 0, text }),
      ev({ type: 'response.output_item.done', output_index: 0, item: msg(text) }),
      ev({ type: 'response.completed', response: response('completed', [msg(text)]) }),
    ]),
  };
}

const upstream = createServer(async (req, res) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  seen.push(raw);
  const path = (req.url ?? '').split('?')[0] ?? '';
  let body: Json = {};
  try {
    body = JSON.parse(raw);
  } catch {
    // not JSON
  }
  const out = path.endsWith('/messages') ? anthropic(body) : path.endsWith('/responses') ? responses(body) : path.endsWith('/count_tokens') ? { type: 'application/json', payload: '{"input_tokens":10}' } : null;
  if (!out) return res.writeHead(404, { 'content-type': 'application/json' }).end('{"error":{"type":"not_found_error","message":"mock"}}');
  res.writeHead(200, { 'content-type': out.type }).end(out.payload);
});

// ---- the CLIs ------------------------------------------------------------------------------------
function run(cmd: string, args: string[], env: NodeJS.ProcessEnv, cwd: string): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { env, cwd, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    const timer = setTimeout(() => child.kill(), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: -1, out, err: String(e) });
    });
  });
}

/** `name` on PATH. On Windows, npm installs .cmd/.ps1 shims; return what they start, so no shell is needed. */
async function find(name: string, behindShim: string[]): Promise<string[] | undefined> {
  const which = await run(process.platform === 'win32' ? 'where' : 'which', [name], process.env, process.cwd());
  const first = which.code === 0 ? which.out.split(/\r?\n/).find(Boolean)?.trim() : undefined;
  if (!first) return undefined;
  if (process.platform !== 'win32' || first.toLowerCase().endsWith('.exe')) return [first];
  const target = join(dirname(first), 'node_modules', ...behindShim);
  if (!existsSync(target)) return undefined;
  return target.endsWith('.js') ? [process.execPath, target] : [target];
}

interface Client {
  name: string;
  find(): Promise<string[] | undefined>;
  args(prompt: string): string[];
  env(base: string, home: string): NodeJS.ProcessEnv;
  upstream: string;
  /** The model request among everything the CLI sent. */
  pick(body: Json): boolean;
  /** Undo the note llm-redact added on purpose. */
  unnote(body: Json): void;
  /** Values the CLI itself varies between two runs (session ids, hashes). */
  normalize(body: Json): void;
}

const CLIENTS: Client[] = [
  {
    name: 'claude',
    find: async () => (process.env.CLAUDE_BIN ? [process.env.CLAUDE_BIN] : find('claude', ['@anthropic-ai', 'claude-code', 'bin', 'claude.exe'])),
    args: (p) => ['-p', p, '--model', 'claude-sonnet-4-5', '--max-turns', '1'],
    env: (base, home) => ({ ANTHROPIC_BASE_URL: base, ANTHROPIC_API_KEY: 'sk-ant-api03-mock-key-for-a-local-test-only', CLAUDE_CONFIG_DIR: join(home, 'claude'), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1', DISABLE_AUTOUPDATER: '1' }),
    upstream: 'anthropic',
    pick: (b) => Array.isArray(b.messages),
    unnote: (b) => {
      if (Array.isArray(b.system) && b.system.at(-1)?.text === NOTE) b.system.pop();
    },
    normalize: (b) => {
      // Claude Code's per-request billing hash, and its session id.
      for (const blk of Array.isArray(b.system) ? b.system : []) if (typeof blk.text === 'string') blk.text = blk.text.replace(/cch=[0-9a-f]+/, 'cch=*');
      if (b.metadata) b.metadata.user_id = '*';
    },
  },
  {
    name: 'codex',
    find: async () => (process.env.CODEX_BIN ? [process.env.CODEX_BIN] : find('codex', ['@openai', 'codex', 'bin', 'codex.js'])),
    args: (p) => ['exec', '--skip-git-repo-check', '--color', 'never', '--sandbox', 'read-only', p],
    env: (base, home) => {
      // The provider config llm-redact env codex recommends, pointed at the mock: Codex can only talk to it.
      writeFileSync(
        join(home, 'codex', 'config.toml'),
        ['model = "gpt-5-codex"', 'model_provider = "mock"', '', '[model_providers.mock]', 'name = "mock"', `base_url = "${base}/v1"`, 'env_key = "LLM_REDACT_SMOKE_KEY"', 'wire_api = "responses"', ''].join('\n'),
      );
      return { LLM_REDACT_SMOKE_KEY: 'sk-mock-key-for-a-local-test-only', CODEX_HOME: join(home, 'codex') };
    },
    upstream: 'openai',
    pick: (b) => Array.isArray(b.input),
    unnote: (b) => {
      if (b.instructions === NOTE) delete b.instructions;
      else if (typeof b.instructions === 'string' && b.instructions.endsWith(`\n\n${NOTE}`)) b.instructions = b.instructions.slice(0, -NOTE.length - 2);
    },
    normalize: (b) => {
      if ('prompt_cache_key' in b) b.prompt_cache_key = '*';
      if (b.client_metadata) b.client_metadata = '*';
    },
  },
];

/** Paths where two JSON values differ (at most a few). */
function diff(a: unknown, b: unknown, path = '$', out: string[] = []): string[] {
  if (out.length >= 8) return out;
  if (typeof a !== typeof b || Array.isArray(a) !== Array.isArray(b) || a === null || b === null || typeof a !== 'object') {
    if (a !== b) out.push(path);
    return out;
  }
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  if (ka.join() !== kb.join()) out.push(`${path} (keys or key order)`);
  for (const k of ka) if (k in (b as object)) diff((a as Json)[k], (b as Json)[k], `${path}.${k}`, out);
  return out;
}
const parse = (raw: string): Json | null => {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
};

await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
const direct = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
const vault = new Vault(Buffer.alloc(32, 1));
const proxy = createProxy({ vault, upstreams: { anthropic: direct, openai: direct }, redact: {}, ...(process.env.SMOKE_LOG ? { log: (l: string) => appendFileSync(process.env.SMOKE_LOG as string, l + '\n') } : {}) });
await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
const viaProxy = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}`;

const wanted = process.argv.slice(2);
let failed = false;
for (const c of CLIENTS.filter((x) => !wanted.length || wanted.includes(x.name))) {
  const cmd = await c.find();
  if (!cmd) {
    console.log(`${c.name}: skipped (not installed)`);
    continue;
  }
  const home = mkdtempSync(join(tmpdir(), `llm-redact-smoke-${c.name}-`));
  writeFileSync(join(home, 'gitconfig'), '');
  for (const d of ['claude', 'codex']) mkdirSync(join(home, d)); // Codex refuses a CODEX_HOME that does not exist
  // A minimal environment: nothing of the user's own setup (accounts, endpoints, identity) leaks in.
  const keep = ['PATH', 'Path', 'SystemRoot', 'SYSTEMROOT', 'ComSpec', 'PATHEXT', 'TEMP', 'TMP', 'TMPDIR', 'WINDIR', 'LANG'];
  const envFor = (base: string): NodeJS.ProcessEnv => ({
    ...Object.fromEntries(keep.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]])),
    HOME: home,
    USERPROFILE: home,
    APPDATA: join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: join(home, 'AppData', 'Local'),
    XDG_CONFIG_HOME: join(home, '.config'),
    // Agents read the git user's e-mail into the conversation: give them none.
    GIT_CONFIG_GLOBAL: join(home, 'gitconfig'),
    GIT_CONFIG_NOSYSTEM: '1',
    // Loopback must not go through a system-wide HTTP proxy (Codex honours the Windows one).
    NO_PROXY: '127.0.0.1,localhost',
    no_proxy: '127.0.0.1,localhost',
    ...c.env(base, home),
  });
  const prompt = `My key is ${SECRET} and my e-mail is ${EMAIL}. Repeat them.`;
  const [exe, ...pre] = cmd as [string, ...string[]];
  seen.length = 0;
  await run(exe, [...pre, ...c.args(prompt)], envFor(`${direct}`), home);
  const plain = seen.splice(0);
  const r = await run(exe, [...pre, ...c.args(prompt)], envFor(`${viaProxy}/${c.upstream}`), home);
  const proxied = seen.splice(0);
  try {
    rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
  } catch {
    // a process the CLI started may still hold the folder; it is in the temp directory
  }

  const before = plain.map(parse).find((b) => b && c.pick(b));
  const raw = proxied.map(parse).find((b) => b && c.pick(b));
  // Undo what llm-redact did on purpose — placeholders back to values, the note — and the request
  // must be exactly what the CLI sent.
  const after = raw && JSON.parse(vault.restore(JSON.stringify(raw), (v) => JSON.stringify(v).slice(1, -1)));
  if (after) c.unnote(after);
  for (const b of [before, after]) if (b) c.normalize(b);
  if (process.env.SMOKE_DUMP) writeFileSync(`${process.env.SMOKE_DUMP}.${c.name}.json`, JSON.stringify({ before, after }));
  const diffs = before && after ? diff(before, after) : ['(no model request captured)'];

  const all = proxied.join('\n');
  const checks: [string, boolean][] = [
    ['sent its requests through the proxy', proxied.length > 0],
    ['the upstream never saw the secret', !all.includes(SECRET)],
    ['the upstream never saw the e-mail', !all.includes(EMAIL)],
    ['the upstream saw placeholders instead', /\[\[REDACTED:[a-z_]+:[0-9a-f]{8}\]\]/.test(all)],
    ['nothing else in the request changed', diffs.length === 0],
    ['printed the restored secret', r.out.includes(SECRET)],
    ['printed the restored e-mail', r.out.includes(EMAIL)],
    ['no placeholder reached the user', !/\[\[REDACTED:/.test(r.out)],
  ];
  console.log(`${c.name}:`);
  for (const [name, ok] of checks) console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}`);
  if (diffs.length) console.log('       differs at: ' + diffs.join(', '));
  console.log(`  (${proxied.length} upstream requests, exit code ${r.code}, placeholders: ${[...new Set(all.match(PH) ?? [])].map((x) => x.split(':')[1]).join(', ') || 'none'})`);
  if (checks.some(([, ok]) => !ok)) {
    failed = true;
    // Lengths only: output may echo the CLI's own environment.
    console.log(`  stdout ${r.out.length} chars; stderr tail: ${r.err.slice(-300).replace(/\s+/g, ' ')}`);
  }
}
proxy.close();
upstream.close();
process.exit(failed ? 1 : 0);
