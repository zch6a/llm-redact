import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { parseJson, redactRequest, type Api } from './body.ts';
import { DETECTORS } from './detectors.ts';
import { DEFAULT_UPSTREAMS, createProxy } from './proxy.ts';
import { redactText, summarize, type RedactOptions } from './redact.ts';
import { Vault, defaultKeyPath, loadKey, writePrivate } from './vault.ts';
import { VERSION } from './version.ts';

const HELP = `llm-redact - keep API keys, tokens and personal data out of your AI agent's requests.

A local proxy: requests are redacted before they leave your machine, responses are restored
before your agent sees them, so it still writes the real key into your .env.

Usage
  llm-redact [start] [options]     run the proxy (default port 8787)
  llm-redact env [client]          what to set for claude, codex, openai, deepseek (default: all)
  llm-redact scan [file|-]         show what a file would look like after redaction
  llm-redact scan --body req.json  which fields of an API request would change, and why
  llm-redact detectors             list what is detected
  llm-redact stats                 what a running proxy has redacted so far (counts only)

Options
  -p, --port <n>             port (default 8787; the proxy only listens on 127.0.0.1)
      --upstream <name=url>  add or replace an upstream (repeatable), e.g. anthropic=https://my-gateway
      --disable <ids>        detectors or kinds to turn off: email,phone or pii or secret
      --enable <ids>         optional detectors to turn on: ipv4
      --allow <value>        a value never to redact (repeatable)
      --no-note              do not tell the model what the placeholders are
      --require-token        only answer under a random path token (for machines with other users)
      --allow-unredacted     forward bodies that cannot be redacted (uploads) instead of refusing them
      --config <file>        settings file (default: ${join(dirname(defaultKeyPath()), 'config.json')})
  -q, --quiet                no request log
      --json                 scan: machine-readable output
      --body                 scan: the file is an API request body; show which fields would change
      --api <name>           scan --body: anthropic, chat, responses or other (default: from its shape)
      --shell <name>         env: bash, zsh, fish, powershell, cmd (default: from your platform)
  -h, --help / --version

Nothing is stored on disk except a random key for stable placeholders. Values stay in memory.
`;

const OPTIONS = {
  port: { type: 'string', short: 'p' },
  upstream: { type: 'string', multiple: true },
  disable: { type: 'string', multiple: true },
  enable: { type: 'string', multiple: true },
  allow: { type: 'string', multiple: true },
  'no-note': { type: 'boolean' },
  'allow-unredacted': { type: 'boolean' },
  'require-token': { type: 'boolean' },
  config: { type: 'string' },
  quiet: { type: 'boolean', short: 'q' },
  json: { type: 'boolean' },
  body: { type: 'boolean' },
  api: { type: 'string' },
  shell: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
} satisfies ParseArgsConfig['options'];

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values'];

class UsageError extends Error {}

const COMMANDS = ['start', 'env', 'scan', 'detectors', 'stats'];

/** ` (did you mean "email"?)` for a near miss (edit distance 2 or less), else ''. */
export function didYouMean(word: string, candidates: string[]): string {
  const dist = (a: string, b: string): number => {
    let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) cur[j] = Math.min((prev[j] as number) + 1, (cur[j - 1] as number) + 1, (prev[j - 1] as number) + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = cur;
    }
    return prev[b.length] as number;
  };
  const best = candidates.map((c) => [c, dist(word.toLowerCase(), c)] as const).sort((x, y) => x[1] - y[1])[0];
  return best && best[1] <= 2 && best[1] < word.length ? ` (did you mean "${best[0]}"?)` : '';
}

interface Config {
  port: number;
  token?: string;
  allowUnredacted: boolean;
  upstreams: Record<string, string>;
  redact: RedactOptions & { note?: boolean };
}

const list = (v: string[] | undefined) => (v ?? []).flatMap((s) => s.split(',')).map((s) => s.trim()).filter(Boolean);

/** The access token for --require-token: random, created once, next to the HMAC key. */
function loadToken(): string {
  const file = join(dirname(defaultKeyPath()), 'token');
  try {
    const t = readFileSync(file, 'utf8').trim();
    if (/^[0-9a-f]{32}$/.test(t)) return t;
  } catch {
    // first use
  }
  const t = randomBytes(16).toString('hex');
  const r = writePrivate(file, t + '\n', true);
  // Another proxy created it at the same moment: both must use the same token.
  if (r === 'exists') return readFileSync(file, 'utf8').trim();
  if (!r) console.error(`llm-redact: warning: could not make ${file} readable by you only (icacls failed)`);
  return t;
}

/** What each config file setting must be. */
const CONFIG_TYPES: Record<string, (x: unknown) => boolean> = {
  port: (x) => Number.isInteger(x),
  upstreams: (x) => typeof x === 'object' && x !== null && !Array.isArray(x) && Object.values(x).every((u) => typeof u === 'string' && /^https?:\/\//.test(u)),
  disable: (x) => Array.isArray(x) && x.every((s) => typeof s === 'string'),
  enable: (x) => Array.isArray(x) && x.every((s) => typeof s === 'string'),
  allow: (x) => Array.isArray(x) && x.every((s) => typeof s === 'string'),
  note: (x) => typeof x === 'boolean',
  requireToken: (x) => typeof x === 'boolean',
  allowUnredacted: (x) => typeof x === 'boolean',
};

/**
 * The settings file. A file that exists but is broken is an error, not "no settings": silently
 * ignoring `{ "requireToken": true, }` (a trailing comma) would turn the token off.
 */
export function readConfigFile(file: string, explicit: boolean): Record<string, unknown> {
  let text: string;
  try {
    text = readFileSync(file, 'utf8');
  } catch (err) {
    if (explicit || (err as NodeJS.ErrnoException).code !== 'ENOENT') throw new UsageError(`could not read ${file}: ${(err as Error).message}`);
    return {};
  }
  let cfg: unknown;
  try {
    cfg = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
  } catch (err) {
    throw new UsageError(`${file} is not valid JSON (${(err as Error).message}); fix or remove it`);
  }
  if (typeof cfg !== 'object' || cfg === null || Array.isArray(cfg)) throw new UsageError(`${file} must hold a JSON object`);
  for (const [k, x] of Object.entries(cfg)) {
    const ok = CONFIG_TYPES[k];
    if (!ok) throw new UsageError(`${file}: unknown setting "${k}"${didYouMean(k, Object.keys(CONFIG_TYPES))}`);
    if (!ok(x)) throw new UsageError(`${file}: "${k}" has the wrong type (${JSON.stringify(x)})`);
  }
  return cfg as Record<string, unknown>;
}

/** Defaults ← config file ← command line. */
export function loadConfig(v: Values): Config {
  const fileCfg = readConfigFile(v.config ?? join(dirname(defaultKeyPath()), 'config.json'), !!v.config);
  const strs = (x: unknown) => (Array.isArray(x) ? x.filter((s): s is string => typeof s === 'string') : []);
  const upstreams = { ...DEFAULT_UPSTREAMS, ...((fileCfg.upstreams as Record<string, string>) ?? {}) };
  for (const u of v.upstream ?? []) {
    const m = /^([a-z0-9_-]+)=(https?:\/\/.+)$/i.exec(u);
    if (!m) throw new UsageError(`--upstream wants name=https://host, got "${u}"`);
    upstreams[(m[1] as string).toLowerCase()] = m[2] as string;
  }
  const known = new Set([...DETECTORS.map((d) => d.id), 'secret', 'pii']);
  const disable = [...strs(fileCfg.disable), ...list(v.disable)];
  const enable = [...strs(fileCfg.enable), ...list(v.enable)];
  for (const id of [...disable, ...enable]) if (!known.has(id)) throw new UsageError(`unknown detector "${id}"${didYouMean(id, [...known])} (see: llm-redact detectors)`);
  const port = Number(v.port ?? fileCfg.port ?? 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UsageError(`bad port ${v.port}`);
  const requireToken = !!v['require-token'] || fileCfg.requireToken === true;
  return { port, upstreams, allowUnredacted: !!v['allow-unredacted'] || fileCfg.allowUnredacted === true, ...(requireToken ? { token: loadToken() } : {}), redact: { disable, enable, allow: [...strs(fileCfg.allow), ...(v.allow ?? [])], note: v['no-note'] ? false : fileCfg.note !== false } };
}

function cmdStart(v: Values): Promise<number> {
  const cfg = loadConfig(v);
  // Values found by their context are remembered across restarts — as keyed hashes, never values.
  const vault = new Vault(loadKey(), { rememberFile: join(dirname(defaultKeyPath()), 'remembered') });
  const server = createProxy({ vault, upstreams: cfg.upstreams, redact: cfg.redact, allowUnredacted: cfg.allowUnredacted, ...(cfg.token ? { token: cfg.token } : {}), log: v.quiet ? undefined : (l) => console.log(l) });
  return new Promise((resolveExit) => {
    server.on('error', (err: NodeJS.ErrnoException) => {
      console.error(err.code === 'EADDRINUSE' ? `Port ${cfg.port} is in use - is llm-redact already running? Try --port.` : err.message);
      resolveExit(1);
    });
    server.listen(cfg.port, '127.0.0.1', () => {
      console.log(`llm-redact ${VERSION} listening on http://127.0.0.1:${cfg.port}${cfg.token ? '/<token> (--require-token: see llm-redact env)' : ''}`);
      // ASCII only: this is the first thing people see, often in a console that is not UTF-8.
      for (const [name, url] of Object.entries(cfg.upstreams)) console.log(`  /${name.padEnd(10)} -> ${url}`);
      console.log(`Run \`llm-redact env\` to see what to set in your agent. Ctrl+C to stop.`);
    });
    const stop = () => {
      const s = server.stats;
      const total = Object.values(s.redacted).reduce((a, b) => a + b, 0);
      console.log(`\n${s.requests} request(s), ${total} value(s) redacted${total ? `: ${Object.entries(s.redacted).map(([k, n]) => `${k} x${n}`).join(' ')}` : ''}.`);
      server.close();
      resolveExit(0);
    };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  });
}

type Shell = 'bash' | 'zsh' | 'fish' | 'powershell' | 'cmd';

function setVar(shell: Shell, name: string, value: string): string {
  if (shell === 'powershell') return `$env:${name} = "${value}"`;
  if (shell === 'cmd') return `set ${name}=${value}`;
  if (shell === 'fish') return `set -gx ${name} ${value}`;
  return `export ${name}=${value}`;
}

export function envText(client: string, port: number, shell: Shell, current: NodeJS.ProcessEnv = process.env, token?: string): string {
  const base = `http://127.0.0.1:${port}${token ? `/${token}` : ''}`;
  const out: string[] = [];
  const want = (c: string) => client === 'all' || client === c;
  if (want('claude')) {
    out.push('# Claude Code (and anything using the Anthropic SDK)', setVar(shell, 'ANTHROPIC_BASE_URL', `${base}/anthropic`));
    const cur = current.ANTHROPIC_BASE_URL;
    const official = (u: string) => u.replace(/\/+$/, '') === DEFAULT_UPSTREAMS.anthropic;
    if (cur && !cur.startsWith(base) && !official(cur)) out.push(`#   You already route Anthropic traffic through ${cur}. Keep it by starting the proxy with`, `#   llm-redact --upstream anthropic=${cur}`);
    out.push('');
  }
  if (want('openai')) out.push('# OpenAI SDKs, OpenCode and most OpenAI-compatible tools', setVar(shell, 'OPENAI_BASE_URL', `${base}/openai/v1`), '');
  if (want('codex'))
    out.push(
      '# Codex: add a provider in ~/.codex/config.toml and select it',
      '#   model_provider = "redacted"',
      '#   [model_providers.redacted]',
      '#   name = "OpenAI via llm-redact"',
      `#   base_url = "${base}/openai/v1"`,
      '#   env_key = "OPENAI_API_KEY"',
      '#   wire_api = "responses"',
      '',
    );
  if (want('deepseek'))
    out.push(
      '# DeepSeek: OpenAI-compatible endpoint (DeepSeek Harness, OpenAI SDKs)',
      setVar(shell, 'OPENAI_BASE_URL', `${base}/deepseek/v1`),
      '# DeepSeek through Claude Code (Anthropic-compatible endpoint)',
      setVar(shell, 'ANTHROPIC_BASE_URL', `${base}/deepseek/anthropic`),
      '',
    );
  if (!out.length) throw new UsageError(`unknown client "${client}": claude, codex, openai, deepseek or all`);
  // Requests to the proxy itself must not go through an HTTP proxy: with HTTPS_PROXY set, or a
  // system-wide proxy (Codex uses the Windows one), they would get a 502 from it instead.
  const existing = (current.NO_PROXY ?? current.no_proxy ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  const noProxy = [...new Set(['127.0.0.1', 'localhost', ...existing])].join(',');
  out.push('# Keep requests to llm-redact away from any HTTP proxy (system-wide or HTTPS_PROXY)', setVar(shell, 'NO_PROXY', noProxy));
  // Windows variables are case-insensitive; elsewhere some tools read only the lower-case one.
  if (shell !== 'powershell' && shell !== 'cmd') out.push(setVar(shell, 'no_proxy', noProxy));
  return out.join('\n').trimEnd();
}

/** Which wire format a request body is, from its shape (for `scan --body` without `--api`). */
export function guessApi(body: unknown): Api {
  if (typeof body !== 'object' || body === null) return 'other';
  const b = body as Record<string, unknown>;
  if (Array.isArray(b.input) || typeof b.input === 'string') return 'responses';
  if (!Array.isArray(b.messages)) return 'other';
  const chatty = b.messages.some((m) => typeof m === 'object' && m !== null && (['system', 'developer', 'tool'].includes(String((m as Record<string, unknown>).role)) || 'tool_calls' in m));
  return chatty ? 'chat' : 'anthropic';
}

interface Change {
  path: string;
  /** Detectors whose placeholders appear in the new value (none: added by llm-redact, e.g. the note). */
  redacted: string[];
  added?: boolean;
}

/** Where a redacted body differs from the original: JSON paths, and what was redacted there. */
export function bodyChanges(before: unknown, after: unknown, path = '', out: Change[] = []): Change[] {
  const labels = (x: unknown) => [...JSON.stringify(x ?? null).matchAll(/\[\[REDACTED:([a-z0-9_]+):[0-9a-f]{8}\]\]/g)].map((m) => m[1] as string);
  if (Array.isArray(before) && Array.isArray(after)) {
    for (let i = 0; i < Math.max(before.length, after.length); i++) {
      if (i >= before.length) out.push({ path: `${path}[${i}]`, redacted: [], added: true });
      else bodyChanges(before[i], after[i], `${path}[${i}]`, out);
    }
    return out;
  }
  if (typeof before === 'object' && before !== null && typeof after === 'object' && after !== null && !Array.isArray(before) && !Array.isArray(after)) {
    const ka = Object.keys(before);
    const kb = Object.keys(after);
    // Keys can be redacted too (inside tool inputs), so entries are matched by position.
    for (let i = 0; i < Math.max(ka.length, kb.length); i++) {
      const k = (kb[i] ?? ka[i]) as string;
      const p = path ? `${path}.${/^[A-Za-z_$][\w$]*$/.test(k) ? k : JSON.stringify(k)}` : k;
      if (i >= ka.length) out.push({ path: p, redacted: [], added: true });
      else {
        if (ka[i] !== kb[i]) out.push({ path: p, redacted: labels(kb[i]) });
        bodyChanges((before as Record<string, unknown>)[ka[i] as string], (after as Record<string, unknown>)[kb[i] as string], p, out);
      }
    }
    return out;
  }
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    // Placeholders that were not there before (a request can carry the model's earlier ones).
    const fresh = labels(after);
    for (const l of labels(before)) {
      const i = fresh.indexOf(l);
      if (i >= 0) fresh.splice(i, 1);
    }
    // Nothing new redacted: the value only grew (the note appended to the system prompt).
    out.push(fresh.length ? { path, redacted: fresh } : { path, redacted: [], added: true });
  }
  return out;
}

function cmdScanBody(v: Values, text: string, cfg: Config): number {
  let body: unknown;
  try {
    body = parseJson(text);
  } catch (err) {
    console.error(`Not a JSON request body: ${(err as Error).message}`);
    return 1;
  }
  const api = (v.api as Api | undefined) ?? guessApi(body);
  if (!['anthropic', 'chat', 'responses', 'other'].includes(api)) throw new UsageError(`--api must be anthropic, chat, responses or other`);
  const r = redactRequest(body, new Vault(loadKey()), api, cfg.redact);
  const changes = bodyChanges(body, r.body);
  if (v.json) {
    process.stdout.write(JSON.stringify({ api, summary: summarize(r.hits), changes }, null, 2) + '\n');
    return 0;
  }
  console.log(`As ${api === 'chat' ? 'OpenAI Chat Completions' : api === 'responses' ? 'OpenAI Responses' : api === 'anthropic' ? 'Anthropic Messages' : 'a generic JSON'} request${v.api ? '' : ' (guessed from its shape; set --api to choose)'}:`);
  if (!changes.length) console.log('  nothing would change.');
  const width = Math.min(60, Math.max(0, ...changes.map((c) => c.path.length)));
  for (const c of changes) console.log(`  ${c.path.padEnd(width)}  ${c.added && !c.redacted.length ? '(added: the note telling the model what placeholders are)' : [...new Set(c.redacted)].map((d) => `${d} x${c.redacted.filter((x) => x === d).length}`).join(' ')}`);
  const s = summarize(r.hits);
  console.log(r.hits.length ? `${r.hits.length} value(s) in ${changes.filter((c) => c.redacted.length).length} field(s): ${Object.entries(s).map(([k, n]) => `${k} x${n}`).join(' ')}` : 'No values to redact.');
  return 0;
}

function cmdScan(v: Values, file: string | undefined): number {
  const cfg = loadConfig(v);
  const raw = !file || file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  const text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw; // a BOM from PowerShell pipes
  if (v.body) return cmdScanBody(v, text, cfg);
  const r = redactText(text, new Vault(loadKey()), cfg.redact);
  if (v.json) {
    // Values found in an encoded form (JSON escapes, %40 …) have no position of their own.
    const lineOf = (i: number) => (i < 0 ? null : text.slice(0, i).split('\n').length);
    process.stdout.write(JSON.stringify({ summary: summarize(r.hits), hits: r.hits.map((h) => ({ detector: h.detector, kind: h.kind, line: lineOf(h.start), placeholder: h.placeholder })) }, null, 2) + '\n');
  } else {
    process.stdout.write(r.text);
    const s = summarize(r.hits);
    console.error(r.hits.length ? `\n${r.hits.length} value(s) would be redacted: ${Object.entries(s).map(([k, n]) => `${k} x${n}`).join(' ')}` : '\nNothing would be redacted.');
  }
  return 0;
}

/** Ask a running proxy what it has redacted since it started (counts only). */
async function cmdStats(v: Values): Promise<number> {
  const port = loadConfig(v).port;
  let s: { version?: string; stats?: { requests: number; redacted: Record<string, number> } };
  try {
    const cfg = loadConfig(v);
    s = (await (await fetch(`http://127.0.0.1:${port}/${cfg.token ? `${cfg.token}/` : ''}`)).json()) as typeof s;
  } catch {
    console.error(`No llm-redact proxy answering on port ${port}. Start it with \`llm-redact\`.`);
    return 1;
  }
  if (v.json) {
    process.stdout.write(JSON.stringify(s.stats, null, 2) + '\n');
    return 0;
  }
  const r = s.stats?.redacted ?? {};
  const total = Object.values(r).reduce((a, b) => a + b, 0);
  console.log(`llm-redact ${s.version} on port ${port}: ${s.stats?.requests ?? 0} request(s), ${total} value(s) redacted`);
  for (const [k, n] of Object.entries(r).sort((a, b) => b[1] - a[1])) console.log(`  ${k.padEnd(20)} ${n}`);
  return 0;
}

function cmdDetectors(): number {
  for (const d of DETECTORS) console.log(`${d.id.padEnd(20)} ${d.kind.padEnd(7)} ${d.description}${d.optional ? ' (off by default: --enable ' + d.id + ')' : ''}`);
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    console.error((err as Error).message + '\nRun `llm-redact --help` for usage.');
    return 2;
  }
  const v = parsed.values;
  if (v.version) {
    console.log(VERSION);
    return 0;
  }
  const [cmd = 'start', ...rest] = parsed.positionals;
  if (v.help || cmd === 'help') {
    console.log(HELP);
    return 0;
  }
  try {
    switch (cmd) {
      case 'start':
        return await cmdStart(v);
      case 'env': {
        const shell = (v.shell ?? (process.platform === 'win32' ? 'powershell' : 'bash')) as Shell;
        if (!['bash', 'zsh', 'fish', 'powershell', 'cmd'].includes(shell)) throw new UsageError(`unknown shell ${shell}`);
        const cfg = loadConfig(v);
        console.log(envText(rest[0] ?? 'all', cfg.port, shell, process.env, cfg.token));
        return 0;
      }
      case 'scan':
        return cmdScan(v, rest[0]);
      case 'detectors':
        return cmdDetectors();
      case 'stats':
        return await cmdStats(v);
      default:
        throw new UsageError(`unknown command "${cmd}"${didYouMean(cmd, COMMANDS)} (commands: ${COMMANDS.join(', ')}; see llm-redact --help)`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(err.message);
      return 2;
    }
    // A file that cannot be read is the user's to fix, not a crash: one line, no stack.
    const e = err as NodeJS.ErrnoException;
    if (e?.syscall && ['ENOENT', 'EACCES', 'EISDIR', 'EPERM'].includes(e.code ?? '')) {
      console.error(`cannot read ${e.path ?? rest[0] ?? 'the input'}: ${e.code === 'ENOENT' ? 'no such file' : e.code === 'EISDIR' ? 'it is a directory' : 'permission denied'}`);
      return 1;
    }
    console.error((err as Error)?.stack ?? String(err));
    return 1;
  }
}
