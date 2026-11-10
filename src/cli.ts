import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { DETECTORS } from './detectors.ts';
import { DEFAULT_UPSTREAMS, createProxy } from './proxy.ts';
import { redactText, summarize, type RedactOptions } from './redact.ts';
import { Vault, defaultKeyPath, loadKey, writePrivate } from './vault.ts';
import { VERSION } from './version.ts';

const HELP = `llm-redact — keep API keys, tokens and personal data out of your AI agent's requests.

A local proxy: requests are redacted before they leave your machine, responses are restored
before your agent sees them, so it still writes the real key into your .env.

Usage
  llm-redact [start] [options]     run the proxy (default port 8787)
  llm-redact env [client]          what to set for claude, codex, openai, deepseek (default: all)
  llm-redact scan [file|-]         show what a file would look like after redaction
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
  shell: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
  version: { type: 'boolean' },
} satisfies ParseArgsConfig['options'];

type Values = ReturnType<typeof parseArgs<{ options: typeof OPTIONS; allowPositionals: true }>>['values'];

class UsageError extends Error {}

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
  writePrivate(file, t + '\n');
  return t;
}

/** Defaults ← config file ← command line. */
export function loadConfig(v: Values): Config {
  const file = v.config ?? join(dirname(defaultKeyPath()), 'config.json');
  let fileCfg: Record<string, unknown> = {};
  try {
    fileCfg = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  } catch (err) {
    if (v.config) throw new UsageError(`could not read ${file}: ${(err as Error).message}`);
  }
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
  for (const id of [...disable, ...enable]) if (!known.has(id)) throw new UsageError(`unknown detector "${id}" (see: llm-redact detectors)`);
  const port = Number(v.port ?? fileCfg.port ?? 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new UsageError(`bad port ${v.port}`);
  const requireToken = !!v['require-token'] || fileCfg.requireToken === true;
  return { port, upstreams, allowUnredacted: !!v['allow-unredacted'] || fileCfg.allowUnredacted === true, ...(requireToken ? { token: loadToken() } : {}), redact: { disable, enable, allow: [...strs(fileCfg.allow), ...(v.allow ?? [])], note: v['no-note'] ? false : fileCfg.note !== false } };
}

function cmdStart(v: Values): Promise<number> {
  const cfg = loadConfig(v);
  const vault = new Vault(loadKey());
  const server = createProxy({ vault, upstreams: cfg.upstreams, redact: cfg.redact, allowUnredacted: cfg.allowUnredacted, ...(cfg.token ? { token: cfg.token } : {}), log: v.quiet ? undefined : (l) => console.log(l) });
  return new Promise((resolveExit) => {
    server.on('error', (err: NodeJS.ErrnoException) => {
      console.error(err.code === 'EADDRINUSE' ? `Port ${cfg.port} is in use — is llm-redact already running? Try --port.` : err.message);
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

function cmdScan(v: Values, file: string | undefined): number {
  const cfg = loadConfig(v);
  const raw = !file || file === '-' ? readFileSync(0, 'utf8') : readFileSync(file, 'utf8');
  const text = raw.charCodeAt(0) === 0xfeff ? raw.slice(1) : raw; // a BOM from PowerShell pipes
  const r = redactText(text, new Vault(loadKey()), cfg.redact);
  if (v.json) {
    const lineOf = (i: number) => text.slice(0, i).split('\n').length;
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
        throw new UsageError(`unknown command "${cmd}"`);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(err.message);
      return 2;
    }
    console.error((err as Error)?.stack ?? String(err));
    return 1;
  }
}
