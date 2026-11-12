// The Agent Skill (plugin/skills/llm-redact/SKILL.md) and the Claude Code plugin around it: the format, and that
// every command the skill gives an AI works and keeps the secret out of what it prints. Synthetic values only, in a
// temporary folder with its own config dirs.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BIN = join(ROOT, 'src', 'bin.ts');
const SKILL = readFileSync(join(ROOT, 'plugin', 'skills', 'llm-redact', 'SKILL.md'), 'utf8').replace(/\r\n/g, '\n');

function frontmatter(): Record<string, string> {
  const m = SKILL.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(m?.[1], 'the frontmatter starts on the first line');
  const out: Record<string, string> = {};
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([a-z-]+):\s*(.*)$/);
    if (kv?.[1]) out[kv[1]] = kv[2] ?? '';
  }
  return out;
}

test("the skill's frontmatter: portable fields only, within the limits", () => {
  const fm = frontmatter();
  assert.equal(fm.name, 'llm-redact');
  const allowed = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools']);
  for (const k of Object.keys(fm)) assert.ok(allowed.has(k), `${k} is a field every skill host accepts`);
  const description = fm.description ?? '';
  assert.ok(description.length > 100 && description.length <= 1536);
  assert.doesNotMatch(description, /[<>]/);
  assert.ok((fm.compatibility ?? '').length <= 500);
});

test('the plugin and its marketplace agree, and follow the package version', () => {
  const market = JSON.parse(readFileSync(join(ROOT, '.claude-plugin', 'marketplace.json'), 'utf8'));
  const plugin = JSON.parse(readFileSync(join(ROOT, 'plugin', '.claude-plugin', 'plugin.json'), 'utf8'));
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(market.plugins?.[0]?.name, plugin.name);
  assert.ok(existsSync(join(ROOT, market.plugins[0].source, '.claude-plugin', 'plugin.json')));
  assert.equal(plugin.version, pkg.version);
});

const PREFIX = 'npx -y github:zch6a/llm-redact';
function skillCommands(): string[][] {
  return [...SKILL.matchAll(/```bash\n([\s\S]*?)```/g)]
    .flatMap((m) => (m[1] ?? '').split('\n'))
    .filter((l) => l.startsWith(PREFIX))
    .map((l) => l.slice(PREFIX.length).trim().split(/\s+/).filter(Boolean));
}

test('the clients and shells the skill names are the ones env accepts', () => {
  const dir = mkdtempSync(join(tmpdir(), 'llm-redact-skill-'));
  const env = { ...process.env, APPDATA: join(dir, 'appdata'), XDG_CONFIG_HOME: join(dir, 'cfg'), HOME: dir, USERPROFILE: dir };
  try {
    const line = SKILL.split('\n').find((l) => l.startsWith('Clients:')) ?? '';
    const [clients = '', shells = ''] = line.split(';');
    const names = (s: string) => [...s.matchAll(/`([a-z]+)`/g)].map((m) => m[1] ?? '');
    assert.ok(names(clients).length >= 3 && names(shells).length >= 4, line);
    for (const client of names(clients)) {
      for (const shell of names(shells)) {
        const r = spawnSync(process.execPath, [BIN, 'env', client, '--shell', shell], { encoding: 'utf8', env });
        assert.equal(r.status, 0, `${client} / ${shell}: ${r.stderr}`);
        assert.match(r.stdout, /127\.0\.0\.1:\d+/, `${client} / ${shell}`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('every command the skill gives works, and no secret reaches its output', () => {
  const commands = skillCommands();
  assert.deepEqual(commands.map((c) => c.slice(0, 2).join(' ')), ['scan .env', 'scan .env', 'scan --body', 'env claude', 'detectors']);
  const dir = mkdtempSync(join(tmpdir(), 'llm-redact-skill-'));
  const env = { ...process.env, APPDATA: join(dir, 'appdata'), XDG_CONFIG_HOME: join(dir, 'cfg'), HOME: dir, USERPROFILE: dir, NO_COLOR: '1' };
  // Fake key shapes, put together at run time so no key-like string sits in the repository.
  const key = ['sk', 'ant', 'api03', 'x'.repeat(20) + 'FAKEFAKEFAKE' + 'y'.repeat(40)].join('-');
  const password = 'hunter2-not-real';
  const secrets = [key, password];
  writeFileSync(join(dir, '.env'), `DATABASE_URL=postgres://app:${password}@db.internal:5432/app\nANTHROPIC_API_KEY=${key}\nPORT=3000\n`);
  writeFileSync(
    join(dir, 'request.json'),
    JSON.stringify({ model: 'claude-x', messages: [{ role: 'user', content: `My key is ${key}, why does it fail?` }] }),
  );
  const run = (args: string[]) => spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8', env, cwd: dir });
  const clean = (out: string, what: string) => {
    for (const s of secrets) assert.ok(!out.includes(s), `${what} printed a secret`);
  };
  try {
    const [scanCmd = [], jsonCmd = [], bodyCmd = [], envCmd = [], detectorsCmd = []] = commands;

    const scan = run(scanCmd);
    assert.equal(scan.status, 0, scan.stderr);
    clean(scan.stdout + scan.stderr, 'scan');
    assert.match(scan.stdout, /\[\[REDACTED:anthropic_key:[0-9a-f]+\]\]/);
    assert.match(scan.stdout, /PORT=3000/, 'everything else is left as it was');
    assert.match(scan.stdout + scan.stderr, /2 value\(s\) would be redacted/, 'the summary line the skill quotes');

    const json = run(jsonCmd);
    assert.equal(json.status, 0, json.stderr);
    clean(json.stdout, 'scan --json');
    const report = JSON.parse(json.stdout);
    assert.ok('summary' in report);
    assert.equal(report.hits.length, 2);
    for (const hit of report.hits) for (const k of ['detector', 'kind', 'line', 'placeholder']) assert.ok(k in hit, k);
    assert.ok(report.hits.every((h: { kind: string }) => ['secret', 'pii'].includes(h.kind)));

    const body = run(bodyCmd);
    assert.equal(body.status, 0, body.stderr);
    clean(body.stdout + body.stderr, 'scan --body');
    assert.match(body.stdout, /anthropic_key/);

    const envOut = run(envCmd);
    assert.equal(envOut.status, 0, envOut.stderr);
    assert.match(envOut.stdout, /ANTHROPIC_BASE_URL=.*127\.0\.0\.1/);

    assert.equal(run(detectorsCmd).status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
