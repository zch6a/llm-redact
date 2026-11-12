/**
 * The findings of the 2026-11 independent review (11 problems, each reproduced before it was fixed), kept fixed.
 * No network: a mock upstream on 127.0.0.1. Fake secrets only.
 */
import './isolate.ts';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { createServer, request, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { redactRequest } from '../src/body.ts';
import { jsonErrorPlace } from '../src/cli.ts';
import { createProxy } from '../src/proxy.ts';
import { redactText } from '../src/redact.ts';
import { Vault, defaultKeyPath } from '../src/vault.ts';

const BIN = fileURLToPath(new URL('../src/bin.ts', import.meta.url));
const v = (n: number) => new Vault(Buffer.alloc(32, n));
const noLeak = (text: string, ...values: string[]) => {
  for (const x of values) assert.ok(!text.includes(x), `leaked ${x} in ${text.slice(0, 200)}`);
};
const PW = 'Tr0ub4dorFAKE9xQ';

describe('review 2: detectors', () => {
  it('a NAME=value inside a quoted string ends at the quote, and the bare value is known afterwards', () => {
    const shapes = [
      `[{"Config": {"Env": ["DB_PASSWORD=${PW}", "PATH=/usr/bin"]}}]`,
      `env: ['DB_PASSWORD=${PW}', 'X=1']`,
      `cmd = "export DB_PASSWORD=${PW}"`,
      `<env name="x" value="DB_PASSWORD=${PW}"/>`,
      `subprocess.run(["psql", "--password=${PW}"])`,
    ];
    for (const s of shapes) {
      const vault = v(70);
      const r = redactText(s, vault);
      noLeak(r.text, PW);
      const values = r.hits.filter((h) => h.start >= 0).map((h) => s.slice(h.start, h.end));
      assert.ok(values.includes(PW), `${s}: the value is the password, without the quote (${values.join(' | ')})`);
      // "Once a secret, always a secret": later, without its name.
      noLeak(redactText(`psql -W ${PW} -h db`, vault).text, PW);
    }
  });

  it('formats that were missed', () => {
    const cases = [
      'REDIS_URL=redis://:S3cr3tFAKEpassw0rd@redis:6379/0',
      'redis://:S3cr3t!FAKE#pw@redis.internal:6379',
      `key=AIzaSy${'FAKE'.repeat(7)}FAKE-&callback=init`,
      `bot 123456789:AA${'FAKE'.repeat(8)}- end`,
      'curl -H "authorization: bearer 9f8e7d6c5b4a3928FAKE1706f5e4d3c2b1a0"',
      'AUTHORIZATION: Bearer 9f8e7d6c5b4a3928FAKE1706f5e4d3c2b1a0',
      'Authorization: Token 9f8e7d6c5b4a3928FAKE1706f5e4d3c2b1a0',
      `SECRET_KEY_BASE=${'a1b2c3d4e5f6'.repeat(10)}`,
      `secret_key_base: ${'a1b2c3d4e5f6'.repeat(10)}`,
      'DB_PASSWORD=Tr0ub4!',
    ];
    for (const s of cases) {
      const r = redactText(s, v(71));
      assert.ok(r.hits.length > 0, `missed: ${s}`);
      for (const h of r.hits) if (h.start >= 0) noLeak(r.text, s.slice(h.start, h.end));
    }
    assert.match(redactText('REDIS_URL=redis://:S3cr3tFAKEpassw0rd@redis:6379/0', v(72)).text, /redis:\/\/:\[\[REDACTED:url_password:[0-9a-f]{8}\]\]@redis:6379\/0/);
  });

  it('numeric HTML entities are decoded before matching', () => {
    for (const s of ['contact: li.wei&#64;corp-mail.cn', 'contact: li.wei&#x40;corp-mail.cn', '<a title="&#x41;KIAFAKEFAKEFAKE1234">']) assert.ok(redactText(s, v(73)).hits.length > 0, s);
  });
});

describe('review 2: request bodies', () => {
  const KEY = 'AKIAFAKEFAKEFAKE1234';
  it('plain text under a data key is not taken for base64 and skipped', () => {
    const text = `${KEY}\n`.repeat(20);
    const anthropic = { model: 'm', messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'text', media_type: 'text/plain', data: text } }] }] };
    noLeak(JSON.stringify(redactRequest(anthropic, v(74), 'anthropic').body), KEY);
    const toolArgs = { model: 'm', messages: [{ role: 'assistant', content: [{ type: 'tool_use', id: 't', name: 'write', input: { path: 'creds.txt', data: text } }] }] };
    noLeak(JSON.stringify(redactRequest(toolArgs, v(75), 'anthropic').body), KEY);
  });

  it('base64 of a text file under a data key is redacted; a real image is left alone', () => {
    const b64 = Buffer.from(`aws_access_key_id = ${KEY}\n`.repeat(20)).toString('base64');
    const out = JSON.stringify(redactRequest({ model: 'm', input: [{ type: 'input_file', file_data: b64 }] }, v(76), 'responses').body);
    assert.ok(!out.includes(b64), 'the text file was redacted');
    assert.ok(!Buffer.from(JSON.parse(out).input[0].file_data, 'base64').toString('utf8').includes(KEY));
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(400, 7)]).toString('base64');
    const img = { model: 'm', messages: [{ role: 'user', content: [{ type: 'image', source: { type: 'base64', media_type: 'image/png', data: png } }] }] };
    assert.equal(JSON.parse(JSON.stringify(redactRequest(img, v(77), 'anthropic').body)).messages[0].content[0].source.data, png);
  });

  it('a text document whose media type has parameters is still text', () => {
    const data = Buffer.from(`token=sk-ant-api03-${'FAKE'.repeat(12)}\n`).toString('base64');
    const body = { model: 'm', messages: [{ role: 'user', content: [{ type: 'document', source: { type: 'base64', media_type: 'text/plain; charset=utf-8', data } }] }] };
    const out = JSON.parse(JSON.stringify(redactRequest(body, v(78), 'anthropic').body));
    noLeak(Buffer.from(out.messages[0].content[0].source.data, 'base64').toString('utf8'), 'sk-ant-api03-FAKE');
  });
});

describe('review 2: the proxy', () => {
  let upstream: Server;
  let proxy: ReturnType<typeof createProxy>;
  let px = '';
  let seen: { headers: Record<string, unknown>; body: string } = { headers: {}, body: '' };
  const log: string[] = [];
  before(async () => {
    upstream = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const ch of req) chunks.push(ch as Buffer);
      seen = { headers: req.headers, body: Buffer.concat(chunks).toString('utf8') };
      if ((req.url ?? '').includes('big')) {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        const chunk = Buffer.alloc(64 * 1024, 120);
        // Far more than a client's socket buffer: the proxy has to wait for the client to read.
        for (let i = 0; i < 400 && !res.destroyed; i++) if (!res.write(chunk)) await new Promise((r) => res.once('drain', r));
        return res.end();
      }
      res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
      res.end('{"ok":true}');
    });
    await new Promise<void>((r) => upstream.listen(0, '127.0.0.1', r));
    proxy = createProxy({ vault: v(79), upstreams: { mock: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}` }, redact: {}, log: (l) => log.push(l) });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', r));
    px = `http://127.0.0.1:${(proxy.address() as AddressInfo).port}/mock`;
  });
  after(() => {
    upstream.close();
    proxy.close();
  });

  it('a body that is not UTF-8 (UTF-16 sent as text/plain) is refused, not forwarded', async () => {
    const body = Buffer.from(`key sk-ant-api03-${'FAKE'.repeat(12)}`, 'utf16le');
    const res = await fetch(`${px}/v1/x`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body });
    assert.equal(res.status, 415);
  });

  it('Proxy-Authorization is not forwarded; the provider\'s CORS headers are not passed back', async () => {
    const res = await fetch(`${px}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'proxy-authorization': 'Basic RkFLRTpGQUtF' }, body: '{"model":"m","messages":[]}' });
    assert.equal(res.status, 200);
    assert.equal(seen.headers['proxy-authorization'], undefined);
    assert.equal(res.headers.get('access-control-allow-origin'), null);
  });

  it('a client that stops reading and disconnects does not leave its handler stuck', async () => {
    const before = log.length;
    await new Promise<void>((resolve) => {
      const u = new URL(`${px}/v1/big`);
      const req = request({ host: u.hostname, port: u.port, path: u.pathname, method: 'POST', headers: { 'content-type': 'application/json' } }, (res) => {
        res.pause(); // never read
        setTimeout(() => {
          res.destroy();
          resolve();
        }, 300);
      });
      req.end('{"model":"m"}');
    });
    for (let i = 0; i < 50 && log.length === before; i++) await new Promise((r) => setTimeout(r, 100));
    assert.match(log.slice(before).join('\n'), /client went away|aborted/, 'the handler finished and logged');
  });
});

describe('review 2: command line', () => {
  it('an empty or invalid token file is replaced, so --require-token cannot turn itself off', () => {
    const file = join(dirname(defaultKeyPath()), 'token');
    mkdirSync(dirname(file), { recursive: true });
    for (const content of ['', '   \n', 'abc']) {
      writeFileSync(file, content);
      const r = spawnSync(process.execPath, [BIN, 'env', '--require-token', '--shell', 'bash'], { encoding: 'utf8' });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /127\.0\.0\.1:\d+\/[0-9a-f]{32}\//, `token file ${JSON.stringify(content)}`);
    }
  });

  it('a JSON error says where, never quotes the input', () => {
    let err: unknown;
    try {
      JSON.parse('{"k":"sk-ant-api03-defFAKE"},]}');
    } catch (e) {
      err = e;
    }
    const place = jsonErrorPlace(err);
    assert.ok(!place.includes('FAKE'), place);
    const r = spawnSync(process.execPath, [BIN, 'scan', '--body', '-'], { input: '{"k":"sk-ant-api03-defFAKE"},]}', encoding: 'utf8' });
    assert.ok(!(r.stdout + r.stderr).includes('defFAKE'), r.stderr);
  });

  it('the config file errors name the setting\'s value', () => {
    const dir = dirname(defaultKeyPath());
    writeFileSync(join(dir, 'cfg-bad-port.json'), '{"port": 70000}');
    const r = spawnSync(process.execPath, [BIN, 'env', '--config', join(dir, 'cfg-bad-port.json')], { encoding: 'utf8' });
    assert.match(r.stderr, /bad port 70000/);
  });
});

describe('review 2: speed', () => {
  it('long runs that matched at every position are linear now', () => {
    for (const s of ['eyJ-'.repeat(250_000), '-----BEGIN PRIVATE KEY-----\n'.repeat(36_000)]) {
      const t = performance.now();
      redactText(s, v(80));
      const ms = performance.now() - t;
      // Was about 1 s on a fast machine; generous for a shared CI runner.
      assert.ok(ms < 2500, `${ms.toFixed(0)} ms for ${s.slice(0, 12)}…`);
    }
  });
});
