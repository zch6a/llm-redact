import './isolate.ts';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { cnIdValid, entropy, ibanValid, looksReal, luhn } from '../src/detectors.ts';
import { redactText, summarize } from '../src/redact.ts';
import { StreamRestorer, couldBePlaceholder } from '../src/stream.ts';
import { PLACEHOLDER, Vault, loadKey } from '../src/vault.ts';
import { VERSION } from '../src/version.ts';

const KEY = Buffer.alloc(32, 7);
const vault = () => new Vault(KEY);
/** Synthetic values: shaped like real ones, valid for no service. */
const FAKE = {
  anthropic: 'sk-ant-api03-' + 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z'.repeat(3),
  openai: 'sk-proj-' + 'Qw3rTy6uIo9pAs2dFg5hJk8l'.repeat(2),
  github: 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0'.repeat(2).slice(0, 36),
  aws: 'AKIA' + 'Q7XK2M9PLW4ZT8RB',
  google: 'AIza' + 'Sy' + 'D8f3kLm2Qp9Xw4Zt7Vb1Nc6Hj5Rg0Ys3E',
  slack: 'xoxb-' + '2345678901-2345678901234-AbCdEfGhIjKlMnOpQrStUvWx',
  stripe: 'sk_live_' + '51HcX7kLm2Qp9Xw4Zt7Vb1Nc',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk',
};

const redact = (t: string, opts = {}) => redactText(t, vault(), opts);
const ids = (t: string, opts = {}) => redact(t, opts).hits.map((h) => h.detector);

describe('detectors: recall', () => {
  const cases: [string, string, string][] = [
    ['anthropic_key', `ANTHROPIC_API_KEY=${FAKE.anthropic}`, FAKE.anthropic],
    ['openai_key', `client = OpenAI(api_key="${FAKE.openai}")`, FAKE.openai],
    ['github_token', `git clone https://x:${FAKE.github}@github.com/o/r`, FAKE.github],
    ['aws_access_key', `aws_access_key_id = ${FAKE.aws}`, FAKE.aws],
    ['aws_secret_key', 'aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKY', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKY'],
    ['google_api_key', `key=${FAKE.google}`, FAKE.google],
    ['slack_token', `SLACK=${FAKE.slack}`, FAKE.slack],
    ['stripe_key', `stripe.api_key = "${FAKE.stripe}"`, FAKE.stripe],
    ['jwt', `token: ${FAKE.jwt}`, FAKE.jwt],
    ['url_password', 'DATABASE_URL=postgres://app:Xq7-mZ2pL9vT@db.internal:5432/prod', 'Xq7-mZ2pL9vT'],
    ['secret_assignment', 'DB_PASSWORD=Tr0ub4dor&3xK9', 'Tr0ub4dor&3xK9'],
    ['bearer_token', 'Authorization: Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0', '9f8e7d6c5b4a39281706f5e4d3c2b1a0'],
    ['email', 'Contact me at li.wei@corp-mail.cn for access.', 'li.wei@corp-mail.cn'],
    ['cn_mobile', '电话 138 1234 5678，微信同号', '138 1234 5678'],
    ['cn_id_card', '身份证 11010519491231002X', '11010519491231002X'],
    ['credit_card', 'card 4111 1111 1111 1111 exp 12/29', '4111 1111 1111 1111'],
    ['iban', 'IBAN GB82 WEST 1234 5698 7654 32', 'GB82 WEST 1234 5698 7654 32'],
    ['us_ssn', 'SSN 123-45-6789', '123-45-6789'],
    ['phone', 'Call +1 415 555 0100 tomorrow', '+1 415 555 0100'],
  ];
  for (const [id, text, value] of cases) {
    it(id, () => {
      const r = redact(text);
      assert.ok(r.hits.some((h) => h.detector === id), `${id} not found in ${JSON.stringify(text)}: ${JSON.stringify(r.hits)}`);
      assert.ok(!r.text.includes(value), `value still present: ${r.text}`);
    });
  }
  it('a PEM private key block as one value', () => {
    const pem = `-----BEGIN OPENSSH PRIVATE KEY-----\n${'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n'.repeat(6)}-----END OPENSSH PRIVATE KEY-----`;
    const r = redact(`key:\n${pem}\nend`);
    assert.deepEqual(r.hits.map((h) => h.detector), ['private_key']);
    assert.match(r.text, /^key:\n\[\[REDACTED:private_key:[0-9a-f]{8}\]\]\nend$/);
  });
  it('values with quotes and escapes are redacted whole (a partial match would leak the rest)', () => {
    const cases: [string, string][] = [
      ['DB_PASSWORD=P"a\\ss-W0rd-9xQz', 'W0rd-9xQz'], // unquoted .env value containing a quote
      ['{"password": "abc\\"Def9xQz12"}', 'Def9xQz12'], // JSON text with an escaped quote
      ["api_key: 'Zq8-mW3pL7vT2k'", 'Zq8-mW3pL7vT2k'],
    ];
    for (const [text, rest] of cases) {
      const r = redact(text);
      assert.ok(!r.text.includes(rest), `${text} → ${r.text}`);
    }
    assert.match(redact('password: Tr0ub4dor&3xK9, next').text, /: \[\[REDACTED:secret_assignment:[0-9a-f]{8}\]\], next$/, 'trailing punctuation stays outside');
  });
  it('a value under a secret-named key in structured data', async () => {
    const { secretByKey } = await import('../src/detectors.ts');
    assert.ok(secretByKey('pw', 'P"a\\ss-W0rd-9xQz'));
    assert.ok(secretByKey('clientSecret', 'Zq8mW3pL7vT2kXr4'));
    assert.ok(!secretByKey('pw', 'changeme'));
    assert.ok(!secretByKey('token_count', '128000'));
    assert.ok(!secretByKey('name', 'Zq8mW3pL7vT2kXr4'));
  });
  it('keeps the name, replaces only the value', () => {
    assert.match(redact('DB_PASSWORD=Tr0ub4dor&3xK9').text, /^DB_PASSWORD=\[\[REDACTED:secret_assignment:[0-9a-f]{8}\]\]$/);
    assert.match(redact('postgres://app:Xq7-mZ2pL9vT@db:5432/x').text, /^postgres:\/\/app:\[\[REDACTED:url_password:[0-9a-f]{8}\]\]@db:5432\/x$/);
  });
});

describe('detectors: precision', () => {
  const clean = [
    'commit 3f9a1c2b7d4e6f8091a2b3c4d5e6f708192a3b4c',
    'id: 550e8400-e29b-41d4-a716-446655440000',
    'created_at: 1731312000000 (ms)',
    'version 1.13.0, unix time 1731312000', // 10 digits
    'order no. 113800138000', // 12 digits: not a mobile number
    'password=your_password',
    'API_KEY=${API_KEY}',
    'token: process.env.GITHUB_TOKEN',
    'SECRET_KEY = os.environ["SECRET_KEY"]',
    'api_key: <your-api-key>',
    'password: "changeme"',
    'token_type = "Bearer"',
    'token_count: 128000',
    'max_tokens=4096',
    'secret_name = projects/x/secrets/db',
    'user@example.com and noreply@github.com',
    'The task-1234567890abcdefghij id and the desk-sk-alike word',
    'import icon from "./logo@2x.png"',
    'phone_ext = 4111', // not a card
    'price 1234 5678 9012 3456', // fails Luhn
    'tel 12345678901', // not a CN mobile (12…)
    '11010519491231002Y', // bad ID check digit
    'GB82 WEST 1234 5698 7654 33', // bad IBAN check
    '[[REDACTED:openai_key:3f9a1c2b]]', // already a placeholder
    // Found by running the detectors over 2,955 real files (public skill repos + this workspace):
    'ApiKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY")',
    'long tokens = result.InputTokens;',
    '-H "x-api-key: $ANTHROPIC_API_KEY" \\',
    '{"model":"claude-x","max_tokens":16000,"messages":[]}',
    'token_endpoint: "https://slack.com/api/oauth.v2.access",',
    "authorization_token: 'ghp_your_github_token',",
    '"secret_value": "sk-your-secret-here",',
    'ANTHROPIC_API_KEY=sk-ant-invalid',
    'CREDENTIALS_HINT = "set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN"',
    'max_tokens = --max-tokens',
    '"x-api-key": api_key,',
    'work_secret=work_secret,',
    '"token_efficiency": 0.9387755102040816,',
    'login(email: string, password: string): Promise<void>;',
    'type UserWithoutPassword = Omit<User, "password">;',
    '--from-file=API_KEY=/secrets/api-key',
    'passwordVisible = !passwordVisible',
    '"composite": 65.45454545454545,', // a decimal that passes Luhn
    'DATABASE_URL: postgres://postgres:test@localhost/test',
  ];
  for (const text of clean)
    it(`leaves alone: ${text.slice(0, 60)}`, () => {
      assert.deepEqual(ids(text), [], `false positive in ${JSON.stringify(text)}`);
    });
  it('optional detectors are off by default', () => {
    assert.deepEqual(ids('server at 8.8.8.8'), []);
    assert.deepEqual(ids('server at 8.8.8.8', { enable: ['ipv4'] }), ['ipv4']);
    assert.deepEqual(ids('lan 192.168.1.10', { enable: ['ipv4'] }), [], 'private ranges are not personal data');
  });
  it('disable by id or kind, and allow lists', () => {
    assert.deepEqual(ids('mail li.wei@corp-mail.cn', { disable: ['email'] }), []);
    assert.deepEqual(ids(`mail li.wei@corp-mail.cn key ${FAKE.github}`, { disable: ['pii'] }), ['github_token']);
    assert.deepEqual(ids('mail li.wei@corp-mail.cn', { allow: ['li.wei@corp-mail.cn'] }), []);
  });
});

describe('validators', () => {
  it('luhn, ID card, IBAN, entropy, looksReal', () => {
    assert.ok(luhn('4111111111111111'));
    assert.ok(!luhn('4111111111111112'));
    assert.ok(cnIdValid('11010519491231002X'));
    assert.ok(!cnIdValid('11010519491231002Y'));
    assert.ok(!cnIdValid('11010520991231002X'), 'birth date in the future');
    assert.ok(ibanValid('GB82WEST12345698765432'));
    assert.ok(!ibanValid('GB82WEST12345698765433'));
    assert.ok(entropy('aaaaaaaa') < 1 && entropy('Xq7-mZ2pL9vT') > 3);
    assert.ok(!looksReal('your_api_key_here') && !looksReal('xxxxxxxxxxxx') && looksReal('Tr0ub4dor&3xK9'));
  });
});

describe('vault', () => {
  it('same value, same placeholder — across vault instances with the same key (prompt caches keep hitting)', () => {
    const a = redact(`k=${FAKE.github}`).text;
    const b = redactText(`other text, k=${FAKE.github}`, vault()).text;
    const ph = a.slice(2);
    assert.ok(b.endsWith(ph));
    const other = redactText(`k=${FAKE.github}`, new Vault(Buffer.alloc(32, 9))).text;
    assert.notEqual(other, a, 'a different local key gives different placeholders');
  });
  it('restores exactly; unknown placeholders stay', () => {
    const v = vault();
    const original = `Use ${FAKE.openai} and mail li.wei@corp-mail.cn.`;
    const { text } = redactText(original, v);
    assert.equal(v.restore(text), original);
    assert.equal(v.restore('[[REDACTED:openai_key:00000000]]'), '[[REDACTED:openai_key:00000000]]');
    assert.equal(v.size, 2);
  });
  it('restore can encode for the context (inside a JSON string fragment)', () => {
    const v = vault();
    const ph = v.placeholderFor('secret_assignment', 'a"b\\c');
    const fragment = `{"pw":"${ph}"}`;
    const restored = v.restore(fragment, (s) => JSON.stringify(s).slice(1, -1));
    assert.deepEqual(JSON.parse(restored), { pw: 'a"b\\c' }, 'still valid JSON with the real value');
  });
  it('summarize reports counts, never values', () => {
    const s = summarize(redactText(`a ${FAKE.github} b ${FAKE.github} mail li.wei@corp-mail.cn`, vault()).hits);
    assert.deepEqual(s, { github_token: 2, email: 1 });
  });
  it('creates a 32-byte key file once and reuses it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'lr-key-'));
    try {
      const p = join(dir, 'sub', 'key');
      const k1 = loadKey(p);
      const k2 = loadKey(p);
      assert.equal(k1.length, 32);
      assert.deepEqual(k1, k2);
      assert.match(readFileSync(p, 'utf8'), /^[0-9a-f]{64}\n$/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('stream restorer', () => {
  const v = vault();
  const secretText = `Here is your config:\nOPENAI_API_KEY=${FAKE.openai}\nGITHUB=${FAKE.github} and [[wiki]] links, a[i] and [[REDACTED:openai_key:00000000]] stay.`;
  const redacted = redactText(secretText, v).text;

  it('recognises partial placeholders', () => {
    for (const s of ['[', '[[', '[[RED', '[[REDACTED:', '[[REDACTED:openai_key', '[[REDACTED:openai_key:3f9a', '[[REDACTED:openai_key:3f9a1c2b]']) assert.ok(couldBePlaceholder(s), s);
    for (const s of ['[[wiki', '[x', '[[REDACTED:Open', '[[REDACTED:a:xyz']) assert.ok(!couldBePlaceholder(s), s);
  });
  it('restores correctly however the stream is split (every split point)', () => {
    for (let cut = 0; cut <= redacted.length; cut++) {
      const r = new StreamRestorer(v);
      const out = r.push(redacted.slice(0, cut)) + r.push(redacted.slice(cut)) + r.flush();
      assert.equal(out, v.restore(redacted), `split at ${cut}`);
    }
  });
  it('restores correctly with random chunk sizes, and never emits a placeholder fragment', () => {
    let seed = 1;
    const rand = (n: number) => ((seed = (seed * 48271) % 2147483647) % n) + 1;
    for (let round = 0; round < 300; round++) {
      const r = new StreamRestorer(v);
      let out = '';
      for (let i = 0; i < redacted.length; ) {
        const n = rand(9);
        const piece = r.push(redacted.slice(i, i + n));
        assert.ok(!/\[\[REDACTED:[a-z_]+:[0-9a-f]{8}\]\]/.test(piece) || piece.includes('00000000'), 'a known placeholder leaked unrestored');
        out += piece;
        i += n;
      }
      out += r.flush();
      assert.equal(out, secretText.replace('[[REDACTED:openai_key:00000000]]', '[[REDACTED:openai_key:00000000]]'));
    }
  });
  it('does not delay ordinary text', () => {
    const r = new StreamRestorer(v);
    assert.equal(r.push('array[i] = 1; see [[Main Page'), 'array[i] = 1; see [[Main Page');
    assert.equal(r.push(' [[RE'), ' ');
    assert.equal(r.push('ST]] done'), '[[REST]] done');
  });
});

describe('performance', () => {
  it('hostile input cannot make the detectors backtrack', () => {
    const N = 200_000;
    const hostile = {
      'long word': 'a'.repeat(N),
      'secret names, no values': 'password='.repeat(N / 9),
      'url no @': 'postgres://u:' + 'p'.repeat(N),
      'digits': '1 '.repeat(N / 2),
      'emails no tld': 'a@'.repeat(N / 2),
      'placeholder-ish': 'your_'.repeat(N / 5) + '!',
      'pem no end': '-----BEGIN PRIVATE KEY-----' + 'A'.repeat(N),
      'jwt dots': 'eyJ' + 'a.'.repeat(N / 2),
    };
    for (const [name, text] of Object.entries(hostile)) {
      const t = performance.now();
      redact(text);
      const ms = performance.now() - t;
      assert.ok(ms < 1500, `${name}: ${ms.toFixed(0)} ms`);
    }
  });
});

describe('meta', () => {
  it('version matches package.json', () => {
    assert.equal(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version, VERSION);
  });
  it('placeholder pattern is global (restore replaces every occurrence)', () => {
    assert.ok(PLACEHOLDER.flags.includes('g'));
  });
});
