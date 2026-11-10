/**
 * What gets redacted. Every detector finds one kind of value and says which part of the match is
 * the value (`group`), so `password=hunter2` keeps `password=` and only the secret is replaced.
 *
 * Precision matters as much as recall: redacting a commit hash or a timestamp would break the
 * agent's work. So structured values are validated (Luhn, ID-card check digits, IBAN mod 97),
 * generic `KEY=value` assignments need a value that looks random, and obvious placeholders
 * (`your_api_key`, `xxx`, `${TOKEN}`) are left alone.
 *
 * Every quantifier is bounded: request bodies can be megabytes, and an unbounded pattern that
 * backtracks would stall every request.
 */

export type Kind = 'secret' | 'pii';

export interface Detector {
  /** Stable id, used in config (`--disable email`) and in placeholders. */
  id: string;
  kind: Kind;
  description: string;
  re: RegExp;
  /** Capture group holding the value (0 = whole match); with a list, the first group that matched. */
  group?: number | number[];
  validate?: (value: string, match: RegExpExecArray) => boolean;
  /** Removed from the end of the value (trailing punctuation), instead of a lookahead that backtracks. */
  trimEnd?: RegExp;
  /** Off unless enabled explicitly (too noisy for most code). */
  optional?: boolean;
}

// ---------------------------------------------------------------- validators

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Values that are obviously not real secrets: documentation placeholders and references. */
const PLACEHOLDER = /^(x+|\*+|\.+|-+|_+|0+|1234\d*|<[^>]*>|\$\{?[A-Za-z_][\w.]*\}?|%[A-Za-z_]+%|\{\{[^}]*\}\}|(your|my|the|a|an|some|example|sample|dummy|fake|test|changeme|change_me|placeholder|redacted|secret|password|passwd|token|apikey|api_key|key|value|xxx|todo|none|null|undefined|true|false)([_-][a-z0-9]{0,20}){0,6})$/i;

/** Words that make a value an example, not a credential: "ghp_your_github_token", "sk-your-secret-here". */
const EXAMPLE_WORDS = new Set(['your', 'my', 'example', 'sample', 'placeholder', 'here', 'xxx', 'xxxx', 'dummy', 'fake', 'invalid', 'changeme', 'replace', 'insert', 'enter', 'todo', 'redacted', 'new', 'goes', 'put', 'paste']);
/** Provider prefixes stripped before the placeholder check ("sk-", "ghp_", "xoxb-", "sk_live_"). */
const PROVIDER_PREFIX = /^(sk-(?:ant-|proj-)?|gh[pousr]_|github_pat_|glpat-|xox[a-z]-|(?:sk|rk|pk)_(?:live|test)_|hf_|npm_|AKIA|AIza)/i;

export function looksReal(value: string): boolean {
  // Documentation placeholders are written in one case (`YOUR_API_KEY`, `your-token-here`); a
  // generated value mixes cases, and must not pass for "a word plus suffixes" (`a_OY3uGb6me…`).
  const bare = value.replace(PROVIDER_PREFIX, '');
  const oneCase = (s: string) => s === s.toLowerCase() || s === s.toUpperCase();
  if ((oneCase(value) && PLACEHOLDER.test(value)) || (oneCase(bare) && PLACEHOLDER.test(bare))) return false;
  if (/^\[\[REDACTED:|^\[?REDACTED\]?$/i.test(value)) return false;
  // A number (a score, a count, a price) is not a credential.
  if (/^[+-]?\d[\d.,_]*(e[+-]?\d+)?[),;]*$/i.test(value)) return false;
  // References and templates: $VAR, $(cmd), %VAR%, {{x}}, <x>.
  if (/^[$%<]|^\{\{/.test(value)) return false;
  // Python f-strings and other prefixed literals: f"{x}", rb'…'.
  if (/^[frbu]{1,2}["']/i.test(value)) return false;
  // Sentences, ellipses and URLs are not credentials.
  // (A leading dash only when it is a command-line flag, `--max-tokens`: base64url values start with
  // `-` one time in 64.)
  if (/\s/.test(value) || /\.\.\.|…/.test(value) || /^[a-z][a-z0-9+.-]*:\/\//i.test(value) || /^--?[a-z][a-z0-9-]*$/.test(value)) return false;
  // Example words in a one-case value (`sk-your-key-here`); in a mixed-case one a segment `MY` is chance.
  if (oneCase(bare) && value.split(/[^A-Za-z0-9]+/).some((w) => EXAMPLE_WORDS.has(w.toLowerCase()))) return false;
  // Code: member access (a.b, a::b, a->b) or a call — `Environment.GetEnvironmentVariable(…)`, `result.tokens`.
  if (/[A-Za-z_$][\w$]*(?:\.|::|->)[A-Za-z_$]/.test(value) || /[A-Za-z_$][\w$]*\(/.test(value)) return false;
  // More code: negation, generics and indexing (`!visible`, `Omit<User, …>`, `stats[k]`), paths and
  // regex literals (`/secrets/key`, `./x`, `~/x`), and the tail of a placeholder (`3f9a1c2b]]`).
  // (Only code-shaped brackets: a generated password may well contain `<` or `]`.)
  if (/^[!/~]|^\.\.?\//.test(value) || /[A-Za-z_$][\w$]*<[A-Za-z_$]|<\/?[A-Za-z]|[\w$)]\[[\w$'".:-]*(?:\]|$)|\]\]|^\[/.test(value)) return false;
  // A bare identifier (letters and underscores, no digit): a variable name like `work_secret`, a type like `string`.
  // Identifiers are one case (`MAX_RETRY`) or camel case with few capitals (`ForgotPassword`); random
  // letters are about half capitals (`DPfZdPkOKHDaTnINNotSs`) — those are not names.
  if (/^[A-Za-z_]+[),;:]*$/.test(value) && value.length < 32) {
    const letters = value.replace(/[^A-Za-z]/g, '');
    if (oneCase(letters) || letters.replace(/[^A-Z]/g, '').length / letters.length < 0.35) return false;
  }
  // Mixed character classes, or high entropy: what generated secrets look like.
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  return entropy(value) >= 3 && (classes >= 2 || value.length >= 20);
}

export function luhn(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

/** Chinese resident identity card (GB 11643-1999): region, a real birth date, ISO 7064 MOD 11-2 check. */
export function cnIdValid(id: string): boolean {
  if (!/^[1-9]\d{16}[\dXx]$/.test(id)) return false;
  const y = Number(id.slice(6, 10));
  const m = Number(id.slice(10, 12));
  const d = Number(id.slice(12, 14));
  const date = new Date(Date.UTC(y, m - 1, d));
  if (y < 1900 || date.getUTCFullYear() !== y || date.getUTCMonth() !== m - 1 || date.getUTCDate() !== d || date.getTime() > Date.now()) return false;
  const weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
  let sum = 0;
  for (let i = 0; i < 17; i++) sum += (id.charCodeAt(i) - 48) * (weights[i] as number);
  return '10X98765432'[sum % 11] === id[17]?.toUpperCase();
}

/** IBAN (ISO 13616): move the first four characters to the end, letters to numbers, mod 97 = 1. */
export function ibanValid(raw: string): boolean {
  const iban = raw.replace(/\s/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const moved = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of v) rem = (rem * 10 + Number(digit)) % 97;
  }
  return rem === 1;
}

const EXAMPLE_EMAIL = /@(example\.(com|org|net)|[\w-]+\.(example|test|invalid|localhost)|localhost)$|^(noreply|no-reply|donotreply|do-not-reply|notifications?|git|root|admin|user|test|foo|bar|you|someone|name)@/i;

// ---------------------------------------------------------------- detectors

/** Ordered: earlier detectors win where matches overlap (specific before generic). */
export const DETECTORS: Detector[] = [
  // ---- private keys and connection strings
  { id: 'private_key', kind: 'secret', description: 'PEM private key block (also when truncated before its END line)', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]{20,16000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|(?:\r?\n[A-Za-z0-9+/=]{4,200}){1,400})/g },
  // ---- provider tokens (fixed prefixes: very low false-positive rate)
  { id: 'anthropic_key', kind: 'secret', description: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,200}/g },
  { id: 'openai_key', kind: 'secret', description: 'OpenAI / DeepSeek / compatible API key (sk-…)', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}/g, validate: (v) => !v.startsWith('sk-ant-') && looksReal(v.slice(3)) },
  { id: 'github_token', kind: 'secret', description: 'GitHub token', re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b/g },
  { id: 'gitlab_token', kind: 'secret', description: 'GitLab token', re: /\bgl(?:pat|dt|ptt|rt)-[A-Za-z0-9_-]{20,64}\b/g },
  { id: 'aws_access_key', kind: 'secret', description: 'AWS access key id', re: /\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b/g },
  { id: 'aws_secret_key', kind: 'secret', description: 'AWS secret access key (next to its name)', re: /\baws_?secret_?access_?key["']?\s{0,5}[:=]\s{0,5}["']?([A-Za-z0-9/+=]{40})\b/gi, group: 1 },
  { id: 'google_api_key', kind: 'secret', description: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: 'slack_token', kind: 'secret', description: 'Slack token', re: /\bxox[abposr]-[A-Za-z0-9-]{10,250}\b/g },
  { id: 'slack_webhook', kind: 'secret', description: 'Slack incoming webhook', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{6,20}\/B[A-Z0-9]{6,20}\/[A-Za-z0-9]{20,40}/g },
  { id: 'discord_webhook', kind: 'secret', description: 'Discord webhook', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{5,30}\/[A-Za-z0-9_-]{30,100}/g },
  { id: 'stripe_key', kind: 'secret', description: 'Stripe secret / restricted key', re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,250}\b/g },
  { id: 'npm_token', kind: 'secret', description: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'huggingface_token', kind: 'secret', description: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{34,40}\b/g },
  { id: 'telegram_bot_token', kind: 'secret', description: 'Telegram bot token', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { id: 'jwt', kind: 'secret', description: 'JSON Web Token', re: /\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,4000}\.[A-Za-z0-9_-]{10,2000}/g },
  // After the provider tokens: a GitHub token used as a URL password keeps its specific label.
  { id: 'url_password', kind: 'secret', description: 'Password inside a URL (postgres://user:PASSWORD@host)', re: /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`]{1,100}:([^\s@/'"`]{3,200})@[^\s/'"`,;@]{1,200}/gi, group: 1, validate: (v) => !/^\$\{?\w+\}?$|^\*+$|^(password|passwd|pass|pwd|secret|test|testing|postgres|root|admin|user|guest|example|changeme|dev|local|mysql|redis|app)$/i.test(v) && !/^\[\[REDACTED:|^\[?REDACTED\]?$/i.test(v) },
  { id: 'bearer_token', kind: 'secret', description: 'Bearer token in an Authorization header', re: /\b(?:Authorization|authorization)["']?\s{0,5}[:=]\s{0,5}["']?Bearer\s{1,5}([A-Za-z0-9._~+/=-]{16,2000})/g, group: 1, validate: (v) => looksReal(v) },

  // ---- generic: NAME=value where the name says secret and the value looks generated
  {
    id: 'secret_assignment',
    kind: 'secret',
    description: 'Value assigned to a name like *_SECRET, *_TOKEN, *PASSWORD, *_API_KEY',
    // The value: quoted (to the closing quote, honouring backslash escapes, so `"a\"b"` is one value)
    // or unquoted (to whitespace: quotes *inside* an unquoted .env value are part of it).
    // `pass` / `pw` only as a word of the name (`db.pass`, `DB_PW`), not inside one (`bypass`, `compass`).
    re: /\b([A-Za-z0-9_.-]{0,100}(?:secret|token|passwd|password|pwd|(?<![A-Za-z0-9])(?:pass|pw)(?![A-Za-z0-9_])|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credential)s?[A-Za-z0-9_]{0,20})["']?\s{0,5}(?:[:=]|=>|:=)\s{0,5}(?:"((?:[^"\\\n]|\\.){8,400})"|'((?:[^'\\\n]|\\.){8,400})'|`([^`\n]{8,400})`|([^\s"'`<>({\[\\;](?:[^\s\\;]|\\(?![nrt])){7,399}))/gi,
    trimEnd: /[,;)}\]]+$/,
    group: [2, 3, 4, 5],
    validate: (v, m) => {
      const name = (m[1] as string).toLowerCase();
      // Names that say "a count / a place / a kind", not "a credential": max_tokens, token_endpoint, secret_name.
      if (/(type|length|count|name|file|path|url|uri|endpoint|host|domain|server|base|prefix|header|field|id|limit|budget|usage|ttl|hint|label|format|expir\w*)s?$/.test(name)) return false;
      if (/^(max|min|num|n|total|input|output|prompt|completion|cached?|cache_read|cache_creation|remaining|used|reasoning)[_-]?tokens?(_[a-z]+)?$|^tokens$/.test(name)) return false;
      return looksReal(v) && !/^(true|false|null|none|undefined)$/i.test(v);
    },
  },

  // ---- personal data
  { id: 'email', kind: 'pii', description: 'E-mail address', re: /(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}\b/g, validate: (v) => !EXAMPLE_EMAIL.test(v) && !/@\d+\.\d+/.test(v) && !/\.(png|jpe?g|gif|svg|webp|js|ts|css)$/i.test(v) },
  { id: 'cn_id_card', kind: 'pii', description: 'Chinese resident ID number (checksum validated)', re: /(?<![\dA-Za-z])[1-9]\d{16}[\dXx](?![\dA-Za-z])/g, validate: (v) => cnIdValid(v) },
  { id: 'cn_mobile', kind: 'pii', description: 'Chinese mobile number', re: /(?<![\dA-Za-z+.-])(?:\+?86[ -]?)?1[3-9]\d[ -]?\d{4}[ -]?\d{4}(?![\dA-Za-z])/g },
  { id: 'phone', kind: 'pii', description: 'Phone number in international format (+1 415 555 0100)', re: /(?<![\w+])\+[1-9]\d{0,2}[ .-]?\(?\d{1,4}\)?(?:[ .-]?\d{2,4}){2,4}(?![\w])/g, validate: (v) => v.replace(/\D/g, '').length >= 9 && v.replace(/\D/g, '').length <= 15 },
  // Not the digits of a decimal (65.4545454545454 passes Luhn by chance) or of a longer number.
  { id: 'credit_card', kind: 'pii', description: 'Payment card number (Luhn validated)', re: /(?<![\d.,-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{4}|\d{4}([ -])\d{6}\2\d{5}|\d{13,19})(?![\d-]|[.,]\d)/g, validate: (v) => {
    const d = v.replace(/\D/g, '');
    return d.length >= 13 && d.length <= 19 && /^(4|5[1-5]|2[2-7]|3[47]|6(011|5|4[4-9]|22)|35|62)/.test(d) && luhn(d) && !/^(\d)\1+$/.test(d);
  } },
  { id: 'iban', kind: 'pii', description: 'IBAN (mod-97 validated)', re: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b/g, validate: (v) => ibanValid(v) },
  { id: 'us_ssn', kind: 'pii', description: 'US Social Security number', re: /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g },
  { id: 'ipv4', kind: 'pii', description: 'Public IPv4 address', optional: true, re: /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g, validate: (v) => !/^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|255\.)/.test(v) },
];

export const DETECTOR_BY_ID = new Map(DETECTORS.map((d) => [d.id, d]));

/** A JSON key / field name that says its value is a secret (`password`, `pw`, `api_key`, `clientSecret`). */
const SECRET_KEY = /^(?:[A-Za-z0-9_.-]{0,40}[_.-])?(?:secret|token|passwd|password|pwd|pw|pass|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)s?$|(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey)$/i;

/**
 * In structured data the key is the context the NAME=value rule would see in text: a string under
 * a secret-named key is a secret if it looks generated (`{"pw": "P\"a\\ss-W0rd-9xQ"}`).
 */
export function secretByKey(key: string, value: string): boolean {
  return SECRET_KEY.test(key) && value.length >= 8 && value.length <= 400 && !/\s/.test(value) && looksReal(value) && !/^\[\[REDACTED:/.test(value);
}
