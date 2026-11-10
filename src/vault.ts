/**
 * The vault maps placeholders to the real values they stand for.
 *
 * Placeholders are derived from an HMAC of the value with a key that never leaves this machine:
 *   [[REDACTED:openai_key:3f9a1c2b]]
 * so the same secret gets the same placeholder in every request, after every restart. That
 * matters twice: the model sees a consistent conversation, and the provider's prompt cache keeps
 * hitting (a placeholder that changed between requests would invalidate the cached prefix).
 *
 * The HMAC is truncated to 8 hex characters — enough to keep different values apart in one
 * conversation, far too short to brute-force anything from, and the key is local anyway.
 * Values live only in memory; after a restart the map refills itself, because the client resends
 * the real values in its history and they are redacted again to the same placeholders.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const PLACEHOLDER = /\[\[REDACTED:([a-z0-9_]{1,40}):([0-9a-f]{8})\]\]/g;

/**
 * Labels of values found by their *context* (`DB_PASSWORD=…`, `Bearer …`, `postgres://u:…@`), not
 * by their shape. Once restored, the model can put such a value anywhere — `psql -W Tr0ub4dor-zq9x`
 * — where no pattern would see it again, and the client would send it back in clear next turn. So
 * these values are remembered and redacted wherever they appear.
 */
export const CONTEXTUAL_LABELS = new Set(['secret_assignment', 'aws_secret_key', 'url_password', 'bearer_token']);
/** Shorter known values are not searched for everywhere: they would match ordinary text. */
const MIN_KNOWN = 8;
const MAX_KNOWN = 5_000;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

export class Vault {
  private readonly byPlaceholder = new Map<string, string>();
  private readonly byValue = new Map<string, string>();
  private readonly key: Buffer;
  /**
   * How many values to remember. A long-running proxy sees many; the least recently used is
   * forgotten first. Forgetting is safe: every request carries the conversation's values again,
   * which puts them back (under the same placeholder — it is an HMAC of the value).
   */
  readonly maxEntries: number;
  constructor(key: Buffer, maxEntries = 200_000) {
    this.key = key;
    this.maxEntries = maxEntries;
  }

  placeholderFor(label: string, value: string): string {
    const known = this.byValue.get(value);
    if (known) {
      this.touch(known, value);
      return known;
    }
    const tag = createHmac('sha256', this.key).update(value).digest('hex').slice(0, 8);
    let ph = `[[REDACTED:${label}:${tag}]]`;
    // Two different values with the same 8-hex tag (astronomically rare): keep them apart.
    for (let n = 2; this.byPlaceholder.has(ph) && this.byPlaceholder.get(ph) !== value; n++) ph = `[[REDACTED:${label}:${tag.slice(0, 6)}${n.toString(16).padStart(2, '0')}]]`;
    this.byPlaceholder.set(ph, value);
    this.byValue.set(value, ph);
    while (this.byPlaceholder.size > this.maxEntries) {
      const [oldPh, oldValue] = this.byPlaceholder.entries().next().value as [string, string];
      this.byPlaceholder.delete(oldPh);
      this.byValue.delete(oldValue);
    }
    if (CONTEXTUAL_LABELS.has(label)) this.remember(value, label);
    return ph;
  }

  // ---- values redacted wherever they appear ---------------------------------------------------
  private readonly known = new Map<string, string>(); // value -> label, least recently used first
  /** Every value ever added to `known`, in order: a cached result checks only those added after it. */
  private knownLog: string[] = [];
  /** Bumped when the log is compacted: older positions mean nothing any more. */
  private knownEpoch = 0;
  private knownRe: RegExp | undefined;

  private remember(value: string, label: string): void {
    if (value.length < MIN_KNOWN) return;
    if (this.known.has(value)) {
      this.known.delete(value);
      this.known.set(value, label);
      return;
    }
    this.known.set(value, label);
    this.knownLog.push(value);
    this.knownRe = undefined;
    if (this.known.size > MAX_KNOWN) this.known.delete(this.known.keys().next().value as string);
    if (this.knownLog.length > 4 * MAX_KNOWN) {
      this.knownLog = [];
      this.knownEpoch++;
    }
  }

  /** A pattern matching every known value (longest first), or undefined when there are none. */
  knownPattern(): RegExp | undefined {
    if (!this.known.size) return undefined;
    this.knownRe ??= new RegExp([...this.known.keys()].sort((a, b) => b.length - a.length).map(escapeRe).join('|'), 'g');
    return this.knownRe;
  }

  /** The label a known value was first redacted with. */
  knownLabel(value: string): string | undefined {
    return this.known.get(value);
  }

  /** Where the known-value log stands: a cache records this with each result. */
  get knownMark(): { epoch: number; at: number } {
    return { epoch: this.knownEpoch, at: this.knownLog.length };
  }

  /** Values learned since `mark`, or undefined when that can no longer be told (log compacted). */
  knownSince(mark: { epoch: number; at: number }): string[] | undefined {
    return mark.epoch === this.knownEpoch ? this.knownLog.slice(mark.at) : undefined;
  }

  /** Most recently used last (Map order is insertion order). */
  private touch(ph: string, value: string): void {
    this.byPlaceholder.delete(ph);
    this.byPlaceholder.set(ph, value);
    this.byValue.delete(value);
    this.byValue.set(value, ph);
  }

  /** The real value behind a placeholder, if this vault created it. */
  valueOf(placeholder: string): string | undefined {
    return this.byPlaceholder.get(placeholder);
  }

  get size(): number {
    return this.byPlaceholder.size;
  }

  /** Replace every known placeholder in `text`; unknown ones (a model inventing one) stay as they are. */
  restore(text: string, encode: (value: string) => string = (v) => v): string {
    if (!text.includes('[[REDACTED:')) return text;
    return text.replace(PLACEHOLDER, (ph) => {
      const v = this.byPlaceholder.get(ph);
      return v === undefined ? ph : encode(v);
    });
  }
}

export function defaultKeyPath(): string {
  const base = process.env.LLM_REDACT_HOME || (process.platform === 'win32' ? join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'llm-redact') : join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'llm-redact'));
  return join(base, 'key');
}

/** The current Windows account's SID (`S-1-5-21-…`), or undefined. */
function windowsSid(): string | undefined {
  try {
    const out = execFileSync('whoami', ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
    return /"(S-1-[\d-]+)"/.exec(out)?.[1];
  } catch {
    return undefined;
  }
}

/**
 * Write a file only you can read. POSIX: mode 600. Windows ignores modes and a new file inherits its
 * folder's ACL, which can include other accounts (sandbox groups, shared profiles) — so the file is
 * created empty, its ACL replaced by "owner only", and only then filled. Returns false when the
 * Windows ACL could not be set (the file is still written).
 */
export function writePrivate(path: string, content: string): boolean {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, '', { mode: 0o600 });
  let ok = true;
  if (process.platform === 'win32') {
    const sid = windowsSid();
    try {
      if (!sid) throw new Error('no SID');
      execFileSync('icacls', [path, '/inheritance:r', '/grant:r', `*${sid}:F`], { windowsHide: true, stdio: 'ignore' });
    } catch {
      ok = false;
    }
  } else chmodSync(path, 0o600);
  writeFileSync(path, content);
  return ok;
}

/** The local HMAC key: created once (32 random bytes), readable only by you. */
export function loadKey(path = defaultKeyPath()): Buffer {
  if (existsSync(path)) {
    const hex = readFileSync(path, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  }
  const key = randomBytes(32);
  writePrivate(path, key.toString('hex') + '\n');
  return key;
}
