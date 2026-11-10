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
import { appendFileSync, chmodSync, existsSync, linkSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const PLACEHOLDER = /\[\[REDACTED:([a-z0-9_]{1,40}):([0-9a-f]{8})\]\]/g;

/**
 * Labels of values found by their *context* (`DB_PASSWORD=…`, `Bearer …`, `postgres://u:…@`), not
 * by their shape. Once restored, the model can put such a value anywhere — `psql -W Tr0ub4dor-zq9x`
 * — where no pattern would see it again, and the client would send it back in clear next turn. So
 * these values are remembered and redacted wherever they appear.
 */
/** First line of the `remembered` file: its format, so a later version can tell it apart. */
export const REMEMBERED_HEADER = '# llm-redact remembered v1: HMAC-SHA256(key, `known\\0` + value) as 32 hex, a tab, the label\n';

export const CONTEXTUAL_LABELS = new Set(['secret_assignment', 'aws_secret_key', 'url_password', 'bearer_token']);
/**
 * Known values of 8+ characters are matched anywhere; shorter ones (a URL password like `s3cr3t`)
 * only as a whole word and only when they mix letters and digits or symbols — `admin` would match
 * ordinary text.
 */
const MIN_KNOWN = 8;
const MIN_KNOWN_SHORT = 4;
const MAX_KNOWN = 5_000;
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const classes = (s: string) => [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(s)).length;

/** What restores placeholders: the vault itself, or a scope of it (see `Vault.scope`). */
export interface Restorer {
  restore(text: string, encode?: (value: string) => string): string;
}

export interface VaultOptions {
  /** How many values to keep (least recently used forgotten first). */
  maxEntries?: number;
  /**
   * A file for the *hashes* of remembered values (HMAC with the key, never a value), so values found
   * by their context are still recognised after a restart, when that context may be gone from the
   * conversation (compacted into a summary).
   */
  rememberFile?: string;
}

export class Vault implements Restorer {
  private readonly byPlaceholder = new Map<string, string>();
  private readonly byValue = new Map<string, string>();
  private readonly key: Buffer;
  /**
   * How many values to remember. A long-running proxy sees many; the least recently used is
   * forgotten first. Forgetting is safe: every request carries the conversation's values again,
   * which puts them back (under the same placeholder — it is an HMAC of the value).
   */
  readonly maxEntries: number;
  private readonly rememberFile: string | undefined;
  constructor(key: Buffer, o: VaultOptions = {}) {
    this.key = key;
    this.maxEntries = o.maxEntries ?? 200_000;
    this.rememberFile = o.rememberFile;
    if (this.rememberFile) this.loadRemembered(this.rememberFile);
  }

  placeholderFor(label: string, value: string): string {
    const known = this.byValue.get(value);
    if (known) {
      this.touch(known, value);
      // In use: a remembered value must not age out while its context keeps coming back.
      if (CONTEXTUAL_LABELS.has(label) || this.known.has(value)) this.remember(value, this.known.get(value) ?? label);
      if (this.restoredKnown.has(value)) this.markRestored(known, value);
      return known;
    }
    const tag = createHmac('sha256', this.key).update(value).digest('hex').slice(0, 8);
    let ph = `[[REDACTED:${label}:${tag}]]`;
    // Two values with the same 8-hex tag: rare (about 5 pairs among 200,000 values of one label),
    // and kept apart by a suffix. Which one gets it depends on the order they are seen in; a
    // response can only restore placeholders of its own request (see `scope`), which keeps a stale
    // one from restoring the other value.
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
  /**
   * Two memories, both least recently used first: values found by their context, and — kept apart
   * so a flood of the former (a log of 10,000 bearer tokens) cannot push them out — those of them
   * that were *restored* to the client. Only a restored value can come back without its context.
   */
  private readonly known = new Map<string, string>(); // value -> label
  private readonly restoredKnown = new Map<string, string>();
  /** Every value ever added to `known`, in order: a cached result checks only those added after it. */
  private knownLog: string[] = [];
  /** Bumped when the log is compacted: older positions mean nothing any more. */
  private knownEpoch = 0;
  private knownRe: RegExp | undefined;

  private remember(value: string, label: string): void {
    if (value.length < MIN_KNOWN && (value.length < MIN_KNOWN_SHORT || classes(value) < 2 || /\s/.test(value))) return;
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
    this.persist(value, label);
  }

  /** A value restored to the client: remembered where context floods cannot push it out. */
  private markRestored(placeholder: string, value: string): void {
    const label = this.known.get(value) ?? this.restoredKnown.get(value) ?? /^\[\[REDACTED:([a-z0-9_]+):/.exec(placeholder)?.[1];
    if (!label || !CONTEXTUAL_LABELS.has(label)) return;
    if (value.length < MIN_KNOWN && (value.length < MIN_KNOWN_SHORT || classes(value) < 2 || /\s/.test(value))) return;
    const isNew = !this.restoredKnown.has(value) && !this.known.has(value);
    this.restoredKnown.delete(value);
    this.restoredKnown.set(value, label);
    if (this.restoredKnown.size > MAX_KNOWN) this.restoredKnown.delete(this.restoredKnown.keys().next().value as string);
    if (isNew) {
      this.knownLog.push(value);
      this.knownRe = undefined;
      this.persist(value, label);
    }
  }

  private knownValues(): string[] {
    return [...new Set([...this.known.keys(), ...this.restoredKnown.keys()])];
  }

  /**
   * While frozen (one walk over a request body), the known-value pattern stays as it was when the
   * walk began: rebuilding it after every newly learned value made a body with thousands of new
   * values quadratic (2,000 messages: 16 s). Values learned meanwhile are found by the walk that
   * follows (see redactRequest), with one rebuild.
   */
  private frozen: { re: RegExp | undefined } | undefined;
  freeze(): void {
    this.frozen = { re: this.buildKnownPattern() };
  }
  thaw(): void {
    this.frozen = undefined;
  }
  get isFrozen(): boolean {
    return this.frozen !== undefined;
  }

  /** A pattern matching every known value (longest first; short ones only as whole words), or undefined. */
  knownPattern(): RegExp | undefined {
    return this.frozen ? this.frozen.re : this.buildKnownPattern();
  }

  private buildKnownPattern(): RegExp | undefined {
    if (!this.known.size && !this.restoredKnown.size) return undefined;
    this.knownRe ??= new RegExp(
      this.knownValues()
        .sort((a, b) => b.length - a.length)
        .map((v) => (v.length < MIN_KNOWN ? `(?<![A-Za-z0-9])${escapeRe(v)}(?![A-Za-z0-9])` : escapeRe(v)))
        .join('|'),
      'g',
    );
    return this.knownRe;
  }

  // ---- remembered across restarts, as hashes ---------------------------------------------------
  /** Hashes from earlier runs not matched to a value yet: hash -> label. */
  private readonly recallable = new Map<string, string>();
  private persisted = 0;

  private knownHash(value: string): string {
    return createHmac('sha256', this.key).update('known\0').update(value).digest('hex').slice(0, 32);
  }

  private loadRemembered(file: string): void {
    let text = '';
    try {
      text = readFileSync(file, 'utf8');
    } catch {
      return; // first run
    }
    const lines = text.split('\n').filter((l) => /^[0-9a-f]{32}\t[a-z0-9_]{1,40}$/.test(l));
    for (const l of lines.slice(-MAX_KNOWN)) {
      const [h, label] = l.split('\t') as [string, string];
      this.recallable.set(h, label);
    }
    this.persisted = lines.length;
  }

  /** Lines waiting to be appended: one write per request (a microtask after it), not one per value. */
  private pendingLines: string[] = [];

  private persist(value: string, label: string): void {
    if (!this.rememberFile) return;
    const h = this.knownHash(value);
    this.recallable.delete(h);
    if (!this.pendingLines.length) queueMicrotask(() => this.flushRemembered());
    this.pendingLines.push(`${h}\t${label}\n`);
  }

  /** Append what was learned since the last flush (runs by itself right after the request that learned it). */
  flushRemembered(): void {
    if (!this.rememberFile || !this.pendingLines.length) return;
    const lines = this.pendingLines;
    this.pendingLines = [];
    try {
      if (this.persisted === 0 && !existsSync(this.rememberFile)) writePrivate(this.rememberFile, REMEMBERED_HEADER);
      appendFileSync(this.rememberFile, lines.join(''));
      this.persisted += lines.length;
      // Keep the file to about the memory's bound: rewrite it with the newest entries.
      if (this.persisted > 2 * MAX_KNOWN) {
        const keep = [...this.recallable.entries()].slice(-MAX_KNOWN).map(([x, l]) => `${x}\t${l}`);
        for (const [v, l] of [...this.known, ...this.restoredKnown]) keep.push(`${this.knownHash(v)}\t${l}`);
        writePrivate(this.rememberFile, REMEMBERED_HEADER + keep.slice(-MAX_KNOWN).join('\n') + '\n');
        this.persisted = Math.min(keep.length, MAX_KNOWN);
      }
    } catch {
      // Remembering across restarts is a bonus; failing to write must not break redaction.
    }
  }

  /**
   * Values remembered in an earlier run, found again in `text`: each word-like token that could be
   * a secret is hashed and compared. A match becomes a known value again. Returns whether one did.
   * Runs on every text not served from the cache while hashes are waiting to be matched — hashes of
   * conversations that never come back stay waiting for the life of the process (at most 5,000).
   */
  recall(text: string): boolean {
    if (!this.recallable.size) return false;
    let found = false;
    // Split on whitespace and quotes only: a password may well hold `=` or `:`. Then try the token,
    // the token without surrounding brackets and punctuation, and what follows its last = or :
    // (`PGPASSWORD=x`, `--password:x`).
    for (const m of text.matchAll(/[^\s'"`]{4,400}/g)) {
      const token = m[0];
      const trimmed = token.replace(/^[([{<]+/, '').replace(/[)\]}>.,;:!?]+$/, '');
      const after = /[=:]([^=:]{4,})$/.exec(trimmed)?.[1];
      for (const t of new Set([token, trimmed, ...(after ? [after] : [])])) {
        if (t.length < MIN_KNOWN_SHORT || (t.length < 20 && classes(t) < 2)) continue;
        const label = this.recallable.get(this.knownHash(t));
        if (label === undefined) continue;
        this.recallable.delete(this.knownHash(t));
        this.remember(t, label);
        this.placeholderFor(label, t);
        found = true;
      }
    }
    return found;
  }

  /** Hashes from earlier runs still waiting to be matched. */
  get recallPending(): number {
    return this.recallable.size;
  }

  // ---- restoring ---------------------------------------------------------------------------------
  /**
   * A restorer for one response: it restores only `placeholders` (those its own request carried,
   * as produced by this vault), with their values pinned now — so a response cannot restore a value
   * of another conversation, a guessed tag, or a placeholder planted in a file the agent read, and a
   * value evicted from the vault while the response streams is still restored.
   */
  scope(placeholders: Iterable<string>, extra?: Map<string, string>): Restorer & { readonly values: Map<string, string>; readonly missed: number } {
    const values = new Map<string, string>(extra ?? []);
    for (const ph of placeholders) {
      const v = this.byPlaceholder.get(ph);
      if (v !== undefined) values.set(ph, v);
    }
    let missed = 0;
    return {
      values,
      /** Placeholders seen in the response that this scope could not restore (the log reports them). */
      get missed() {
        return missed;
      },
      restore: (text, encode = (v) => v) => {
        if (!text.includes('[[REDACTED:')) return text;
        return text.replace(new RegExp(PLACEHOLDER.source, 'g'), (ph) => {
          const v = values.get(ph);
          if (v === undefined) {
            missed++;
            return ph;
          }
          this.markRestored(ph, v);
          return encode(v);
        });
      },
    };
  }

  /**
   * Whether every known value is made only of characters no encoding changes (letters, digits,
   * `.` `_` `~` `-`): such a value can only appear in a decoded view of a text if it appears in the
   * text itself — so a text without one needs no known-value search in its views.
   */
  get knownPlain(): boolean {
    if (this.knownPlainAt !== this.knownLog.length + this.knownEpoch * 1e9) {
      this.knownPlainAt = this.knownLog.length + this.knownEpoch * 1e9;
      this.knownPlainValue = this.knownValues().every((k) => /^[A-Za-z0-9._~-]+$/.test(k));
    }
    return this.knownPlainValue;
  }
  private knownPlainAt = -1;
  private knownPlainValue = true;

  /** The label a known value was first redacted with. */
  knownLabel(value: string): string | undefined {
    return this.known.get(value) ?? this.restoredKnown.get(value);
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

  /**
   * Replace every placeholder this vault knows in `text`; unknown ones (a model inventing one) stay
   * as they are. The proxy restores through `scope` instead; this is for tools and tests.
   */
  restore(text: string, encode: (value: string) => string = (v) => v): string {
    if (!text.includes('[[REDACTED:')) return text;
    return text.replace(PLACEHOLDER, (ph) => {
      const v = this.byPlaceholder.get(ph);
      if (v === undefined) return ph;
      // Restored values come back in the next request, without their context: remember them.
      this.markRestored(ph, v);
      return encode(v);
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

/** Owner only, replacing whatever ACL `path` had (inherited or explicit). Windows; false if it failed. */
function ownerOnlyAcl(path: string, dir: boolean): boolean {
  const sid = windowsSid();
  if (!sid) return false;
  try {
    // Only ever applied to a fresh file or folder (writePrivate renames a new temporary file over the
    // target), so there are no explicit entries for other accounts to remove — just inherited ones.
    execFileSync('icacls', [path, '/inheritance:r', '/grant:r', `*${sid}:${dir ? '(OI)(CI)F' : 'F'}`], { windowsHide: true, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/** Create the folder for private files, owner only when this creates it. False if that failed. */
function privateDir(dir: string): boolean {
  const created = mkdirSync(dir, { recursive: true });
  if (created === undefined) return true;
  if (process.platform === 'win32') return ownerOnlyAcl(dir, true);
  chmodSync(dir, 0o700);
  return true;
}

/**
 * Write a file only you can read. POSIX: mode 600. Windows ignores modes and a new file inherits its
 * folder's ACL, which can include other accounts (sandbox groups, shared profiles). So the content
 * goes to a temporary file that is owner-only *before* anything is written to it, which then
 * replaces `path` — or, with `exclusive`, is linked into place only if `path` does not exist yet
 * (two processes starting at once must not end up with two keys). Returns whether the owner-only
 * ACL could be set, or 'exists' when `exclusive` lost the race.
 */
export function writePrivate(path: string, content: string, exclusive = false): boolean | 'exists' {
  let ok = privateDir(dirname(path));
  const tmp = `${path}.${randomBytes(6).toString('hex')}.tmp`;
  writeFileSync(tmp, '', { mode: 0o600, flag: 'wx' });
  try {
    if (process.platform === 'win32') ok = ownerOnlyAcl(tmp, false) && ok;
    else chmodSync(tmp, 0o600);
    writeFileSync(tmp, content);
    if (!exclusive) {
      renameSync(tmp, path);
      return ok;
    }
    try {
      linkSync(tmp, path);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') return 'exists';
      // No hard links on this drive (FAT, some network shares): rename, if it is still not there.
      if (existsSync(path)) return 'exists';
      renameSync(tmp, path);
    }
    return ok;
  } finally {
    rmSync(tmp, { force: true });
  }
}

/** How llm-redact reports a privacy problem it can keep working with (stderr by default). */
export type Warn = (message: string) => void;
const toStderr: Warn = (m) => console.error(`llm-redact: warning: ${m}`);

/**
 * The local HMAC key: created once (32 random bytes), readable only by you. Never overwritten: a
 * file that is not a key is an error to look at, not something to replace — every placeholder
 * would change with a new key.
 */
export function loadKey(path = defaultKeyPath(), warn: Warn = toStderr): Buffer {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (existsSync(path)) {
      const hex = readFileSync(path, 'utf8').trim();
      if (/^[0-9a-f]{64}$/i.test(hex)) return Buffer.from(hex, 'hex');
      // Another process may be between creating and filling it: read again before giving up.
      if (attempt < 2 && hex === '') continue;
      throw new Error(`${path} is not an llm-redact key (64 hex characters). Move it away to create a new one; placeholders from before will no longer be restored.`);
    }
    const key = randomBytes(32);
    const r = writePrivate(path, key.toString('hex') + '\n', true);
    if (r === 'exists') continue; // another process created it first: use that one
    if (!r) warn(`could not make ${path} readable by you only (icacls failed); other accounts on this machine may be able to read it`);
    return key;
  }
  throw new Error(`could not read or create ${path}`);
}
