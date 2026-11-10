/**
 * Redact and restore text.
 *
 *   redactText("token = ghp_…", vault)  →  "token = [[REDACTED:github_token:3f9a1c2b]]"
 *   vault.restore(…)                     →  the original text
 *
 * Detectors run in order; where matches overlap, the earlier detector wins (a private-key block
 * beats the tokens inside it; a provider token beats the generic NAME=value rule).
 *
 * Text is also searched one or two encoding levels down — JSON escapes (`\"`, `\u0026`), HTML
 * entities (`&quot;`), percent-encoding, CSV-doubled quotes, shell and Python quoting, and base64
 * tokens (replaced whole) — because tool results quote logs, configs and API
 * responses. Every decoded view keeps a map back to the original offsets, so a value found there
 * is replaced exactly where it is, however the serializer happened to spell it.
 */
import { DETECTORS, type Detector, type Kind } from './detectors.ts';
import { PLACEHOLDER, type Vault } from './vault.ts';

export interface RedactOptions {
  /** Detector ids to turn off (`email`), or `secret` / `pii` for a whole kind. */
  disable?: string[];
  /** Optional detectors to turn on (`ipv4`). */
  enable?: string[];
  /** Values never to redact (your own public e-mail in commit messages, a test key). */
  allow?: string[];
  /** Results for long texts seen before (the proxy keeps one per vault; options must not change while it is in use). */
  cache?: RedactCache;
}

export interface Hit {
  detector: string;
  kind: Kind;
  /** Position in the text (-1 when the value was found in an encoded form and replaced by span mapping). */
  start: number;
  end: number;
  placeholder: string;
}

/** A redaction result, with the (label, value) behind each hit, in order. */
interface Cached {
  text: string;
  hits: Hit[];
  values: [string, string][];
  /** Where the vault's known-value log stood when this was computed. */
  mark: { epoch: number; at: number };
  /** Whether the text holds a base64-looking token (worked out once: a later value could hide in one). */
  b64?: boolean;
}

/** More matches in one text than any real request has: refuse it rather than redact part of it. */
export class RedactLimitError extends Error {
  readonly status = 413;
}

/**
 * Agents re-send the whole conversation every turn, so the same long tool results are redacted
 * again and again. This remembers results for long texts, least recently used out first, bounded
 * by size. In memory only — like the vault, it holds real values.
 */
export class RedactCache {
  private readonly map = new Map<string, Cached>();
  private size = 0;
  readonly maxChars: number;
  /** Texts shorter than this are cheaper to redact than to look up. */
  static readonly MIN = 1024;

  constructor(maxChars = 32 * 1024 * 1024) {
    this.maxChars = maxChars;
  }

  get(text: string): Cached | undefined {
    const r = this.map.get(text);
    if (r) {
      this.map.delete(text);
      this.map.set(text, r);
    }
    return r;
  }

  set(text: string, r: Cached): void {
    const cost = text.length + r.text.length;
    if (cost > this.maxChars / 4) return;
    // A newer result replaces an older one (a request's second walk redoes what its first walk
    // did with an older pattern — kept, the stale entry would be redone on every later request).
    const old = this.map.get(text);
    if (old) {
      this.map.delete(text);
      this.size -= text.length + old.text.length;
    }
    this.map.set(text, r);
    this.size += cost;
    for (const [k, v] of this.map) {
      if (this.size <= this.maxChars) break;
      this.map.delete(k);
      this.size -= k.length + v.text.length;
    }
  }

  get entries(): number {
    return this.map.size;
  }
}

export function activeDetectors(opts: RedactOptions = {}): Detector[] {
  const off = new Set(opts.disable ?? []);
  const on = new Set(opts.enable ?? []);
  return DETECTORS.filter((d) => !off.has(d.id) && !off.has(d.kind) && (!d.optional || on.has(d.id)));
}

/** The same pattern with the `d` flag, for exact group positions. */
const WITH_INDICES = new WeakMap<RegExp, RegExp>();
function indexed(re: RegExp): RegExp {
  let r = WITH_INDICES.get(re);
  if (!r) {
    r = new RegExp(re.source, re.flags.includes('d') ? re.flags : re.flags + 'd');
    WITH_INDICES.set(re, r);
  }
  r.lastIndex = 0;
  return r;
}

/** Far more values than any real request holds (64 MB of e-mail addresses is ~3 million). */
const MAX_VALUES = 1_000_000;

interface Span {
  start: number;
  end: number;
}
interface Found extends Span {
  detector: Detector;
  value: string;
}

/** First index in `spans` (sorted, disjoint) whose end is after `pos`. */
function firstEndingAfter(spans: Span[], pos: number): number {
  let lo = 0;
  let hi = spans.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((spans[mid] as Span).end <= pos) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
const overlapsAny = (spans: Span[], s: number, e: number): boolean => {
  const i = firstEndingAfter(spans, s);
  return i < spans.length && (spans[i] as Span).start < e;
};
/** Merge two sorted lists of disjoint spans. */
function mergeSpans(a: Span[], b: Span[]): Span[] {
  const out: Span[] = [];
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) out.push(j >= b.length || (i < a.length && (a[i] as Span).start <= (b[j] as Span).start) ? (a[i++] as Span) : (b[j++] as Span));
  return out;
}

/** Detectors that recognise a value by its own shape (a provider key), not by its surroundings. */
const SHAPE_DETECTORS = new Map<string, RegExp>();
/**
 * The most specific label for a value: an `sk-proj-…` under a JSON key "password" is still an
 * openai_key. Labels should depend on the value, not on where it was found, or the same secret gets a different placeholder
 * after a restart (and the prompt cache misses). (In text this holds by detector order: the shape
 * detectors run before the generic NAME=value rule.)
 */
export function canonicalDetector(value: string, fallback: Detector, detectors: Detector[] = DETECTORS): Detector {
  for (const d of detectors) {
    if (d === fallback || d.group !== undefined || d.kind !== fallback.kind) continue;
    let whole = SHAPE_DETECTORS.get(d.id);
    if (!whole) {
      whole = new RegExp(`^(?:${d.re.source})$`, d.re.flags.replace(/[gy]/g, ''));
      SHAPE_DETECTORS.set(d.id, whole);
    }
    const m = whole.exec(value);
    if (m && (!d.validate || d.validate(value, m))) return d;
  }
  return fallback;
}

/**
 * Where every detector matches, overlaps resolved, sorted by position. Overlap is judged on the
 * *values*, not the whole matches: a URL's host part must not hide an e-mail after it. Placeholders
 * already in the text are never matched again (a request carries back the model's own output).
 */
export function findValues(text: string, detectors: Detector[], allow: Set<string> = new Set()): Found[] {
  let taken: Span[] = [];
  if (text.includes('[[REDACTED:')) {
    const re = new RegExp(PLACEHOLDER.source, 'g');
    for (let m = re.exec(text); m; m = re.exec(text)) taken.push({ start: m.index, end: m.index + m[0].length });
  }
  const out: Found[] = [];
  for (const d of detectors) {
    const re = indexed(d.re);
    const mine: Span[] = [];
    // Each exec moves past its match, so the loop is bounded by the text length.
    for (let m = re.exec(text); m; m = re.exec(text)) {
      if (m[0] === '') {
        re.lastIndex++;
        continue;
      }
      const groups = d.group === undefined ? [0] : Array.isArray(d.group) ? d.group : [d.group];
      const g = groups.find((i) => m![i] !== undefined) ?? 0;
      let value = m[g];
      if (!value) continue;
      // Exact position of the value from the regex engine (never a string search: the value can repeat in the match).
      const start = (m.indices?.[g]?.[0] ?? m.index) as number;
      if (d.trimEnd) value = value.replace(d.trimEnd, '');
      if (!value) continue;
      const end = start + value.length;
      if (allow.has(value) || overlapsAny(taken, start, end)) continue;
      if (d.validate && !d.validate(value, m)) continue;
      mine.push({ start, end });
      out.push({ detector: d, start, end, value });
      if (out.length > MAX_VALUES) throw new RedactLimitError(`more than ${MAX_VALUES} values to redact in one text; refusing it rather than redacting part of it`);
    }
    // A detector's own values come in order and do not overlap each other.
    taken = mergeSpans(taken, mine);
  }
  return out.sort((a, b) => a.start - b.start);
}

// ---- decoded views ------------------------------------------------------------------------------

/** A decoded form of the text, with `map[i]` = offset in the original of view character i (`map[length]` = end). */
interface View {
  text: string;
  map: Int32Array;
}

const JSON_ESCAPE = /\\(["\\/bfnrt]|u[0-9a-fA-F]{4})/g;
const JSON_CHAR: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
const HTML_ENTITY = /&(?:(quot|amp|apos|lt|gt)|#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6}));/g;
const HTML_CHAR: Record<string, string> = { quot: '"', amp: '&', apos: "'", lt: '<', gt: '>' };
const DECODERS: { name: string; test: RegExp; re: RegExp; decode: (m: RegExpExecArray) => string }[] = [
  { name: 'json', test: /\\["\\/bfnrtu]/, re: JSON_ESCAPE, decode: (m) => ((m[1] as string).length === 5 ? String.fromCharCode(parseInt((m[1] as string).slice(1), 16)) : (JSON_CHAR[m[1] as string] ?? (m[1] as string))) },
  {
    name: 'html',
    test: /&(?:quot|amp|apos|lt|gt|#\d|#[xX][0-9a-fA-F]);/,
    re: HTML_ENTITY,
    decode: (m) => {
      if (m[1]) return HTML_CHAR[m[1]] as string;
      const cp = parseInt((m[2] ?? m[3]) as string, m[2] ? 10 : 16);
      return cp > 0x10ffff ? m[0] : String.fromCodePoint(cp);
    },
  },
  // Percent-encoding (form data, URLs quoted in logs): li.wei%40corp-mail.cn.
  { name: 'percent', test: /%[0-9a-fA-F]{2}/, re: /%([0-9a-fA-F]{2})/g, decode: (m) => String.fromCharCode(parseInt(m[1] as string, 16)) },
  // CSV doubles the quotes inside a quoted field, {""api_key"":""xyz""}; an empty JSON string "" is not that.
  { name: 'csv', test: /[^"]""[A-Za-z_]/, re: /""/g, decode: () => '"' },
  // Shell and Python quoting: bash -x prints 'Tr0ub'\''4dor', Python repr 'Tr0ub\'4dor'.
  { name: 'shell', test: /'\\''|\\'/, re: /'\\''|\\'/g, decode: () => "'" },
];

/** Decode one level; undefined when there is nothing to decode. */
function decodeView(v: View, d: (typeof DECODERS)[number]): View | undefined {
  if (!d.test.test(v.text)) return undefined;
  const re = new RegExp(d.re.source, d.re.flags);
  const parts: string[] = [];
  const map = new Int32Array(v.text.length + 1);
  let n = 0;
  let pos = 0;
  for (let m = re.exec(v.text); m; m = re.exec(v.text)) {
    for (let i = pos; i < m.index; i++) map[n++] = v.map[i] as number;
    parts.push(v.text.slice(pos, m.index));
    const ch = d.decode(m);
    // Every unit of the decoded character starts where its escape starts.
    for (let i = 0; i < ch.length; i++) map[n++] = v.map[m.index] as number;
    parts.push(ch);
    pos = m.index + m[0].length;
  }
  for (let i = pos; i < v.text.length; i++) map[n++] = v.map[i] as number;
  parts.push(v.text.slice(pos));
  map[n] = v.map[v.text.length] as number;
  return { text: parts.join(''), map: map.slice(0, n + 1) };
}

/** The decoded views worth searching: JSON one and two levels down, HTML entities (and JSON inside them), percent-encoding, CSV quotes, shell quoting. */
function viewsOf(text: string): View[] {
  if (!DECODERS.some((d) => d.test.test(text))) return [];
  const identity = new Int32Array(text.length + 1);
  for (let i = 0; i <= text.length; i++) identity[i] = i;
  const root: View = { text, map: identity };
  const [json, html, percent, csv, shell] = DECODERS as (typeof DECODERS)[number][] as [(typeof DECODERS)[number], (typeof DECODERS)[number], (typeof DECODERS)[number], (typeof DECODERS)[number], (typeof DECODERS)[number]];
  const out: View[] = [];
  const j1 = decodeView(root, json);
  if (j1) {
    out.push(j1);
    const j2 = decodeView(j1, json);
    if (j2) out.push(j2);
  }
  const h1 = decodeView(root, html);
  if (h1) {
    out.push(h1);
    const hj = decodeView(h1, json);
    if (hj) out.push(hj);
  }
  const p1 = decodeView(root, percent);
  if (p1) out.push(p1);
  const c1 = decodeView(root, csv);
  if (c1) out.push(c1);
  const s1 = decodeView(root, shell);
  if (s1) out.push(s1);
  return out;
}

export function redactText(text: string, vault: Vault, opts: RedactOptions = {}): { text: string; hits: Hit[] } {
  if (!text) return { text, hits: [] };
  const cache = opts.cache && text.length >= RedactCache.MIN ? opts.cache : undefined;
  const cached = cache?.get(text);
  if (cached && cacheValid(cached, text, vault)) return { text: cached.text, hits: cached.hits.map((h) => ({ ...h })) };
  // After a restart: values remembered as hashes, matched in this text, become known again first.
  vault.recall(text);
  let mark = vault.knownMark;
  let r = redactUncached(text, vault, opts);
  // This text taught the vault a value (`DB_PASSWORD=x` … `psql -W x`): once more, so the value is
  // also found where only the known-value pass can see it. (A second round learns nothing new.)
  // (Inside a request walk the pattern is frozen: the walk over the whole body that follows does this.)
  if (!vault.isFrozen && vault.knownSince(mark)?.length !== 0) {
    mark = vault.knownMark;
    r = redactUncached(text, vault, opts);
  }
  cache?.set(text, { text: r.text, hits: r.hits.map((h) => ({ ...h })), values: r.values, mark, b64: hasBase64(text) });
  return { text: r.text, hits: r.hits };
}

/**
 * A cached result is still right when its values get the same placeholders (putting them back into
 * a vault that may have forgotten them) and no value learned since then occurs in the text.
 */
function cacheValid(cached: Cached, text: string, vault: Vault): boolean {
  if (!cached.values.every(([label, value], i) => vault.placeholderFor(label, value) === cached.hits[i]?.placeholder)) return false;
  const learned = vault.knownSince(cached.mark);
  if (!learned || (learned.length && occursIn(text, learned, cached.b64 ?? true))) return false;
  cached.mark = vault.knownMark;
  return true;
}

interface Replacement extends Span {
  detector: Detector;
  value: string;
  direct: boolean;
}

/** Does any of `values` occur in `text` — as it is, or in one of its decoded views? */
function occursIn(text: string, values: string[], b64: boolean): boolean {
  if (values.some((v) => text.includes(v))) return true;
  // Inside a base64 token it could be anywhere: recompute rather than decode every token here.
  if (b64) return true;
  // Values made of encoding-proof characters can be in a decoded view only if they are in the text.
  if (values.every((v) => /^[A-Za-z0-9._~-]+$/.test(v))) return false;
  return viewsOf(text).some((view) => values.some((v) => view.text.includes(v)));
}

/** Base64 tokens: 16+ characters in whole groups of 4, standard or URL-safe, at most 64 KB each. */
const BASE64_TOKEN = /(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/_-]{4}){4,16384}(?:[A-Za-z0-9+/_-]{2}==|[A-Za-z0-9+/_-]{3}=)?(?![A-Za-z0-9+/=_-])/g;
const MAX_BASE64_TOKENS = 5_000;
/** Does 	ext hold a token that looks like base64 (the same test base64Secrets applies)? */
function hasBase64(text: string): boolean {
  if (text.length < 16) return false;
  for (const m of text.matchAll(BASE64_TOKEN)) if (looksBase64(m[0])) return true;
  return false;
}

/** An identifier or a word is not base64: it needs a digit, + / - _ or padding, and both cases. */
const looksBase64 = (token: string) => /[\d+/=_-]/.test(token) && /[A-Z]/.test(token) && /[a-z]/.test(token);

/**
 * Secrets inside base64 tokens: each token that decodes to mostly printable text is searched with
 * every detector (remembered values included); a token that hides one becomes one replacement.
 */
function base64Secrets(text: string, detectors: Detector[], allow: Set<string>, taken: Span[]): Replacement[] {
  if (text.length < 16 || !/[A-Za-z0-9+/_-]{16}/.test(text)) return [];
  const sorted = [...taken].sort((a, b) => a.start - b.start);
  const out: Replacement[] = [];
  let seen = 0;
  for (const m of text.matchAll(BASE64_TOKEN)) {
    const token = m[0];
    if (!looksBase64(token)) continue;
    if (++seen > MAX_BASE64_TOKENS) break;
    const start = m.index;
    const end = start + token.length;
    if (overlapsAny(sorted, start, end)) continue;
    const decoded = Buffer.from(token.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    // Mostly printable text, or it was not base64 of text (an image, a hash, an id).
    const printable = decoded.replace(/[^\x20-\x7e\t\n\r]/g, '').length;
    if (decoded.length < 8 || printable < decoded.length * 0.9) continue;
    const hit = findValues(decoded, detectors, allow)[0];
    if (!hit) continue;
    out.push({ detector: hit.detector, value: token, start, end, direct: true });
  }
  return out;
}

/** Values the vault learned from their context, as a detector that runs first. */
function knownDetector(vault: Vault): Detector | undefined {
  const re = vault.knownPattern();
  return re && { id: KNOWN, kind: 'secret', description: 'A value already redacted by its context, wherever it appears again', re };
}
const KNOWN = 'known_value';

function redactUncached(text: string, vault: Vault, opts: RedactOptions): Omit<Cached, 'mark'> {
  const known = knownDetector(vault);
  const detectors = known ? [known, ...activeDetectors(opts)] : activeDetectors(opts);
  const allow = new Set(opts.allow ?? []);
  const reps: Replacement[] = findValues(text, detectors, allow).map((f) => ({ ...f, direct: true }));
  // Values visible only once the text is decoded: map their spans back to the original.
  if (/[\\&"%']/.test(text)) {
    let accepted: Span[] = reps.slice();
    // Known values made of encoding-proof characters show up in a view only if they show up here.
    const viewDetectors = known && vault.knownPlain && !reps.some((r) => r.detector === known) ? detectors.slice(1) : detectors;
    for (const view of viewsOf(text)) {
      const extra: Replacement[] = [];
      for (const f of findValues(view.text, viewDetectors, allow)) {
        const start = view.map[f.start] as number;
        const end = view.map[f.end] as number;
        if (end <= start || overlapsAny(accepted, start, end)) continue;
        extra.push({ ...f, start, end, direct: false });
      }
      if (!extra.length) continue;
      reps.push(...extra);
      accepted = mergeSpans(accepted, extra);
    }
    reps.sort((a, b) => a.start - b.start);
  }
  // Base64 that hides a secret (`Authorization: Basic …` printed by curl -v, `echo $KEY | base64`):
  // the whole token is replaced — the value cannot be cut out of it.
  const b64 = base64Secrets(text, detectors, allow, reps);
  if (b64.length) {
    reps.push(...b64);
    reps.sort((a, b) => a.start - b.start);
  }
  const hits: Hit[] = [];
  const values: [string, string][] = [];
  const parts: string[] = [];
  let pos = 0;
  for (const f of reps) {
    // A known value keeps the label (and so the placeholder) it was first redacted with.
    const label = f.detector.id === KNOWN ? (vault.knownLabel(f.value) ?? 'secret_assignment') : f.detector.id;
    const placeholder = vault.placeholderFor(label, f.value);
    parts.push(text.slice(pos, f.start), placeholder);
    pos = f.end;
    hits.push({ detector: label, kind: f.detector.id === KNOWN ? 'secret' : f.detector.kind, start: f.direct ? f.start : -1, end: f.direct ? f.end : -1, placeholder });
    values.push([label, f.value]);
  }
  parts.push(text.slice(pos));
  return { text: parts.join(''), hits, values };
}

/** Counts per detector — what a log or report may show. Never values. */
export function summarize(hits: Hit[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const h of hits) out[h.detector] = (out[h.detector] ?? 0) + 1;
  return out;
}
