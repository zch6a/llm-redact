/**
 * Redact and restore text.
 *
 *   redactText("token = ghp_…", vault)  →  "token = [[REDACTED:github_token:3f9a1c2b]]"
 *   vault.restore(…)                     →  the original text
 *
 * Detectors run in order; where matches overlap, the earlier detector wins (a private-key block
 * beats the tokens inside it; a provider token beats the generic NAME=value rule).
 */
import { DETECTORS, type Detector, type Kind } from './detectors.ts';
import type { Vault } from './vault.ts';

export interface RedactOptions {
  /** Detector ids to turn off (`email`), or `secret` / `pii` for a whole kind. */
  disable?: string[];
  /** Optional detectors to turn on (`ipv4`). */
  enable?: string[];
  /** Values never to redact (your own public e-mail in commit messages, a test key). */
  allow?: string[];
}

export interface Hit {
  detector: string;
  kind: Kind;
  start: number;
  end: number;
  placeholder: string;
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

/** Bounds the work per detector and text: generous, and counted on accepted values, not attempts. */
const MAX_VALUES = 100_000;
const MAX_ATTEMPTS = 2_000_000;

/**
 * Where every detector matches, overlaps resolved, sorted by position. Overlap is judged on the
 * *values*, not the whole matches: a URL's host part must not hide an e-mail after it.
 */
export function findValues(text: string, detectors: Detector[], allow: Set<string> = new Set()): { detector: Detector; start: number; end: number; value: string }[] {
  const taken: { start: number; end: number }[] = [];
  const out: { detector: Detector; start: number; end: number; value: string }[] = [];
  const overlaps = (s: number, e: number) => taken.some((t) => s < t.end && e > t.start);
  for (const d of detectors) {
    const re = indexed(d.re);
    let m: RegExpExecArray | null;
    let attempts = 0;
    let accepted = 0;
    while ((m = re.exec(text)) && attempts++ < MAX_ATTEMPTS && accepted < MAX_VALUES) {
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
      if (allow.has(value) || overlaps(start, end)) continue;
      if (d.validate && !d.validate(value, m)) continue;
      taken.push({ start, end });
      out.push({ detector: d, start, end, value });
      accepted++;
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

/** JSON-style unescaping (`\"`, `\\`, `\/`, `\n`, `\uXXXX`): how text looks one encoding level down. */
export function unescapeJsonish(s: string): string {
  return s.replace(/\\(["\\/bfnrt]|u[0-9a-fA-F]{4})/g, (_, c: string) => (c.length === 5 ? String.fromCharCode(parseInt(c.slice(1), 16)) : ({ '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' } as Record<string, string>)[c] ?? c));
}

/** How `value` appears when its text was JSON-encoded once (two spellings of `/`). */
function encodedForms(value: string): string[] {
  const once = JSON.stringify(value).slice(1, -1);
  return [...new Set([once, once.replace(/\//g, '\\/')])];
}

export function redactText(text: string, vault: Vault, opts: RedactOptions = {}): { text: string; hits: Hit[] } {
  if (!text) return { text, hits: [] };
  const detectors = activeDetectors(opts);
  const allow = new Set(opts.allow ?? []);
  const found = findValues(text, detectors, allow);
  const hits: Hit[] = [];
  let out = '';
  let pos = 0;
  for (const f of found) {
    const placeholder = vault.placeholderFor(f.detector.id, f.value);
    out += text.slice(pos, f.start) + placeholder;
    pos = f.end;
    hits.push({ detector: f.detector.id, kind: f.detector.kind, start: f.start, end: f.end, placeholder });
  }
  out += text.slice(pos);
  // Text that is itself JSON-encoded (a log line inside a string, a tool result quoting a config
  // file): look one and two levels down, and replace what is found there in its encoded spelling.
  if (/\\["\\/nrtu]/.test(out)) {
    let view = text;
    for (let level = 0; level < 2 && /\\["\\/nrtu]/.test(view); level++) {
      view = unescapeJsonish(view);
      for (const f of findValues(view, detectors, allow)) {
        const placeholder = vault.placeholderFor(f.detector.id, f.value);
        const forms = level === 0 ? encodedForms(f.value) : encodedForms(f.value).flatMap(encodedForms);
        for (const form of forms) {
          if (!form || !out.includes(form)) continue;
          out = out.split(form).join(placeholder);
          hits.push({ detector: f.detector.id, kind: f.detector.kind, start: -1, end: -1, placeholder });
        }
      }
    }
  }
  return { text: out, hits };
}

/** Counts per detector — what a log or report may show. Never values. */
export function summarize(hits: Hit[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const h of hits) out[h.detector] = (out[h.detector] ?? 0) + 1;
  return out;
}
