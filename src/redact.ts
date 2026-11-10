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

/** Where every detector matches, overlaps resolved, sorted by position. */
export function findValues(text: string, detectors: Detector[], allow: Set<string> = new Set()): { detector: Detector; start: number; end: number; value: string }[] {
  const taken: { start: number; end: number }[] = [];
  const out: { detector: Detector; start: number; end: number; value: string }[] = [];
  const overlaps = (s: number, e: number) => taken.some((t) => s < t.end && e > t.start);
  for (const d of detectors) {
    d.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = d.re.exec(text)) && guard++ < 10000) {
      if (m[0] === '') {
        d.re.lastIndex++;
        continue;
      }
      const value = d.group ? m[d.group] : m[0];
      if (!value) continue;
      const start = m.index + (d.group ? m[0].indexOf(value) : 0);
      const end = start + value.length;
      if (allow.has(value) || overlaps(m.index, m.index + m[0].length)) continue;
      if (d.validate && !d.validate(value, m)) continue;
      taken.push({ start: m.index, end: m.index + m[0].length });
      out.push({ detector: d, start, end, value });
    }
  }
  return out.sort((a, b) => a.start - b.start);
}

export function redactText(text: string, vault: Vault, opts: RedactOptions = {}): { text: string; hits: Hit[] } {
  if (!text) return { text, hits: [] };
  const found = findValues(text, activeDetectors(opts), new Set(opts.allow ?? []));
  if (!found.length) return { text, hits: [] };
  const hits: Hit[] = [];
  let out = '';
  let pos = 0;
  for (const f of found) {
    const placeholder = vault.placeholderFor(f.detector.id, f.value);
    out += text.slice(pos, f.start) + placeholder;
    pos = f.end;
    hits.push({ detector: f.detector.id, kind: f.detector.kind, start: f.start, end: f.end, placeholder });
  }
  return { text: out + text.slice(pos), hits };
}

/** Counts per detector — what a log or report may show. Never values. */
export function summarize(hits: Hit[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const h of hits) out[h.detector] = (out[h.detector] ?? 0) + 1;
  return out;
}
