/**
 * Walk API request and response bodies.
 *
 * Requests: every string the model will read is redacted — message text, tool results, earlier
 * tool-call arguments, system prompts — in the Anthropic Messages, OpenAI Chat Completions and
 * OpenAI Responses formats (and anything shaped like them: DeepSeek, OpenRouter, local servers).
 *
 * Left alone, because changing them breaks the request or means nothing:
 * - ids, model names, roles, types, tool names, stop sequences, cache_control
 * - tool *definitions* (schemas the client wrote, not data)
 * - thinking / reasoning blocks and their signatures: Anthropic verifies them byte for byte
 * - base64 images and documents
 *
 * Responses: placeholders the model wrote are restored everywhere except in thinking/reasoning
 * (those are sent back verbatim next turn and must still match their signature).
 */
import { DETECTOR_BY_ID, secretByKey, type Detector } from './detectors.ts';
import { activeDetectors, canonicalDetector, redactText, type Hit, type RedactOptions } from './redact.ts';
import type { Vault } from './vault.ts';

/** Which API a body belongs to — known from the request path, not guessed from the body. */
export type Api = 'anthropic' | 'chat' | 'responses' | 'other';

export function apiFor(path: string): Api {
  const p = path.split('?')[0] as string;
  // Anthropic directly or through Vertex AI (…/models/claude-x:streamRawPredict).
  if (/\/messages\/?$/.test(p) || /:(stream)?rawPredict$/i.test(p)) return 'anthropic';
  if (/\/chat\/completions\/?$/.test(p)) return 'chat';
  if (/\/responses\/?$/.test(p)) return 'responses';
  return 'other';
}

/**
 * Keys whose string values are API structure — but only in the API's own envelope. Inside a tool
 * call's input or arguments everything is user data: `{"user": "li.wei@…"}` there is content.
 */
const STRUCTURAL = new Set(['id', 'model', 'role', 'type', 'name', 'tool_name', 'namespace', 'phase', 'tool_use_id', 'tool_call_id', 'call_id', 'item_id', 'previous_response_id', 'stop_reason', 'finish_reason', 'stop_sequence', 'stop_sequences', 'stop', 'media_type', 'format', 'detail', 'object', 'status', 'signature', 'encrypted_content', 'service_tier', 'reasoning_effort', 'safety_identifier', 'prompt_cache_key', 'file_id', 'container_upload']);
/**
 * Top-level request fields left alone: tool definitions and output schemas (written by the client,
 * like its code), settings, and `mcp_servers` (its `authorization_token` is for the provider, like
 * the API key in the header). Not here: `prediction` (the file being rewritten) and `metadata`
 * (stored by the provider) — those are data.
 */
const OPAQUE_TOP = new Set(['tools', 'tool_choice', 'functions', 'response_format', 'text', 'reasoning', 'thinking', 'container', 'mcp_servers', 'stream_options']);
/** Block types that can be signed: verified byte for byte by the provider, never changed in either direction. */
const SIGNED_TYPES = new Set(['thinking', 'redacted_thinking', 'reasoning']);
/** String fields that hold JSON text (tool-call arguments): restored values need JSON escaping there. */
const JSON_TEXT = new Set(['arguments', 'partial_json']);
/** Fields of a tool call whose (object) value is the model's or the user's own data. */
const FREE = new Set(['input', 'arguments', 'args']);
/** Deeper than this is not an API request: refuse rather than overflow the stack. */
const MAX_DEPTH = 500;
/** Integers this long can be card, phone or ID numbers; shorter ones are counts and sizes. */
const MIN_NUMBER_DIGITS = 7;

/**
 * A signed block: a thinking block with its signature, redacted thinking, encrypted reasoning
 * (OpenAI, OpenRouter's `reasoning.*` details). A block merely *called* thinking is not one.
 */
function isSigned(o: Record<string, unknown>): boolean {
  const t = o.type;
  if (typeof t !== 'string' || !(SIGNED_TYPES.has(t) || t.startsWith('reasoning.'))) return false;
  return typeof o.signature === 'string' || typeof o.encrypted_content === 'string' || typeof o.data === 'string' || (t === 'reasoning' && typeof o.id === 'string');
}

const hasRawJson = typeof (JSON as { rawJSON?: unknown }).rawJSON === 'function';
const isRaw = (v: unknown): v is { rawJSON: string } => hasRawJson && (JSON as unknown as { isRawJSON(x: unknown): boolean }).isRawJSON(v);

/**
 * JSON.parse that keeps numbers exactly as written (`12345678901234567890`, `1.10`), so a body that
 * is re-serialised changes only where something was redacted. Deep nesting is an error, not a crash.
 */
export function parseJson(text: string): unknown {
  try {
    if (!hasRawJson) return JSON.parse(text);
    const raw = (JSON as unknown as { rawJSON(s: string): unknown }).rawJSON;
    return JSON.parse(text, (_k, v: unknown, ctx?: { source?: string }) => (typeof v === 'number' && ctx?.source !== undefined && String(v) !== ctx.source ? raw(ctx.source) : v));
  } catch (err) {
    if (err instanceof RangeError) throw new Error(`request nested deeper than ${MAX_DEPTH} levels`);
    throw err;
  }
}

/** Own property, even for "__proto__" (plain assignment would set the prototype instead). */
function put(o: Record<string, unknown>, k: string, v: unknown): void {
  Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
}

export const NOTE =
  "Note from the user's local privacy proxy: some values in this conversation (keys, tokens, personal data) were replaced by placeholders like [[REDACTED:kind:id]] before being sent to you. Where such a value is needed — in code, commands or files — write the placeholder exactly as it appears; it is turned back into the real value on the user's machine. Do not ask for the real values or try to guess them.";

export interface RedactResult {
  body: unknown;
  hits: Hit[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * A binary payload — the *whole* string is a base64 data: URL, or base64 under a data-ish key. Only
 * that field is skipped; a string that merely starts like one is text.
 */
function isBinary(key: string, s: string): boolean {
  if (s.startsWith('data:')) return /^data:[\w.+/-]{1,100};base64,[A-Za-z0-9+/=\r\n]*$/.test(s);
  return (key === 'data' || key === 'file_data' || key === 'b64_json') && s.length > 256 && /^[A-Za-z0-9+/=\r\n]+$/.test(s);
}

export type Visit = (s: string, key: string, free: boolean) => string;

/** Media types that are text: a file of this type sent as base64 is decoded and redacted like any text. */
const TEXT_MEDIA = /^(?:text\/[\w.+-]+|application\/(?:json|xml|yaml|x-yaml|toml|javascript|x-sh|sql|x-ndjson|[\w.-]+\+(?:json|xml)))$/i;

/** Redact a base64 text file; unchanged (same string) when nothing was found or it is not UTF-8 text. */
function base64Text(b64: string, fn: Visit): string {
  const bytes = Buffer.from(b64, 'base64');
  const text = bytes.toString('utf8');
  // Not UTF-8 after all (a mislabelled binary): leave it — changing it would corrupt it.
  if (!Buffer.from(text, 'utf8').equals(bytes)) return b64;
  const r = fn(text, '', true);
  return r === text ? b64 : Buffer.from(r, 'utf8').toString('base64');
}

/** A text file inside a data: URL (`data:text/plain;base64,…`), redacted; other data: URLs unchanged. */
function dataUrlText(s: string, fn: Visit): string {
  const m = /^data:([\w.+/-]{1,100})(;[^,;]{1,100})*;base64,/.exec(s);
  if (!m || !TEXT_MEDIA.test(m[1] as string)) return s;
  const b64 = s.slice(m[0].length);
  const r = base64Text(b64, fn);
  return r === b64 ? s : m[0] + r;
}

/**
 * How much of the body is data:
 * - `envelope`: a known API's request — structure (ids, roles, types), settings and signed blocks are left alone;
 * - `loose`: an API we do not know — every string and object key is data, but signed blocks and binary stay;
 * - `data`: inside a tool call's input or arguments — everything is data, whatever its name.
 */
type Mode = 'envelope' | 'loose' | 'data';

/** A number long enough to be a card or phone number: its digits as written, else undefined. */
function numberText(v: unknown): string | undefined {
  const s = typeof v === 'number' ? (Number.isInteger(v) ? String(v) : undefined) : isRaw(v) ? v.rawJSON : undefined;
  return s !== undefined && /^-?\d+$/.test(s) && s.replace('-', '').length >= MIN_NUMBER_DIGITS ? s : undefined;
}

/** Fields whose whole value is the user's or the model's data: tool inputs, and what tools returned. */
function isDataField(parent: Record<string, unknown>, k: string, x: unknown): boolean {
  if (FREE.has(k) && isObject(x)) return true;
  return (k === 'content' && parent.type === 'tool_result') || (k === 'output' && typeof parent.type === 'string' && parent.type.endsWith('_call_output'));
}

/** The key a value is judged by. A message's `name` is the participant's name — data, not a tool name. */
function envelopeKey(parent: Record<string, unknown>, k: string): string {
  return k === 'name' && typeof parent.role === 'string' ? '' : k;
}

function walk(v: unknown, fn: Visit, key = '', mode: Mode = 'envelope', depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new Error(`request nested deeper than ${MAX_DEPTH} levels`);
  if (typeof v === 'string') {
    if (isBinary(key, v)) return v.startsWith('data:') ? dataUrlText(v, fn) : v;
    return mode === 'envelope' && STRUCTURAL.has(key) ? v : fn(v, key, mode !== 'envelope');
  }
  const digits = numberText(v);
  if (digits !== undefined) {
    // A card or phone number written as a JSON number: redacted, it becomes a string.
    if (mode === 'envelope' && STRUCTURAL.has(key)) return v;
    const r = fn(digits, key, mode !== 'envelope');
    return r === digits ? v : r;
  }
  if (Array.isArray(v)) return v.map((x) => walk(x, fn, key, mode, depth + 1));
  if (!isObject(v) || isRaw(v)) return v;
  if (mode !== 'data' && isSigned(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) {
    if (mode === 'envelope' && depth === 0 && OPAQUE_TOP.has(k)) {
      put(out, k, x);
      continue;
    }
    // An Anthropic document / file source with a text media type: { type: 'base64', media_type: 'text/plain', data }.
    if (k === 'data' && typeof x === 'string' && v.type === 'base64' && typeof v.media_type === 'string' && TEXT_MEDIA.test(v.media_type)) {
      put(out, k, base64Text(x, fn));
      continue;
    }
    // Outside a known envelope object keys are data too (`{"li.wei@corp-mail.cn": "admin"}`).
    const name = mode === 'envelope' ? k : fn(k, '', true);
    put(out, name, walk(x, fn, envelopeKey(v, k), mode === 'envelope' && isDataField(v, k, x) ? 'data' : mode, depth + 1));
  }
  return out;
}

/** Redact a parsed request body. Adds the placeholder note when the request contains any placeholder. */
export function redactRequest(body: unknown, vault: Vault, api: Api, opts: RedactOptions & { note?: boolean } = {}): RedactResult {
  const hits: Hit[] = [];
  let sawPlaceholder = false;
  const off = new Set(opts.disable ?? []);
  const allow = new Set(opts.allow ?? []);
  const generic = DETECTOR_BY_ID.get('secret_assignment') as Detector;
  const text = (s: string, key = ''): string => {
    // A value under a secret-named key (in tool arguments, config objects): redact it whole — with
    // the label its shape says (an `sk-…` under "password" is still an openai_key).
    if (key && !off.has('secret_assignment') && !off.has('secret') && !allow.has(s) && secretByKey(key, s)) {
      const d = canonicalDetector(s, generic, activeDetectors(opts));
      const placeholder = vault.placeholderFor(d.id, s);
      hits.push({ detector: d.id, kind: d.kind, start: 0, end: s.length, placeholder });
      sawPlaceholder = true;
      return placeholder;
    }
    const r = redactText(s, vault, opts);
    hits.push(...r.hits);
    if (r.text.includes('[[REDACTED:')) sawPlaceholder = true;
    return r.text;
  };
  const visit: Visit = (s, key) => {
    // Tool-call arguments are JSON text: redact the values inside (as a free zone), not their
    // escaped form. Only re-serialise when something changed, so untouched arguments stay
    // byte-identical (prompt cache).
    if (JSON_TEXT.has(key)) {
      let parsed: unknown;
      let isJson = true;
      try {
        parsed = parseJson(s);
      } catch (err) {
        if ((err as Error).message.includes('nested deeper')) throw err;
        isJson = false; // not JSON after all: treat as text
      }
      if (isJson) {
        const before = hits.length;
        const red = walk(parsed, (x, k) => text(x, k), '', 'data');
        // Numbers and formatting kept as written; re-serialised only where something changed.
        return hits.length > before ? JSON.stringify(red) : s;
      }
    }
    return text(s, key);
  };
  const out = walk(body, visit, '', api === 'other' ? 'loose' : 'envelope');
  if (sawPlaceholder && opts.note !== false && isObject(out)) addNote(out, api);
  return { body: out, hits };
}

const isSystem = (m: unknown) => isObject(m) && (m.role === 'system' || m.role === 'developer');

/**
 * Tell the model what the placeholders are — at the *end* of the system prompt, so a cached
 * prefix (tools + system up to the last cache breakpoint) is unchanged. Deterministic: once a
 * conversation contains a placeholder, every later request carries the same note.
 */
function addNote(body: Record<string, unknown>, api: Api): void {
  if (api === 'anthropic') {
    if (typeof body.system === 'string') body.system = body.system ? `${body.system}\n\n${NOTE}` : NOTE;
    else if (Array.isArray(body.system)) body.system = [...body.system, { type: 'text', text: NOTE }];
    else body.system = NOTE;
  } else if (api === 'chat' && Array.isArray(body.messages)) {
    // One more system message, right after the existing ones.
    const msgs = body.messages;
    const firstOther = msgs.findIndex((m) => !isSystem(m));
    const at = firstOther < 0 ? msgs.length : firstOther;
    body.messages = [...msgs.slice(0, at), { role: 'system', content: NOTE }, ...msgs.slice(at)];
  } else if (api === 'responses') {
    body.instructions = typeof body.instructions === 'string' && body.instructions ? `${body.instructions}\n\n${NOTE}` : NOTE;
  }
}

/**
 * An `application/x-www-form-urlencoded` body: each name and value is decoded (`%40` is `@`),
 * redacted, and re-encoded only when something changed — so `li.wei%40corp-mail.cn` is found.
 */
export function redactForm(body: string, vault: Vault, opts: RedactOptions = {}): { text: string; hits: Hit[] } {
  const hits: Hit[] = [];
  const text = body
    .split('&')
    .map((pair) => {
      const eq = pair.indexOf('=');
      const parts = eq < 0 ? [pair] : [pair.slice(0, eq), pair.slice(eq + 1)];
      return parts
        .map((raw) => {
          let plain = raw;
          try {
            plain = decodeURIComponent(raw.replace(/\+/g, ' '));
          } catch {
            // malformed escapes: redact it as it is
          }
          const r = redactText(plain, vault, opts);
          if (!r.hits.length) return raw;
          hits.push(...r.hits);
          return encodeURIComponent(r.text);
        })
        .join('=');
    })
    .join('&');
  return { text, hits };
}

/** JSON-string escaping for a value restored inside JSON text (tool-call arguments). */
export const jsonEncode = (value: string): string => JSON.stringify(value).slice(1, -1);

/** Restore placeholders in a parsed (non-streamed) response body — tool inputs, keys and arguments included. */
export function restoreResponse(body: unknown, vault: Vault): unknown {
  // Everywhere except signed blocks (sent back verbatim next turn: a restored value would go out in clear).
  return walk(body, (s, key) => vault.restore(s, JSON_TEXT.has(key) ? jsonEncode : undefined), '', 'loose');
}
