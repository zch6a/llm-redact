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
import { secretByKey } from './detectors.ts';
import { redactText, type Hit, type RedactOptions } from './redact.ts';
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
 * Top-level request fields left alone: tool definitions (schemas the client wrote), settings, and
 * `mcp_servers` (its `authorization_token` is for the provider, like the API key in the header).
 */
const OPAQUE_TOP = new Set(['tools', 'tool_choice', 'functions', 'response_format', 'text', 'metadata', 'reasoning', 'thinking', 'container', 'mcp_servers', 'stream_options', 'prediction']);
/** Signed blocks: verified byte for byte by the provider, never changed in either direction. */
const SIGNED_TYPES = new Set(['thinking', 'redacted_thinking', 'reasoning']);
/** String fields that hold JSON text (tool-call arguments): restored values need JSON escaping there. */
const JSON_TEXT = new Set(['arguments', 'partial_json']);
/** Fields of a tool call whose value is the model's or the user's own data. */
const FREE = new Set(['input']);
/** Deeper than this is not an API request: refuse rather than overflow the stack. */
const MAX_DEPTH = 500;

export const NOTE =
  "Note from the user's local privacy proxy: some values in this conversation (keys, tokens, personal data) were replaced by placeholders like [[REDACTED:kind:id]] before being sent to you. Where such a value is needed — in code, commands or files — write the placeholder exactly as it appears; it is turned back into the real value on the user's machine. Do not ask for the real values or try to guess them.";

export interface RedactResult {
  body: unknown;
  hits: Hit[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A binary payload: a data: URL, or a long base64 string under a data-ish key. Only that field is skipped. */
function isBinary(key: string, s: string): boolean {
  if (s.startsWith('data:') && /^data:[\w.+/-]{1,100};base64,/.test(s)) return true;
  return (key === 'data' || key === 'file_data' || key === 'b64_json') && s.length > 256 && /^[A-Za-z0-9+/=\r\n]+$/.test(s.slice(0, 4096));
}

export type Visit = (s: string, key: string, free: boolean) => string;

/**
 * Walk a body. `free`: inside a tool call's input / arguments, where every string — and every
 * object key — is data, whatever its name.
 */
function walk(v: unknown, fn: Visit, key = '', free = false, depth = 0): unknown {
  if (depth > MAX_DEPTH) throw new Error(`request nested deeper than ${MAX_DEPTH} levels`);
  if (typeof v === 'string') {
    if (isBinary(key, v)) return v;
    return !free && STRUCTURAL.has(key) ? v : fn(v, key, free);
  }
  if (Array.isArray(v)) return v.map((x) => walk(x, fn, key, free, depth + 1));
  if (!isObject(v)) return v;
  if (!free && typeof v.type === 'string' && SIGNED_TYPES.has(v.type)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) {
    if (!free && depth === 0 && OPAQUE_TOP.has(k)) {
      out[k] = x;
      continue;
    }
    // In free zones object keys are data too (`{"li.wei@corp-mail.cn": "admin"}`).
    const name = free ? fn(k, '', true) : k;
    out[name] = walk(x, fn, k, free || (FREE.has(k) && isObject(x)), depth + 1);
  }
  return out;
}

/** Redact a parsed request body. Adds the placeholder note when the request contains any placeholder. */
export function redactRequest(body: unknown, vault: Vault, api: Api, opts: RedactOptions & { note?: boolean } = {}): RedactResult {
  const hits: Hit[] = [];
  let sawPlaceholder = false;
  const off = new Set(opts.disable ?? []);
  const allow = new Set(opts.allow ?? []);
  const text = (s: string, key = ''): string => {
    // A value under a secret-named key (in tool arguments, config objects): redact it whole.
    if (key && !off.has('secret_assignment') && !off.has('secret') && !allow.has(s) && secretByKey(key, s)) {
      hits.push({ detector: 'secret_assignment', kind: 'secret', start: 0, end: s.length, placeholder: vault.placeholderFor('secret_assignment', s) });
      sawPlaceholder = true;
      return vault.placeholderFor('secret_assignment', s);
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
      try {
        const parsed: unknown = JSON.parse(s);
        const before = hits.length;
        const red = walk(parsed, (x, k) => text(x, k), '', true);
        return hits.length > before ? JSON.stringify(red) : s;
      } catch (err) {
        if ((err as Error).message.includes('nested deeper')) throw err;
        // not JSON after all: treat as text
      }
    }
    return text(s, key);
  };
  const out = walk(body, visit);
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

/** JSON-string escaping for a value restored inside JSON text (tool-call arguments). */
export const jsonEncode = (value: string): string => JSON.stringify(value).slice(1, -1);

/** Restore placeholders in a parsed (non-streamed) response body — tool inputs, keys and arguments included. */
export function restoreResponse(body: unknown, vault: Vault): unknown {
  return walk(body, (s, key) => vault.restore(s, JSON_TEXT.has(key) ? jsonEncode : undefined));
}
