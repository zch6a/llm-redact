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
  if (/\/messages(\?|$)/.test(path)) return 'anthropic';
  if (/\/chat\/completions(\?|$)/.test(path)) return 'chat';
  if (/\/responses(\?|$)/.test(path)) return 'responses';
  return 'other';
}

/** Keys whose string values are structure, not content. */
const STRUCTURAL = new Set(['id', 'model', 'role', 'type', 'name', 'tool_name', 'namespace', 'phase', 'tool_use_id', 'tool_call_id', 'call_id', 'item_id', 'previous_response_id', 'stop_reason', 'finish_reason', 'stop_sequence', 'stop_sequences', 'stop', 'media_type', 'format', 'detail', 'object', 'status', 'signature', 'encrypted_content', 'cache_control', 'service_tier', 'reasoning_effort', 'user', 'safety_identifier', 'prompt_cache_key']);
/** Keys whose whole subtree is left alone. */
const OPAQUE = new Set(['tools', 'tool_choice', 'functions', 'function_call', 'response_format', 'text_format', 'metadata', 'cache_control', 'reasoning', 'thinking', 'container']);
/** Block / item types that are signed or binary. */
const OPAQUE_TYPES = new Set(['thinking', 'redacted_thinking', 'reasoning', 'image', 'input_image', 'input_audio', 'audio', 'image_url', 'file', 'input_file']);
/** String fields that hold JSON text (tool-call arguments): restored values need JSON escaping there. */
const JSON_TEXT = new Set(['arguments', 'partial_json']);

export const NOTE =
  "Note from the user's local privacy proxy: some values in this conversation (keys, tokens, personal data) were replaced by placeholders like [[REDACTED:kind:id]] before being sent to you. Where such a value is needed — in code, commands or files — write the placeholder exactly as it appears; it is turned back into the real value on the user's machine. Do not ask for the real values or try to guess them.";

export interface RedactResult {
  body: unknown;
  hits: Hit[];
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** A source / image_url that carries base64 or a data: URL. */
function binary(o: Record<string, unknown>): boolean {
  return o.type === 'base64' || (typeof o.url === 'string' && o.url.startsWith('data:'));
}

function walk(v: unknown, fn: (s: string, key: string) => string, key = ''): unknown {
  if (typeof v === 'string') return STRUCTURAL.has(key) ? v : fn(v, key);
  if (Array.isArray(v)) return v.map((x) => walk(x, fn, key));
  if (!isObject(v)) return v;
  if ((typeof v.type === 'string' && OPAQUE_TYPES.has(v.type)) || binary(v)) return v;
  const out: Record<string, unknown> = {};
  for (const [k, x] of Object.entries(v)) out[k] = OPAQUE.has(k) ? x : walk(x, fn, k);
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
  const out = walk(body, (s, key) => {
    // Tool-call arguments are JSON text: redact the values inside, not their escaped form. Only
    // re-serialise when something changed, so untouched arguments stay byte-identical (cache).
    if (JSON_TEXT.has(key)) {
      try {
        const parsed: unknown = JSON.parse(s);
        const before = hits.length;
        const red = walk(parsed, text);
        return hits.length > before ? JSON.stringify(red) : s;
      } catch {
        // not JSON after all: treat as text
      }
    }
    return text(s, key);
  });
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

/** Restore placeholders in a parsed (non-streamed) response body. */
export function restoreResponse(body: unknown, vault: Vault): unknown {
  return walk(body, (s, key) => vault.restore(s, JSON_TEXT.has(key) ? jsonEncode : undefined));
}
