/**
 * Restore placeholders in server-sent event streams, without breaking the stream.
 *
 * Text and tool-call arguments arrive as many small deltas; a placeholder can be split across any
 * of them. Each text block / tool call gets its own StreamRestorer; what it holds back is emitted
 * when the block, choice or item ends. Thinking and reasoning deltas pass through untouched (they
 * are signed and sent back verbatim next turn).
 */
import { jsonEncode, restoreResponse, type Api } from './body.ts';
import { StreamRestorer } from './stream.ts';
import type { Vault } from './vault.ts';

interface Event {
  /** Lines other than data: (event:, id:, retry:, comments), kept as they were. */
  head: string[];
  data: string | null;
}

/** Split an SSE byte stream into events, whatever the network chunking (LF or CRLF). */
export class SseParser {
  private buf = '';
  feed(chunk: string): Event[] {
    this.buf += chunk;
    const out: Event[] = [];
    for (;;) {
      const m = /\r?\n\r?\n/.exec(this.buf);
      if (!m) break;
      const block = this.buf.slice(0, m.index);
      this.buf = this.buf.slice(m.index + m[0].length);
      out.push(parseBlock(block));
    }
    return out;
  }
  /** Whatever is left at the end (a final event without a blank line after it). */
  end(): Event[] {
    const rest = this.buf;
    this.buf = '';
    return rest.trim() ? [parseBlock(rest)] : [];
  }
}

function parseBlock(block: string): Event {
  const head: string[] = [];
  const data: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith('data:')) data.push(line.slice(line.startsWith('data: ') ? 6 : 5));
    else head.push(line);
  }
  return { head, data: data.length ? data.join('\n') : null };
}

export function serialize(e: Event): string {
  const lines = [...e.head];
  if (e.data !== null) for (const l of e.data.split('\n')) lines.push(`data: ${l}`);
  return lines.join('\n') + '\n\n';
}

type Json = Record<string, unknown>;
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Rewrites events of one response stream. One instance per HTTP response. */
export class SseRestorer {
  private readonly vault: Vault;
  /** From the request path; for an unknown path, settled by the first event that says which format it is. */
  private api: Api;
  private readonly restorers = new Map<string, StreamRestorer>();
  private lastChat: Json | null = null;

  constructor(vault: Vault, api: Api) {
    this.vault = vault;
    this.api = api;
  }

  private restorer(key: string, json: boolean): StreamRestorer {
    let r = this.restorers.get(key);
    if (!r) {
      r = new StreamRestorer(this.vault, json ? jsonEncode : undefined);
      this.restorers.set(key, r);
    }
    return r;
  }

  private take(key: string): string {
    const r = this.restorers.get(key);
    if (!r) return '';
    this.restorers.delete(key);
    return r.flush();
  }

  /** One event in, zero or more events out (a held-back tail can become an extra delta). */
  transform(e: Event): Event[] {
    if (e.data === null) return [e];
    if (e.data.trim() === '[DONE]') return [...this.flushChat(e.head), e];
    let d: unknown;
    try {
      d = JSON.parse(e.data);
    } catch {
      return [e];
    }
    if (!isObj(d)) return [e];
    if (this.api === 'other') this.api = sniff(d);
    const out = this.api === 'anthropic' ? this.anthropic(d, e.head) : this.api === 'chat' ? this.chat(d, e.head) : this.api === 'responses' ? this.responses(d, e.head) : [restoreResponse(d, this.vault) as Json];
    return out.map((x) => ('head' in x && 'data' in x ? (x as unknown as Event) : { head: e.head, data: JSON.stringify(x) }));
  }

  /** End of stream: anything still held back (a stream cut off mid-block). */
  finish(): Event[] {
    return this.api === 'chat' ? this.flushChat([]) : [];
  }

  // ---- Anthropic Messages ------------------------------------------------------------------
  private anthropic(d: Json, head: string[]): (Json | Event)[] {
    const idx = String(d.index ?? '');
    if (d.type === 'content_block_start' && isObj(d.content_block)) {
      const b = d.content_block;
      // Text blocks stream text_delta, tool calls stream partial JSON: remember which, for the tail.
      if (b.type === 'text' || b.type === 'tool_use') {
        this.toolBlocks[b.type === 'tool_use' ? 'add' : 'delete'](idx);
        return [{ ...d, content_block: restoreResponse(b, this.vault) }];
      }
      return [d];
    }
    if (d.type === 'content_block_delta' && isObj(d.delta)) {
      const delta = d.delta;
      if (delta.type === 'text_delta' && typeof delta.text === 'string') return [{ ...d, delta: { ...delta, text: this.restorer(`a${idx}`, false).push(delta.text) } }];
      if (delta.type === 'input_json_delta' && typeof delta.partial_json === 'string') return [{ ...d, delta: { ...delta, partial_json: this.restorer(`a${idx}`, true).push(delta.partial_json) } }];
      return [d];
    }
    if (d.type === 'content_block_stop') {
      const tail = this.take(`a${idx}`);
      if (!tail) return [d];
      const delta = this.toolBlocks.has(idx) ? { type: 'input_json_delta', partial_json: tail } : { type: 'text_delta', text: tail };
      return [{ head: replaceEvent(head, 'content_block_delta'), data: JSON.stringify({ type: 'content_block_delta', index: d.index, delta }) }, d];
    }
    // Everything else (message_start, message_delta, error, …): whole objects, restored as such.
    return [restoreResponse(d, this.vault) as Json];
  }
  /** Anthropic block indexes that are tool calls (their deltas are partial JSON). */
  private readonly toolBlocks = new Set<string>();

  // ---- OpenAI Chat Completions ---------------------------------------------------------------
  private chat(d: Json, _head: string[]): Json[] {
    if (!Array.isArray(d.choices)) return [restoreResponse(d, this.vault) as Json];
    this.lastChat = d;
    const choices = d.choices.map((c) => {
      if (!isObj(c)) return c;
      const ci = String(c.index ?? 0);
      const delta = isObj(c.delta) ? { ...c.delta } : null;
      if (delta) {
        if (typeof delta.content === 'string') delta.content = this.restorer(`c${ci}`, false).push(delta.content);
        // The legacy `function_call` (before tool_calls) streams JSON arguments the same way.
        if (isObj(delta.function_call) && typeof delta.function_call.arguments === 'string') delta.function_call = { ...delta.function_call, arguments: this.restorer(`l${ci}`, true).push(delta.function_call.arguments) };
        if (Array.isArray(delta.tool_calls))
          delta.tool_calls = delta.tool_calls.map((tc) => {
            if (!isObj(tc)) return tc;
            // Custom tools stream free text in `custom.input`; function tools stream JSON in `function.arguments`.
            if (isObj(tc.custom) && typeof tc.custom.input === 'string') return { ...tc, custom: { ...tc.custom, input: this.restorer(`u${ci}.${String(tc.index ?? 0)}`, false).push(tc.custom.input) } };
            if (!isObj(tc.function) || typeof tc.function.arguments !== 'string') return tc;
            return { ...tc, function: { ...tc.function, arguments: this.restorer(`t${ci}.${String(tc.index ?? 0)}`, true).push(tc.function.arguments) } };
          });
      }
      // The choice ends here: whatever is held back goes out in this chunk.
      if (c.finish_reason && delta) this.drainChoice(ci, delta);
      return delta ? { ...c, delta } : c;
    });
    return [{ ...d, choices }];
  }

  private drainChoice(ci: string, delta: Json): void {
    const text = this.take(`c${ci}`);
    if (text) delta.content = (typeof delta.content === 'string' ? delta.content : '') + text;
    const legacy = this.take(`l${ci}`);
    if (legacy) delta.function_call = { ...(isObj(delta.function_call) ? delta.function_call : {}), arguments: (isObj(delta.function_call) && typeof delta.function_call.arguments === 'string' ? delta.function_call.arguments : '') + legacy };
    for (const key of [...this.restorers.keys()].filter((k) => k.startsWith(`t${ci}.`) || k.startsWith(`u${ci}.`))) {
      const tail = this.take(key);
      if (!tail) continue;
      const index = Number(key.slice(key.indexOf('.') + 1));
      const calls = Array.isArray(delta.tool_calls) ? delta.tool_calls : [];
      delta.tool_calls = [...calls, key.startsWith('u') ? { index, custom: { input: tail } } : { index, function: { arguments: tail } }];
    }
  }

  /** Before [DONE] (or at the end): a chunk carrying anything still held back. */
  private flushChat(head: string[]): Event[] {
    if (!this.restorers.size || !this.lastChat) return [];
    const byChoice = new Map<string, Json>();
    for (const key of [...this.restorers.keys()]) {
      const ci = key.startsWith('c') || key.startsWith('l') ? key.slice(1) : key.slice(1, key.indexOf('.'));
      if (!byChoice.has(ci)) byChoice.set(ci, {});
      this.drainChoice(ci, byChoice.get(ci) as Json);
    }
    const choices = [...byChoice.entries()].filter(([, delta]) => Object.keys(delta).length).map(([ci, delta]) => ({ index: Number(ci), delta, finish_reason: null }));
    return choices.length ? [{ head, data: JSON.stringify({ ...this.lastChat, choices }) }] : [];
  }

  // ---- OpenAI Responses ----------------------------------------------------------------------
  private responses(d: Json, head: string[]): (Json | Event)[] {
    const t = String(d.type ?? '');
    const textKey = `r${String(d.item_id ?? '')}:${String(d.content_index ?? 0)}`;
    const argKey = `f${String(d.item_id ?? '')}`;
    if (t === 'response.output_text.delta' && typeof d.delta === 'string') return [{ ...d, delta: this.restorer(textKey, false).push(d.delta) }];
    if (t === 'response.function_call_arguments.delta' && typeof d.delta === 'string') return [{ ...d, delta: this.restorer(argKey, true).push(d.delta) }];
    // Custom (freeform) tools — Codex's apply_patch is one: the input is plain text, not JSON.
    const customKey = `x${String(d.item_id ?? '')}`;
    if (t === 'response.custom_tool_call_input.delta' && typeof d.delta === 'string') return [{ ...d, delta: this.restorer(customKey, false).push(d.delta) }];
    if (t === 'response.custom_tool_call_input.done') {
      const tail = this.take(customKey);
      const done = { ...d, input: typeof d.input === 'string' ? this.vault.restore(d.input) : d.input };
      return tail ? [{ head: replaceEvent(head, 'response.custom_tool_call_input.delta'), data: JSON.stringify({ ...d, type: 'response.custom_tool_call_input.delta', delta: tail, input: undefined }) }, done] : [done];
    }
    if (t === 'response.output_text.done') {
      const tail = this.take(textKey);
      const done = { ...d, text: typeof d.text === 'string' ? this.vault.restore(d.text) : d.text };
      return tail ? [{ head: replaceEvent(head, 'response.output_text.delta'), data: JSON.stringify({ ...d, type: 'response.output_text.delta', delta: tail, text: undefined }) }, done] : [done];
    }
    if (t === 'response.function_call_arguments.done') {
      const tail = this.take(argKey);
      const done = { ...d, arguments: typeof d.arguments === 'string' ? this.vault.restore(d.arguments, jsonEncode) : d.arguments };
      return tail ? [{ head: replaceEvent(head, 'response.function_call_arguments.delta'), data: JSON.stringify({ ...d, type: 'response.function_call_arguments.delta', delta: tail, arguments: undefined }) }, done] : [done];
    }
    // Whole objects (items, parts, the final response): restore everything that is not reasoning.
    if ('item' in d || 'part' in d || 'response' in d) return [restoreResponse(d, this.vault) as Json];
    return [d];
  }

}

const ANTHROPIC_EVENTS = new Set(['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop', 'ping', 'error']);

/** Which wire format an event belongs to (for streams on a path we did not recognise). */
function sniff(d: Json): Api {
  const t = typeof d.type === 'string' ? d.type : '';
  if (ANTHROPIC_EVENTS.has(t)) return 'anthropic';
  if (t.startsWith('response.')) return 'responses';
  if (Array.isArray(d.choices) || d.object === 'chat.completion.chunk') return 'chat';
  return 'other';
}

/** The same head lines with `event:` set to `name` (if the stream uses event: lines at all). */
function replaceEvent(head: string[], name: string): string[] {
  return head.some((l) => l.startsWith('event:')) ? head.map((l) => (l.startsWith('event:') ? `event: ${name}` : l)) : head;
}
