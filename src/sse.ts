/**
 * Restore placeholders in streamed responses, without breaking the stream.
 *
 * Text and tool-call arguments arrive as many small deltas; a placeholder can be split across any
 * of them. Each text block / tool call gets its own StreamRestorer; what it holds back goes out
 * when the block, choice or item ends — or before an error or the end of the stream, so nothing is
 * lost when the usual terminator never comes. Thinking and reasoning (Anthropic thinking, OpenAI
 * and OpenRouter reasoning and their summaries) pass through untouched: signed ones are sent back
 * verbatim next turn. Unsigned reasoning text in Chat streams (DeepSeek `reasoning_content`) is
 * restored like any text.
 *
 * Formats: Anthropic Messages, OpenAI Chat Completions (and legacy completions), OpenAI Responses,
 * Gemini (`streamGenerateContent?alt=sse`), and newline-delimited JSON (Ollama). Anything else is
 * restored event by event.
 */
import { isSigned, jsonEncode, parseJson, restoreResponse, type Api } from './body.ts';
import { StreamRestorer } from './stream.ts';
import type { Restorer } from './vault.ts';

export interface Event {
  /** Lines other than data: (event:, id:, retry:, comments), kept as they were. */
  head: string[];
  data: string | null;
}

/** A blank line: two line ends, each CRLF, LF or a lone CR (all three are valid SSE). */
const EVENT_END = /(?:\r\n|\r(?!\n)|\n)(?:\r\n|\r(?!\n)|\n)/g;

/** Split an SSE byte stream into events, whatever the network chunking and line endings. */
export class SseParser {
  /** An event still arriving, in pieces: joined only once it is complete (a 16 MB event is not re-scanned per chunk). */
  private parts: string[] = [];
  private pending = 0;
  /** The last few characters received: an event end can straddle two chunks. */
  private tail = '';
  /** Largest event accepted: a stream that never ends an event must not fill the memory. */
  readonly maxEvent: number;

  constructor(maxEvent = 64 * 1024 * 1024) {
    this.maxEvent = maxEvent;
  }

  feed(chunk: string): Event[] {
    const window = this.tail + chunk;
    this.tail = window.slice(-3);
    this.parts.push(chunk);
    this.pending += chunk.length;
    if (!new RegExp(EVENT_END.source).test(window) || (window.endsWith('\r') && !hasEndBefore(window, window.length - 1))) {
      if (this.pending > this.maxEvent) throw new Error(`upstream sent an event over ${this.maxEvent} characters`);
      return [];
    }
    const buf = this.parts.join('');
    const out: Event[] = [];
    const re = new RegExp(EVENT_END.source, 'g');
    let start = 0;
    for (let m = re.exec(buf); m; m = re.exec(buf)) {
      // A CR at the very end may be the first half of a CRLF still on its way.
      if (m.index + m[0].length === buf.length && buf.endsWith('\r')) break;
      out.push(parseBlock(buf.slice(start, m.index)));
      start = m.index + m[0].length;
    }
    const rest = buf.slice(start);
    this.parts = rest ? [rest] : [];
    this.pending = rest.length;
    this.tail = rest.slice(-3);
    return out;
  }

  /**
   * The end of the stream: events that turn out complete now (one ending in a CR, which could have
   * been half a CRLF until the stream ended), and the rest — an event without its blank line, which
   * a client discards (SSE spec), so it goes out as the bytes it was, not as a completed event.
   */
  end(): { events: Event[]; rest: string } {
    const buf = this.parts.join('');
    this.parts = [];
    this.pending = 0;
    this.tail = '';
    const events: Event[] = [];
    const re = new RegExp(EVENT_END.source, 'g');
    let start = 0;
    for (let m = re.exec(buf); m; m = re.exec(buf)) {
      events.push(parseBlock(buf.slice(start, m.index)));
      start = m.index + m[0].length;
    }
    return { events, rest: buf.slice(start) };
  }
}

/** Is there a complete event end in `s` ending at or before `limit`? */
function hasEndBefore(s: string, limit: number): boolean {
  const re = new RegExp(EVENT_END.source, 'g');
  for (let m = re.exec(s); m; m = re.exec(s)) if (m.index + m[0].length <= limit) return true;
  return false;
}

function parseBlock(block: string): Event {
  const head: string[] = [];
  const data: string[] = [];
  for (const line of block.split(/\r\n|\r|\n/)) {
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
/** One output event: its object, and the head lines it goes out with. */
interface Out {
  obj: Json;
  head: string[];
  /** Made up by the proxy (a held-back tail): no `id:` of its own, and its own sequence number. */
  synthetic?: boolean;
}

/** The streamed formats, as told by the request path or the first event. */
type Mode = Api | 'gemini';

/**
 * Responses events that stream a field, and the event that closes it. Each pair restores with one
 * StreamRestorer; the closing event carries the whole value, restored too.
 */
const RESPONSES_STREAMS: Record<string, { done: string; field: string; json: boolean }> = {
  'response.output_text.delta': { done: 'response.output_text.done', field: 'text', json: false },
  'response.refusal.delta': { done: 'response.refusal.done', field: 'refusal', json: false },
  'response.function_call_arguments.delta': { done: 'response.function_call_arguments.done', field: 'arguments', json: true },
  'response.custom_tool_call_input.delta': { done: 'response.custom_tool_call_input.done', field: 'input', json: false },
  'response.mcp_call_arguments.delta': { done: 'response.mcp_call_arguments.done', field: 'arguments', json: true },
};
const RESPONSES_DONE = new Map(Object.entries(RESPONSES_STREAMS).map(([delta, s]) => [s.done, delta]));
/** After these, nothing more comes for the response: held-back text must go out first. */
const RESPONSES_END = new Set(['response.completed', 'response.failed', 'response.incomplete', 'error']);

/** Rewrites events of one response stream. One instance per HTTP response. */
export class SseRestorer {
  private readonly vault: Restorer;
  private mode: Mode;
  private readonly restorers = new Map<string, StreamRestorer>();
  /** Anthropic block indexes that are tool calls (their deltas are partial JSON). */
  private readonly toolBlocks = new Set<string>();
  /** Chat: the chunk fields a made-up flush chunk copies (id, model, … — not usage, not choices). */
  private chatTemplate: Json | null = null;
  /** Responses: what a made-up delta for a held-back key needs (its type, item, indexes). */
  private readonly responsesMeta = new Map<string, Json>();
  /** Responses: sequence numbers shift by the events the proxy inserted. */
  private seqShift = 0;
  private lastSeq = -1;

  constructor(vault: Restorer, api: Api) {
    this.vault = vault;
    this.mode = api;
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

  private restore(d: unknown): Json {
    return restoreResponse(d, this.vault, this.mode === 'gemini' ? 'other' : this.mode) as Json;
  }

  /** One event in, zero or more events out (a held-back tail can become an extra delta). */
  transform(e: Event): Event[] {
    if (e.data === null) return [e];
    if (e.data.trim() === '[DONE]') return [...this.emit(this.flushChat(e.head)), e];
    let d: unknown;
    try {
      d = parseJson(e.data); // numbers exactly as the upstream wrote them
    } catch {
      return [e];
    }
    if (!isObj(d)) return [e];
    if (this.mode === 'other') this.mode = sniff(d);
    let out: Out[];
    try {
      out = this.mode === 'anthropic' ? this.anthropic(d, e.head) : this.mode === 'chat' ? this.chat(d, e.head) : this.mode === 'responses' ? this.responses(d, e.head) : this.mode === 'gemini' ? this.gemini(d, e.head) : [{ obj: this.restore(d), head: e.head }];
    } catch {
      // An event the proxy cannot process (nested absurdly deep, …) goes through as it came: the
      // stream must not die over it.
      return [e];
    }
    return this.emit(out);
  }

  /** End of stream: anything still held back (a stream cut off mid-block). */
  finish(): Event[] {
    const out = this.mode === 'chat' ? this.flushChat([]) : this.mode === 'anthropic' ? this.flushAnthropic([]) : this.mode === 'responses' ? this.flushResponses([]) : this.mode === 'gemini' ? this.flushGemini([]) : [];
    return this.emit(out);
  }

  private emit(out: Out[]): Event[] {
    return out.map((o) => {
      if (this.mode === 'responses' && (typeof o.obj.sequence_number === 'number' || o.synthetic)) {
        // Inserted events get the next number; the upstream's later ones move up by as many.
        if (o.synthetic) this.seqShift++;
        const n = o.synthetic ? this.lastSeq + 1 : (o.obj.sequence_number as number) + this.seqShift;
        o.obj = { ...o.obj, sequence_number: n };
        this.lastSeq = n;
      }
      return { head: o.synthetic ? o.head.filter((l) => !l.startsWith('id:')) : o.head, data: JSON.stringify(o.obj) };
    });
  }

  // ---- Anthropic Messages ------------------------------------------------------------------
  private anthropic(d: Json, head: string[]): Out[] {
    const idx = String(d.index ?? '');
    const same = (obj: Json): Out[] => [{ obj, head }];
    if (d.type === 'content_block_start' && isObj(d.content_block)) {
      const b = d.content_block;
      if (b.type === 'thinking' || b.type === 'redacted_thinking') return same(d);
      // Tool calls (client, server and MCP tools) stream partial JSON; the rest streams text.
      this.toolBlocks[typeof b.type === 'string' && b.type.endsWith('tool_use') ? 'add' : 'delete'](idx);
      return same({ ...d, content_block: this.restore(b) });
    }
    if (d.type === 'content_block_delta' && isObj(d.delta)) {
      const delta = d.delta;
      if (delta.type === 'text_delta' && typeof delta.text === 'string') return same({ ...d, delta: { ...delta, text: this.restorer(`a:${idx}`, false).push(delta.text) } });
      if (delta.type === 'input_json_delta' && typeof delta.partial_json === 'string') return same({ ...d, delta: { ...delta, partial_json: this.restorer(`a:${idx}`, true).push(delta.partial_json) } });
      // A citation arrives whole: its cited text is restored as the non-streamed path does.
      if (delta.type === 'citations_delta' && isObj(delta.citation)) return same({ ...d, delta: { ...delta, citation: this.restore(delta.citation) } });
      return same(d); // thinking_delta, signature_delta: untouched
    }
    if (d.type === 'content_block_stop') return [...this.anthropicTail(idx, head), { obj: d, head }];
    // The stream ends (or fails): nothing may stay held back.
    if (d.type === 'message_stop' || d.type === 'error') return [...this.flushAnthropic(head), { obj: this.restore(d), head }];
    return same(this.restore(d));
  }

  private anthropicTail(idx: string, head: string[]): Out[] {
    const tail = this.take(`a:${idx}`);
    if (!tail) return [];
    const delta = this.toolBlocks.has(idx) ? { type: 'input_json_delta', partial_json: tail } : { type: 'text_delta', text: tail };
    return [{ obj: { type: 'content_block_delta', index: Number(idx), delta }, head: replaceEvent(head, 'content_block_delta'), synthetic: true }];
  }

  private flushAnthropic(head: string[]): Out[] {
    return [...this.restorers.keys()].filter((k) => k.startsWith('a:')).flatMap((k) => this.anthropicTail(k.slice(2), head.length ? head : ['event: content_block_delta']));
  }

  // ---- OpenAI Chat Completions (and legacy completions) ------------------------------------
  /** Streamed string fields of a choice's delta: [restorer prefix, field, JSON text?]. */
  private static readonly CHAT_FIELDS: [string, string, boolean][] = [
    ['c', 'content', false],
    ['f', 'refusal', false],
    // Reasoning text that is not signed (DeepSeek `reasoning_content`, OpenRouter / vLLM `reasoning`).
    ['k', 'reasoning_content', false],
    ['g', 'reasoning', false],
  ];

  private chat(d: Json, head: string[]): Out[] {
    if (!Array.isArray(d.choices)) return [{ obj: this.restore(d), head }];
    const { choices: _c, usage: _u, ...meta } = d;
    this.chatTemplate ??= meta;
    // A chunk with no choices (usage at the end): anything still held goes out before it.
    const before = d.choices.length ? [] : this.flushChat(head);
    const choices = d.choices.map((c) => {
      if (!isObj(c)) return c;
      const ci = String(c.index ?? 0);
      const out: Json = { ...c };
      let delta = isObj(c.delta) ? { ...c.delta } : null;
      if (delta) {
        for (const [p, field, json] of SseRestorer.CHAT_FIELDS) if (typeof delta[field] === 'string') delta[field] = this.restorer(`${p}:${ci}`, json).push(delta[field] as string);
        // The legacy `function_call` (before tool_calls) streams JSON arguments the same way.
        if (isObj(delta.function_call) && typeof delta.function_call.arguments === 'string') delta.function_call = { ...delta.function_call, arguments: this.restorer(`l:${ci}`, true).push(delta.function_call.arguments) };
        if (Array.isArray(delta.tool_calls))
          delta.tool_calls = delta.tool_calls.map((tc) => {
            if (!isObj(tc)) return tc;
            // Custom tools stream free text in `custom.input`; function tools stream JSON in `function.arguments`.
            if (isObj(tc.custom) && typeof tc.custom.input === 'string') return { ...tc, custom: { ...tc.custom, input: this.restorer(`u:${ci}:${String(tc.index ?? 0)}`, false).push(tc.custom.input) } };
            if (!isObj(tc.function) || typeof tc.function.arguments !== 'string') return tc;
            return { ...tc, function: { ...tc.function, arguments: this.restorer(`t:${ci}:${String(tc.index ?? 0)}`, true).push(tc.function.arguments) } };
          });
      }
      // Legacy completions (and FIM endpoints): the text is the choice's own `text`.
      if (typeof c.text === 'string') out.text = this.restorer(`x:${ci}`, false).push(c.text);
      // The choice ends here: whatever is held back goes out in this chunk (with a delta if it had none).
      if (c.finish_reason && this.pendingFor(ci)) {
        delta ??= 'text' in c ? null : {}; // legacy completions have no delta
        this.drainChoice(ci, delta, out);
      }
      if (delta) out.delta = delta;
      return out;
    });
    return [...before, { obj: { ...d, choices }, head }];
  }

  private pendingFor(ci: string): boolean {
    return [...this.restorers.keys()].some((k) => k.split(':')[1] === ci);
  }

  /** Put what is held back for choice `ci` into `delta` (chat) or `choice.text` (completions). */
  private drainChoice(ci: string, delta: Json | null, choice: Json): void {
    const text = this.take(`x:${ci}`);
    if (text) choice.text = (typeof choice.text === 'string' ? choice.text : '') + text;
    if (!delta) return;
    for (const [p, field] of SseRestorer.CHAT_FIELDS) {
      const tail = this.take(`${p}:${ci}`);
      if (tail) delta[field] = (typeof delta[field] === 'string' ? delta[field] : '') + tail;
    }
    const legacy = this.take(`l:${ci}`);
    if (legacy) delta.function_call = { ...(isObj(delta.function_call) ? delta.function_call : {}), arguments: (isObj(delta.function_call) && typeof delta.function_call.arguments === 'string' ? delta.function_call.arguments : '') + legacy };
    for (const key of [...this.restorers.keys()].filter((k) => (k.startsWith('t:') || k.startsWith('u:')) && k.split(':')[1] === ci)) {
      const tail = this.take(key);
      if (!tail) continue;
      const index = Number(key.split(':')[2]);
      const calls = Array.isArray(delta.tool_calls) ? delta.tool_calls : [];
      delta.tool_calls = [...calls, key.startsWith('u:') ? { index, custom: { input: tail } } : { index, function: { arguments: tail } }];
    }
  }

  /** Before [DONE], a usage chunk, or the end: a chunk carrying anything still held back. */
  private flushChat(head: string[]): Out[] {
    if (!this.restorers.size || !this.chatTemplate) return [];
    const byChoice = new Map<string, Json>();
    for (const key of [...this.restorers.keys()]) {
      const ci = key.split(':')[1] as string;
      if (byChoice.has(ci)) continue;
      const choice: Json = { index: Number(ci) };
      const completions = key.startsWith('x:');
      const delta: Json | null = completions ? null : {};
      this.drainChoice(ci, delta, choice);
      if (delta && Object.keys(delta).length) choice.delta = delta;
      choice.finish_reason = null;
      byChoice.set(ci, choice);
    }
    const choices = [...byChoice.values()].filter((c) => 'delta' in c || 'text' in c);
    return choices.length ? [{ obj: { ...this.chatTemplate, choices }, head, synthetic: true }] : [];
  }

  // ---- OpenAI Responses ----------------------------------------------------------------------
  /** The Responses API's id for this response, once an event has said it (for `previous_response_id`). */
  responseId: string | undefined;

  private responses(d: Json, head: string[]): Out[] {
    const t = String(d.type ?? '');
    if (isObj(d.response) && typeof d.response.id === 'string') this.responseId ??= d.response.id;
    const same = (obj: Json): Out[] => [{ obj, head }];
    const key = (deltaType: string) => `${deltaType}|${String(d.item_id ?? '')}|${String(d.output_index ?? '')}|${String(d.content_index ?? '')}`;
    const stream = RESPONSES_STREAMS[t];
    if (stream && typeof d.delta === 'string') {
      const k = key(t);
      if (!this.responsesMeta.has(k)) this.responsesMeta.set(k, { type: t, ...pick(d, ['item_id', 'output_index', 'content_index']) });
      return same({ ...d, delta: this.restorer(k, stream.json).push(d.delta) });
    }
    const deltaType = RESPONSES_DONE.get(t);
    if (deltaType) {
      const s = RESPONSES_STREAMS[deltaType] as (typeof RESPONSES_STREAMS)[string];
      const tail = this.responsesTail(key(deltaType), head);
      const value = d[s.field];
      return [...tail, { obj: { ...d, [s.field]: typeof value === 'string' ? this.vault.restore(value, s.json ? jsonEncode : undefined) : value }, head }];
    }
    // Reasoning (summaries and reasoning text included) is sent back verbatim with its encrypted
    // content next turn, and request-side reasoning items are left alone: never restored.
    if (t.startsWith('response.reasoning')) return same(d);
    if (isObj(d.part) && typeof d.part.type === 'string' && d.part.type.startsWith('reasoning')) return same(d);
    if (RESPONSES_END.has(t)) return [...this.flushResponses(head), { obj: this.restore(d), head }];
    // Whole objects (items, parts, annotations, the response, errors): restored except reasoning.
    return same(this.restore(d));
  }

  private responsesTail(k: string, head: string[]): Out[] {
    const meta = this.responsesMeta.get(k);
    this.responsesMeta.delete(k);
    const tail = this.take(k);
    if (!tail || !meta) return [];
    return [{ obj: { ...meta, delta: tail }, head: head.length ? replaceEvent(head, String(meta.type)) : [`event: ${String(meta.type)}`], synthetic: true }];
  }

  private flushResponses(head: string[]): Out[] {
    return [...this.responsesMeta.keys()].flatMap((k) => this.responsesTail(k, head));
  }

  // ---- Gemini (streamGenerateContent?alt=sse) ------------------------------------------------
  private gemini(d: Json, head: string[]): Out[] {
    if (!Array.isArray(d.candidates)) return [{ obj: this.restore(d), head }];
    const candidates = d.candidates.map((c) => {
      if (!isObj(c)) return c;
      const ci = String(c.index ?? 0);
      const content = isObj(c.content) ? { ...c.content } : null;
      if (content && Array.isArray(content.parts)) {
        content.parts = content.parts.map((part, pi) => {
          if (!isObj(part)) return part;
          // A part with a thought signature goes back as it came; unsigned thought text is restored
          // like any text (as it is when not streamed).
          if (typeof part.thoughtSignature === 'string') return part;
          if (typeof part.text === 'string') return { ...part, text: this.restorer(`m:${ci}:${pi}`, false).push(part.text) };
          return this.restore(part); // function calls and the like come whole
        });
      }
      const out: Json = content ? { ...c, content } : { ...c };
      if (c.finishReason) {
        const tails = [...this.restorers.keys()].filter((k) => k.startsWith(`m:${ci}:`)).map((k) => this.take(k)).join('');
        if (tails) {
          const parts = Array.isArray(content?.parts) ? [...(content.parts as unknown[])] : [];
          const last = parts.length - 1;
          if (last >= 0 && isObj(parts[last]) && typeof (parts[last] as Json).text === 'string') parts[last] = { ...(parts[last] as Json), text: (parts[last] as Json).text + tails };
          else parts.push({ text: tails });
          out.content = { ...(content ?? { role: 'model' }), parts };
        }
      }
      return out;
    });
    const { candidates: _c, ...rest } = d;
    return [{ obj: { ...this.restore(rest), candidates }, head }];
  }

  private flushGemini(head: string[]): Out[] {
    const byCandidate = new Map<string, string>();
    for (const k of [...this.restorers.keys()].filter((x) => x.startsWith('m:'))) {
      const ci = k.split(':')[1] as string;
      byCandidate.set(ci, (byCandidate.get(ci) ?? '') + this.take(k));
    }
    const candidates = [...byCandidate.entries()].filter(([, t]) => t).map(([ci, text]) => ({ index: Number(ci), content: { role: 'model', parts: [{ text }] } }));
    return candidates.length ? [{ obj: { candidates }, head, synthetic: true }] : [];
  }
}

function pick(o: Json, keys: string[]): Json {
  const out: Json = {};
  for (const k of keys) if (k in o) out[k] = o[k];
  return out;
}

/**
 * Newline-delimited JSON streams (Ollama's `/api/chat` and `/api/generate`): one object per line.
 * The streamed text fields keep a restorer across lines (a placeholder can be split between
 * them); the rest of each object is restored whole; the line that says `done` gets the held tail.
 */
export class NdjsonRestorer {
  private readonly vault: Restorer;
  /** The line still arriving, in pieces (joined once, when its newline comes: no rescanning). */
  private parts: string[] = [];
  private pending = 0;
  private readonly restorers = new Map<string, StreamRestorer>();
  readonly maxLine: number;
  /** Streamed text fields: [object path, restorer key]. */
  private static readonly FIELDS: [string[], string][] = [
    [['message', 'content'], 'mc'],
    [['message', 'thinking'], 'mt'],
    [['response'], 'r'],
    [['thinking'], 't'],
  ];

  constructor(vault: Restorer, maxLine = 64 * 1024 * 1024) {
    this.vault = vault;
    this.maxLine = maxLine;
  }

  /** Complete lines out, as text. */
  feed(chunk: string): string {
    const nl = chunk.lastIndexOf('\n');
    if (nl < 0) {
      this.parts.push(chunk);
      this.pending += chunk.length;
      if (this.pending > this.maxLine) throw new Error(`upstream sent a line over ${this.maxLine} characters`);
      return '';
    }
    const lines = this.parts.join('') + chunk.slice(0, nl + 1);
    const rest = chunk.slice(nl + 1);
    this.parts = rest ? [rest] : [];
    this.pending = rest.length;
    return lines.replace(/[^\n]+/g, (l) => this.line(l));
  }

  end(): string {
    const rest = this.parts.join('');
    this.parts = [];
    this.pending = 0;
    return rest ? this.line(rest, true) : '';
  }

  private line(l: string, last = false): string {
    let d: unknown;
    try {
      d = parseJson(l); // numbers exactly as written
    } catch {
      return l; // not JSON after all: as it came (a restored value could make it invalid)
    }
    if (!isObj(d) || isSigned(d)) return l;
    const done = d.done === true || last;
    for (const [path, key] of NdjsonRestorer.FIELDS) {
      let parent = path.length === 1 ? d : isObj(d[path[0] as string]) ? (d[path[0] as string] as Json) : undefined;
      const field = path[path.length - 1] as string;
      let r = this.restorers.get(key);
      if (!parent || typeof parent[field] !== 'string') {
        // The last line has no such field: the held tail still has to go out.
        const tail = done && r ? r.flush() : '';
        if (tail) {
          if (!parent) d[path[0] as string] = parent = {};
          parent[field] = tail;
        }
        continue;
      }
      if (!r) {
        r = new StreamRestorer(this.vault);
        this.restorers.set(key, r);
      }
      parent[field] = r.push(parent[field] as string) + (done ? r.flush() : '');
    }
    if (done) this.restorers.clear();
    try {
      return JSON.stringify(restoreResponse(d, this.vault));
    } catch {
      return l;
    }
  }
}

const ANTHROPIC_EVENTS = new Set(['message_start', 'content_block_start', 'content_block_delta', 'content_block_stop', 'message_delta', 'message_stop', 'ping', 'error']);

/** Which wire format an event belongs to (for streams on a path we did not recognise). */
function sniff(d: Json): Mode {
  const t = typeof d.type === 'string' ? d.type : '';
  if (ANTHROPIC_EVENTS.has(t)) return 'anthropic';
  if (t.startsWith('response.')) return 'responses';
  if (Array.isArray(d.choices) || d.object === 'chat.completion.chunk' || d.object === 'text_completion') return 'chat';
  if (Array.isArray(d.candidates)) return 'gemini';
  return 'other';
}

/** The same head lines with `event:` set to `name` (if the stream uses event: lines at all). */
function replaceEvent(head: string[], name: string): string[] {
  return head.some((l) => l.startsWith('event:')) ? head.map((l) => (l.startsWith('event:') ? `event: ${name}` : l)) : head;
}
