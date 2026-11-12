/**
 * Property test of the response side: random texts — placeholders, near-placeholders, quotes,
 * backslashes, newlines, emoji — split into random deltas, framed with random line endings, cut into
 * random network chunks. Whatever the split, the client must get exactly what a direct connection
 * would give with the placeholders replaced: the same text, valid JSON in tool arguments, nothing
 * held back at the end. Seeded, so a failure names its case and can be replayed.
 */
import './isolate.ts';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { NdjsonRestorer, SseParser, SseRestorer, serialize, type Event } from '../src/sse.ts';
import { Vault } from '../src/vault.ts';

const v = new Vault(Buffer.alloc(32, 21));
const VALUES = ['sk-proj-' + 'B'.repeat(40), 'p"a\\ss\nwé\u2028d\u{1F600}', 'a\tb\u0000c', '[[REDACTED:x:00000000]]-ish'];
const PHS = VALUES.map((x, i) => v.placeholderFor(`lab_${i}`, x));
const PIECES = ['hello ', 'a[i] ', '[[wiki]] ', '[[RED', '[[REDACTED:', '[', '[[', ']]', 'x', 'é', '\u{1F600}', '\n', '"', '\\', '[[REDACTED:lab_0:deadbeef]]', ...PHS, ...PHS];

function rng(seed: number) {
  let s = seed >>> 0 || 1;
  const next = () => ((s = (Math.imul(s, 1103515245) + 12345) >>> 0) / 0x100000000);
  return { int: (n: number) => Math.floor(next() * n), pick: <T>(a: T[]): T => a[Math.floor(next() * a.length)] as T };
}
type Rng = ReturnType<typeof rng>;
const text = (r: Rng) => Array.from({ length: 1 + r.int(12) }, () => r.pick(PIECES)).join('');
/** Split by code points into 1..8-point pieces. */
const split = (r: Rng, s: string) => {
  const cps = [...s];
  const out: string[] = [];
  for (let i = 0; i < cps.length; ) {
    const n = 1 + r.int(8);
    out.push(cps.slice(i, i + n).join(''));
    i += n;
  }
  return out.length ? out : [''];
};
const restored = (s: string) => v.restore(s);
const frame = (r: Rng, evs: [string | null, unknown][]) => {
  const eol = r.pick(['\n', '\r\n', '\r']);
  return evs.map(([name, d]) => (name ? `event: ${name}${eol}` : '') + `data: ${JSON.stringify(d)}${eol}${eol}`).join('');
};
/** Through the parser and restorer, cut into random network chunks. */
function run(r: Rng, api: 'anthropic' | 'chat' | 'responses' | 'other', wire: string): Json[] {
  const parser = new SseParser();
  const restorer = new SseRestorer(v, api);
  const out: Event[] = [];
  for (let i = 0; i < wire.length; ) {
    const n = 1 + r.int(20);
    for (const e of parser.feed(wire.slice(i, i + n))) out.push(...restorer.transform(e));
    i += n;
  }
  const last = parser.end();
  for (const e of last.events) out.push(...restorer.transform(e));
  out.push(...restorer.finish());
  assert.equal(last.rest, '', 'every event complete');
  // Each output event must itself be well-formed SSE that a client can parse back.
  const reparsed = new SseParser().feed(out.map(serialize).join(''));
  assert.equal(reparsed.length, out.length);
  return out.filter((e) => e.data && e.data !== '[DONE]').map((e) => JSON.parse(e.data as string) as Json);
}
type Json = Record<string, any>;

const FORMATS: Record<string, (r: Rng, t: string) => { got: string; want: string }> = {
  anthropicText(r, t) {
    const evs: [string, unknown][] = [['content_block_start', { type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } }], ...split(r, t).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: p } }] as [string, unknown]), ['content_block_stop', { type: 'content_block_stop', index: 0 }]];
    const o = run(r, 'anthropic', frame(r, evs));
    return { got: o.filter((d) => d.delta?.type === 'text_delta').map((d) => d.delta.text).join(''), want: restored(t) };
  },
  anthropicToolJson(r, t) {
    const js = JSON.stringify({ cmd: t });
    const evs: [string, unknown][] = [['content_block_start', { type: 'content_block_start', index: 1, content_block: { type: 'tool_use', id: 't', name: 'Bash', input: {} } }], ...split(r, js).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: p } }] as [string, unknown]), ['content_block_stop', { type: 'content_block_stop', index: 1 }]];
    const o = run(r, 'anthropic', frame(r, evs));
    return { got: JSON.parse(o.filter((d) => d.delta?.type === 'input_json_delta').map((d) => d.delta.partial_json).join('')).cmd, want: restored(t) };
  },
  anthropicCutByError(r, t) {
    // No content_block_stop: the stream fails. Held-back text must still arrive, before the error.
    const evs: [string, unknown][] = [...split(r, t).map((p) => ['content_block_delta', { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: p } }] as [string, unknown]), ['error', { type: 'error', error: { type: 'overloaded_error', message: 'x' } }]];
    const o = run(r, 'anthropic', frame(r, evs));
    assert.equal(o.at(-1)?.type, 'error');
    return { got: o.filter((d) => d.delta?.type === 'text_delta').map((d) => d.delta.text).join(''), want: restored(t) };
  },
  chatText(r, t) {
    const evs: [null, unknown][] = split(r, t).map((p) => [null, { id: 'c', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: p }, finish_reason: null }] }]);
    evs.push([null, { id: 'c', object: 'chat.completion.chunk', choices: [{ index: 0, finish_reason: 'stop' }] }]);
    const o = run(r, 'chat', frame(r, evs) + 'data: [DONE]\n\n');
    return { got: o.flatMap((d) => d.choices).map((c) => c.delta?.content ?? '').join(''), want: restored(t) };
  },
  chatToolArgsTwoChoices(r, t) {
    // n=2, interleaved, each with a tool call: both come out as valid JSON with the values restored.
    const js = JSON.stringify({ cmd: t });
    const a = split(r, js);
    const b = split(r, js);
    const evs: [null, unknown][] = [];
    for (let i = 0; i < Math.max(a.length, b.length); i++)
      for (const [ci, parts] of [[0, a], [1, b]] as const) if (parts[i] !== undefined) evs.push([null, { id: 'c', choices: [{ index: ci, delta: { tool_calls: [{ index: 0, function: { arguments: parts[i] } }] }, finish_reason: null }] }]);
    evs.push([null, { id: 'c', choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }, { index: 1, delta: {}, finish_reason: 'tool_calls' }] }]);
    const o = run(r, 'chat', frame(r, evs) + 'data: [DONE]\n\n');
    const args = (ci: number) => JSON.parse(o.flatMap((d) => d.choices).filter((c) => c.index === ci).flatMap((c) => c.delta?.tool_calls ?? []).map((tc) => tc.function.arguments).join('')).cmd;
    assert.equal(args(1), restored(t));
    return { got: args(0), want: restored(t) };
  },
  legacyCompletions(r, t) {
    const evs: [null, unknown][] = split(r, t).map((p) => [null, { id: 'x', object: 'text_completion', choices: [{ index: 0, text: p, finish_reason: null }] }]);
    const o = run(r, 'other', frame(r, evs) + 'data: [DONE]\n\n');
    return { got: o.flatMap((d) => d.choices).map((c) => c.text ?? '').join(''), want: restored(t) };
  },
  responsesText(r, t) {
    let seq = 0;
    const evs: [string, unknown][] = [...split(r, t).map((p) => ['response.output_text.delta', { type: 'response.output_text.delta', item_id: 'm', output_index: 0, content_index: 0, delta: p, sequence_number: seq++ }] as [string, unknown]), ['response.output_text.done', { type: 'response.output_text.done', item_id: 'm', output_index: 0, content_index: 0, text: t, sequence_number: seq++ }]];
    const o = run(r, 'responses', frame(r, evs));
    // Sequence numbers stay strictly increasing even with an inserted tail event.
    const seqs = o.map((d) => d.sequence_number as number);
    assert.ok(seqs.every((n, i) => i === 0 || n > (seqs[i - 1] as number)), `sequence ${seqs}`);
    assert.equal(o.find((d) => d.type.endsWith('.done'))?.text, restored(t));
    return { got: o.filter((d) => d.type.endsWith('.delta')).map((d) => d.delta).join(''), want: restored(t) };
  },
  responsesArgs(r, t) {
    const js = JSON.stringify({ cmd: t });
    const evs: [string, unknown][] = [...split(r, js).map((p) => ['response.function_call_arguments.delta', { type: 'response.function_call_arguments.delta', item_id: 'f', output_index: 0, delta: p }] as [string, unknown]), ['response.function_call_arguments.done', { type: 'response.function_call_arguments.done', item_id: 'f', output_index: 0, arguments: js }]];
    const o = run(r, 'responses', frame(r, evs));
    assert.equal(JSON.parse(o.find((d) => d.type.endsWith('.done'))?.arguments).cmd, restored(t));
    return { got: JSON.parse(o.filter((d) => d.type.endsWith('.delta')).map((d) => d.delta).join('')).cmd, want: restored(t) };
  },
  gemini(r, t) {
    const parts = split(r, t);
    const evs: [null, unknown][] = parts.map((p, i) => [null, { candidates: [{ index: 0, content: { role: 'model', parts: [{ text: p }] }, ...(i === parts.length - 1 ? { finishReason: 'STOP' } : {}) }] }]);
    const o = run(r, 'other', frame(r, evs));
    return { got: o.flatMap((d) => d.candidates).flatMap((c) => c.content?.parts ?? []).map((p: Json) => p.text ?? '').join(''), want: restored(t) };
  },
  ndjson(r, t) {
    const parts = split(r, t);
    const wire = [...parts.map((p) => JSON.stringify({ message: { role: 'assistant', content: p }, done: false })), JSON.stringify({ message: { role: 'assistant', content: '' }, done: true })].join('\n') + '\n';
    const nd = new NdjsonRestorer(v);
    let out = '';
    for (let i = 0; i < wire.length; ) {
      const n = 1 + r.int(20);
      out += nd.feed(wire.slice(i, i + n));
      i += n;
    }
    out += nd.end();
    return { got: out.split('\n').filter(Boolean).map((l) => (JSON.parse(l) as Json).message.content).join(''), want: restored(t) };
  },
};

describe('response side: random splits, every format', () => {
  const RUNS = 400;
  for (const [name, f] of Object.entries(FORMATS))
    it(`${name} (${RUNS} random cases)`, () => {
      for (let seed = 1; seed <= RUNS; seed++) {
        const r = rng(seed * 7919 + name.length);
        const t = text(r);
        let res: { got: string; want: string };
        try {
          res = f(r, t);
        } catch (err) {
          throw new Error(`${name}, seed ${seed}, text ${JSON.stringify(t)}: ${(err as Error).message}`);
        }
        assert.equal(res.got, res.want, `${name}, seed ${seed}, text ${JSON.stringify(t)}`);
      }
    });
});
