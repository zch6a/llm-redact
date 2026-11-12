/**
 * The proxy: http://127.0.0.1:<port>/<upstream>/<path> → <upstream URL>/<path>.
 *
 *   ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic   → https://api.anthropic.com
 *   OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1      → https://api.openai.com/v1
 *   http://127.0.0.1:8787/deepseek/...                   → https://api.deepseek.com/...
 *
 * Requests are redacted before they leave; responses (JSON or SSE) are restored before the client
 * sees them. Headers — including the API key — pass through untouched: the provider needs them.
 *
 * Security: listens on loopback only, refuses requests whose Host is not loopback (DNS
 * rebinding), sends no CORS headers (a web page cannot read responses), and logs counts, never
 * bodies or values.
 */
import { timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { brotliDecompressSync, gunzipSync, inflateSync, zstdDecompressSync } from 'node:zlib';
import { apiFor, parseJson, redactForm, redactRequest, restoreResponse } from './body.ts';
import { RedactCache, redactText, summarize, type RedactOptions } from './redact.ts';
import { NdjsonRestorer, SseParser, SseRestorer, serialize } from './sse.ts';
import type { Vault } from './vault.ts';
import { VERSION } from './version.ts';

export const DEFAULT_UPSTREAMS: Record<string, string> = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  deepseek: 'https://api.deepseek.com',
};

export interface ProxyOptions {
  vault: Vault;
  upstreams: Record<string, string>;
  redact: RedactOptions & { note?: boolean };
  /** One line per request (counts only). */
  log?: (line: string) => void;
  /** Things that weaken protection (a body forwarded unredacted): always reported, even without a log. */
  warn?: (line: string) => void;
  /** Largest request body accepted (bytes) — also the limit for what a compressed body may inflate to. */
  maxBody?: number;
  /** Forward bodies that cannot be redacted (multipart uploads, binary) instead of refusing them. */
  allowUnredacted?: boolean;
  /**
   * Require this secret as the first path segment (`/<token>/anthropic/…`), so that other programs on
   * a shared machine cannot use the proxy at all. (They could not get your values restored anyway: a
   * response restores only its own request's placeholders.)
   */
  token?: string;
}

export interface ProxyStats {
  requests: number;
  redacted: Record<string, number>;
}

// (Proxy-Authorization is for the hop it is sent to, this proxy: never forwarded to the provider.)
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host', 'content-length', 'content-encoding', 'accept-encoding', 'expect']);
/** Response headers never passed back: requests from other origins are refused here, so the provider's CORS answer means nothing. */
const RESPONSE_DROP = /^access-control-/i;
const LOOPBACK_ORIGIN = /^https?:\/\/(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$/i;
const LOOPBACK_HOST = /^(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$/i;

/**
 * An error the way both SDKs read one: Anthropic's `{ type: "error", error: { type, message } }`,
 * which OpenAI clients read as `error.message` too. (Part of the 1.0 surface: see COMPATIBILITY.md.)
 */
function fail(res: ServerResponse, status: number, message: string, extra: Record<string, unknown> = {}): void {
  const type = status === 413 ? 'request_too_large' : status === 403 ? 'permission_error' : status === 404 ? 'not_found_error' : status >= 500 ? 'api_error' : 'invalid_request_error';
  send(res, status, { type: 'error', error: { type, message: message.startsWith('llm-redact') ? message : `llm-redact: ${message}` }, ...extra });
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

async function readBody(req: IncomingMessage, max: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > max) throw Object.assign(new Error(`request body over ${max} bytes`), { status: 413 });
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

/** A response body, up to `max` bytes (an upstream that never stops must not fill the memory). */
async function readLimited(body: ReadableStream<Uint8Array>, max: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const c of body) {
    size += c.length;
    if (size > max) throw new Error(`upstream response over ${max} bytes`);
    chunks.push(c);
  }
  return Buffer.concat(chunks);
}

/** Decompress, never beyond `max` bytes (a 1 MB gzip bomb must not inflate to a gigabyte). */
function decompress(buf: Buffer, encoding: string | undefined, max: number): Buffer {
  const o = { maxOutputLength: max };
  switch ((encoding ?? '').toLowerCase().trim()) {
    case '':
    case 'identity':
      return buf;
    case 'gzip':
    case 'x-gzip':
      return gunzipSync(buf, o);
    case 'deflate':
      return inflateSync(buf, o);
    case 'br':
      return brotliDecompressSync(buf, o);
    case 'zstd':
      return zstdDecompressSync(buf, o);
    default:
      throw Object.assign(new Error(`unsupported content-encoding ${encoding}`), { status: 415 });
  }
}

export function createProxy(opts: ProxyOptions): Server & { stats: ProxyStats } {
  const stats: ProxyStats = { requests: 0, redacted: {} };
  const maxBody = opts.maxBody ?? 64 * 1024 * 1024;
  const log = opts.log ?? (() => {});
  // What weakens protection is said even when the log is off (-q).
  const warn = opts.warn ?? ((l: string) => console.error(`llm-redact: warning: ${l}`));
  // One cache per proxy (and so per vault): repeated history is not redacted again every turn.
  const redactOpts = { ...opts.redact, cache: new RedactCache() };
  /**
   * What a Responses response could restore, by its id: a request that continues it
   * (`previous_response_id`) may restore those too — its history lives on the server.
   */
  const scopes = new Map<string, Map<string, string>>();

  // One request must never take the proxy down (and with it every agent using it).
  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      // Never the URL as it came: with --require-token its first segment is the token.
      const where = opts.token ? (req.url ?? '').replace(opts.token, '<token>') : req.url;
      log(`${req.method} ${where} -> internal error: ${(err as Error)?.message ?? err}`);
      if (!res.headersSent) fail(res, 500, 'llm-redact internal error');
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const t0 = Date.now();
    // DNS rebinding: a web page that resolves its own name to 127.0.0.1 still sends its own Host.
    if (!LOOPBACK_HOST.test(req.headers.host ?? '')) return fail(res, 403, 'llm-redact only accepts requests addressed to localhost');
    // A web page on another site can still POST here (a "simple" request needs no preflight). Agents
    // and SDKs send no Origin; a local web app sends a loopback one.
    const origin = req.headers.origin;
    if ((origin !== undefined && !LOOPBACK_ORIGIN.test(origin)) || req.headers['sec-fetch-site'] === 'cross-site') return fail(res, 403, 'llm-redact does not accept requests from web pages of other sites');
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      return fail(res, 400, 'bad request URL');
    }
    let segments = url.pathname.split('/').slice(1);
    if (opts.token) {
      // Constant-time comparison: the token is a secret.
      const given = Buffer.from(segments[0] ?? '');
      const want = Buffer.from(opts.token);
      if (given.length !== want.length || !timingSafeEqual(given, want)) return fail(res, 403, 'this llm-redact proxy requires its access token in the URL (see: llm-redact env)');
      segments = segments.slice(1);
    }
    const [name = '', ...rest] = segments;
    if (!name) return send(res, 200, { name: 'llm-redact', version: VERSION, upstreams: Object.keys(opts.upstreams), stats });
    // Own properties only: "__proto__" or "constructor" is not an upstream.
    const base = Object.hasOwn(opts.upstreams, name) ? opts.upstreams[name] : undefined;
    if (typeof base !== 'string') return fail(res, 404, `unknown upstream "${name}"`, { upstreams: Object.keys(opts.upstreams) });
    const path = '/' + rest.join('/');
    const target = base.replace(/\/+$/, '') + path + url.search;
    const api = apiFor(path);
    stats.requests++;

    // Fail closed: a body that cannot be redacted is refused, never forwarded as it came in.
    let body: Buffer | undefined;
    let note = '';
    const counts: Record<string, number> = {};
    // The placeholders this request's redaction produced: the only ones its response may restore.
    const produced = new Set<string>();
    let previous: string | undefined;
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const raw = await readBody(req, maxBody);
        const plain = decompress(raw, req.headers['content-encoding'], maxBody);
        const type = (req.headers['content-type'] ?? '').toLowerCase();
        // Patterns match UTF-8 text; a body in another charset would pass them by unseen.
        const declared = /;\s*charset="?([^";\s]+)/.exec(type)?.[1];
        let text = plain.toString('utf8');
        // Undeclared is not "UTF-8" either: a UTF-16 body sent as text/plain went through as if it were, with the
        // key readable to anyone who drops the NUL bytes. Text that does not round-trip as UTF-8 is refused too.
        const notUtf8 = !declared && plain.length > 0 && (plain.includes(0) || !Buffer.from(text, 'utf8').equals(plain));
        const charset = declared ?? (notUtf8 ? 'non-UTF-8 (undeclared)' : undefined);
        const foreign = notUtf8 || (!!declared && !/^(utf-?8|us-ascii|ascii)$/.test(declared));
        if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // a BOM is not a reason to skip redaction
        if (!plain.length) body = plain;
        else if (foreign) {
          if (!opts.allowUnredacted) throw Object.assign(new Error(`cannot redact a ${charset} body; refusing to forward it (send UTF-8, or start llm-redact with --allow-unredacted)`), { status: 415 });
          body = plain;
          note = ` (${charset} body forwarded UNREDACTED: --allow-unredacted)`;
        } else if (/json/.test(type) || (!type && /^\s*[{[]/.test(text.slice(0, 64)))) {
          let parsed: unknown;
          try {
            parsed = parseJson(text);
          } catch (err) {
            if ((err as Error).message.includes('nested deeper')) throw err;
            throw Object.assign(new Error('request body is not valid JSON; llm-redact does not forward what it cannot redact'), { status: 400 });
          }
          const r = redactRequest(parsed, opts.vault, api, redactOpts);
          Object.assign(counts, summarize(r.hits));
          for (const h of r.hits) produced.add(h.placeholder);
          if (typeof parsed === 'object' && parsed !== null && typeof (parsed as { previous_response_id?: unknown }).previous_response_id === 'string') previous = (parsed as { previous_response_id: string }).previous_response_id;
          body = Buffer.from(JSON.stringify(r.body), 'utf8');
        } else if (/^text\/|x-www-form-urlencoded/.test(type)) {
          const r = /x-www-form-urlencoded/.test(type) ? redactForm(text, opts.vault, redactOpts) : redactText(text, opts.vault, redactOpts);
          Object.assign(counts, summarize(r.hits));
          for (const h of r.hits) produced.add(h.placeholder);
          body = Buffer.from(r.text, 'utf8');
        } else if (opts.allowUnredacted) {
          body = plain;
          note = ` (${type || 'untyped'} body forwarded UNREDACTED: --allow-unredacted)`;
        } else throw Object.assign(new Error(`cannot redact a ${type || 'untyped'} body (file uploads, binary); refusing to forward it. Start llm-redact with --allow-unredacted to forward such bodies as they are.`), { status: 415 });
      }
    } catch (err) {
      const status = (err as { status?: number }).status ?? (/maxOutputLength|buffer|too large|nested deeper/i.test((err as Error).message) ? 413 : 400);
      log(`${req.method} /${name}${path} -> refused (${status}): ${(err as Error).message}`);
      return fail(res, status, (err as Error).message);
    }
    for (const [k, n] of Object.entries(counts)) stats.redacted[k] = (stats.redacted[k] ?? 0) + n;
    // Restores only this request's placeholders, with their values pinned now: no guessed tag, no
    // placeholder planted in a file the agent read, no other conversation's value — and an eviction
    // from the vault while the response streams cannot take a value away from it.
    // (Keyed by upstream and id: an id from one provider means nothing for another.)
    const scope = opts.vault.scope(produced, previous ? scopes.get(`${name}\0${previous}`) : undefined);

    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k.toLowerCase()) && v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
    // Uncompressed responses, so placeholders can be restored in them.
    headers['accept-encoding'] = 'identity';

    const abort = new AbortController();
    res.on('close', () => {
      if (!res.writableFinished) abort.abort();
    });
    let upstream: Response;
    try {
      upstream = await fetch(target, { method: req.method, headers, body: body && body.length ? new Uint8Array(body) : undefined, redirect: 'manual', signal: abort.signal });
    } catch (err) {
      log(`${req.method} /${name}${path} -> upstream error: ${(err as Error).message}`);
      return fail(res, 502, `upstream ${base} unreachable: ${(err as Error).message}`);
    }

    const outHeaders: Record<string, string | string[]> = {};
    upstream.headers.forEach((v, k) => {
      if (!HOP.has(k.toLowerCase()) && !RESPONSE_DROP.test(k)) outHeaders[k] = v;
    });
    // Every Set-Cookie, not only the last (Headers joins the others away).
    const cookies = upstream.headers.getSetCookie();
    if (cookies.length) outHeaders['set-cookie'] = cookies;
    // fetch decodes these itself; anything else arrives still encoded and must keep its header.
    const encoding = (upstream.headers.get('content-encoding') ?? '').toLowerCase().trim();
    const undecoded = !!encoding && !['identity', 'gzip', 'x-gzip', 'deflate', 'br', 'zstd'].includes(encoding);
    if (undecoded) outHeaders['content-encoding'] = encoding;
    // A redirect would make the client re-send its ORIGINAL (unredacted) body to wherever it points.
    // Within this upstream: point it back through the proxy. Anywhere else: refuse.
    if (upstream.status >= 300 && upstream.status < 400 && outHeaders.location) {
      const loc = new URL(outHeaders.location, target);
      const root = base.replace(/\/+$/, '');
      if (loc.href.startsWith(root + '/') || loc.href === root) {
        outHeaders.location = `http://${req.headers.host}/${opts.token ? `${opts.token}/` : ''}${name}${loc.href.slice(root.length)}`;
      } else {
        await upstream.body?.cancel();
        log(`${req.method} /${name}${path} -> refused redirect to ${loc.origin}`);
        return fail(res, 502, `upstream redirected to ${loc.origin}; llm-redact does not let clients follow redirects past it`);
      }
    }
    const type = upstream.headers.get('content-type') ?? '';
    let outcome: string | undefined;
    let responseId: string | undefined;
    /** Write, waiting when the client reads slower than the upstream sends (no unbounded buffering). */
    // A client that stops reading and then disconnects never sends 'drain': waiting for it alone left the handler
    // stuck for good (no log line, its pinned values kept in memory). Its 'close' ends the wait as an abort.
    const write = async (s: string | Uint8Array): Promise<void> => {
      if (!s.length || res.write(s)) return;
      if (res.destroyed) throw Object.assign(new Error('the client went away'), { name: 'AbortError' });
      await new Promise<void>((resolve, reject) => {
        const off = () => {
          res.off('drain', drained);
          res.off('close', closed);
        };
        const drained = () => {
          off();
          resolve();
        };
        const closed = () => {
          off();
          reject(Object.assign(new Error('the client went away'), { name: 'AbortError' }));
        };
        res.once('drain', drained);
        res.once('close', closed);
      });
    };
    try {
      if (req.method === 'HEAD' || !upstream.body || undecoded) {
        // Nothing to restore — or bytes still encoded in a way fetch could not undo: as they came,
        // with their length (fetch changed nothing here).
        const length = upstream.headers.get('content-length');
        res.writeHead(upstream.status, length && (req.method === 'HEAD' || undecoded) ? { ...outHeaders, 'content-length': length } : outHeaders);
        if (upstream.body && req.method !== 'HEAD') for await (const chunk of upstream.body) await write(chunk);
        res.end();
      } else if (/text\/event-stream/i.test(type)) {
        res.writeHead(upstream.status, outHeaders);
        res.flushHeaders(); // the client sees the stream start now, not with the first complete event
        const parser = new SseParser(maxBody);
        const restorer = new SseRestorer(scope, api);
        const decoder = new TextDecoder();
        for await (const chunk of upstream.body) {
          for (const e of parser.feed(decoder.decode(chunk, { stream: true }))) for (const o of restorer.transform(e)) await write(serialize(o));
        }
        const final = parser.feed(decoder.decode());
        const last = parser.end();
        for (const e of [...final, ...last.events]) for (const o of restorer.transform(e)) await write(serialize(o));
        for (const o of restorer.finish()) await write(serialize(o));
        // An event cut off without its blank line: a client discards it, so it goes out as it was.
        res.end(last.rest);
        responseId = restorer.responseId;
      } else if (/ndjson|jsonl|json-seq|x-json-stream/i.test(type)) {
        // One JSON object per line (Ollama): restored line by line, as it streams.
        res.writeHead(upstream.status, outHeaders);
        res.flushHeaders();
        const nd = new NdjsonRestorer(scope, maxBody);
        const decoder = new TextDecoder();
        for await (const chunk of upstream.body) await write(nd.feed(decoder.decode(chunk, { stream: true })));
        res.end(nd.feed(decoder.decode()) + nd.end());
      } else if (/json|^text\//i.test(type) || !type) {
        const bytes = await readLimited(upstream.body, maxBody);
        const text = new TextDecoder().decode(bytes);
        let out: string | Uint8Array = text;
        if (/json/i.test(type) || !type) {
          try {
            const parsed = parseJson(text);
            out = JSON.stringify(restoreResponse(parsed, scope, api));
            if (typeof parsed === 'object' && parsed !== null && typeof (parsed as { id?: unknown }).id === 'string') responseId = (parsed as { id: string }).id;
          } catch {
            // Not parseable (or absurdly nested): as it came. A blind text restore could put real
            // values inside signed thinking, or break the JSON. (Untyped and not JSON: raw bytes.)
            out = type ? text : bytes;
          }
        } else out = scope.restore(text);
        res.writeHead(upstream.status, { ...outHeaders, 'content-length': String(typeof out === 'string' ? Buffer.byteLength(out) : out.length) });
        res.end(out);
      } else {
        res.writeHead(upstream.status, outHeaders);
        for await (const chunk of upstream.body) await write(chunk);
        res.end();
      }
    } catch (err) {
      outcome = `response refused: ${(err as Error).message}`;
      if (!res.headersSent) fail(res, 502, (err as Error).message);
      else res.destroy(err as Error);
    }
    // A later request may continue this response (Responses API): keep what it could restore.
    if (api === 'responses' && responseId && scope.values.size) {
      scopes.set(`${name}\0${responseId}`, scope.values);
      if (scopes.size > 1000) scopes.delete(scopes.keys().next().value as string);
    }
    const summary = Object.entries(counts).map(([k, n]) => `${k} x${n}`).join(' ');
    // Placeholders the response held that its request did not carry: written as they are, so say so.
    const unrestored = scope.missed ? `  unrestored ${scope.missed}` : '';
    log(`${req.method} /${name}${path} -> ${outcome ?? upstream.status} ${Date.now() - t0}ms${summary ? `  redacted ${summary}` : ''}${unrestored}${note}`);
    if (note) warn(`${req.method} /${name}${path}${note}`);
  }
  // Agents are idle between turns. Node closes idle connections after 5 s by default, and a client
  // reusing one at that moment gets ECONNRESET on a POST it will not retry. Clients' own idle
  // timeouts are shorter than this, so they close first.
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  return Object.assign(server, { stats });
}
