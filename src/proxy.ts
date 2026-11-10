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
import { once } from 'node:events';
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
  /** Largest request body accepted (bytes) — also the limit for what a compressed body may inflate to. */
  maxBody?: number;
  /** Forward bodies that cannot be redacted (multipart uploads, binary) instead of refusing them. */
  allowUnredacted?: boolean;
  /**
   * Require this secret as the first path segment (`/<token>/anthropic/…`). Anyone who can reach the
   * proxy could otherwise get a placeholder they have seen turned back into its value.
   */
  token?: string;
}

export interface ProxyStats {
  requests: number;
  redacted: Record<string, number>;
}

const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host', 'content-length', 'content-encoding', 'accept-encoding', 'expect']);
const LOOPBACK_HOST = /^(127\.\d+\.\d+\.\d+|localhost|\[::1\])(:\d+)?$/i;

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
  // One cache per proxy (and so per vault): repeated history is not redacted again every turn.
  const redactOpts = { ...opts.redact, cache: new RedactCache() };

  // One request must never take the proxy down (and with it every agent using it).
  const server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      log(`${req.method} ${req.url} -> internal error: ${(err as Error)?.message ?? err}`);
      if (!res.headersSent) send(res, 500, { error: 'llm-redact internal error' });
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const t0 = Date.now();
    // DNS rebinding: a web page that resolves its own name to 127.0.0.1 still sends its own Host.
    if (!LOOPBACK_HOST.test(req.headers.host ?? '')) return send(res, 403, { error: 'llm-redact only accepts requests addressed to localhost' });
    let url: URL;
    try {
      url = new URL(req.url ?? '/', 'http://localhost');
    } catch {
      return send(res, 400, { error: 'bad request URL' });
    }
    let segments = url.pathname.split('/').slice(1);
    if (opts.token) {
      // Constant-time comparison: the token is a secret.
      const given = Buffer.from(segments[0] ?? '');
      const want = Buffer.from(opts.token);
      if (given.length !== want.length || !timingSafeEqual(given, want)) return send(res, 403, { error: 'this llm-redact proxy requires its access token in the URL (see: llm-redact env)' });
      segments = segments.slice(1);
    }
    const [name = '', ...rest] = segments;
    if (!name) return send(res, 200, { name: 'llm-redact', version: VERSION, upstreams: Object.keys(opts.upstreams), stats });
    // Own properties only: "__proto__" or "constructor" is not an upstream.
    const base = Object.hasOwn(opts.upstreams, name) ? opts.upstreams[name] : undefined;
    if (typeof base !== 'string') return send(res, 404, { error: `unknown upstream "${name}"`, upstreams: Object.keys(opts.upstreams) });
    const path = '/' + rest.join('/');
    const target = base.replace(/\/+$/, '') + path + url.search;
    const api = apiFor(path);
    stats.requests++;

    // Fail closed: a body that cannot be redacted is refused, never forwarded as it came in.
    let body: Buffer | undefined;
    let note = '';
    const counts: Record<string, number> = {};
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const raw = await readBody(req, maxBody);
        const plain = decompress(raw, req.headers['content-encoding'], maxBody);
        const type = (req.headers['content-type'] ?? '').toLowerCase();
        // Patterns match UTF-8 text; a body in another charset would pass them by unseen.
        const charset = /;\s*charset="?([^";\s]+)/.exec(type)?.[1];
        const foreign = !!charset && !/^(utf-?8|us-ascii|ascii)$/.test(charset);
        let text = plain.toString('utf8');
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
          body = Buffer.from(JSON.stringify(r.body), 'utf8');
        } else if (/^text\/|x-www-form-urlencoded/.test(type)) {
          const r = /x-www-form-urlencoded/.test(type) ? redactForm(text, opts.vault, redactOpts) : redactText(text, opts.vault, redactOpts);
          Object.assign(counts, summarize(r.hits));
          body = Buffer.from(r.text, 'utf8');
        } else if (opts.allowUnredacted) {
          body = plain;
          note = ` (${type || 'untyped'} body forwarded UNREDACTED: --allow-unredacted)`;
        } else throw Object.assign(new Error(`cannot redact a ${type || 'untyped'} body (file uploads, binary); refusing to forward it. Start llm-redact with --allow-unredacted to forward such bodies as they are.`), { status: 415 });
      }
    } catch (err) {
      const status = (err as { status?: number }).status ?? (/maxOutputLength|buffer|too large|nested deeper/i.test((err as Error).message) ? 413 : 400);
      log(`${req.method} /${name}${path} -> refused (${status}): ${(err as Error).message}`);
      return send(res, status, { error: (err as Error).message });
    }
    for (const [k, n] of Object.entries(counts)) stats.redacted[k] = (stats.redacted[k] ?? 0) + n;

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
      return send(res, 502, { error: `upstream ${base} unreachable: ${(err as Error).message}` });
    }

    const outHeaders: Record<string, string | string[]> = {};
    upstream.headers.forEach((v, k) => {
      if (!HOP.has(k.toLowerCase())) outHeaders[k] = v;
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
        return send(res, 502, { error: `upstream redirected to ${loc.origin}; llm-redact does not let clients follow redirects past it` });
      }
    }
    const type = upstream.headers.get('content-type') ?? '';
    let outcome: string | undefined;
    /** Write, waiting when the client reads slower than the upstream sends (no unbounded buffering). */
    const write = async (s: string | Uint8Array): Promise<void> => {
      if (s.length && !res.write(s)) await once(res, 'drain');
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
        const restorer = new SseRestorer(opts.vault, api);
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
      } else if (/ndjson|jsonl|json-seq|x-json-stream/i.test(type)) {
        // One JSON object per line (Ollama): restored line by line, as it streams.
        res.writeHead(upstream.status, outHeaders);
        res.flushHeaders();
        const nd = new NdjsonRestorer(opts.vault, maxBody);
        const decoder = new TextDecoder();
        for await (const chunk of upstream.body) await write(nd.feed(decoder.decode(chunk, { stream: true })));
        res.end(nd.feed(decoder.decode()) + nd.end());
      } else if (/json|^text\//i.test(type) || !type) {
        const bytes = await readLimited(upstream.body, maxBody);
        const text = new TextDecoder().decode(bytes);
        let out: string | Uint8Array = text;
        if (/json/i.test(type) || !type) {
          try {
            out = JSON.stringify(restoreResponse(parseJson(text), opts.vault, api));
          } catch {
            // Not parseable (or absurdly nested): as it came. A blind text restore could put real
            // values inside signed thinking, or break the JSON. (Untyped and not JSON: raw bytes.)
            out = type ? text : bytes;
          }
        } else out = opts.vault.restore(text);
        res.writeHead(upstream.status, { ...outHeaders, 'content-length': String(typeof out === 'string' ? Buffer.byteLength(out) : out.length) });
        res.end(out);
      } else {
        res.writeHead(upstream.status, outHeaders);
        for await (const chunk of upstream.body) await write(chunk);
        res.end();
      }
    } catch (err) {
      outcome = `response refused: ${(err as Error).message}`;
      if (!res.headersSent) send(res, 502, { error: (err as Error).message });
      else res.destroy(err as Error);
    }
    const summary = Object.entries(counts).map(([k, n]) => `${k} x${n}`).join(' ');
    log(`${req.method} /${name}${path} -> ${outcome ?? upstream.status} ${Date.now() - t0}ms${summary ? `  redacted ${summary}` : ''}${note}`);
  }
  // Agents are idle between turns. Node closes idle connections after 5 s by default, and a client
  // reusing one at that moment gets ECONNRESET on a POST it will not retry. Clients' own idle
  // timeouts are shorter than this, so they close first.
  server.keepAliveTimeout = 65_000;
  server.headersTimeout = 66_000;
  return Object.assign(server, { stats });
}
