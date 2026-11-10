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
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { brotliDecompressSync, gunzipSync, inflateSync, zstdDecompressSync } from 'node:zlib';
import { apiFor, redactRequest, restoreResponse } from './body.ts';
import { summarize, type RedactOptions } from './redact.ts';
import { SseParser, SseRestorer, serialize } from './sse.ts';
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
  /** Largest request body accepted (bytes). */
  maxBody?: number;
}

export interface ProxyStats {
  requests: number;
  redacted: Record<string, number>;
}

const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'host', 'content-length', 'content-encoding', 'accept-encoding']);
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

function decompress(buf: Buffer, encoding: string | undefined): Buffer {
  switch ((encoding ?? '').toLowerCase().trim()) {
    case '':
    case 'identity':
      return buf;
    case 'gzip':
    case 'x-gzip':
      return gunzipSync(buf);
    case 'deflate':
      return inflateSync(buf);
    case 'br':
      return brotliDecompressSync(buf);
    case 'zstd':
      return zstdDecompressSync(buf);
    default:
      throw Object.assign(new Error(`unsupported content-encoding ${encoding}`), { status: 415 });
  }
}

export function createProxy(opts: ProxyOptions): Server & { stats: ProxyStats } {
  const stats: ProxyStats = { requests: 0, redacted: {} };
  const maxBody = opts.maxBody ?? 64 * 1024 * 1024;
  const log = opts.log ?? (() => {});

  const server = createServer(async (req, res) => {
    const t0 = Date.now();
    // DNS rebinding: a web page that resolves its own name to 127.0.0.1 still sends its own Host.
    if (!LOOPBACK_HOST.test(req.headers.host ?? '')) return send(res, 403, { error: 'llm-redact only accepts requests addressed to localhost' });
    const url = new URL(req.url ?? '/', 'http://localhost');
    const [, name = '', ...rest] = url.pathname.split('/');
    if (!name) return send(res, 200, { name: 'llm-redact', version: VERSION, upstreams: Object.keys(opts.upstreams), stats });
    const base = opts.upstreams[name];
    if (!base) return send(res, 404, { error: `unknown upstream "${name}"`, upstreams: Object.keys(opts.upstreams) });
    const path = '/' + rest.join('/');
    const target = base.replace(/\/+$/, '') + path + url.search;
    const api = apiFor(path);
    stats.requests++;

    let body: Buffer | undefined;
    let note = '';
    const counts: Record<string, number> = {};
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        const raw = await readBody(req, maxBody);
        const plain = decompress(raw, req.headers['content-encoding']);
        body = plain;
        if (/json/i.test(req.headers['content-type'] ?? '') || /^\s*[{[]/.test(plain.subarray(0, 64).toString('utf8'))) {
          try {
            const parsed: unknown = JSON.parse(plain.toString('utf8'));
            const r = redactRequest(parsed, opts.vault, api, opts.redact);
            Object.assign(counts, summarize(r.hits));
            body = Buffer.from(JSON.stringify(r.body), 'utf8');
          } catch {
            note = ' (body not JSON: passed through unredacted)';
          }
        } else if (plain.length) note = ` (${req.headers['content-type'] ?? 'unknown'} body passed through unredacted)`;
      }
    } catch (err) {
      return send(res, (err as { status?: number }).status ?? 400, { error: (err as Error).message });
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

    const outHeaders: Record<string, string> = {};
    upstream.headers.forEach((v, k) => {
      if (!HOP.has(k.toLowerCase())) outHeaders[k] = v;
    });
    const type = upstream.headers.get('content-type') ?? '';
    try {
      if (/text\/event-stream/i.test(type) && upstream.body) {
        res.writeHead(upstream.status, outHeaders);
        const parser = new SseParser();
        const restorer = new SseRestorer(opts.vault, api);
        const decoder = new TextDecoder();
        for await (const chunk of upstream.body) {
          for (const e of parser.feed(decoder.decode(chunk, { stream: true }))) for (const o of restorer.transform(e)) res.write(serialize(o));
        }
        for (const e of [...parser.feed(decoder.decode()), ...parser.end()]) for (const o of restorer.transform(e)) res.write(serialize(o));
        for (const o of restorer.finish()) res.write(serialize(o));
        res.end();
      } else if (/json/i.test(type)) {
        const text = await upstream.text();
        let out = text;
        try {
          out = JSON.stringify(restoreResponse(JSON.parse(text), opts.vault));
        } catch {
          out = opts.vault.restore(text);
        }
        res.writeHead(upstream.status, { ...outHeaders, 'content-length': String(Buffer.byteLength(out)) });
        res.end(out);
      } else {
        res.writeHead(upstream.status, outHeaders);
        if (upstream.body) for await (const chunk of upstream.body) res.write(chunk);
        res.end();
      }
    } catch (err) {
      if (!res.headersSent) send(res, 502, { error: (err as Error).message });
      else res.destroy(err as Error);
    }
    const summary = Object.entries(counts).map(([k, n]) => `${k} x${n}`).join(' ');
    log(`${req.method} /${name}${path} -> ${upstream.status} ${Date.now() - t0}ms${summary ? `  redacted ${summary}` : ''}${note}`);
  });
  return Object.assign(server, { stats });
}
