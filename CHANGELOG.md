# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.5.0] — 2026-11-11

A fourth independent review looked at the system over time — across turns, sessions and restarts — and found 16 problems, all reproduced. All are fixed, each with a test; every fix was undone once in a copy of the code to make sure the suite fails without it. A new soak test runs concurrent agents for hundreds of turns.

### Security

- **A response restores only its own request's placeholders**, with their values pinned when the request was redacted (for the Responses API, also those of the response it continues). Before, any client could get any value in the shared vault restored — by guessing tags (1,000,000 guesses in one request found 6 real addresses), from another session, or through a placeholder planted in a file the agent reads. Pinning also keeps a value restorable when the vault evicts it mid-stream.
- **Restored values stay remembered.** A value found by its context and restored to the client is kept in a memory of its own, so a flood of other context-found values (an access log with 5,000 bearer tokens) can no longer push it out — after which it went out in clear every turn. Values in use are refreshed whenever they are seen or restored.
- **Remembered across restarts**, as keyed hashes in a `remembered` file (never values): after a restart a compaction summary holding a restored value — with its context long gone — no longer leaks it.
- Within one request, a bare value *before* its context is caught (the request is walked again when it taught the vault a value) — the shape of the first request after a restart.
- Short URL passwords (4–7 characters, mixed classes) are remembered too, matched as whole words.
- **Base64**: `Authorization: Basic …` from `curl -v`, `echo $KEY | base64` — a base64 token that decodes to text holding a secret (remembered values included) is replaced whole.
- Percent-encoding of any character, and shell / Python quoting (`'\''`, `\'`), are decoded views now.
- A cached result is no longer reused when a value learned later appears in it in an encoded form.
- A broken default `config.json` (a trailing comma) or a mistyped setting (`"requireToken": "true"`) is an error instead of silently turning `--require-token` off.
- Key and token files: written owner-only before anything is in them, replacing explicit ACL entries too (`icacls /reset`); created atomically (processes starting at once agree on one key); an existing key that does not parse is refused, never overwritten; a warning when the ACL cannot be set; the folder is owner-only when created.
- The access token no longer appears in the log on an internal error.

### Added

- `npm run soak`: concurrent agents, hundreds of turns, compaction, restored values in the history — no leak and no placeholder at the client on any turn; latency and live heap over time (4 agents × 600 turns: flat latency, ~60 MB live heap).
- Known-value search skips decoded views when it cannot find anything there (5,000 remembered values: 681 → 549 ms on a cold 6.5 MB request).

## [0.4.0] — 2026-11-11

A third independent review, of the response side only, found 20 problems (19 reproduced). All are fixed, each with a test; every fix was undone once in a copy of the code to make sure the suite fails without it (24 mutations, all caught). A seeded property test now covers every streamed format.

### Security

- **Restored values were sent back in clear.** The model writes a placeholder somewhere new (`psql -W [[REDACTED:…]]`); the client gets the real password; next turn it sends that history back — and a value that was found by its *context* (`DB_PASSWORD=`, `Bearer`, URL passwords) has no context there. Such values are now remembered (8+ characters, the 5,000 most recent) and redacted wherever they appear, in every decoded view, with their original placeholder.
- **Responses are bounded**: a response body over the body limit (64 MB) is refused, an SSE event or NDJSON line that never ends is cut off, and writes wait for slow clients (backpressure). The vault is bounded too (200,000 values, least recently used forgotten — they come back with the next request).
- Reasoning is never restored, streamed or not, in any format — Responses `reasoning_text` parts, OpenRouter `reasoning.*` details (always passed back verbatim), unsigned Anthropic thinking, signed NDJSON lines — so no restored value can go back in clear inside a block the request side leaves alone.

### Fixed

- Placeholders are restored in Gemini streams (split across events), legacy completions / FIM streams (`choices[].text`), Responses refusals, MCP call arguments, annotations and `error` events, Anthropic citations, and `server_tool_use` / `mcp_tool_use` blocks.
- Held-back text is no longer lost when a stream ends without its usual terminator (an `error` event, a missing `.done`, a cut connection).
- Numbers in restored responses — streamed or not, SSE or NDJSON — are exactly as the upstream wrote them.
- A tool parameter named `arguments` or `partial_json` is no longer JSON-escaped twice when restored.
- Events the proxy inserts for held-back text carry no `id:` line and the next sequence number (later ones move up); a Chat flush chunk no longer repeats `usage`, and a tail goes into the finish chunk even when it has no `delta`.
- The last event of a CR-only stream is delivered (restored) at the end; an event cut off without its blank line is passed on as the bytes it was, as a client would discard it.
- NDJSON lines are no longer rescanned per chunk (8 MB line: 16 s → 18 ms).
- An event that cannot be processed (absurd nesting) passes through instead of killing the stream; an unparseable JSON body is passed through instead of restored blindly.
- Every `Set-Cookie` is kept; HEAD keeps `content-length`; untyped JSON and `text/*` responses are restored; a content-encoding fetch cannot decode passes through untouched; SSE and NDJSON headers go out immediately.
- Keep-alive: idle connections are kept 65 s, so a client reusing one between turns no longer gets ECONNRESET.

### Added

- `llm-redact scan --body request.json`: which fields of an API request would change, and what was found in each (`--api`, `--json`); `docs/example-request.json` to try it on.
- "Did you mean" for unknown commands and detectors; unreadable files are one line, not a stack trace.
- CI runs the suite without `JSON.rawJSON` (the fallback path) and the built package on Node 22.15.

## [0.3.0] — 2026-11-11

A second independent leak review, focused on what 0.2.0 changed, found 20 more problems (19 reproduced). All are fixed, each with a regression test; every fix was then undone once in a copy of the code to make sure some test fails without it.

### Security

- **Encoded text, any spelling.** Values in decoded views (JSON escapes, HTML entities, percent-encoding, CSV quotes) are now replaced by mapping their span back to the original, instead of re-encoding the value and searching for that spelling — so Go's `\u0026`, .NET's `\u002B` and Python's `\u00e4` escapes no longer hide a value.
- **Predicted Outputs** (`prediction.content`, the file being rewritten) and **`metadata`** are redacted; they were skipped as settings.
- **Numbers**: card and phone numbers written as JSON numbers are redacted; tool-call arguments with no string hits are no longer returned untouched when they hold such numbers.
- **Unknown APIs** (Ollama, Gemini, anything not Anthropic/OpenAI) are walked as data — every string and object key — instead of with the OpenAI/Anthropic structure rules.
- **Tool results** are data whatever their objects' keys are called; a chat message's `name` (the participant) is redacted.
- A string that only *starts* like a data: URL, or like base64 under a `data` key, is no longer skipped whole. Text files sent as base64 (`data:text/plain;base64,…`, Anthropic `media_type: text/plain` documents) are decoded, redacted and re-encoded.
- A block is treated as signed only when it carries a signature (or encrypted content); OpenRouter's signed `reasoning.*` details are left alone.
- **Never a partial redaction**: more than a million values in one text is a 413 refusal (the old per-detector caps stopped matching silently and forwarded the rest).
- Form bodies are redacted field by field after decoding (`%40`, `+`); `text/*` in a charset other than UTF-8 is refused (415) or, with `--allow-unredacted`, forwarded byte for byte.
- Reasoning summaries are no longer restored in one event and kept in another: like the rest of signed reasoning, they keep their placeholders (a client sending one back would otherwise send the value in clear).

### Fixed

- Placeholders already in a request were redacted again into nested placeholders (`[[REDACTED:github_token:[[REDACTED:…]]]]`).
- A placeholder's label no longer depends on which rule saw the value first (`password: sk-proj-…` is an `openai_key`), so placeholders stay the same after a restart.
- Numbers are kept exactly as written when a body is re-serialised (`12345678901234567890`, `1.10`); `__proto__` keys are no longer dropped.
- `pass` / `pw` names in JSON text (`{"db":{"pass":"…"}}`), and a bare `token` name, are found; `pass_rate`, `bypass`, Python f-strings are not secrets; passwords containing `<` or `]` are no longer rejected as code.
- Newline-delimited JSON responses (Ollama streaming) are restored line by line, as they stream, and stay valid JSON.
- Quadratic work removed: the escaped-text pass (0.8 MB: 13 s → 0.1 s), overlap checks (100,000 values: 9.7 s → 0.3 s), and the SSE parser on large events (16 MB: 1.9 s → 0.02 s). CR-only SSE line endings work.
- `Expect: 100-continue` (curl) no longer makes the upstream request fail.
- `reasoning_content` (DeepSeek) and `reasoning` (OpenRouter, vLLM) deltas in chat streams are restored.

### Added

- `npm run smoke`: the real Claude Code and Codex CLIs, against a local mock (no tokens spent), checking that the proxied request is byte-for-byte what the CLI sends directly once placeholders are undone.
- `llm-redact env` prints `NO_PROXY=127.0.0.1,localhost` (merged with yours): Codex sends even loopback requests through the Windows system proxy.
- A bounded in-memory cache of redaction results for long texts: agents re-send the whole conversation every turn (5 MB: 290 ms → 3 ms on the next turn).
- Key and token files get an owner-only ACL on Windows (a profile folder can be readable by other accounts).

## [0.2.0] — 2026-11-11

An independent leak review found 19 ways for a value to get past the proxy, or for the proxy to fail; all are fixed, each with a regression test (`test/regressions.test.ts`).

### Security

- **Fails closed.** Bodies that cannot be redacted are refused instead of forwarded: invalid JSON (400; a UTF-8 BOM no longer makes a JSON body "not JSON"), nesting deeper than 500 levels (413), decompression past the body limit (413, gzip bombs), and multipart / binary bodies (415). `text/*` and form-encoded bodies are redacted as text.
- **Tool inputs are data whatever their keys are called.** Inside a tool call's `input` and `arguments`, keys such as `user`, `name`, `id`, `metadata`, `type` and their values — and object keys themselves — were treated as API structure and skipped. Top-level settings (`tools`, `metadata`, `mcp_servers`, …) are now skipped only at the top level.
- Legacy `function_call.arguments` in Chat Completions history is redacted.
- Values inside escaped JSON text (a JSON string inside a string, up to two levels) are found and replaced in their escaped spelling.
- Redirects: within the upstream they are rewritten to go back through the proxy; anywhere else they are refused (the client would re-send its original body there).
- `--require-token`: the proxy only answers under a random path token, for machines with other users.
- `--allow-unredacted` to forward uploads as they are, explicitly.
- No crash or hang on hostile input: `/__proto__/…` is not an upstream, a malformed URL gets 400, any handler error is a 500 instead of a dead process.

### Fixed

- `url_password` redacted the wrong span when the password also appeared in the host name; the host part no longer runs into an e-mail address after it.
- Card numbers followed by a CVV, private keys cut off before their END line, and variable names longer than 40 characters before a secret are detected.
- A text with more than 10,000 matches is redacted completely; a crafted input (`token=;` × 60 then a million `;`) no longer takes 13 s.
- Non-streamed responses restore placeholders in tool inputs and object keys; Anthropic `error` events and other event types are restored; streams on unrecognised paths are identified by their first event; Vertex AI `:rawPredict` / `:streamRawPredict` and trailing-slash paths are recognised.

### Added

- `llm-redact stats`: what a running proxy has redacted so far (counts only).
- Codex custom tools (`apply_patch`): their streamed input is restored.
- Precision measured on 2,955 real files; the generic `NAME=value` rule went from 317 hits to 25.

## [0.1.0] — 2026-11-11

### Added

- Local proxy (`127.0.0.1` only) with path-based upstreams: `/anthropic`, `/openai`, `/deepseek`, and any `--upstream name=url`.
- Request redaction for Anthropic Messages, OpenAI Chat Completions and OpenAI Responses bodies; thinking blocks, signatures, encrypted reasoning, images, ids and tool definitions are never touched.
- Response restoration for JSON and server-sent events, including tool-call arguments (kept valid JSON), with placeholders split anywhere across deltas.
- 27 detectors (19 secret, 8 personal data; one optional), with checksum validation, entropy checks for generic assignments, documentation-placeholder filters, and key-name context in structured data.
- HMAC placeholders that are stable across requests and restarts (prompt caches keep hitting); values in memory only.
- A one-line note to the model when a request contains placeholders, appended to the end of the system prompt.
- CLI: `start`, `env` (bash, zsh, fish, PowerShell, cmd), `scan`, `detectors`; config file; counts-only request log.
