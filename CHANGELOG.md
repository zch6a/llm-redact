# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

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
