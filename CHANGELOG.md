# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-11-11

### Added

- Local proxy (`127.0.0.1` only) with path-based upstreams: `/anthropic`, `/openai`, `/deepseek`, and any `--upstream name=url`.
- Request redaction for Anthropic Messages, OpenAI Chat Completions and OpenAI Responses bodies; thinking blocks, signatures, encrypted reasoning, images, ids and tool definitions are never touched.
- Response restoration for JSON and server-sent events, including tool-call arguments (kept valid JSON), with placeholders split anywhere across deltas.
- 27 detectors (19 secret, 8 personal data; one optional), with checksum validation, entropy checks for generic assignments, documentation-placeholder filters, and key-name context in structured data.
- HMAC placeholders that are stable across requests and restarts (prompt caches keep hitting); values in memory only.
- A one-line note to the model when a request contains placeholders, appended to the end of the system prompt.
- CLI: `start`, `env` (bash, zsh, fish, PowerShell, cmd), `scan`, `detectors`; config file; counts-only request log.
