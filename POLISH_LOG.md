# Polish log

Each round goes through the full checklist: features vs. README, code read-through, tests, first-run UX, docs, engineering, security & privacy.

## v0.1.0 — in development

Goal: a local proxy between an AI agent and its model API. Requests are redacted before they leave the machine (API keys, tokens, private keys, connection-string passwords, generic `*_SECRET=` assignments; e-mail, phone numbers, Chinese ID numbers, payment cards, IBAN, SSN), responses are restored on the way back — including streamed text and tool-call arguments — so the agent keeps working with real values while the provider never sees them. Targets: Claude Code (Anthropic Messages API), Codex (OpenAI Responses API), OpenCode and other OpenAI-compatible clients, DeepSeek (OpenAI- and Anthropic-compatible endpoints), DeepSeek Harness.

Design decisions so far:

- **Placeholders are HMACs of the value with a local key** (`[[REDACTED:openai_key:3f9a1c2b]]`): the same secret gets the same placeholder in every request and after a restart, so the provider's prompt cache keeps hitting and the model sees a consistent conversation. Values live only in memory; after a restart the client resends them in its history and the map refills.
- **Precision first.** Structured values are validated (Luhn, GB 11643 check digit + real birth date, IBAN mod 97); generic assignments need a value with entropy ≥ 3 bits/char and mixed character classes; documentation placeholders (`your_api_key`, `${TOKEN}`, `<key>`, `changeme`) and references (`process.env.X`) are left alone; example e-mail domains and `noreply@` are not personal data. Specific detectors run before generic ones and win overlaps (a GitHub token used as a URL password is labelled `github_token`).
- **Streaming restore** holds back only a tail that could still become a placeholder; tested by splitting a reply at every position and with 300 random chunkings.
- **Every quantifier is bounded** (lesson from skill-guard's ReDoS round), including the placeholder-value filter, which first had a nested ambiguous quantifier.

Done: `src/detectors.ts` (23 detectors, 1 optional), `src/vault.ts`, `src/redact.ts`, `src/stream.ts`; 60 tests.

Next:

- [ ] Request walker: redact text fields of Anthropic Messages, OpenAI Chat Completions and Responses bodies; never touch thinking blocks / signatures / encrypted reasoning, images, ids, model names.
- [ ] Response restore: JSON bodies and SSE streams (Anthropic `text_delta` / `input_json_delta`, OpenAI chat deltas incl. tool-call arguments, Responses `*.delta` events), with JSON-string encoding inside argument fragments.
- [ ] Proxy (`node:http`, 127.0.0.1 only): path-based upstreams (`/anthropic`, `/openai`, `/deepseek`, custom), header passthrough, no compression upstream, request-body decompression.
- [ ] CLI: `start`, `env` (exports for Claude Code / Codex / OpenCode / DeepSeek Harness), `scan <file|->` to preview, `--disable`, `--allow`.
- [ ] Mock upstream for end-to-end tests (no network): the upstream must only ever see placeholders, the client must only ever see real values.
- [ ] README (en/zh), SECURITY, CONTRIBUTING, CHANGELOG, CI.
