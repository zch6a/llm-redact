# Polish log

Each round goes through the full checklist: features vs. README, code read-through, tests, first-run UX, docs, engineering, security & privacy.

## v0.1.0 — first release (2026-11-11)

Built on top of the core below: the request walker (`body.ts`), SSE restoration for all three wire formats (`sse.ts`), the proxy (`proxy.ts`), the CLI (`cli.ts`), docs and CI. 75 tests, including end-to-end tests through a mock upstream that implements Anthropic Messages, OpenAI Chat Completions and OpenAI Responses (streamed and not), streams its answers in 3–4-character deltas over 7-byte network chunks, and quotes back whatever placeholder it received.

What the end-to-end tests found (both would have been leaks in real use):

- **A password containing a quote was sent in clear.** `DB_PASSWORD=P"a\ss-W0rd-9xQz` — the generic rule treated `"` as the end of the value, saw a one-character value, and redacted nothing. The value grammar now distinguishes quoted values (to the closing quote, honouring backslash escapes) from unquoted ones (to whitespace, quotes inside included, trailing punctuation trimmed).
- **A bare secret in JSON had no context.** Inside parsed tool-call arguments, `{"pw": "…"}` has no `NAME=` text around the value. In structured data the key is the context: a value under a secret-named key is redacted whole if it looks generated (`secretByKey`), with negative tests (`token_count: 128000`, `name: …`).

Other decisions made while building:

- The API format is taken from the request path, not guessed from the body (a body-shape heuristic was written first and thrown away: Anthropic and Chat bodies overlap too much).
- Tool-call `arguments` are JSON text: restored values are JSON-escaped there, and in requests the values *inside* are redacted (parse → redact → re-serialise only when something changed, so untouched arguments stay byte-identical for prompt caching).
- The placeholder note goes at the end of the system prompt (after cache breakpoints) and is deterministic.
- Console output is ASCII (`->`, `x2`): a garbled banner in a GBK console was the first thing a smoke test showed.

## Core (before v0.1.0)

Goal: a local proxy between an AI agent and its model API. Requests are redacted before they leave the machine (API keys, tokens, private keys, connection-string passwords, generic `*_SECRET=` assignments; e-mail, phone numbers, Chinese ID numbers, payment cards, IBAN, SSN), responses are restored on the way back — including streamed text and tool-call arguments — so the agent keeps working with real values while the provider never sees them. Targets: Claude Code (Anthropic Messages API), Codex (OpenAI Responses API), OpenCode and other OpenAI-compatible clients, DeepSeek (OpenAI- and Anthropic-compatible endpoints), DeepSeek Harness.

Design decisions so far:

- **Placeholders are HMACs of the value with a local key** (`[[REDACTED:openai_key:3f9a1c2b]]`): the same secret gets the same placeholder in every request and after a restart, so the provider's prompt cache keeps hitting and the model sees a consistent conversation. Values live only in memory; after a restart the client resends them in its history and the map refills.
- **Precision first.** Structured values are validated (Luhn, GB 11643 check digit + real birth date, IBAN mod 97); generic assignments need a value with entropy ≥ 3 bits/char and mixed character classes; documentation placeholders (`your_api_key`, `${TOKEN}`, `<key>`, `changeme`) and references (`process.env.X`) are left alone; example e-mail domains and `noreply@` are not personal data. Specific detectors run before generic ones and win overlaps (a GitHub token used as a URL password is labelled `github_token`).
- **Streaming restore** holds back only a tail that could still become a placeholder; tested by splitting a reply at every position and with 300 random chunkings.
- **Every quantifier is bounded** (lesson from skill-guard's ReDoS round), including the placeholder-value filter, which first had a nested ambiguous quantifier.

Done then: `src/detectors.ts`, `src/vault.ts`, `src/redact.ts`, `src/stream.ts`; 60 tests.

## Round 1 — backlog

- [ ] Run it for real with Claude Code against the user's actual setup (they route through a relay: `--upstream anthropic=<relay>`) — needs the user, since it spends tokens; until then, a recorded-format replay test from real SSE captures if any are available locally.
- [ ] Independent review before 1.0 (lesson from skill-guard): leaks first — body shapes the walker skips, encodings, fields.
- [ ] Corpus for precision: run `scan` over real repositories (read-only) and count what would be redacted that is not a secret.
- [ ] Gemini / other formats? Only if a target client needs them.
- [ ] `stats` endpoint / command: what was redacted this session (counts).
