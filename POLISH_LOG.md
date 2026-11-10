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

## Round 1 — done (v0.2.0)

- [x] **Precision on real code.** Ran every detector over 2,955 real files (19 MB: the five public skill repositories from skill-guard's corpus plus this workspace's three projects), printing hits with values masked. The generic `NAME=value` rule had **317 hits, nearly all false**: shell references (`$ANTHROPIC_API_KEY"`), code (`Environment.GetEnvironmentVariable(…)`, `result.InputTokens`, `sum(…)`), bare identifiers (`work_secret`), types (`password: string`), generics, negations, paths, URLs (`token_endpoint: "https://…"`), sentences in quotes, numbers (`"token_efficiency": 0.93…`), token counts (`max_tokens`), and documentation placeholders with a provider prefix (`ghp_your_github_token`, `sk-your-secret-here`, `sk-ant-invalid`). Now **25**, all genuinely password-shaped example or test values. Card numbers: decimals that pass Luhn by chance (`65.4545454545454`) excluded, 14 → 9 (the rest are Stripe's published test cards). URL passwords: dummy values (`postgres:test@localhost`) excluded. Each class is now a negative test (19 new cases); recall tests unchanged.
- [x] **Real request shapes.** Surveyed local Claude Code and Codex session logs for block/item types and key names only (no content read out): every shape is handled — except **Codex custom tool calls** (`apply_patch` is one). Requests were fine (their `input` is redacted), but in a streamed response the patch arrives as `response.custom_tool_call_input.delta`, which was not restored: a patch writing a key into `.env` would have written the *placeholder* to disk. Fixed for Responses and Chat Completions custom tools, with an end-to-end test.
- [x] `llm-redact stats`: what a running proxy has redacted so far (counts only).
- [x] **Independent leak review** (a reviewer with only the code, asked to get a synthetic value past the proxy): **19 findings, 18 confirmed and fixed**, the 19th documented. The worst were structural: the proxy *failed open* — a body it could not parse (a UTF-8 BOM was enough) went out as it came, uploads went out unredacted, and a redirect would have made the client re-send its original body to wherever the upstream pointed. The walker treated keys like `user`, `name`, `id`, `metadata` as API structure even inside tool inputs, so `{"user": "li.wei@…"}` in a tool call leaked, as did object keys. Smaller: escaped JSON inside strings, the url_password span when the host repeats the password, card + CVV, truncated private keys, long names, a 10k-match cap, a 13-second ReDoS shape, `/__proto__` and malformed URLs crashing or hanging the process, unknown stream formats, Anthropic `error` events, legacy `function_call`. The 19th — anything that can reach the proxy, or make the model echo a placeholder, gets the value restored — is inherent to the design; `--require-token` closes the first half for shared machines and README/SECURITY now say plainly that a prompt-injected agent can still use restored secrets.
- [x] **Every finding is a regression test** (`test/regressions.test.ts`, 40 tests). Checked the other way round too: run against the pre-fix code, the file fails across the board (the ReDoS case alone took 13.6 s, and the hostile-URL probe hung the old proxy).
- [x] Precision corpus rerun after the fixes: unchanged on the external repositories (`secret_assignment` and `credit_card` only grew by this project's own new test fixtures).
- [x] Docs: fail-closed behaviour, `--require-token`, `--allow-unredacted`, and the injected-agent limit in README (en/zh) and SECURITY; CHANGELOG 0.2.0.
- [ ] Run it for real with Claude Code against the user's setup (spends their tokens: needs their go-ahead — asked, no answer yet).

135 tests (was 95).

## Round 2 — backlog

- Second, fresh leak review focused on what round 1 changed (free zones, escaped-text pass, redirect rewrite, token path).
- Throughput: the escaped-text pass runs detectors again on unescaped views; measure on a 5 MB conversation and cap the cost.
- `scan --diff`-style output that shows exactly which spans would change in a request body (helps users trust it).
- Windows: token/key file permissions (mode 600 is ignored on NTFS) — use an ACL or say so.
- An end-to-end smoke with a real client binary (Claude Code / Codex) pointed at a mock upstream — no tokens spent.
