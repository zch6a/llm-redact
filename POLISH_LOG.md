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

## Round 2 — done (v0.3.0)

- [x] **The real CLIs, end to end, no tokens spent** (`scripts/smoke.ts`, `npm run smoke`): Claude Code 2.1.121 and Codex 0.131.0 each run twice against a local mock — directly and through the proxy — with a fake key, a throwaway home and a minimal environment. Checked: the mock never sees the synthetic key or e-mail, the CLI prints the real values, and the proxied request is **byte-for-byte the direct one** once placeholders and the note are undone (tools, system prompt, cache_control, key order). Both pass. What it found:
  - **Codex sends `127.0.0.1` traffic through the Windows system proxy** (on here, as on many machines in China) and got a 502 from it. `llm-redact env` now prints `NO_PROXY=127.0.0.1,localhost` (merged with an existing `NO_PROXY`); README says why.
  - The first run inherited the environment and **Claude Code put the git user's real e-mail into the conversation** — llm-redact did replace it (the mock only saw a placeholder), but a test must not touch real identity: the smoke now gets an empty git config and a minimal environment.
  - The Codex provider block `llm-redact env codex` prints works exactly as printed (the smoke uses that very config).
  - Per-run values to ignore when comparing: Claude Code's `cch=` billing hash in system block 0 and `metadata.user_id`; Codex's `prompt_cache_key`.
- [x] **Throughput.** A synthetic 5.3 MB agent conversation (200 tool results of code, logs, JSON in strings) redacts in ~290 ms; the escaped-text pass costs 2.6× the plain scan. Agents re-send the whole history every turn, so the proxy now keeps a bounded LRU cache of results for long texts (≥ 1 KB, 32 M chars in total, in memory only): the next turn takes **3 ms**.
- [x] **Windows key/token permissions.** `%APPDATA%` here is also readable by a `CodexSandboxUsers` group — "it is in your profile" is not a guarantee. Key and token are now written through `writePrivate`: created empty, inherited ACL replaced by one granting only the current account's SID (`icacls /inheritance:r /grant:r *SID:F`), then filled. Test checks there is exactly one, non-inherited ACL entry (POSIX: mode 600).
- [x] `test/cli.test.ts`: `env` output (token, NO_PROXY merge, PowerShell, existing gateway), owner-only files, cache equivalence/copies/bounds. 143 tests.
- [x] **Second independent leak review** (fresh reviewer, focused on round 1's changes): **20 findings, 19 reproduced**, all fixed. The pattern this time: round 1's fixes were right in spirit but each had a hole.
  - *Re-encode-and-search* for escaped text missed every serializer that escapes differently from `JSON.stringify` (Go `&`, .NET `+`, Python `ä`) — **and was quadratic** (0.8 MB: 13 s). Replaced by decoded views that carry an offset map back to the original: a value is replaced at its span, whatever its spelling; one linear pass. Same mechanism now covers HTML entities, percent-encoding and CSV quotes.
  - "Leave settings alone" also left `prediction` (Predicted Outputs: the whole file being rewritten) and `metadata` alone. "Leave signed blocks alone" skipped anything merely *called* thinking. "Skip data: URLs / base64" skipped strings that only *started* like one.
  - The silent caps of round 1 (100k values, 2M attempts) **failed open**: everything after them went out. Now a refusal (413); overlap checks are binary searches instead of a scan (100k values: 9.7 s → 0.3 s).
  - Placeholders the model wrote, sent back in the next request, were redacted again into nested placeholders — the `]]` guard ran after `trimEnd` had removed the brackets. Placeholders are now pre-taken spans for every detector.
  - Numbers: never visited (a card number as a JSON number went out), and re-serialising lost precision (`12345678901234567890`) and `__proto__` keys. Now `JSON.parse` with source text + `JSON.rawJSON` keeps every number exactly as written; long integers are checked.
  - Unknown APIs (Ollama, Gemini) got the Anthropic/OpenAI structure rules — `id`, `name`, `type` skipped — so their tool arguments leaked. Now walked as data.
  - Also: form bodies (`%40`), UTF-16 text, NDJSON responses broken by raw restore, labels depending on which rule saw a value first (placeholders changed across restarts), reasoning summaries restored in one event but not another, `Expect: 100-continue`, SSE parser rescanning a 16 MB event per chunk (1.9 s → 23 ms) and ignoring CR-only line ends.
  - Kept deliberately (documented): tool definitions and output schemas, `stop`, `safety_identifier`, signed blocks, binary files.
- [x] **Mutation check of the regression tests**: each of 15 fixes undone once in a copy of the code; the first run showed **two tests that tested nothing** — a label test passing because the shared vault remembered an earlier label, and a form test passing because the new percent view caught the case on its own path. Both rewritten; now every mutation is caught.
- [x] Precision corpus after all this: unchanged on external repositories except three real-shaped test tokens under bare `TOKEN` names (now in scope by design); `pass_rate` and f-strings fixed after the first rerun showed them.
- [x] Smoke with the real Claude Code and Codex after the walker rewrite: both still byte-identical.

167 tests (was 135).

## Round 3 — done (v0.4.0)

- [x] **Vault memory is bounded** (200,000 values, least recently used out first; every lookup refreshes). Forgetting is safe because each request carries the conversation's values again and the placeholder is an HMAC of the value. One trap found while doing it: the redaction cache returns a stored result *without* asking the vault, so a cached text could carry a placeholder the vault had forgotten — and the response could not be restored. Cache entries now keep their (label, value) pairs and put them back on a hit (and are discarded if a value would now get a different placeholder).
- [x] **ECONNRESET between turns.** The suite failed once in a full run, never alone: the test before took over 5 s, Node's server closed the idle keep-alive connection exactly as the client reused it, and a POST is not retried. Agents are idle between turns all the time — this would have been a real intermittent failure. The proxy now keeps idle connections for 65 s (longer than clients do, so they close first).
- [x] **Old-Node fallback** exercised: the suite also runs with `JSON.rawJSON` removed (a preload, `test/fixtures/no-rawjson.mjs`) — everything passes except exact-number preservation, which is skipped with a reason. CI runs that, and a new job runs the built package on Node 22.15.0 (the minimum promised).
- [x] **`scan --body request.json`**: which fields of an API request would change and what was found in each (`--api`, `--json`), with `docs/example-request.json` to try. Also fixed: `scan --json` reported line 1 for values found in an encoded form (position −1).
- [x] **First-run and error paths** walked through by hand: `scan` on a missing file or a directory printed a Node stack trace (now one line, exit 1); unknown commands and detectors now suggest the near miss (`scna` -> `scan`, `emial` -> `email`); the last non-ASCII characters in console output (help header, port-in-use message) replaced, as round 1 did for the rest (a non-UTF-8 Windows console garbles them). Port in use, bad port, bad `--upstream`, unknown option/client/shell were already clear.
- [x] **Third independent review, response side only**: 20 findings, 19 reproduced, all fixed. The stream restorer itself held (the reviewer's own property test: 48,000 runs, no failure); the problems were around it:
  - **Critical, and on the boundary of both sides: restored values went back in clear.** A value found by its *context* (`DB_PASSWORD=`) is restored where the model wrote its placeholder — `psql -W <value>` — and next turn the client's history carries the bare value where no pattern sees it. Two earlier reviews of the request side could not find this: it needs a response first. Fix: context-found values are remembered (8+ characters, 5,000 most recent, LRU) and matched first — as one alternation regex, which measured 94 ms for 5,000 values over 5 MB (a prefix map was slower) — in the text and every decoded view, keeping their placeholder; a text that teaches a value is redacted once more; cached results are checked against values learned since.
  - Formats and events not restored: Gemini text split across events, legacy completions `choices[].text`, Responses refusals / MCP arguments / annotations / `error`, Anthropic citations, MCP and server tool blocks.
  - Held-back text lost when the terminator never came (an error event, no `.done`); inserted tail events duplicating `id:` and `sequence_number`; a Chat flush chunk repeating `usage`.
  - Numbers re-serialised lossily in every response (the request side had `parseJson` since 0.3.0; the response side still used `JSON.parse`).
  - Unbounded memory: SSE events, NDJSON lines and JSON bodies with no limit, writes ignoring backpressure; NDJSON buffering quadratic (8 MB: 16 s → 18 ms).
  - Reasoning restored on some paths and not others (Responses `reasoning_text` parts, OpenRouter `reasoning.summary`, unsigned Anthropic thinking, signed NDJSON lines) — now never, anywhere.
  - Headers: one `Set-Cookie` of several, HEAD losing its length, an undecodable content-encoding stripped from still-encoded bytes; untyped JSON and `text/*` not restored.
- [x] **The CR-only end-of-stream bug found while re-running the reviewer's property test**: with CR line endings the last event ends in `\r\r` at the very end of the stream; the parser rightly waits in case the CR is half a CRLF — and then handed the complete event back as raw bytes, unrestored. `end()` now returns the events that turn out complete plus the genuinely incomplete rest.
- [x] **`test/fuzz.test.ts`**: a seeded property test of every streamed format (Anthropic text / tool JSON / cut by an error, Chat text / interleaved n=2 tool calls, legacy completions, Responses text with increasing sequence numbers / arguments, Gemini, NDJSON) × random texts (placeholders, near-placeholders, quotes, backslashes, newlines, U+2028, emoji, NUL) × random deltas × random line endings × random network chunks; every output must re-parse as SSE. 4,000 cases per run.
- [x] **Mutation check**: 24 fixes undone one at a time; the first run showed two that no test noticed (numbers in *streamed* events; usage copied into a flush chunk, which only happens when a stream is cut before `finish_reason`). Tests added; all 24 caught.
- [x] Smoke with the real Claude Code and Codex: still byte-identical.
- Not claimed: Codex with a ChatGPT login (`requires_openai_auth`, upstream `chatgpt.com/backend-api/codex`) — cannot be checked without a real login.

172 tests.

## Round 4 — backlog

- A fourth review with a different angle: the proxy as a whole under real client traffic patterns (long sessions, many turns, compaction, parallel agents on one proxy) — memory over hours, cache hit rates, vault churn.
- `scan --body` for responses too (what would be restored, where).
- Measure the known-value pass on a long real-shaped session (5,000 remembered values × every request).
- Codex with a ChatGPT login (`requires_openai_auth`) — still not claimed.
