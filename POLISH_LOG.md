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
  - *Re-encode-and-search* for escaped text missed every serializer that escapes differently from `JSON.stringify` (Go `\u0026`, .NET `\u002B`, Python `\u00e4`) — **and was quadratic** (0.8 MB: 13 s). Replaced by decoded views that carry an offset map back to the original: a value is replaced at its span, whatever its spelling; one linear pass. Same mechanism now covers HTML entities, percent-encoding and CSV quotes.
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

## Round 4 — done (v0.5.0)

- [x] **Soak test** (`scripts/soak.ts`, `npm run soak`): concurrent agents on one proxy, each sending its whole growing history every turn, tool results of ~20 KB with new secrets every third turn (one by shape, one only by context), a mock model echoing placeholders in prose and in `psql -W …` commands (so restored values come back in the next history), and compaction every 50 turns into a summary quoting restored values in prose. Every upstream body is checked against **every** agent's secrets. 4 agents × 600 turns (2,400 requests, 1.2 GB upstream, 1,600 secrets): **0 leaks, 0 placeholders at the client**; latency flat over the whole run (p50 30 ms for 0.5 MB requests, 63 ms for 1 MB); live heap after GC levels off at ~60 MB (the result cache reaching its bound); RSS 350–440 MB is transient allocation for parsing 1 MB bodies, not retention.
- [x] **Known-value pass at scale**: a cold 6.5 MB request costs 317 ms with no remembered values, 681 ms with 5,000. Most remembered values are made only of characters no encoding changes; such a value can be in a decoded view only if it is in the text itself, so views skip the known-value search when the text has none and all known values are plain: 5,000 values now 549 ms (100 values: +44 ms). A value with a quote or backslash keeps the views searched (test + mutation check). Repeat turns hit the cache either way (8–9 ms).
- [x] **Fourth independent review — the system over time** (cross-turn leaks, concurrency, placeholder integrity, config and lifecycle): 16 findings, all reproduced, all fixed.
  - **Two high**: a restored value aged out of the 5,000-value memory — a lookup never refreshed it, and a flood of other context-found values (a log of bearer tokens) pushed it out, after which it went out in clear every turn; and after a restart the memory was empty, so a value whose context had been compacted away was unknown. Fix, in two parts: values that were *restored* are kept in a memory of their own (only a restored value can come back without its context — a token in a log never restored only ever returns with its `Bearer`), refreshed on use; and remembered values are persisted as keyed hashes (`remembered`, HMAC only, never a value) and matched against tokens of the first requests after a restart.
  - A plain LRU was not enough, and the first test showed it: with a working set of 5,002 values and a cap of 5,000, the password and a flood token kept evicting each other on every turn. Keeping restored values apart is what fixes it, not a bigger cap.
  - **Design: any client could get any value in the shared vault restored** — by guessing tags (1,000,000 guesses in one 30 MB request: 6 real addresses), across sessions, or by a placeholder planted in a file the agent reads. Now a response restores only the placeholders its own request's redaction produced, with values pinned (Responses API: plus those of the response it continues). Same probe after the fix: 0. It also fixes a stream losing a value evicted from the vault mid-response.
  - Also: a bare value before its context within one request (re-walk); short URL passwords not remembered (now 4–7 characters as whole words); base64 (`Authorization: Basic` from `curl -v`); percent-encoding of any character; shell / Python quoting; the cache reused when a newly learned value was in it encoded; a broken config silently dropping `requireToken`; ACL failures silent; explicit ACL entries kept on rewrite; non-atomic key creation (three processes starting at once ended with different keys in 10/10 runs — now 0/10); a corrupt key overwritten; the token in the internal-error log line.
  - Kept as limits (documented): values wrapped across lines, reformatted, or deliberately transformed by the model.
- [x] **Mutation check**: 18 fixes undone one at a time; the first run left **5 surviving** — a scope that did not mark restored values (tests restored through the vault, never through a response scope), recency refresh (no test needed it once restored values were kept apart — but a user-written bare value still does), a percent test that a `pw=` name rule caught by itself, a token test that never hit the internal-error path, and an `icacls /reset` that turned out redundant (writePrivate renames a fresh temporary file over the target, so the ACL is replaced anyway — removed). Tests rewritten, the redundant code removed; a sixth, the new cache shortcut, survived once because 1,100 `x` counted as a base64 token — fixed by sharing the base64 heuristic. All caught.
- [x] Docs: the README showed `&`, `+`, `ä` where it meant the escapes `\u0026`, `\u002B`, `\u00e4` — the Edit tool had decoded them in an earlier round (CHANGELOG and this log too). Fixed with a script that builds the backslashes from char codes, and every doc checked for stray control characters.

222 tests (was 204).

## Round 5 — done (v1.0.0): the last round of the first cycle

- [x] **The latency rise, profiled** (CPU profile of a warm 1.3 MB request in a growing history): a third of the time was one tiny regex, `[A-Za-z0-9+/_-]{16}` — the base64 test added to cache validation in 0.5.0, run on every cached text whenever a turn learned a value; now recorded once per cache entry (learning turns 15.9 → 4.4 ms). `parseJson`'s reviver (exact numbers) cost a call per value — 50 ms instead of 7 ms on 1.4 MB of small fields; it now runs only when a number would change (10 ms). Soak, 1 MB requests: p50 back to 63–67 ms.
- [x] **Fifth independent review — "would you trust this with your keys?"** Verdict: ship after fixes. The ones that mattered:
  - **The proxy could stall for seconds** — every newly learned value rebuilt the remembered-value pattern for the next string, so a body with thousands of new values was quadratic: 2,000 messages with one bearer token each, 16 s, during which every agent on the (single-threaded) proxy waited; plus one `appendFileSync` per remembered value. The pattern is now frozen for each walk over a request (values learned during it are found by the second walk), the file written once per request: 67 ms. Measured before and after, and a timing test.
  - **~2% of random tokens slipped through** `looksReal`: a leading `-` (base64url, 1 in 64) was taken for a CLI flag, and mixed-case values were read as documentation placeholders (`a_OY3u…`, `…_MY`) because the placeholder pattern and the example-word list were case-insensitive. Placeholder patterns now apply only to one-case values, a dash only to flag shapes. Measured on 4,000 random tokens per context: 75–93 → 1–3 missed. Measuring *again* for the README showed my "1 in 1,500" was about base64 tokens: letters-only random tokens are missed **1 in 13** (they look like identifiers, and the rule must not take `parentToolId` for a secret — three alternative tests traded one error for the other, see `ident5.mts`). Documented as measured.
  - Recall after a restart split tokens on `=` and `:` — a password containing one was never recalled. Form fields ignored their names (`password=…`). Placeholders a response could not restore reached the client unnoticed (now counted in the log line). A web page of another site could POST through the proxy (`Origin` now checked). Weakening settings were silent (now warned at every start, unredacted forwards always on stderr). Gemini signed thought parts and reasoning had two rules (streamed vs not) — now one written rule.
  - Outbound HTTP proxies: Node's `fetch` ignores `HTTPS_PROXY`. I tried to confirm that `NODE_USE_ENV_PROXY=1` fixes it and could not — so it is not claimed: a startup warning and a documented limit instead.
- [x] **Mutation check**: 21 fixes undone one at a time; the first run left 4 surviving, all for the same reason as before — the property test's random tokens rarely hit the exact shapes the review found, a test value (`xxx;Pool`) that was rejected for another reason, and no test of a base64 token in a cached text. Explicit tests for each; all 21 caught.
- [x] **A regression of my own, caught by the soak, not by the tests**: the stall fix freezes the pattern for a request's first walk, and the second walk redoes the texts that taught a value — but `RedactCache.set` kept an existing entry, so the stale first-walk result stayed and every text that ever taught a value was redone on every later request (1 MB requests: p50 165 ms instead of 65). `set` now replaces. The regression test I wrote for it first passed against the broken code too: its filler (`'x'.repeat(1200)`) was glued to `DB_PASSWORD`, making a 1,212-character name the rule rightly ignores, so nothing was learned at all — found by printing the cache's marks, not by guessing. With a newline in between it fails on the old code and passes on the new.
- [x] **Docs checked against runs**, not taken from the review: the README's "2 MB in about 100 ms / 250 ms" was 140 / 420 ms when measured, and is now stated so. Every claim in the new Performance, Restarts and upgrades, and Not supported sections was run or read in the code. Two more escapes decoded by the editing tool in an earlier round (a `redact.ts` header comment) fixed with a script.
- [x] **`docs/COMPATIBILITY.md`**: placeholders (grammar, HMAC truncation, collision suffix), labels, the note, files on disk (`remembered` now has a format header), config keys (a newer version's key warns, a typo errors), commands and exit codes, JSON outputs, error responses (one shape both SDKs read), routing, what a response restores. Not frozen: what is detected, encodings looked into, the log line, terminal output, limits.
- [x] The npm package now ships CHANGELOG, SECURITY and COMPATIBILITY (the README links to them).

235 tests (was 222). **First cycle complete for llm-redact: 5/5.**

## Inserted task — Agent Skill and presentation (v1.1.0)

- [x] **Agent Skill + Claude Code plugin** (`plugin/skills/llm-redact/SKILL.md`, a marketplace in the repository itself; `claude plugin validate` passes for both). The point for an assistant is not the proxy but `scan`: read a `.env`, config or log through `llm-redact scan` and only placeholders enter the conversation, even with no proxy running. `scan --json` answers "is there a secret in it?" with positions and kinds, never values. Setting up the proxy changes how the user's agent connects, so the skill has the assistant explain and ask first, and leave the long-running `start` to the user's own terminal.
- [x] **`test/skill.test.ts`**: the frontmatter (portable fields, limits), plugin and marketplace agree with the package version, every command in the skill's bash blocks run in order on synthetic secrets in a temp folder with its own config dirs, and none of the secrets appears in any output; the summary line the skill quotes is what `scan` prints; every client × shell the skill names is accepted by `env` (4 × 5 runs).
- [x] **README** (both languages): an "Ask your AI assistant" section. **Social preview** (`docs/social-preview.png`, from `scripts/social-card.html`): the example `.env` on your machine against what the provider receives. **Launch kit**: `launch/llm-redact.md` outside the repository (drafts; posting is the user's).

239 tests (was 235).

## Next cycle (after #4–#12)

- Codex with a ChatGPT login (`requires_openai_auth`, upstream `chatgpt.com/backend-api/codex`) — needs a real login to verify.
- An upstream proxy option (or a verified `NODE_USE_ENV_PROXY` recipe) for networks that only reach providers through an HTTP proxy.
- Recall cost after a restart (5,000 pending hashes: +280 ms on a cold 2 MB request): a length index of remembered values would cut the hashing.
- Letters-only random tokens (1 in 13 missed by the generic rule): a better identifier test that keeps real identifiers apart.
- The real run with the user's own Claude Code setup (needs their go-ahead: it spends tokens).

## Cycle 2, round 1 — 1.2.0 (2026-11-12)

The second cycle starts with an independent review, as for the other tools: someone who had not written it, on
synthetic data, with a mock upstream on 127.0.0.1, every home and config folder in a temp directory and the proxy
variables unset. It confirmed 11 problems by running them; I ran its scripts again against this working copy before
fixing anything, and after.

- **The leak.** A `NAME=value` inside a quoted string (`["DB_PASSWORD=…", …]` from docker inspect, `cmd = "export
  X=…"`, `['--password=…']`) kept its closing quote as part of the value: the agent got a wrong password back, and the
  vault remembered `value"`, so the bare password went out unredacted the next time it came without its name — the
  "once a secret, always a secret" promise failed exactly where it matters. The detector now cuts an unquoted value
  at the end of the quoted string around it (a small `trim` hook next to `trimEnd`).
- **Missed formats:** `redis://:password@host` (an empty user), keys and tokens ending in `-` (a fixed length then
  `\b`), `authorization: bearer` in other cases and the `Token`/`Basic` schemes, Rails' `SECRET_KEY_BASE` (the name
  rule rejected names ending in `base`), numeric HTML entities (the pre-check wanted one digit), 6–7 character
  passwords (they can never reach the entropy bar: three kinds of character instead).
- **Skipped as binary:** any base64-looking string under `data`/`file_data`/`b64_json`, which plain text often is.
  Now only real binary (valid base64 with a known file signature) is skipped; base64 of UTF-8 text is decoded,
  redacted and encoded again; the rest is text.
- **Forwarded unseen:** an undeclared non-UTF-8 body (UTF-16 as `text/plain`) — refused now — and a text document
  whose media type has parameters.
- **The proxy:** two patterns restarted at every position of a long run (1 s per MB; a 4 MB request held up every
  other agent for 30 s) — now under 0.3 s per MB, and the worst all-encodings case went from about 28 s to 5 s for
  4 MB; a client that stopped reading and disconnected left a handler waiting for `drain` forever; an empty token
  file turned `--require-token` off; `Proxy-Authorization` was forwarded and the provider's CORS headers passed back.
- **Output:** JSON parse errors quoted the input (possibly the end of a key) in `scan --body` and config errors; the
  startup warning about `HTTP_PROXY` was wrong under `NODE_USE_ENV_PROXY=1`.
- Two tests encoded the old behaviour and changed with it: a 7-character password was "not a secret" (now it is,
  and found again as a whole word, never inside a longer one), and a test used an `Authorization: Basic` header as
  text nothing recognised (Basic credentials are redacted on sight now, so it uses another header).
- Kept as documented limits: base64 wrapped at 76 columns (only the line with the key's prefix is caught), a
  passphrase of ordinary words, URL query strings (Gemini's API key travels there and must reach Google).
- **Engineering:** tests isolated from the real key and vault, with proxy variables cleared (`test/isolate.ts`); CI
  actions pinned to commits, no token in the checkout, no dependency scripts; a release workflow that packs, installs
  and runs the package (it must redact a sample) and attaches it.

Tests: 255 (was 242), the review's findings in `test/review2.test.ts`.
