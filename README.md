<div align="center">

<img src="assets/banner.svg" alt="llm-redact — Your agent still writes the real key into `.env`. The model provider never sees it." width="100%">

<p>
<a href="https://github.com/zch6a/llm-redact/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zch6a/llm-redact/actions/workflows/ci.yml/badge.svg"></a>
<img alt="Node 22.15" src="https://img.shields.io/badge/node-%E2%89%A522.15-339933?logo=nodedotjs&logoColor=white">
<img alt="Zero dependencies" src="https://img.shields.io/badge/dependencies-0-2ea44f">
<img alt="OpenAI and Anthropic APIs" src="https://img.shields.io/badge/APIs-OpenAI%20%7C%20Anthropic-8a63d2">
<a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

**English** · [简体中文](README.zh-CN.md)

A local proxy between your AI coding agent and its model API. API keys, tokens, private keys and
personal data are replaced by placeholders before a request leaves your machine, and put back
before your agent reads the reply — in text, in tool calls, in streamed responses.

Claude Code · Codex · OpenCode · DeepSeek · any OpenAI- or Anthropic-compatible client

Local · Zero dependencies · No value ever written to disk

```bash
npx github:zch6a/llm-redact
```

</div>

---

## Why

Coding agents read everything: your `.env`, the config you pasted, the stack trace with a connection string, the customer e-mail in a test fixture. All of it is sent to the model provider — and may be logged, retained or used for abuse monitoring there.

You can try to keep secrets out of the context. Or you can make sure that whatever reaches the context, the real values never leave your machine.

## What it does

The agent asks the model to write a config file. This is what the **provider** receives (real output of `llm-redact scan docs/example.env.txt`):

```text
Please add these to my deployment config and check the database connects:

OPENAI_API_KEY=[[REDACTED:openai_key:a3aec50a]]
DATABASE_URL=postgres://app:[[REDACTED:url_password:1e808a61]]@db.internal:5432/prod
SESSION_TOKEN=[[REDACTED:jwt:e8ee0e1e]]
MAX_TOKENS=4096
LOG_LEVEL=info

If it fails, email [[REDACTED:email:c58c2eab]] or call [[REDACTED:cn_mobile:602543a6]].
```

The model answers with a tool call that writes `OPENAI_API_KEY=[[REDACTED:openai_key:a3aec50a]]` to `.env`. llm-redact turns the placeholder back into the real key on the way in, so **the file on your disk has the real key** — and the provider only ever saw the placeholder.

`MAX_TOKENS=4096` and `LOG_LEVEL=info` are left alone: redacting things that are not secret would break the agent's work, so precision is treated as seriously as recall.

## Quick start

```bash
npx github:zch6a/llm-redact          # listens on http://127.0.0.1:8787
npx github:zch6a/llm-redact env      # prints what to set for each client, for your shell
```

Then point your agent at it:

| Client | Setting |
|---|---|
| **Claude Code** | `ANTHROPIC_BASE_URL=http://127.0.0.1:8787/anthropic` |
| **OpenAI SDKs, OpenCode** and most OpenAI-compatible tools | `OPENAI_BASE_URL=http://127.0.0.1:8787/openai/v1` |
| **Codex** | a provider in `~/.codex/config.toml` with `base_url = "http://127.0.0.1:8787/openai/v1"` (`llm-redact env codex` prints it) |
| **DeepSeek** (OpenAI-compatible, e.g. DeepSeek Harness) | `OPENAI_BASE_URL=http://127.0.0.1:8787/deepseek/v1` |
| **DeepSeek through Claude Code** | `ANTHROPIC_BASE_URL=http://127.0.0.1:8787/deepseek/anthropic` |

Already using a gateway or relay? Chain it: `llm-redact --upstream anthropic=https://your-gateway`. `llm-redact env` notices an existing `ANTHROPIC_BASE_URL` and prints exactly that line.

Behind an HTTP proxy (`HTTPS_PROXY`, or a system-wide proxy — Codex uses the Windows one even for `127.0.0.1`)? Requests to llm-redact must bypass it, or they get a 502 from it: `llm-redact env` also prints `NO_PROXY=127.0.0.1,localhost`, keeping whatever your `NO_PROXY` already had.

Your API key travels in headers, untouched — the provider needs it. Only request bodies are redacted.

Tested end to end with the real **Claude Code 2.1** and **Codex 0.131** CLIs (`npm run smoke`, against a local mock: no tokens spent). Each sends a synthetic key and e-mail; the mock sees only placeholders, the CLI prints the real values, and the proxied request is byte-for-byte what the CLI sent directly once placeholders and the note are undone.

## Ask your AI assistant

llm-redact comes with an Agent Skill. In Claude Code:

```text
/plugin marketplace add zch6a/llm-redact
/plugin install llm-redact@llm-redact
```

Then ask "is there anything secret in this `.env`?" or "read the deploy log and tell me why it fails". The skill has the
assistant read files likely to hold secrets through `llm-redact scan`, so it works with placeholders and the real values
never enter the conversation, even without the proxy running. Ask "redact my agent's requests" and it explains the
proxy and prints what to set for your shell; it changes nothing without asking. Assistants that read Agent Skills from
a folder: copy [`plugin/skills/llm-redact`](plugin/skills/llm-redact/SKILL.md) into theirs.

## What is detected

| Secrets | Personal data |
|---|---|
| Anthropic, OpenAI / DeepSeek (`sk-…`), GitHub, GitLab, AWS, Google, Slack, Stripe, npm, Hugging Face, Telegram keys and tokens · Slack and Discord webhooks · JWTs · Bearer tokens · PEM private keys · passwords in URLs (`postgres://user:…@`) · values of `*_SECRET`, `*_TOKEN`, `*PASSWORD`, `*_API_KEY` (in text, `.env` files and JSON) | E-mail addresses · Chinese mobile numbers · Chinese ID numbers (check digit and birth date validated) · international phone numbers · payment cards (Luhn) · IBAN (mod 97) · US SSN · public IPv4 (opt-in) |

`llm-redact detectors` lists all of them. Turn any off with `--disable email,phone` (or a whole kind: `--disable pii`), and keep specific values with `--allow`.

What is **not** redacted on purpose: documentation placeholders (`your_api_key`, `ghp_your_token`, `${TOKEN}`, `<key>`, `changeme`), references and code (`process.env.X`, `$API_KEY`, `config.token`, `getenv(…)`), token counts (`max_tokens=4096`), example domains and `noreply@` addresses, numbers that fail their checksum, commit hashes, UUIDs and timestamps.

Measured, not assumed: over 2,955 real files (five popular public skill repositories plus three code projects), the generic `NAME=value` rule went from 317 hits — almost all code and placeholders — to 25, all of them password-shaped example values. Each false-positive class found there is a test.

## How it works

- **Stable placeholders.** `[[REDACTED:openai_key:a3aec50a]]` — the tag is an HMAC of the value with a random key created on first run (`~/.config/llm-redact/key`, or `%APPDATA%\llm-redact\key`). The same secret gets the same placeholder in every request and after restarts, so **the provider's prompt cache keeps hitting** and the conversation stays consistent for the model.
- **Values stay in memory.** After a restart the map refills by itself: your client resends its history, which contains the real values, and they are redacted again to the same placeholders. The map is bounded (the 200,000 most recently used values); a forgotten value comes back with the next request that carries it.
- **Once a secret, always a secret.** A value found by its *context* — `DB_PASSWORD=…`, `Bearer …`, `postgres://user:…@` — is remembered and redacted wherever it appears later. That matters because restored values come back: the model writes the placeholder into `psql -W [[REDACTED:…]]`, you get the real password, and next turn your client sends that command back in its history, where no pattern would recognise the bare value. Values that were restored are kept apart from the rest, so a log full of tokens cannot push them out; values of 4–7 characters (a short URL password) are matched only as whole words. Across restarts they are remembered as keyed hashes (`remembered` next to the key — never a value), because by then their context may have been compacted away.
- **Base64 is looked into.** `curl -v` prints `Authorization: Basic …` with your restored password inside; a token whose decoded text holds a secret is replaced whole.
- **Streaming.** A placeholder can be split across any number of streamed deltas (`[[RED` + `ACTED:op…`). The restorer holds back only a tail that could still become a placeholder — ordinary text is not delayed — and tool-call arguments stay valid JSON even when the restored value contains quotes or backslashes.
- **Encoded text is searched too.** Tool results quote logs, configs and API responses, so text is also searched one and two levels down — JSON escapes in any spelling (`\"`, Go's `\u0026`, .NET's `\u002B`, Python's `\u00e4`), HTML entities, percent-encoding, CSV-doubled quotes, shell and Python quoting (`'\''`, `\'`) — and a value found there is replaced exactly where it sits. Card and phone numbers written as JSON numbers are found; other numbers are kept exactly as written (`12345678901234567890`, `1.10`). Placeholders already in a request (the model's own earlier output) are never redacted again.
- **Signed blocks are left alone.** Anthropic thinking blocks, OpenAI reasoning items (summaries included), OpenRouter reasoning details and Gemini parts with a thought signature are verified byte for byte by the provider (or must go back as they came); they are never modified in either direction, streamed or not. Plain reasoning *text* — DeepSeek's `reasoning_content`, Ollama's `thinking`, unsigned Gemini thoughts — is ordinary text, redacted and restored like any other.
- **The model is told.** When a request in a format it knows (Anthropic, Chat Completions, Responses) contains placeholders, one sentence is appended to the end of the system prompt explaining them (so it writes them verbatim instead of asking for the key). Appending at the end keeps cached prefixes intact. `--no-note` turns it off. Other formats (Ollama, Gemini) get no note: there is no system prompt llm-redact knows how to extend.

- **Fails closed.** A body it cannot redact is refused, never forwarded as it came: invalid JSON → 400; absurd nesting, a compressed body that inflates past the limit, or more than a million values in one text → 413; an upload, other binary body, or text in a charset other than UTF-8 → 415 (start with `--allow-unredacted` to forward those as they are; the log marks each one). Plain-text bodies are redacted as text, form bodies field by field. A redirect to anywhere but the same upstream is refused, because the client would re-send its original, unredacted body there.

Supported wire formats: Anthropic Messages (also through Vertex AI's `:streamRawPredict`), OpenAI Chat Completions, OpenAI Responses — streamed and not, including tool inputs, tool results, earlier tool-call arguments, Predicted Outputs and Codex's custom tools; text files sent as base64. Any other JSON API (Ollama, Gemini, …) is redacted generically — every string and object key — and its responses are restored: Gemini and legacy-completions streams, newline-delimited JSON streams (Ollama), and server-sent events on paths it does not know. Responses keep everything a direct connection would give — numbers exactly as written, every `Set-Cookie`, event ids and sequence numbers (an inserted event for held-back text gets the next number; later ones move up), and a stream that ends without its usual terminator still delivers every character. Sizes are bounded by `--max-body` (64 MB by default): a request body, a non-streamed response body, and each single event or line of a streamed one (a stream as a whole may run as long as it likes) — an upstream that never stops an event is cut off, not buffered.

Left as they are, on purpose: **tool definitions and output schemas** (written by the client, like its code, and kept byte-stable for the prompt cache), request settings (`stop`, `safety_identifier`, `mcp_servers`), signed blocks, and binary files (images, PDFs).

## Commands

| Command | |
|---|---|
| `llm-redact` / `llm-redact start` | Run the proxy (`-p 8787`) |
| `llm-redact env [claude\|codex\|openai\|deepseek]` | What to set, for `--shell bash\|zsh\|fish\|powershell\|cmd` |
| `llm-redact scan [file\|-]` | Preview what a file or paste would look like after redaction (`--json` for positions) |
| `llm-redact scan --body request.json` | Which fields of an API request would change, and what was found in each (`--api` to set the format, `--json`) — try it on [docs/example-request.json](docs/example-request.json) |
| `llm-redact detectors` | List detectors |
| `llm-redact stats` | What a running proxy has redacted so far (counts only) |

Options: `--upstream name=url` (repeatable) · `--disable ids` · `--enable ids` · `--allow value` · `--no-note` · `--require-token` · `--allow-unredacted` · `--max-body MB` · `--config file` · `-q`. A config file (`config.json` next to the key) takes the same settings: `{ "port": 8787, "upstreams": {}, "disable": [], "enable": [], "allow": [], "note": true, "requireToken": false, "allowUnredacted": false, "maxBody": 64 }`. A broken file, a setting of the wrong type or a near-miss name (`requireTokn`) is an error; an unknown name is a warning (a setting of a newer version). The files live in `~/.config/llm-redact` (`%APPDATA%\llm-redact` on Windows), or in `$LLM_REDACT_HOME` if that is set.

Settings that weaken protection — `--allow-unredacted`, turned-off detectors, `--allow` values, and an `HTTPS_PROXY` it cannot use — are printed as warnings at every start, and every body forwarded unredacted is reported on stderr, also with `-q`.

The request log shows counts only — `POST /anthropic/v1/messages -> 200 1834ms  redacted openai_key x1 email x2` — never bodies or values. `unrestored 2` at the end of a line means the response held placeholders its request did not carry; they reached the client as they are (see Restarts below).

Errors from llm-redact itself have the shape both SDKs read, `{ "type": "error", "error": { "type": "invalid_request_error", "message": "llm-redact: …" } }`, with the status saying what happened: 400 not JSON, 403 not allowed, 413 too large or too deep, 415 cannot be redacted, 502 the upstream could not be reached or answered badly.

## Performance

Redaction runs in the proxy's single thread, so a request being redacted delays the others for that long. A new 2 MB request takes about 140 ms (about 420 ms while 5,000 values remembered from before a restart are still waiting to be matched); everything an agent sends again next turn comes from a cache, so a 1 MB request of a running session costs a few milliseconds. Measured with `npm run soak` (four agents, hundreds of turns: flat latency, ~60 MB of live memory).

## Restarts and upgrades

- The key and the `remembered` hashes survive a restart: placeholders stay the same, so prompt caches keep hitting, and remembered values are recognised again.
- The cache, the in-memory values and the per-response scopes do not. Values come back with the next request that carries them. A Responses API conversation continued with `previous_response_id` across a restart — or one that keeps its history on the server (`conversation`) — gets placeholders it can no longer restore: they are passed through as they are and counted (`unrestored`) in the log.
- A new version that detects more (or less) changes the placeholders of the values concerned: one prompt-cache miss.

## Security

- Listens on **127.0.0.1 only** and rejects requests whose `Host` is not loopback (no DNS rebinding from a web page). No CORS headers: a browser page cannot read its responses.
- **A response restores only its own request's placeholders.** The values pinned for a response are those its request carried (for the Responses API, also those of the response it continues). So nothing — another program on this machine, another agent on the same proxy, a placeholder planted in a file the agent reads, a model guessing tags — can get a value restored that the asking request did not already hold.
- **`--require-token`** makes the proxy answer only under a random path token (`http://127.0.0.1:8787/<token>/anthropic`; `llm-redact env` prints the URL with it) — so other programs on a shared machine cannot use it at all.
- Nothing is written to disk except the HMAC key, the keyed hashes of remembered values, and with `--require-token` the token — all readable by you only, created atomically and never overwritten if a key is already there (mode 600; on Windows the inherited ACL is replaced by one granting only your account, since a profile folder can be readable by other accounts such as sandbox groups). No telemetry, no other network traffic than the upstream you configured.
- Zero runtime dependencies — the code that sees your secrets is the code in this repository.

## Limits — read this

- **Pattern-based.** A secret with no recognisable shape and no telling name around it (`hunter2` in the middle of a sentence) is not found — unless it was seen earlier with its name: remembered values are found anywhere. A value that is *changed* on the way is not: wrapped across lines (`base64` output wrapped at 76 columns: only the line that holds the key's prefix is caught), reformatted (a phone number printed another way), or transformed on purpose (hex, reversed, split) — the model can always do that to a value it was given, and llm-redact looks only into the common encodings (JSON, HTML, percent, CSV, shell quoting, base64). Names of people, addresses and free-text personal details are not detected, nor a passphrase of ordinary words (`DB_PASSWORD="correct horse battery staple"`: telling it from a sentence is guesswork). URL query strings are forwarded as they are (Gemini sends your API key there, and Google must get it). Use `scan` to see what your own files look like.
- **Uploads and binary files are not redacted.** Bodies sent as `multipart/form-data` are refused unless you pass `--allow-unredacted`, in which case they go out as they are. Images and PDFs inside a request are passed through (text files sent as base64 are redacted).
- **Tool definitions are not redacted.** A key pasted into an MCP server's tool description goes out with it.
- **Responses typed `application/json` are read whole** before they are restored (a stream mislabelled that way arrives at once at the end).
- **Not supported:** WebSocket transports (a client that talks to the provider over a WebSocket does not go through the proxy's redaction). llm-redact connects to the upstream **directly**: Node's `fetch` does not use `HTTPS_PROXY` (unless you set `NODE_USE_ENV_PROXY=1` on Node 24, and then the already redacted requests go through that proxy, which the startup warning says), so if the provider is only reachable through an HTTP proxy, requests fail (502). A non-streamed request that takes more than 5 minutes before the provider answers is cut off by Node's `fetch` — stream long requests.
- **Tokens made only of letters** can look like identifiers (`ForgotPassword`), which the generic `NAME=value` rule must not take for secrets: a random letters-only token is missed about one time in 13. A random token of 20+ characters almost always has a digit or a symbol, so overall about 1 random base64 token in 1,500 is missed; provider keys (`sk-…`, `ghp_…`, …) are found by their shape whatever they contain.
- **Only what goes through the proxy.** Tools the agent runs itself (a web fetch, a `curl`) are outside it.
- **Placeholders are restored on your side — for whatever wrote them.** That is the design: the model writes `[[REDACTED:…]]` into a command or file and the real value lands on your machine. It also means an agent that has been prompt-injected (by a web page, a README, a tool result) can still be steered into using a restored secret — say, a `curl` that sends it somewhere. llm-redact keeps values away from the *provider*; it does not make an agent safe to run with secrets in reach.
- The model sees placeholders, so it cannot reason about the *content* of a secret (e.g. "is this key for staging or production?"). That is the point.

## Compatibility

From 1.0, placeholders, labels, files on disk, config keys, flags, exit codes, JSON outputs and error responses are stable within 1.x — see [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) for exactly what is promised and what (what is detected, the log line) may improve in a minor release.

## Requirements

Node.js 22.15+. No dependencies.

## License

[MIT](LICENSE)
