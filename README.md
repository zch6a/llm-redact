<div align="center">

# 🫥 llm-redact

**Your agent still writes the real key into `.env`. The model provider never sees it.**

A local proxy between your AI coding agent and its model API. API keys, tokens, private keys and
personal data are replaced by placeholders before a request leaves your machine, and put back
before your agent reads the reply — in text, in tool calls, in streamed responses.

Claude Code · Codex · OpenCode · DeepSeek · any OpenAI- or Anthropic-compatible client

Local · Zero dependencies · Nothing stored but a random key

[English](README.md) · [简体中文](README.zh-CN.md)

```bash
npx llm-redact
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
STRIPE_SECRET=[[REDACTED:stripe_key:f1350c3c]]
MAX_TOKENS=4096
LOG_LEVEL=info

If it fails, email [[REDACTED:email:c58c2eab]] or call [[REDACTED:cn_mobile:602543a6]].
```

The model answers with a tool call that writes `OPENAI_API_KEY=[[REDACTED:openai_key:a3aec50a]]` to `.env`. llm-redact turns the placeholder back into the real key on the way in, so **the file on your disk has the real key** — and the provider only ever saw the placeholder.

`MAX_TOKENS=4096` and `LOG_LEVEL=info` are left alone: redacting things that are not secret would break the agent's work, so precision is treated as seriously as recall.

## Quick start

```bash
npx llm-redact          # listens on http://127.0.0.1:8787
npx llm-redact env      # prints what to set for each client, for your shell
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
- **Once a secret, always a secret.** A value found by its *context* — `DB_PASSWORD=…`, `Bearer …`, `postgres://user:…@` — is remembered and redacted wherever it appears later. That matters because restored values come back: the model writes the placeholder into `psql -W [[REDACTED:…]]`, you get the real password, and next turn your client sends that command back in its history, where no pattern would recognise the bare value.
- **Streaming.** A placeholder can be split across any number of streamed deltas (`[[RED` + `ACTED:op…`). The restorer holds back only a tail that could still become a placeholder — ordinary text is not delayed — and tool-call arguments stay valid JSON even when the restored value contains quotes or backslashes.
- **Encoded text is searched too.** Tool results quote logs, configs and API responses, so text is also searched one and two levels down — JSON escapes in any spelling (`\"`, Go's `&`, .NET's `+`, Python's `ä`), HTML entities, percent-encoding, CSV-doubled quotes — and a value found there is replaced exactly where it sits. Card and phone numbers written as JSON numbers are found; other numbers are kept exactly as written (`12345678901234567890`, `1.10`). Placeholders already in a request (the model's own earlier output) are never redacted again.
- **Signed blocks are left alone.** Anthropic thinking blocks with their signature and OpenAI / OpenRouter encrypted reasoning (summaries included) are verified byte for byte by the provider; they are never modified in either direction. Unsigned reasoning (DeepSeek's `reasoning_content`) is ordinary text.
- **The model is told.** When a request contains placeholders, one sentence is appended to the end of the system prompt explaining them (so it writes them verbatim instead of asking for the key). Appending at the end keeps cached prefixes intact. `--no-note` turns it off.

- **Fails closed.** A body it cannot redact is refused, never forwarded as it came: invalid JSON → 400; absurd nesting, a compressed body that inflates past the limit, or more than a million values in one text → 413; an upload, other binary body, or text in a charset other than UTF-8 → 415 (start with `--allow-unredacted` to forward those as they are; the log marks each one). Plain-text bodies are redacted as text, form bodies field by field. A redirect to anywhere but the same upstream is refused, because the client would re-send its original, unredacted body there.

Supported wire formats: Anthropic Messages (also through Vertex AI's `:streamRawPredict`), OpenAI Chat Completions, OpenAI Responses — streamed and not, including tool inputs, tool results, earlier tool-call arguments, Predicted Outputs and Codex's custom tools; text files sent as base64. Any other JSON API (Ollama, Gemini, …) is redacted generically — every string and object key — and its responses are restored: Gemini and legacy-completions streams, newline-delimited JSON streams (Ollama), and server-sent events on paths it does not know. Responses keep everything a direct connection would give — numbers exactly as written, every `Set-Cookie`, event ids and sequence numbers (an inserted event for held-back text gets the next number; later ones move up), and a stream that ends without its usual terminator still delivers every character. A response is limited to the request body limit (64 MB by default): an upstream that never stops is cut off, not buffered.

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

Options: `--upstream name=url` (repeatable) · `--disable ids` · `--enable ids` · `--allow value` · `--no-note` · `--require-token` · `--allow-unredacted` · `--config file` · `-q`. A config file (`config.json` next to the key) takes the same settings: `{ "port": 8787, "upstreams": {}, "disable": [], "enable": [], "allow": [], "requireToken": false, "allowUnredacted": false }`.

The request log shows counts only — `POST /anthropic/v1/messages -> 200 1834ms  redacted openai_key x1 email x2` — never bodies or values.

## Security

- Listens on **127.0.0.1 only** and rejects requests whose `Host` is not loopback (no DNS rebinding from a web page). No CORS headers: a browser page cannot read its responses.
- **On a machine with other users, use `--require-token`.** Any local process that can reach the port can ask the proxy to turn a placeholder it has seen back into its value (that is what the proxy does for responses). With the flag the proxy answers only under a random path token (`http://127.0.0.1:8787/<token>/anthropic`); `llm-redact env` prints the URL with it.
- Nothing is written to disk except the HMAC key and, with `--require-token`, the token — both readable by you only (mode 600; on Windows the inherited ACL is replaced by one granting only your account, since a profile folder can be readable by other accounts such as sandbox groups). No telemetry, no other network traffic than the upstream you configured.
- Zero runtime dependencies — the code that sees your secrets is the code in this repository.

## Limits — read this

- **Pattern-based.** A secret with no recognisable shape and no telling name around it (`hunter2` in the middle of a sentence) is not found — unless it was seen earlier with its name: remembered values (8 characters or more, the 5,000 most recent) are found anywhere. Names of people, addresses and free-text personal details are not detected. Use `scan` to see what your own files look like.
- **Uploads and binary files are not redacted.** Bodies sent as `multipart/form-data` are refused unless you pass `--allow-unredacted`, in which case they go out as they are. Images and PDFs inside a request are passed through (text files sent as base64 are redacted).
- **Tool definitions are not redacted.** A key pasted into an MCP server's tool description goes out with it.
- **Responses typed `application/json` are read whole** before they are restored (a stream mislabelled that way arrives at once at the end).
- **Only what goes through the proxy.** Tools the agent runs itself (a web fetch, a `curl`) are outside it.
- **Placeholders are restored on your side — for whatever wrote them.** That is the design: the model writes `[[REDACTED:…]]` into a command or file and the real value lands on your machine. It also means an agent that has been prompt-injected (by a web page, a README, a tool result) can still be steered into using a restored secret — say, a `curl` that sends it somewhere. llm-redact keeps values away from the *provider*; it does not make an agent safe to run with secrets in reach.
- The model sees placeholders, so it cannot reason about the *content* of a secret (e.g. "is this key for staging or production?"). That is the point.

## Requirements

Node.js 22.15+. No dependencies.

## License

[MIT](LICENSE)
