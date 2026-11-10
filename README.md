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

Your API key travels in headers, untouched — the provider needs it. Only request bodies are redacted.

## What is detected

| Secrets | Personal data |
|---|---|
| Anthropic, OpenAI / DeepSeek (`sk-…`), GitHub, GitLab, AWS, Google, Slack, Stripe, npm, Hugging Face, Telegram keys and tokens · Slack and Discord webhooks · JWTs · Bearer tokens · PEM private keys · passwords in URLs (`postgres://user:…@`) · values of `*_SECRET`, `*_TOKEN`, `*PASSWORD`, `*_API_KEY` (in text, `.env` files and JSON) | E-mail addresses · Chinese mobile numbers · Chinese ID numbers (check digit and birth date validated) · international phone numbers · payment cards (Luhn) · IBAN (mod 97) · US SSN · public IPv4 (opt-in) |

`llm-redact detectors` lists all of them. Turn any off with `--disable email,phone` (or a whole kind: `--disable pii`), and keep specific values with `--allow`.

What is **not** redacted on purpose: documentation placeholders (`your_api_key`, `${TOKEN}`, `<key>`, `changeme`), references (`process.env.X`, `os.environ[...]`), example domains and `noreply@` addresses, numbers that fail their checksum, commit hashes, UUIDs and timestamps.

## How it works

- **Stable placeholders.** `[[REDACTED:openai_key:a3aec50a]]` — the tag is an HMAC of the value with a random key created on first run (`~/.config/llm-redact/key`, or `%APPDATA%\llm-redact\key`). The same secret gets the same placeholder in every request and after restarts, so **the provider's prompt cache keeps hitting** and the conversation stays consistent for the model.
- **Values stay in memory.** After a restart the map refills by itself: your client resends its history, which contains the real values, and they are redacted again to the same placeholders.
- **Streaming.** A placeholder can be split across any number of streamed deltas (`[[RED` + `ACTED:op…`). The restorer holds back only a tail that could still become a placeholder — ordinary text is not delayed — and tool-call arguments stay valid JSON even when the restored value contains quotes or backslashes.
- **Signed blocks are left alone.** Anthropic thinking blocks and OpenAI encrypted reasoning are verified byte for byte by the provider; they are never modified in either direction.
- **The model is told.** When a request contains placeholders, one sentence is appended to the end of the system prompt explaining them (so it writes them verbatim instead of asking for the key). Appending at the end keeps cached prefixes intact. `--no-note` turns it off.

Supported wire formats: Anthropic Messages, OpenAI Chat Completions, OpenAI Responses — streamed and not. Anything else is passed through with a note in the log.

## Commands

| Command | |
|---|---|
| `llm-redact` / `llm-redact start` | Run the proxy (`-p 8787`) |
| `llm-redact env [claude\|codex\|openai\|deepseek]` | What to set, for `--shell bash\|zsh\|fish\|powershell\|cmd` |
| `llm-redact scan [file\|-]` | Preview what a file or paste would look like after redaction (`--json` for positions) |
| `llm-redact detectors` | List detectors |

Options: `--upstream name=url` (repeatable) · `--disable ids` · `--enable ids` · `--allow value` · `--no-note` · `--config file` · `-q`. A config file (`config.json` next to the key) takes the same settings: `{ "port": 8787, "upstreams": {}, "disable": [], "enable": [], "allow": [] }`.

The request log shows counts only — `POST /anthropic/v1/messages -> 200 1834ms  redacted openai_key x1 email x2` — never bodies or values.

## Security

- Listens on **127.0.0.1 only** and rejects requests whose `Host` is not loopback (no DNS rebinding from a web page). No CORS headers: a browser page cannot read its responses.
- Nothing is written to disk except the HMAC key (created with mode 600). No telemetry, no other network traffic than the upstream you configured.
- Zero runtime dependencies — the code that sees your secrets is the code in this repository.

## Limits — read this

- **Pattern-based.** A secret with no recognisable shape and no telling name around it (`hunter2` in the middle of a sentence) is not found. Names of people, addresses and free-text personal details are not detected. Use `scan` to see what your own files look like.
- **Bodies only.** Files the agent uploads as `multipart/form-data` and anything that is not JSON are passed through unchanged (the log says so).
- **Only what goes through the proxy.** Tools the agent runs itself (a web fetch, a `curl`) are outside it.
- The model sees placeholders, so it cannot reason about the *content* of a secret (e.g. "is this key for staging or production?"). That is the point.

## Requirements

Node.js 22.15+. No dependencies.

## License

[MIT](LICENSE)
