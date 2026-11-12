---
name: llm-redact
description: Keep API keys, passwords, tokens and personal data out of AI requests with llm-redact. Use before reading or sharing a file that may hold secrets (.env files, configs, logs, request dumps, stack traces), when the user asks whether a file contains secrets, or when they want their AI agent's requests redacted before they leave the machine.
license: MIT
compatibility: Needs Node 22.15+ on the machine. Runs llm-redact with npx from GitHub (github:zch6a/llm-redact) unless an llm-redact command is installed. Local only.
metadata:
  homepage: https://github.com/zch6a/llm-redact
---

# Keeping secrets out of AI requests with llm-redact

llm-redact finds secrets (API keys, tokens, private keys, passwords in URLs and more) and personal data in text and
replaces each with a stable placeholder such as `[[REDACTED:anthropic_key:4d2bf65d]]`. It runs locally.

## Reading a file that may hold secrets

Whatever you read becomes part of this conversation and is sent to the model's API. For a file that is likely to
contain secrets, read it through llm-redact instead of opening it directly:

```bash
npx -y github:zch6a/llm-redact scan .env
```

Use `llm-redact` instead of `npx -y github:zch6a/llm-redact` if the command is installed. It prints the file with
each secret replaced by a placeholder, then a summary line such as `2 value(s) would be redacted: url_password x1
anthropic_key x1`. Work with the placeholders: refer to a secret by its line and kind, never try to recover the real
value, and when a value has to change, tell the user which line and let them edit it.

To answer "does this file contain secrets?" without its content, use the JSON form: `{summary, hits}`, each hit
with `detector`, `kind` (`secret` or `pii`), `line` and `placeholder`, never the value:

```bash
npx -y github:zch6a/llm-redact scan .env --json
```

## Which fields of an API request would change

```bash
npx -y github:zch6a/llm-redact scan --body request.json
```

## Redacting an agent's requests (the proxy)

llm-redact can sit between the user's agent and its API: requests are redacted before they leave the machine and
responses are restored before the agent sees them. This changes how the user's agent connects, so explain it and
ask before setting anything. What to set, for a client and a shell:

```bash
npx -y github:zch6a/llm-redact env claude --shell bash
```

Clients: `claude`, `codex`, `openai`, `deepseek`; shells: `bash`, `zsh`, `fish`, `powershell`, `cmd`. The proxy itself
(`llm-redact start`) keeps running: the user starts it in a terminal of their own. Do not change their shell profile
without asking.

## What is detected

```bash
npx -y github:zch6a/llm-redact detectors
```

Detection is pattern-based: it catches known key formats, credentials in URLs and similar, not every secret. Say so
when the user relies on it.
