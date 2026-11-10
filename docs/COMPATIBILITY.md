# Compatibility

From 1.0.0, llm-redact follows [Semantic Versioning](https://semver.org/). This page says what that covers — and what it deliberately does not, because a redactor that never changed what it finds would never get better.

## Stable within 1.x

| What | Promise |
|---|---|
| **Placeholders** | `[[REDACTED:<label>:<tag>]]`, where `<tag>` is the first 8 hex characters of HMAC-SHA256(key, value) — or, for the rare second value with the same tag, its first 6 followed by a 2-digit hex counter. The same key and value give the same placeholder in every 1.x version, so prompt caches and old conversations keep working across upgrades. |
| **Labels** | The detector ids (`llm-redact detectors`) are the labels inside placeholders and in the `remembered` file: an id always means the same kind of value and is never reused. New detectors add new ids. |
| **The note to the model** | The sentence appended to the system prompt does not change within 1.x (it is part of the cached prompt prefix). |
| **Files on disk** | In `~/.config/llm-redact` (`%APPDATA%\llm-redact` on Windows) or `$LLM_REDACT_HOME`: `key` (64 hex characters, never overwritten), `remembered` (a `# llm-redact remembered v1` header, then one `32-hex-HMAC<TAB>label` line per value), `token` (32 hex characters, with `--require-token`), `config.json`. A 1.x version reads what an earlier 1.x wrote. |
| **Config file** | The keys `port`, `upstreams`, `disable`, `enable`, `allow`, `note`, `requireToken`, `allowUnredacted`, `maxBody`, with their types. New keys may be added; a 1.x version given a key from a newer version warns and ignores it (a near-miss of a known key — a typo — is an error, so a misspelt `requireToken` cannot silently turn the token off). |
| **Commands, options, exit codes** | `start`, `env`, `scan`, `detectors`, `stats` and their options keep their meaning. Exit codes: `0` success, `1` failure (port in use, unreadable file, no proxy answering), `2` usage error. |
| **JSON output** | `scan --json`, `scan --body --json`, `stats --json` and the status page (`GET /`): fields are only added, never renamed or removed. |
| **Error responses** | Errors from llm-redact itself are `{ "type": "error", "error": { "type": "…", "message": "llm-redact: …" } }` with statuses 400 (not JSON), 403 (not allowed: Host, Origin, token), 404 (unknown upstream), 413 (too large or too deep), 415 (cannot be redacted), 500 (internal), 502 (upstream unreachable or misbehaving). The `error.type` values are those of the Anthropic API. |
| **Routing** | `http://127.0.0.1:<port>/[<token>/]<upstream>/<path>` → `<upstream URL>/<path>`; the default upstreams `anthropic`, `openai`, `deepseek`. |
| **What a response restores** | Only placeholders produced while redacting the request it answers (for the Responses API, also those of the response it continues by `previous_response_id`, while the proxy runs). |
| **Node.js** | Every Node.js LTS line from 22.15 on, on Windows, macOS and Linux. Dropping a Node version is a major change. |

## Not frozen (can change in a minor release)

- **What is found.** New detectors, better patterns, fewer false positives, more recall. A minor update can redact a value the previous version left — or leave one it redacted. Either changes that value's placeholder, which costs one prompt-cache miss; restoring keeps working because the client sends the value again. If you need identical requests across machines, pin the version (`npx llm-redact@1.2.3`).
- **Which encodings are looked into** (JSON escapes, HTML, percent, CSV, shell quoting, base64 — more may be added) and **which API fields** are walked as data or left alone, as providers add fields.
- **The request log line.** It is for people: `METHOD /upstream/path -> status time  redacted label xN …  unrestored N`; fields may be added. Counts only, never values — that part is a promise.
- **Terminal output** of `scan`, `env` comments, warnings and the startup banner. Parse the JSON outputs instead. (The variable assignments `env` prints are stable.)
- **Limits**: the vault and memory bounds, the cache size, timeouts.

## Deprecation

Anything in the stable list that has to change is first deprecated in a minor release — with a warning on stderr and a note in the CHANGELOG — and removed no earlier than the next major release.
