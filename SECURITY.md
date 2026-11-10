# Security

llm-redact sees your secrets by design — that is the only way to keep them from the provider. So its own behaviour is part of the threat model.

## What it does with your data

- Listens on 127.0.0.1 only; rejects requests whose `Host` header is not loopback (DNS rebinding); sends no CORS headers.
- Keeps real values in memory only (the vault, and a bounded cache of redaction results for long texts that agents re-send every turn). The one file it writes is a random 32-byte HMAC key used to make placeholders stable (plus the access token with `--require-token`). Both are owner-only: mode 600 on POSIX; on Windows the inherited ACL is replaced by one granting only your account. The key cannot be used to recover values, but with it someone who sees placeholders could test guesses for low-entropy values (a phone number), so it is kept private.
- Logs counts per detector, never request bodies, values or placeholders' values.
- Talks to nothing but the upstreams you configured. No telemetry.
- Has no runtime dependencies.
- Fails closed: a body it cannot redact (invalid JSON, absurd nesting, a decompression bomb, an upload) is refused rather than forwarded, unless you start it with `--allow-unredacted`. Redirects that leave the upstream are refused (the client would re-send its unredacted body).

## What it does not protect against

- **Other local users and processes.** Anything that can reach the port can have a placeholder it has seen restored to its value. On shared machines start with `--require-token`: requests must then carry a random 128-bit token as the first path segment (compared in constant time; stored next to the key, mode 600).
- **A prompt-injected agent.** Placeholders the model writes are restored before your client sees them — by design, so commands and files get real values. An agent steered by injected instructions can therefore still use, and send out, a restored secret through its own tools. llm-redact keeps values from the provider; it is not a sandbox for the agent.
- **Shapes it does not know.** Detection is pattern-based; see the README's Limits.

## Reporting a vulnerability

Please report privately (GitHub → Security → "Report a vulnerability") rather than in a public issue if you find:

- a way for a value that a detector matches to reach the upstream anyway (a **leak**) — e.g. through a body format, an encoding, a field the walker skips;
- a way to make the proxy reveal values to anything other than the client that sent them;
- input that makes redaction hang (a stalled proxy blocks the agent).

Include a minimal synthetic example. Missed secret *shapes* and false positives are welcome as public issues.
