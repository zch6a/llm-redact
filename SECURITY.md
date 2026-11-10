# Security

llm-redact sees your secrets by design — that is the only way to keep them from the provider. So its own behaviour is part of the threat model.

## What it does with your data

- Listens on 127.0.0.1 only; rejects requests whose `Host` header is not loopback (DNS rebinding); sends no CORS headers.
- Keeps real values in memory only (the vault, and a bounded cache of redaction results for long texts that agents re-send every turn). It writes three files, all owner-only (mode 600 on POSIX; on Windows any inherited or explicit ACL is replaced by one granting only your account, and a warning is printed if that fails): a random 32-byte HMAC key that makes placeholders stable, created atomically and never overwritten; `remembered`, keyed hashes (HMAC, never values) of values found by their context, so they are still recognised after a restart; and with `--require-token` the access token. The key cannot be used to recover values, but with it someone who sees placeholders could test guesses for low-entropy values (a phone number), so it is kept private.
- Logs counts per detector, never request bodies, values or placeholders' values.
- Talks to nothing but the upstreams you configured. No telemetry.
- Has no runtime dependencies.
- Bounded memory: at most 200,000 values (least recently used forgotten first), a 32 M-character result cache, 5,000 remembered context-found values; responses are limited to the request body limit (default 64 MB) and written with backpressure, so a runaway upstream cannot exhaust memory.
- Fails closed: a body it cannot redact (invalid JSON, absurd nesting, a decompression bomb, an upload) is refused rather than forwarded, unless you start it with `--allow-unredacted`. Redirects that leave the upstream are refused (the client would re-send its unredacted body).
- A response restores only the placeholders its own request carried, with their values pinned when the request was redacted (for the Responses API also those of the response it continues, by `previous_response_id`). Another program on the machine, another agent on the same proxy, a placeholder planted in a file the agent reads, or a model guessing tags cannot get a value restored that the asking request did not already hold.
- A broken or mistyped config file is an error, not silently ignored (`{ "requireToken": true, }` must not turn the token off).

## What it does not protect against

- **Other local users and processes using the proxy.** They cannot get your values (see above), but they can send their own requests through it. On shared machines start with `--require-token`: requests must then carry a random 128-bit token as the first path segment (compared in constant time; stored next to the key, owner-only).
- **A prompt-injected agent.** Placeholders the model writes are restored before your client sees them — by design, so commands and files get real values. An agent steered by injected instructions can therefore still use, and send out, a restored secret through its own tools. llm-redact keeps values from the provider; it is not a sandbox for the agent.
- **A model transforming a value on purpose.** The model is given placeholders, not values — but it can ask your tools to transform a restored value (hex-encode it, reverse it, split it) and the result goes back to the provider. llm-redact looks into the common encodings (JSON, HTML, percent, CSV, shell quoting, base64), not arbitrary transformations.
- **Shapes it does not know.** Detection is pattern-based; see the README's Limits.

## Reporting a vulnerability

Please report privately (GitHub → Security → "Report a vulnerability") rather than in a public issue if you find:

- a way for a value that a detector matches to reach the upstream anyway (a **leak**) — e.g. through a body format, an encoding, a field the walker skips;
- a way to make the proxy reveal values to anything other than the client that sent them;
- input that makes redaction hang (a stalled proxy blocks the agent).

Include a minimal synthetic example. Missed secret *shapes* and false positives are welcome as public issues.
