# Security

llm-redact sees your secrets by design — that is the only way to keep them from the provider. So its own behaviour is part of the threat model.

## What it does with your data

- Listens on 127.0.0.1 only; rejects requests whose `Host` header is not loopback (DNS rebinding); sends no CORS headers.
- Keeps real values in memory only. The one file it writes is a random 32-byte HMAC key (mode 600 on POSIX) used to make placeholders stable; the key cannot be used to recover values.
- Logs counts per detector, never request bodies, values or placeholders' values.
- Talks to nothing but the upstreams you configured. No telemetry.
- Has no runtime dependencies.

## Reporting a vulnerability

Please report privately (GitHub → Security → "Report a vulnerability") rather than in a public issue if you find:

- a way for a value that a detector matches to reach the upstream anyway (a **leak**) — e.g. through a body format, an encoding, a field the walker skips;
- a way to make the proxy reveal values to anything other than the client that sent them;
- input that makes redaction hang (a stalled proxy blocks the agent).

Include a minimal synthetic example. Missed secret *shapes* and false positives are welcome as public issues.
