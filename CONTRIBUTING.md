# Contributing

Two properties matter more than features: **nothing a detector matches may reach the upstream**, and **nothing that is not a secret may be changed** (a redacted commit hash breaks the agent's work).

## Setup

Development runs the TypeScript sources directly (Node.js 22.18+ or 24; on 22.15–22.17 add `--experimental-strip-types`). The published package is plain JavaScript and runs on 22.15+.

```bash
npm install
npm run dev -- scan some-file.txt   # preview redaction
npm run dev                          # run the proxy from source
npm test
npm run check                        # type-check (src, tests) + tests
```

## Layout

```
src/
  detectors.ts  what is detected: patterns, validators (Luhn, ID check digit, IBAN), placeholder filters
  redact.ts     find values (overlaps resolved, earlier detector wins) and replace them
  vault.ts      HMAC placeholders, value map, the local key
  stream.ts     restore placeholders in text that arrives in pieces
  body.ts       walk Anthropic / OpenAI Chat / OpenAI Responses bodies (what to redact, what never to touch)
  sse.ts        server-sent events: parse, restore per block / choice / item, re-serialise
  proxy.ts      the HTTP proxy
  cli.ts        start, env, scan, detectors
test/
  core.test.ts  detectors (recall and precision), vault, stream restorer (every split point)
  proxy.test.ts end to end through a mock upstream for all three APIs, streamed and not
```

## Adding a detector

1. Add it to `DETECTORS` in `src/detectors.ts`: a `description`, a pattern with **bounded** quantifiers (request bodies are large; an unbounded pattern followed by a required literal backtracks), and a `validate` if the shape alone is ambiguous.
2. Put specific detectors before generic ones: where matches overlap, the earlier one wins.
3. Add a recall case and, more importantly, the most plausible *false positive* to `test/core.test.ts`.
4. If it is noisy in ordinary code, make it `optional`.

Never commit real keys or personal data as fixtures — build synthetic values (see `FAKE` in the tests).

## Adding a wire format

Extend `apiFor` (by request path), the request walker in `body.ts` (what is content, what is structure, what is signed), and the SSE restorer in `sse.ts`. Add a mock route in `test/proxy.test.ts`: the two invariants are checked there for every format.
