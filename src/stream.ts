/**
 * Restore placeholders in text that arrives in pieces (streamed model output).
 *
 * A placeholder can be split anywhere — "[[RED" in one delta, "ACTED:openai_key:3f9a1c2b]]" in
 * the next. The restorer emits text as soon as it is safe and holds back only a tail that could
 * still turn into a placeholder, so ordinary text (including "[[wiki links]]" or "a[i]") is not
 * delayed beyond the character that rules it out.
 */
import type { Vault } from './vault.ts';

const OPEN = '[[REDACTED:';
/** Longest possible placeholder: "[[REDACTED:" + 40-char label + ":" + 8 hex + "]]". */
const MAX = OPEN.length + 40 + 1 + 8 + 2;
const REST = /^[a-z0-9_]{0,40}(?::[0-9a-f]{0,8}(?:\]\]?)?)?$/;

/** Could `s` (which starts with "[") still grow into a placeholder? */
export function couldBePlaceholder(s: string): boolean {
  if (s.length <= OPEN.length) return OPEN.startsWith(s);
  return s.startsWith(OPEN) && REST.test(s.slice(OPEN.length));
}

export class StreamRestorer {
  private buf = '';
  private readonly vault: Vault;
  private readonly encode: (value: string) => string;
  /** `encode` turns a restored value into what the stream carries (e.g. JSON string escaping). */
  constructor(vault: Vault, encode: (value: string) => string = (v) => v) {
    this.vault = vault;
    this.encode = encode;
  }

  /** Add a piece; returns what can be emitted now (possibly ''). */
  push(chunk: string): string {
    this.buf += chunk;
    const hold = this.holdFrom();
    const ready = this.buf.slice(0, hold);
    this.buf = this.buf.slice(hold);
    return this.vault.restore(ready, this.encode);
  }

  /** End of stream: whatever is held back, restored (a dangling "[[RED" is emitted as is). */
  flush(): string {
    const out = this.vault.restore(this.buf, this.encode);
    this.buf = '';
    return out;
  }

  /** Index from which the buffer must be held back (buffer length = nothing to hold). */
  private holdFrom(): number {
    const b = this.buf;
    for (let i = Math.max(0, b.length - MAX); i < b.length; i++) {
      if (b.charCodeAt(i) !== 91 /* [ */) continue;
      const tail = b.slice(i);
      // A complete placeholder in the tail is restorable now; only an incomplete one is held.
      if (couldBePlaceholder(tail) && !/\]\]$/.test(tail)) return i;
    }
    return b.length;
  }
}
