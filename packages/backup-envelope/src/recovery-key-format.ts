/**
 * How a recovery key is written down, and read back.
 *
 * `ccrk1` followed by the 32 secret bytes in base64url, in space-separated groups of four so it can
 * be read aloud and typed back. The prefix is version and recognition: if this ever needs a second
 * format, a pasted key says which it is.
 *
 * Groups are separated by SPACES, not dashes: base64url's own alphabet includes `-`, so a dash
 * separator could not be told from a character of the key — stripping the separators would silently
 * corrupt one key in a few, which is the worst possible failure for a string whose only job is to be
 * the last way in. Parsing therefore ignores whitespace and nothing else.
 *
 * It lives here rather than in the console because the console is no longer the only thing that
 * reads one: `npx @controlclaw/recover` takes the same string at a terminal prompt, and a second
 * implementation of this parser is the kind of thing that works for a year and then eats somebody's
 * only copy of their key.
 */

const PREFIX = "ccrk1";

function toBase64Url(b64: string): string {
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): string {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return b64 + "=".repeat((4 - (b64.length % 4)) % 4);
}

/** Groups of four, space separated: `ccrk1 a7Kd 9fQz …`. Awkward to mistype, easy to read back. */
export function formatRecoveryKey(secretKeyB64: string): string {
  const raw = toBase64Url(secretKeyB64);
  return `${PREFIX} ${(raw.match(/.{1,4}/g) ?? []).join(" ")}`;
}

/**
 * Forgiving about whitespace, the case of the prefix, a dash or underscore written after it, and
 * about what surrounds the key: the whole downloaded key file, or the line it was copied from, can
 * be pasted as is and only the `ccrk1 …` part is read. Strict about the key itself: whitespace is
 * the only thing removed from it, because every other printable character could be part of it.
 */
export function parseRecoveryKey(input: string): string {
  // The key with its prefix, wherever it sits in the text: 43 base64url characters, possibly
  // written in groups. Taken over the bare form below when both would match.
  const inText = new RegExp(`${PREFIX}[-_]?((?:\\s*[A-Za-z0-9_-]){43})(?![A-Za-z0-9_-])`, "i").exec(input);
  const grouped = inText?.[1];
  const raw = grouped !== undefined ? grouped.replace(/\s+/g, "") : input.replace(/\s+/g, "").replace(new RegExp(`^${PREFIX}[-_]?`, "i"), "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(raw)) {
    throw new Error("That does not look like a recovery key. It starts with ccrk1 and is a long string of letters and numbers.");
  }
  return fromBase64Url(raw);
}
