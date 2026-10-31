/**
 * Reading a 6-digit confirmation code out of whatever the person typed or pasted.
 *
 * The firewall writes codes as "123 456" in its messages, and people copy them with the space, or
 * with a dash, or copy the whole message. Every code input runs its value through `extractCode` so
 * the separator is not taken as a digit and the code lands in full.
 */

export const CODE_LENGTH = 6;

/** "Code: 123 456" or "code 123-456": the label the firewall's messages use, then the code. */
const LABELLED = /code\s*:?\s*(\d{3})[\s\-‐-―.]?(\d{3})(?!\d)/i;
/** Three digits, an optional space, dash or dot, three digits, with no other digit touching it. */
const STANDALONE = /(?<!\d)(\d{3})[\s\-‐-―.]?(\d{3})(?!\d)/;

/**
 * The code in `text`, as at most `length` digits.
 *
 * A pasted message is read for its "Code:" line first, then for a lone 3+3 digit group, so the
 * digits in the summary above it (a version, a time) are not mistaken for the code. Anything else
 * keeps only its digits, the first `length` of them: typing "12 3" gives "123".
 */
export function extractCode(text: string, length: number = CODE_LENGTH): string {
  if (length === CODE_LENGTH) {
    const match = LABELLED.exec(text) ?? STANDALONE.exec(text);
    if (match) return match[1] + match[2];
  }
  return text.replace(/\D/g, "").slice(0, length);
}
