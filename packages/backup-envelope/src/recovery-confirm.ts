import { fromB64, sodiumReady, toB64, utf8 } from "./sodium";

/**
 * Confirming a firewall change with the recovery key, for when no channel can deliver the code
 * (T-99, `docs/security-design.md` § Confirming with the recovery key).
 *
 * A confirmation code is a secret the firewall hands to a person over one of the agents' channels.
 * When every agent that runs an approved channel is down, that path is gone, and so is every way to
 * confirm anything, including the update that would fix the agent. This is a second path for the
 * same secret: the firewall seals it to the organization's recovery key instead of sending it, and
 * the owner opens it with that key.
 *
 *   answer    = 16 characters from a 32-letter alphabet (80 bits), fresh per proposal
 *   plaintext = "controlclaw/recovery-confirm/v1\n" ‖ JSON { changeId, subject, summary, expiresAt, answer }
 *   challenge = crypto_box_seal(plaintext, recoveryPublicKey)          (X25519, the backups wrap key)
 *
 * The firewall keeps only a hash of the answer, exactly as it keeps a hash of a code, and checks it
 * the same way: single use, five tries, ten minutes. The answer fits the field a code travels in, so
 * the control plane relays it without knowing which of the two it is carrying.
 *
 * **Why the X25519 wrap key and not the Ed25519 signing half.** Every firewall that holds a recovery
 * key holds the wrap key; the signing half only exists on keys set or re-pasted since the offline
 * CLI (`recovery-identity.ts`), and the orgs that need this most are the ones that set a key once and
 * never came back to it.
 *
 * **The wrap key opens backups, so the opener is strict.** Anyone can seal to a public key, and the
 * same key opens every backup's wrapped data key. So `openRecoveryChallenge` returns the answer only
 * from a plaintext that starts with this file's context line and parses as exactly this JSON for the
 * change the caller asked about. A wrapped data key is 32 raw bytes and cannot pass that; a challenge
 * a control plane sealed itself carries an answer it already knew, which confirms nothing.
 */

/** Domain separation for what is sealed. Changing this string invalidates every open challenge. */
export const RECOVERY_CONFIRM_CONTEXT = "controlclaw/recovery-confirm/v1";

/** Crockford base32, lower case: no i, l, o or u, so a person reading it aloud cannot mix them up. */
const ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
export const RECOVERY_ANSWER_LENGTH = 16;

/** What a challenge says, for the page to show before the answer goes anywhere. */
export interface RecoveryChallengeBody {
  changeId: string;
  /** What is being changed, as the code message names it ("MJHBot", "your firewall"). */
  subject: string;
  /** The firewall's own words for the change, the same line a code message carries. */
  summary: string;
  /** ISO time the firewall stops accepting the answer. */
  expiresAt: string;
  answer: string;
}

/** A fresh answer: 80 bits, in the alphabet above. */
export async function makeRecoveryAnswer(): Promise<string> {
  const sodium = await sodiumReady();
  let out = "";
  for (let i = 0; i < RECOVERY_ANSWER_LENGTH; i++) out += ALPHABET[sodium.randombytes_uniform(ALPHABET.length)];
  return out;
}

/** The firewall's half: seal the challenge to the organization's recovery wrap key. */
export async function sealRecoveryChallenge(body: RecoveryChallengeBody, recoveryPublicKeyB64: string): Promise<string> {
  const sodium = await sodiumReady();
  const plain = utf8(`${RECOVERY_CONFIRM_CONTEXT}\n${JSON.stringify(body)}`);
  return toB64(sodium.crypto_box_seal(plain, fromB64(recoveryPublicKeyB64)));
}

function field(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  if (typeof v !== "string" || v.length === 0 || v.length > 2000) throw new Error("bad field");
  return v;
}

/**
 * The owner's half, in the browser or in `npx @controlclaw/recover answer`. Throws unless the
 * challenge opens with this key, carries this file's context, and is for `expectChangeId`.
 */
export async function openRecoveryChallenge(challengeB64: string, recoverySecretKeyB64: string, expectChangeId: string | null): Promise<RecoveryChallengeBody> {
  const sodium = await sodiumReady();
  let opened: Uint8Array;
  try {
    const secret = fromB64(recoverySecretKeyB64);
    opened = sodium.crypto_box_seal_open(fromB64(challengeB64), sodium.crypto_scalarmult_base(secret), secret);
  } catch {
    throw new Error("This recovery key cannot open this confirmation. Check it is your organization's current recovery key.");
  }
  const prefix = `${RECOVERY_CONFIRM_CONTEXT}\n`;
  let plain: string;
  try {
    plain = new TextDecoder("utf-8", { fatal: true }).decode(opened);
  } catch {
    plain = "";
  }
  if (!plain.startsWith(prefix)) throw new Error("That is not a confirmation from your firewall.");
  let body: RecoveryChallengeBody;
  try {
    const o = JSON.parse(plain.slice(prefix.length)) as Record<string, unknown>;
    body = { changeId: field(o, "changeId"), subject: field(o, "subject"), summary: field(o, "summary"), expiresAt: field(o, "expiresAt"), answer: field(o, "answer") };
  } catch {
    throw new Error("That is not a confirmation from your firewall.");
  }
  if (body.answer.length !== RECOVERY_ANSWER_LENGTH || [...body.answer].some((c) => !ALPHABET.includes(c))) {
    throw new Error("That is not a confirmation from your firewall.");
  }
  if (expectChangeId !== null && body.changeId !== expectChangeId) {
    throw new Error("This confirmation is for a different change. Close this dialog and start again.");
  }
  return body;
}
