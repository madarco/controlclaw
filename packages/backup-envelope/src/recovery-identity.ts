import { fromB64, sodiumReady, toB64, utf8 } from "./sodium";
import { fingerprint } from "./envelope";

/**
 * How the owner's recovery key becomes a way to **talk to their firewall**, with ControlClaw out of
 * the path (`packages/recover`, `packages/mitm-agent/src/recovery.ts`).
 *
 * A recovery key is an X25519 secret: it can open a sealed data key and nothing else. X25519 cannot
 * sign, so a second keypair is needed — and asking an owner to keep two secrets would be a worse
 * feature than none. So the signing keypair is **derived from the same 32 bytes**:
 *
 *   seed    = blake2b-256( "controlclaw-recovery-sign/v1" ‖ recoverySecretKey )
 *   keypair = crypto_sign_seed_keypair(seed)                        (Ed25519)
 *
 * One secret, two keypairs, no new thing to lose. The derivation is one-way: the signing secret
 * gives nothing back about the X25519 secret, and the firewall only ever holds the two public
 * halves.
 *
 * **The public halves have to be told to the firewall, and that is the one thing the control plane
 * could lie about.** The X25519 half already travels that way (`backup.recovery.propose`, so the
 * firewall can wrap data keys to it); the Ed25519 half now rides along, and a rebuilt firewall is
 * sent both again (`backup.recovery.rebind`). A compromised control plane could substitute a pair
 * of its own and then drive the recovery routes itself. What stops that is not cryptography, it is
 * a person: the firewall prints `recoveryKeyFingerprint` of the pair it was given on its serial
 * console, the CLI prints the fingerprint of the key the owner typed, and they have to match. See
 * `docs/security-design.md` § Backups.
 */

/** Domain separation for the derivation. Changing this string invalidates every derived key. */
const SIGN_SEED_CONTEXT = "controlclaw-recovery-sign/v1";
/** Domain separation for what a request signature covers. */
const REQUEST_CONTEXT = "controlclaw-recovery-request/v1";
/** Domain separation for the fingerprint the owner reads off two screens. */
const PAIR_CONTEXT = "controlclaw-recovery-pair/v1";

/** How far a signed request's timestamp may be from the firewall's clock, either way. */
export const RECOVERY_REPLAY_WINDOW_MS = 5 * 60_000;

export interface RecoverySigningKeypair {
  /** base64 Ed25519 public key (32 bytes). The firewall holds this; it is not a secret. */
  publicKey: string;
  /** base64 Ed25519 secret key (64 bytes). Derived on demand, never stored anywhere. */
  secretKey: string;
}

/** The two public halves of one recovery key. Together they are what a firewall is told. */
export interface RecoveryPublicKeys {
  /** X25519, for the wraps. */
  publicKey: string;
  /** Ed25519, for the recovery routes. */
  signingPublicKey: string;
}

export async function deriveRecoverySigningKeypair(recoverySecretKeyB64: string): Promise<RecoverySigningKeypair> {
  const sodium = await sodiumReady();
  const secret = fromB64(recoverySecretKeyB64);
  if (secret.length !== sodium.crypto_scalarmult_SCALARBYTES) throw new Error("That is not a recovery key.");
  const seed = sodium.crypto_generichash(sodium.crypto_sign_SEEDBYTES, new Uint8Array([...utf8(SIGN_SEED_CONTEXT), ...secret]), null);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  return { publicKey: toB64(kp.publicKey), secretKey: toB64(kp.privateKey) };
}

/** Both public halves of a recovery key, from the secret the owner holds. */
export async function recoveryPublicKeys(recoverySecretKeyB64: string): Promise<RecoveryPublicKeys> {
  const sodium = await sodiumReady();
  const publicKey = toB64(sodium.crypto_scalarmult_base(fromB64(recoverySecretKeyB64)));
  return { publicKey, signingPublicKey: (await deriveRecoverySigningKeypair(recoverySecretKeyB64)).publicKey };
}

/**
 * The fingerprint an owner compares between their terminal and their firewall's serial console.
 *
 * Over **both** halves, not the X25519 one alone. A control plane that substituted only the signing
 * key — keeping the wrap key honest, so nothing else looked wrong — would otherwise pass a check
 * over `fingerprintOf(publicKey)` while holding the one key that drives the recovery routes.
 */
export async function recoveryKeyFingerprint(keys: RecoveryPublicKeys): Promise<string> {
  const sodium = await sodiumReady();
  const h = sodium.crypto_generichash(32, utf8(`${PAIR_CONTEXT}\n${keys.publicKey}\n${keys.signingPublicKey}`), null);
  const hex = [...h.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return (hex.match(/.{4}/g) ?? []).join("-");
}

/** The familiar fingerprint of the wrap key alone — what the console has always shown. */
export async function recoveryWrapFingerprint(publicKeyB64: string): Promise<string> {
  return fingerprint(publicKeyB64);
}

export interface RecoveryRequestFields {
  method: string;
  /** The path only, with no query and no host: a firewall behind a name is still the same request. */
  path: string;
  /** Milliseconds since the epoch, as the caller's clock has it. */
  timestamp: number;
  /** The whole body. Omit it and give `bodyDigest` instead for a body too big to hold. */
  body?: Uint8Array;
  /** `recoveryBodyDigest` of the body, for a caller that hashed it as it streamed past. */
  bodyDigest?: string;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** The body hash a signature covers. Exported so a streaming verifier and a signer agree. */
export async function recoveryBodyDigest(body: Uint8Array): Promise<string> {
  const sodium = await sodiumReady();
  return hex(sodium.crypto_generichash(32, body, null));
}

/**
 * The same hash, fed in pieces — a 5 GB archive is hashed as it arrives rather than held. Callers
 * must `await sodiumReady()` before constructing one, which `createRecoveryBodyHasher` does.
 */
export async function createRecoveryBodyHasher(): Promise<{ update(chunk: Uint8Array): void; digest(): string }> {
  const sodium = await sodiumReady();
  const state = sodium.crypto_generichash_init(null, 32);
  // `crypto_generichash_final` consumes the state, so the answer is kept: a caller that asks twice
  // (a signer that also logs it) must not get "invalid usage" the second time.
  let done: string | null = null;
  return {
    update(chunk) {
      if (done !== null) throw new Error("this body has already been hashed");
      sodium.crypto_generichash_update(state, chunk);
    },
    digest() {
      done ??= hex(sodium.crypto_generichash_final(state, 32));
      return done;
    },
  };
}

/**
 * What a signature covers: the method, the path, the timestamp and a hash of the whole body. The
 * body is hashed rather than signed directly so a multi-megabyte archive is streamed once, and the
 * hash is over the WHOLE body — the JSON head and the archive bytes together — so neither can be
 * swapped for the other's.
 */
async function signedString(f: RecoveryRequestFields): Promise<Uint8Array> {
  const digest = f.bodyDigest ?? (await recoveryBodyDigest(f.body ?? new Uint8Array(0)));
  return utf8(`${REQUEST_CONTEXT}\n${f.method.toUpperCase()}\n${f.path}\n${f.timestamp}\n${digest}`);
}

export async function signRecoveryRequest(signingSecretKeyB64: string, f: RecoveryRequestFields): Promise<string> {
  const sodium = await sodiumReady();
  return toB64(sodium.crypto_sign_detached(await signedString(f), fromB64(signingSecretKeyB64)));
}

export type RecoveryVerdict = { ok: true } | { ok: false; reason: "stale" | "bad_signature"; message: string };

/**
 * Check one signed request. Two failures, told apart on purpose: a clock that is out is worth
 * saying so the owner fixes it, and a bad signature is what the lockout counts.
 */
export async function verifyRecoveryRequest(
  signingPublicKeyB64: string,
  signatureB64: string,
  f: RecoveryRequestFields,
  now: number,
  windowMs: number = RECOVERY_REPLAY_WINDOW_MS,
): Promise<RecoveryVerdict> {
  if (!Number.isFinite(f.timestamp) || Math.abs(now - f.timestamp) > windowMs) {
    return {
      ok: false,
      reason: "stale",
      message: `This request is dated ${Math.round(Math.abs(now - f.timestamp) / 1000)}s away from the firewall's clock, and the window is ${Math.round(windowMs / 1000)}s. Check the clock on the machine you are running this from.`,
    };
  }
  const sodium = await sodiumReady();
  let good = false;
  try {
    good = sodium.crypto_sign_verify_detached(fromB64(signatureB64), await signedString(f), fromB64(signingPublicKeyB64));
  } catch {
    good = false;
  }
  return good ? { ok: true } : { ok: false, reason: "bad_signature", message: "This request is not signed by the recovery key this firewall was given." };
}

// ---- the wire between the CLI and the firewall ----

/**
 * One recovery request carries a small JSON head and, usually, an archive after it. They travel in
 * one body rather than two requests because **the signature covers the body**: a head signed apart
 * from its bytes could be replayed against different bytes, and a firewall that accepted that would
 * be back to trusting whoever served the archive.
 *
 *   ┌────────────┬───────────────┬────────────┬──────────────────────┐
 *   │ "CCRCV001" │ u32 BE length │ head (JSON)│ the archive, or none │
 *   └────────────┴───────────────┴────────────┴──────────────────────┘
 */
export const RECOVERY_BODY_MAGIC = "CCRCV001";
const RECOVERY_BODY_HEADER_BYTES = RECOVERY_BODY_MAGIC.length + 4;
/** A head is a handful of ids and one sealed key. Anything larger is not one. */
const MAX_RECOVERY_HEAD_BYTES = 64 * 1024;

export function encodeRecoveryBody(head: unknown, tail: Uint8Array = new Uint8Array(0)): Uint8Array {
  const body = utf8(JSON.stringify(head));
  if (body.length > MAX_RECOVERY_HEAD_BYTES) throw new Error("This request's head is larger than the recovery protocol allows.");
  const out = new Uint8Array(RECOVERY_BODY_HEADER_BYTES + body.length + tail.length);
  out.set(utf8(RECOVERY_BODY_MAGIC), 0);
  const at = RECOVERY_BODY_MAGIC.length;
  out[at] = (body.length >>> 24) & 0xff;
  out[at + 1] = (body.length >>> 16) & 0xff;
  out[at + 2] = (body.length >>> 8) & 0xff;
  out[at + 3] = body.length & 0xff;
  out.set(body, RECOVERY_BODY_HEADER_BYTES);
  out.set(tail, RECOVERY_BODY_HEADER_BYTES + body.length);
  return out;
}

export function decodeRecoveryBody(bytes: Uint8Array): { head: Record<string, unknown>; tail: Uint8Array } {
  const magic = utf8(RECOVERY_BODY_MAGIC);
  if (bytes.length < RECOVERY_BODY_HEADER_BYTES) throw new Error("This request is too short to be a recovery request.");
  for (let i = 0; i < magic.length; i++) if (bytes[i] !== magic[i]) throw new Error("This is not a recovery request.");
  const at = magic.length;
  const len = ((bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!) >>> 0;
  if (len === 0 || len > MAX_RECOVERY_HEAD_BYTES || bytes.length < RECOVERY_BODY_HEADER_BYTES + len) {
    throw new Error("This recovery request's head is the wrong size.");
  }
  const end = RECOVERY_BODY_HEADER_BYTES + len;
  let head: Record<string, unknown>;
  try {
    head = JSON.parse(new TextDecoder().decode(bytes.subarray(RECOVERY_BODY_HEADER_BYTES, end))) as Record<string, unknown>;
  } catch {
    throw new Error("This recovery request's head is not readable.");
  }
  if (!head || typeof head !== "object") throw new Error("This recovery request's head is not readable.");
  return { head, tail: bytes.subarray(end) };
}
