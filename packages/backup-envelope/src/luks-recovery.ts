import { fromB64, sodiumReady, toB64, utf8 } from "./sodium";

/**
 * How a box's **disk passphrase** is sealed to the organization's recovery key.
 *
 * The box generates a random LUKS passphrase and keeps it inside the container it opens. The only
 * other copy is this blob, on the box's plain root and mirrored in the control plane as ciphertext:
 * it is what lets an owner open a box when no partner box is up (`docs/plans/disk-encryption.md` §6).
 *
 * **Why not `crypto_box_seal`,** which is what the backups feature uses to wrap data keys to the same
 * key? Because the thing doing the sealing here is a box that has just formatted its disk — before
 * any `pnpm install`, so before libsodium exists on it. `crypto_box_seal` is XSalsa20-Poly1305, which
 * Node cannot do without a library. So the seal is spelled out in primitives Node ships with, and
 * they are the same ones a browser ships with:
 *
 *   eph     = X25519 keypair, per seal
 *   shared  = X25519(eph.secret, recoveryPublicKey)
 *   key     = HKDF-SHA256(shared, salt = eph.public ‖ recoveryPublicKey, info = CONTEXT, 32)
 *   blob    = { v: 1, eph, iv, ct }        AES-256-GCM, tag appended to ct
 *
 * The recipient is the **same X25519 key** as the backup wraps (`org_backup_settings.publicKey`), so
 * this adds no new secret for the owner to keep: it is the recovery key they were already shown once.
 *
 * The box's copy of the seal is `roles/controlclaw/files/cc-seal` in the Ansible repo — twenty lines
 * of Node with no imports. Two implementations of one format is a drift risk, so {@link LUKS_SEAL_VECTOR}
 * pins it: the test below opens the vector, and `cc-seal --selftest` opens it on the box at
 * provisioning time. Neither can change the format without the other failing loudly.
 */

/** Domain separation. Changing this string invalidates every sealed passphrase in the fleet. */
export const LUKS_SEAL_CONTEXT = "controlclaw/luks-recovery/v1";

export interface SealedPassphrase {
  v: 1;
  /** base64 ephemeral X25519 public key (32 bytes). */
  eph: string;
  /** base64 AES-GCM nonce (12 bytes). */
  iv: string;
  /** base64 ciphertext with the 16-byte tag appended. */
  ct: string;
  /**
   * Which recovery key this was sealed to: {@link recoveryKeyTag} of its public half. Written by the
   * box when it seals (`cc-seal`), so it cannot disagree with the blob. Not part of the crypto, and
   * absent on a blob sealed before the field existed: then nobody can tell which key opens it.
   */
  to?: string;
}

/** The shape of a {@link SealedPassphrase.to}. */
export const RECOVERY_KEY_TAG = /^sha256:[0-9a-f]{16}$/;

/**
 * A short name for a recovery public key: "sha256:" and the first 8 bytes of SHA-256 over the raw
 * key, in hex. The box computes the same when it seals (`cc-seal`'s `keyTag`, which may use nothing
 * but Node's own crypto, hence SHA-256 and not the BLAKE2b of {@link fingerprint}). Comparing it
 * with the tag on a box's sealed passphrase says whether that box is sealed to this key: an
 * organization can replace its recovery key, and nothing re-seals a box when it does.
 */
export async function recoveryKeyTag(recoveryPublicKeyB64: string): Promise<string> {
  const raw = Uint8Array.from(atob(recoveryPublicKeyB64), (c) => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", raw));
  return `sha256:${[...digest.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** The tag a sealed passphrase carries, when it is one; null for a blob from before the field, or anything else. */
export function sealedTo(blob: unknown): string | null {
  const to = (blob as { to?: unknown } | null)?.to;
  return typeof to === "string" && RECOVERY_KEY_TAG.test(to) ? to : null;
}

/**
 * When a recovery key did not open a sealed passphrase: is it a different key from the one the blob
 * names? Returns both tags when it is, so the owner can be told "this is not the key this box was
 * sealed to" in place of "wrong key"; null when the blob names none, names this key, or the key
 * cannot be read. The name in the blob is the box's own word, so this explains a failed open and
 * must never be used to refuse a key before trying it.
 */
export async function sealedToAnotherKey(blob: unknown, recoverySecretKeyB64: string): Promise<{ sealedTo: string; key: string } | null> {
  const named = sealedTo(blob);
  if (!named) return null;
  try {
    const sodium = await sodiumReady();
    const key = await recoveryKeyTag(toB64(sodium.crypto_scalarmult_base(fromB64(recoverySecretKeyB64))));
    return key === named ? null : { sealedTo: named, key };
  } catch {
    return null;
  }
}

function hkdfSha256(shared: Uint8Array, salt: Uint8Array, length: number): Promise<ArrayBuffer> {
  const subtle = globalThis.crypto.subtle;
  return subtle
    .importKey("raw", shared as unknown as ArrayBuffer, "HKDF", false, ["deriveBits"])
    .then((k) =>
      subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as unknown as ArrayBuffer, info: utf8(LUKS_SEAL_CONTEXT) as unknown as ArrayBuffer }, k, length * 8),
    );
}

/**
 * Open a sealed passphrase with the owner's recovery key. Runs in the console (which already loads
 * libsodium for backups) and in `packages/recover`; never on a box.
 *
 * @param blob the box's sealed blob
 * @param recoverySecretKeyB64 the 32-byte X25519 secret the owner was shown once
 */
export async function openSealedPassphrase(blob: SealedPassphrase, recoverySecretKeyB64: string): Promise<string> {
  if (blob?.v !== 1) throw new Error("Unknown sealed-passphrase version.");
  const sodium = await sodiumReady();
  const secret = fromB64(recoverySecretKeyB64);
  if (secret.length !== sodium.crypto_scalarmult_SCALARBYTES) throw new Error("That is not a recovery key.");

  const eph = fromB64(blob.eph);
  if (eph.length !== 32) throw new Error("Malformed sealed passphrase.");
  // The same shared secret the box computed: libsodium's scalarmult and Node's X25519
  // diffieHellman both return the raw 32-byte point.
  const shared = sodium.crypto_scalarmult(secret, eph);
  const recipientPub = sodium.crypto_scalarmult_base(secret);
  const salt = new Uint8Array([...eph, ...recipientPub]);

  const keyBits = await hkdfSha256(shared, salt, 32);
  const key = await globalThis.crypto.subtle.importKey("raw", keyBits, "AES-GCM", false, ["decrypt"]);
  let plain: ArrayBuffer;
  try {
    plain = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(blob.iv) as unknown as ArrayBuffer },
      key,
      fromB64(blob.ct) as unknown as ArrayBuffer,
    );
  } catch {
    // The common cause is the wrong recovery key, and saying so is more use than "decrypt failed".
    throw new Error("That recovery key does not open this box's disk.");
  }
  return new TextDecoder().decode(plain);
}

/**
 * Seal a passphrase to a recovery public key. The box does this with `cc-seal`; this copy exists so
 * the round trip is testable and so `dev-fake-mitm-box.ts` can stand in for a box.
 */
export async function sealPassphrase(passphrase: string, recoveryPublicKeyB64: string): Promise<SealedPassphrase> {
  const sodium = await sodiumReady();
  const recipientPub = fromB64(recoveryPublicKeyB64);
  if (recipientPub.length !== 32) throw new Error("That is not a recovery public key.");

  const ephSecret = sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES);
  const ephPublic = sodium.crypto_scalarmult_base(ephSecret);
  const shared = sodium.crypto_scalarmult(ephSecret, recipientPub);
  const salt = new Uint8Array([...ephPublic, ...recipientPub]);

  const keyBits = await hkdfSha256(shared, salt, 32);
  const key = await globalThis.crypto.subtle.importKey("raw", keyBits, "AES-GCM", false, ["encrypt"]);
  const iv = sodium.randombytes_buf(12);
  const ct = await globalThis.crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as ArrayBuffer }, key, utf8(passphrase) as unknown as ArrayBuffer);
  return { v: 1, eph: toB64(ephPublic), iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

/**
 * A fixed blob, its recovery key, and what it opens to. Generated once, checked in on purpose: it is
 * what stops `cc-seal` on a box and this file drifting into two incompatible formats, which would
 * only be discovered by an owner who could not open their own disk.
 */
export const LUKS_SEAL_VECTOR = {
  /** base64 X25519 secret (the "recovery key"). Test-only; not a key any box ever used. */
  recoverySecretKey: "Y29udHJvbGNsYXctbHVrcy1zZWFsLXRlc3QtdmVjdG8=",
  /** its X25519 public half, which is what a box seals to. */
  recoveryPublicKey: "OLIAAYYu9C/XU5mQckoX00FBWNlYg7+Ur4qx2M/tKXs=",
  /** {@link recoveryKeyTag} of that public key. `cc-seal --selftest` checks its own against this string. */
  recoveryKeyTag: "sha256:0006bb1c1b76749b",
  passphrase: "vector-passphrase-do-not-use",
  /** Sealed by this file, and opened by `cc-seal --selftest` on every box. */
  sealed: {
    v: 1,
    eph: "DNeI9JVpucy5zvkkwMUvGGkdlEB73HMIMluNnjz8sHk=",
    iv: "Yr0Nnhumk9xZOHUT",
    ct: "P0RioW2uVExRNeuGbesfn/f7EpXKmbx23w+85AUJ+CERJSET0K3JEdj4qng=",
  },
  /**
   * Sealed by `cc-seal` on 2026-09-26 and checked in so this file's test proves the *other*
   * direction too: a blob a real box produced opens here. Without this, a drift that only broke
   * box→owner would pass every test in this repo and fail on a customer's worst day.
   */
  sealedByCcSeal: {
    v: 1,
    eph: "+t4Da1Qc+E1eqUeV52CkH+joWZecDenaIzI0RfA9RC4=",
    iv: "qPRNfpnF5Cd8tuqB",
    ct: "x3mhV1GNdprHIFuzUqZvVpYxLQvN+CGGP98WHCTGMuopBzUH3o9q3WpNeasznCjs",
  },
  sealedByCcSealOpensTo: "a-real-looking-passphrase-abc123",
} as const;
