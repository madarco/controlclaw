import { fromB64, sodiumReady, toB64, utf8, type Sodium } from "./sodium";

/**
 * The backup envelope: how a ControlClaw backup is sealed, and the only crypto in this feature.
 *
 * One random **data key** per backup encrypts the archive with
 * `crypto_secretstream_xchacha20poly1305` — chunked, so a 5 GB archive streams through with a
 * fixed memory cost and a truncated upload is refused rather than silently half-restored. The data
 * key itself is wrapped once per **recipient** with `crypto_box_seal` (anonymous sealed box, X25519
 * + XSalsa20-Poly1305): once to the org firewall's key, once to the owner's recovery key.
 *
 * Nothing but ciphertext leaves the box. The wrapped keys, the stream header and the manifest hash
 * live in the control plane's `backup` row rather than inside the archive, which is what makes
 * "add a recipient" cheap: unwrap the data key on a box that holds one private half, wrap it again
 * to the new public half, update the row. The archive is never rewritten.
 *
 * Every chunk is pushed with `{orgId, vmId, backupId, kind}` as associated data, so a blob served
 * for another box, another backup or the other archive of the same backup fails to open — the
 * control plane stores the bytes and cannot substitute them undetected.
 */

/** Which of a backup's two archives this is. They restore independently. */
/** `gbrain`: the organization's brain (docs/plans/gbrain.md §10): its database dump, pages and settings. */
export type BackupArchiveKind = "workspace" | "state" | "firewall" | "gbrain";

/** What a chunk is bound to. Order matters: it is serialised positionally. */
export interface EnvelopeBinding {
  orgId: string;
  vmId: string;
  backupId: string;
  kind: BackupArchiveKind;
}

/** Plaintext bytes per chunk. 512 KiB keeps ~10k frames at the 5 GB v1 limit. */
export const CHUNK_BYTES = 512 * 1024;

/** `crypto_secretstream_xchacha20poly1305_ABYTES` — 17 bytes of tag + MAC per chunk. */
const STREAM_OVERHEAD = 17;

/** Frame length prefix: u32 big-endian. Bounds a frame so a corrupt length cannot allocate wildly. */
const FRAME_HEADER_BYTES = 4;
const MAX_FRAME_BYTES = CHUNK_BYTES + STREAM_OVERHEAD;

/**
 * The associated data string. Field names are included so two bindings can never collide by
 * shifting a value from one field into the next (`vmId: "a|b"` must not read as `vmId: "a"`,
 * `backupId: "b"`).
 */
export function bindingAad(b: EnvelopeBinding): string {
  return `controlclaw-backup/v1\norg=${b.orgId}\nvm=${b.vmId}\nbackup=${b.backupId}\nkind=${b.kind}`;
}

function frame(body: Uint8Array): Uint8Array {
  const out = new Uint8Array(FRAME_HEADER_BYTES + body.length);
  const n = body.length;
  out[0] = (n >>> 24) & 0xff;
  out[1] = (n >>> 16) & 0xff;
  out[2] = (n >>> 8) & 0xff;
  out[3] = n & 0xff;
  out.set(body, FRAME_HEADER_BYTES);
  return out;
}

// ---- keys ----

export interface RecipientKeypair {
  /** base64 X25519 public key — travels freely; the control plane may hold it. */
  publicKey: string;
  /** base64 X25519 secret key — never leaves the firewall box, or the owner's browser. */
  secretKey: string;
  fingerprint: string;
}

export async function generateRecipientKeypair(): Promise<RecipientKeypair> {
  const sodium = await sodiumReady();
  const kp = sodium.crypto_box_keypair();
  return {
    publicKey: toB64(kp.publicKey),
    secretKey: toB64(kp.privateKey),
    fingerprint: await fingerprint(toB64(kp.publicKey)),
  };
}

/** The public half of a secret key, so a saved recovery key is the only thing anyone has to keep. */
export async function publicKeyOf(secretKeyB64: string): Promise<string> {
  const sodium = await sodiumReady();
  return toB64(sodium.crypto_scalarmult_base(fromB64(secretKeyB64)));
}

/**
 * A short name for a public key, for the one job a fingerprint has here: letting the owner compare
 * what the console says their firewall's key is against what they expect, before handing a rewrapped
 * data key to it. 64 bits, grouped, lower case — long enough that nobody grinds a collision for a
 * string a person reads, short enough that they will actually read it.
 */
export async function fingerprint(publicKeyB64: string): Promise<string> {
  const sodium = await sodiumReady();
  const h = sodium.crypto_generichash(32, fromB64(publicKeyB64), null);
  const hex = [...h.subarray(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return (hex.match(/.{4}/g) ?? []).join("-");
}

export async function randomDataKey(): Promise<string> {
  const sodium = await sodiumReady();
  return toB64(sodium.randombytes_buf(sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES));
}

/** Wrap the data key for one recipient. Anonymous: the recipient learns nothing about the sender. */
export async function wrapDataKey(dataKeyB64: string, recipientPublicKeyB64: string): Promise<string> {
  const sodium = await sodiumReady();
  return toB64(sodium.crypto_box_seal(fromB64(dataKeyB64), fromB64(recipientPublicKeyB64)));
}

/** Throws when the wrap was made for a different recipient, or was tampered with. */
export async function unwrapDataKey(wrappedB64: string, secretKeyB64: string): Promise<string> {
  const sodium = await sodiumReady();
  let open: Uint8Array;
  try {
    // The decode and the scalar multiplication are inside the try too: a malformed key or wrap would
    // otherwise escape as a raw base64 or libsodium error, and the one caller that pre-flights this
    // (`BackupFirewall.proposeRestore`) would report "you need your recovery key" for what is really
    // corrupt input.
    const secret = fromB64(secretKeyB64);
    open = sodium.crypto_box_seal_open(fromB64(wrappedB64), sodium.crypto_scalarmult_base(secret), secret);
  } catch {
    throw new Error("This key cannot open that backup.");
  }
  if (open.length !== sodium.crypto_secretstream_xchacha20poly1305_KEYBYTES) throw new Error("This key cannot open that backup.");
  return toB64(open);
}

/**
 * Move a backup's data key to a new recipient without touching the archive: unwrap with a private
 * half you hold, wrap to the new public half. This is what the owner's browser runs after a
 * firewall rebuild — the recovery secret key never leaves the page, and only the new wrap is sent.
 */
export async function rewrapDataKey(opts: { wrapped: string; secretKey: string; toPublicKey: string }): Promise<string> {
  return wrapDataKey(await unwrapDataKey(opts.wrapped, opts.secretKey), opts.toPublicKey);
}

// ---- the stream ----

export interface Encryptor {
  /** base64 stream header (24 bytes). Kept in the `backup` row, not in the blob. */
  readonly header: string;
  /** One framed ciphertext chunk. `plain` must be at most CHUNK_BYTES. */
  push(plain: Uint8Array): Uint8Array;
  /** The FINAL-tagged empty chunk. Its absence is how a truncated archive is caught. */
  final(): Uint8Array;
}

export async function makeEncryptor(dataKeyB64: string, binding: EnvelopeBinding): Promise<Encryptor> {
  const sodium = await sodiumReady();
  const ad = utf8(bindingAad(binding));
  const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(fromB64(dataKeyB64));
  let closed = false;
  return {
    header: toB64(header),
    push(plain) {
      if (closed) throw new Error("the archive stream is already closed");
      if (plain.length > CHUNK_BYTES) throw new Error(`chunk of ${plain.length} bytes is over the ${CHUNK_BYTES} limit`);
      return frame(
        sodium.crypto_secretstream_xchacha20poly1305_push(state, plain, ad, sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE),
      );
    },
    final() {
      if (closed) throw new Error("the archive stream is already closed");
      closed = true;
      return frame(
        sodium.crypto_secretstream_xchacha20poly1305_push(
          state,
          new Uint8Array(0),
          ad,
          sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
        ),
      );
    },
  };
}

export interface Decryptor {
  /** Feed arbitrary download chunks in; get whatever plaintext is now complete out. */
  push(cipher: Uint8Array): Uint8Array[];
  /** Throws unless the FINAL chunk arrived and nothing is left half-read. */
  end(): void;
}

const WRONG_KEY = "This archive could not be opened: the key or the backup it names is wrong.";
const TRUNCATED = "This archive ended early — it is incomplete. Nothing was restored.";

export async function makeDecryptor(dataKeyB64: string, headerB64: string, binding: EnvelopeBinding): Promise<Decryptor> {
  const sodium = await sodiumReady();
  const ad = utf8(bindingAad(binding));
  const header = fromB64(headerB64);
  if (header.length !== sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES) throw new Error(WRONG_KEY);
  let state: ReturnType<typeof sodium.crypto_secretstream_xchacha20poly1305_init_pull>;
  try {
    state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, fromB64(dataKeyB64));
  } catch {
    throw new Error(WRONG_KEY);
  }
  // Frames arrive split across however many pieces the HTTP body came in; buffer until whole.
  let buffer = new Uint8Array(0);
  let sawFinal = false;

  const take = (n: number): Uint8Array => {
    const head = buffer.subarray(0, n);
    buffer = buffer.subarray(n);
    return head;
  };

  return {
    push(cipher) {
      if (cipher.length > 0) {
        const merged = new Uint8Array(buffer.length + cipher.length);
        merged.set(buffer);
        merged.set(cipher, buffer.length);
        buffer = merged;
      }
      const out: Uint8Array[] = [];
      for (;;) {
        if (buffer.length < FRAME_HEADER_BYTES) return out;
        const len = ((buffer[0]! << 24) | (buffer[1]! << 16) | (buffer[2]! << 8) | buffer[3]!) >>> 0;
        if (len < STREAM_OVERHEAD || len > MAX_FRAME_BYTES) throw new Error(WRONG_KEY);
        if (buffer.length < FRAME_HEADER_BYTES + len) return out;
        take(FRAME_HEADER_BYTES);
        const body = take(len);
        // A frame after the FINAL one means somebody appended to the blob: refuse the whole thing
        // rather than restore a prefix of it.
        if (sawFinal) throw new Error(WRONG_KEY);
        let r: { message: Uint8Array; tag: number };
        try {
          r = sodium.crypto_secretstream_xchacha20poly1305_pull(state, body, ad) as { message: Uint8Array; tag: number };
        } catch {
          throw new Error(WRONG_KEY);
        }
        // libsodium-wrappers returns `false` rather than throwing on a MAC failure.
        if (!r) throw new Error(WRONG_KEY);
        if (r.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL) sawFinal = true;
        if (r.message.length > 0) out.push(r.message);
      }
    },
    end() {
      if (!sawFinal || buffer.length > 0) throw new Error(TRUNCATED);
    },
  };
}

/** How big the blob will be for a given plaintext size — the presigned PUT wants a bound. */
export function cipherSizeFor(plainBytes: number): number {
  const full = Math.floor(plainBytes / CHUNK_BYTES);
  const rest = plainBytes % CHUNK_BYTES;
  const frames = full + (rest > 0 ? 1 : 0) + 1; // + the FINAL frame
  return plainBytes + frames * (STREAM_OVERHEAD + FRAME_HEADER_BYTES);
}

export { toB64, fromB64 } from "./sodium";
export type { Sodium };
