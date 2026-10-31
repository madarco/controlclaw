import { sodiumReady, utf8 } from "./sodium";
import type { BackupArchiveKind } from "./envelope";

/**
 * The **archive file**: a downloaded backup that can be opened with nothing but a recovery key.
 *
 * What is in the object store is the sealed stream on its own. Everything needed to open it — the
 * stream header, the manifest hash, the wraps of the data key, and the four values the envelope
 * binds every chunk to — lives in the control plane's `backup` row, because that is what makes
 * "add a recipient" a row rather than a rewrite of a 5 GB blob.
 *
 * That is fine while the control plane is in the loop and wrong the moment it is not. So a
 * **download** is not the raw object: it is a small JSON prelude followed by the same bytes, and
 * `npx @controlclaw/recover decrypt` needs the file and the owner's recovery key and nothing else.
 * The S3 objects are untouched; the download route assembles the file as it streams.
 *
 *   ┌────────────┬──────────────┬───────────────┬───────────────────────────┐
 *   │ "CCBKUP01" │ u32 BE length│ prelude (JSON)│ the sealed stream, as-is  │
 *   └────────────┴──────────────┴───────────────┴───────────────────────────┘
 *
 * The magic is checked rather than assumed: a file without it is an archive downloaded before this
 * existed, and the CLI says so and points at `--header-file` instead of failing on a JSON parse.
 */

/** 8 bytes, ASCII. `01` is the container version, not the envelope's. */
export const ARCHIVE_FILE_MAGIC = "CCBKUP01";
export const ARCHIVE_FILE_EXTENSION = ".ccbak";

/** The fixed part of the container: the magic plus the u32 length of the prelude. */
export const ARCHIVE_FILE_HEADER_BYTES = ARCHIVE_FILE_MAGIC.length + 4;

/**
 * A prelude big enough to hold a few wraps and no more. It is read before anything is verified, so
 * it gets a hard bound: a corrupt length must not make a CLI allocate a gigabyte.
 */
const MAX_PRELUDE_BYTES = 64 * 1024;

/** One recipient's sealed copy of the data key, exactly as the `backup_key_wrap` row holds it. */
export interface ArchiveKeyWrap {
  recipient: "firewall" | "recovery";
  /** The public key it was sealed to, so the CLI can say "that is not the key this needs". */
  fingerprint: string;
  wrapped: string;
}

/**
 * Everything the control plane knows about one archive that is not the ciphertext. All of it is
 * public by construction: a wrap is useless without a private half, and the header is a nonce.
 */
export interface ArchivePrelude {
  /** This container's version. Bumped if the shape below ever changes incompatibly. */
  version: 1;
  /** The envelope version the stream was sealed with. One, so far. */
  envelope: 1;
  kind: BackupArchiveKind;
  backupId: string;
  orgId: string;
  /**
   * The box the archive was TAKEN on — the `vmId` of the envelope binding, not wherever it is being
   * restored to. It is the one value a restore cannot guess and cannot take on trust: a wrong one
   * simply fails to decrypt.
   */
  sourceBoxId: string;
  /** What the agent (or the firewall) was called, for the CLI's output. Never used as an id. */
  agentName: string;
  takenAt: string;
  /** base64, 24 bytes of `crypto_secretstream` header. */
  header: string;
  manifestHash: string;
  wraps: ArchiveKeyWrap[];
  plainBytes: number;
  cipherBytes: number;
  entries: number;
}

function isWrap(v: unknown): v is ArchiveKeyWrap {
  const w = v as ArchiveKeyWrap | null;
  return !!w && (w.recipient === "firewall" || w.recipient === "recovery") && typeof w.fingerprint === "string" && typeof w.wrapped === "string";
}

/** Throws with a sentence a person can act on; never returns a half-checked prelude. */
export function parseArchivePrelude(json: string): ArchivePrelude {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(json) as Record<string, unknown>;
  } catch {
    throw new Error("This file's header is not readable, so it is not a ControlClaw backup.");
  }
  const need = (k: keyof ArchivePrelude): string => {
    const v = raw[k];
    if (typeof v !== "string" || v.length === 0) throw new Error(`This file's header has no ${k}, so it cannot be opened.`);
    return v;
  };
  if (raw.version !== 1) throw new Error(`This file was written by a newer version of ControlClaw (format ${String(raw.version)}). Update the recover tool.`);
  const kind = need("kind");
  if (kind !== "workspace" && kind !== "state" && kind !== "firewall") throw new Error(`This file says it is a ${kind} archive, which this version does not know.`);
  const wraps = Array.isArray(raw.wraps) ? raw.wraps.filter(isWrap) : [];
  if (wraps.length === 0) throw new Error("This file carries no sealed key, so nothing can open it.");
  const num = (k: string): number => (typeof raw[k] === "number" && Number.isFinite(raw[k]) ? (raw[k] as number) : 0);
  return {
    version: 1,
    envelope: 1,
    kind,
    backupId: need("backupId"),
    orgId: need("orgId"),
    sourceBoxId: need("sourceBoxId"),
    agentName: typeof raw.agentName === "string" ? raw.agentName : "",
    takenAt: typeof raw.takenAt === "string" ? raw.takenAt : "",
    header: need("header"),
    manifestHash: need("manifestHash"),
    wraps,
    plainBytes: num("plainBytes"),
    cipherBytes: num("cipherBytes"),
    entries: num("entries"),
  };
}

/** Canonical bytes of a prelude: sorted keys, no incidental whitespace. */
export function encodeArchivePrelude(p: ArchivePrelude): Uint8Array {
  const json = JSON.stringify({
    agentName: p.agentName,
    backupId: p.backupId,
    cipherBytes: p.cipherBytes,
    entries: p.entries,
    envelope: 1,
    header: p.header,
    kind: p.kind,
    manifestHash: p.manifestHash,
    orgId: p.orgId,
    plainBytes: p.plainBytes,
    sourceBoxId: p.sourceBoxId,
    takenAt: p.takenAt,
    version: 1,
    wraps: p.wraps.map((w) => ({ fingerprint: w.fingerprint, recipient: w.recipient, wrapped: w.wrapped })),
  });
  const body = utf8(json);
  if (body.length > MAX_PRELUDE_BYTES) throw new Error("This backup's key material is larger than the archive format allows.");
  const out = new Uint8Array(ARCHIVE_FILE_HEADER_BYTES + body.length);
  out.set(utf8(ARCHIVE_FILE_MAGIC), 0);
  const at = ARCHIVE_FILE_MAGIC.length;
  out[at] = (body.length >>> 24) & 0xff;
  out[at + 1] = (body.length >>> 16) & 0xff;
  out[at + 2] = (body.length >>> 8) & 0xff;
  out[at + 3] = body.length & 0xff;
  out.set(body, ARCHIVE_FILE_HEADER_BYTES);
  return out;
}

export type ArchiveFileHead =
  | { kind: "prelude"; prelude: ArchivePrelude; streamOffset: number }
  /** No magic: an archive downloaded before the format existed, or a raw object from the store. */
  | { kind: "raw" }
  /** The magic is there but the prelude has not all arrived yet. Only streaming callers see this. */
  | { kind: "incomplete"; need: number };

/**
 * Read the head of a downloaded file. Deliberately tolerant about ONE thing — a file with no magic
 * is "raw", not an error — because that is the shape of every archive downloaded before this
 * existed and the CLI has a better answer for it than a parse failure.
 */
export function readArchiveFileHead(bytes: Uint8Array): ArchiveFileHead {
  const magic = utf8(ARCHIVE_FILE_MAGIC);
  const cmp = Math.min(bytes.length, magic.length);
  for (let i = 0; i < cmp; i++) if (bytes[i] !== magic[i]) return { kind: "raw" };
  if (bytes.length < ARCHIVE_FILE_HEADER_BYTES) return { kind: "incomplete", need: ARCHIVE_FILE_HEADER_BYTES - bytes.length };
  const at = magic.length;
  const len = ((bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!) >>> 0;
  if (len === 0 || len > MAX_PRELUDE_BYTES) throw new Error("This file's header is the wrong size, so it is not a ControlClaw backup.");
  const end = ARCHIVE_FILE_HEADER_BYTES + len;
  if (bytes.length < end) return { kind: "incomplete", need: end - bytes.length };
  const json = new TextDecoder().decode(bytes.subarray(ARCHIVE_FILE_HEADER_BYTES, end));
  return { kind: "prelude", prelude: parseArchivePrelude(json), streamOffset: end };
}

/**
 * A short name for one archive file, so two downloads of the same backup can be told apart and a
 * support conversation has something to quote. Over the prelude's canonical bytes, so a prelude
 * somebody edited — a substituted wrap, a different `sourceBoxId` — is a different id.
 */
export async function archiveFileId(p: ArchivePrelude): Promise<string> {
  const sodium = await sodiumReady();
  const h = sodium.crypto_generichash(32, encodeArchivePrelude(p).subarray(ARCHIVE_FILE_HEADER_BYTES), null);
  const hex = [...h.subarray(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return (hex.match(/.{4}/g) ?? []).join("-");
}
