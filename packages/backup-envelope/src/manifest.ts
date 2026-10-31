import { sodiumReady, utf8 } from "./sodium";
import type { BackupArchiveKind } from "./envelope";

/**
 * The manifest: what a backup says it contains, and the hash that lets a restore check it got
 * exactly that. It is written INTO the archive (as the first entry) and its hash is kept in the
 * control plane's row, so a restore can tell "the control plane served me the wrong blob" (the
 * envelope's associated data already catches that) from "the blob I was served is not what was
 * recorded" — a stale or partially-written object.
 */

export interface ManifestEntry {
  /** Relative to the archive root, forward slashes, no leading `./`. */
  path: string;
  bytes: number;
  /** Unix mode, low 12 bits. Restoring an executable that lost its bit is a silent breakage. */
  mode: number;
  kind: "file" | "dir" | "link";
  /** Symlink target, for `link` entries. */
  target?: string;
}

export interface Manifest {
  version: 1;
  kind: BackupArchiveKind;
  /** ISO 8601, from the box that took it. */
  takenAt: string;
  /** Where the archive root maps to on a box, so a restore puts it back in the right place. */
  root: string;
  entries: ManifestEntry[];
  totalBytes: number;
  /** Directories skipped by the exclude list, with what they would have cost. For the console. */
  excluded: { path: string; bytes: number }[];
}

export const MANIFEST_PATH = ".controlclaw-backup-manifest.json";

/**
 * Canonical bytes of a manifest: keys in a fixed order, entries sorted by path, no incidental
 * whitespace. Two boxes that archived the same tree must hash to the same string, and a hash that
 * depended on `JSON.stringify` key order would be a coin flip across Node versions.
 */
export function canonicalManifest(m: Manifest): string {
  const entry = (e: ManifestEntry) =>
    e.kind === "link"
      ? { bytes: e.bytes, kind: e.kind, mode: e.mode, path: e.path, target: e.target ?? "" }
      : { bytes: e.bytes, kind: e.kind, mode: e.mode, path: e.path };
  return JSON.stringify({
    entries: [...m.entries].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).map(entry),
    excluded: [...m.excluded].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)).map((e) => ({ bytes: e.bytes, path: e.path })),
    kind: m.kind,
    root: m.root,
    takenAt: m.takenAt,
    totalBytes: m.totalBytes,
    version: m.version,
  });
}

export async function manifestHash(m: Manifest): Promise<string> {
  const sodium = await sodiumReady();
  return [...sodium.crypto_generichash(32, utf8(canonicalManifest(m)), null)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** True when this manifest is the one the control plane recorded. Constant time is not needed: public. */
export async function manifestMatches(m: Manifest, expectedHash: string): Promise<boolean> {
  return (await manifestHash(m)) === expectedHash;
}

export function parseManifest(json: string): Manifest {
  const m = JSON.parse(json) as Manifest;
  if (m?.version !== 1 || !Array.isArray(m.entries)) throw new Error("the archive's manifest is not readable");
  return { ...m, excluded: Array.isArray(m.excluded) ? m.excluded : [] };
}
