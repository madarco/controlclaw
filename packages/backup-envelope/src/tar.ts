/**
 * A minimal POSIX/GNU tar writer and reader.
 *
 * Written out rather than pulled in because it runs inside `vm-agent`, which the security design
 * asks to keep tiny and auditable ("keep it small, fuzz it, pin the binary hash"), and because
 * extracting an archive is the one place a backup could do damage: a crafted entry name is a write
 * anywhere on the box. Doing the path checks here, where they are visible, is worth 150 lines.
 *
 * It lives in this package rather than in `vm-agent` because it is part of the backup FORMAT, and
 * three things now read that format: the agent box, and — since the offline path — `packages/recover`
 * on an owner's own machine. One reader, one set of path checks.
 *
 * Only what a backup needs: regular files, directories, symlinks, GNU long names. No sparse files,
 * no device nodes, no hard links, no pax attributes — anything else is refused on read and never
 * produced on write.
 */

const BLOCK = 512;
const ZERO = new Uint8Array(BLOCK);

export type TarType = "file" | "dir" | "link";

export interface TarEntry {
  path: string;
  type: TarType;
  size: number;
  mode: number;
  mtime: number;
  /** For `link` entries. */
  target?: string;
}

function octal(value: number, width: number): string {
  return value.toString(8).padStart(width - 1, "0") + "\0";
}

function writeString(buf: Uint8Array, at: number, s: string, width: number): void {
  const bytes = new TextEncoder().encode(s);
  if (bytes.length > width) throw new Error(`tar field does not fit: ${s}`);
  buf.set(bytes, at);
}

const TYPEFLAG: Record<TarType, string> = { file: "0", dir: "5", link: "2" };

function header(entry: TarEntry, typeflag = TYPEFLAG[entry.type], name = entry.path): Uint8Array {
  const h = new Uint8Array(BLOCK);
  writeString(h, 0, name, 100);
  writeString(h, 100, octal(entry.mode & 0o7777, 8), 8);
  writeString(h, 108, octal(0, 8), 8);
  writeString(h, 116, octal(0, 8), 8);
  writeString(h, 124, octal(entry.type === "file" ? entry.size : 0, 12), 12);
  writeString(h, 136, octal(Math.max(0, Math.floor(entry.mtime)), 12), 12);
  // The checksum is computed with this field full of spaces, then written over it.
  h.fill(0x20, 148, 156);
  writeString(h, 156, typeflag, 1);
  if (entry.target) writeString(h, 157, entry.target, 100);
  writeString(h, 257, "ustar", 6);
  writeString(h, 263, "00", 2);
  let sum = 0;
  for (const b of h) sum += b;
  writeString(h, 148, `${sum.toString(8).padStart(6, "0")}\0 `, 8);
  return h;
}

function padding(size: number): Uint8Array {
  const rest = size % BLOCK;
  return rest === 0 ? new Uint8Array(0) : new Uint8Array(BLOCK - rest);
}

/**
 * A GNU long-link block pair: a header with type `L` (a long *name*) or `K` (a long link *target*),
 * followed by the value as its body. Every tar since the nineties understands both; the ustar
 * prefix-field trick only works for paths that happen to split on a slash in the right place, and
 * there is no equivalent trick at all for a link target.
 */
function longLink(value: string, typeflag: "L" | "K"): Uint8Array[] {
  const bytes = new TextEncoder().encode(value);
  const head = header({ path: "././@LongLink", type: "file", size: bytes.length + 1, mode: 0o644, mtime: 0 }, typeflag, "././@LongLink");
  const body = new Uint8Array(bytes.length + 1);
  body.set(bytes);
  return [head, body, padding(body.length)].filter((b) => b.length > 0);
}

/**
 * The header blocks for one entry, with a long-link pair in front for whichever of the name and the
 * link target does not fit in its 100-byte field.
 *
 * The target case is not hypothetical: one deep symlink anywhere under OpenClaw's home — the kind a
 * package manager leaves behind — used to fail the WHOLE backup with "tar field does not fit".
 */
export function tarHeader(entry: TarEntry): Uint8Array[] {
  const name = new TextEncoder().encode(entry.path);
  const target = new TextEncoder().encode(entry.target ?? "");
  const out: Uint8Array[] = [];
  // Order matters: GNU tar applies the last `K` and the last `L` it saw to the next real header.
  if (target.length > 100) out.push(...longLink(entry.target!, "K"));
  if (name.length > 100) out.push(...longLink(entry.path, "L"));
  out.push(
    header(
      // The real header's own fields must still fit; the long-link pair is what carries the value.
      { ...entry, path: name.length > 100 ? "././@LongLink" : entry.path, target: target.length > 100 ? "" : entry.target },
      TYPEFLAG[entry.type],
      name.length > 100 ? "././@LongLink" : entry.path,
    ),
  );
  return out;
}

/** What follows an entry's body so the next header starts on a block boundary. */
export function tarPadding(size: number): Uint8Array[] {
  const p = padding(size);
  return p.length > 0 ? [p] : [];
}

/** The two zero blocks that end an archive. */
export function tarEnd(): Uint8Array[] {
  return [ZERO, ZERO];
}

// ---- reading ----

function readString(buf: Uint8Array, at: number, width: number): string {
  const slice = buf.subarray(at, at + width);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}

function readOctal(buf: Uint8Array, at: number, width: number): number {
  const s = readString(buf, at, width).trim();
  if (s === "") return 0;
  const n = parseInt(s, 8);
  if (!Number.isFinite(n) || n < 0) throw new Error("this archive has a malformed tar header");
  return n;
}

export interface ReadEntry extends TarEntry {
  /** The entry's bytes, for `file` entries. */
  body: Uint8Array;
}

/**
 * Feed download chunks in, get whole entries out. Refuses anything a backup would never contain
 * rather than guessing: an unknown type flag, a missing ustar magic, or a size that does not fit.
 */
export class TarReader {
  private buffer = new Uint8Array(0);
  private longName: string | null = null;
  private longTarget: string | null = null;
  private zeroBlocks = 0;
  private ended = false;

  push(chunk: Uint8Array): ReadEntry[] {
    if (chunk.length > 0) {
      const merged = new Uint8Array(this.buffer.length + chunk.length);
      merged.set(this.buffer);
      merged.set(chunk, this.buffer.length);
      this.buffer = merged;
    }
    const out: ReadEntry[] = [];
    for (;;) {
      if (this.ended || this.buffer.length < BLOCK) return out;
      const head = this.buffer.subarray(0, BLOCK);
      if (head.every((b) => b === 0)) {
        this.buffer = this.buffer.subarray(BLOCK);
        if (++this.zeroBlocks >= 2) this.ended = true;
        continue;
      }
      this.zeroBlocks = 0;
      if (readString(head, 257, 6).replace(/\0.*$/, "") !== "ustar") throw new Error("this archive is not a tar file we wrote");
      const size = readOctal(head, 124, 12);
      const bodyBlocks = Math.ceil(size / BLOCK) * BLOCK;
      if (this.buffer.length < BLOCK + bodyBlocks) return out;
      const body = this.buffer.subarray(BLOCK, BLOCK + size);
      const flag = readString(head, 156, 1);
      const path = this.longName ?? readString(head, 0, 100);
      this.buffer = this.buffer.subarray(BLOCK + bodyBlocks);
      if (flag === "L" || flag === "K") {
        const value = new TextDecoder().decode(body).replace(/\0+$/, "");
        if (flag === "L") this.longName = value;
        else this.longTarget = value;
        continue;
      }
      const longTarget = this.longTarget;
      this.longName = null;
      this.longTarget = null;
      const type: TarType | null = flag === "0" || flag === "" ? "file" : flag === "5" ? "dir" : flag === "2" ? "link" : null;
      if (!type) throw new Error(`this archive contains an entry type we do not restore (${flag})`);
      out.push({
        path,
        type,
        size: type === "file" ? size : 0,
        mode: readOctal(head, 100, 8) & 0o7777,
        mtime: readOctal(head, 136, 12),
        ...(type === "link" ? { target: longTarget ?? readString(head, 157, 100) } : {}),
        // A copy, not a view: the buffer it points into is reused as more chunks arrive.
        body: type === "file" ? new Uint8Array(body) : new Uint8Array(0),
      });
    }
  }

  /** True once both end-of-archive blocks arrived. A restore refuses an archive that never ends. */
  complete(): boolean {
    return this.ended;
  }
}

/**
 * The only safe reading of an entry's name. A backup is served to the box by the control plane, so
 * `../../etc/shadow` or `/etc/shadow` in a header must not become a write there — even though the
 * envelope already proves the bytes are the ones the box itself sealed.
 */
export function safeEntryPath(path: string): string {
  const clean = path.replace(/\\/g, "/").replace(/^\.\//, "");
  if (clean === "" || clean === ".") throw new Error("this archive contains an entry with no name");
  if (clean.startsWith("/")) throw new Error(`this archive contains an absolute path (${clean})`);
  const parts = clean.split("/");
  if (parts.some((p) => p === "..")) throw new Error(`this archive contains a path that climbs out of it (${clean})`);
  if (clean.includes("\0")) throw new Error("this archive contains an entry name with a null byte");
  return parts.filter((p) => p !== "" && p !== ".").join("/");
}
