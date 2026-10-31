import { createHash, createPublicKey, verify } from "node:crypto";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

declare const __CC_CLI_VERSION__: string;

/**
 * Where the release's assets are, `{version}` replaced, and the minisign public key (the base64 line
 * of the .pub) its SHA256SUMS is signed with. Empty in a dev build: standalone/release/release.sh
 * stamps both into the copy it packs (standalone/release/SIGNING.md).
 */
const RELEASE_URL = "";
const RELEASE_PUBKEY = "";

/** DER SubjectPublicKeyInfo prefix of an Ed25519 key; the 32 raw bytes follow. */
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");

/**
 * Checks a minisign signature (the prehashed form minisign makes by default: Ed25519 over the
 * file's BLAKE2b-512), its key id and the signature over its trusted comment. Returns the trusted
 * comment; throws on anything else.
 */
export function verifyMinisign(pubkey: string, data: Buffer, minisig: string): string {
  const pk = Buffer.from(pubkey.trim(), "base64");
  if (pk.length !== 42 || pk.subarray(0, 2).toString() !== "Ed") throw new Error("not a minisign public key");
  const lines = minisig.split("\n");
  const sig = Buffer.from(lines[1] ?? "", "base64");
  if (sig.length !== 74 || sig.subarray(0, 2).toString() !== "ED") throw new Error("not a prehashed minisign signature");
  if (!sig.subarray(2, 10).equals(pk.subarray(2, 10))) throw new Error("signed with another key");
  const key = createPublicKey({ key: Buffer.concat([ED25519_SPKI, pk.subarray(10)]), format: "der", type: "spki" });
  const s = sig.subarray(10);
  if (!verify(null, createHash("blake2b512").update(data).digest(), key, s)) throw new Error("the file does not match its signature");
  const tc = lines[2] ?? "";
  if (!tc.startsWith("trusted comment: ")) throw new Error("no trusted comment");
  const global = Buffer.from(lines[3] ?? "", "base64");
  if (!verify(null, Buffer.concat([s, Buffer.from(tc.slice("trusted comment: ".length))]), key, global)) {
    throw new Error("the trusted comment does not match its signature");
  }
  return tc.slice("trusted comment: ".length);
}

export interface ReleaseOpts {
  url?: string;
  pubkey?: string;
  version?: string;
  arch?: string;
  fetch?: typeof fetch;
}

/**
 * Downloads the vm-agent of this CLI's own release into a new temp folder, after checking
 * SHA256SUMS against the release key and the binary against SHA256SUMS. Null when this build has
 * no release to download from (a dev build); throws when the download or a check fails.
 * CONTROLCLAW_RELEASE_URL moves where the files come from, never the key.
 */
export async function releaseVmAgent(o: ReleaseOpts = {}): Promise<string | null> {
  const version = o.version ?? (typeof __CC_CLI_VERSION__ === "string" ? __CC_CLI_VERSION__ : "0.0.0-dev");
  const pubkey = o.pubkey ?? RELEASE_PUBKEY;
  const pattern = o.url ?? process.env.CONTROLCLAW_RELEASE_URL ?? RELEASE_URL;
  if (!pubkey || !pattern) return null;
  const arch = { x64: "x86_64", arm64: "aarch64" }[o.arch ?? process.arch];
  if (!arch) throw new Error(`The release has no vm-agent for ${o.arch ?? process.arch}.`);
  const base = pattern.replaceAll("{version}", version).replace(/\/$/, "");
  const get = async (name: string): Promise<Buffer> => {
    const url = `${base}/${name}`;
    try {
      // The vm-agent is about 20 MB: two minutes is a slow line, not a stalled server.
      const res = await (o.fetch ?? fetch)(url, { signal: AbortSignal.timeout(120_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return Buffer.from(await res.arrayBuffer());
    } catch (e) {
      throw new Error(`Could not download ${url} (${(e as Error).message}).`, { cause: e });
    }
  };
  const sums = await get("SHA256SUMS");
  let comment: string;
  try {
    comment = verifyMinisign(pubkey, sums, (await get("SHA256SUMS.minisig")).toString());
  } catch (e) {
    throw new Error(`The release's SHA256SUMS is not signed by the release key: ${(e as Error).message.replace(/\.$/, "")}.`, { cause: e });
  }
  // Signed for this version (standalone/release/release.sh), not an older release served under its name.
  if (comment !== `controlclaw ${version}`) throw new Error(`The release's signature is for another version (${comment}).`);
  const asset = `vm-agent-${arch}-linux-musl`;
  const want = sums
    .toString()
    .split("\n")
    .find((l) => l.endsWith(`  ${asset}`))
    ?.slice(0, 64);
  if (!want) throw new Error(`The release's SHA256SUMS has no ${asset}.`);
  const bin = await get(asset);
  if (createHash("sha256").update(bin).digest("hex") !== want) throw new Error(`${asset} does not match the release's SHA256SUMS.`);
  const path = join(mkdtempSync(join(tmpdir(), "controlclaw-vm-agent-")), "vm-agent");
  writeFileSync(path, bin);
  chmodSync(path, 0o755);
  return path;
}

/**
 * The vm-agent to install: the one given or found (`found`), else this release's, downloaded and
 * checked. `downloaded` is the folder it was downloaded to, for the caller to remove once it is
 * installed. Null, with the reason said, when there is none.
 */
export async function vmAgentOrRelease(
  found: string | null,
  say: { out: (l: string) => void; err: (l: string) => void },
): Promise<{ path: string; downloaded: string | null } | null> {
  if (found) return { path: found, downloaded: null };
  let path: string | null;
  try {
    path = await releaseVmAgent();
  } catch (e) {
    say.err(`${(e as Error).message} Pass --vm-agent <path>.`);
    return null;
  }
  if (!path) {
    say.err("No vm-agent binary found. Pass --vm-agent <path> (this build has no release to download it from).");
    return null;
  }
  say.out(`  Downloaded and checked the vm-agent of this release: ${path}`);
  return { path, downloaded: dirname(path) };
}
