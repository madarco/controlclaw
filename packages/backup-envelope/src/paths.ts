import type { BackupArchiveKind } from "./envelope";

/**
 * What an agent backup holds, and what it deliberately leaves out. Shared so the box that archives,
 * the console that explains it and the tests all read one list.
 *
 * Two archives per backup, because they want restoring separately: someone who broke their agent's
 * configuration wants `state` back without rolling their work back a day, and someone who deleted a
 * directory wants `workspace` back without losing the model they set up since.
 *
 *   workspace → OpenClaw's working tree (`~/.openclaw/workspace`)
 *   state     → the rest of OpenClaw's home: config, sessions and memory, auth profiles
 *               (placeholders, not real secrets — the real ones live on the firewall), the WhatsApp
 *               session, installed plugins.
 *
 * Two things are never in either, and both are identity rather than content: `/opt/controlclaw/keys`
 * (the box's own keypair, the pinned firewall key, the session secret) and OpenClaw's gateway token.
 * A box restored from a backup keeps the identity it was provisioned with — otherwise restoring a
 * backup onto a second box would clone the first box's right to speak for it.
 */

/** Where each archive's root sits, relative to OpenClaw's home directory. */
export const ARCHIVE_ROOTS: Record<"workspace" | "state", string> = {
  workspace: "workspace",
  state: ".",
};

/** Path segments that are never worth their bytes. Matched on a whole segment, case-insensitively. */
const EXCLUDED_SEGMENTS = new Set(
  [
    "node_modules",
    ".cache",
    "cache",
    "caches",
    "cachestorage",
    "code cache",
    "gpucache",
    "shadercache",
    "dawncache",
    "crashpad",
    "_cacache",
    ".pnpm-store",
    ".turbo",
    ".venv",
    "__pycache__",
    "logs",
    "tmp",
    ".tmp",
  ].map((s) => s.toLowerCase()),
);

/**
 * This box's identity, wherever it turns up. Never archived, and — the other half of the same rule —
 * never REMOVED by a restore: a `state` restore replaces the whole of OpenClaw's home, so anything
 * excluded from the archive would otherwise be deleted by the swap. Losing a cache that way is
 * fine; losing the gateway token would leave a restored box unable to drive OpenClaw at all.
 */
export const IDENTITY_NAMES = ["openclaw_gateway_token", "saas_public_key.pem", "vm_private_key.pem", "vm_public_key.pem", "mitm_pinned_pubkey.pem", "session_secret"];

/** Files that are noise, a socket, or a token we must never copy. */
const EXCLUDED_NAMES = new Set([...IDENTITY_NAMES, ".DS_Store"].map((s) => s.toLowerCase()));

/**
 * What a restore of `kind` carries across from the old directory rather than replacing. The
 * workspace is the other archive's business; the rest is identity (above).
 */
export function keepOnRestore(kind: BackupArchiveKind): string[] {
  // The integrity-pinned Meet runtime is installed by Ansible, not rolled back with content.
  return kind === "state" ? ["workspace", "extensions/google-meet", ...IDENTITY_NAMES] : [];
}

const EXCLUDED_SUFFIXES = [".log", ".log.gz", ".sock", ".pid", ".swp", ".core"];

/**
 * A restore's own scratch directories. They sit next to what they are replacing — the swap is a
 * rename, and a rename must not cross filesystems — so a workspace restore leaves
 * `workspace.cc-restoring` and `workspace.cc-previous-<ms>` INSIDE OpenClaw's home. If the box dies
 * between the swap and the cleanup, the next `state` backup would otherwise archive a whole second
 * copy of the workspace: the one archive that is meant to contain no workspace at all, doubled in
 * size and possibly over the 5 GB limit. Matched anywhere, not just at the top level.
 */
const RESTORE_SCRATCH = /\.cc-(restoring|previous-\d+)$/;

/**
 * `state` also skips the workspace — that is the other archive, not a hole in this one.
 *
 * A brain (`gbrain`) skips only identity and restore scratch: what is archived there is a staged
 * copy (the database dump, GBrain's pages, its settings) made for the backup, and a page's folder
 * can be called `logs` or `cache` like anything else. Skipping those would be losing someone's notes.
 */
export function shouldExclude(relPath: string, kind: BackupArchiveKind): boolean {
  const parts = relPath.split("/").filter((p) => p.length > 0 && p !== ".");
  if (parts.length === 0) return false;
  if (kind === "state" && parts[0] === "workspace") return true;
  if (parts.some((p) => RESTORE_SCRATCH.test(p))) return true;
  const name = parts[parts.length - 1]!.toLowerCase();
  if (EXCLUDED_NAMES.has(name)) return true;
  if (kind === "gbrain") return false;
  if (EXCLUDED_SUFFIXES.some((s) => name.endsWith(s))) return true;
  return parts.some((p) => EXCLUDED_SEGMENTS.has(p.toLowerCase()));
}

/**
 * Absolute paths that must never appear in any archive, whatever a caller asks for. The archive
 * roots are computed, not passed in, so this is belt-and-braces — but the cost of being wrong here
 * is a box's identity in an object store, so it is checked anyway.
 */
export const FORBIDDEN_ROOTS = ["/opt/controlclaw/keys", "/opt/controlclaw/mitm", "/etc/ssh", "/root"];

export function assertArchivableRoot(absolutePath: string): void {
  const p = absolutePath.replace(/\/+$/, "") || "/";
  if (p === "/") throw new Error("refusing to archive the whole filesystem");
  for (const bad of FORBIDDEN_ROOTS) {
    if (p === bad || p.startsWith(`${bad}/`)) throw new Error(`refusing to archive ${bad}: it is this box's identity, not its content`);
  }
}

/**
 * The firewall's own backup, which is the opposite shape: a short, explicit list of files rather
 * than a tree with exclusions. Its contents are what a rebuilt firewall would otherwise lose — the
 * box key that unlocks its stores, the stores themselves, its CA, and the grants and rules it is
 * enforcing. Not the traffic log: it is large, it is already shipped to the console, and it is the
 * one thing here that is a record of behaviour rather than of configuration.
 */
export const FIREWALL_BACKUP_FILES = [
  "/opt/controlclaw/keys/box_key",
  "/opt/controlclaw/state/channels.enc",
  "/opt/controlclaw/state/llm.enc",
  "/opt/controlclaw/state/backup.enc",
  "/opt/controlclaw/state/drive.enc",
  "/opt/controlclaw/state/google.enc",
  "/opt/controlclaw/state/agentmail.enc",
  "/opt/controlclaw/state/twilio-voice.enc",
  "/opt/controlclaw/state/secrets.enc",
  // Website logins (docs/plans/website-credentials.md): typed into the firewall's own page, so a
  // rebuild without them is a round of asking every owner for every password again.
  "/opt/controlclaw/state/logins.enc",
  // Enrolled browsers and each agent's pinned hostname. Without it a restored firewall asks every
  // browser for a code again, and re-pins agents from whatever the identity map says that day.
  "/opt/controlclaw/state/access.enc",
  // Approved meeting settings survive rebuilds; active media leases never do.
  "/opt/controlclaw/state/meetings.enc",
  // Content rules (docs/plans/firewall-content-rules.md): every change was confirmed with a code,
  // so a rebuild must not quietly drop them.
  "/opt/controlclaw/state/content-rules.enc",
  // The CA three ways, as gen-ca.sh writes it: the pair the firewall publishes and the agents
  // install, and the combined key+cert the proxy signs with. They must travel together: a restore
  // that brought only the combined file back left the proxy signing with one CA while every agent
  // was told to trust another (prod, 2026-09-22).
  "/opt/controlclaw/mitm/ca/ca-cert.pem",
  "/opt/controlclaw/mitm/ca/ca-key.pem",
  "/opt/controlclaw/mitm/ca/mitmproxy-ca.pem",
  "/run/mitm/config/rules.json",
  "/run/mitm/config/grants.json",
  "/run/mitm/config/identities.json",
];
