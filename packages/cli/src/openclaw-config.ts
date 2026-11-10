import { join } from "node:path";
import type { Io } from "./commands.js";
import { type Install, restartArgv, restartUser } from "./openclaw.js";
import { type ConfigBackup, type ConnectRecord, pathOwner, type Recorder, stateDir } from "./state.js";
import { type Sys, type User, userByUid } from "./sys.js";

/**
 * OpenClaw's config file, kept as it was before the vm-agent first writes to it (a model, a bot, the
 * firewall's MCP servers), so `disconnect --restore-config` can put it back. `disconnect` alone
 * removes the copy: what the panel set stays in OpenClaw.
 */
export const COPY = "openclaw.json.before-controlclaw";

/** Who reads and writes the file: the owner of its folder, when that is a user here; else this process. */
function ownerOf(sys: Sys, path: string): User | null {
  if (sys.euid !== 0) return null;
  let uid = 0;
  try {
    uid = pathOwner(sys, path);
  } catch {
    return null;
  }
  return uid === 0 ? null : userByUid(sys, uid);
}

async function readConfig(sys: Sys, path: string): Promise<string | null> {
  // Never through a link: root would read wherever it points.
  if (sys.lstat(path)?.link) return null;
  const user = ownerOf(sys, path);
  return user ? sys.readAs(user, path) : sys.read(path);
}

/** Keeps the copy (0600, in the state folder) and records it. Returns its path, or null when there is no file. */
export async function backupConfig(sys: Sys, rec: Recorder, record: ConnectRecord, install: Install, user: User | null): Promise<string | null> {
  const config = install.config_file;
  if (!config) return null;
  let text: string | null;
  try {
    text = await readConfig(sys, config);
  } catch {
    text = null;
  }
  if (text === null) return null;
  const copy = join(stateDir(sys), COPY);
  await rec.file(copy, text, { mode: 0o600 });
  const backup: ConfigBackup = { config, copy, restart: restartArgv(install), ...(restartUser(install, user) ? { restartAs: restartUser(install, user) } : {}) };
  record.configBackup = backup;
  rec.start();
  return copy;
}

/** The copy's text, read before disconnect removes it. */
export function backupText(sys: Sys, record: ConnectRecord): string | null {
  return record.configBackup ? sys.read(record.configBackup.copy) : null;
}

/** Puts OpenClaw's config back as it was before connect, then restarts OpenClaw so it reads it. */
export async function restoreConfig(sys: Sys, io: Io, b: ConfigBackup, text: string): Promise<boolean> {
  const st = sys.lstat(b.config);
  if (st?.link) {
    io.err(`  ${b.config} is now a link: not written. The copy was ${b.copy}.`);
    return false;
  }
  try {
    const user = ownerOf(sys, b.config);
    if (user) await sys.writeAs(user, b.config, text);
    else {
      const was = sys.stat(b.config);
      sys.write(b.config, text, { mode: was?.mode ?? 0o600, owner: was ?? undefined });
    }
  } catch (e) {
    io.err(`  could not put back ${b.config}: ${(e as Error).message}`);
    return false;
  }
  io.out(`  OpenClaw's config is back as it was before connect (${b.config}).`);
  if (b.restart) {
    const r = await sys.run(b.restart, { user: b.restartAs, timeoutMs: 180_000 });
    if (r.code !== 0) io.out(`  ! OpenClaw did not restart (${(r.stderr || r.stdout).trim().split("\n").pop()}): restart it yourself so it reads its config.`);
  }
  return true;
}
