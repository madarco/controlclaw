import type { Recorder } from "../state.js";
import type { Sys } from "../sys.js";

/**
 * Installs a Debian package `connect` needs, and records its removal for `disconnect` (recorded
 * first, so it runs after whatever uses the package is gone). The package lists are refreshed
 * first: a fresh cloud image has none.
 */
export async function aptInstall(sys: Sys, rec: Recorder, pkg: string): Promise<void> {
  rec.onUndo(`remove ${pkg}`, [["apt-get", "purge", "-y", "-q", pkg]]);
  const env = { DEBIAN_FRONTEND: "noninteractive" };
  await sys.run(["apt-get", "update", "-q"], { env, timeoutMs: 300_000 });
  const r = await sys.run(["apt-get", "install", "-y", "-q", pkg], { env, timeoutMs: 300_000 });
  if (r.code !== 0) throw new Error(`apt-get install ${pkg} failed: ${r.stderr.trim()}`);
}
