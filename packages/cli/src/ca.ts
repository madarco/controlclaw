import { join } from "node:path";
import type { Install } from "./openclaw.js";
import type { Recorder } from "./state.js";
import { type Sys, type User, which } from "./sys.js";

/** The firewall's CA in the system store (curl, Python, Go, git). */
export const SYSTEM_CA = "/usr/local/share/ca-certificates/controlclaw.crt";
export const NSS_NAME = "ControlClaw firewall";

/** A PEM certificate, or the reason it is not one. */
export function checkPem(pem: string): string | null {
  const t = pem.trim();
  if (!t.startsWith("-----BEGIN CERTIFICATE-----") || !t.endsWith("-----END CERTIFICATE-----")) {
    return "the CA file is not a PEM certificate";
  }
  return null;
}

export async function installSystemStore(sys: Sys, rec: Recorder, pem: string): Promise<void> {
  // Recorded first, so on undo it runs after the file is gone.
  rec.onUndo("refresh the system CA store", [["update-ca-certificates"]]);
  await rec.file(SYSTEM_CA, pem);
  const r = await sys.run(["update-ca-certificates"]);
  if (r.code !== 0) throw new Error(`update-ca-certificates failed: ${r.stderr.trim()}`);
}

/**
 * `NODE_EXTRA_CA_CERTS` for OpenClaw's gateway. Node reads it only at start, so it has to be in
 * the service's environment: a drop-in next to its unit, which OpenClaw's own `gateway install`
 * does not touch. Returns a note when OpenClaw runs some way a drop-in cannot reach.
 */
export async function installNodeEnv(sys: Sys, rec: Recorder, install: Install, user: User | null, caPath: string): Promise<string | null> {
  const body = `# Written by controlclaw connect; removed by controlclaw disconnect.\n[Service]\nEnvironment=NODE_EXTRA_CA_CERTS=${caPath}\n`;
  const runs = install.runs;
  if (runs.kind === "systemd-user" && user) {
    const reload = ["systemctl", "--user", "daemon-reload"];
    rec.onUndo("reload the user's systemd", [reload], { user });
    await rec.file(join(user.home, ".config/systemd/user", `${runs.unit}.d`, "controlclaw.conf"), body, { owner: user });
    await sys.run(reload, { user });
    return null;
  }
  if (runs.kind === "systemd-system") {
    rec.onUndo("reload systemd", [["systemctl", "daemon-reload"]]);
    await rec.file(join("/etc/systemd/system", `${runs.unit}.d`, "controlclaw.conf"), body);
    await sys.run(["systemctl", "daemon-reload"]);
    return null;
  }
  return `OpenClaw does not run as a systemd unit: add NODE_EXTRA_CA_CERTS=${caPath} to how you start it, then restart it.`;
}

/** Chrome on Linux reads its own NSS store, not the system one. Only stores that exist. */
export async function installNss(sys: Sys, rec: Recorder, user: User, caPath: string): Promise<number> {
  const certutil = await which(sys, "certutil");
  if (!certutil) return 0;
  let n = 0;
  for (const db of [join(user.home, ".pki/nssdb"), join(user.home, ".local/share/pki/nssdb")]) {
    if (!sys.exists(db)) continue;
    rec.onUndo("remove the CA from Chrome", [[certutil, "-d", `sql:${db}`, "-D", "-n", NSS_NAME]], { user });
    const r = await sys.run([certutil, "-d", `sql:${db}`, "-A", "-t", "C,,", "-n", NSS_NAME, "-i", caPath], { user });
    if (r.code === 0) n++;
  }
  return n;
}
