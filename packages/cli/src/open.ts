import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { join } from "node:path";
import type { Io } from "./commands.js";
import { composeIn, setupTokenIn } from "./fwcontainer.js";
import { loadFirewall, loadRecord, sudoUserRecord } from "./state.js";
import { type Sys, type User, userByName, userByUid } from "./sys.js";

/**
 * `controlclaw open`: the panel of the firewall on this machine (`up`, `up --local`, or `install.sh`),
 * always on 127.0.0.1:8800. Before there is an admin, the link carries the setup token in its
 * fragment (`#setup=`), which the browser never sends and the panel takes out of the address bar
 * once it has read it. With a desktop it is opened as the user who ran the command (not root);
 * otherwise the link is printed with the SSH tunnel to reach it.
 */
export const PANEL = "http://127.0.0.1:8800";

export interface OpenNet {
  /** The panel's `GET /api/session`; null when nothing answers. */
  session: () => Promise<{ setup: boolean } | null>;
}

export const realOpenNet: OpenNet = {
  async session() {
    try {
      const r = await fetch(`${PANEL}/api/session`, { signal: AbortSignal.timeout(5000) });
      if (!r.ok) return null;
      const j = (await r.json()) as { setup?: unknown };
      return { setup: j.setup === true };
    } catch {
      return null;
    }
  },
};

/** The newest setup token, from wherever this machine's firewall logs. */
async function setupToken(sys: Sys): Promise<{ token: string | null; hint: string }> {
  const rec = loadRecord(sys) ?? (await sudoUserRecord(sys))?.record;
  const fw = loadFirewall(sys);
  // up --local's project, or the container `install` runs.
  const project = rec?.up ? { name: rec.up.project, dir: rec.up.dir } : fw?.kind === "docker" ? { name: fw.project!, dir: fw.dir! } : null;
  if (project) {
    const logs = await sys.run(composeIn(project.name, project.dir)("logs", "--no-color", "firewall"), { timeoutMs: 30_000 });
    return { token: setupTokenIn(logs.stdout), hint: `docker compose -p ${project.name} logs firewall | grep 'no admin yet'` };
  }
  // install.sh: the firewall agent's journal, which root (or the adm group) can read.
  const j = await sys.run(["journalctl", "-u", "controlclaw-mitm-agent", "--no-pager", "-o", "cat"], { timeoutMs: 30_000 });
  return { token: setupTokenIn(j.stdout), hint: "sudo journalctl -u controlclaw-mitm-agent | grep 'no admin yet'" };
}

export async function open(sys: Sys, io: Io, net: OpenNet = realOpenNet): Promise<number> {
  const s = await net.session();
  if (!s) {
    io.err(`No firewall panel answers on ${PANEL}. Start one with controlclaw up (or up --local), or check it with controlclaw status.`);
    return 1;
  }
  let link = PANEL;
  // A new firewall (no admin yet): what it does until there are rules.
  const policy = s.setup ? "Every site is allowed and logged. To lock it down: Internet access, Every other site: Block." : null;
  if (s.setup) {
    const { token, hint } = await setupToken(sys);
    if (token) link = `${PANEL}/#setup=${token}`;
    else io.out(`The panel asks for its setup token: ${hint}${sys.euid === 0 ? "" : " (with sudo)"}`);
  }
  if (sys.env.DISPLAY || sys.env.WAYLAND_DISPLAY) {
    // As the person at the desktop, not root: their browser, their profile.
    const user = sys.euid === 0 ? (sys.env.SUDO_USER ? userByName(sys, sys.env.SUDO_USER) : null) : userByUid(sys, sys.euid);
    if (user && user.uid !== 0 && (await desktopOpen(sys, user, link))) {
      io.out(`Opened the firewall's panel: ${PANEL}`);
      if (policy) io.out(policy);
      return 0;
    }
  }
  io.out(`Firewall panel: ${link}`);
  io.out(`  From another machine: ssh -L 8800:127.0.0.1:8800 ${hostname()}, then open the address above there.`);
  if (policy) io.out(policy);
  return 0;
}

/** How long the page that carries the token stays on disk: the browser has read it by then. */
const PAGE_SECONDS = 15;

/**
 * `xdg-open` as `user`. A link with the token is not passed on the command line, where every user
 * of the machine can read it (the browser keeps its first URL in its own for as long as it runs): a
 * page only `user` can read, in their home (a snap browser cannot read /tmp or hidden folders),
 * sends the browser on, and is removed after a few seconds.
 */
async function desktopOpen(sys: Sys, user: User, link: string): Promise<boolean> {
  const env: Record<string, string> = {};
  for (const k of ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"]) if (sys.env[k]) env[k] = sys.env[k]!;
  const as = sys.euid === 0 ? user : undefined;
  if (!link.includes("#")) return (await sys.run(["xdg-open", link], { user: as, env, timeoutMs: 20_000 })).code === 0;
  const page = join(user.home, `controlclaw-open-${randomBytes(6).toString("hex")}.html`);
  const html = `<!doctype html><meta charset="utf-8"><title>ControlClaw</title><script>location.replace(${JSON.stringify(link)})</script>\n`;
  try {
    await sys.writeAs(user, page, html, 0o600);
  } catch {
    return false;
  }
  try {
    const r = await sys.run(["xdg-open", `file://${page}`], { user: as, env, timeoutMs: 20_000 });
    if (r.code === 0) await sys.run(["sleep", String(PAGE_SECONDS)]);
    return r.code === 0;
  } finally {
    await sys.removeAs(user, page, []);
  }
}
