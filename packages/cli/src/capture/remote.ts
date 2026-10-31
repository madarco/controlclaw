import type { Facts } from "../doctor.js";
import type { Check } from "../probe.js";
import type { ConnectRecord } from "../state.js";
import type { Sys } from "../sys.js";
import { aptInstall } from "./apt.js";
import { host, WG_IFACE } from "./host.js";
import type { CaptureMode, Ctx, Tunnel } from "./mode.js";

/**
 * Remote: the machine reaches its firewall over WireGuard, from anywhere (plan §4, "Identity
 * without a private network"). Pairing gave it a tunnel address, its identity at the proxy, and the
 * firewall's side. This writes `cc-wg0`, then captures OpenClaw's user as host mode does, with the
 * firewall at its tunnel address; the capture's tunnel chains make sure nothing for the firewall
 * leaves by another interface, so with the tunnel down OpenClaw's traffic goes nowhere.
 */
export const WG_DIR = "/etc/wireguard";
export const WG_UNIT = `wg-quick@${WG_IFACE}.service`;
/** About 45 seconds: a ping and a look every round. */
const HANDSHAKE_TRIES = 15;

export function wgConf(t: Tunnel): string {
  return `# Written by controlclaw connect; removed by controlclaw disconnect.
[Interface]
Address = ${t.address}/32
PostUp = wg set %i private-key ${WG_DIR}/${WG_IFACE}.key

[Peer]
PublicKey = ${t.firewallPublicKey}
Endpoint = ${t.endpoint}
# Only the firewall's tunnel address: the machine's other traffic keeps its own routes.
AllowedIPs = ${t.firewall}/32
PersistentKeepalive = 25
`;
}

export const remote: CaptureMode = {
  name: "remote",
  protects:
    "like host mode on this machine (anyone with root or sudo can remove the rules); its traffic reaches the firewall over WireGuard from any network, and its tunnel address is its identity",
  blockers(f: Facts) {
    const out = host.blockers(f).map((b) => b.replace("use --mode docker", "use --mode docker with a firewall it can reach"));
    if (!f.wireguard && !f.apt) out.push("needs WireGuard (wireguard-tools), and apt-get is not here to install it");
    return out;
  },
  // The tunnel first: the vm-agent listens on its address, and the checks after install go through it.
  async prepare(ctx: Ctx) {
    const { sys, rec, facts } = ctx;
    const t = ctx.tunnel;
    if (!t) throw new Error("remote mode needs a tunnel: pair with a code (not --ca)");
    if (!facts.wireguard) {
      ctx.log("Installing WireGuard");
      await aptInstall(sys, rec, "wireguard-tools");
    }
    await rec.file(`${WG_DIR}/${WG_IFACE}.key`, `${t.privateKey}\n`, { mode: 0o600 });
    await rec.file(`${WG_DIR}/${WG_IFACE}.conf`, wgConf(t), { mode: 0o600 });
    rec.onUndo("take down the tunnel", [["systemctl", "disable", "--now", WG_UNIT]]);
    const up = await sys.run(["systemctl", "enable", "--now", WG_UNIT]);
    if (up.code !== 0) throw new Error(`could not bring up ${WG_IFACE}: ${up.stderr.trim()} (journalctl -u ${WG_UNIT})`);
    // The firewall adds the peer within seconds of pairing: wait for its first answer.
    for (let i = 0; i < HANDSHAKE_TRIES; i++) {
      await sys.run(["ping", "-c", "1", "-W", "1", t.firewall]);
      const h = await sys.run(["wg", "show", WG_IFACE, "latest-handshakes"]);
      if (Number(h.stdout.trim().split(/\s+/)[1] ?? 0) > 0) {
        ctx.log(`Tunnel ${WG_IFACE} up: ${t.address} to the firewall at ${t.firewall} (${t.endpoint})`);
        return;
      }
      await sys.run(["sleep", "2"]);
    }
    throw new Error(`the firewall does not answer on WireGuard at ${t.endpoint} (is UDP ${t.endpoint.split(":").pop()} open to this machine?)`);
  },
  install(ctx: Ctx) {
    return host.install(ctx);
  },
  async status(sys: Sys, record: ConnectRecord) {
    const checks: Check[] = [await tunnelCheck(sys)];
    return [...checks, ...(await host.status(sys, record))];
  },
};

/** The tunnel: up, and when the firewall last answered (a handshake every two minutes or so). */
async function tunnelCheck(sys: Sys): Promise<Check> {
  const r = await sys.run(["wg", "show", WG_IFACE, "latest-handshakes"]);
  if (r.code !== 0) return { name: "tunnel", ok: false, detail: `${WG_IFACE} is down: OpenClaw reaches nothing (sudo systemctl restart ${WG_UNIT})` };
  const at = Number(r.stdout.trim().split(/\s+/)[1] ?? 0);
  const ago = Math.round(Date.now() / 1000 - at);
  if (!at) return { name: "tunnel", ok: false, detail: `${WG_IFACE} is up, but the firewall never answered (UDP to its endpoint blocked?)` };
  return { name: "tunnel", ok: ago < 180, detail: `${WG_IFACE} up, last handshake ${ago}s ago` };
}
