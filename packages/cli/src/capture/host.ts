import { AGENT_PORT } from "../agent.js";
import { installNodeEnv, installNss, installSystemStore } from "../ca.js";
import type { Facts } from "../doctor.js";
import { escapeGroupMessage } from "../groups.js";
import { restartOpenClaw } from "../openclaw.js";
import { type Check, dnsAnswers, ipv4Of, proxyAnswers, splitHostPort } from "../probe.js";
import type { ConnectRecord } from "../state.js";
import type { Sys, User } from "../sys.js";
import { aptInstall } from "./apt.js";
import type { CaptureMode, Ctx } from "./mode.js";

/**
 * Same host, Linux: every packet from OpenClaw's uid is caught by nftables. TCP goes to redsocks,
 * which hands it to the firewall's proxy as a CONNECT (the proxy reads the name from TLS); DNS goes
 * to the firewall; everything else from that uid is refused. The same pieces the managed boxes get
 * from the Ansible role (redirect.nft, redsocks, the resolved drop-in), matched on the uid instead
 * of the whole box, and written by this CLI.
 *
 * Fail-closed at boot: `controlclaw-capture.service` loads the rules before the network is up and
 * does not wait for the firewall. With the firewall or redsocks down, OpenClaw's connections fail.
 */
export const DIR = "/etc/controlclaw/capture";
export const TABLE = "controlclaw_capture";
export const REDSOCKS_PORT = 12346;
export const CAPTURE_UNIT = "controlclaw-capture.service";
export const REDSOCKS_UNIT = "controlclaw-redsocks.service";
export const RESOLVED_DROPIN = "/etc/systemd/resolved.conf.d/controlclaw.conf";
export const NFTABLES_DROPIN = "/etc/systemd/system/nftables.service.d/controlclaw.conf";
const HEADER = "# Written by controlclaw connect; removed by controlclaw disconnect.";

/** Removes the table, also when it is not there (`nft destroy` needs nftables 1.0.8). */
/** Remote mode's WireGuard interface. */
export const WG_IFACE = "cc-wg0";

export const REMOVE_NFT = `table inet ${TABLE}\ndelete table inet ${TABLE}\n`;

export interface NftOpts {
  uid: number;
  /** The firewall's DNS (IPv4). */
  dns: string;
  /**
   * TCP ports the uid may reach on loopback: redsocks, the vm-agent and OpenClaw's own (from
   * `loopbackPorts`). Nothing else: a root listener on loopback (sshd with the user's keys, a local
   * proxy) would be a way out.
   */
  loopbackPorts: string[];
  /** systemd-resolved's uid: its upstream queries may go only to the firewall's DNS. */
  resolveUid: number | null;
  /** Remote mode: the firewall is reached only through this WireGuard interface. */
  tunnel?: { iface: string; address: string; firewall: string };
  /**
   * The firewall's gates (3900 app connections, 3940 MCP servers): reached directly, not through
   * redsocks, since the proxy never connects to the firewall's own addresses. OpenClaw dials 3940,
   * the vm-agent's relay 3900.
   */
  gate?: string;
}

/** The vm-agent's relay for app connections, on loopback. */
export const CONNECTOR_RELAY_PORT = 3111;

/** The firewall's gate ports: app connections, MCP servers. */
export const GATE_PORTS = [3900, 3940];

export function captureNft(o: NftOpts): string {
  const { uid, dns } = o;
  const ports = o.loopbackPorts.join(", ");
  const resolve = o.resolveUid === null
    ? ""
    : `    # systemd-resolved asks only the firewall (not a DHCP server of some link, not DNS over TLS,
    # not the link by LLMNR or mDNS).
    meta skuid ${o.resolveUid} meta l4proto { tcp, udp } th dport { 53, 853 } ip daddr != ${dns} reject
    meta skuid ${o.resolveUid} meta nfproto ipv6 meta l4proto { tcp, udp } th dport { 53, 853 } reject
    meta skuid ${o.resolveUid} meta l4proto { tcp, udp } th dport { 5353, 5355 } reject
`;
  // Names go through resolved's stub, which asks only the firewall (above). Not DNATed: a query
  // from 127.x sent to another machine is dropped as martian.
  const stub = o.resolveUid === null ? "" : "    ip daddr { 127.0.0.53, 127.0.0.54 } meta l4proto { tcp, udp } th dport 53 accept\n";
  const gatePorts = GATE_PORTS.join(", ");
  const gateNat = o.gate ? `    meta skuid ${uid} ip daddr ${o.gate} tcp dport { ${gatePorts} } return\n` : "";
  const gateOut = o.gate ? `    ip daddr ${o.gate} tcp dport { ${gatePorts} } accept\n` : "";
  return `#!/usr/sbin/nft -f
${HEADER}
# Traffic from uid ${uid} (OpenClaw): TCP to redsocks, DNS to the firewall (or resolved's stub, which
# asks only the firewall), the rest refused.
table inet ${TABLE}
delete table inet ${TABLE}
table inet ${TABLE} {
  chain nat_out {
    type nat hook output priority -100; policy accept;
    meta skuid ${uid} meta nfproto ipv4 ip daddr != 127.0.0.0/8 meta l4proto { tcp, udp } th dport 53 dnat ip to ${dns}:53
    meta skuid ${uid} ip daddr 127.0.0.0/8 return
${gateNat}    meta skuid ${uid} meta nfproto ipv4 meta l4proto tcp redirect to :${REDSOCKS_PORT}
  }
  chain out {
    type filter hook output priority 0; policy accept;
${resolve}    # Only the uid's packets are judged; others, and the kernel's own (WireGuard's UDP, which has
    # no socket owner and would match neither skuid test), go on.
    meta skuid ${uid} jump uid_out
  }
  chain uid_out {
    ct state established,related accept
    # By address, not oif: a redirected packet still shows the outside interface here.
    ip daddr 127.0.0.0/8 tcp dport { ${ports} } accept
    ip6 daddr ::1 tcp dport { ${ports} } accept
    meta nfproto ipv4 ip daddr ${dns} meta l4proto { tcp, udp } th dport 53 accept
${gateOut}${stub}    meta l4proto tcp reject with tcp reset
    reject
  }
${tunnelChains(o)}}
`;
}

/**
 * Remote mode's two extra chains. After routing, with the interface final (NAT done): nothing for
 * the firewall's tunnel address leaves by another interface, whoever sends it, so with the tunnel
 * down OpenClaw's traffic (through redsocks), DNS and resolved's queries go nowhere. And the
 * vm-agent, on this machine's tunnel address, is reached only through the tunnel. What goes into the
 * tunnel leaves from this machine's tunnel address (DNS DNATed there would not).
 */
function tunnelChains(o: NftOpts): string {
  if (!o.tunnel) return "";
  const { iface, address, firewall } = o.tunnel;
  return `  chain tunnel_post {
    type filter hook postrouting priority 0; policy accept;
    ip daddr ${firewall} oifname != "${iface}" drop
  }
  chain tunnel_fwd {
    type filter hook forward priority 0; policy accept;
    # A container's traffic (Docker masquerades it on the way out) would reach the firewall as this
    # agent's: nothing forwarded goes into the tunnel.
    oifname "${iface}" drop
  }
  chain tunnel_snat {
    type nat hook postrouting priority 100; policy accept;
    # DNS DNATed into the tunnel keeps the source of the route it first took; the firewall takes
    # only this machine's tunnel address from it.
    oifname "${iface}" ip saddr != ${address} snat ip to ${address}
  }
  chain tunnel_in {
    type filter hook input priority 0; policy accept;
    ip daddr ${address} iifname != { "${iface}", "lo" } drop
  }
`;
}

/**
 * The loopback ports for `NftOpts.loopbackPorts`: redsocks, the vm-agent, and OpenClaw's own, as
 * OpenClaw 2026.10 derives them from the gateway's port (gw): browser control gw+2, the extension
 * relays gw+3 to gw+10, the default profile's CDP gw+11; and the CDP port each other browser
 * profile has in its config (OpenClaw picks one from gw+11 to gw+110 when the profile is made and
 * writes it there). With `profilePorts` null (a config that is not plain JSON, so its profiles
 * cannot be read) the whole range to gw+110 stays open, as before. Not the ephemeral range: a root
 * listener there would be a way out. OpenClaw's Codex relay, which listens on an ephemeral port,
 * does not work in host mode (README); nor does a browser profile made after connect, until
 * connect runs again.
 */
export function loopbackPorts(gatewayPort: number, profilePorts: number[] | null = []): string[] {
  const top = Math.min(gatewayPort + (profilePorts === null ? 110 : 11), 65535);
  const own = top > gatewayPort ? `${gatewayPort}-${top}` : String(gatewayPort);
  const extra = [...new Set(profilePorts ?? [])].filter((p) => Number.isInteger(p) && p > 0 && p <= 65535 && (p < gatewayPort || p > top)).sort((a, b) => a - b);
  // 3111: the vm-agent's relay for app connections (OpenClaw's MCP entry for them).
  return [String(REDSOCKS_PORT), String(AGENT_PORT), String(CONNECTOR_RELAY_PORT), own, ...extra.map(String)];
}

/**
 * The CDP ports of the browser profiles in OpenClaw's config (`browser.profiles.<name>.cdpPort`, or
 * the port of a loopback `cdpUrl`). `null` when the config is not plain JSON (JSON5): its profiles
 * cannot be read.
 */
export function profilePorts(configText: string | null): number[] | null {
  if (configText === null) return [];
  let cfg: unknown;
  try {
    cfg = JSON.parse(configText);
  } catch {
    return null;
  }
  const profiles = (cfg as { browser?: { profiles?: Record<string, { cdpPort?: unknown; cdpUrl?: unknown }> } })?.browser?.profiles ?? {};
  return Object.values(profiles).flatMap((p) => {
    if (typeof p?.cdpPort === "number") return [p.cdpPort];
    let u: URL | null = null;
    try {
      u = typeof p?.cdpUrl === "string" ? new URL(p.cdpUrl) : null;
    } catch {
      u = null;
    }
    return u && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname) && u.port ? [Number(u.port)] : [];
  });
}

export function redsocksConf(proxyIp: string, proxyPort: number): string {
  // redsocks takes C-style comments only.
  return `// ${HEADER.slice(2)}
base {
  log_debug = off;
  log_info = on;
  log = stderr;
  daemon = off;
  redirector = iptables;
  redsocks_conn_max = 2000;
}

redsocks {
  local_ip = 127.0.0.1;
  local_port = ${REDSOCKS_PORT};
  ip = ${proxyIp};
  port = ${proxyPort};
  type = http-connect;
}
`;
}

export function redsocksUnit(): string {
  return `${HEADER}
[Unit]
Description=ControlClaw: OpenClaw's TCP to the firewall's proxy
After=network.target

[Service]
# Its own uid, never OpenClaw's: its connections to the proxy are not caught again.
DynamicUser=yes
ExecStart=/usr/sbin/redsocks -c ${DIR}/redsocks.conf
Restart=always
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`;
}

export function captureUnit(nft: string): string {
  return `${HEADER}
[Unit]
Description=ControlClaw: capture rules for OpenClaw's user
DefaultDependencies=no
Before=network-pre.target shutdown.target
Wants=network-pre.target
# nftables.service flushes the whole ruleset: load after it at boot. Its drop-in
# (${NFTABLES_DROPIN}) loads ours again after each later start, restart or reload.
After=local-fs.target nftables.service
Conflicts=shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${nft} -f ${DIR}/capture.nft
ExecStop=${nft} -f ${DIR}/remove.nft

[Install]
WantedBy=multi-user.target
`;
}

/**
 * nftables.service runs `flush ruleset` on start, restart, reload and stop. This drop-in loads the
 * capture again after each, so `systemctl restart` or `stop nftables` does not silently open the uid.
 */
export function nftablesDropin(nft: string): string {
  return `${HEADER}
[Service]
ExecStartPost=-${nft} -f ${DIR}/capture.nft
ExecReload=-${nft} -f ${DIR}/capture.nft
ExecStopPost=-${nft} -f ${DIR}/capture.nft
`;
}

export function resolvedDropin(dns: string): string {
  // No LLMNR or mDNS: resolved would send a single-label or .local name onto the local link, a way
  // out for OpenClaw's user through the stub.
  return `${HEADER}\n[Resolve]\nDNS=${dns}\nDomains=~.\nLLMNR=no\nMulticastDNS=no\n`;
}

/**
 * A request made as OpenClaw's user: it can only have gone through the capture. Any HTTP answer
 * (also the firewall's 403) means the path works and the CA is trusted.
 */
export async function requestAs(sys: Sys, user: User): Promise<Check> {
  const r = await sys.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", "https://example.com/"], { user });
  if (r.code === 127) return { name: `request as ${user.name}`, ok: true, detail: "skipped (no curl)" };
  const code = r.stdout.trim();
  const ok = r.code === 0 && code !== "000";
  return { name: `request as ${user.name}`, ok, detail: ok ? `https://example.com answered ${code} through the firewall` : (r.stderr.trim() || `curl exit ${r.code}`) };
}

export const host: CaptureMode = {
  name: "host",
  protects:
    "limited: OpenClaw's user cannot reach the network except through the firewall, but anyone with root or sudo on this machine can remove the rules",
  blockers(f: Facts) {
    const out: string[] = [];
    if (!f.linux) out.push("needs Linux");
    if (!f.systemd) out.push("needs systemd");
    if (!f.root) out.push("needs root (run it with sudo)");
    if (!f.nft) out.push("needs nftables (apt-get install nftables)");
    if (!f.redsocks && !f.apt) out.push("needs redsocks, and apt-get is not here to install it");
    const runs = f.openclaw.install.runs.kind;
    if (runs === "not-found") out.push("no OpenClaw found on this machine");
    if (runs === "docker") out.push("OpenClaw runs in Docker: use --mode docker");
    const u = f.openclaw.user;
    if (u && u.uid !== 0 && f.escapeGroups.length) out.push(escapeGroupMessage(u, f.escapeGroups));
    // Fail closed: a user whose groups cannot be read may be in docker (or lxd, libvirt).
    if (u && u.uid !== 0 && f.groupsUnknown) out.push(`cannot read the groups of ${u.name} (id -nG failed), so cannot tell whether it can start containers that go around the rules`);
    if (f.resolved && f.resolveUid === null) {
      out.push("systemd-resolved runs, but there is no systemd-resolve user to limit to the firewall's DNS: resolved could still ask any DNS server");
    }
    if (runs !== "not-found" && f.openclaw.user?.uid === 0) out.push("OpenClaw runs as root: the rules would catch every root process. Run OpenClaw as its own user");
    return out;
  },
  async install(ctx: Ctx) {
    const { sys, rec, facts, user } = ctx;
    if (!user) throw new Error("no OpenClaw user");
    if (!ctx.firewall.dns) throw new Error("host mode needs the firewall's DNS address (--dns)");
    const notes: string[] = [];
    const proxy = splitHostPort(ctx.firewall.proxy, 8080);
    const proxyIp = await ipv4Of(proxy.host);
    const dns = await ipv4Of(ctx.firewall.dns);
    const nft = facts.nft ?? "/usr/sbin/nft";

    if (!facts.redsocks) {
      ctx.log("Installing redsocks");
      await aptInstall(sys, rec, "redsocks");
      // The package's own service is not used; ours runs with our config.
      await sys.run(["systemctl", "disable", "--now", "redsocks.service"]);
    }

    rec.onUndo("reload systemd", [["systemctl", "daemon-reload"]]);
    await rec.file(`${DIR}/redsocks.conf`, redsocksConf(proxyIp, proxy.port));
    await rec.file(`/etc/systemd/system/${REDSOCKS_UNIT}`, redsocksUnit());
    const nftText = captureNft({
      uid: user.uid,
      dns,
      loopbackPorts: loopbackPorts(ctx.install.gateway_port, profilePorts(ctx.install.config_file ? sys.read(ctx.install.config_file) : null)),
      resolveUid: facts.resolved ? facts.resolveUid : null,
      ...(ctx.tunnel ? { tunnel: { iface: WG_IFACE, address: ctx.tunnel.address, firewall: ctx.tunnel.firewall } } : {}),
      gate: proxyIp,
    });
    await rec.file(`${DIR}/capture.nft`, nftText);
    await rec.file(`${DIR}/remove.nft`, REMOVE_NFT);
    await rec.file(`/etc/systemd/system/${CAPTURE_UNIT}`, captureUnit(nft));
    await rec.file(NFTABLES_DROPIN, nftablesDropin(nft));
    // Stopping the unit removes the table (ExecStop); the script again in case the unit was gone.
    rec.onUndo("remove the capture rules", [["systemctl", "disable", "--now", CAPTURE_UNIT]]);
    // From the file, not stdin: nft refuses a socket as its input (Node's stdin for a child).
    rec.onUndo("remove the capture rules", [[nft, "-f", `${DIR}/remove.nft`]]);
    rec.onUndo("stop redsocks", [["systemctl", "disable", "--now", REDSOCKS_UNIT]]);
    await sys.run(["systemctl", "daemon-reload"]);
    for (const unit of [REDSOCKS_UNIT, CAPTURE_UNIT]) {
      const r = await sys.run(["systemctl", "enable", "--now", unit]);
      if (r.code !== 0) throw new Error(`could not start ${unit}: ${r.stderr.trim()}`);
    }
    // A service that fails at once is "active" for a moment, then restarts: look again.
    await sys.run(["sleep", "2"]);
    const rs = await sys.run(["systemctl", "show", "-p", "ActiveState,NRestarts", REDSOCKS_UNIT]);
    const prop = Object.fromEntries(rs.stdout.split("\n").map((l) => l.trim().split("=", 2) as [string, string]));
    if (prop.ActiveState !== "active" || prop.NRestarts !== "0") {
      throw new Error(`${REDSOCKS_UNIT} does not stay up (journalctl -u ${REDSOCKS_UNIT})`);
    }
    ctx.log(`Capture rules loaded for ${user.name} (uid ${user.uid})`);

    if (facts.resolved) {
      rec.onUndo("restart systemd-resolved", [["systemctl", "restart", "systemd-resolved"]]);
      await rec.file(RESOLVED_DROPIN, resolvedDropin(dns));
      await sys.run(["systemctl", "restart", "systemd-resolved"]);
      notes.push(`This machine's DNS now goes to the firewall (${dns}). If the firewall stops, DNS stops for every program here, not only OpenClaw.`);
    }

    await installSystemStore(sys, rec, ctx.caPem);
    const envNote = await installNodeEnv(sys, rec, ctx.install, user, ctx.caPath);
    if (envNote) notes.push(envNote);
    const nss = await installNss(sys, rec, user, ctx.caPath);
    if (nss) ctx.log(`CA added to ${nss} Chrome certificate store(s)`);

    ctx.log("Restarting OpenClaw");
    const restarted = await restartOpenClaw(sys, ctx.install, user);
    if (restarted) notes.push(restarted);
    return notes;
  },
  async status(sys: Sys, record: ConnectRecord) {
    const checks: Check[] = [];
    const table = await sys.run(["nft", "list", "table", "inet", TABLE]);
    checks.push({
      name: "capture rules",
      ok: table.code === 0,
      detail: table.code === 0 ? `loaded for uid ${record.user?.uid}` : `not loaded: OpenClaw's traffic is not captured (sudo systemctl restart ${CAPTURE_UNIT})`,
    });
    for (const unit of [REDSOCKS_UNIT, CAPTURE_UNIT]) {
      const r = await sys.run(["systemctl", "is-active", unit]);
      checks.push({ name: unit, ok: r.stdout.trim() === "active", detail: r.stdout.trim() || "unknown" });
    }
    if (record.firewall.dns) {
      const d = await dnsAnswers(record.firewall.dns);
      if (!d.ok) d.detail += ": DNS on this whole machine depends on it";
      checks.push(d);
    }
    if (record.user) checks.push(await requestAs(sys, record.user));
    return checks;
  },
};
