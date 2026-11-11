import { gatewayIsolated, ISOLATED_GATEWAY, PROBE, q } from "./capture/docker.js";
import type { CaptureMode } from "./capture/mode.js";
import type { Check } from "./probe.js";
import type { Sys } from "./sys.js";

/**
 * The firewall's container networks and addresses, which `install` uses, and OpenClaw's image and
 * setup, which `openclaw install` uses.
 *
 * Also what `up --local` made before 0.10.1, which `status`, `disconnect` and `uninstall` still
 * handle: the firewall and OpenClaw as two containers of one Compose project (`controlclaw-local`,
 * in `/opt/controlclaw-local`), OpenClaw only on the internal `agents` network, the vm-agent as root.
 * `up --all` now runs `install`, `openclaw install` and `connect` instead.
 */
export const PROJECT = "controlclaw-local";
export const DEFAULT_OPENCLAW_IMAGE = "ghcr.io/openclaw/openclaw:2026.10.9";
export const AGENTS_SUBNET = "172.31.251.0/24";
export const OUTSIDE_SUBNET = "172.31.252.0/24";
export const FW_AGENTS_IP = "172.31.251.2";
export const FW_OUTSIDE_IP = "172.31.252.2";
/**
 * This machine on the `outside` network (Docker gives a bridge's host the subnet's first address):
 * the vm-agent listens there, for the firewall alone. Not set in the Compose file: a changed network
 * there makes Compose refuse an existing install.
 */
export const HOST_OUTSIDE_IP = "172.31.252.1";
export const GATEWAY_PORT = 18789;
export const OPENCLAW_CONTAINER = `${PROJECT}-openclaw-1`;
/** OpenClaw's user in its image: its state folders are given to it. */
export const NODE_UID = 1000;

/**
 * The firewall's service, for `install`: on `outside` (and `agents` when an OpenClaw
 * container is behind it), at fixed addresses; its panel, pairing and pages published on this
 * machine's loopback only. `fw` is where agents reach its proxy, DNS and gates.
 */
export function firewallService(o: {
  image: string;
  agents: boolean;
  /** Where its gates listen, and the address agents are given for them. */
  gate: string;
  /** The proxy's and DNS's address pairing tells agents. */
  pairAt: string;
  /** Ports it relays to OpenClaw's container (CC_FORWARD): its port → that address:port. */
  forwards?: { port: number; to: string }[];
  /** More ports it publishes on this machine: `spec` as Compose takes it, and what it is. */
  publish?: { spec: string; what: string }[];
}): string[] {
  const fw = o.agents ? FW_AGENTS_IP : FW_OUTSIDE_IP;
  const env = (k: string, v: string) => `      ${k}: ${q(v)}`;

  const forwards = o.forwards ?? [];
  return [
    "  firewall:",
    `    image: ${q(o.image)}`,
    "    restart: unless-stopped",
    "    environment:",
    // A private address: the firewall starts its DNS (on its container's addresses).
    env("CC_LISTEN", fw),
    // The panel and pairing on the outside network only: OpenClaw (on the agents network, or captured
    // on this machine) cannot reach them. Published on this machine's loopback (below).
    env("LOCAL_PANEL_BIND", `${FW_OUTSIDE_IP}:8800`),
    env("LOCAL_PANEL_INSECURE", "1"),
    env("PAIR_BIND", `${FW_OUTSIDE_IP}:8801`),
    env("PAIR_PROXY_ADDR", `${o.pairAt}:8080`),
    env("PAIR_DNS_ADDR", o.pairAt),
    ...(forwards.length ? [env("CC_FORWARD", forwards.map((f) => `${f.port}=${f.to}`).join(","))] : []),
    // The relay, the pages and webhooks on the outside network too; the connector gates where
    // OpenClaw dials them.
    env("CC_FORWARD_BIND", FW_OUTSIDE_IP),
    env("INGRESS_BIND", FW_OUTSIDE_IP),
    env("CONNECTOR_GATE_BIND", o.gate),
    "    volumes:",
    "      - firewall:/opt/controlclaw",
    "    tmpfs:",
    "      - /run/mitm/config:uid=10001,gid=10001,mode=0700,size=16m",
    "    networks:",
    ...(o.agents ? ["      agents:", `        ipv4_address: ${FW_AGENTS_IP}`] : []),
    "      outside:",
    `        ipv4_address: ${FW_OUTSIDE_IP}`,
    "    ports:",
    `      - ${q("127.0.0.1:8800:8800")} # the firewall's panel`,
    `      - ${q("127.0.0.1:8801:8801")} # pairing`,
    `      - ${q("127.0.0.1:8790:8790")} # the firewall's pages and webhooks`,
    ...(o.publish ?? []).map((p) => `      - ${q(p.spec)} # ${p.what}`),
  ];
}

/** The firewall's networks: `outside`, and the internal `agents` with no address for this machine. */
export function firewallNetworks(agents: boolean): string[] {
  return [
    "networks:",
    ...(agents ? ["  agents:", "    internal: true", ...ISOLATED_GATEWAY, "    ipam:", `      config: [{ subnet: ${q(AGENTS_SUBNET)} }]`] : []),
    "  outside:",
    "    ipam:",
    `      config: [{ subnet: ${q(OUTSIDE_SUBNET)} }]`,
    "volumes:",
    "  firewall:",
  ];
}

/**
 * OpenClaw in a container, set up once (`onboard`, with the gateway token from `.env`), and its
 * Control UI's allowed origins at each run: the UI is opened at this machine's loopback (or an SSH
 * tunnel to it), and OpenClaw sees the browser through a relay: it accepts the page only from an
 * origin it is told.
 */
export async function setUpOpenClaw(sys: Sys, compose: (...a: string[]) => string[], service: string, first: boolean): Promise<void> {
  const cli = (...a: string[]) => compose("run", "--rm", "--no-deps", "-T", "--entrypoint", "node", service, "dist/index.js", ...a);
  if (first) {
    const onboard = await sys.run(
      cli("onboard", "--non-interactive", "--accept-risk", "--skip-health", "--mode", "local", "--auth-choice", "skip", "--gateway-auth", "token",
        "--gateway-token-ref-env", "OPENCLAW_GATEWAY_TOKEN", "--skip-channels", "--no-install-daemon"),
      { timeoutMs: 300_000 },
    );
    if (onboard.code !== 0) throw new Error(`openclaw onboard: ${(onboard.stderr || onboard.stdout).trim().split("\n").pop()}`);
  }
  const origins = { gateway: { controlUi: { allowedOrigins: [`http://127.0.0.1:${GATEWAY_PORT}`, `http://localhost:${GATEWAY_PORT}`] } } };
  const patched = await sys.run(cli("config", "patch", "--stdin"), { input: JSON.stringify(origins), timeoutMs: 300_000 });
  if (patched.code !== 0) throw new Error(`openclaw config patch: ${(patched.stderr || patched.stdout).trim().split("\n").pop()}`);
}

/** The environment OpenClaw's image wants, as OpenClaw's own compose file sets it. */
export const OPENCLAW_ENV: [string, string][] = [
  ["HOME", "/home/node"],
  ["OPENCLAW_HOME", "/home/node"],
  ["OPENCLAW_STATE_DIR", "/home/node/.openclaw"],
  ["OPENCLAW_CONFIG_PATH", "/home/node/.openclaw/openclaw.json"],
  ["OPENCLAW_CONFIG_DIR", "/home/node/.openclaw"],
  ["OPENCLAW_WORKSPACE_DIR", "/home/node/.openclaw/workspace"],
  ["OPENCLAW_GATEWAY_PORT", String(GATEWAY_PORT)],
];

/** For `status` and `disconnect`: the shape `up --local` made before 0.10.1, not a capture `connect` installs. Not in doctor's list. */
export const local: CaptureMode = {
  name: "local",
  protects: "strong: OpenClaw runs in a container whose only way out is the firewall container (up --local before 0.10.1)",
  blockers() {
    return ["made by up --local before 0.10.1, not connect"];
  },
  async install() {
    throw new Error("up --local before 0.10.1 made this: controlclaw up --all now runs install, openclaw install and connect");
  },
  async status(sys: Sys) {
    const checks: Check[] = [];
    for (const svc of ["firewall", "openclaw"]) {
      const r = await sys.run(["docker", "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", `${PROJECT}-${svc}-1`]);
      const s = r.stdout.trim();
      checks.push({ name: svc, ok: r.code === 0 && s.startsWith("running"), detail: s || "not running" });
    }
    const nets = await sys.run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", OPENCLAW_CONTAINER]);
    let names: string[] = [];
    try {
      names = Object.keys(JSON.parse(nets.stdout) as object);
    } catch {
      /* not running */
    }
    checks.push({ name: "OpenClaw's network", ok: names.length === 1 && names[0] === `${PROJECT}_agents`, detail: names.join(", ") || "none" });
    checks.push(await gatewayIsolated(sys, `${PROJECT}_agents`));
    // Any HTTP answer (the firewall's 403 too) means the way through the firewall works.
    const probe = await sys.run(["docker", "exec", OPENCLAW_CONTAINER, "node", "-e", PROBE], { timeoutMs: 30_000 });
    const answer = probe.stdout.trim();
    checks.push({ name: "request from OpenClaw", ok: /^HTTP \d+/.test(answer), detail: answer || "no answer" });
    return checks;
  },
};

