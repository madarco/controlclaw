import { isIPv4 } from "node:net";
import { dirname, join } from "node:path";
import type { Facts } from "../doctor.js";
import { type Check, dnsAnswers, splitHostPort } from "../probe.js";
import { type ConnectRecord, stateDir } from "../state.js";
import type { Sys } from "../sys.js";
import { GATE_PORTS } from "./host.js";
import type { CaptureMode, Ctx } from "./mode.js";

/**
 * Docker: OpenClaw's gateway container is moved onto a Compose network with `internal: true`. It
 * has no route out, so the only way to the internet is the gate container, which sits on that
 * network and the normal one and relays to the firewall: its proxy port and its DNS. OpenClaw and
 * every Node child are pointed at the proxy (OPENCLAW_PROXY_URL, HTTP(S)_PROXY); anything that
 * ignores it (a direct IP, another DNS server, a raw socket) has nowhere to go.
 *
 * Docker publishes no ports for a container that is only on an internal network, so the gate also
 * publishes the gateway's old ports and relays them in. Later (`up --local`) the firewall container
 * itself takes the gate's place on the network.
 *
 * Restored at boot by Docker: the network and the override are persistent, and Compose's restart
 * policy brings both containers back the same way.
 */
export const DIR = "/etc/controlclaw/docker";
export const OVERRIDE = `${DIR}/compose.controlclaw.yml`;
export const BUNDLE = `${DIR}/ca-bundle.crt`;
/** The override and the CA bundle: in /etc as root, else (`up` by a user who can use Docker) in its config folder. */
export function dockerFiles(sys: Sys): { override: string; bundle: string } {
  if (sys.euid === 0) return { override: OVERRIDE, bundle: BUNDLE };
  const dir = join(stateDir(sys), "docker");
  return { override: join(dir, "compose.controlclaw.yml"), bundle: join(dir, "ca-bundle.crt") };
}
export const SUBNET = "172.31.250.0/24";
export const GATE_IP = "172.31.250.2";
export const GATEWAY_IP = "172.31.250.10";
export const GATE_SERVICE = "controlclaw-gate";
export const GATE_IMAGE = "alpine/socat:1.8.0.3";
/** Where the CA is inside the gateway container. */
export const CONTAINER_CA = "/etc/controlclaw/ca.crt";
/** Run in the gateway container (NODE_USE_ENV_PROXY is set there): prints "HTTP <status>". */
export const PROBE = `fetch("https://example.com/").then(r => console.log("HTTP " + r.status), e => console.log("failed: " + (e.cause?.code ?? e.message)))`;

export interface ComposeInfo {
  project: string;
  workingDir: string;
  files: string[];
  service: string;
  /** The gateway's published TCP ports: host side ("ip:port" or "port") → container port. */
  ports: { host: string; container: number }[];
  /** What would let the gateway out of the internal network: a socket, privileges, capabilities. */
  escapes: string[];
}

interface Inspected {
  Config?: { Labels?: Record<string, string> };
  Mounts?: { Source?: string; Destination?: string }[];
  HostConfig?: {
    PortBindings?: Record<string, { HostIp?: string; HostPort?: string }[] | null>;
    Privileged?: boolean;
    CapAdd?: string[] | null;
    NetworkMode?: string;
  };
}

const SOCKET = /(docker|containerd|podman|crio|cri-dockerd)\.sock$|^\/run\/(docker|containerd|podman)\b|^\/var\/run\/(docker|containerd|podman)\b/;
/** Host folders that hold a container runtime's socket. */
const SOCKET_DIRS = ["/", "/run", "/var/run", "/var", "/run/user", "/var/run/user"];
/** A user's runtime folder (rootless docker, podman), or anything in it. */
const USER_RUNTIME = /^\/(var\/)?run\/user\/\d+(\/|$)/;
const NET_CAPS = ["ALL", "NET_ADMIN", "NET_RAW", "SYS_ADMIN"];

/** The ways out of the internal network a container has, from `docker inspect`. */
export function escapesOf(c: Inspected): string[] {
  const out: string[] = [];
  for (const m of c.Mounts ?? []) {
    const src = (m.Source ?? "").replace(/\/+$/, "") || "/";
    if (SOCKET.test(src) || SOCKET.test(m.Destination ?? "") || SOCKET_DIRS.includes(src) || USER_RUNTIME.test(src)) {
      out.push(`it mounts ${m.Source} (a container runtime can start containers that are not on the internal network)`);
    }
  }
  if (c.HostConfig?.Privileged) out.push("it is privileged");
  const caps = (c.HostConfig?.CapAdd ?? []).map((x) => x.toUpperCase().replace(/^CAP_/, "")).filter((x) => NET_CAPS.includes(x));
  if (caps.length) out.push(`it has ${caps.join(", ")}`);
  const net = c.HostConfig?.NetworkMode ?? "";
  if (net === "host" || net.startsWith("container:")) out.push(`its network mode is ${net}`);
  return out;
}

/** The Compose project behind a container, from `docker inspect`'s labels. */
export function parseInspect(raw: string): ComposeInfo | null {
  let c: Inspected;
  try {
    c = (JSON.parse(raw) as Inspected[])[0]!;
  } catch {
    return null;
  }
  const l = c?.Config?.Labels ?? {};
  const project = l["com.docker.compose.project"];
  const workingDir = l["com.docker.compose.project.working_dir"];
  const files = l["com.docker.compose.project.config_files"];
  const service = l["com.docker.compose.service"];
  if (!project || !workingDir || !files || !service) return null;
  const ports: ComposeInfo["ports"] = [];
  for (const [key, binds] of Object.entries(c.HostConfig?.PortBindings ?? {})) {
    const [port, proto] = key.split("/");
    if (proto !== "tcp") continue;
    for (const b of binds ?? []) {
      if (!b.HostPort) continue;
      // An IPv6 address in brackets, as Compose takes it: `[::1]:18789`.
      const ip = b.HostIp?.includes(":") ? `[${b.HostIp}]` : b.HostIp;
      ports.push({ host: ip ? `${ip}:${b.HostPort}` : b.HostPort, container: Number(port) });
    }
  }
  return { project, workingDir, files: files.split(","), service, ports, escapes: escapesOf(c) };
}

/** A loopback address means the gate itself, not this machine. */
function isLoopback(host: string): boolean {
  return host === "localhost" || /^127\./.test(host) || host === "::1";
}

export function q(s: string): string {
  return JSON.stringify(s);
}

export function gateScript(proxy: { host: string; port: number }, dns: string | null, info: ComposeInfo): string {
  const relays = [`socat TCP-LISTEN:8080,fork,reuseaddr TCP:${proxy.host}:${proxy.port}`];
  if (dns) {
    relays.push(`socat UDP-LISTEN:53,fork,reuseaddr UDP:${dns}:53`, `socat TCP-LISTEN:53,fork,reuseaddr TCP:${dns}:53`);
  }
  // The firewall's gates (app connections, MCP servers), where the proxy is.
  for (const port of GATE_PORTS) relays.push(`socat TCP-LISTEN:${port},fork,reuseaddr TCP:${proxy.host}:${port}`);
  for (const p of info.ports) relays.push(`socat TCP-LISTEN:${p.container},fork,reuseaddr TCP:${GATEWAY_IP}:${p.container}`);
  return `${relays.map((r) => `${r} &`).join(" ")} wait`;
}

/**
 * What a captured OpenClaw container gets: the firewall's proxy for OpenClaw's own proxy setting,
 * for Node (`NODE_USE_ENV_PROXY`) and for other programs, and the CA for Node and the system store.
 */
export function proxyEnv(proxyUrl: string, gate?: string): [string, string][] {
  // The firewall's gates are dialled directly: the proxy never connects to the firewall itself.
  const direct = ["localhost", "127.0.0.1", "::1", ...(gate ? [gate] : [])].join(",");
  return [
    ["OPENCLAW_PROXY_URL", proxyUrl],
    ["HTTP_PROXY", proxyUrl],
    ["HTTPS_PROXY", proxyUrl],
    ["http_proxy", proxyUrl],
    ["https_proxy", proxyUrl],
    ["NO_PROXY", direct],
    ["no_proxy", direct],
    ["NODE_USE_ENV_PROXY", "1"],
    ["NODE_EXTRA_CA_CERTS", CONTAINER_CA],
    ["SSL_CERT_FILE", "/etc/ssl/certs/ca-certificates.crt"],
  ];
}

export interface HostFiles {
  /** The CA on this machine, mounted at CONTAINER_CA. */
  ca: string;
  bundle: string;
}

const ROOT_FILES: HostFiles = { ca: CONTAINER_CA, bundle: BUNDLE };

export function overrideYaml(info: ComposeInfo, proxy: { host: string; port: number }, dns: string | null, files: HostFiles = ROOT_FILES): string {
  const env = proxyEnv(`http://${GATE_IP}:8080`, GATE_IP);
  const clash = info.ports.find((p) => p.container === 8080 || p.container === 53 || GATE_PORTS.includes(p.container));
  if (clash) throw new Error(`the gateway publishes port ${clash.container}, which the gate uses for the firewall`);
  const loop = [proxy.host, dns ?? ""].find(isLoopback);
  if (loop) {
    throw new Error(`${loop} is the gate itself, not this machine: a firewall here must listen on the docker0 address (172.17.0.1), and --proxy and --dns name it`);
  }
  return [
    "# Written by controlclaw connect; removed by controlclaw disconnect.",
    "# OpenClaw's gateway on an internal network; the gate is its only way out.",
    "services:",
    `  ${info.service}:`,
    "    ports: !reset []",
    "    networks: !override",
    "      controlclaw:",
    `        ipv4_address: ${GATEWAY_IP}`,
    `    dns: [${q(GATE_IP)}]`,
    "    environment:",
    ...env.map(([k, v]) => `      ${k}: ${q(v)}`),
    ...caVolumes(files),
    `  ${GATE_SERVICE}:`,
    `    image: ${GATE_IMAGE}`,
    "    restart: unless-stopped",
    `    entrypoint: ["/bin/sh", "-c"]`,
    `    command: [${q(gateScript(proxy, dns, info))}]`,
    ...(info.ports.length ? ["    ports:", ...info.ports.map((p) => `      - ${q(`${p.host}:${p.container}`)}`)] : []),
    "    networks:",
    "      default: {}",
    "      controlclaw:",
    `        ipv4_address: ${GATE_IP}`,
    "networks:",
    "  controlclaw:",
    "    internal: true",
    ...ISOLATED_GATEWAY,
    "    ipam:",
    "      config:",
    `        - subnet: ${SUBNET}`,
    "",
  ].join("\n");
}

function caVolumes(files: HostFiles): string[] {
  return [
    "    volumes:",
    `      - ${q(`${files.ca}:${CONTAINER_CA}:ro`)}`,
    `      - ${q(`${files.bundle}:/etc/ssl/certs/ca-certificates.crt:ro`)}`,
  ];
}

/**
 * The firewall's own network on this machine (`controlclaw up`): the gateway joins it, and the
 * firewall's container, its only other member, is its proxy and DNS. No gate: the firewall
 * publishes the gateway's ports itself (CC_FORWARD).
 */
export interface FirewallNet {
  /** The Docker network, made by the firewall's Compose project. */
  network: string;
  /** The firewall's address on it. */
  firewall: string;
  /** The gateway's address on it, the one the firewall knows it by. */
  gateway: string;
}

export function overrideOnFirewallNet(info: ComposeInfo, net: FirewallNet, files: HostFiles): string {
  const env = proxyEnv(`http://${net.firewall}:8080`, net.firewall);
  return [
    "# Written by controlclaw up; removed by controlclaw disconnect.",
    "# OpenClaw's gateway on the firewall's internal network; the firewall is its only way out.",
    "services:",
    `  ${info.service}:`,
    "    ports: !reset []",
    "    networks: !override",
    "      controlclaw:",
    `        ipv4_address: ${net.gateway}`,
    `    dns: [${q(net.firewall)}]`,
    "    environment:",
    ...env.map(([k, v]) => `      ${k}: ${q(v)}`),
    ...caVolumes(files),
    "networks:",
    "  controlclaw:",
    "    external: true",
    `    name: ${q(net.network)}`,
    "",
  ].join("\n");
}

/** Their compose files and ours, for COMPOSE_FILE (paths relative to the project when they are inside it). */
export function composeFileValue(info: ComposeInfo, override: string = OVERRIDE): string {
  const rel = (f: string) => (f.startsWith(`${info.workingDir}/`) ? f.slice(info.workingDir.length + 1) : f);
  return [...info.files.map(rel), override].join(":");
}

function composeArgv(info: ComposeInfo, override: string | null): string[] {
  const files = override ? [...info.files, override] : info.files;
  return ["docker", "compose", "-p", info.project, "--project-directory", info.workingDir, ...files.flatMap((f) => ["-f", f])];
}

/** Another network that already holds `subnet`, by name. */
export async function subnetTaken(sys: Sys, ours: string, subnet: string = SUBNET): Promise<string | null> {
  const ids = (await sys.run(["docker", "network", "ls", "-q"])).stdout.split("\n").filter(Boolean);
  if (!ids.length) return null;
  const r = await sys.run(["docker", "network", "inspect", ...ids]);
  try {
    const nets = JSON.parse(r.stdout) as { Name: string; IPAM?: { Config?: { Subnet?: string }[] } }[];
    return nets.find((n) => n.Name !== ours && (n.IPAM?.Config ?? []).some((c) => c.Subnet === subnet))?.Name ?? null;
  } catch {
    return null;
  }
}

/**
 * An internal network still gives the host an address on its bridge (its gateway), and the host
 * takes in what comes to it there: any service on 0.0.0.0 (sshd, a resolver, a dev server) would be
 * a way out. Docker 28 can leave the bridge with no address on the host.
 */
export const ISOLATED_GATEWAY = [
  // No IPv6 either: a daemon that turns it on for new networks would give the host an IPv6 address there.
  "    enable_ipv6: false",
  "    driver_opts:",
  "      com.docker.network.bridge.gateway_mode_ipv4: isolated",
];
export const DOCKER_MIN_MAJOR = 28;

/** Docker's major version, from `docker version`'s server version. */
export function dockerMajor(version: string | null | undefined): number {
  return Number(/^(\d+)\./.exec(version ?? "")?.[1] ?? 0);
}

/** Why this Docker (its server version) is too old for an internal network the host stays out of. */
export function dockerTooOld(version: string | null | undefined): string | null {
  if (dockerMajor(version) >= DOCKER_MIN_MAJOR) return null;
  return `needs Docker ${DOCKER_MIN_MAJOR} or newer (found ${version || "none"}): an older one gives the host an address on the internal network, where its services would be a way out`;
}

/** Whether a network leaves the host no address on its bridge. */
export async function gatewayIsolated(sys: Sys, network: string): Promise<Check> {
  const r = await sys.run(["docker", "network", "inspect", "-f", '{{index .Options "com.docker.network.bridge.gateway_mode_ipv4"}}', network]);
  if (r.code !== 0) return { name: "host unreachable from it", ok: false, detail: `no network ${network} (not running?)` };
  const mode = r.stdout.trim();
  return {
    name: "host unreachable from it",
    ok: mode === "isolated",
    detail: mode === "isolated" ? `${network} gives the host no address` : `${network} gives the host an address: its services on 0.0.0.0 are reachable (disconnect, then connect again)`,
  };
}

/** What docker mode needs besides root: a Docker that can keep the host off an internal network, and OpenClaw in it. */
export function dockerNeeds(f: Facts): string[] {
  const out: string[] = [];
  if (!f.docker?.ok) out.push("needs Docker");
  else if (!f.docker.compose || !composeAtLeast(f.docker.compose, 2, 24, 4)) out.push("needs Docker Compose 2.24.4 or newer");
  const old = f.docker?.ok ? dockerTooOld(f.docker.version) : null;
  if (old) out.push(old);
  if (f.openclaw.install.runs.kind !== "docker") out.push("OpenClaw does not run in a Docker container here");
  return out;
}

/**
 * The gateway's Compose project, checked: refused when it could leave the internal network, or
 * when other services of the project run with it (they would lose it).
 */
export async function gatewayProject(sys: Sys, container: string): Promise<ComposeInfo> {
  const info = parseInspect((await sys.run(["docker", "inspect", "--", container])).stdout);
  if (!info) throw new Error(`${container} was not started with Docker Compose: docker mode needs its compose file`);
  if (info.escapes.length) {
    throw new Error(`${container} could leave the internal network: ${info.escapes.join("; ")}. Remove that from its compose file first`);
  }
  // The gateway leaves its networks: services that talk to it there would lose it.
  const others = (await sys.run(["docker", "ps", "--filter", `label=com.docker.compose.project=${info.project}`, "--format", "{{.Names}}"])).stdout
    .split("\n")
    .filter((n) => n && n !== container);
  if (others.length) {
    throw new Error(`docker mode takes the gateway off its network, and these services of ${info.project} run with it: ${others.join(", ")}`);
  }
  // Compose must read the project's files (its compose files, its .env) to move the gateway, and
  // again to put it back: a user in the docker group may not (a root project's .env is 0600).
  const cfg = await sys.run([...composeArgv(info, null), "config", "-q"]);
  if (cfg.code !== 0) {
    throw new Error(`docker compose cannot read ${info.project}'s files here (${cfg.stderr.trim().split("\n").pop()}): run this with sudo, or as the user who owns ${info.workingDir}`);
  }
  return info;
}

export const docker: CaptureMode = {
  name: "docker",
  protects: "strong: the gateway container has no route out; its only way to the internet is the firewall",
  // Root, or a user who can use Docker (the docker group, which can do what root does).
  blockers(f: Facts) {
    return dockerNeeds(f);
  },
  async install(ctx: Ctx) {
    const { sys, rec } = ctx;
    if (ctx.install.runs.kind !== "docker") throw new Error("OpenClaw does not run in Docker");
    const container = ctx.install.runs.container;
    const info = await gatewayProject(sys, container);
    const net = ctx.firewallNet;
    if (!net) {
      const taken = await subnetTaken(sys, `${info.project}_controlclaw`);
      if (taken) throw new Error(`the Docker network ${taken} already uses ${SUBNET}`);
    }
    const { override, bundle: bundlePath } = dockerFiles(sys);
    const files: HostFiles = { ca: ctx.caPath, bundle: bundlePath };

    // The image's own CA bundle plus ours, mounted over the system store: no root needed inside.
    const bundle = await sys.run(["docker", "exec", container, "cat", "/etc/ssl/certs/ca-certificates.crt"]);
    if (bundle.code !== 0 || !bundle.stdout.includes("BEGIN CERTIFICATE")) {
      throw new Error(`could not read the CA bundle in ${container}: is it running?`);
    }
    await rec.file(bundlePath, `${bundle.stdout.trimEnd()}\n${ctx.caPem.trim()}\n`);
    await rec.file(override, net ? overrideOnFirewallNet(info, net, files) : overrideYaml(info, splitHostPort(ctx.firewall.proxy, 8080), ctx.firewall.dns, files));

    // Only the gateway (and the gate) are touched. The gate goes first, while the override that
    // names it is still there. The firewall's network is its own project's: not removed here.
    rec.onUndo(
      "put the gateway back on its own network",
      net
        ? [[...composeArgv(info, null), "up", "-d", info.service]]
        : [
            [...composeArgv(info, override), "rm", "-s", "-f", GATE_SERVICE],
            [...composeArgv(info, null), "up", "-d", info.service],
            ["docker", "network", "rm", `${info.project}_controlclaw`],
          ],
    );
    ctx.log(`Moving ${container} onto the internal network`);
    const up = await sys.run([...composeArgv(info, override), "up", "-d", info.service, ...(net ? [] : [GATE_SERVICE])], { timeoutMs: 600_000 });
    if (up.code !== 0) throw new Error(`docker compose up failed: ${up.stderr.trim().split("\n").slice(-3).join(" ")}`);
    const notes = [`OpenClaw's container now reaches the internet only through the firewall. Its ports are published by ${net ? "the firewall's container" : GATE_SERVICE}.`];

    // `docker compose up` in their folder (an OpenClaw update) must keep the override: Compose
    // reads COMPOSE_FILE from the project's .env when no -f is given.
    const env = join(info.workingDir, ".env");
    const before = sys.read(env);
    const keep = `Otherwise the next "docker compose up" there puts the gateway back on its open network (controlclaw status shows it).`;
    if (before !== null && /^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=/m.test(before)) {
      notes.push(`Your ${env} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR, so it is left as it is: add ${override} to COMPOSE_FILE. ${keep}`);
    } else if (!canWrite(sys, env)) {
      notes.push(`This user cannot write ${env}: add COMPOSE_FILE=${composeFileValue(info, override)} to it yourself. ${keep}`);
    } else {
      const line = `COMPOSE_FILE=${composeFileValue(info, override)}`;
      await rec.file(env, `${before === null ? "" : `${before.trimEnd()}\n`}# Added by controlclaw; removed by controlclaw disconnect.\n${line}\n`);
      notes.push(`"docker compose up" in ${info.workingDir} keeps the capture: ${env} now names the override in COMPOSE_FILE. With -f, add -f ${override}; without it the gateway goes back on its open network (controlclaw status shows it).`);
    }
    return notes;
  },
  async status(sys: Sys, record: ConnectRecord) {
    const checks: Check[] = [];
    const c = record.container ?? "";
    const nets = await sys.run(["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", "--", c]);
    let names: string[] = [];
    try {
      names = Object.keys(JSON.parse(nets.stdout) as object);
    } catch {
      /* not running */
    }
    const want = record.up?.network;
    const only = names.length === 1 && (want ? names[0] === want : names[0]!.endsWith("_controlclaw"));
    checks.push({ name: "gateway network", ok: only, detail: names.length ? `${c} is on ${names.join(", ")}` : `${c} is not running` });
    if (only) checks.push(await gatewayIsolated(sys, names[0]!));
    if (!want) {
      const gate = await sys.run(["docker", "ps", "-q", "--filter", `label=com.docker.compose.service=${GATE_SERVICE}`]);
      checks.push({ name: GATE_SERVICE, ok: gate.stdout.trim() !== "", detail: gate.stdout.trim() ? "running" : "not running" });
    }
    // A request from inside: any HTTP answer means it went through the firewall (there is no other way).
    const probe = await sys.run(["docker", "exec", c, "node", "-e", PROBE], { timeoutMs: 30_000 });
    const answer = probe.stdout.trim();
    checks.push({ name: "request from the gateway", ok: /^HTTP \d+/.test(answer), detail: answer || "no answer" });
    // The firewall's DNS on its own network is out of this machine's reach: the request above used it.
    if (!want && record.firewall.dns && isIPv4(record.firewall.dns)) checks.push(await dnsAnswers(record.firewall.dns));
    return checks;
  },
};

/** Whether this process may write `path` (as root, always): its owner, or the folder's when it is not there. */
function canWrite(sys: Sys, path: string): boolean {
  if (sys.euid === 0) return true;
  const st = sys.stat(path) ?? sys.stat(dirname(path));
  return st?.uid === sys.euid;
}

export function composeAtLeast(version: string, major: number, minor: number, patch: number): boolean {
  const m = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(version);
  if (!m) return false;
  const have = [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)];
  const want = [major, minor, patch];
  for (let i = 0; i < 3; i++) if (have[i] !== want[i]) return have[i]! > want[i]!;
  return true;
}
