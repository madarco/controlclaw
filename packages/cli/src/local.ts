import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { AGENT_PORT, installAgent } from "./agent.js";
import { composeAtLeast, dockerTooOld, gatewayIsolated, ISOLATED_GATEWAY, PROBE, proxyEnv, q, subnetTaken } from "./capture/docker.js";
import { GATE_PORTS } from "./capture/host.js";
import type { CaptureMode } from "./capture/mode.js";
import { type Io, type PairNet, realNet } from "./commands.js";
import { findVmAgent } from "./openclaw.js";
import { vmAgentOrRelease } from "./release.js";
import { agentKeypair, caFingerprint, pair, unpair } from "./pair.js";
import type { Check } from "./probe.js";
import { type ConnectRecord, loadRecord, Recorder, undoAll } from "./state.js";
import { type Sys, userByUid } from "./sys.js";

/**
 * `controlclaw up --local` (plan §5, "One command, two shapes"): the firewall and OpenClaw as two
 * containers on this machine. OpenClaw is only on an internal network (`agents`), whose one other
 * member is the firewall: its proxy and DNS are OpenClaw's only way out, as in docker capture, with
 * the firewall container where the gate was. The firewall is also on a network of its own
 * (`outside`): its traffic out, and the panel and pairing, published on this machine's loopback,
 * which OpenClaw cannot reach. The firewall publishes OpenClaw's gateway port (CC_FORWARD), since
 * Docker publishes nothing from an internal network.
 *
 * It pairs itself: a code from the firewall with OpenClaw's fixed address, then the pairing, then
 * the vm-agent on this machine (as root, for the container) with the firewall's key and its id.
 */
export const PROJECT = "controlclaw-local";
export const DEFAULT_DIR = "/opt/controlclaw-local";
export const DEFAULT_OPENCLAW_IMAGE = "ghcr.io/openclaw/openclaw:2026.10.9";
export const AGENTS_SUBNET = "172.31.251.0/24";
export const OUTSIDE_SUBNET = "172.31.252.0/24";
export const FW_AGENTS_IP = "172.31.251.2";
export const OPENCLAW_IP = "172.31.251.10";
export const FW_OUTSIDE_IP = "172.31.252.2";
/**
 * This machine on the `outside` network (Docker gives a bridge's host the subnet's first address):
 * the vm-agent listens there, for the firewall alone. Not set in the Compose file: a changed network
 * there makes Compose refuse an existing install.
 */
export const HOST_OUTSIDE_IP = "172.31.252.1";
export const GATEWAY_PORT = 18789;
const AGENT_LISTEN = `${HOST_OUTSIDE_IP}:${AGENT_PORT}`;
export const OPENCLAW_CONTAINER = `${PROJECT}-openclaw-1`;
/** OpenClaw's user in its image: its state folders are given to it. */
const NODE_UID = 1000;

export interface UpOpts {
  firewallImage?: string;
  openclawImage?: string;
  dir?: string;
  name?: string;
  vmAgent?: string;
}

/**
 * Where OpenClaw reaches the firewall's gates: its own loopback. OpenClaw's proxy setting sends
 * everything but loopback to the proxy, which refuses the firewall's own address, so an MCP server at
 * the gate never started (matrix 2). A relay in OpenClaw's container puts the gates there; the gate
 * still sees OpenClaw's address. In the container itself, not a sidecar sharing its network: a
 * restart of OpenClaw (a secret, the emergency stop) leaves a sidecar on a network that is gone.
 */
export const GATE_ADDR = "127.0.0.1";
/** Where the relay is in OpenClaw's container. */
const GATE_RELAY = "/etc/controlclaw/gate-relay.mjs";

/**
 * The relay OpenClaw's container runs next to its gateway: each gate port, loopback to the firewall.
 * A failure is written to the container's log (`docker logs`), and a port it cannot listen on is
 * tried again every 5 s: it never dies quietly while the gateway runs on.
 */
export function gateRelayScript(): string {
  return [
    "// Written by controlclaw up --local: the firewall's gates on OpenClaw's loopback.",
    'import net from "node:net";',
    'const say = (m) => process.stderr.write(`[controlclaw gate-relay] ${m}\\n`);',
    'process.on("uncaughtException", (e) => say(`error: ${e?.message ?? e}`));',
    `for (const port of ${JSON.stringify(GATE_PORTS)}) {`,
    "  const server = net.createServer((c) => {",
    `    const u = net.connect(port, ${q(FW_AGENTS_IP)});`,
    "    const end = () => { c.destroy(); u.destroy(); };",
    '    u.on("error", (e) => { say(`${port}: the firewall: ${e.code ?? e.message}`); end(); });',
    '    c.on("error", end); c.on("close", end); u.on("close", end);',
    "    c.pipe(u).pipe(c);",
    "  });",
    `  const listen = () => server.listen(port, ${q(GATE_ADDR)});`,
    '  server.on("error", (e) => { say(`${port}: cannot listen (${e.code ?? e.message}); trying again in 5 s`); setTimeout(listen, 5000); });',
    '  server.on("listening", () => say(`${port}: listening`));',
    "  listen();",
    "}",
    "",
  ].join("\n");
}

/** The Compose file: what `up --local` runs. */
export function localCompose(o: { firewallImage: string; openclawImage: string; dir: string }): string {
  const proxy = `http://${FW_AGENTS_IP}:8080`;
  const oc = (k: string, v: string) => `      ${k}: ${q(v)}`;
  return [
    "# Written by controlclaw up --local; removed by controlclaw disconnect (the data stays).",
    `name: ${PROJECT}`,
    "services:",
    "  firewall:",
    `    image: ${q(o.firewallImage)}`,
    "    restart: unless-stopped",
    "    environment:",
    // A private address: the firewall starts its DNS for the agents.
    oc("CC_LISTEN", FW_AGENTS_IP),
    // The panel and pairing on the outside network only: OpenClaw, on the agents network, cannot
    // reach them. Published on this machine's loopback (below).
    oc("LOCAL_PANEL_BIND", `${FW_OUTSIDE_IP}:8800`),
    oc("LOCAL_PANEL_INSECURE", "1"),
    oc("PAIR_BIND", `${FW_OUTSIDE_IP}:8801`),
    oc("PAIR_PROXY_ADDR", `${FW_AGENTS_IP}:8080`),
    oc("PAIR_DNS_ADDR", FW_AGENTS_IP),
    oc("CC_FORWARD", `${GATEWAY_PORT}=${OPENCLAW_IP}:${GATEWAY_PORT}`),
    // The relay, the pages and webhooks on the outside network too; the connector gates on the
    // agents network, where OpenClaw dials them.
    oc("CC_FORWARD_BIND", FW_OUTSIDE_IP),
    oc("INGRESS_BIND", FW_OUTSIDE_IP),
    oc("CONNECTOR_GATE_BIND", FW_AGENTS_IP),
    "    volumes:",
    "      - firewall:/opt/controlclaw",
    "    tmpfs:",
    "      - /run/mitm/config:uid=10001,gid=10001,mode=0700,size=16m",
    "    networks:",
    "      agents:",
    `        ipv4_address: ${FW_AGENTS_IP}`,
    "      outside:",
    `        ipv4_address: ${FW_OUTSIDE_IP}`,
    "    ports:",
    `      - ${q(`127.0.0.1:${GATEWAY_PORT}:${GATEWAY_PORT}`)} # OpenClaw's gateway and Control UI`,
    `      - ${q("127.0.0.1:8800:8800")} # the firewall's panel`,
    `      - ${q("127.0.0.1:8801:8801")} # pairing`,
    `      - ${q("127.0.0.1:8790:8790")} # the firewall's pages and webhooks`,
    "  openclaw:",
    `    image: ${q(o.openclawImage)}`,
    "    restart: unless-stopped",
    "    init: true",
    "    depends_on: [firewall]",
    // The gates' relay, then the gateway: both in this container, so a restart restarts both.
    `    command: ["sh", "-c", ${q(`node ${GATE_RELAY} & exec node dist/index.js gateway --bind lan --port ${GATEWAY_PORT}`)}]`,
    "    env_file: [.env]",
    "    environment:",
    oc("HOME", "/home/node"),
    oc("OPENCLAW_HOME", "/home/node"),
    oc("OPENCLAW_STATE_DIR", "/home/node/.openclaw"),
    oc("OPENCLAW_CONFIG_PATH", "/home/node/.openclaw/openclaw.json"),
    oc("OPENCLAW_CONFIG_DIR", "/home/node/.openclaw"),
    oc("OPENCLAW_WORKSPACE_DIR", "/home/node/.openclaw/workspace"),
    oc("OPENCLAW_GATEWAY_PORT", String(GATEWAY_PORT)),
    ...proxyEnv(proxy, FW_AGENTS_IP).map(([k, v]) => oc(k, v)),
    "    volumes:",
    `      - ${q(`${join(o.dir, "openclaw")}:/home/node/.openclaw`)}`,
    `      - ${q(`${join(o.dir, "openclaw-secrets")}:/home/node/.config/openclaw`)}`,
    `      - ${q(`${join(o.dir, "ca.crt")}:/etc/controlclaw/ca.crt:ro`)}`,
    `      - ${q(`${join(o.dir, "gate-relay.mjs")}:${GATE_RELAY}:ro`)}`,
    `      - ${q(`${join(o.dir, "ca-bundle.crt")}:/etc/ssl/certs/ca-certificates.crt:ro`)}`,
    `    dns: [${q(FW_AGENTS_IP)}]`,
    "    cap_drop: [NET_RAW, NET_ADMIN]",
    "    security_opt: [\"no-new-privileges:true\"]",
    "    networks:",
    "      agents:",
    `        ipv4_address: ${OPENCLAW_IP}`,
    "    healthcheck:",
    "      test: [\"CMD\", \"node\", \"dist/docker-healthcheck.js\"]",
    "      interval: 15s",
    "      start_period: 60s",
    "networks:",
    "  agents:",
    "    internal: true",
    ...ISOLATED_GATEWAY,
    "    ipam:",
    `      config: [{ subnet: ${q(AGENTS_SUBNET)} }]`,
    "  outside:",
    "    ipam:",
    `      config: [{ subnet: ${q(OUTSIDE_SUBNET)} }]`,
    "volumes:",
    "  firewall:",
    "",
  ].join("\n");
}

const compose = (dir: string, ...args: string[]) => ["docker", "compose", "-p", PROJECT, "--project-directory", dir, "-f", join(dir, "compose.yaml"), ...args];

async function hasImage(sys: Sys, image: string): Promise<boolean> {
  return (await sys.run(["docker", "image", "inspect", "--format", "{{.Id}}", image])).code === 0;
}

async function waitFor(sys: Sys, what: string, tries: number, test: () => Promise<boolean>): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (await test()) return;
    await sys.run(["sleep", "2"]);
  }
  throw new Error(`${what} did not come up`);
}

export async function up(sys: Sys, io: Io, o: UpOpts, net: PairNet = realNet): Promise<number> {
  const tmp: { dir: string | null } = { dir: null };
  try {
    return await upWith(sys, io, o, net, tmp);
  } finally {
    // A downloaded vm-agent is installed by now, or not needed: its folder goes either way.
    if (tmp.dir) sys.remove(tmp.dir);
  }
}

async function upWith(sys: Sys, io: Io, o: UpOpts, net: PairNet, tmp: { dir: string | null }): Promise<number> {
  if (sys.euid !== 0) {
    io.err("up --local needs root (sudo): it runs Docker and installs the vm-agent for the container.");
    return 1;
  }
  if (!o.firewallImage) {
    io.err("up --local needs --firewall-image <image>: there is no published image yet. Build one with standalone/docker/build.sh (controlclaw-firewall:dev-amd64), or docker load its tar.");
    return 2;
  }
  const existing = loadRecord(sys);
  if (existing) {
    io.err(`Already connected (${existing.mode}). Run controlclaw disconnect first.`);
    return 1;
  }
  const dir = o.dir ?? DEFAULT_DIR;
  const ocImage = o.openclawImage ?? DEFAULT_OPENCLAW_IMAGE;
  const v = await sys.run(["docker", "compose", "version", "--short"]);
  if (v.code !== 0 || !composeAtLeast(v.stdout.trim(), 2, 24, 4)) {
    io.err(`up --local needs Docker with Compose 2.24.4 or newer (found: ${v.stdout.trim() || "none"}).`);
    return 1;
  }
  const server = await sys.run(["docker", "version", "--format", "{{.Server.Version}}"]);
  if (server.code !== 0) {
    io.err(`Docker does not answer: ${server.stderr.trim()}`);
    return 1;
  }
  const old = dockerTooOld(server.stdout.trim());
  if (old) {
    io.err(`up --local ${old}.`);
    return 1;
  }
  if (!(await hasImage(sys, o.firewallImage))) {
    io.err(`No image ${o.firewallImage} here: build it (standalone/docker/build.sh) or docker load it first.`);
    return 1;
  }
  for (const [net_, subnet] of [[`${PROJECT}_agents`, AGENTS_SUBNET], [`${PROJECT}_outside`, OUTSIDE_SUBNET]] as const) {
    const taken = await subnetTaken(sys, net_, subnet);
    if (taken) {
      io.err(`Docker network ${taken} already uses ${subnet}, which up --local needs.`);
      return 1;
    }
  }
  // Last of the checks: it may download about 20 MB.
  const agent = await vmAgentOrRelease(await findVmAgent(sys, o.vmAgent), io);
  if (!agent) return 1;
  tmp.dir = agent.downloaded;
  const vmAgent = agent.path;
  const root = userByUid(sys, 0) ?? { name: "root", uid: 0, gid: 0, home: "/root" };

  const record: ConnectRecord = {
    version: 1,
    mode: "local",
    at: new Date().toISOString(),
    user: null,
    firewall: { url: "http://127.0.0.1:8801/", proxy: `${FW_AGENTS_IP}:8080`, dns: FW_AGENTS_IP },
    container: OPENCLAW_CONTAINER,
    cli: ["docker", "exec", "-i", OPENCLAW_CONTAINER, "node", "dist/index.js"],
    ca: join(dir, "ca.crt"),
    steps: [],
  };
  const rec = new Recorder(sys, record);
  rec.start();
  const log = (l: string) => io.out(`  ${l}`);
  let paired = false;
  try {
    if (!(await hasImage(sys, ocImage))) {
      io.out(`Pulling ${ocImage}`);
      const p = await sys.run(["docker", "pull", "-q", ocImage], { timeoutMs: 900_000 });
      if (p.code !== 0) throw new Error(`docker pull ${ocImage}: ${p.stderr.trim()}`);
    }
    io.out(`Writing ${dir}`);
    const token = randomBytes(24).toString("hex");
    await rec.file(join(dir, "compose.yaml"), localCompose({ firewallImage: o.firewallImage, openclawImage: ocImage, dir }));
    await rec.file(join(dir, ".env"), `# Written by controlclaw up --local.\nOPENCLAW_GATEWAY_TOKEN=${token}\n`, { mode: 0o600 });
    // OpenClaw's state: its user's, kept by disconnect (as is the firewall's volume).
    for (const d of ["openclaw", "openclaw/workspace", "openclaw-secrets"]) {
      const made = await sys.run(["install", "-d", "-m", "0700", "-o", String(NODE_UID), "-g", String(NODE_UID), join(dir, d)]);
      if (made.code !== 0) throw new Error(`could not make ${join(dir, d)}: ${made.stderr.trim()}`);
    }

    io.out("Starting the firewall");
    rec.onUndo("stop the containers (their data stays)", [compose(dir, "down")]);
    const fw = await sys.run(compose(dir, "up", "-d", "firewall"), { timeoutMs: 300_000 });
    if (fw.code !== 0) throw new Error(`docker compose up firewall: ${fw.stderr.trim()}`);
    await waitFor(sys, "the firewall", 45, async () => {
      const r = await sys.run(compose(dir, "exec", "-T", "-u", "controlclaw", "firewall", "sh", "-c", "test -s /opt/controlclaw/state/local.db && test -s /opt/controlclaw/keys/vm_public_key.pem"));
      return r.code === 0;
    });

    io.out("Pairing OpenClaw with it");
    const name = o.name ?? "openclaw";
    // --replace: a machine set up again keeps OpenClaw at the same address.
    const made = await sys.run(compose(dir, "exec", "-T", "-u", "controlclaw", "firewall", "mitm-agent", "pair-code", "--name", name, "--address", OPENCLAW_IP, "--replace"));
    const code = made.stdout.trim().split("\n")[0] ?? "";
    if (made.code !== 0 || !code) throw new Error(`mitm-agent pair-code: ${made.stderr.trim() || "no code"}`);
    const keypair = agentKeypair();
    const unpairSecret = randomBytes(32).toString("hex");
    // The pairing listener comes up a moment after the database: tried again while it cannot be reached.
    let p: Awaited<ReturnType<typeof pair>> | null = null;
    for (let i = 0; !p; i++) {
      try {
        p = await pair(record.firewall.url, code, { publicKey: keypair.publicPem, name, source: "127.0.0.1", unpairSecret, agentListen: AGENT_LISTEN }, net.post);
      } catch (e) {
        if (i >= 15 || !(e as Error).message.startsWith("could not reach")) throw e;
        await sys.run(["sleep", "2"]);
      }
    }
    paired = true;
    record.firewall.agentId = p.agentId;
    record.firewall.unpair = unpairSecret;
    log(`agent ${p.agentId} (${p.name}), known to the firewall by ${p.address}`);
    log(`the firewall's CA: SHA-256 ${caFingerprint(p.caPem)}`);

    // The CA for Node, and the image's own bundle with it for everything else.
    const bundle = await sys.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", ocImage, "/etc/ssl/certs/ca-certificates.crt"]);
    if (bundle.code !== 0) throw new Error(`could not read ${ocImage}'s CA bundle: ${bundle.stderr.trim()}`);
    await rec.file(join(dir, "ca.crt"), `${p.caPem.trim()}\n`);
    await rec.file(join(dir, "gate-relay.mjs"), gateRelayScript());
    await rec.file(join(dir, "ca-bundle.crt"), `${bundle.stdout.trimEnd()}\n${p.caPem.trim()}\n`);

    if (!sys.exists(join(dir, "openclaw/openclaw.json"))) {
      io.out("Setting up OpenClaw");
      const onboard = await sys.run(
        compose(dir, "run", "--rm", "--no-deps", "-T", "--entrypoint", "node", "openclaw", "dist/index.js", "onboard", "--non-interactive", "--accept-risk",
          "--skip-health", "--mode", "local", "--auth-choice", "skip", "--gateway-auth", "token", "--gateway-token-ref-env", "OPENCLAW_GATEWAY_TOKEN",
          "--skip-channels", "--no-install-daemon"),
        { timeoutMs: 300_000 },
      );
      if (onboard.code !== 0) throw new Error(`openclaw onboard: ${(onboard.stderr || onboard.stdout).trim().split("\n").pop()}`);
    }
    // The Control UI is opened at this machine's loopback (or an SSH tunnel to it), and OpenClaw sees
    // it through the firewall's relay: it accepts the page only from an origin it is told.
    const origins = { gateway: { controlUi: { allowedOrigins: [`http://127.0.0.1:${GATEWAY_PORT}`, `http://localhost:${GATEWAY_PORT}`] } } };
    const patched = await sys.run(compose(dir, "run", "--rm", "--no-deps", "-T", "--entrypoint", "node", "openclaw", "dist/index.js", "config", "patch", "--stdin"), {
      input: JSON.stringify(origins),
      timeoutMs: 300_000,
    });
    if (patched.code !== 0) throw new Error(`openclaw config patch: ${(patched.stderr || patched.stdout).trim().split("\n").pop()}`);
    io.out("Starting OpenClaw");
    const oc = await sys.run(compose(dir, "up", "-d", "openclaw"), { timeoutMs: 300_000 });
    if (oc.code !== 0) throw new Error(`docker compose up openclaw: ${oc.stderr.trim()}`);
    // A first start sets up its plugins: up to about four minutes.
    await waitFor(sys, "OpenClaw's gateway", 120, async () => {
      const r = await sys.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", OPENCLAW_CONTAINER]);
      return r.stdout.trim() === "healthy";
    });

    io.out("Installing the vm-agent");
    const paths = await installAgent(sys, rec, {
      binary: vmAgent,
      user: root,
      firewallUrl: record.firewall.url,
      firewallKey: p.firewallPublicKey,
      container: OPENCLAW_CONTAINER,
      agentId: p.agentId,
      keypair,
      // On the host's side of the `outside` network, where the firewall's container reaches it;
      // OpenClaw, on the internal network only, cannot.
      listen: AGENT_LISTEN,
      allowFrom: [FW_OUTSIDE_IP],
      gate: GATE_ADDR,
      after: "docker.service",
    });
    log(`${paths.bin}, config ${paths.config}`);

    io.out("");
    for (const c of await local.status(sys, record)) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
    const logs = await sys.run(compose(dir, "logs", "--no-color", "firewall"));
    const setup = /setup token \(POST \/api\/setup\): ([0-9a-f]+)/.exec(logs.stdout)?.[1];
    io.out("");
    io.out(`OpenClaw:  http://127.0.0.1:${GATEWAY_PORT}/#token=${token}`);
    io.out(`Firewall:  http://127.0.0.1:8800${setup ? `  (first sign-in: the setup token ${setup})` : ""}`);
    io.out("           From another machine: ssh -L 8800:127.0.0.1:8800 -L 18789:127.0.0.1:18789 <this machine>");
    // A new firewall: no admin yet, and every request blocked.
    if (setup) io.out("! The firewall blocks everything until you add rules in its panel (Internet access): allow your model provider first.");
    io.out(`Undo it with: controlclaw disconnect (the data in ${dir} and the firewall's volume stay)`);
    return 0;
  } catch (e) {
    io.err(`up --local failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    // The firewall forgets the agent while it still runs; then the rest goes.
    if (paired) await unpair(record.firewall.url, record.firewall.agentId ?? "", record.firewall.unpair ?? "", net.post);
    await undoAll(sys, record, io.err);
    return 1;
  }
}

/** For `status`, `disconnect` and doctor: the shape `up --local` makes, not a capture `connect` installs. */
export const local: CaptureMode = {
  name: "local",
  protects: "strong: OpenClaw runs in a container whose only way out is the firewall container (controlclaw up --local)",
  blockers(f) {
    const out: string[] = [];
    if (!f.root) out.push("needs root (run it with sudo)");
    if (!f.docker?.ok) out.push("needs Docker");
    else if (!f.docker.compose || !composeAtLeast(f.docker.compose, 2, 24, 4)) out.push("needs Compose 2.24.4 or newer");
    out.push("made by controlclaw up --local, not connect");
    return out;
  },
  async install() {
    throw new Error("use controlclaw up --local");
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

