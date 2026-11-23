import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { join } from "node:path";
import {
  BRAIN_CONTAINER,
  BRAIN_MODELS,
  BRAIN_PROJECT,
  BRAIN_SUBNET,
  type BrainEgress,
  brainCompose,
  GBRAIN_PORT,
  helpers,
  imageFiles,
  imageTag,
} from "./brain-image.js";
import { ISOLATED_GATEWAY, subnetTaken } from "./capture/docker.js";
import { WG_IFACE } from "./capture/host.js";
import type { Ctx } from "./capture/mode.js";
import { remote, WG_UNIT } from "./capture/remote.js";
import type { Io, PairNet } from "./commands.js";
import type { Facts } from "./doctor.js";
import { composeIn, dockerProblem, listening, pairHere, rootlessDocker, waitFor } from "./fwcontainer.js";
import { FW_AGENTS_IP, FW_OUTSIDE_IP, HOST_OUTSIDE_IP } from "./local.js";
import { agentKeypair, caFingerprint, normalizeCode, type Paired, pair, pairUrl, unpair, wgKeypair } from "./pair.js";
import { type Check, ipv4Of, splitHostPort } from "./probe.js";
import { releaseFile, vmAgentOrRelease } from "./release.js";
import { type Firewall, loadFirewall, Recorder, stateDir, type Step, undoAll } from "./state.js";
import { type Sys, userByName } from "./sys.js";
import { UP_PROJECT } from "./up.js";

/**
 * The brain on a standalone firewall (docs/standalone/brain.md, docs/plans/standalone-brain.md part
 * A): GBrain, and the vm-agent in brain mode next to it, which the firewall drives with its signed
 * calls (who may use the brain, its model key, the emergency stop's lock).
 *
 * - `brain install`: GBrain and Postgres in Docker (`brain-image.ts`), with no way out but the
 *   firewall, and the vm-agent on this machine as root (it runs GBrain's helpers with `docker exec`).
 * - `brain connect`: a GBrain already running here as a systemd service: the vm-agent and GBrain's
 *   helpers next to it, and a drop-in on GBrain's unit that sends its traffic to the firewall and
 *   allows it nowhere else (systemd's IP filter).
 * - Both pair with the firewall as the brain (`role: gbrain`): with no code typed for the firewall
 *   `controlclaw install` runs on this machine, else with a code over WireGuard, as `connect --mode
 *   remote` (the firewall calls the vm-agent only on its own machine or through the tunnel).
 * - Each step is recorded in `brain.json`, as `connect.json`; `brain disconnect` undoes them.
 */
export const BRAIN_DIR = "/etc/controlclaw/brain";
/** The vm-agent's own folder: its keys, sessions, the gate's tokens, the pages' hand-over folder. */
export const BRAIN_STATE = "/var/lib/controlclaw/brain";
const LIB = "/usr/local/lib/controlclaw/brain";
const BIN = `${LIB}/vm-agent`;
const FILES_UI = `${LIB}/files-ui`;
export const BRAIN_UNIT = "controlclaw-brain-agent.service";
const UNIT_PATH = `/etc/systemd/system/${BRAIN_UNIT}`;
const CONFIG = `${BRAIN_DIR}/agent.json`;
/** Where the firewall calls the brain's vm-agent on this machine: 3102 is an OpenClaw's (`up --all`). */
export const BRAIN_AGENT_PORT = 3103;
/** Remote: the firewall calls a tunnel address on 3100, as for a remote OpenClaw. */
const REMOTE_AGENT_PORT = 3100;
/** The brain's address on the firewall's `agents` network (`brain install` next to `install`): its identity at the proxy. */
export const BRAIN_FW_IP = "172.31.251.20";
const PAIR_URL = "http://127.0.0.1:8801/";
const PANEL_URL = "http://localhost:8800";
/** Compose's `.env`: the database's password, kept with the volumes. */
const DB_ENV = `${BRAIN_DIR}/.env`;

export interface BrainRecord {
  version: 1;
  kind: "install" | "connect";
  at: string;
  firewall: Firewall;
  /** `install`: the image built. */
  image?: string;
  /** `connect`: GBrain's systemd unit. */
  unit?: string;
  steps: Step[];
}

export function brainRecordPath(sys: Sys): string {
  return join(stateDir(sys), "brain.json");
}

export function loadBrain(sys: Sys): BrainRecord | null {
  const raw = sys.read(brainRecordPath(sys));
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as BrainRecord;
    return r.version === 1 ? r : null;
  } catch {
    return null;
  }
}

export interface BrainOpts {
  /** A firewall elsewhere: its pairing address. Without it, the firewall installed here. */
  firewall?: string;
  code?: string;
  codeFile?: string;
  name?: string;
  vmAgent?: string;
  /** The brain's pages (`files-ui`, from apps/saas/scripts/build-box-files.mjs). */
  pagesUi?: string;
  /** The name the firewall relays the brain's pages under (`PUT /api/brain/pages` there). */
  pagesName?: string;
  /** `connect`: GBrain's unit, its port. */
  gbrainUnit?: string;
  gbrainPort?: string;
}

/** What the vm-agent in brain mode reads (rust/bins/vm-agent/src/gbrain/standalone.rs). */
export function brainAgentConfig(o: {
  listen: string;
  agentId: string;
  firewallUrl: string;
  firewallKey: string;
  allowFrom: string[];
  port: number;
  exec: string[];
  /** The name the firewall relays the pages under; the brain's name on the firewall otherwise. */
  pagesName?: string;
  name?: string;
}): string {
  const host = o.listen.slice(0, o.listen.lastIndexOf(":"));
  return `${JSON.stringify(
    {
      mode: "brain",
      listen: o.listen,
      state_dir: BRAIN_STATE,
      agent_id: o.agentId,
      firewall: { url: o.firewallUrl, public_key: o.firewallKey, hostnames: [host], allow_from: o.allowFrom },
      gbrain: { port: o.port, exec: o.exec, panel_url: PANEL_URL, ...(o.pagesName ? { pages_name: o.pagesName } : {}), ...(o.name ? { name: o.name } : {}) },
    },
    null,
    2,
  )}\n`;
}

export function brainAgentUnit(o: { after?: string; filesUi: boolean }): string {
  return [
    "# Written by controlclaw brain; removed by controlclaw brain disconnect.",
    "[Unit]",
    "Description=ControlClaw agent (brain)",
    `After=network-online.target${o.after ? ` ${o.after}` : ""}`,
    "",
    "[Service]",
    `Environment=CC_AGENT_CONFIG=${CONFIG}`,
    `Environment=HOME=${BRAIN_STATE}`,
    ...(o.filesUi ? [`Environment=FILES_UI_DIR=${FILES_UI}`] : []),
    `ExecStart=${BIN}`,
    "Restart=always",
    "RestartSec=5",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
}

/**
 * The drop-in on a connected GBrain's own unit: its model key and base URL (`cc-gbrain-key` writes
 * them), the firewall's CA and proxy, and no address but loopback and the firewall's.
 */
export function gbrainDropin(o: { keyFile: string; ca: string; proxy: string; allow: string[] }): string {
  const url = `http://${o.proxy}`;
  return [
    "# Written by controlclaw brain connect; removed by controlclaw brain disconnect.",
    "[Service]",
    `EnvironmentFile=-${o.keyFile}`,
    `Environment=NODE_EXTRA_CA_CERTS=${o.ca}`,
    `Environment=HTTP_PROXY=${url} HTTPS_PROXY=${url} http_proxy=${url} https_proxy=${url}`,
    "Environment=NO_PROXY=localhost,127.0.0.1,::1 no_proxy=localhost,127.0.0.1,::1",
    // The brain's way out is the firewall: anything else it dials is refused by the kernel.
    "IPAddressDeny=any",
    `IPAddressAllow=localhost ${o.allow.join(" ")}`,
    "",
  ].join("\n");
}

function needRoot(sys: Sys, io: Io, what: string): boolean {
  if (sys.euid === 0) return true;
  io.err(`brain ${what} installs a system service and runs Docker as root: run it with sudo.`);
  return false;
}

/** The pages' bundle: `--pages-ui`, else this release's `files-ui.tar.gz`, unpacked; null when there is none. */
async function pagesBundle(sys: Sys, io: Io, given: string | undefined, tmp: string[]): Promise<string | null> {
  if (given) {
    if (!sys.exists(join(given, "brain.js"))) throw new Error(`--pages-ui: ${given} has no brain.js (apps/saas/scripts/build-box-files.mjs builds it)`);
    return given;
  }
  const tar = await releaseFile("files-ui.tar.gz");
  if (!tar) {
    io.out("  ! No pages bundle in this build (--pages-ui <dir>): the brain's pages will not load.");
    return null;
  }
  const dir = join(tar, "..", "files-ui");
  tmp.push(join(tar, ".."));
  const x = await sys.run(["tar", "-xzf", tar, "-C", join(tar, "..")]);
  if (x.code !== 0 || !sys.exists(join(dir, "brain.js"))) throw new Error(`could not unpack the pages: ${x.stderr.trim()}`);
  return dir;
}

/** The pairing code, never from the command line (see `connect`). */
async function codeFor(sys: Sys, io: Io, o: BrainOpts): Promise<string | null> {
  let code: string | null | undefined;
  if (o.codeFile) code = sys.read(o.codeFile)?.trim();
  else if (o.code && o.code !== "-") {
    io.err("Not on the command line: every user of this machine can read it. Type it when asked, or use --code - (stdin) or --code-file <file>.");
    return null;
  } else code = io.ask ? (await io.ask(o.code === "-" ? "" : "Pairing code for the brain (pair-code --role gbrain): "))?.trim() : null;
  if (!code || !normalizeCode(code)) {
    io.err("The pairing code is 12 letters and digits, like 4F7K-92QD-XM3P. Make one for the brain: in the panel, or mitm-agent pair-code --role gbrain.");
    return null;
  }
  return code;
}

/** Where the brain stands toward its firewall, once paired. */
interface Placement {
  paired: Paired;
  keypair: { privatePem: string; publicPem: string };
  unpairSecret: string;
  firewall: Firewall;
  /** Where the vm-agent listens, who may call it, and the gate. */
  listen: string;
  allowFrom: string[];
  /** The firewall's proxy, as the brain dials it (`ip:port`), and its DNS. */
  proxy: string;
  dns: string;
  /** Remote: the tunnel the vm-agent starts after. */
  after?: string;
}

/**
 * Pairs as the brain: with the firewall `controlclaw install` runs here (no code), or over WireGuard
 * with a typed code (`remote` brings the tunnel up and records it). `address` is the brain's
 * identity at the proxy when the firewall is here.
 */
async function place(sys: Sys, io: Io, rec: Recorder<BrainRecord>, o: BrainOpts, net: PairNet, address: string, name: string): Promise<Placement | null> {
  if (!o.firewall) {
    const fw = loadFirewall(sys);
    if (!fw || fw.kind !== "docker" || !fw.project || !fw.dir) {
      io.err("No firewall in a container on this machine (controlclaw install). For a firewall elsewhere: --firewall http://<its address>:8801, with a code made for the brain (WireGuard).");
      return null;
    }
    io.out("Pairing the brain with the firewall on this machine");
    const listen = `${HOST_OUTSIDE_IP}:${BRAIN_AGENT_PORT}`;
    // Never `--replace`: for a brain it would also take the place of a brain paired elsewhere, and this
    // machine's address (`brain connect`) may be an OpenClaw's in host mode.
    const p = await pairHere(sys, composeIn(fw.project, fw.dir), { name, address, listen, url: PAIR_URL, role: "gbrain", replace: false }, net);
    const proxyIp = address === BRAIN_FW_IP ? FW_AGENTS_IP : FW_OUTSIDE_IP;
    return {
      ...p,
      firewall: { url: PAIR_URL, proxy: `${proxyIp}:8080`, dns: proxyIp, agentId: p.paired.agentId, unpair: p.unpairSecret },
      listen,
      allowFrom: [FW_OUTSIDE_IP],
      proxy: `${proxyIp}:8080`,
      dns: proxyIp,
    };
  }
  let url: URL;
  try {
    url = new URL(o.firewall);
  } catch {
    io.err(`--firewall: not a URL: ${o.firewall}`);
    return null;
  }
  // One tunnel per machine: an OpenClaw connected in remote mode has it already.
  if (sys.exists(`/etc/wireguard/${WG_IFACE}.conf`)) {
    io.err(`This machine has a tunnel to a firewall already (${WG_IFACE}, connect --mode remote). A brain on it needs a machine of its own, or the firewall on this machine.`);
    return null;
  }
  const code = await codeFor(sys, io, o);
  if (!code) return null;
  const keypair = agentKeypair();
  const wg = wgKeypair();
  const unpairSecret = randomBytes(32).toString("hex");
  const ip = await net.ipv4(url.hostname);
  const source = await net.source(ip);
  const base = new URL(url.toString());
  if (base.protocol === "http:") base.hostname = ip;
  io.out(`Pairing the brain with ${pairUrl(base.toString())}, from ${source}`);
  const paired = await pair(base.toString(), code, { publicKey: keypair.publicPem, name, source, unpairSecret, wgPublicKey: wg.publicKey, role: "gbrain" }, net.post);
  const firewall: Firewall = { url: url.toString(), proxy: paired.proxy ?? "", dns: paired.dns, agentId: paired.agentId, unpair: unpairSecret };
  rec.record.firewall = firewall;
  rec.start();
  if (!paired.wg) throw new Error("the firewall gave no tunnel: a brain on another machine needs a firewall with WireGuard (install.sh --wireguard)");
  const t = paired.wg;
  const hasWg = (await sys.run(["sh", "-c", "command -v wg"])).code === 0;
  const hasApt = (await sys.run(["sh", "-c", "command -v apt-get"])).code === 0;
  // Remote mode's tunnel, exactly as `connect --mode remote` brings it up.
  const ctx = {
    sys,
    rec: rec as unknown as Ctx["rec"],
    facts: { wireguard: hasWg ? "wg" : null, apt: hasApt } as unknown as Facts,
    log: (l: string) => io.out(`  ${l}`),
    tunnel: { address: t.address, firewall: t.firewallAddress, firewallPublicKey: t.firewallPublicKey, endpoint: t.endpoint, privateKey: wg.privateKey },
  } as unknown as Ctx;
  await remote.prepare!(ctx);
  const proxy = splitHostPort(paired.proxy ?? `${t.firewallAddress}:8080`, 8080);
  return {
    paired,
    keypair,
    unpairSecret,
    firewall,
    listen: `${t.address}:${REMOTE_AGENT_PORT}`,
    allowFrom: [t.firewallAddress],
    proxy: `${proxy.host}:${proxy.port}`,
    dns: paired.dns ?? t.firewallAddress,
    after: WG_UNIT,
  };
}

/** The vm-agent in brain mode: its binary, keys, config, the pages' bundle and its unit, started. */
async function installBrainAgent(
  sys: Sys,
  rec: Recorder<BrainRecord>,
  o: { binary: string; filesUi: string | null; placement: Placement; port: number; exec: string[]; pagesName?: string },
): Promise<void> {
  const p = o.placement;
  rec.onUndo("remove the brain's vm-agent and its pages", [["rm", "-rf", "--", LIB]]);
  const mk = await sys.run(["install", "-d", "-m", "0755", LIB]);
  if (mk.code !== 0) throw new Error(`could not make ${LIB}: ${mk.stderr.trim()}`);
  const cp = await sys.run(["install", "-m", "0755", o.binary, BIN]);
  if (cp.code !== 0) throw new Error(`could not install the vm-agent: ${cp.stderr.trim()}`);
  if (o.filesUi) {
    const ui = await sys.run(["cp", "-R", o.filesUi, FILES_UI]);
    if (ui.code !== 0) throw new Error(`could not install the pages: ${ui.stderr.trim()}`);
  }
  rec.onUndo("remove the brain's vm-agent state", [["rm", "-rf", "--", BRAIN_STATE]]);
  await rec.file(join(BRAIN_STATE, "vm_private_key.pem"), p.keypair.privatePem, { mode: 0o600 });
  await rec.file(join(BRAIN_STATE, "vm_public_key.pem"), p.keypair.publicPem, { mode: 0o644 });
  await rec.file(
    CONFIG,
    brainAgentConfig({
      listen: p.listen,
      agentId: p.paired.agentId,
      firewallUrl: p.firewall.url,
      firewallKey: p.paired.firewallPublicKey,
      allowFrom: p.allowFrom,
      port: o.port,
      exec: o.exec,
      pagesName: o.pagesName,
      name: p.paired.name,
    }),
    { mode: 0o600 },
  );
  rec.onUndo("reload systemd", [["systemctl", "daemon-reload"]]);
  await rec.file(UNIT_PATH, brainAgentUnit({ after: p.after, filesUi: !!o.filesUi }), { mode: 0o644 });
  rec.onUndo("stop the brain's vm-agent", [["systemctl", "disable", "--now", BRAIN_UNIT]]);
  await sys.run(["systemctl", "daemon-reload"]);
  const up = await sys.run(["systemctl", "enable", "--now", BRAIN_UNIT]);
  if (up.code !== 0) throw new Error(`could not start the brain's vm-agent: ${up.stderr.trim()}`);
  // One that exits at once (a config it refuses) is "activating" between restarts: it must stay up.
  await sys.run(["sleep", "3"]);
  const st = await sys.run(["systemctl", "show", "-p", "ActiveState,NRestarts", BRAIN_UNIT]);
  if (!/ActiveState=active/.test(st.stdout) || !/NRestarts=0/.test(st.stdout)) {
    const log = await sys.run(["journalctl", "-u", BRAIN_UNIT, "-n", "3", "--no-pager", "-o", "cat"]);
    throw new Error(`the brain's vm-agent does not stay up: ${log.stdout.trim().split("\n").pop() ?? ""}`);
  }
}

/** The parent folders this makes, removed again on undo when they are empty: recorded first, so they go last. */
function recordParents(sys: Sys, rec: Recorder<BrainRecord>): void {
  for (const d of ["/usr/local/lib/controlclaw", "/var/lib/controlclaw"]) {
    if (!sys.exists(d)) rec.onUndo(`remove ${d} if empty`, [["rmdir", "--ignore-fail-on-non-empty", d]]);
  }
}

/** GBrain answers its `/health` on this machine's loopback. */
async function gbrainHealthy(sys: Sys, port: number): Promise<boolean> {
  const r = await sys.run(["curl", "-fsS", "--max-time", "3", `http://127.0.0.1:${port}/health`]);
  return r.code === 0;
}

/** This machine's time zone, for the nightly run's hours. */
function timeZone(): string {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

/** `controlclaw brain install`. */
/** A hostname with a dot and no port, as the firewall's `PUT /api/brain/pages` takes it. */
export function pagesNameOk(n: string): boolean {
  const labels = n.split(".");
  return (
    n.length <= 253 &&
    labels.length >= 2 &&
    labels.every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) &&
    // An address is not a name: the firewall's `PUT /api/brain/pages` refuses it too.
    !/^\d+$/.test(labels[labels.length - 1]!)
  );
}

function badPagesName(io: Io, o: BrainOpts): boolean {
  // Names are kept lower case, as the firewall keeps them: the sign-in compares origins exactly.
  if (o.pagesName !== undefined) o.pagesName = o.pagesName.trim().toLowerCase();
  if (o.pagesName === undefined || pagesNameOk(o.pagesName)) return false;
  io.err(`--pages-name: ${o.pagesName} is not a hostname with a dot and no port (such as brain.example.com).`);
  return true;
}

export async function brainInstall(sys: Sys, io: Io, o: BrainOpts, net: PairNet): Promise<number> {
  if (badPagesName(io, o)) return 2;
  if (!needRoot(sys, io, "install")) return 1;
  const existing = loadBrain(sys);
  if (existing?.kind === "connect") {
    io.err("A GBrain of this machine is connected already (brain connect). Run controlclaw brain disconnect first.");
    return 1;
  }
  if (existing) {
    io.out("The brain is installed already: starting it.");
    const up = await sys.run([...composeIn(BRAIN_PROJECT, BRAIN_DIR)("up", "-d"), ], { timeoutMs: 300_000 });
    await sys.run(["systemctl", "start", BRAIN_UNIT]);
    if (up.code !== 0) {
      io.err(`docker compose up: ${up.stderr.trim().split("\n").pop()}`);
      return 1;
    }
    return 0;
  }
  if (process.arch !== "x64") {
    io.err("brain install needs an x86-64 machine: GBrain's release has no binary for this one yet.");
    return 1;
  }
  const problem = await dockerProblem(sys, "brain install");
  if (problem) {
    io.err(problem);
    return 1;
  }
  if (await rootlessDocker(sys)) {
    io.err("brain install does not work with rootless Docker (the brain's networks would be in a namespace of their own).");
    return 1;
  }
  for (const port of [GBRAIN_PORT]) {
    if (await listening("127.0.0.1", port)) {
      io.err(`Something already listens on 127.0.0.1:${port}, which the brain needs.`);
      return 1;
    }
  }
  const taken = await subnetTaken(sys, `${BRAIN_PROJECT}_brain`, BRAIN_SUBNET);
  if (taken) {
    io.err(`Docker network ${taken} already uses ${BRAIN_SUBNET}, which the brain's network needs.`);
    return 1;
  }
  const tmp: string[] = [];
  try {
    return await install(sys, io, o, net, tmp);
  } finally {
    for (const d of tmp) sys.remove(d);
  }
}

async function install(sys: Sys, io: Io, o: BrainOpts, net: PairNet, tmp: string[]): Promise<number> {
  const agent = await vmAgentOrRelease(o.vmAgent ?? null, io);
  if (!agent) return 1;
  if (agent.downloaded) tmp.push(agent.downloaded);
  let filesUi: string | null;
  try {
    filesUi = await pagesBundle(sys, io, o.pagesUi, tmp);
  } catch (e) {
    io.err((e as Error).message);
    return 2;
  }
  const files = imageFiles();
  const image = imageTag(files);
  const record: BrainRecord = { version: 1, kind: "install", at: new Date().toISOString(), firewall: { url: "", proxy: "", dns: null }, image, steps: [] };
  const rec = new Recorder<BrainRecord>(sys, record, brainRecordPath(sys));
  rec.start();
  recordParents(sys, rec);
  const compose = composeIn(BRAIN_PROJECT, BRAIN_DIR);
  let placement: Placement | null = null;
  try {
    // The image first: the slow step, and nothing to undo with the firewall if it fails.
    io.out(`Building the brain's image (GBrain, checked by sha256; Postgres 16 with pgvector)`);
    const ctxDir = join(BRAIN_DIR, "image");
    for (const [name, text] of Object.entries(files)) await rec.file(join(ctxDir, name), text, { mode: name.startsWith("bin/") ? 0o755 : 0o644 });
    rec.onUndo("remove the brain's image", [["docker", "image", "rm", image]]);
    const built = await sys.run(["docker", "build", "-q", "-t", image, ctxDir], { timeoutMs: 1_800_000 });
    if (built.code !== 0) throw new Error(`docker build: ${(built.stderr || built.stdout).trim().split("\n").slice(-3).join(" ")}`);

    // The firewall here: the brain on its `agents` network, which it has no way out of but the
    // firewall. Elsewhere: through the gate, over the tunnel.
    placement = await place(sys, io, rec, o, net, BRAIN_FW_IP, o.name ?? "brain");
    if (!placement) {
      await undoAll(sys, record, io.err, brainRecordPath(sys));
      return 1;
    }
    const p = placement;
    record.firewall = p.firewall;
    rec.start();
    io.out(`  the brain is ${p.paired.agentId} (${p.paired.name}), known to the firewall by ${p.paired.address}`);
    io.out(`  the firewall's CA: SHA-256 ${caFingerprint(p.paired.caPem)}`);
    const ca = join(BRAIN_DIR, "ca.crt");
    await rec.file(ca, `${p.paired.caPem.trim()}\n`, { mode: 0o644 });
    // GBrain's account reads the CA here; what is secret in this folder is a 0600 file.
    await sys.run(["chmod", "0755", BRAIN_DIR]);
    // The database's password lives as long as its volume: not recorded, so `brain disconnect` keeps it
    // with the data and a later install opens the same database; `--purge` removes both.
    if (!/^GBRAIN_DB_PASSWORD=[0-9a-f]{48}$/m.test(sys.read(DB_ENV) ?? "")) {
      sys.write(DB_ENV, `GBRAIN_DB_PASSWORD=${randomBytes(24).toString("hex")}\n`, { mode: 0o600 });
    }
    const egress: BrainEgress = o.firewall
      ? { kind: "gate", proxy: splitHostPort(p.proxy, 8080), dns: await ipv4Of(p.dns) }
      : { kind: "firewall-net", network: `${UP_PROJECT}_agents`, firewall: FW_AGENTS_IP, address: BRAIN_FW_IP };
    const out = join(BRAIN_STATE, "gbrain-pages");
    rec.onUndo("remove the pages' hand-over folder", [["rm", "-rf", "--", out]]);
    await sys.run(["install", "-d", "-m", "0750", out]);
    await rec.file(join(BRAIN_DIR, "compose.yaml"), brainCompose({ image, egress, out, ca, tz: timeZone(), gatewayIsolated: ISOLATED_GATEWAY, pagesName: o.pagesName }), { mode: 0o644 });
    rec.onUndo("stop the brain's containers (their volumes stay)", [compose("down")]);
    io.out("Starting GBrain and Postgres");
    const up = await sys.run(compose("up", "-d"), { timeoutMs: 900_000 });
    if (up.code !== 0) throw new Error(`docker compose up: ${up.stderr.trim().split("\n").pop()}`);

    io.out("Installing the brain's vm-agent");
    await installBrainAgent(sys, rec, { binary: agent.path, filesUi, placement: p, port: GBRAIN_PORT, exec: ["docker", "exec", "-i", "-u", "0", BRAIN_CONTAINER], pagesName: o.pagesName });

    io.out("Waiting for GBrain (its first start sets up the database: a minute or two)");
    try {
      await waitFor(sys, "GBrain", 150, () => gbrainHealthy(sys, GBRAIN_PORT));
    } catch (e) {
      // Before the undo removes the container: what GBrain said.
      const logs = await sys.run(compose("logs", "--no-color", "--tail", "15", "gbrain", "postgres"));
      io.err((logs.stdout || logs.stderr).trim());
      throw e;
    }
    io.out("");
    for (const c of await brainChecks(sys, record)) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
    io.out("");
    io.out("The brain is installed. Its model calls go through the firewall, paid by your AI Gateway or OpenAI key there (add one in the panel's Settings if you have none).");
    io.out(o.pagesName ? `Its pages: https://${o.pagesName}, through the firewall's relay (the panel's Brain page opens them).` : "Its pages: give them a name with --pages-name, the one set on the firewall (PUT /api/brain/pages).");
    io.out("Undo it all with: sudo controlclaw brain disconnect (add --purge to delete what it learned)");
    return 0;
  } catch (e) {
    io.err(`brain install failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    await undoAll(sys, record, io.err, brainRecordPath(sys));
    if (placement || record.firewall.agentId) await unpairBrain(record.firewall, io, net.post);
    return 1;
  }
}

/** GBrain's systemd unit, as `systemctl show` describes it. */
export interface GBrainUnit {
  unit: string;
  user: string;
  bin: string;
  port: number | null;
  envFile: string | null;
}

/** `systemctl show -p Id,User,ExecStart,EnvironmentFiles` → the unit, when it runs `gbrain serve`. */
export function parseUnit(show: string): GBrainUnit | null {
  const prop = (k: string) => show.split("\n").find((l) => l.startsWith(`${k}=`))?.slice(k.length + 1) ?? "";
  const exec = prop("ExecStart");
  const argv = /argv\[\]=([^;]*)/.exec(exec)?.[1]?.trim().split(/\s+/) ?? [];
  const at = argv.findIndex((a) => a === "serve");
  if (at < 1 || !/gbrain/.test(argv[0] ?? "")) return null;
  const portArg = argv.findIndex((a) => a === "--port");
  const inline = argv.find((a) => a.startsWith("--port="))?.slice(7);
  const port = Number(inline ?? (portArg >= 0 ? argv[portArg + 1] : NaN));
  const env = prop("EnvironmentFiles").split(/\s+/)[0]?.replace(/^-/, "") || null;
  return { unit: prop("Id"), user: prop("User"), bin: argv[0]!, port: Number.isInteger(port) && port > 0 ? port : null, envFile: env };
}

/**
 * Why `gbrain config show` describes a GBrain `brain connect` cannot hold to the firewall, or null:
 * its database must be on this machine (the drop-in allows GBrain nothing else, and Postgres does not
 * go through a proxy), and its embedding model the one the firewall's allow-list for the brain takes.
 */
export function gbrainConfigProblem(show: string): string | null {
  const val = (k: string) => new RegExp(`^\\s*${k}:\\s*(\\S+)`, "m").exec(show)?.[1] ?? null;
  const db = val("database_url");
  const host = db && db !== "undefined" ? /@([^/:?]+|\[[^\]]+\])/.exec(db)?.[1] ?? null : null;
  if (db && db !== "undefined" && host && !["127.0.0.1", "localhost", "[::1]"].includes(host)) {
    return `GBrain's database is on ${host}. brain connect lets GBrain reach only this machine and the firewall, so it would lose it: move the database onto this machine, or use brain install.`;
  }
  const embed = val("embedding_model");
  if (embed && embed !== "openai:text-embedding-3-small") {
    return `GBrain embeds with ${embed}. The firewall lets the brain use openai:text-embedding-3-small only (and GPT-5.6 Luna and Terra); changing GBrain's embedding model means embedding every page again, so brain connect leaves that to you.`;
  }
  return null;
}

async function findGBrainUnit(sys: Sys, given?: string): Promise<GBrainUnit | null> {
  const show = async (u: string) => (await sys.run(["systemctl", "show", "-p", "Id,User,ExecStart,EnvironmentFiles", u])).stdout;
  if (given) return parseUnit(await show(given));
  const list = await sys.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"]);
  for (const line of list.stdout.split("\n")) {
    const u = line.trim().split(/\s+/)[0];
    if (!u?.endsWith(".service")) continue;
    const parsed = parseUnit(await show(u));
    if (parsed) return parsed;
  }
  return null;
}

/** `controlclaw brain connect`: a GBrain already running here, as a systemd service. */
export async function brainConnect(sys: Sys, io: Io, o: BrainOpts, net: PairNet): Promise<number> {
  if (badPagesName(io, o)) return 2;
  if (!needRoot(sys, io, "connect")) return 1;
  if (loadBrain(sys)) {
    io.err("The brain is set up here already. Run controlclaw brain disconnect first.");
    return 1;
  }
  const unit = await findGBrainUnit(sys, o.gbrainUnit);
  if (!unit) {
    io.err(`No running systemd service that runs gbrain serve${o.gbrainUnit ? ` (${o.gbrainUnit})` : ""}. Run GBrain as a system service first (docs/standalone/brain.md), or name it with --gbrain-unit.`);
    return 1;
  }
  const port = o.gbrainPort ? Number(o.gbrainPort) : unit.port;
  if (!port || !Number.isInteger(port)) {
    io.err(`${unit.unit} does not say GBrain's port (--port): pass --gbrain-port.`);
    return 2;
  }
  const user = unit.user ? userByName(sys, unit.user) : null;
  if (!user || user.uid === 0) {
    io.err(`${unit.unit} runs as ${unit.user || "root"}: run GBrain as its own user (User= in the unit), so its traffic can be held to the firewall without holding root's.`);
    return 1;
  }
  const helperPaths = ["cc-gbrain-key", "cc-gbrain-token", "cc-gbrain-model", "cc-gbrain-login-link", "cc-gbrain-pages", "cc-gbrain-dream"].map((n) => `/usr/local/bin/${n}`);
  const clash = helperPaths.find((p) => sys.exists(p));
  if (clash) {
    io.err(`${clash} exists already (an Ansible brain?): brain connect does not overwrite it.`);
    return 1;
  }
  // What the drop-in and the firewall's allow-list for the brain leave it: a database on this
  // machine (the drop-in allows nothing else), and the embedding model the allow-list takes.
  const env = unit.envFile ?? join(user.home, ".gbrain/env");
  const shown = await sys.run([
    "runuser", "-u", user.name, "--", "env", `HOME=${user.home}`, "bash", "-c",
    `cd ${JSON.stringify(user.home)}; [ ! -f ${JSON.stringify(env)} ] || { set -a; . ${JSON.stringify(env)}; set +a; }; exec "$@"`, "_", unit.bin, "config", "show",
  ]);
  const problem = gbrainConfigProblem(shown.stdout);
  if (shown.code !== 0 || problem) {
    io.err(problem ?? `Could not read ${unit.unit}'s settings (gbrain config show): ${shown.stderr.trim().split("\n").pop() ?? ""}`);
    return 1;
  }
  io.out(`GBrain: ${unit.unit}, as ${user.name}, on 127.0.0.1:${port}`);
  const tmp: string[] = [];
  try {
    const agent = await vmAgentOrRelease(o.vmAgent ?? null, io);
    if (!agent) return 1;
    if (agent.downloaded) tmp.push(agent.downloaded);
    let filesUi: string | null;
    try {
      filesUi = await pagesBundle(sys, io, o.pagesUi, tmp);
    } catch (e) {
      io.err((e as Error).message);
      return 2;
    }
    return await connectWith(sys, io, o, net, { unit, user, port, binary: agent.path, filesUi });
  } finally {
    for (const d of tmp) sys.remove(d);
  }
}

async function connectWith(
  sys: Sys,
  io: Io,
  o: BrainOpts,
  net: PairNet,
  g: { unit: GBrainUnit; user: NonNullable<ReturnType<typeof userByName>>; port: number; binary: string; filesUi: string | null },
): Promise<number> {
  const record: BrainRecord = { version: 1, kind: "connect", at: new Date().toISOString(), firewall: { url: "", proxy: "", dns: null }, unit: g.unit.unit, steps: [] };
  const rec = new Recorder<BrainRecord>(sys, record, brainRecordPath(sys));
  rec.start();
  recordParents(sys, rec);
  let placement: Placement | null = null;
  // A folder of its own: the helpers read the file as GBrain's account (0640, root:GBrain's group).
  const keyDir = join(BRAIN_DIR, "gbrain");
  const keyFile = join(keyDir, "gbrain.env");
  const home = g.user.home;
  const env = g.unit.envFile ?? join(home, ".gbrain/env");
  const restart = `systemctl restart ${g.unit.unit} >/dev/null`;
  try {
    // This machine's address toward the firewall here (its side of `outside`); over the tunnel, the tunnel's.
    placement = await place(sys, io, rec, o, net, HOST_OUTSIDE_IP, o.name ?? hostname());
    if (!placement) {
      await undoAll(sys, record, io.err, brainRecordPath(sys));
      return 1;
    }
    const p = placement;
    record.firewall = p.firewall;
    rec.start();
    io.out(`  the brain is ${p.paired.agentId} (${p.paired.name}), known to the firewall by ${p.paired.address}`);
    io.out(`  the firewall's CA: SHA-256 ${caFingerprint(p.paired.caPem)}`);
    const ca = join(BRAIN_DIR, "ca.crt");
    await rec.file(ca, `${p.paired.caPem.trim()}\n`, { mode: 0o644 });
    // GBrain's account reads the CA here; what is secret in this folder is a 0600 file.
    await sys.run(["chmod", "0755", BRAIN_DIR]);

    io.out("Installing GBrain's helpers");
    const out = join(BRAIN_STATE, "gbrain-pages");
    for (const [name, text] of Object.entries(
      // GBrain's account reads the key file when a helper runs GBrain's CLI (an Import's embeddings,
      // through the firewall): a placeholder and the proxy's settings, 0640 root:GBrain's group.
      helpers({ user: g.user.name, home, env, keyFile, keyOwner: `root:${g.user.gid}`, keyMode: "0640", gbrain: g.unit.bin, host: "127.0.0.1", port: g.port, out, owner: "root", restart }),
    )) {
      const path = name.endsWith(".py") ? `/usr/local/lib/${name}` : `/usr/local/bin/${name}`;
      await rec.file(path, text, { mode: name.endsWith(".py") ? 0o644 : 0o755, owner: { uid: 0, gid: 0 } });
    }
    rec.onUndo("remove the pages' hand-over folder", [["rm", "-rf", "--", out]]);
    await sys.run(["install", "-d", "-m", "0750", out]);
    // Every token the brain minted in this GBrain (the agents' `cc-<vmId>`, the pages' own) is
    // revoked on disconnect: the gate that held them goes, and nothing else should.
    rec.onUndo("revoke the tokens the brain made in GBrain", [["bash", "-c", REVOKE, "_", home, env, g.unit.bin, g.user.name, record.at]]);

    // GBrain's model tiers to the brain's models (the firewall's allow-list for the brain takes only
    // those); what they were is put back on disconnect.
    const keys = ["models.tier.utility", "models.tier.reasoning", "models.tier.subagent", "models.fence_repair", "models.content_repair", "models.tier.deep"];
    const asGbrain = (args: string[]) => [
      "runuser", "-u", g.user.name, "--", "env", `HOME=${home}`, "bash", "-c", `cd ${JSON.stringify(home)}; [ ! -f ${JSON.stringify(env)} ] || { set -a; . ${JSON.stringify(env)}; set +a; }; exec "$@"`, "_", g.unit.bin, ...args,
    ];
    const back: string[][] = [];
    for (const k of keys) {
      const r = await sys.run(asGbrain(["config", "get", k]));
      // Not set (GBrain's own default): `get` exits 1, and the undo unsets it again.
      const was = r.code === 0 ? r.stdout.split("\n").map((l) => l.trim()).find((l) => l && !l.startsWith("[")) : undefined;
      // An unset that finds nothing (the set below never happened) is not a failure.
      back.push(was ? asGbrain(["config", "set", k, was]) : ["bash", "-c", '"$@" >/dev/null 2>&1 || true', "_", ...asGbrain(["config", "unset", k])]);
    }
    // The helper keeps the brain's model here (the role's `cc-model`): it goes with the rest.
    const ccModel = join(home, ".gbrain/cc-model");
    back.push(["rm", "-f", "--", ccModel]);
    await sys.run(["rm", "-f", "--", ccModel]);
    if (back.length) rec.onUndo("put back GBrain's models", back);
    const m = await sys.run(["/usr/local/bin/cc-gbrain-model", BRAIN_MODELS[0]], { timeoutMs: 120_000 });
    if (m.code !== 0) throw new Error(`could not set GBrain's model: ${(m.stderr || m.stdout).trim().split("\n").pop()}`);
    const deep = await sys.run(asGbrain(["config", "set", "models.tier.deep", `openai:${BRAIN_MODELS[1]}`]));
    if (deep.code !== 0) throw new Error(`could not set GBrain's deep model: ${deep.stderr.trim()}`);

    io.out(`Sending ${g.unit.unit}'s traffic to the firewall`);
    const proxy = splitHostPort(p.proxy, 8080);
    const allow = [...new Set([await ipv4Of(proxy.host), await ipv4Of(p.dns)])];
    rec.onUndo(`restart ${g.unit.unit}`, [["systemctl", "restart", g.unit.unit]]);
    rec.onUndo("reload systemd", [["systemctl", "daemon-reload"]]);
    await rec.file(`/etc/systemd/system/${g.unit.unit}.d/controlclaw-brain.conf`, gbrainDropin({ keyFile, ca, proxy: `${proxy.host}:${proxy.port}`, allow }), { mode: 0o644 });
    // Also for the helpers, which run GBrain's CLI outside its unit (and so outside the drop-in).
    rec.onUndo("remove the key file's folder if empty", [["rmdir", "--ignore-fail-on-non-empty", keyDir]]);
    const mk = await sys.run(["install", "-d", "-m", "0750", "-o", "root", "-g", String(g.user.gid), keyDir]);
    if (mk.code !== 0) throw new Error(`could not make ${keyDir}: ${mk.stderr.trim()}`);
    await rec.file(keyFile, connectKeyFile(`http://${proxy.host}:${proxy.port}`, ca), { mode: 0o640, owner: { uid: 0, gid: g.user.gid } });
    await sys.run(["systemctl", "daemon-reload"]);
    const rs = await sys.run(["systemctl", "restart", g.unit.unit]);
    if (rs.code !== 0) throw new Error(`could not restart ${g.unit.unit}: ${rs.stderr.trim()}`);

    io.out("Installing the brain's vm-agent");
    await installBrainAgent(sys, rec, { binary: g.binary, filesUi: g.filesUi, placement: p, port: g.port, exec: [], pagesName: o.pagesName });
    await waitFor(sys, "GBrain", 60, () => gbrainHealthy(sys, g.port));
    io.out("");
    for (const c of await brainChecks(sys, record)) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
    io.out("");
    io.out(`Connected. ${g.unit.unit} reaches only the firewall now, and the firewall decides who may use it.`);
    io.out("Undo it all with: sudo controlclaw brain disconnect");
    return 0;
  } catch (e) {
    io.err(`brain connect failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    await undoAll(sys, record, io.err, brainRecordPath(sys));
    if (placement || record.firewall.agentId) await unpairBrain(record.firewall, io, net.post);
    return 1;
  }
}

/**
 * A connected GBrain's key file at connect: the firewall's proxy and CA, and a model key nothing swaps,
 * so GBrain's own key (a real one, in its own env) is out of effect from the first restart, until the
 * firewall pushes the user's key's placeholder; with no key in the panel, its model calls fail there.
 */
export function connectKeyFile(proxyUrl: string, ca: string): string {
  return [
    "# Written by controlclaw brain connect: the firewall's proxy and CA, and the brain's model key (a placeholder the firewall swaps).",
    ...["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"].map((k) => `${k}=${proxyUrl}`),
    "NO_PROXY=localhost,127.0.0.1,::1",
    "no_proxy=localhost,127.0.0.1,::1",
    `NODE_EXTRA_CA_CERTS=${ca}`,
    // As cc-brain-run's first env file: the gateway, and a stand-in the firewall swaps for nothing.
    "OPENAI_BASE_URL=https://ai-gateway.vercel.sh/v1",
    "OPENAI_API_KEY=vck-cc-included-none",
    "",
  ].join("\n");
}

/** `bash -c REVOKE _ <home> <env> <gbrain> <user> <since>`: the tokens a connected brain made, revoked. */
export const REVOKE = `set -u
home="$1"; env="$2"; bin="$3"; user="$4"; since="$5"
g() { cd "$home" && runuser -u "$user" -- env HOME="$home" bash -c '[ ! -f "$0" ] || { set -a; . "$0"; set +a; }; exec "$@"' "$env" "$bin" "$@"; }
names="$(g auth list --json | python3 -I -c 'import json, sys
from datetime import datetime, timezone
def at(v):
    try:
        d = datetime.fromisoformat(str(v).strip().replace("Z", "+00:00").replace(" ", "T", 1))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None
s = at(sys.argv[1])
def ours(t):
    if t.get("name") == "controlclaw-pages":
        return True
    c = at(t.get("created_at"))
    # A time it cannot read counts as ours: a token left open is worse than one revoked too many.
    return str(t.get("name", "")).startswith("cc-") and (c is None or c >= s)
print("\\n".join(sorted({t["name"] for t in json.load(sys.stdin) if t.get("status") == "active" and ours(t)})))' "$since")" || exit 1
for n in $names; do g auth revoke "$n" >/dev/null || exit 1; done`;

async function unpairBrain(fw: Firewall, io: Io, post: PairNet["post"]): Promise<void> {
  if (!fw.agentId || !fw.unpair) return;
  const r = await unpair(fw.url, fw.agentId, fw.unpair, post);
  if (r === null) io.out(`  The firewall forgot the brain (${fw.agentId}).`);
  else io.out(`  ! The firewall still lists the brain as ${fw.agentId} (${r}); remove it there.`);
}

/** `controlclaw brain disconnect [--purge]`: every step undone, the brain unpaired. */
export async function brainDisconnect(sys: Sys, io: Io, o: { purge?: boolean; force?: boolean }, post: PairNet["post"]): Promise<number> {
  if (!needRoot(sys, io, "disconnect")) return 1;
  const record = loadBrain(sys);
  if (!record) {
    io.out("No brain here.");
    return 0;
  }
  const tunnel = hasTunnel(record);
  io.out(`${record.kind === "install" ? "Removing the brain's containers and its vm-agent" : `Removing the brain's vm-agent and helpers, and ${record.unit}'s drop-in`}${tunnel ? ", and the tunnel" : ""}`);
  await unpairBrain(record.firewall, io, post);
  const failed = await undoAll(sys, record, io.err, brainRecordPath(sys));
  if (record.kind === "install" && o.purge) {
    const v = await sys.run(["docker", "volume", "rm", `${BRAIN_PROJECT}_postgres`, `${BRAIN_PROJECT}_gbrain`]);
    io.out(v.code === 0 ? "  The brain's data is deleted." : `  ! The brain's volumes are still there: ${v.stderr.trim()}`);
    if (v.code === 0) {
      sys.remove(DB_ENV);
      sys.removeEmptyDir(BRAIN_DIR);
      sys.removeEmptyDir(stateDir(sys));
    }
  } else if (record.kind === "install") {
    io.out(`  What the brain learned stays in the volumes ${BRAIN_PROJECT}_postgres and ${BRAIN_PROJECT}_gbrain (brain disconnect --purge deletes them; brain install uses them again).`);
  }
  if (!failed) {
    io.out("Done.");
    return 0;
  }
  if (o.force) {
    sys.remove(brainRecordPath(sys));
    io.out(`Done. ${failed} step(s) failed (above) and were given up; check them by hand.`);
    return 1;
  }
  io.out(`Done, with ${failed} step(s) that failed (above). Run brain disconnect again once fixed, or with --force to give them up.`);
  return 1;
}

/** Whether the brain set up a tunnel (it is one of the steps to undo). */
function hasTunnel(record: BrainRecord): boolean {
  return record.steps.some((s) => s.kind === "run" && s.argv.some((a) => a.includes(WG_UNIT)));
}

async function brainChecks(sys: Sys, record: BrainRecord): Promise<Check[]> {
  const checks: Check[] = [];
  const agent = await sys.run(["systemctl", "is-active", BRAIN_UNIT]);
  checks.push({ name: "brain's vm-agent", ok: agent.stdout.trim() === "active", detail: agent.stdout.trim() || "unknown" });
  if (record.kind === "install") {
    // `egress` only when the firewall is on this machine (brainCompose's firewall-net layout).
    const egress = (await sys.run(["docker", "inspect", "-f", "{{.Name}}", `${BRAIN_PROJECT}-egress-1`])).code === 0;
    for (const svc of ["postgres", "gbrain", "gate", ...(egress ? ["egress"] : [])]) {
      const r = await sys.run(["docker", "inspect", "-f", "{{.State.Status}}", `${BRAIN_PROJECT}-${svc}-1`]);
      checks.push({ name: svc, ok: r.stdout.trim() === "running", detail: r.stdout.trim() || "not running" });
    }
  } else if (record.unit) {
    const r = await sys.run(["systemctl", "is-active", record.unit]);
    checks.push({ name: record.unit, ok: r.stdout.trim() === "active", detail: r.stdout.trim() || "unknown" });
  }
  if (hasTunnel(record)) {
    const h = await sys.run(["wg", "show", WG_IFACE, "latest-handshakes"]);
    const at = Number(h.stdout.trim().split(/\s+/)[1] ?? 0);
    checks.push({ name: "tunnel", ok: h.code === 0 && at > 0 && Date.now() / 1000 - at < 180, detail: h.code === 0 ? `${WG_IFACE} up` : `${WG_IFACE} is down` });
  }
  return checks;
}

/** `controlclaw brain status [--json]`. */
export async function brainStatus(sys: Sys, io: Io, o: { json?: boolean }): Promise<number> {
  const record = loadBrain(sys);
  if (!record) {
    io.out(o.json ? JSON.stringify({ brain: false }) : sys.euid === 0 ? "No brain here." : "No brain here (run it with sudo if brain install or connect ran with sudo).");
    return 0;
  }
  const checks = await brainChecks(sys, record);
  const ok = checks.every((c) => c.ok);
  if (o.json) io.out(JSON.stringify({ brain: true, kind: record.kind, since: record.at, firewall: { url: record.firewall.url, agentId: record.firewall.agentId }, ok, checks }, null, 2));
  else {
    io.out(`The brain (${record.kind === "install" ? "brain install" : `brain connect, ${record.unit}`}) since ${record.at}, ${record.firewall.agentId ?? "not paired"} at ${record.firewall.url}`);
    for (const c of checks) io.out(`  ${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
  }
  return ok ? 0 : 1;
}

