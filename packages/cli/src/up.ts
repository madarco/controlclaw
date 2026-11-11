import { isIPv4 } from "node:net";
import { join } from "node:path";
import { AGENT_PORT, installAgent, keepAfterLogout } from "./agent.js";
import { type ComposeInfo, docker, dockerNeeds, type FirewallNet, gatewayProject, subnetTaken } from "./capture/docker.js";
import { host } from "./capture/host.js";
import type { Ctx } from "./capture/mode.js";
import { disconnect, type Io, type PairNet, realNet } from "./commands.js";
import { gatherFacts, runsText } from "./doctor.js";
import { codeIn, composeIn, containerHealthy, dockerProblem, ensureImage, listening, pairHere, releaseImage, rootlessDocker, waitFirewall, waitFor } from "./fwcontainer.js";
import { AGENTS_SUBNET, firewallNetworks, firewallService, FW_AGENTS_IP, FW_OUTSIDE_IP, HOST_OUTSIDE_IP, local, OUTSIDE_SUBNET } from "./local.js";
import { open as openPanel, type OpenNet, realOpenNet } from "./open.js";
import { backupConfig } from "./openclaw-config.js";
import { cliArgv, findVmAgent, restartArgv, restartUser } from "./openclaw.js";
import { openclawInstall } from "./openclaw-install.js";
import { caFingerprint, unpair } from "./pair.js";
import type { Check } from "./probe.js";
import { cliVersion, releaseFile, vmAgentOrRelease } from "./release.js";
import { type ConnectRecord, type FirewallRecord, firewallRecordPath, loadFirewall, loadRecord, Recorder, ROOT_FIREWALL, ROOT_RECORD, stateDir, sudoUserRecord, undoAll } from "./state.js";
import { type Sys, type User, userByUid } from "./sys.js";

/**
 * The firewall on this machine, and OpenClaw here connected to it with no code typed.
 *
 * `controlclaw install` runs the firewall: a container (`--docker`, the default) or `install.sh`'s
 * systemd units (`--host`). The container has the same networks and fixed addresses as `up --local`
 * (local.ts), so `allow_from` stays right when it is recreated: `outside` (`172.31.252.0/24`: the
 * firewall at `.2`, this machine at `.1`) and the internal `agents` (`172.31.251.0/24`, no address for
 * this machine). Its panel, pairing and pages are published on this machine's loopback only; with
 * `--listen <ip>`, its proxy, DNS, pairing and gates also on that address, for other machines.
 *
 * `controlclaw connect` without `--firewall` pairs with that container by itself:
 * - docker mode: the gateway's container joins `agents` as its only network, so the firewall's
 *   container is its only way out; the firewall publishes the ports the gateway published (CC_FORWARD);
 * - host mode: host capture (nftables, redsocks, resolved) pointed at the firewall on `outside`.
 * The vm-agent listens on this machine's side of `outside`, for the firewall's container alone.
 */
export const UP_PROJECT = "controlclaw-firewall";
/** The gateway's address on `agents` (docker mode): the one the firewall knows it by. */
export const UP_GATEWAY_IP = "172.31.251.10";
const AGENT_LISTEN = `${HOST_OUTSIDE_IP}:${AGENT_PORT}`;
const PAIR_URL = "http://127.0.0.1:8801/";
/** Published on this machine's loopback: the panel, pairing, the pages. */
const LOOPBACK_PORTS = [8800, 8801, 8790];
/** The firewall's own ports in its container: a gateway port it would publish must be none of them. */
const FIREWALL_PORTS = [53, 3100, 3101, 3900, 3940, 8080, 8790, 8800, 8801];
/** Published on `--listen` for other machines: the proxy, pairing, the gates. DNS (53) besides. */
const LISTEN_PORTS = [8080, 8801, 3900, 3940];

export type UpMode = "docker" | "host";

/** `up --local`'s firewall volume (local.ts's project). */
const LOCAL_VOLUME = "controlclaw-local_firewall";

/** Whether something listens on a port of this machine: swapped in tests. */
export type Listening = (host: string, port: number) => Promise<boolean>;

/** The network calls these make, swapped in tests. */
export interface HereNet extends PairNet {
  open?: OpenNet;
  busy?: Listening;
}

/**
 * The firewall's Compose file. `forwards`: the gateway's ports it publishes (connect, docker mode).
 * `gateOnAgents`: its gates on `agents`, where a gateway in docker mode reaches them; else on
 * `outside`, where this machine (host mode) and, through --listen, other machines do.
 */
export function upCompose(o: { image: string; listen?: string; forwards?: ComposeInfo["ports"]; gateOnAgents?: boolean }): string {
  const ports = o.forwards ?? [];
  // One relay per port of the gateway, however many host addresses it was published on.
  const relayed = [...new Set(ports.map((p) => p.container))];
  const l = o.listen;
  return [
    "# Written by controlclaw install; removed by controlclaw uninstall (the volume stays without --purge).",
    `name: ${UP_PROJECT}`,
    "services:",
    ...firewallService({
      image: o.image,
      agents: true,
      gate: o.gateOnAgents ? FW_AGENTS_IP : FW_OUTSIDE_IP,
      pairAt: l ?? FW_AGENTS_IP,
      forwards: relayed.map((port) => ({ port, to: `${UP_GATEWAY_IP}:${port}` })),
      publish: [
        ...(l
          ? [
              ...LISTEN_PORTS.map((p) => ({ spec: `${l}:${p}:${p}`, what: "for agents on other machines" })),
              { spec: `${l}:53:53/udp`, what: "DNS for agents on other machines" },
              { spec: `${l}:53:53/tcp`, what: "DNS for agents on other machines" },
            ]
          : []),
        ...ports.map((p) => ({ spec: `${p.host}:${p.container}`, what: "OpenClaw's, as its container published it" })),
      ],
    }),
    ...firewallNetworks(true),
    "",
  ].join("\n");
}

/** Where `install` keeps the firewall's Compose file: next to its record. */
export function upDir(sys: Sys): string {
  return join(stateDir(sys), "firewall");
}

/** A private IPv4 address: DNS published on a public one would answer the whole internet. */
export function privateIpv4(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  const [a, b] = ip.split(".").map(Number) as [number, number];
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
}

/** `compose up -d firewall`, then until it can make a code. Throws with Compose's reason. */
async function startFirewall(sys: Sys, compose: (...a: string[]) => string[]): Promise<void> {
  const r = await sys.run(compose("up", "-d", "firewall"), { timeoutMs: 300_000 });
  if (r.code !== 0) throw new Error(`docker compose up firewall: ${r.stderr.trim().split("\n").pop()}`);
  await waitFirewall(sys, compose);
}

/** Why Docker here cannot run the firewall's container for this command; null when it can. */
async function dockerHere(sys: Sys, what: string): Promise<string | null> {
  const problem = await dockerProblem(sys, what);
  if (problem) return problem;
  if (await rootlessDocker(sys)) {
    return `${what} does not work with rootless Docker: its networks are in a namespace of their own, where this machine has no address for the vm-agent to take the firewall's calls on. Use Docker run by root (your user in the docker group is enough).`;
  }
  return null;
}

export interface InstallOpts {
  /** `install.sh`'s systemd units instead of a container. */
  host?: boolean;
  /** The address other machines reach it at. */
  listen?: string;
  firewallImage?: string;
  /** The name on the pairing code it prints. */
  name?: string;
  /** Not the panel yet (`up --here` opens it once, at the end). */
  noOpen?: boolean;
}

/**
 * `controlclaw install`: the firewall on this machine. Run again, it starts the firewall if it is not
 * running and opens the panel.
 */
export async function installFirewall(sys: Sys, io: Io, o: InstallOpts, net: HereNet = realNet): Promise<number> {
  if (o.listen !== undefined && !privateIpv4(o.listen)) {
    io.err(`--listen: ${o.listen} is not a private IPv4 address. Agents reach the firewall on your private network; on a public address its proxy and DNS would answer the whole internet.`);
    return 2;
  }
  const existing = loadFirewall(sys);
  if (existing) {
    const asked = { kind: o.host ? "host" : "docker", listen: o.listen, image: o.firewallImage };
    const differs = asked.kind !== existing.kind || (o.listen !== undefined && o.listen !== existing.listen) || (asked.image !== undefined && asked.kind === "docker" && asked.image !== existing.image);
    if (differs) {
      io.err(`The firewall is installed already, another way (${existing.kind}${existing.listen ? `, --listen ${existing.listen}` : ""}, ${existing.image}). To change it: controlclaw uninstall (its data stays), then install again.`);
      return 1;
    }
    io.out(`The firewall is installed already (${existing.kind === "docker" ? `a container, ${existing.image}` : `install.sh, ${existing.image}`}${existing.listen ? `, for other machines on ${existing.listen}` : ""}).`);
    if (existing.kind === "docker") {
      try {
        await startFirewall(sys, composeIn(existing.project!, existing.dir!));
      } catch (e) {
        io.err(`The firewall's container does not start (${(e as Error).message}): docker compose -p ${existing.project} logs firewall says why.`);
        return 1;
      }
    }
    await openPanel(sys, io, net.open);
    return 0;
  }
  const local = loadRecord(sys);
  if (local?.mode === "local") {
    io.err("up --local runs its own firewall here already. Run controlclaw uninstall first.");
    return 1;
  }
  if ((await sudoUserRecord(sys)) || (sys.euid !== 0 && sys.exists("/etc/controlclaw/firewall.json"))) {
    io.err("A firewall was installed here by another user (with or without sudo): run controlclaw status as that user.");
    return 1;
  }
  return o.host ? installHost(sys, io, o, net) : installDocker(sys, io, o, net);
}

async function installDocker(sys: Sys, io: Io, o: InstallOpts, net: HereNet): Promise<number> {
  const problem = await dockerHere(sys, "install");
  if (problem) {
    io.err(problem);
    return 1;
  }
  const busy = net.busy ?? listening;
  for (const port of LOOPBACK_PORTS) {
    if (await busy("127.0.0.1", port)) {
      io.err(`Something already listens on 127.0.0.1:${port}, which the firewall's panel, pairing or pages need. Is a firewall installed here already (install.sh, up --local, standalone/docker)?`);
      return 1;
    }
  }
  for (const [name, subnet] of [[`${UP_PROJECT}_agents`, AGENTS_SUBNET], [`${UP_PROJECT}_outside`, OUTSIDE_SUBNET]] as const) {
    const taken = await subnetTaken(sys, name, subnet);
    if (taken) {
      io.err(`Docker network ${taken} already uses ${subnet}, which the firewall's container needs.`);
      return 1;
    }
  }
  const image = o.firewallImage ?? releaseImage();
  if (!image) {
    io.err("This is a dev build of controlclaw, with no release image: pass --firewall-image <image> (standalone/docker/build.sh builds one).");
    return 2;
  }
  const dir = upDir(sys);
  const compose = composeIn(UP_PROJECT, dir);
  const record: FirewallRecord = { version: 1, kind: "docker", at: new Date().toISOString(), image, dir, project: UP_PROJECT, ...(o.listen ? { listen: o.listen } : {}), steps: [] };
  const path = firewallRecordPath(sys);
  const rec = new Recorder(sys, record, path);
  rec.start();
  try {
    await ensureImage(sys, io, image);
    io.out("Starting the firewall");
    await rec.file(join(dir, "compose.yaml"), upCompose({ image, listen: o.listen }));
    rec.onUndo("stop the firewall (its volume stays)", [compose("down")]);
    await startFirewall(sys, compose);
  } catch (e) {
    io.err(`install failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    await undoAll(sys, record, io.err, path);
    return 1;
  }
  io.out(`The firewall runs in a container on this machine (${image}).`);
  await afterInstall(sys, io, o, net, compose("exec", "-T", "-u", "controlclaw", "firewall", "mitm-agent", "pair-code"));
  return 0;
}

async function installHost(sys: Sys, io: Io, o: InstallOpts, net: HereNet): Promise<number> {
  if (sys.euid !== 0) {
    io.err("install --host needs root (sudo): it installs the firewall's systemd units.");
    return 1;
  }
  const version = cliVersion();
  const asset = `controlclaw-install-${version}.tar.gz`;
  if (releaseImage(version)) io.out(`Downloading and checking ${asset}`);
  let tarball: string | null;
  try {
    tarball = await releaseFile(asset);
  } catch (e) {
    io.err((e as Error).message);
    return 1;
  }
  if (!tarball) {
    io.err("This is a dev build of controlclaw, with no release to install from: run standalone/install/install.sh yourself.");
    return 2;
  }
  const keep = join(stateDir(sys), "installer");
  const record: FirewallRecord = { version: 1, kind: "host", at: new Date().toISOString(), image: version, installer: join(keep, `controlclaw-install-${version}`, "install.sh"), ...(o.listen ? { listen: o.listen } : {}), steps: [] };
  const path = firewallRecordPath(sys);
  const rec = new Recorder(sys, record, path);
  rec.start();
  try {
    // Kept for uninstall: install.sh --uninstall.
    rec.onUndo("remove the installer", [["rm", "-rf", "--", keep]]);
    const x = await sys.run(["sh", "-c", 'mkdir -p "$1" && tar xzf "$2" -C "$1"', "sh", keep, tarball]);
    if (x.code !== 0) throw new Error(`could not unpack ${asset}: ${x.stderr.trim()}`);
    rec.onUndo("uninstall the firewall (its data stays)", [[record.installer!, "--uninstall"]]);
    io.out("Running install.sh (a few minutes)");
    const r = await sys.run([record.installer!, "--version", version, ...(o.listen ? ["--listen", o.listen] : [])], { timeoutMs: 1_800_000 });
    if (r.code !== 0) throw new Error(`install.sh: ${(r.stderr || r.stdout).trim().split("\n").slice(-3).join(" ")}`);
  } catch (e) {
    io.err(`install failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    await undoAll(sys, record, io.err, path);
    return 1;
  } finally {
    sys.remove(join(tarball, ".."));
  }
  io.out(`The firewall is installed on this machine (install.sh ${version}).`);
  await afterInstall(sys, io, o, net, ["runuser", "-u", "controlclaw", "--", "mitm-agent", "pair-code"]);
  return 0;
}

/** The panel, then how agents connect: this machine pairs by itself; another machine with a code. */
async function afterInstall(sys: Sys, io: Io, o: InstallOpts, net: HereNet, pairCode: string[]): Promise<void> {
  if (!o.noOpen) {
    await openPanel(sys, io, net.open);
    io.out("Next: open the panel and set it up.");
  }
  const sudo = sys.euid === 0 ? "sudo " : "";
  if (loadFirewall(sys)?.kind === "docker" && !o.noOpen) io.out(`OpenClaw on this machine: ${sudo}npx controlclaw connect (it pairs by itself).`);
  if (!o.listen) {
    io.out("Other machines cannot reach this firewall: install it with --listen <this machine's private address> for them.");
    return;
  }
  const code = await sys.run([...pairCode, "--name", o.name ?? "agent"]);
  const c = codeIn(code.stdout);
  if (code.code !== 0 || !c) {
    io.out(`No pairing code yet (${code.stderr.trim() || "no answer"}): make one in the panel, Agents.`);
    return;
  }
  io.out(`OpenClaw on another machine: npx controlclaw connect --firewall http://${o.listen}:8801 (with sudo there for host mode)`);
  io.out(`  with the pairing code ${c} (once, within 10 minutes; the panel makes more, in Agents).`);
}

export interface ConnectHereOpts {
  mode?: string;
  name?: string;
  user?: string;
  vmAgent?: string;
  /** The capture alone: no vm-agent, so the panel cannot set OpenClaw's models or bots, or stop it. */
  captureOnly?: boolean;
}

/** `connect` without `--firewall`: with the firewall `install` runs on this machine, paired with no code. */
export async function connectHere(sys: Sys, io: Io, o: ConnectHereOpts, net: HereNet = realNet): Promise<number> {
  const tmp: { dir: string | null } = { dir: null };
  try {
    return await connectHereWith(sys, io, o, net, tmp);
  } finally {
    // A downloaded vm-agent is installed by now, or not needed: its folder goes either way.
    if (tmp.dir) sys.remove(tmp.dir);
  }
}

async function connectHereWith(sys: Sys, io: Io, o: ConnectHereOpts, net: HereNet, tmp: { dir: string | null }): Promise<number> {
  if (o.mode !== undefined && o.mode !== "auto" && o.mode !== "docker" && o.mode !== "host") {
    io.err("With the firewall on this machine, --mode is auto, docker or host (proxy and remote: connect --firewall <url>).");
    return 2;
  }
  const existing = loadRecord(sys);
  if (existing?.up && existing.mode !== "local") return resume(sys, io, existing, net.open);
  if (existing) {
    io.err(`Already connected (${existing.mode}). Run controlclaw disconnect first.`);
    return 1;
  }
  const theirs = await sudoUserRecord(sys);
  if (theirs) {
    io.err(`This machine was set up by ${theirs.user.name} without sudo. Run, as ${theirs.user.name}: controlclaw connect`);
    return 1;
  }
  if (sys.euid !== 0 && (sys.exists(ROOT_RECORD) || sys.exists(ROOT_FIREWALL))) {
    io.err("This machine was set up with sudo. Run: sudo controlclaw connect");
    return 1;
  }
  const fwRec = loadFirewall(sys);
  if (!fwRec) {
    io.err("No firewall on this machine. Install one first (controlclaw install, or controlclaw up --here for both), or connect to one elsewhere: controlclaw connect --firewall http://<its address>:8801");
    return 1;
  }
  if (fwRec.kind !== "docker") {
    io.err(`The firewall here was installed with install.sh: connect to it with a code from its panel (Agents), at ${fwRec.listen ? `http://${fwRec.listen}:8801` : "its private address"}: controlclaw connect --firewall http://<address>:8801. Pairing by itself needs the firewall in a container (controlclaw install).`);
    return 1;
  }
  const problem = await dockerHere(sys, "connect");
  if (problem) {
    io.err(problem);
    return 1;
  }

  io.out("Checking this machine (doctor)");
  let facts = await gatherFacts(sys, { user: o.user, vmAgent: o.vmAgent });
  // Not found at all: no need to download the vm-agent to say so.
  if (facts.openclaw.install.runs.kind === "not-found" && facts.openclaw.via === "vm-agent") {
    io.err("No OpenClaw on this machine. Install one first: controlclaw openclaw install (or controlclaw up --all for both).");
    return 1;
  }
  const agent = await vmAgentOrRelease(facts.vmAgent, io);
  if (!agent) return 1;
  tmp.dir = agent.downloaded;
  if (agent.downloaded) facts = await gatherFacts(sys, { user: o.user, vmAgent: agent.path });
  if (facts.openclaw.discoverError) {
    io.err(`The vm-agent could not look at this OpenClaw (vm-agent discover: ${facts.openclaw.discoverError}).`);
    return 1;
  }
  const install = facts.openclaw.install;
  if (install.runs.kind === "not-found") {
    io.err("No OpenClaw on this machine. Install one first: controlclaw openclaw install (or controlclaw up --all for both).");
    return 1;
  }
  const chosen = o.mode === "auto" ? undefined : (o.mode as UpMode | undefined);
  const mode: UpMode = chosen ?? (install.runs.kind === "docker" ? "docker" : "host");
  io.out(`  OpenClaw ${install.version ?? ""}: ${runsText(install.runs, facts.openclaw.user?.name ?? null)}. Mode: ${mode}${chosen ? "" : " (--mode overrides it)"}.`);
  const blockers = mode === "docker" ? dockerNeeds(facts) : host.blockers(facts);
  if (blockers.length) {
    io.err(`This machine cannot do ${mode} mode:`);
    for (const b of blockers) io.err(`  - ${b}`);
    return 1;
  }
  let info: ComposeInfo | null = null;
  if (install.runs.kind === "docker") {
    try {
      info = await gatewayProject(sys, install.runs.container);
    } catch (e) {
      io.err(`This machine cannot do docker mode: ${(e as Error).message}.`);
      return 1;
    }
    const clash = info.ports.find((p) => FIREWALL_PORTS.includes(p.container));
    if (clash) {
      io.err(`The gateway publishes port ${clash.container}, which the firewall's container uses itself: publish it on another port first.`);
      return 1;
    }
  }
  // Docker mode: the vm-agent runs as root, or as this user (who can use Docker) without sudo.
  const user = mode === "host" ? facts.openclaw.user : null;
  const agentUser: User | null = user ?? userByUid(sys, sys.euid);
  if (!agentUser) {
    io.err("Cannot tell which user to run the vm-agent as. Pass --user.");
    return 1;
  }

  const dir = fwRec.dir!;
  const compose = composeIn(fwRec.project!, dir);
  const fwNet: FirewallNet | undefined = mode === "docker" ? { network: `${fwRec.project}_agents`, firewall: FW_AGENTS_IP, gateway: UP_GATEWAY_IP } : undefined;
  const fwIp = mode === "docker" ? FW_AGENTS_IP : FW_OUTSIDE_IP;
  // Docker mode: the gateway is on `agents` alone, so the gates go there too. Not with --listen:
  // other machines reach the gates through ports Docker publishes on `outside`.
  const gateOnAgents = mode === "docker" && !fwRec.listen;
  const record: ConnectRecord = {
    version: 1,
    mode,
    at: new Date().toISOString(),
    user,
    firewall: { url: PAIR_URL, proxy: `${fwIp}:8080`, dns: fwIp },
    container: install.runs.kind === "docker" ? install.runs.container : undefined,
    cli: cliArgv(install, []),
    ca: join(stateDir(sys), "ca.crt"),
    up: { dir, project: fwRec.project!, ...(fwNet ? { network: fwNet.network } : {}) },
    ...(o.captureOnly ? { captureOnly: true } : {}),
    steps: [],
  };
  const rec = new Recorder(sys, record);
  rec.start();
  const log = (l: string) => io.out(`  ${l}`);
  let paired = false;
  try {
    await startFirewall(sys, compose);
    io.out("Pairing OpenClaw with the firewall on this machine");
    const name = o.name ?? "openclaw";
    const p = await pairHere(
      sys,
      compose,
      // Without the vm-agent the firewall has nothing to call.
      { name, address: mode === "docker" ? UP_GATEWAY_IP : HOST_OUTSIDE_IP, listen: o.captureOnly ? undefined : AGENT_LISTEN, url: PAIR_URL },
      net,
    );
    paired = true;
    record.firewall.agentId = p.paired.agentId;
    record.firewall.unpair = p.unpairSecret;
    log(`agent ${p.paired.agentId} (${p.paired.name}), known to the firewall by ${p.paired.address}`);
    log(`the firewall's CA: SHA-256 ${caFingerprint(p.paired.caPem)}`);

    // Recorded first, so disconnect restarts OpenClaw last, after its settings are back.
    const restart = restartArgv(install);
    if (restart && mode === "host") rec.onUndo("restart OpenClaw", [restart], { user: restartUser(install, user) });
    await rec.file(record.ca, `${p.paired.caPem.trim()}\n`);

    const notes: string[] = [];
    if (o.captureOnly) {
      notes.push("No vm-agent (--capture-only): the panel cannot set OpenClaw's models, bots or MCP servers here, or stop it. Its traffic goes through the firewall.");
    } else {
      // Before the vm-agent's first write to OpenClaw's config.
      const kept = await backupConfig(sys, rec, record, install, user);
      if (kept) log(`OpenClaw's config as it was: ${kept} (controlclaw disconnect --restore-config puts it back)`);
      io.out("Installing the vm-agent");
      const paths = await installAgent(sys, rec, {
        binary: agent.path,
        user: agentUser,
        firewallUrl: PAIR_URL,
        firewallKey: p.paired.firewallPublicKey,
        container: record.container,
        agentId: p.paired.agentId,
        keypair: p.keypair,
        // This machine's side of `outside`, where the firewall's container calls it, from its own address only.
        listen: AGENT_LISTEN,
        allowFrom: [FW_OUTSIDE_IP],
        gate: gateOnAgents ? FW_AGENTS_IP : FW_OUTSIDE_IP,
        // A system unit only: a user's own systemd does not know Docker's.
        ...(sys.euid === 0 ? { after: "docker.service" } : {}),
      });
      log(`${paths.bin}, config ${paths.config}`);
      if (!paths.system) {
        const linger = await keepAfterLogout(sys, rec, agentUser);
        if (linger) notes.push(linger);
      }
    }

    io.out(`Setting up ${mode} mode`);
    const ctx: Ctx = { sys, rec, facts, install, user, firewall: record.firewall, caPem: p.paired.caPem, caPath: record.ca, log, ...(fwNet ? { firewallNet: fwNet } : {}) };
    notes.push(...(await (mode === "docker" ? docker : host).install(ctx)));

    if (info?.ports.length || gateOnAgents) {
      // The gateway left its ports: the firewall publishes them now, relayed to it on `agents`.
      if (info?.ports.length) io.out("Publishing OpenClaw's ports from the firewall");
      // Undone before the gateway is put back on its own network, which wants its ports again: the
      // firewall comes back without them, its gates where they were (its compose file is put back
      // first, then this runs).
      rec.onUndo("give OpenClaw's ports back", [compose("up", "-d", "firewall")]);
      await rec.file(join(dir, "compose.yaml"), upCompose({ image: fwRec.image, listen: fwRec.listen, forwards: info?.ports, gateOnAgents }));
      await startFirewall(sys, compose);
    }
    if (mode === "docker") {
      // The gateway restarted on its new network: its own healthcheck says when it answers again.
      await gatewayReady(sys, record.container!, notes);
    }
    record.up!.done = true;
    rec.start();

    io.out("");
    for (const c of await upChecks(sys, record)) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
    for (const n of notes) io.out(`! ${n}`);
    io.out("");
    io.out(`Connected in ${mode} mode to the firewall on this machine.`);
    io.out(`Undo it with: ${sys.euid === 0 ? "sudo " : ""}controlclaw disconnect (uninstall also removes the firewall)`);
    return 0;
  } catch (e) {
    io.err(`connect failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    // The firewall forgets the agent while it still runs; then the rest goes.
    if (paired) await unpair(PAIR_URL, record.firewall.agentId ?? "", record.firewall.unpair ?? "", net.post);
    await undoAll(sys, record, io.err);
    return 1;
  }
}

/** Until the gateway's healthcheck passes, at most about four minutes (its first start sets up plugins). */
async function gatewayReady(sys: Sys, container: string, notes: string[]): Promise<void> {
  try {
    await waitFor(sys, container, 120, () => containerHealthy(sys, container, true));
  } catch {
    notes.push(`${container} is still starting: its Control UI answers once docker ps says healthy.`);
  }
}

/** `up --here`: the firewall on this machine, then OpenClaw here connected to it. */
export async function upHere(sys: Sys, io: Io, o: InstallOpts & ConnectHereOpts, net: HereNet = realNet): Promise<number> {
  if (!loadFirewall(sys)) {
    // The panel opens once, at the end.
    const installed = await installFirewall(sys, io, { ...o, noOpen: true }, net);
    if (installed !== 0) return installed;
  }
  const connected = await connectHere(sys, io, o, net);
  if (connected === 0) {
    await openPanel(sys, io, net.open);
    io.out("Next: open the panel and set it up.");
  }
  return connected;
}

export interface UpAllOpts {
  firewallImage?: string;
  name?: string;
  openclawImage?: string;
  /** OpenClaw's folder (`openclaw install --dir`). */
  dir?: string;
  vmAgent?: string;
}

/**
 * `up --all` (and `up --local`): `install`, `openclaw install --docker`, then `connect`, each skipped
 * when done already, then the panel once. Run again, it checks what is there. Without root for a user
 * who can use Docker, as those three are.
 */
export async function upAll(sys: Sys, io: Io, o: UpAllOpts, net: HereNet = realNet): Promise<number> {
  const tmp: { dir: string | null } = { dir: null };
  try {
    return await upAllWith(sys, io, o, net, tmp);
  } finally {
    if (tmp.dir) sys.remove(tmp.dir);
  }
}

async function upAllWith(sys: Sys, io: Io, o: UpAllOpts, net: HereNet, tmp: { dir: string | null }): Promise<number> {
  const existing = loadRecord(sys);
  if (existing?.mode === "local") return oldLocal(sys, io, existing, net);
  if (sys.euid !== 0 && !existing && !loadFirewall(sys) && (sys.exists(ROOT_RECORD) || sys.exists(ROOT_FIREWALL))) {
    io.err("This machine was set up with sudo. Run: sudo npx controlclaw up --all");
    return 1;
  }
  const theirs = await sudoUserRecord(sys);
  if (theirs) {
    io.err(`This machine was set up by ${theirs.user.name} without sudo. Run, as ${theirs.user.name}: npx controlclaw up --all`);
    return 1;
  }
  if (existing && !existing.up) {
    io.err(`This machine's OpenClaw is connected to another firewall (${existing.mode} mode, ${existing.firewall.url}). Run controlclaw disconnect first.`);
    return 1;
  }
  const fwHere = loadFirewall(sys);
  if (fwHere?.kind === "host") {
    io.err("The firewall here was installed with install.sh, which up --all cannot pair with by itself: controlclaw openclaw install --firewall http://<its address>:8801, with a code from its panel.");
    return 1;
  }
  if (!fwHere) {
    const installed = await installFirewall(sys, io, { firewallImage: o.firewallImage, noOpen: true }, net);
    if (installed !== 0) return installed;
  }
  let connected: number;
  if (existing) {
    connected = await connectHere(sys, io, { name: o.name, vmAgent: o.vmAgent }, net);
  } else {
    // Whether OpenClaw is here already (an earlier up --all that stopped before connect): the
    // vm-agent tells, downloaded once for the look and for connect.
    const found = await vmAgentOrRelease(await findVmAgent(sys, o.vmAgent), io);
    if (!found) return 1;
    tmp.dir = found.downloaded;
    const vmAgent = found.path;
    const facts = await gatherFacts(sys, { vmAgent });
    if (facts.openclaw.discoverError) {
      io.err(`The vm-agent could not look for OpenClaw here (vm-agent discover: ${facts.openclaw.discoverError}).`);
      return 1;
    }
    if (facts.openclaw.install.runs.kind === "not-found") {
      io.out("");
      connected = await openclawInstall(sys, io, { openclawImage: o.openclawImage, dir: o.dir, name: o.name, vmAgent }, net);
    } else {
      io.out(`OpenClaw is on this machine already (${runsText(facts.openclaw.install.runs, facts.openclaw.user?.name ?? null)}): connecting it`);
      connected = await connectHere(sys, io, { name: o.name, vmAgent }, net);
    }
  }
  // connect again opens the panel itself, after its checks.
  if (connected === 0 && !existing?.up) {
    await openPanel(sys, io, net.open);
    io.out("Next: open the panel and set it up.");
  }
  return connected;
}

/**
 * A machine set up by `up --local` before 0.10.1 (`/opt/controlclaw-local`, two containers of one
 * Compose project): it keeps running as it is. `up --all` checks it; uninstall, then `up --all`,
 * moves it to the shape the three commands make (its data stays in its folder and volume).
 */
async function oldLocal(sys: Sys, io: Io, record: ConnectRecord, net: HereNet): Promise<number> {
  io.out(`This machine was set up by up --local or up --all of 0.10.0 or earlier (since ${record.at}, in ${record.up?.dir ?? "/opt/controlclaw-local"}): checking it`);
  const checks = await local.status(sys, record);
  for (const c of checks) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
  await openPanel(sys, io, net.open);
  io.out("It keeps working as it is. To move to the current setup: sudo npx controlclaw uninstall, then npx controlclaw up --all (a new OpenClaw: its old data stays in its folder).");
  return checks.every((c) => c.ok) ? 0 : 1;
}

/**
 * `controlclaw uninstall`: disconnect (when connected), then the firewall. Its data (the volume, or
 * install.sh's /opt/controlclaw) only with `--purge`.
 */
export async function uninstall(sys: Sys, io: Io, o: { purge?: boolean; force?: boolean }, post = realNet.post): Promise<number> {
  if (sys.euid !== 0 && !loadFirewall(sys) && !loadRecord(sys) && (sys.exists(ROOT_RECORD) || sys.exists(ROOT_FIREWALL))) {
    io.err("This machine was set up with sudo. Run: sudo controlclaw uninstall");
    return 1;
  }
  let failed = 0;
  const connected = loadRecord(sys);
  const localVolume = connected?.mode === "local" ? LOCAL_VOLUME : null;
  if (connected) failed += (await disconnect(sys, io, { force: o.force }, post)) === 0 ? 0 : 1;
  if (localVolume && o.purge) failed += await removeVolume(sys, io, localVolume);
  // up --local's volume, also after a disconnect that already stopped its containers.
  if (!localVolume && o.purge && (await sys.run(["docker", "volume", "inspect", LOCAL_VOLUME])).code === 0) failed += await removeVolume(sys, io, LOCAL_VOLUME);
  const fw = loadFirewall(sys);
  if (!fw) {
    if (!connected) io.out(o.purge ? "No firewall installed here, and not connected." : "No firewall installed here, and not connected (up --local's data stays without --purge).");
    return failed ? 1 : 0;
  }
  if (loadRecord(sys)) {
    io.err("The firewall stays: disconnect did not finish (above). Run controlclaw uninstall again once fixed, or disconnect --force first.");
    return 1;
  }
  io.out(`Removing the firewall (${fw.kind === "docker" ? "its container" : "install.sh's units"})`);
  if (fw.kind === "host" && o.purge) {
    // install.sh removes its data itself with --purge.
    fw.steps = fw.steps.map((s) => (s.kind === "run" ? { ...s, argv: s.argv.map((a) => (a[0] === fw.installer && a[1] === "--uninstall" ? [...a, "--purge"] : a)) } : s));
  }
  const left = await undoAll(sys, fw, io.err, firewallRecordPath(sys));
  if (left) {
    io.out(`Done, with ${left} step(s) that failed (above). Run uninstall again once fixed.`);
    return 1;
  }
  if (fw.kind === "docker" && o.purge) failed += await removeVolume(sys, io, `${fw.project}_firewall`);
  io.out(o.purge ? "Done. The firewall and its data are gone." : "Done. The firewall's data stays (uninstall --purge removes it).");
  return failed ? 1 : 0;
}

async function removeVolume(sys: Sys, io: Io, volume: string): Promise<number> {
  const r = await sys.run(["docker", "volume", "rm", volume]);
  if (r.code === 0 || /no such volume/i.test(r.stderr)) return 0;
  io.err(`  could not remove the volume ${volume}: ${r.stderr.trim()}`);
  return 1;
}

/** `status` for a connect to the firewall here: the firewall's container, then the mode's checks. */
export async function upChecks(sys: Sys, record: ConnectRecord): Promise<Check[]> {
  const checks: Check[] = [await firewallCheck(sys, record.up!.project)];
  const mode = record.mode === "docker" ? docker : host;
  checks.push(...(await mode.status(sys, record)));
  return checks;
}

/** The firewall `install` runs here: its container running, or install.sh's firewall agent active. */
export async function firewallCheck(sys: Sys, project?: string, kind: FirewallRecord["kind"] = "docker"): Promise<Check> {
  if (kind === "host") {
    const r = await sys.run(["systemctl", "is-active", "controlclaw-mitm-agent"]);
    return { name: "firewall", ok: r.stdout.trim() === "active", detail: `controlclaw-mitm-agent ${r.stdout.trim() || "unknown"}` };
  }
  const r = await sys.run(["docker", "inspect", "-f", "{{.State.Status}}", `${project ?? UP_PROJECT}-firewall-1`]);
  const st = r.stdout.trim();
  return { name: "firewall container", ok: r.code === 0 && st === "running", detail: st || "not there" };
}

/**
 * `connect` again on a machine it connected to the firewall here: the firewall started if it is not
 * (after a failure, say), then the checks. Pairing is never done twice.
 */
async function resume(sys: Sys, io: Io, record: ConnectRecord, openNet?: OpenNet): Promise<number> {
  const up = record.up!;
  if (!up.done) {
    io.err("An earlier connect stopped half way and could not undo all of it. Run controlclaw disconnect (--force for steps that keep failing), then connect again.");
    return 1;
  }
  io.out(`Already connected to the firewall on this machine (${record.mode} mode, since ${record.at}): checking it`);
  try {
    await startFirewall(sys, composeIn(up.project, up.dir));
  } catch (e) {
    io.err(`The firewall's container does not start (${(e as Error).message}): docker compose -p ${up.project} logs firewall says why.`);
    return 1;
  }
  const checks = await upChecks(sys, record);
  for (const c of checks) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
  const ok = checks.every((c) => c.ok);
  if (!ok) io.out("Something above is not right (✗). controlclaw status shows it again; controlclaw disconnect, then connect, starts over.");
  if (openNet) await openPanel(sys, io, openNet);
  return ok ? 0 : 1;
}

export { realOpenNet };
