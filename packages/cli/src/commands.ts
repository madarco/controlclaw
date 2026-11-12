import { randomBytes } from "node:crypto";
import { hostname } from "node:os";
import { join } from "node:path";
import { AGENT_PORT, agentPaths, installAgent, keepAfterLogout, REMOTE_AGENT_PORT, UNIT } from "./agent.js";
import { checkPem } from "./ca.js";
import { GATE_ADDR } from "./capture/docker.js";
import type { Ctx } from "./capture/mode.js";
import { doctorJson, gatherFacts, MODES, renderDoctor, runsText } from "./doctor.js";
import { backupConfig, backupText, restoreConfig } from "./openclaw-config.js";
import { cliArgv, restartArgv, restartUser } from "./openclaw.js";
import { WG_UNIT } from "./capture/remote.js";
import { agentKeypair, wgKeypair, caFingerprint, httpPost, normalizeCode, onThisMachine, type Paired, type Post, pair, pairUrl, sourceToward, unpair } from "./pair.js";
import { type Check, dnsAnswers, ipv4Of, proxyAnswers, splitHostPort } from "./probe.js";
import { vmAgentOrRelease } from "./release.js";
import { type ConnectRecord, loadFirewall, loadRecord, type Mode, Recorder, ROOT_RECORD, recordPath, stateDir, sudoUserRecord, undoAll } from "./state.js";
import { type Sys, type User, userByUid } from "./sys.js";
import { firewallCheck, upChecks } from "./up.js";

export interface Io {
  out: (line: string) => void;
  err: (line: string) => void;
  /** One line typed by the person (not echoed), or the first line of stdin; null when there is none. */
  ask?: (prompt: string) => Promise<string | null>;
}

export interface ConnectOpts {
  mode?: string;
  firewall?: string;
  ca?: string;
  firewallKey?: string;
  proxy?: string;
  dns?: string;
  user?: string;
  vmAgent?: string;
  /** The pairing code, or `-` to read it from stdin. Left out, connect asks for it. */
  code?: string;
  /** A file holding the pairing code. */
  codeFile?: string;
  name?: string;
  /** The capture alone: no vm-agent. */
  captureOnly?: boolean;
}

export async function doctor(sys: Sys, io: Io, opts: { json?: boolean; user?: string; vmAgent?: string }): Promise<number> {
  const f = await gatherFacts(sys, opts);
  io.out(opts.json ? JSON.stringify(doctorJson(f), null, 2) : renderDoctor(f));
  return 0;
}

/**
 * The pairing code, kept off the command line (any user can read another's in /proc): asked for,
 * read from stdin (`--code -`) or from `--code-file`. `--code <code>` is refused.
 */
async function readCode(sys: Sys, io: Io, o: ConnectOpts): Promise<string | null> {
  if (o.codeFile) {
    const text = sys.read(o.codeFile);
    if (text === null) {
      io.err(`--code-file: cannot read ${o.codeFile}`);
      return null;
    }
    if ((sys.stat(o.codeFile)?.mode ?? 0) & 0o077) io.out(`! ${o.codeFile} can be read by other users: keep it 0600, and delete it after.`);
    return text.trim();
  }
  if (o.code && o.code !== "-") {
    io.err("Not on the command line: every user of this machine can read it while connect runs. Leave out --code and type the code when asked, or use --code - (stdin) or --code-file <file>.");
    return null;
  }
  const typed = io.ask ? await io.ask(o.code === "-" ? "" : "Pairing code from the firewall (mitm-agent pair-code): ") : null;
  if (!typed?.trim()) {
    io.err("No pairing code: type it when asked, or pass --code - (stdin) or --code-file <file>.");
    return null;
  }
  return typed.trim();
}

/** `--firewall-key` is a PEM file, or the PEM itself. */
function readKey(sys: Sys, v: string): string {
  if (v.trim().startsWith("-----BEGIN")) return v.trim();
  const pem = sys.read(v);
  if (!pem || !pem.includes("-----BEGIN PUBLIC KEY-----")) throw new Error(`--firewall-key: ${v} is not a PEM public key`);
  return pem.trim();
}

/** The network calls pairing makes, swapped in tests. */
export interface PairNet {
  post: Post;
  /** This machine's address toward an IPv4 address. */
  source: (ip: string) => Promise<string>;
  ipv4: (host: string) => Promise<string>;
  /**
   * Whether the firewall at `ip`, reached from `source`, is on this machine: one of its own
   * addresses, or a container behind one of its Docker bridges.
   */
  sameMachine?: (ip: string, source: string) => boolean;
}

export const realNet: PairNet = { post: httpPost, source: sourceToward, ipv4: ipv4Of, sameMachine: onThisMachine };

export async function connect(sys: Sys, io: Io, o: ConnectOpts, net: PairNet = realNet): Promise<number> {
  const tmp: { dir: string | null } = { dir: null };
  try {
    return await connectWith(sys, io, o, net, tmp);
  } finally {
    // A downloaded vm-agent is installed by now, or not needed: its folder goes either way.
    if (tmp.dir) sys.remove(tmp.dir);
  }
}

async function connectWith(sys: Sys, io: Io, o: ConnectOpts, net: PairNet, tmp: { dir: string | null }): Promise<number> {
  // auto (the default): docker for an OpenClaw in a container, else host; decided once it is found.
  const auto = o.mode === undefined || o.mode === "auto";
  let mode = auto ? undefined : MODES.find((m) => m.name === o.mode && m.name !== "local");
  if (!auto && !mode) {
    io.err("--mode must be auto, docker, host, proxy or remote.");
    return 2;
  }
  if (!o.firewall) {
    io.err("connect needs --firewall <url>: the firewall's pairing address (or, by hand, its URL with --ca and --firewall-key).");
    return 2;
  }
  const pairing = !o.ca;
  if (mode?.name === "remote" && !pairing) {
    io.err("Remote mode pairs with a code (the firewall gives this machine its tunnel): leave out --ca and --firewall-key.");
    return 2;
  }
  if (mode?.name === "remote" && (o.proxy || o.dns)) {
    // They would point the capture at an address outside the tunnel, in clear.
    io.err("Remote mode uses the firewall's proxy and DNS inside the tunnel: leave out --proxy and --dns.");
    return 2;
  }
  if (pairing && o.firewallKey) {
    io.err("--firewall-key goes with --ca. Without them, connect pairs with a code, which brings both.");
    return 2;
  }
  if (!pairing && (o.code || o.codeFile)) {
    io.err("A pairing code brings the firewall's CA and key: leave out --ca and --firewall-key.");
    return 2;
  }
  const existing = loadRecord(sys);
  if (existing) {
    io.err(`Already connected (${existing.mode} mode). Run controlclaw disconnect first (--force gives up steps that keep failing).`);
    return 1;
  }

  let url: URL;
  try {
    url = new URL(o.firewall);
  } catch {
    io.err(`--firewall: not a URL: ${o.firewall}`);
    return 2;
  }
  let caPem: string | null = null;
  let key: string | null = null;
  let code: string | null = null;
  if (pairing) {
    code = await readCode(sys, io, o);
    if (code === null) return 2;
    if (!normalizeCode(code)) {
      io.err("The pairing code is 12 letters and digits, like 4F7K-92QD-XM3P.");
      return 2;
    }
  } else {
    caPem = sys.read(o.ca ?? "");
    const bad = caPem === null ? `cannot read ${o.ca}` : checkPem(caPem);
    if (bad || !caPem) {
      io.err(`--ca: ${bad}`);
      return 2;
    }
    try {
      if (o.firewallKey) key = readKey(sys, o.firewallKey);
    } catch (e) {
      io.err((e as Error).message);
      return 2;
    }
  }

  io.out("Checking this machine");
  let facts = await gatherFacts(sys, { user: o.user, vmAgent: o.vmAgent });
  const agent = await vmAgentOrRelease(facts.vmAgent, io);
  if (!agent) return 1;
  const binary = agent.path;
  if (agent.downloaded) {
    tmp.dir = agent.downloaded;
    // OpenClaw's discovery and the mode checks need it: look again with it.
    facts = await gatherFacts(sys, { user: o.user, vmAgent: binary });
  }
  if (facts.openclaw.discoverError) {
    // A quick look cannot tell how OpenClaw runs, and the capture depends on it.
    io.err(`The vm-agent could not look at this OpenClaw (vm-agent discover: ${facts.openclaw.discoverError}).`);
    return 1;
  }
  if (!mode) {
    const runs = facts.openclaw.install.runs.kind;
    if (runs === "not-found") {
      io.err("No OpenClaw on this machine. Install one first: controlclaw openclaw install.");
      return 1;
    }
    mode = MODES.find((m) => m.name === (runs === "docker" ? "docker" : "host"))!;
    io.out(`  OpenClaw ${facts.openclaw.install.version ?? ""}: ${runsText(facts.openclaw.install.runs, facts.openclaw.user?.name ?? null)}. Mode: ${mode.name} (--mode overrides it).`);
  }
  const blockers = mode.blockers(facts);
  if (blockers.length) {
    io.err(`This machine cannot do ${mode.name} mode:`);
    for (const b of blockers) io.err(`  - ${b}`);
    return 1;
  }

  const install = facts.openclaw.install;
  const user = facts.openclaw.user;
  const container = install.runs.kind === "docker" ? install.runs.container : undefined;
  // The agent runs as OpenClaw's user; for a container, as whoever can use Docker (this user).
  const agentUser: User | null = user ?? userByUid(sys, sys.euid);
  if (!agentUser) {
    io.err("Cannot tell which user to run the vm-agent as. Pass --user.");
    return 1;
  }

  // Pairing comes after the checks (a machine that cannot do the mode spends no code) and before
  // anything is installed (a failed pairing leaves nothing to undo).
  let paired: Paired | null = null;
  let keypair: { privatePem: string; publicPem: string } | undefined;
  let wgKeys: { privateKey: string; publicKey: string } | undefined;
  const unpairSecret = randomBytes(32).toString("hex");
  // Paired: where the firewall calls the vm-agent, and the one address it calls from.
  let reach: { listen: string; allowFrom: string[] } | undefined;
  let sameHost = true;
  if (code !== null) {
    keypair = agentKeypair();
    // Remote: this machine's WireGuard key, made here so a failed pairing leaves nothing behind.
    wgKeys = mode.name === "remote" ? wgKeypair() : undefined;
    const withAgent = !o.captureOnly;
    try {
      // The firewall checks that the request comes from the address it says: so both are the IPv4
      // address measured here (plain HTTP goes to it directly, not over IPv6 or another record).
      const ip = await net.ipv4(url.hostname);
      const source = await net.source(ip);
      const base = new URL(url.toString());
      if (base.protocol === "http:") base.hostname = ip;
      io.out(`Pairing with ${pairUrl(base.toString())}, from ${source}`);
      // The firewall calls the vm-agent in plain HTTP: over the tunnel (remote mode, on its tunnel
      // address, the firewall's default there), or on this machine (the firewall on it: the route
      // to it is local, so the source is its address). Never across a network in clear.
      sameHost = (net.sameMachine ?? onThisMachine)(ip, source);
      const agentListen = withAgent && !wgKeys && sameHost ? `${source}:${AGENT_PORT}` : undefined;
      paired = await pair(base.toString(), code, { publicKey: keypair.publicPem, name: o.name ?? hostname(), source, unpairSecret, wgPublicKey: wgKeys?.publicKey, agentListen }, net.post);
      reach = paired.wg
        ? { listen: `${paired.wg.address}:${REMOTE_AGENT_PORT}`, allowFrom: [paired.wg.firewallAddress] }
        : agentListen ? { listen: agentListen, allowFrom: [paired.callsFrom ?? ip] } : undefined;
    } catch (e) {
      io.err(`Pairing failed: ${(e as Error).message}`);
      return 1;
    }
    if (wgKeys && !paired.wg) {
      io.err("Pairing failed: the firewall gave no tunnel (does it run WireGuard? install.sh --wireguard)");
      return 1;
    }
    caPem = paired.caPem;
    key = paired.firewallPublicKey;
    io.out(`  agent ${paired.agentId} (${paired.name}), known to the firewall by ${paired.address}`);
    io.out(`  the firewall's CA: SHA-256 ${caFingerprint(caPem)}`);
    if (paired.replaced.length) {
      io.out(`  ! the firewall had ${paired.replaced.join(", ")} at ${paired.address}: this machine replaces it (the proxy tells agents apart by address only)`);
    }
  }
  const badCa = caPem === null ? "missing" : checkPem(caPem);
  if (badCa || caPem === null) {
    io.err(`The firewall's CA: ${badCa}`);
    return 1;
  }

  let proxyAddr: string;
  let dns: string | null = null;
  try {
    const p = splitHostPort(o.proxy ?? paired?.proxy ?? url.hostname, 8080);
    proxyAddr = `${p.host}:${p.port}`;
    if (mode.name !== "proxy") dns = await ipv4Of(o.dns ?? paired?.dns ?? url.hostname);
  } catch (e) {
    io.err((e as Error).message);
    return 2;
  }

  const record: ConnectRecord = {
    version: 1,
    mode: mode.name as Mode,
    at: new Date().toISOString(),
    user,
    firewall: { url: url.toString(), proxy: proxyAddr, dns, ...(paired ? { agentId: paired.agentId, unpair: unpairSecret } : {}) },
    container,
    cli: cliArgv(install, []),
    // On this machine; in docker mode the override mounts it into the gateway.
    ca: join(stateDir(sys), "ca.crt"),
    ...(o.captureOnly ? { captureOnly: true } : {}),
    steps: [],
  };
  const rec = new Recorder(sys, record);
  rec.start();
  const log = (l: string) => io.out(`  ${l}`);
  let lingerNote: string | null = null;
  try {
    // Recorded first, so disconnect restarts OpenClaw last, after its settings are back.
    const restart = restartArgv(install);
    if (restart && mode.name !== "docker") {
      rec.onUndo("restart OpenClaw", [restart], { user: restartUser(install, user) });
    }
    const caPath = record.ca;
    await rec.file(caPath, `${caPem.trim()}\n`);

    const tunnel = paired?.wg && wgKeys
      ? { address: paired.wg.address, firewall: paired.wg.firewallAddress, firewallPublicKey: paired.wg.firewallPublicKey, endpoint: paired.wg.endpoint, privateKey: wgKeys.privateKey }
      : undefined;
    const ctx: Ctx = { sys, rec, facts, install, user, firewall: record.firewall, caPem, caPath, log, ...(tunnel ? { tunnel } : {}) };
    if (mode.prepare) {
      io.out(`Preparing ${mode.name} mode`);
      await mode.prepare(ctx);
    }
    if (o.captureOnly) {
      log("No vm-agent (--capture-only): the firewall cannot set OpenClaw's models, bots or MCP servers here, or stop it.");
    } else {
      // Before the vm-agent's first write to OpenClaw's config.
      const kept = await backupConfig(sys, rec, record, install, user);
      if (kept) log(`OpenClaw's config as it was: ${kept} (controlclaw disconnect --restore-config puts it back)`);
      io.out("Installing the vm-agent");
      const paths = await installAgent(sys, rec, { binary, user: agentUser, firewallUrl: url.toString(), firewallKey: key, container, agentId: paired?.agentId, keypair,
        ...(reach ?? {}),
        // Where OpenClaw reaches the firewall's gates: its own loopback in docker mode (relayed to the
        // gate container), else the proxy's address (the tunnel's in remote mode). Not in proxy mode:
        // everything OpenClaw sends goes through the proxy there, which never connects to the firewall itself.
        ...(mode.name === "proxy" ? {} : { gate: mode.name === "docker" ? GATE_ADDR : await ipv4Of(splitHostPort(proxyAddr, 8080).host) }),
        // Remote: once the tunnel is up.
        ...(paired?.wg ? { after: WG_UNIT } : {}) });
      log(`${paths.bin}, config ${paths.config}`);
      if (!key) log("No --firewall-key: the agent answers nothing until it has the firewall's key (pair with --code).");
      if (!paths.system) {
        const linger = await keepAfterLogout(sys, rec, agentUser);
        if (linger) lingerNote = linger;
      }
    }

    io.out(`Setting up ${mode.name} mode`);
    const notes = await mode.install(ctx);
    if (lingerNote) notes.push(lingerNote);

    io.out("");
    for (const c of [...(await mode.status(sys, record)), await proxyAnswers(proxyAddr)]) io.out(`${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
    for (const n of notes) io.out(`! ${n}`);
    if (paired && !paired.wg && !sameHost && !o.captureOnly) {
      io.out("! The firewall is on another machine: it does not call this agent's vm-agent (that would be plain HTTP across the network), so it cannot set bots, models or MCP servers here or stop OpenClaw. Use --mode remote for those.");
    }
    io.out("");
    io.out(`Connected in ${mode.name} mode. Protection: ${mode.protects}.`);
    io.out("Undo it all with: controlclaw disconnect");
    return 0;
  } catch (e) {
    io.err(`Connect failed: ${(e as Error).message}`);
    io.err("Undoing what was done");
    await undoAll(sys, record, io.err);
    if (paired) {
      await unpairFrom(record.firewall, io, net.post);
      io.err("The code is spent: make a new one.");
    }
    return 1;
  }
}

/**
 * With sudo, on a machine set up without it (`up` by a user who can use Docker): the record and the
 * vm-agent's user service are that user's, so the command runs as that user.
 */
async function asSetupUser(sys: Sys, io: Io, argv: string[]): Promise<number | null> {
  const theirs = await sudoUserRecord(sys);
  if (!theirs) return null;
  const u = theirs.user;
  // `sudo npx` runs a copy in root's cache, which the user may not read: then they run it themselves.
  const script = process.argv[1] ?? "";
  if (!script || (await sys.run(["test", "-r", script], { user: u })).code !== 0) {
    io.err(`This machine was set up by ${u.name} without sudo. Run, as ${u.name}: controlclaw ${argv.join(" ")}`);
    return 1;
  }
  io.out(`Set up by ${u.name} without sudo: running as ${u.name}.`);
  const r = await sys.run([process.execPath, script, ...argv], { user: u, timeoutMs: 900_000 });
  if (r.stdout.trim()) io.out(r.stdout.trimEnd());
  if (r.stderr.trim()) io.err(r.stderr.trimEnd());
  return r.code;
}

/** Without root, a connect made with sudo is not this user's to see: say so instead of "Not connected". */
function needsSudo(sys: Sys, io: Io, what: string): boolean {
  if (sys.euid === 0 || !sys.exists(ROOT_RECORD)) return false;
  io.err(`This machine was connected with sudo. Run: sudo controlclaw ${what}`);
  return true;
}

/** Asks the firewall to forget this agent, with the secret it paired with. It says when it could not. */
async function unpairFrom(fw: ConnectRecord["firewall"], io: Io, post: Post): Promise<void> {
  if (!fw.agentId) return;
  const r = fw.unpair ? await unpair(fw.url, fw.agentId, fw.unpair, post) : "no secret was kept";
  if (r === null) io.out(`  The firewall forgot this machine (${fw.agentId}).`);
  else io.out(`  ! The firewall still lists this machine as ${fw.agentId} (${r}); remove it there if it is not coming back.`);
}

export async function disconnect(sys: Sys, io: Io, opts: { force?: boolean; restoreConfig?: boolean } = {}, post: Post = httpPost): Promise<number> {
  const record = loadRecord(sys);
  if (!record && needsSudo(sys, io, "disconnect")) return 1;
  if (!record) {
    const code = await asSetupUser(sys, io, ["disconnect", ...(opts.force ? ["--force"] : []), ...(opts.restoreConfig ? ["--restore-config"] : [])]);
    if (code !== null) return code;
  }
  if (!record) {
    io.out("Not connected.");
    return 0;
  }
  // Read before the undo removes it.
  const before = opts.restoreConfig ? backupText(sys, record) : null;
  if (opts.restoreConfig && before === null) io.err("  No copy of OpenClaw's config was kept (connect made none): it stays as it is.");
  io.out(`Removing ${record.mode} mode, the CA${record.captureOnly ? "" : " and the vm-agent"}${record.mode === "local" ? ", and stopping the containers (their data stays)" : ""}`);
  await unpairFrom(record.firewall, io, post);
  const failed = await undoAll(sys, record, io.err);
  // Only once the vm-agent is gone: one still running could write its settings back over it.
  if (before !== null && record.configBackup && !failed) await restoreConfig(sys, io, record.configBackup, before);
  else if (before !== null && failed && record.configBackup) {
    // The undo may have removed the copy already: kept for the next disconnect --restore-config.
    sys.write(record.configBackup.copy, before, { mode: 0o600 });
    io.err(`  OpenClaw's config is not put back while steps failed: the copy stays in ${record.configBackup.copy}. Run disconnect --restore-config again once fixed.`);
  }
  else if (record.configBackup && !failed) io.out("  OpenClaw keeps what the panel set in its config (disconnect --restore-config puts back the copy from before connect).");
  if (!failed) {
    io.out(`Done. This machine is as it was before connect${record.up && record.mode !== "local" ? "; the firewall here still runs (controlclaw uninstall removes it)" : ""}.`);
    return 0;
  }
  if (opts.force) {
    // A step that can never work (its target is gone) must not keep the machine "connected".
    sys.remove(recordPath(sys));
    sys.removeEmptyDir(stateDir(sys));
    io.out(`Done. ${failed} step(s) failed (above) and were given up; check them by hand.`);
    return 1;
  }
  io.out(`Done, with ${failed} step(s) that failed (above). They are kept: run disconnect again once fixed, or disconnect --force to give them up.`);
  return 1;
}

export async function status(sys: Sys, io: Io, opts: { json?: boolean }): Promise<number> {
  const record = loadRecord(sys);
  if (!record && needsSudo(sys, io, "status")) return 1;
  if (!record) {
    const code = await asSetupUser(sys, io, ["status", ...(opts.json ? ["--json"] : [])]);
    if (code !== null) return code;
  }
  const fw = loadFirewall(sys);
  if (!record) {
    const c = fw ? await firewallCheck(sys, fw.project, fw.kind) : null;
    if (opts.json) io.out(JSON.stringify({ connected: false, ...(c ? { firewall: { kind: fw!.kind, ...c } } : {}) }));
    else io.out(`Not connected.${c ? `\n  ${c.ok ? "✓" : "✗"} ${c.name} (installed here): ${c.detail}` : ""}`);
    return c && !c.ok ? 1 : 0;
  }
  const mode = MODES.find((m) => m.name === record.mode)!;
  const checks: Check[] = record.up && record.mode !== "local" ? await upChecks(sys, record) : await mode.status(sys, record);
  // A firewall installed here that this machine is not paired with (it pairs elsewhere): shown too.
  if (fw && !record.up) checks.unshift(await firewallCheck(sys, fw.project, fw.kind));
  const agentUser = record.user ?? userByUid(sys, sys.euid);
  if (agentUser && !record.captureOnly) {
    const p = agentPaths(sys, agentUser);
    const r = await sys.run([...(p.system ? ["systemctl"] : ["systemctl", "--user"]), "is-active", UNIT]);
    checks.push({ name: "vm-agent", ok: r.stdout.trim() === "active", detail: r.stdout.trim() || "unknown" });
  }
  // The firewall of up --local, and of up in docker mode, is on a network this machine is not on:
  // their own check runs from inside OpenClaw.
  if (record.mode !== "local" && !record.up?.network) {
    checks.push(await proxyAnswers(record.firewall.proxy));
    if (record.firewall.dns && !checks.some((c) => c.name === "firewall DNS")) checks.push(await dnsAnswers(record.firewall.dns));
  }
  const ok = checks.every((c) => c.ok);
  if (opts.json) {
    io.out(JSON.stringify({ connected: true, mode: record.mode, since: record.at, firewall: record.firewall, ok, checks }, null, 2));
  } else {
    io.out(`Connected in ${record.mode} mode since ${record.at}, firewall ${record.firewall.url}${record.firewall.agentId ? `, as ${record.firewall.agentId}` : ""}`);
    for (const c of checks) io.out(`  ${c.ok ? "✓" : "✗"} ${c.name}: ${c.detail}`);
  }
  return ok ? 0 : 1;
}
