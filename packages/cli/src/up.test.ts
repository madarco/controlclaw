import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { overrideOnFirewallNet, parseInspect } from "./capture/docker.js";
import { run } from "./cli.js";
import { disconnect, type Io, status } from "./commands.js";
import { CA, fakeMachine, fixture, KEY } from "./fake-machine.js";
import type { Ask } from "./menu.js";
import { open, type OpenNet } from "./open.js";
import { hmacHex, normalizeCode, type Post, REQUEST_TAG, RESPONSE_TAG } from "./pair.js";
import { loadFirewall, loadRecord } from "./state.js";
import type { FakeSys } from "./sys.js";
import { connectHere, type HereNet, installFirewall, uninstall, upAll, UP_GATEWAY_IP, upCompose, upHere } from "./up.js";

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

const CODE = "4F7K-92QD-XM3P";
const NEW_PANEL: OpenNet = { session: async () => ({ setup: true }) };
const IMAGE = "ghcr.io/madarco/controlclaw-firewall:0.9.4";
const FW = "docker compose -p controlclaw-firewall --project-directory /etc/controlclaw/firewall -f /etc/controlclaw/firewall/compose.yaml";
const GW = "docker compose -p openclaw --project-directory /root/openclaw -f /root/openclaw/docker-compose.yml";

/** No terminal: the menu cannot be shown. */
const noTerminal: Ask = { pick: async () => null, line: async () => null };

/** The firewall's pairing endpoint, as cc-local answers: the code's address is the agent's. */
function firewall(address: string) {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  const post: Post = async (url, body) => {
    calls.push({ url, body: body as Record<string, unknown> });
    if (url.endsWith("/unpair")) return { status: 200, json: { ok: true } };
    const { request } = body as { request: string };
    const req = JSON.parse(request) as Record<string, unknown>;
    const key = normalizeCode(CODE)!;
    const pairing = JSON.stringify({ v: 1, nonce: req.nonce, agent_id: "agent_up1", name: req.name, address, firewall_public_key: KEY, ca_pem: CA, replaced: [] });
    if ((body as { proof: string }).proof !== hmacHex(key, REQUEST_TAG, request)) return { status: 401, json: { error: "no" } };
    return { status: 200, json: { pairing, mac: hmacHex(key, RESPONSE_TAG, pairing) } };
  };
  const net: HereNet = { post, source: async () => "127.0.0.1", ipv4: async () => "127.0.0.1", open: NEW_PANEL, busy: async () => false };
  return { calls, net };
}

function hasDocker(): boolean {
  try {
    execFileSync("docker", ["compose", "version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** A machine whose firewall container runs (once `install` started it). */
function upMachine(kind: "docker" | "systemd-user", dir = "/etc/controlclaw/firewall"): FakeSys {
  const sys = fakeMachine(kind);
  // As the firewall prints it: the hint, then the code.
  sys.on("mitm-agent pair-code", { stdout: `On the agent's machine: controlclaw connect --firewall http://<this firewall>:8801 --mode <mode>, and type the code when it asks\nIt works once, within 10 minutes.\n${CODE}\n` });
  sys.on("{{.State.Status}}", { stdout: "running\n" });
  sys.on("{{.State.Health.Status}}", { stdout: "healthy\n" });
  sys.on("com.docker.network.bridge.gateway_mode_ipv4", { stdout: "isolated\n" });
  sys.on("{{json .NetworkSettings.Networks}}", { stdout: '{"controlclaw-firewall_agents":{}}' });
  sys.on("node -e", { stdout: "HTTP 403\n" });
  sys.on(`compose -p controlclaw-firewall --project-directory ${dir} -f ${dir}/compose.yaml logs`, {
    stdout: "firewall-1  | [cc-local] no admin yet: set the password with this one-time setup token (POST /api/setup): 0a1d11\nfirewall-1  | [cc-local] no admin yet: set the password with this one-time setup token (POST /api/setup): beef22\n",
  });
  return sys;
}

test("install: the firewall's Compose file, for this machine and for others on --listen", () => {
  const info = parseInspect(fixture("inspect-compose.json"))!;
  const d = upCompose({ image: IMAGE, forwards: info.ports });
  assert.match(d, /^name: controlclaw-firewall$/m);
  assert.match(d, /  agents:\n    internal: true\n    enable_ipv6: false\n    driver_opts:\n      com.docker.network.bridge.gateway_mode_ipv4: isolated/);
  assert.match(d, /networks:\n      agents:\n        ipv4_address: 172.31.251.2\n      outside:\n        ipv4_address: 172.31.252.2/, "a fixed address: allow_from stays right");
  assert.match(d, /CONNECTOR_GATE_BIND: "172.31.252.2"/);
  assert.match(d, /PAIR_BIND: "172.31.252.2:8801"/);
  assert.match(d, /PAIR_PROXY_ADDR: "172.31.251.2:8080"/);
  assert.match(d, /CC_FORWARD: "18789=172.31.251.10:18789,18790=172.31.251.10:18790"/);
  for (const port of ["8800", "8801", "8790"]) assert.match(d, new RegExp(`- "127.0.0.1:${port}:${port}"`), "on loopback only");
  assert.match(d, /- "18789:18789" # OpenClaw's/, "the gateway's ports as it published them");
  assert.doesNotMatch(d, /- "10\./);
  // One relay per port, also when it was published on two addresses; IPv6 in brackets.
  const two = upCompose({ image: IMAGE, forwards: [{ host: "127.0.0.1:18789", container: 18789 }, { host: "[::1]:18789", container: 18789 }] });
  assert.match(two, /CC_FORWARD: "18789=172.31.251.10:18789"\n/);
  assert.match(two, /- "\[::1\]:18789:18789"/);
  const v6 = JSON.parse(fixture("inspect-compose.json"));
  v6[0].HostConfig.PortBindings = { "18789/tcp": [{ HostIp: "::1", HostPort: "18789" }] };
  assert.deepEqual(parseInspect(JSON.stringify(v6))!.ports, [{ host: "[::1]:18789", container: 18789 }]);

  const l = upCompose({ image: IMAGE, listen: "10.0.1.5" });
  assert.match(l, /PAIR_PROXY_ADDR: "10.0.1.5:8080"/, "pairing tells other machines where the proxy is");
  for (const port of ["8080", "8801", "3900", "3940"]) assert.match(l, new RegExp(`- "10.0.1.5:${port}:${port}"`));
  assert.match(l, /- "10.0.1.5:53:53\/udp"/);
  assert.doesNotMatch(l, /- "10.0.1.5:8800/, "the panel stays on loopback");
});

test("install: the Compose files are valid, the gateway's override on the firewall's network", { skip: !hasDocker() && "no docker compose here" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cc-up-"));
  writeFileSync(join(dir, "compose.yaml"), upCompose({ image: "alpine:3.20", listen: "10.0.1.5", forwards: [{ host: "18789", container: 18789 }] }));
  const fw = JSON.parse(execFileSync("docker", ["compose", "-f", join(dir, "compose.yaml"), "config", "--format", "json"], { encoding: "utf8" }));
  assert.equal(fw.networks.agents.internal, true);
  writeFileSync(join(dir, "base.yml"), "services:\n  openclaw-gateway:\n    image: alpine:3.20\n    ports: [\"18789:18789\"]\n");
  const info = { ...parseInspect(fixture("inspect-compose.json"))!, files: [join(dir, "base.yml")] };
  writeFileSync(join(dir, "over.yml"), overrideOnFirewallNet(info, { network: "controlclaw-firewall_agents", firewall: "172.31.251.2", gateway: UP_GATEWAY_IP }, { ca: "/etc/controlclaw/ca.crt", bundle: "/b" }));
  const c = JSON.parse(execFileSync("docker", ["compose", "-p", "cctest", "-f", join(dir, "base.yml"), "-f", join(dir, "over.yml"), "config", "--format", "json"], { encoding: "utf8" }));
  const gw = c.services["openclaw-gateway"];
  assert.deepEqual(Object.keys(gw.networks), ["controlclaw"]);
  assert.equal(gw.networks.controlclaw.ipv4_address, UP_GATEWAY_IP);
  assert.equal(gw.ports, undefined);
  assert.equal(c.networks.controlclaw.name, "controlclaw-firewall_agents");
  assert.equal(c.networks.controlclaw.external, true);
});

test("install: starts the firewall, opens the panel and prints a code for other machines; again, it only checks; uninstall --purge removes it and its volume", async () => {
  const sys = upMachine("docker");
  const before = new Map(sys.files);
  const fw = firewall("x");
  const o = io();
  assert.equal(await installFirewall(sys, o, { listen: "10.0.1.5", firewallImage: IMAGE }, fw.net), 0, o.lines.join("\n"));
  assert.ok(sys.ran().includes(`${FW} up -d firewall`));
  assert.equal(loadFirewall(sys)?.kind, "docker");
  assert.equal(loadFirewall(sys)?.listen, "10.0.1.5");
  const text = o.lines.join("\n");
  assert.match(text, /Firewall panel: http:\/\/127.0.0.1:8800\/#setup=beef22/, "the newest token only");
  assert.match(text, /OpenClaw on this machine: sudo npx controlclaw connect \(it pairs by itself\)/);
  assert.match(text, /npx controlclaw connect --firewall http:\/\/10.0.1.5:8801 \(with sudo there for host mode\)\n  with the pairing code 4F7K-92QD-XM3P/);
  assert.equal(loadRecord(sys), null, "installed, not connected");

  // Again, another way: refused, nothing changed.
  const other = io();
  assert.equal(await installFirewall(sys, other, { listen: "10.0.1.9" }, fw.net), 1);
  assert.match(other.lines.join("\n"), /installed already, another way \(docker, --listen 10.0.1.5.*controlclaw uninstall \(its data stays\), then install again/);

  sys.calls = [];
  const again = io();
  assert.equal(await installFirewall(sys, again, {}, fw.net), 0);
  assert.match(again.lines.join("\n"), /installed already/);
  assert.ok(!sys.ran().some((l) => l.includes("pair-code")));

  const st = io();
  assert.equal(await status(sys, st, {}), 0);
  assert.match(st.lines.join("\n"), /Not connected.\n  ✓ firewall container \(installed here\): running/);

  sys.calls = [];
  const u = io();
  assert.equal(await uninstall(sys, u, { purge: true }, fw.net.post), 0, u.lines.join("\n"));
  assert.ok(sys.ran().includes(`${FW} down`));
  assert.ok(sys.ran().includes("docker volume rm controlclaw-firewall_firewall"));
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());

  const bad = io();
  assert.equal(await installFirewall(upMachine("docker"), bad, { listen: "203.0.113.9", firewallImage: IMAGE }, fw.net), 2);
  assert.match(bad.lines.join("\n"), /not a private IPv4 address/);
  const dev = io();
  assert.equal(await installFirewall(upMachine("docker"), dev, { host: true }, fw.net), 2);
  assert.match(dev.lines.join("\n"), /dev build .*install\.sh yourself/);
});

test("connect here, docker mode: paired with no code typed, the gateway on the firewall's network, its ports from the firewall; disconnect gives them back and the firewall stays", async () => {
  const sys = upMachine("docker");
  const fw = firewall(UP_GATEWAY_IP);
  assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, fw.net), 0);
  const installed = sys.files.get("/etc/controlclaw/firewall/compose.yaml");
  const before = new Map(sys.files);
  sys.calls = [];
  const o = io();
  assert.equal(await run(["connect", "--vm-agent", "/opt/vm-agent"], o, sys, noTerminal, fw.net), 0, o.lines.join("\n"));
  const ran = sys.ran();
  const at = (s: string) => ran.findIndex((l) => l.includes(s));
  assert.ok(at(`pair-code --name openclaw --address ${UP_GATEWAY_IP} --replace`) >= 0);
  assert.ok(at(`${GW} -f /etc/controlclaw/docker/compose.controlclaw.yml up -d openclaw-gateway`) > at("systemctl enable --now controlclaw-agent.service"));
  assert.ok(!ran.some((l) => l.includes("controlclaw-gate")), "no gate container: the firewall is the way out");
  assert.match(sys.files.get("/etc/controlclaw/firewall/compose.yaml")!, /CC_FORWARD: "18789=172.31.251.10:18789,18790=172.31.251.10:18790"/);
  assert.match(sys.files.get("/etc/controlclaw/docker/compose.controlclaw.yml")!, /external: true\n    name: "controlclaw-firewall_agents"/);
  assert.equal(JSON.parse(String(fw.calls[0]!.body.request)).agent_listen, "172.31.252.1:3102");
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.listen, "172.31.252.1:3102");
  assert.deepEqual(agent.firewall.allow_from, ["172.31.252.2"]);
  assert.deepEqual(agent.openclaw, { runs: "docker", container: "openclaw-openclaw-gateway-1" });
  const text = o.lines.join("\n");
  assert.match(text, /Mode: docker/);
  assert.match(text, /✓ firewall container: running/);
  assert.match(text, /✓ request from the gateway: HTTP 403/);
  assert.equal(loadRecord(sys)?.up?.done, true);

  // Again: checks only, never a second pairing.
  sys.calls = [];
  const again = io();
  assert.equal(await connectHere(sys, again, {}, fw.net), 0);
  assert.match(again.lines.join("\n"), /Already connected to the firewall on this machine/);
  assert.ok(!sys.ran().some((l) => l.includes("pair-code")));

  sys.calls = [];
  const d = io();
  assert.equal(await disconnect(sys, d, {}, fw.net.post), 0, d.lines.join("\n"));
  const after = sys.ran();
  const i = (s: string) => after.findIndex((l) => l === s);
  assert.ok(fw.calls.some((x) => x.url === "http://127.0.0.1:8801/unpair"));
  assert.ok(i(`${FW} up -d firewall`) >= 0 && i(`${FW} up -d firewall`) < i(`${GW} up -d openclaw-gateway`), "the firewall lets go of the ports before the gateway takes them back");
  assert.ok(!after.includes(`${FW} down`), "disconnect leaves the firewall");
  assert.equal(sys.files.get("/etc/controlclaw/firewall/compose.yaml"), installed, "without the gateway's ports again");
  assert.match(d.lines.join("\n"), /the firewall here still runs \(controlclaw uninstall removes it\)/);
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

test("connect here, host mode: host capture pointed at the firewall's container", async () => {
  const sys = upMachine("systemd-user");
  sys.on("{{json .NetworkSettings.Networks}}", { stdout: "" });
  const fw = firewall("172.31.252.1");
  assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, fw.net), 0);
  const o = io();
  assert.equal(await connectHere(sys, o, { vmAgent: "/opt/vm-agent" }, fw.net), 0, o.lines.join("\n"));
  assert.match(o.lines.join("\n"), /Mode: host/);
  assert.ok(sys.ran().some((l) => l.includes("pair-code --name openclaw --address 172.31.252.1 --replace")));
  assert.match(sys.files.get("/etc/controlclaw/capture/redsocks.conf")!, /ip = 172.31.252.2;\n  port = 8080;/);
  assert.match(sys.files.get("/etc/controlclaw/capture/capture.nft")!, /ip daddr 172.31.252.2 tcp dport \{ 3900, 3940 \} accept/);
  assert.match(sys.files.get("/etc/systemd/resolved.conf.d/controlclaw.conf")!, /DNS=172.31.252.2/);
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.firewall.gate, "172.31.252.2");
  assert.match(sys.files.get("/etc/systemd/system/controlclaw-agent.service")!, /User=claw/);
});

test("up --here: install, then connect, then the panel once; uninstall takes both away", async () => {
  const sys = upMachine("docker");
  const before = new Map(sys.files);
  const fw = firewall(UP_GATEWAY_IP);
  const o = io();
  assert.equal(await run(["up", "--here", "--firewall-image", IMAGE, "--vm-agent", "/opt/vm-agent"], o, sys, noTerminal, fw.net), 0, o.lines.join("\n"));
  const text = o.lines.join("\n");
  assert.equal(text.match(/Firewall panel:/g)?.length, 1, "the panel once, at the end");
  assert.ok(text.indexOf("Connected in docker mode") < text.indexOf("Firewall panel:"));
  assert.ok(loadFirewall(sys) && loadRecord(sys));
  const u = io();
  assert.equal(await uninstall(sys, u, {}, fw.net.post), 0, u.lines.join("\n"));
  assert.match(u.lines.join("\n"), /The firewall's data stays/);
  assert.ok(!sys.ran().some((l) => l.startsWith("docker volume rm")));
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

/** A machine with Docker and no OpenClaw, until `openclaw install` starts one (then as upMachine's). */
function bareDocker(dir?: string): FakeSys {
  const sys = upMachine("docker", dir);
  const none: [string, Partial<{ stdout: string }>][] = [
    ["/opt/vm-agent discover", { stdout: '{"cli":null,"version":null,"config_file":null,"state_dir":null,"runs":{"kind":"not-found"},"gateway_port":18789}' }],
    ["ps -eo", { stdout: "    0     1 /sbin/init\n" }],
  ];
  sys.answers.unshift(...none);
  const run = sys.run.bind(sys);
  sys.run = async (argv, opts) => {
    const r = await run(argv, opts);
    if (argv.join(" ").endsWith("up -d openclaw-gateway")) sys.answers = sys.answers.filter((a) => !none.includes(a));
    return r;
  };
  return sys;
}

test("up --all: install, openclaw install, connect in docker mode, then the panel once; again, it only checks", async () => {
  const sys = bareDocker();
  const before = new Map(sys.files);
  const fw = firewall(UP_GATEWAY_IP);
  const o = io();
  assert.equal(await run(["up", "--all", "--firewall-image", IMAGE, "--vm-agent", "/opt/vm-agent"], o, sys, noTerminal, fw.net), 0, o.lines.join("\n"));
  const text = o.lines.join("\n");
  const ran = sys.ran();
  const at = (x: string) => ran.findIndex((l) => l.includes(x));
  assert.ok(at(`${FW} up -d firewall`) >= 0);
  assert.ok(at("-f /opt/openclaw/compose.yaml up -d openclaw-gateway") > at(`${FW} up -d firewall`));
  assert.ok(at("pair-code --name openclaw") > at("up -d openclaw-gateway"));
  assert.match(text, /Control UI: http:\/\/127.0.0.1:18789\/#token=[0-9a-f]{48}/);
  assert.match(text, /Connected in docker mode/);
  assert.equal(text.match(/Firewall panel:/g)?.length, 1, "the panel once, at the end");
  assert.ok(text.indexOf("Connected in docker mode") < text.indexOf("Firewall panel:"));
  assert.equal(loadFirewall(sys)?.kind, "docker");
  assert.equal(loadRecord(sys)?.mode, "docker");
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.openclaw.container, "openclaw-openclaw-gateway-1");
  // The gateway is on `agents` alone: the gates are there too.
  assert.equal(agent.firewall.gate, "172.31.251.2");
  assert.match(sys.files.get("/etc/controlclaw/firewall/compose.yaml")!, /CONNECTOR_GATE_BIND: "172.31.251.2"/);

  // Again: nothing installed twice, the checks.
  sys.calls = [];
  const o2 = io();
  assert.equal(await upAll(sys, o2, { vmAgent: "/opt/vm-agent" }, fw.net), 0, o2.lines.join("\n"));
  assert.match(o2.lines.join("\n"), /^Already connected to the firewall on this machine \(docker mode/);
  assert.equal(o2.lines.join("\n").match(/Firewall panel:/g)?.length, 1);
  assert.ok(!sys.ran().some((l) => l.includes("pair-code") || l.includes("onboard")));

  const u = io();
  assert.equal(await uninstall(sys, u, {}, fw.net.post), 0, u.lines.join("\n"));
  // OpenClaw's own folder stays, as openclaw install leaves it.
  assert.deepEqual([...sys.files.keys()].filter((k) => !k.startsWith("/opt/openclaw")).sort(), [...before.keys()].sort());
});

test("up --all without sudo: everything in the user's folders, the vm-agent a user service; a stop half way is picked up", async () => {
  const sys = bareDocker("/home/claw/.config/controlclaw/firewall");
  sys.euid = 1001;
  sys.env.HOME = "/home/claw";
  const fw = firewall(UP_GATEWAY_IP);
  // connect fails once (the firewall's pairing is down): OpenClaw stays installed.
  const down = { ...fw.net, post: async () => ({ status: 503, json: { error: "down" } }) };
  const o = io();
  assert.equal(await upAll(sys, o, { vmAgent: "/opt/vm-agent", firewallImage: IMAGE }, down), 1, o.lines.join("\n"));
  assert.ok(sys.files.has("/home/claw/openclaw/compose.yaml"));
  assert.equal(loadRecord(sys), null);
  sys.calls = [];
  const o2 = io();
  assert.equal(await upAll(sys, o2, { vmAgent: "/opt/vm-agent" }, fw.net), 0, o2.lines.join("\n"));
  assert.match(o2.lines.join("\n"), /OpenClaw is on this machine already \(Docker container openclaw-openclaw-gateway-1\): connecting it/);
  assert.ok(!sys.ran().some((l) => l.includes("onboard")), "not set up twice");
  assert.ok(sys.files.has("/home/claw/.config/controlclaw/connect.json"));
  assert.ok(sys.ran().includes("systemctl --user enable --now controlclaw-agent.service"));
  assert.ok(!sys.ran().some((l) => l.startsWith("sudo ")));

  // Connected to a firewall elsewhere, or one install.sh runs here: refused before anything is installed.
  const remote = bareDocker();
  remote.files.set("/etc/controlclaw/connect.json", JSON.stringify({ version: 1, mode: "remote", at: "x", user: null, firewall: { url: "http://10.0.0.2:8801/", proxy: "", dns: "" }, steps: [] }));
  const o3 = io();
  assert.equal(await upAll(remote, o3, { vmAgent: "/opt/vm-agent", firewallImage: IMAGE }, fw.net), 1);
  assert.match(o3.lines.join("\n"), /connected to another firewall \(remote mode/);
  const hostFw = bareDocker();
  hostFw.files.set("/etc/controlclaw/firewall.json", JSON.stringify({ version: 1, kind: "host", at: "x", image: "0.10.0", steps: [] }));
  const o4 = io();
  assert.equal(await upAll(hostFw, o4, { vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o4.lines.join("\n"), /installed with install.sh/);
  for (const m of [remote, hostFw]) assert.ok(!m.ran().some((l) => l.includes(" up -d ") || l.includes("docker pull")));
});

test("connect here: refused with no firewall here, no OpenClaw, rootless Docker, a busy panel port, or a gateway that can get out", async () => {
  const fw = firewall("x");
  const o0 = io();
  assert.equal(await connectHere(upMachine("docker"), o0, {}, fw.net), 1);
  assert.match(o0.lines.join("\n"), /No firewall on this machine. Install one first/);

  const installed = async (sys: FakeSys) => {
    assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, fw.net), 0);
    return sys;
  };
  const none = await installed(upMachine("systemd-user"));
  none.on("runuser -u claw -- env HOME=/home/claw XDG_RUNTIME_DIR=/run/user/1001 /opt/vm-agent discover", { stdout: '{"cli":null,"version":null,"config_file":null,"state_dir":null,"runs":{"kind":"not-found"},"gateway_port":18789}' });
  const o1 = io();
  assert.equal(await connectHere(none, o1, { vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o1.lines.join("\n"), /No OpenClaw on this machine. Install one first: controlclaw openclaw install/);

  const rootless = upMachine("docker");
  rootless.on("docker info --format {{json .SecurityOptions}}", { stdout: '["name=seccomp,profile=builtin","name=rootless"]\n' });
  const o3 = io();
  assert.equal(await installFirewall(rootless, o3, { firewallImage: IMAGE }, fw.net), 1);
  assert.match(o3.lines.join("\n"), /rootless Docker/);

  const busy = io();
  assert.equal(await installFirewall(upMachine("docker"), busy, { firewallImage: IMAGE }, { ...fw.net, busy: async (_h, p) => p === 8800 }), 1);
  assert.match(busy.lines.join("\n"), /already listens on 127.0.0.1:8800/);

  const sock = await installed(upMachine("docker"));
  const c = JSON.parse(fixture("inspect-compose.json"));
  c[0].Mounts = [{ Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock" }];
  sock.on("docker inspect -- openclaw-openclaw-gateway-1", { stdout: JSON.stringify(c) });
  sock.calls = [];
  const o5 = io();
  assert.equal(await connectHere(sock, o5, { vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o5.lines.join("\n"), /could leave the internal network/);
  assert.ok(!sock.ran().some((l) => l.includes("pair-code")), "no pairing");

  // A project this user's Compose cannot read (a root project's .env, 0600): refused before pairing.
  const unreadable = await installed(upMachine("docker"));
  unreadable.on("docker-compose.yml config -q", { code: 1, stderr: "open /root/openclaw/.env: permission denied\n" });
  unreadable.calls = [];
  const o7 = io();
  assert.equal(await connectHere(unreadable, o7, { vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o7.lines.join("\n"), /docker compose cannot read openclaw's files here \(open \/root\/openclaw\/.env: permission denied\): run this with sudo/);
  assert.ok(!unreadable.ran().some((l) => l.includes("pair-code")), "no code spent");

  const host = await installed(upMachine("systemd-user"));
  const o6 = io();
  assert.equal(await connectHere(host, o6, { mode: "docker", vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o6.lines.join("\n"), /OpenClaw does not run in a Docker container here/);
});

test("connect --capture-only: no vm-agent, and no copy of the config (nothing writes to it)", async () => {
  const sys = upMachine("docker");
  const fw = firewall(UP_GATEWAY_IP);
  assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, fw.net), 0);
  const o = io();
  assert.equal(await run(["connect", "--capture-only", "--vm-agent", "/opt/vm-agent"], o, sys, noTerminal, fw.net), 0, o.lines.join("\n"));
  assert.ok(!sys.files.has("/etc/controlclaw/agent.json"));
  assert.equal(JSON.parse(String(fw.calls[0]!.body.request)).agent_listen, null, "the firewall has nothing to call");
  assert.equal(loadRecord(sys)?.configBackup, undefined);
  const st = io();
  await status(sys, st, {});
  assert.doesNotMatch(st.lines.join("\n"), /vm-agent/);
});

test("disconnect --restore-config puts OpenClaw's config back as it was before connect, and restarts it", async () => {
  const sys = upMachine("docker");
  sys.files.set("/root/.openclaw/openclaw.json", '{"before":true}\n');
  const fw = firewall(UP_GATEWAY_IP);
  assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, fw.net), 0);
  assert.equal(await connectHere(sys, io(), { vmAgent: "/opt/vm-agent" }, fw.net), 0);
  assert.equal(sys.files.get("/etc/controlclaw/openclaw.json.before-controlclaw"), '{"before":true}\n');
  assert.equal(sys.stat("/etc/controlclaw/openclaw.json.before-controlclaw")?.mode, 0o600);
  // What the panel set through the vm-agent.
  sys.files.set("/root/.openclaw/openclaw.json", '{"model":"set by the panel"}\n');
  sys.calls = [];
  const d = io();
  assert.equal(await run(["disconnect", "--restore-config"], d, sys, noTerminal, fw.net), 0, d.lines.join("\n"));
  assert.equal(sys.files.get("/root/.openclaw/openclaw.json"), '{"before":true}\n');
  assert.ok(!sys.files.has("/etc/controlclaw/openclaw.json.before-controlclaw"));
  const ran = sys.ran();
  assert.ok(ran.lastIndexOf("docker restart -- openclaw-openclaw-gateway-1") > ran.lastIndexOf(`${GW} up -d openclaw-gateway`), "restarted once the file is back");
  assert.match(d.lines.join("\n"), /OpenClaw's config is back as it was before connect/);

  // Without the flag the panel's settings stay, and the copy goes.
  const s2 = upMachine("docker");
  s2.files.set("/root/.openclaw/openclaw.json", '{"before":true}\n');
  assert.equal(await installFirewall(s2, io(), { firewallImage: IMAGE }, fw.net), 0);
  assert.equal(await connectHere(s2, io(), { vmAgent: "/opt/vm-agent" }, fw.net), 0);
  s2.files.set("/root/.openclaw/openclaw.json", '{"model":"set by the panel"}\n');
  const d2 = io();
  assert.equal(await disconnect(s2, d2, {}, fw.net.post), 0);
  assert.equal(s2.files.get("/root/.openclaw/openclaw.json"), '{"model":"set by the panel"}\n');
  assert.match(d2.lines.join("\n"), /disconnect --restore-config puts back/);
});

test("up --here without sudo (docker mode): the state in the user's config, the vm-agent as a user service that outlives logout", async () => {
  const sys = upMachine("docker", "/home/claw/.config/controlclaw/firewall");
  sys.euid = 1001;
  sys.env.HOME = "/home/claw";
  const before = new Map(sys.files);
  const fw = firewall(UP_GATEWAY_IP);
  const o = io();
  assert.equal(await upHere(sys, o, { vmAgent: "/opt/vm-agent", firewallImage: IMAGE }, fw.net), 0, o.lines.join("\n"));
  assert.ok(sys.files.has("/home/claw/.config/controlclaw/connect.json"));
  assert.ok(sys.files.has("/home/claw/.config/controlclaw/firewall.json"));
  assert.match(sys.files.get("/home/claw/.config/controlclaw/docker/compose.controlclaw.yml")!, /"\/home\/claw\/.config\/controlclaw\/ca.crt:\/etc\/controlclaw\/ca.crt:ro"/);
  assert.doesNotMatch(sys.files.get("/home/claw/.config/systemd/user/controlclaw-agent.service")!, /docker.service/);
  assert.ok(sys.ran().includes("systemctl --user enable --now controlclaw-agent.service"));
  assert.ok(sys.ran().includes("loginctl enable-linger claw"));

  // With sudo now, nothing is set up a second time.
  const root = upMachine("docker");
  root.env = { SUDO_USER: "claw" };
  root.files.set("/home/claw/.config/controlclaw/connect.json", sys.files.get("/home/claw/.config/controlclaw/connect.json")!);
  const o3 = io();
  assert.equal(await connectHere(root, o3, {}, fw.net), 1);
  assert.match(o3.lines.join("\n"), /set up by claw without sudo\. Run, as claw: controlclaw connect/);

  sys.calls = [];
  assert.equal(await uninstall(sys, io(), {}, fw.net.post), 0);
  assert.ok(sys.ran().includes("loginctl disable-linger claw"));
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());

  // Set up with sudo: a user who can use Docker is told so, and uninstall does not say all is gone.
  const bySudo = upMachine("docker");
  assert.equal(await installFirewall(bySudo, io(), { firewallImage: IMAGE }, fw.net), 0);
  bySudo.euid = 1001;
  bySudo.env.HOME = "/home/claw";
  const o4 = io();
  assert.equal(await connectHere(bySudo, o4, {}, fw.net), 1);
  assert.match(o4.lines.join("\n"), /set up with sudo. Run: sudo controlclaw connect/);
  const o5 = io();
  assert.equal(await uninstall(bySudo, o5, {}, fw.net.post), 1);
  assert.match(o5.lines.join("\n"), /sudo controlclaw uninstall/);

  // Host mode keeps needing root.
  const h = upMachine("systemd-user", "/home/claw/.config/controlclaw/firewall");
  h.euid = 1001;
  h.env.HOME = "/home/claw";
  h.on("/opt/vm-agent discover", { stdout: fixture("discover-systemd-user.json") });
  const o2 = io();
  assert.equal(await upHere(h, o2, { vmAgent: "/opt/vm-agent", firewallImage: IMAGE }, fw.net), 1);
  assert.match(o2.lines.join("\n"), /needs root/);
});

test("up: the menu runs what was picked; without a terminal it asks for a flag", async () => {
  const o = io();
  assert.equal(await run(["up"], o, upMachine("docker"), noTerminal, firewall("x").net), 2);
  assert.match(o.lines.join("\n"), /No terminal to show the menu on: run up --all .*up --here/);

  const sys = upMachine("docker");
  const shown: string[] = [];
  const pickHere: Ask = {
    pick: async (t, items) => {
      shown.push(t, ...items.map((i) => i.label));
      return 1;
    },
    line: async () => null,
  };
  const fw = firewall(UP_GATEWAY_IP);
  const o2 = io();
  assert.equal(await run(["up", "--firewall-image", IMAGE, "--vm-agent", "/opt/vm-agent"], o2, sys, pickHere, fw.net), 0, o2.lines.join("\n"));
  assert.deepEqual(shown, ["What do you want to set up?", "Firewall + new OpenClaw here", "Protect the OpenClaw here", "Firewall only", "New OpenClaw only", "Connect this OpenClaw"]);
  assert.ok(loadFirewall(sys) && loadRecord(sys)?.up, "Protect the OpenClaw here: install, then connect");

  const fwOnly = upMachine("docker");
  const pickFw: Ask = { pick: async () => 2, line: async () => "10.0.1.5" };
  assert.equal(await run(["up", "--firewall-image", IMAGE], io(), fwOnly, pickFw, fw.net), 0);
  assert.equal(loadFirewall(fwOnly)?.listen, "10.0.1.5");
  assert.equal(loadRecord(fwOnly), null);

  assert.equal(await run(["up", "--all", "--here"], io(), upMachine("docker"), noTerminal, fw.net), 2);
});

test("open: the link with the setup token in its fragment, the desktop's browser as the user who ran sudo, or the SSH tunnel", async () => {
  const sys = upMachine("docker");
  assert.equal(await installFirewall(sys, io(), { firewallImage: IMAGE }, firewall("x").net), 0);

  const o = io();
  assert.equal(await open(sys, o, NEW_PANEL), 0);
  assert.match(o.lines.join("\n"), /Firewall panel: http:\/\/127.0.0.1:8800\/#setup=beef22/);
  assert.match(o.lines.join("\n"), /ssh -L 8800:127.0.0.1:8800 /);
  assert.match(o.lines.join("\n"), /Every site is allowed and logged\. To lock it down: Internet access, Every other site: Block\./, "a new firewall says what it does");

  const o2 = io();
  assert.equal(await open(sys, o2, { session: async () => ({ setup: false }) }), 0);
  assert.match(o2.lines.join("\n"), /Firewall panel: http:\/\/127.0.0.1:8800$/m, "no token once there is an admin");

  sys.env = { DISPLAY: ":0", SUDO_USER: "claw" };
  sys.calls = [];
  const o3 = io();
  assert.equal(await open(sys, o3, NEW_PANEL), 0);
  // Not on a command line every user can read: a page only claw can read, removed after.
  const opened = sys.ran().find((l) => l.includes("xdg-open"))!;
  assert.match(opened, /^runuser -u claw -- env DISPLAY=:0 HOME=\/home\/claw XDG_RUNTIME_DIR=\/run\/user\/1001 xdg-open file:\/\/\/home\/claw\/controlclaw-open-[0-9a-f]{12}\.html$/);
  assert.doesNotMatch(sys.ran().join("\n"), /beef22/);
  const page = opened.slice(opened.indexOf("file://") + 7);
  assert.ok(sys.ran().includes(`as claw write ${page}`));
  assert.ok(!sys.files.has(page), "removed once the browser has it");
  assert.match(o3.lines.join("\n"), /Opened the firewall's panel: http:\/\/127.0.0.1:8800$/m);
  assert.doesNotMatch(o3.lines.join("\n"), /beef22/, "not printed when the browser has it");

  const o4 = io();
  assert.equal(await open(sys, o4, { session: async () => null }), 1);
  assert.match(o4.lines.join("\n"), /No firewall panel answers/);
});
