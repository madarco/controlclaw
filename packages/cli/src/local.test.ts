import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { disconnect, type Io, type PairNet } from "./commands.js";
import { CA, fakeMachine, KEY } from "./fake-machine.js";
import { gateRelayScript, localCompose, OPENCLAW_CONTAINER, up } from "./local.js";
import { hmacHex, normalizeCode, type Post, REQUEST_TAG, RESPONSE_TAG } from "./pair.js";
import type { OpenNet } from "./open.js";
import { loadRecord } from "./state.js";

/** A panel with no admin yet. */
const NEW_PANEL: OpenNet = { session: async () => ({ setup: true }) };

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

const CODE = "4F7K-92QD-XM3P";

/** The firewall's pairing endpoint, as cc-local answers: the code's address is the agent's. */
function firewall() {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  const post: Post = async (url, body) => {
    calls.push({ url, body: body as Record<string, unknown> });
    if (url.endsWith("/unpair")) return { status: 200, json: { ok: true } };
    const { request } = body as { request: string };
    const req = JSON.parse(request) as Record<string, unknown>;
    const key = normalizeCode(CODE)!;
    const pairing = JSON.stringify({
      v: 1, nonce: req.nonce, agent_id: "agent_local1", name: req.name, address: "172.31.251.10",
      firewall_public_key: KEY, ca_pem: CA, proxy: "172.31.251.2:8080", dns: "172.31.251.2", replaced: [],
    });
    if ((body as { proof: string }).proof !== hmacHex(key, REQUEST_TAG, request)) return { status: 401, json: { error: "no" } };
    return { status: 200, json: { pairing, mac: hmacHex(key, RESPONSE_TAG, pairing) } };
  };
  const net: PairNet = { post, source: async () => "127.0.0.1", ipv4: async () => "127.0.0.1" };
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

test("up --local: OpenClaw only on the internal network, the panel and pairing out of its reach", () => {
  const y = localCompose({ firewallImage: "controlclaw-firewall:dev-amd64", openclawImage: "ghcr.io/openclaw/openclaw:2026.10.9", dir: "/opt/controlclaw-local" });
  assert.match(y, /^name: controlclaw-local$/m);
  assert.match(y, /  agents:\n    internal: true\n    enable_ipv6: false\n    driver_opts:\n      com.docker.network.bridge.gateway_mode_ipv4: isolated/, "the host gets no address on it");
  // OpenClaw: one network, the firewall's DNS and proxy, the CA.
  const oc = y.slice(y.indexOf("  openclaw:"), y.indexOf("\nnetworks:"));
  assert.match(oc, /networks:\n      agents:\n        ipv4_address: 172.31.251.10/);
  assert.doesNotMatch(oc, /outside/);
  assert.doesNotMatch(oc, /ports:/, "Docker publishes nothing from an internal network: the firewall does");
  assert.match(oc, /dns: \["172.31.251.2"\]/);
  assert.match(oc, /HTTPS_PROXY: "http:\/\/172.31.251.2:8080"/);
  assert.match(oc, /NODE_EXTRA_CA_CERTS: "\/etc\/controlclaw\/ca.crt"/);
  assert.match(oc, /cap_drop: \[NET_RAW, NET_ADMIN\]/);
  // The firewall: the panel and pairing on the outside address, published on loopback only.
  assert.match(y, /LOCAL_PANEL_BIND: "172.31.252.2:8800"/);
  assert.match(y, /PAIR_BIND: "172.31.252.2:8801"/);
  assert.match(y, /CC_FORWARD: "18789=172.31.251.10:18789"/);
  for (const port of ["18789", "8800", "8801", "8790"]) assert.match(y, new RegExp(`- "127.0.0.1:${port}:${port}"`));
  assert.doesNotMatch(y, /- "0.0.0.0|- "\d+:\d+"/, "nothing on every address");
  // The gates on OpenClaw's loopback, relayed in its own container (a restart restarts both): its
  // proxy setting lets loopback through, and the firewall still sees OpenClaw's address.
  assert.match(oc, /command: \["sh", "-c", "node \/etc\/controlclaw\/gate-relay.mjs & exec node dist\/index.js gateway --bind lan --port 18789"\]/);
  assert.match(oc, /gate-relay.mjs:\/etc\/controlclaw\/gate-relay.mjs:ro"/);
  const relay = gateRelayScript();
  assert.match(relay, /for \(const port of \[3900,3940\]\)/);
  assert.match(relay, /net.connect\(port, "172.31.251.2"\)/);
  assert.match(relay, /listen\(port, "127.0.0.1"\)/);
  // A failure is logged and a port it cannot take is tried again: it never dies quietly.
  assert.match(relay, /server.on\("error", .*setTimeout\(listen, 5000\)/);
  assert.match(relay, /process.on\("uncaughtException"/);
});

test("up --local: the Compose file is valid", { skip: !hasDocker() && "no docker compose here" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cc-local-"));
  writeFileSync(join(dir, "compose.yaml"), localCompose({ firewallImage: "alpine:3.20", openclawImage: "alpine:3.20", dir }));
  writeFileSync(join(dir, ".env"), "OPENCLAW_GATEWAY_TOKEN=x\n");
  const out = JSON.parse(execFileSync("docker", ["compose", "-f", join(dir, "compose.yaml"), "config", "--format", "json"], { encoding: "utf8" }));
  assert.equal(out.networks.agents.internal, true);
  assert.deepEqual(Object.keys(out.services.openclaw.networks), ["agents"]);
});

function localMachine() {
  const sys = fakeMachine("systemd-user");
  sys.on("mitm-agent pair-code", { stdout: `${CODE}\n` });
  sys.on("com.docker.network.bridge.gateway_mode_ipv4", { stdout: "isolated\n" });
  sys.on("docker run --rm --network none --entrypoint cat", { stdout: "-----BEGIN CERTIFICATE-----\nIMAGE\n-----END CERTIFICATE-----\n" });
  sys.on("{{.State.Health.Status}}", { stdout: "healthy\n" });
  sys.on("{{.State.Status}}", { stdout: "running healthy\n" });
  sys.on("{{json .NetworkSettings.Networks}}", { stdout: '{"controlclaw-local_agents":{}}' });
  sys.on("node -e", { stdout: "HTTP 403\n" });
  sys.on("compose -p controlclaw-local --project-directory /opt/controlclaw-local -f /opt/controlclaw-local/compose.yaml logs", {
    stdout: "firewall-1  | [cc-local] no admin yet: set the password with this one-time setup token (POST /api/setup): abc123\n",
  });
  sys.on("/opt/vm-agent discover", { stdout: '{"cli":null,"version":"2026.10.9","config_file":null,"state_dir":null,"runs":{"kind":"docker","container":"controlclaw-local-openclaw-1"},"gateway_port":18789}' });
  return sys;
}

test("up --local: starts the firewall, pairs OpenClaw at its fixed address, starts it, installs the vm-agent; disconnect stops it and keeps the data", async () => {
  const sys = localMachine();
  const before = new Map(sys.files);
  const fw = firewall();
  const o = io();
  assert.equal(await up(sys, o, { firewallImage: "controlclaw-firewall:dev-amd64", vmAgent: "/opt/vm-agent" }, fw.net, NEW_PANEL), 0, o.lines.join("\n"));
  const ran = sys.ran();
  const at = (s: string) => ran.findIndex((l) => l.includes(s));
  const c = "docker compose -p controlclaw-local --project-directory /opt/controlclaw-local -f /opt/controlclaw-local/compose.yaml";
  assert.ok(at(`${c} up -d firewall`) >= 0);
  assert.ok(at("pair-code --name openclaw --address 172.31.251.10 --replace") > at(`${c} up -d firewall`));
  assert.ok(at("onboard --non-interactive") > at("pair-code"), "OpenClaw is set up after the CA is there");
  assert.ok(at("config patch --stdin") > at("onboard"), "the Control UI's origins, after setup");
  assert.ok(at(`${c} up -d openclaw`) > at("config patch --stdin"));
  const patch = sys.calls.find((x) => x.argv.join(" ").includes("config patch --stdin"))!;
  assert.deepEqual(JSON.parse(patch.opts.input!).gateway.controlUi.allowedOrigins, ["http://127.0.0.1:18789", "http://localhost:18789"]);
  assert.ok(at("systemctl enable --now controlclaw-agent.service") > at(`${c} up -d openclaw`));
  assert.equal(fw.calls[0]!.url, "http://127.0.0.1:8801/pair");
  // What pairing gave: the CA, with the image's bundle; the vm-agent with the key and id.
  assert.equal(sys.files.get("/opt/controlclaw-local/ca.crt"), CA);
  assert.match(sys.files.get("/opt/controlclaw-local/ca-bundle.crt")!, /IMAGE[\s\S]*MIIB/);
  assert.equal(sys.stat("/opt/controlclaw-local/.env")?.mode, 0o600);
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.agent_id, "agent_local1");
  assert.equal(agent.openclaw.container, OPENCLAW_CONTAINER);
  // On the host's side of the outside network, for the firewall's container alone.
  assert.equal(agent.listen, "172.31.252.1:3102");
  assert.deepEqual(agent.firewall.allow_from, ["172.31.252.2"]);
  assert.equal(agent.firewall.gate, "127.0.0.1", "OpenClaw dials the gates on its own loopback, relayed to the firewall");
  assert.equal(JSON.parse(String(fw.calls[0]!.body.request)).agent_listen, "172.31.252.1:3102");
  assert.match(sys.files.get("/etc/systemd/system/controlclaw-agent.service")!, /After=network-online.target docker.service/);
  const text = o.lines.join("\n");
  assert.match(text, /OpenClaw: http:\/\/127.0.0.1:18789\/#token=[0-9a-f]{48}/);
  // No desktop here: the panel's link, with the setup token in its fragment.
  assert.match(text, /Firewall panel: http:\/\/127.0.0.1:8800\/#setup=abc123/);
  assert.match(text, /ssh -L 8800:127.0.0.1:8800 /);
  assert.doesNotMatch(text, /blocks everything/);
  assert.match(text, /✓ request from OpenClaw: HTTP 403/);
  assert.match(text, /✓ host unreachable from it: controlclaw-local_agents gives the host no address/);
  assert.equal(loadRecord(sys)?.mode, "local");

  sys.calls = [];
  const d = io();
  assert.equal(await disconnect(sys, d, {}, fw.net.post), 0, d.lines.join("\n"));
  assert.ok(sys.ran().includes(`${c} down`), "the containers stop; their data stays (no -v)");
  assert.ok(fw.calls.some((x) => x.url === "http://127.0.0.1:8801/unpair"));
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

test("up --local: refused without root, an image, or with a connect in place; undone when OpenClaw does not come up", async () => {
  const sys = localMachine();
  sys.euid = 1000;
  assert.equal(await up(sys, io(), { firewallImage: "x" }), 1);
  const old = localMachine();
  old.on("docker version --format", { stdout: "27.5.1\n" });
  const oo = io();
  assert.equal(await up(old, oo, { firewallImage: "x", vmAgent: "/opt/vm-agent" }), 1);
  assert.match(oo.lines.join("\n"), /needs Docker 28 or newer/);
  const s2 = localMachine();
  const o2 = io();
  assert.equal(await up(s2, o2, {}), 2);
  assert.match(o2.lines.join("\n"), /--firewall-image/);
  const s3 = localMachine();
  s3.on("docker image inspect --format {{.Id}} controlclaw-firewall:none", { code: 1 });
  s3.on("docker pull -q controlclaw-firewall:none", { code: 1, stderr: "manifest unknown\n" });
  const o3 = io();
  assert.equal(await up(s3, o3, { firewallImage: "controlclaw-firewall:none", vmAgent: "/opt/vm-agent" }, firewall().net, NEW_PANEL), 1);
  assert.match(o3.lines.join("\n"), /docker pull controlclaw-firewall:none: manifest unknown/);

  const s4 = localMachine();
  const before = new Map(s4.files);
  s4.on("{{.State.Health.Status}}", { stdout: "starting\n" });
  const fw = firewall();
  const o4 = io();
  assert.equal(await up(s4, o4, { firewallImage: "controlclaw-firewall:dev-amd64", vmAgent: "/opt/vm-agent" }, fw.net, NEW_PANEL), 1);
  assert.match(o4.lines.join("\n"), /OpenClaw's gateway did not come up/);
  assert.ok(fw.calls.some((x) => x.url.endsWith("/unpair")), "the firewall forgets it first");
  assert.ok(s4.ran().some((l) => l.endsWith("compose.yaml down")));
  assert.deepEqual([...s4.files.keys()].sort(), [...before.keys()].sort());
  assert.equal(loadRecord(s4), null);
});
