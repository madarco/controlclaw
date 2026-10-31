import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { connect, disconnect, type Io, type PairNet } from "./commands.js";
import { CA, fakeMachine, KEY } from "./fake-machine.js";
import { agentKeypair, hmacHex, normalizeCode, onThisMachine, type Post, pair, pairUrl, REQUEST_TAG, RESPONSE_TAG } from "./pair.js";
import { loadRecord } from "./state.js";

/** The person types the code when asked (by default the one the fake firewall knows). */
function io(typed: string | null = CODE): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l), ask: async () => typed };
}

const CODE = "4F7K-92QD-XM3P";
const FW_WG = "uEjM2N4pNCQnVBJm/eEtYhXeJ8JyBQlpS9Oa8HVnHlA=";

/** A firewall that answers as cc-local does: it checks the proof with its code and signs with it. */
function firewall(code: string, over: (p: Record<string, unknown>) => Record<string, unknown> = (p) => p) {
  const seen: { url: string; request: Record<string, unknown> }[] = [];
  const unpaired: { url: string; body: Record<string, unknown> }[] = [];
  let unpairHash: unknown = null;
  const post: Post = async (url, body) => {
    if (url.endsWith("/unpair")) {
      const b = body as Record<string, unknown>;
      unpaired.push({ url, body: b });
      const ok = createHash("sha256").update(String(b.secret)).digest("hex") === unpairHash;
      return ok ? { status: 200, json: { ok: true } } : { status: 404, json: { error: "No such agent, or not its secret." } };
    }
    const { request, proof } = body as { request: string; proof: string };
    const key = normalizeCode(code)!;
    if (proof !== hmacHex(key, REQUEST_TAG, request)) return { status: 401, json: { error: "No waiting pairing code matches." } };
    const req = JSON.parse(request) as Record<string, unknown>;
    seen.push({ url, request: req });
    unpairHash = req.unpair_sha256;
    const pairing = JSON.stringify(
      over({
        v: 1,
        nonce: req.nonce,
        agent_id: "agent_0a1b2c3d",
        name: req.name,
        address: req.address ?? "203.0.113.7",
        firewall_public_key: KEY,
        ca_pem: CA,
        proxy: "127.0.0.1:9",
        dns: "10.0.0.2",
        replaced: ["agent_old"],
        // Where the firewall calls the vm-agent from: a firewall container, its own address.
        ...(req.agent_listen ? { calls_from: "172.17.0.2" } : {}),
        // Over WireGuard (remote mode): a tunnel address, and the proxy and DNS on the firewall's.
        ...(req.wg_public_key
          ? {
              address: "10.77.0.2",
              proxy: "10.77.0.1:8080",
              dns: "10.77.0.1",
              replaced: [],
              wg: { firewall_public_key: FW_WG, endpoint: "203.0.113.1:51820", address: "10.77.0.2", firewall_address: "10.77.0.1" },
            }
          : {}),
      }),
    );
    return { status: 200, json: { pairing, mac: hmacHex(key, RESPONSE_TAG, pairing) } };
  };
  const net: PairNet = { post, source: async () => "203.0.113.7", ipv4: async () => "192.0.2.5" };
  return { post, seen, unpaired, net };
}

test("codes read as the firewall reads them", () => {
  assert.equal(normalizeCode("4f7k 92qd-xm3p"), "4F7K92QDXM3P");
  assert.equal(normalizeCode("O1IL-0000-0000"), "011100000000");
  assert.equal(normalizeCode("4F7K-92QD"), null);
  assert.equal(normalizeCode("4F7K-92QD-XM3U"), null);
  // The same vector as cc-local's pairing tests: both sides make the same HMAC.
  assert.equal(hmacHex("4F7K92QDXM3P", REQUEST_TAG, '{"v":1}'), "cf7e753a7cd09e5ab89e472d13b8b09f9c99223d603ea1a54dca87f2b4d900a2");
  assert.equal(pairUrl("http://fw.example.com:8801"), "http://fw.example.com:8801/pair");
  assert.equal(pairUrl("https://gw.example.com/fw"), "https://gw.example.com/fw/pair", "a path is kept");
});

test("pair: takes only an answer made with the code, for this request", async () => {
  const kp = agentKeypair();
  assert.match(kp.privatePem, /BEGIN PRIVATE KEY/);
  const fw = firewall(CODE);
  const p = await pair("http://fw:8801", CODE.toLowerCase(), { publicKey: kp.publicPem, name: "laptop", source: "203.0.113.7" }, fw.post);
  assert.equal(p.agentId, "agent_0a1b2c3d");
  assert.equal(p.proxy, "127.0.0.1:9");
  assert.equal(fw.seen[0]!.url, "http://fw:8801/pair");
  assert.equal(fw.seen[0]!.request.agent_public_key, kp.publicPem);
  assert.equal(JSON.stringify(fw.seen[0]!.request).includes(normalizeCode(CODE)!), false, "the code never travels");

  // A firewall that knows another code (someone in the middle): its answer is refused.
  await assert.rejects(pair("http://fw:8801", CODE, { publicKey: kp.publicPem, source: "203.0.113.7" }, firewall("AAAA-BBBB-CCCC").post), /refused: No waiting/);
  const forged: Post = async (url, body) => {
    const r = await fw.post(url, body);
    const j = r.json as { pairing: string; mac: string };
    return { status: 200, json: { pairing: j.pairing.replace("10.0.0.2", "6.6.6.6"), mac: j.mac } };
  };
  await assert.rejects(pair("http://fw:8801", CODE, { publicKey: kp.publicPem, source: "203.0.113.7" }, forged), /not made with this code/);
  const replay = firewall(CODE, (p) => ({ ...p, nonce: "00".repeat(32) }));
  await assert.rejects(pair("http://fw:8801", CODE, { publicKey: kp.publicPem, source: "203.0.113.7" }, replay.post), /another nonce/);
  await assert.rejects(pair("http://fw:8801", "nope", { publicKey: kp.publicPem, source: "203.0.113.7" }, fw.post), /12 letters/);
});

test("connect --code: pairs, then installs the agent with the firewall's key, its id and its own key pair", async () => {
  const sys = fakeMachine("systemd-user");
  const before = new Map(sys.files);
  const fw = firewall(CODE);
  const o = io();
  const code = await connect(sys, o, { mode: "host", firewall: "http://fw.example.com:8801", vmAgent: "/opt/vm-agent", name: "claw-box" }, fw.net);
  assert.equal(code, 0, o.lines.join("\n"));
  const text = o.lines.join("\n");
  assert.match(text, /agent agent_0a1b2c3d \(claw-box\), known to the firewall by 203.0.113.7/);
  assert.match(text, /the firewall's CA: SHA-256/);
  assert.match(text, /had agent_old at 203.0.113.7: this machine replaces it/);

  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.agent_id, "agent_0a1b2c3d");
  assert.equal(agent.firewall.public_key, KEY.trim());
  // The firewall is on another machine: no call to the vm-agent in clear across the network.
  assert.equal(fw.seen[0]!.request.agent_listen, null);
  assert.equal(agent.listen, "127.0.0.1:3100");
  assert.equal(agent.firewall.allow_from, undefined);
  assert.match(text, /The firewall is on another machine: .* Use --mode remote/);
  const state = "/home/claw/.local/state/controlclaw";
  const pub = sys.files.get(`${state}/vm_public_key.pem`)!;
  assert.equal(pub, fw.seen[0]!.request.agent_public_key, "the key the firewall recorded is the one the agent uses");
  assert.equal(sys.stat(`${state}/vm_private_key.pem`)?.mode, 0o600);
  assert.equal(sys.stat(`${state}/vm_private_key.pem`)?.uid, 1001, "the agent's user owns its key");
  assert.equal(sys.files.get("/etc/controlclaw/ca.crt"), CA);
  // What pairing said: the proxy and DNS.
  assert.match(sys.files.get("/etc/controlclaw/capture/redsocks.conf")!, /ip = 127.0.0.1;\n  port = 9;/);
  assert.match(sys.files.get("/etc/systemd/resolved.conf.d/controlclaw.conf")!, /DNS=10.0.0.2/);
  assert.equal(loadRecord(sys)?.firewall.agentId, "agent_0a1b2c3d");

  // Root writes nothing into claw's home itself: claw does (a link planted there leads nowhere
  // root can reach).
  const ran = sys.ran();
  assert.ok(ran.includes(`as claw write ${state}/vm_private_key.pem`));
  assert.ok(ran.includes("as claw write /home/claw/.config/systemd/user/openclaw-gateway.service.d/controlclaw.conf"));
  sys.calls = [];
  const d = io();
  assert.equal(await disconnect(sys, d, {}, fw.post), 0, d.lines.join("\n"));
  const undo = sys.ran();
  assert.ok(undo.includes(`as claw remove ${state}/vm_private_key.pem`));
  assert.ok(undo.some((l) => l.startsWith("runuser -u claw -- ") && l.endsWith(`rm -rf -- ${state}`)), "the state folder goes as claw too");
  assert.match(d.lines.join("\n"), /The firewall forgot this machine \(agent_0a1b2c3d\)/);
  assert.equal(fw.unpaired[0]!.url, "http://fw.example.com:8801/unpair");
  assert.equal(fw.unpaired[0]!.body.agent_id, "agent_0a1b2c3d");
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

test("connect --code: with the firewall on this machine, the vm-agent listens on this machine's address for it alone", async () => {
  const sys = fakeMachine("systemd-user");
  const fw = firewall(CODE);
  const o = io();
  // A firewall container on this machine: reached through a Docker bridge.
  const net = { ...fw.net, source: async () => "192.0.2.5", sameMachine: () => true };
  assert.equal(await connect(sys, o, { mode: "host", firewall: "http://fw.example.com:8801", vmAgent: "/opt/vm-agent" }, net), 0, o.lines.join("\n"));
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(fw.seen[0]!.request.agent_listen, "192.0.2.5:3100");
  assert.equal(agent.listen, "192.0.2.5:3100");
  assert.deepEqual(agent.firewall.allow_from, ["172.17.0.2"], "where the firewall says it calls from");
  // A calls_from that is not an IPv4 address is not written: the address connect dialled is.
  const s2 = fakeMachine("systemd-user");
  const fw2 = firewall(CODE, (p) => ({ ...p, calls_from: "fw.example; rm" }));
  assert.equal(await connect(s2, io(), { mode: "host", firewall: "http://fw.example.com:8801", vmAgent: "/opt/vm-agent" }, { ...fw2.net, source: async () => "192.0.2.5", sameMachine: () => true }), 0);
  assert.deepEqual(JSON.parse(s2.files.get("/etc/controlclaw/agent.json")!).firewall.allow_from, ["192.0.2.5"]);
  assert.deepEqual(agent.firewall.hostnames, ["192.0.2.5"]);
  assert.doesNotMatch(o.lines.join("\n"), /on another machine/);
});

test("the firewall is on this machine when it has one of its addresses, or sits behind one of its Docker bridges", () => {
  const ifaces = {
    lo: [{ family: "IPv4", address: "127.0.0.1" }],
    eth0: [{ family: "IPv4", address: "203.0.113.7" }],
    docker0: [{ family: "IPv4", address: "172.17.0.1" }],
    "br-6e46c54463ef": [{ family: "IPv4", address: "172.31.252.1" }],
  } as unknown as Parameters<typeof onThisMachine>[2];
  assert.equal(onThisMachine("203.0.113.7", "203.0.113.7", ifaces), true, "its own address");
  assert.equal(onThisMachine("172.17.0.2", "172.17.0.1", ifaces), true, "a container on docker0");
  assert.equal(onThisMachine("172.31.252.2", "172.31.252.1", ifaces), true, "a container on a Compose network");
  assert.equal(onThisMachine("192.0.2.5", "203.0.113.7", ifaces), false, "across the network");
});

test("connect --code: --proxy and --dns still win over what pairing says", async () => {
  const sys = fakeMachine("systemd-user");
  const o = io();
  const opts = { mode: "host", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent", proxy: "127.0.0.1:7", dns: "10.9.9.9" };
  assert.equal(await connect(sys, o, opts, firewall(CODE).net), 0, o.lines.join("\n"));
  assert.match(sys.files.get("/etc/controlclaw/capture/redsocks.conf")!, /port = 7;/);
  assert.match(sys.files.get("/etc/systemd/resolved.conf.d/controlclaw.conf")!, /DNS=10.9.9.9/);
});

test("connect --code: nothing is installed when pairing fails, and no code is spent on a machine that cannot do the mode", async () => {
  const sys = fakeMachine("systemd-user");
  const before = new Map(sys.files);
  const o = io();
  assert.equal(await connect(sys, o, { mode: "host", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, firewall("AAAA-BBBB-CCCC").net), 1);
  assert.match(o.lines.join("\n"), /Pairing failed: the firewall refused/);
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
  assert.equal(loadRecord(sys), null);

  const docker = fakeMachine("systemd-user");
  const fw = firewall(CODE);
  assert.equal(await connect(docker, io(), { mode: "docker", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.equal(fw.seen.length, 0, "the mode's checks come first");

  const both = io();
  assert.equal(await connect(sys, both, { mode: "host", firewall: "http://fw:8801", code: "-", ca: "/tmp/ca.pem" }), 2);
  assert.match(both.lines.join("\n"), /leave out --ca/);
});

test("connect --code: the code is asked for, read from stdin or a file, and a code on argv is refused", async () => {
  const base = { mode: "host", firewall: "http://127.0.0.1:8801", vmAgent: "/opt/vm-agent" };
  // Asked for (a terminal): nothing on the command line.
  const sys = fakeMachine("systemd-user");
  const fw = firewall(CODE);
  const asked: string[] = [];
  const o = { ...io(), ask: async (p: string) => (asked.push(p), CODE) };
  assert.equal(await connect(sys, o, base, fw.net), 0, o.lines.join("\n"));
  assert.match(asked[0]!, /Pairing code from the firewall/);
  assert.doesNotMatch(o.lines.join("\n"), /on the command line/);
  assert.ok("source" in fw.seen[0]!.request, "the machine's own address goes under the proof");

  // --code - reads stdin without a prompt.
  const s2 = fakeMachine("systemd-user");
  const o2 = { ...io(), ask: async (p: string) => (asked.push(p), CODE) };
  assert.equal(await connect(s2, o2, { ...base, code: "-" }, firewall(CODE).net), 0);
  assert.equal(asked[1], "");

  // A file, warned about when others can read it.
  const s3 = fakeMachine("systemd-user");
  s3.files.set("/root/code", `${CODE}\n`);
  s3.modes.set("/root/code", { mode: 0o644, uid: 0, gid: 0 });
  const o3 = io();
  assert.equal(await connect(s3, o3, { ...base, codeFile: "/root/code" }, firewall(CODE).net), 0);
  assert.match(o3.lines.join("\n"), /can be read by other users/);

  // On argv: refused, and nothing is sent.
  const s4 = fakeMachine("systemd-user");
  const o4 = io();
  const fw4 = firewall(CODE);
  assert.equal(await connect(s4, o4, { ...base, code: CODE }, fw4.net), 2);
  assert.match(o4.lines.join("\n"), /Not on the command line/);
  assert.equal(fw4.seen.length, 0);

  // No code and nobody to ask.
  const o5 = io(null);
  assert.equal(await connect(fakeMachine("systemd-user"), o5, base, firewall(CODE).net), 2);
  assert.match(o5.lines.join("\n"), /No pairing code/);
});

test("connect --code: pairing goes to the IPv4 address measured, from the source measured; a failed install unpairs", async () => {
  const sys = fakeMachine("systemd-user");
  const fw = firewall(CODE);
  const o = io();
  assert.equal(await connect(sys, o, { mode: "host", firewall: "http://fw.example.com:8801", vmAgent: "/opt/vm-agent" }, fw.net), 0);
  assert.equal(fw.seen[0]!.url, "http://192.0.2.5:8801/pair", "not over IPv6 or another record");
  assert.equal(fw.seen[0]!.request.source, "203.0.113.7");
  assert.match(String(fw.seen[0]!.request.unpair_sha256), /^[0-9a-f]{64}$/);
  assert.match(loadRecord(sys)!.firewall.unpair ?? "", /^[0-9a-f]{64}$/);

  // No source: stops here, with the code kept.
  const s2 = fakeMachine("systemd-user");
  const fw2 = firewall(CODE);
  const o2 = io();
  const net2 = { ...fw2.net, source: async () => Promise.reject(new Error("no route")) };
  assert.equal(await connect(s2, o2, { mode: "host", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, net2), 1);
  assert.equal(fw2.seen.length, 0);

  // Paired, then the install fails: the firewall is asked to forget the agent.
  const s3 = fakeMachine("systemd-user");
  s3.on("systemctl enable --now controlclaw-capture.service", { code: 1, stderr: "nft: syntax error" });
  const fw3 = firewall(CODE);
  const o3 = io();
  assert.equal(await connect(s3, o3, { mode: "host", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, fw3.net), 1);
  assert.equal(fw3.unpaired.length, 1);
  assert.match(o3.lines.join("\n"), /The firewall forgot this machine/);
});

test("connect --mode remote: pairs with a WireGuard key, brings up cc-wg0 and captures through it; disconnect takes it all down", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("wg show cc-wg0 latest-handshakes", { stdout: `${FW_WG}\t1793400000\n` });
  const before = new Map(sys.files);
  const fw = firewall(CODE);
  const o = io();
  assert.equal(await connect(sys, o, { mode: "remote", firewall: "http://fw.example.com:8801", vmAgent: "/opt/vm-agent" }, fw.net), 0, o.lines.join("\n"));
  const sent = String(fw.seen[0]!.request.wg_public_key);
  assert.match(sent, /^[A-Za-z0-9+/]{43}=$/, "its WireGuard public key went with the request");
  const key = sys.files.get("/etc/wireguard/cc-wg0.key")!.trim();
  assert.match(key, /^[A-Za-z0-9+/]{43}=$/);
  assert.notEqual(key, sent, "the private half stays here");
  assert.equal(sys.stat("/etc/wireguard/cc-wg0.key")?.mode, 0o600);
  const conf = sys.files.get("/etc/wireguard/cc-wg0.conf")!;
  assert.match(conf, /Address = 10.77.0.2\/32/);
  assert.match(conf, new RegExp(`PublicKey = ${FW_WG.replace(/[+/]/g, "\\$&")}`));
  assert.match(conf, /Endpoint = 203.0.113.1:51820\n/);
  assert.match(conf, /AllowedIPs = 10.77.0.1\/32\n/);
  const ran = sys.ran();
  assert.ok(ran.some((l) => l.includes("apt-get install -y -q wireguard-tools")));
  assert.ok(ran.includes("systemctl enable --now wg-quick@cc-wg0.service"));
  assert.ok(ran.indexOf("systemctl enable --now wg-quick@cc-wg0.service") < ran.indexOf("systemctl enable --now controlclaw-agent.service"), "the tunnel before the vm-agent that listens on it");
  // Host capture, against the firewall's tunnel address, with the tunnel chains.
  assert.match(sys.files.get("/etc/controlclaw/capture/redsocks.conf")!, /ip = 10.77.0.1;\n  port = 8080;/);
  const nft = sys.files.get("/etc/controlclaw/capture/capture.nft")!;
  assert.match(nft, /dnat ip to 10.77.0.1:53/);
  assert.match(nft, /type filter hook postrouting priority 0; policy accept;\n    ip daddr 10.77.0.1 oifname != "cc-wg0" drop/);
  assert.match(nft, /ip daddr 10.77.0.2 iifname != \{ "cc-wg0", "lo" \} drop/);
  assert.match(sys.files.get("/etc/systemd/resolved.conf.d/controlclaw.conf")!, /DNS=10.77.0.1/);
  // The vm-agent on its tunnel address, after the tunnel.
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.listen, "10.77.0.2:3100");
  assert.deepEqual(agent.firewall.allow_from, ["10.77.0.1"], "only the firewall's end of the tunnel");
  assert.equal(agent.firewall.gate, "10.77.0.1", "MCP servers and app connections through the tunnel");
  // Captured, but the gates are reached directly (the proxy never connects to the firewall).
  assert.match(nft, /meta skuid 1001 ip daddr 10.77.0.1 tcp dport \{ 3900, 3940 \} return\n    meta skuid 1001 meta nfproto ipv4 meta l4proto tcp redirect/);
  assert.match(nft, /ip daddr 10.77.0.1 tcp dport \{ 3900, 3940 \} accept/);
  assert.equal(fw.seen[0]!.request.agent_listen, null, "the firewall's default over the tunnel");
  assert.match(sys.files.get("/etc/systemd/system/controlclaw-agent.service")!, /After=network-online.target wg-quick@cc-wg0.service/);
  assert.equal(loadRecord(sys)?.mode, "remote");

  sys.calls = [];
  assert.equal(await disconnect(sys, io(), {}, fw.post), 0);
  const undo = sys.ran();
  assert.ok(undo.includes("systemctl disable --now wg-quick@cc-wg0.service"));
  assert.ok(undo.indexOf("apt-get purge -y -q wireguard-tools") > undo.indexOf("systemctl disable --now wg-quick@cc-wg0.service"), "the package goes after the tunnel");
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

test("connect --mode remote: only with pairing, and only with a firewall that runs WireGuard", async () => {
  const o = io();
  assert.equal(await connect(fakeMachine("systemd-user"), o, { mode: "remote", firewall: "http://fw:8801", ca: "/tmp/ca.pem" }), 2);
  assert.match(o.lines.join("\n"), /Remote mode pairs with a code/);
  for (const extra of [{ proxy: "203.0.113.1:8080" }, { dns: "203.0.113.1" }]) {
    const e = io();
    assert.equal(await connect(fakeMachine("systemd-user"), e, { mode: "remote", firewall: "http://fw:8801", ...extra }), 2);
    assert.match(e.lines.join("\n"), /leave out --proxy and --dns/);
  }
  // A firewall that answers without a tunnel (no WireGuard there).
  const fw = firewall(CODE, (p) => ({ ...p, wg: undefined }));
  const o2 = io();
  const sys = fakeMachine("systemd-user");
  assert.equal(await connect(sys, o2, { mode: "remote", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o2.lines.join("\n"), /the firewall gave no tunnel/);
  assert.equal(loadRecord(sys), null);
});

test("connect --mode remote: a firewall that never answers on WireGuard stops connect, and it is all undone", async () => {
  const sys = fakeMachine("systemd-user");
  const before = new Map(sys.files);
  const fw = firewall(CODE);
  const o = io();
  assert.equal(await connect(sys, o, { mode: "remote", firewall: "http://fw:8801", vmAgent: "/opt/vm-agent" }, fw.net), 1);
  assert.match(o.lines.join("\n"), /does not answer on WireGuard at 203.0.113.1:51820 \(is UDP 51820 open/);
  assert.equal(fw.unpaired.length, 1, "and the firewall forgets it");
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});
