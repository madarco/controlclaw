import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { captureNft, captureUnit, loopbackPorts, nftablesDropin, profilePorts, redsocksConf, resolvedDropin } from "./capture/host.js";
import { BUNDLE, composeAtLeast, escapesOf, OVERRIDE, overrideYaml, parseInspect } from "./capture/docker.js";
import { currentProxy, proxyPatch, validateChecks } from "./capture/proxy.js";
import { wgConf } from "./capture/remote.js";
import { wgKeypair } from "./pair.js";
import { run } from "./cli.js";
import type { Io } from "./commands.js";
import { fakeMachine, fixture } from "./fake-machine.js";

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

function hasDocker(): boolean {
  try {
    execFileSync("docker", ["compose", "version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

test("host: the rules catch only the uid, send DNS to the firewall and refuse the rest", () => {
  const nft = captureNft({ uid: 1001, dns: "10.0.0.2", loopbackPorts: loopbackPorts(18789), resolveUid: 991 });
  assert.match(nft, /^table inet controlclaw_capture\ndelete table inet controlclaw_capture\n/m, "loading twice replaces, never doubles");
  // Only the uid's packets are judged: the kernel's own (no socket owner) are not refused.
  assert.match(nft, /meta skuid 1001 jump uid_out\n  \}\n  chain uid_out \{\n    ct state established,related accept/);
  assert.doesNotMatch(nft, /meta skuid != 1001/);
  assert.match(nft, /meta skuid 1001 ip daddr 127.0.0.0\/8 return/);
  // DNS to any server goes to the firewall; to resolved's stub it stays (resolved asks only the
  // firewall), since a 127.x query sent to another machine is dropped as martian.
  assert.match(nft, /meta skuid 1001 meta nfproto ipv4 ip daddr != 127.0.0.0\/8 meta l4proto \{ tcp, udp \} th dport 53 dnat ip to 10.0.0.2:53/);
  assert.match(nft, /ip daddr \{ 127.0.0.53, 127.0.0.54 \} meta l4proto \{ tcp, udp \} th dport 53 accept\n    meta l4proto tcp reject/);
  assert.match(nft, /meta l4proto tcp reject with tcp reset\n    reject\n/);
  // Loopback by address (a redirected packet still shows oif eth0), and only these ports.
  assert.match(nft, /ip daddr 127.0.0.0\/8 tcp dport \{ 12346, 3100, 3111, 18789-18800 \} accept/);
  assert.match(nft, /ip6 daddr ::1 tcp dport \{ 12346, 3100, 3111, 18789-18800 \} accept/);
  assert.doesNotMatch(nft, /ip daddr 127.0.0.0\/8 accept/);
  // resolved may ask only the firewall, and its rules come before the "other uids" accept.
  assert.match(nft, /meta skuid 991 meta l4proto \{ tcp, udp \} th dport \{ 53, 853 \} ip daddr != 10.0.0.2 reject/);
  assert.ok(nft.indexOf("meta skuid 991") < nft.indexOf("meta skuid 1001 jump uid_out"));
  assert.match(nft, /meta skuid 991 meta l4proto \{ tcp, udp \} th dport \{ 5353, 5355 \} reject/, "no LLMNR or mDNS onto the link");
  assert.match(resolvedDropin("10.0.0.2"), /LLMNR=no\nMulticastDNS=no\n/);
  const noResolved = captureNft({ uid: 1001, dns: "10.0.0.2", loopbackPorts: ["1"], resolveUid: null });
  assert.doesNotMatch(noResolved, /skuid 991/);
  assert.doesNotMatch(noResolved, /127.0.0.53/, "no stub to allow without resolved");
  assert.deepEqual(loopbackPorts(65530), ["12346", "3100", "3111", "65530-65535"], "never past 65535");
  // A profile's own CDP port, from the config; one inside the range is not listed twice.
  const cfg = JSON.stringify({ browser: { profiles: { work: { cdpPort: 18802 }, x: { cdpPort: 18795 }, remote: { cdpUrl: "http://127.0.0.1:9333" }, far: { cdpUrl: "http://10.0.0.9:9222" } } } });
  assert.deepEqual(profilePorts(cfg), [18802, 18795, 9333]);
  assert.deepEqual(loopbackPorts(18789, profilePorts(cfg)), ["12346", "3100", "3111", "18789-18800", "9333", "18802"]);
  assert.equal(profilePorts("{ json5: true, }"), null, "not plain JSON: its profiles cannot be read");
  assert.deepEqual(loopbackPorts(18789, null), ["12346", "3100", "3111", "18789-18899"], "so OpenClaw's whole range stays open");
  assert.deepEqual(loopbackPorts(65535), ["12346", "3100", "3111", "65535"]);
  // redsocks refuses a `#` comment.
  assert.ok(redsocksConf("10.0.0.2", 8080).startsWith("// "));
});

test("remote: the tunnel chains, and cc-wg0's config", () => {
  const plain = captureNft({ uid: 1001, dns: "10.77.0.1", loopbackPorts: ["1"], resolveUid: 991 });
  assert.doesNotMatch(plain, /tunnel_post/);
  const nft = captureNft({ uid: 1001, dns: "10.77.0.1", loopbackPorts: ["1"], resolveUid: 991, tunnel: { iface: "cc-wg0", address: "10.77.0.2", firewall: "10.77.0.1" } });
  // After routing (NAT done): nothing for the firewall leaves by another interface.
  assert.match(nft, /chain tunnel_post \{\n    type filter hook postrouting priority 0; policy accept;\n    ip daddr 10.77.0.1 oifname != "cc-wg0" drop/);
  assert.match(nft, /type nat hook postrouting priority 100; policy accept;\n(    #.*\n)*    oifname "cc-wg0" ip saddr != 10.77.0.2 snat ip to 10.77.0.2/);
  assert.match(nft, /type filter hook forward priority 0; policy accept;\n(    #.*\n)*    oifname "cc-wg0" drop/, "nothing forwarded into the tunnel");
  assert.match(nft, /chain tunnel_in \{\n    type filter hook input priority 0; policy accept;\n    ip daddr 10.77.0.2 iifname != \{ "cc-wg0", "lo" \} drop/);
  const conf = wgConf({ address: "10.77.0.2", firewall: "10.77.0.1", firewallPublicKey: "K=", endpoint: "fw.example.com:51820", privateKey: "P=" });
  assert.match(conf, /AllowedIPs = 10.77.0.1\/32\nPersistentKeepalive = 25/);
  assert.doesNotMatch(conf, /P=/, "the private key is in its own file, not the config");
  const k = wgKeypair();
  assert.match(k.privateKey, /^[A-Za-z0-9+/]{43}=$/);
  assert.match(k.publicKey, /^[A-Za-z0-9+/]{43}=$/);
});

test("host: the capture unit loads after nftables.service, and nftables loads it again", () => {
  const unit = captureUnit("/usr/sbin/nft");
  assert.match(unit, /After=local-fs.target nftables.service/);
  assert.match(unit, /ExecStop=\/usr\/sbin\/nft -f \/etc\/controlclaw\/capture\/remove.nft/);
  const dropin = nftablesDropin("/usr/sbin/nft");
  assert.match(dropin, /ExecStartPost=-\/usr\/sbin\/nft -f \/etc\/controlclaw\/capture\/capture.nft/);
  assert.match(dropin, /ExecReload=-\/usr\/sbin\/nft -f \/etc\/controlclaw\/capture\/capture.nft/);
  assert.match(dropin, /ExecStopPost=-\/usr\/sbin\/nft -f \/etc\/controlclaw\/capture\/capture.nft/, "stop flushes too");
});

test("docker: the compose labels, and the published TCP ports only", () => {
  const info = parseInspect(fixture("inspect-compose.json"))!;
  assert.equal(info.project, "openclaw");
  assert.equal(info.service, "openclaw-gateway");
  assert.deepEqual(info.files, ["/root/openclaw/docker-compose.yml"]);
  assert.deepEqual(info.ports, [
    { host: "18789", container: 18789 },
    { host: "127.0.0.1:18790", container: 18790 },
  ]);
  assert.equal(parseInspect('[{"Config":{"Labels":{}}}]'), null, "not a Compose container");
});

test("docker: the override moves the gateway to the internal network and the ports to the gate", () => {
  const info = parseInspect(fixture("inspect-compose.json"))!;
  assert.throws(() => overrideYaml(info, { host: "127.0.0.1", port: 8080 }, null), /docker0 address/);
  const y = overrideYaml(info, { host: "172.17.0.1", port: 8080 }, "172.17.0.1");
  assert.match(y, /ports: !reset \[\]/);
  assert.match(y, /networks: !override\n {6}controlclaw:/);
  assert.match(y, /OPENCLAW_PROXY_URL: "http:\/\/172.31.250.2:8080"/);
  assert.match(y, /TCP:172.17.0.1:8080/);
  assert.match(y, /UDP:172.17.0.1:53/);
  // The firewall's gates, relayed where the proxy is; dialled directly, not through the proxy.
  assert.match(y, /TCP-LISTEN:3900,fork,reuseaddr TCP:172.17.0.1:3900/);
  assert.match(y, /TCP-LISTEN:3940,fork,reuseaddr TCP:172.17.0.1:3940/);
  assert.match(y, /NO_PROXY: "localhost,127.0.0.1,::1,172.31.250.2"/);
  assert.throws(() => overrideYaml({ ...info, ports: [{ host: "3940", container: 3940 }] }, { host: "fw", port: 8080 }, null), /port 3940/);
  assert.match(y, /- "127.0.0.1:18790:18790"/);
  assert.match(y, /internal: true\n    enable_ipv6: false\n    driver_opts:\n      com.docker.network.bridge.gateway_mode_ipv4: isolated/);
  assert.throws(() => overrideYaml({ ...info, ports: [{ host: "8080", container: 8080 }] }, { host: "fw", port: 8080 }, null), /port 8080/);
});

test("docker: the override is valid Compose on top of a gateway service", { skip: !hasDocker() && "no docker compose here" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "cc-cli-"));
  writeFileSync(join(dir, "base.yml"), "services:\n  openclaw-gateway:\n    image: alpine:3.20\n    ports: [\"18789:18789\"]\n    environment:\n      - HOME=/home/node\n");
  const info = { ...parseInspect(fixture("inspect-compose.json"))!, files: [join(dir, "base.yml")] };
  writeFileSync(join(dir, "over.yml"), overrideYaml(info, { host: "203.0.113.5", port: 8080 }, "203.0.113.5"));
  const out = execFileSync("docker", ["compose", "-p", "cctest", "-f", join(dir, "base.yml"), "-f", join(dir, "over.yml"), "config", "--format", "json"], { encoding: "utf8" });
  const c = JSON.parse(out) as { services: Record<string, { ports?: unknown[]; networks: Record<string, unknown>; environment: Record<string, string> }>; networks: Record<string, { internal?: boolean }> };
  const gw = c.services["openclaw-gateway"]!;
  assert.deepEqual(Object.keys(gw.networks), ["controlclaw"]);
  assert.equal(gw.ports, undefined);
  assert.equal(gw.environment.HOME, "/home/node", "their environment is kept");
  assert.equal(gw.environment.NODE_EXTRA_CA_CERTS, "/etc/controlclaw/ca.crt");
  assert.equal(c.networks.controlclaw!.internal, true);
  assert.deepEqual(Object.keys(c.services["controlclaw-gate"]!.networks).sort(), ["controlclaw", "default"]);
});

test("docker: connect writes the override and runs compose with it; disconnect runs it without", async () => {
  const sys = fakeMachine("docker");
  const o = io();
  const code = await run(["connect", "--mode", "docker", "--firewall", "http://127.0.0.1:3940", "--proxy", "192.0.2.9:9", "--dns", "192.0.2.9", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o, sys);
  assert.equal(code, 0, o.lines.join("\n"));
  assert.match(sys.files.get(BUNDLE)!, /IMAGE[\s\S]*MIIB/, "the image's bundle plus ours");
  assert.ok(sys.files.has(OVERRIDE));
  assert.ok(sys.files.has("/etc/controlclaw/ca.crt"));
  assert.deepEqual(JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!).openclaw, { runs: "docker", container: "openclaw-openclaw-gateway-1" });
  const compose = "docker compose -p openclaw --project-directory /root/openclaw -f /root/openclaw/docker-compose.yml";
  assert.ok(sys.ran().includes(`${compose} -f ${OVERRIDE} up -d openclaw-gateway controlclaw-gate`), "only the gateway and the gate");

  sys.calls = [];
  assert.equal(await run(["disconnect"], io(), sys), 0);
  assert.ok(sys.ran().includes(`${compose} -f ${OVERRIDE} rm -s -f controlclaw-gate`), "only the gate is removed");
  assert.ok(sys.ran().includes(`${compose} up -d openclaw-gateway`));
  assert.ok(sys.ran().includes("docker network rm openclaw_controlclaw"));
  assert.ok(!sys.files.has(OVERRIDE) && !sys.files.has(BUNDLE));
});

test("proxy: the setting, and the owner's own proxy read from the file (config get redacts it)", () => {
  assert.deepEqual(proxyPatch("10.0.0.2:8080").proxy, { enabled: true, proxyUrl: "http://10.0.0.2:8080", loopbackMode: "gateway-only" });
  assert.equal(currentProxy("/c.json", "{}"), undefined);
  assert.deepEqual(currentProxy("/c.json", '{"proxy":{"proxyUrl":"http://u:p@corp:3128"}}'), { proxyUrl: "http://u:p@corp:3128" });
  assert.throws(() => currentProxy("/c.json", null), /cannot read/);
  assert.throws(() => currentProxy("/c.json", "{ proxy: {}, // json5\n}"), /not plain JSON/);
});

test("proxy: an OpenClaw that already has a proxy is refused, and nothing is left behind", async () => {
  const sys = fakeMachine("systemd-user");
  sys.files.set("/home/claw/.openclaw/openclaw.json", '{"proxy":{"proxyUrl":"http://corp:3128"}}');
  const before = new Map(sys.files);
  const o = io();
  assert.equal(await run(["connect", "--mode", "proxy", "--firewall", "http://10.0.0.2:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o, sys), 1);
  assert.match(o.lines.join("\n"), /already has a proxy setting/);
  assert.ok(!sys.ran().some((l) => l.includes("config patch")));
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort());
});

test("proxy: connect patches OpenClaw's config as its user, and disconnect patches it back", async () => {
  const sys = fakeMachine("systemd-user");
  sys.files.set("/home/claw/.openclaw/openclaw.json", '{"gateway":{"port":18789}}');
  const o = io();
  const code = await run(["connect", "--mode", "proxy", "--firewall", "http://10.0.0.2:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent", "--proxy", "127.0.0.1:9"], o, sys);
  assert.equal(code, 0, o.lines.join("\n"));
  const patch = sys.calls.find((c) => c.argv.join(" ").endsWith("openclaw config patch --stdin"))!;
  assert.match(patch.argv.join(" "), /^runuser -u claw -- env HOME=\/home\/claw/);
  assert.equal(patch.opts.input, JSON.stringify(proxyPatch("127.0.0.1:9")));
  assert.match(o.lines.join("\n"), /Shell commands and other programs on this machine do not/);

  sys.calls = [];
  assert.equal(await run(["disconnect"], io(), sys), 0);
  const back = sys.calls.find((c) => c.argv.join(" ").endsWith("config patch --stdin"))!;
  assert.equal(back.opts.input, JSON.stringify({ proxy: null }));
});

test("proxy: status reads `openclaw proxy validate --json` (recorded on OpenClaw 2026.10.9)", () => {
  const raw = fixture("proxy-validate.json");
  const [setting, request] = validateChecks(raw, "http://127.0.0.1:8080");
  assert.equal(setting!.ok, true, setting!.detail);
  assert.equal(request!.ok, true, request!.detail);
  assert.equal(validateChecks(raw, "http://10.0.0.2:8080")[0]!.ok, false, "another proxy is not ours");
  const failed = raw.replace(/"status": 200/, '"error": "fetch failed"');
  assert.equal(validateChecks(failed, "http://127.0.0.1:8080")[1]!.ok, false);
  assert.equal(validateChecks("Error: no config", "http://127.0.0.1:8080")[0]!.ok, false);
});

test("docker: refused when other services of the project run with the gateway; Compose 2.24.4 at least", async () => {
  const sys = fakeMachine("docker");
  sys.on("docker ps --filter label=com.docker.compose.project=openclaw", { stdout: "openclaw-openclaw-gateway-1\nopenclaw-redis-1\n" });
  const o = io();
  assert.equal(await run(["connect", "--mode", "docker", "--firewall", "http://192.0.2.9:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o, sys), 1);
  assert.match(o.lines.join("\n"), /run with it: openclaw-redis-1/);
  assert.ok(!sys.ran().some((l) => l.includes(" up -d")));
  assert.equal(composeAtLeast("2.24.3", 2, 24, 4), false);
  assert.equal(composeAtLeast("v2.24.4", 2, 24, 4), true);
  assert.equal(composeAtLeast("5.6.1", 2, 24, 4), true);
});

test("docker: a gateway that can leave the internal network is refused, with the reason", async () => {
  const base = JSON.parse(fixture("inspect-compose.json"))[0];
  const withSock = { ...base, Mounts: [{ Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock" }] };
  assert.match(escapesOf(withSock).join(), /mounts \/var\/run\/docker.sock/);
  assert.match(escapesOf({ ...base, Mounts: [{ Source: "/", Destination: "/host" }] }).join(), /mounts \//);
  assert.match(escapesOf({ ...base, HostConfig: { ...base.HostConfig, Privileged: true } }).join(), /privileged/);
  assert.match(escapesOf({ ...base, HostConfig: { ...base.HostConfig, CapAdd: ["CAP_NET_ADMIN", "SYS_TIME"] } }).join(), /has NET_ADMIN$/);
  assert.match(escapesOf({ ...base, HostConfig: { ...base.HostConfig, NetworkMode: "host" } }).join(), /network mode is host/);
  assert.match(escapesOf({ ...base, Mounts: [{ Source: "/run/user/1000", Destination: "/run/user/1000" }] }).join(), /mounts \/run\/user\/1000/, "rootless docker or podman");
  assert.match(escapesOf({ ...base, Mounts: [{ Source: "/run/user/1000/podman", Destination: "/podman" }] }).join(), /mounts/);
  assert.deepEqual(escapesOf({ ...base, Mounts: [{ Source: "/srv/oc/config", Destination: "/home/node/.openclaw" }] }), []);

  const sys = fakeMachine("docker");
  sys.on("docker inspect -- openclaw-openclaw-gateway-1", { stdout: JSON.stringify([withSock]) });
  const o = io();
  assert.equal(await run(["connect", "--mode", "docker", "--firewall", "http://192.0.2.9:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o, sys), 1);
  assert.match(o.lines.join("\n"), /could leave the internal network: it mounts \/var\/run\/docker.sock/);
  assert.ok(!sys.ran().some((l) => l.includes(" up -d")));
});

test("docker: the override goes into the project's COMPOSE_FILE, and comes out again", async () => {
  const sys = fakeMachine("docker");
  sys.files.set("/root/openclaw/.env", "OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw:2026.10.9\n");
  sys.modes.set("/root/openclaw/.env", { mode: 0o600, uid: 1000, gid: 1000 });
  const o = io();
  assert.equal(await run(["connect", "--mode", "docker", "--firewall", "http://192.0.2.9:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o, sys), 0, o.lines.join("\n"));
  assert.match(sys.files.get("/root/openclaw/.env")!, /^OPENCLAW_IMAGE=.*\n# Added by controlclaw connect.*\nCOMPOSE_FILE=docker-compose.yml:\/etc\/controlclaw\/docker\/compose.controlclaw.yml\n$/);
  assert.deepEqual(sys.stat("/root/openclaw/.env"), { mode: 0o600, uid: 1000, gid: 1000 }, "their mode and owner are kept");
  assert.match(o.lines.join("\n"), /keeps the capture/);
  assert.equal(await run(["disconnect"], io(), sys), 0);
  assert.equal(sys.files.get("/root/openclaw/.env"), "OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw:2026.10.9\n");
  assert.deepEqual(sys.stat("/root/openclaw/.env"), { mode: 0o600, uid: 1000, gid: 1000 });

  const s2 = fakeMachine("docker");
  s2.files.set("/root/openclaw/.env", "COMPOSE_FILE=a.yml:b.yml\n");
  const o2 = io();
  assert.equal(await run(["connect", "--mode", "docker", "--firewall", "http://192.0.2.9:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], o2, s2), 0);
  assert.equal(s2.files.get("/root/openclaw/.env"), "COMPOSE_FILE=a.yml:b.yml\n", "theirs is not touched");
  assert.match(o2.lines.join("\n"), /left as it is: add \/etc\/controlclaw\/docker\/compose.controlclaw.yml to COMPOSE_FILE/);
  for (const env of ["export COMPOSE_FILE=a.yml\n", "COMPOSE_PATH_SEPARATOR=;\n"]) {
    const s3 = fakeMachine("docker");
    s3.files.set("/root/openclaw/.env", env);
    assert.equal(await run(["connect", "--mode", "docker", "--firewall", "http://192.0.2.9:3940", "--ca", "/tmp/ca.pem", "--vm-agent", "/opt/vm-agent"], io(), s3), 0);
    assert.equal(s3.files.get("/root/openclaw/.env"), env, env);
  }
});
