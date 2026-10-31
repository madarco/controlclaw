import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "./cli.js";
import type { Io } from "./commands.js";
import { gatherFacts, renderDoctor, verdicts, warnings } from "./doctor.js";
import { fakeMachine, fixture } from "./fake-machine.js";
import { loadRecord, pathOwner, Recorder } from "./state.js";

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

test("doctor: an official install under its own user can do host and proxy, not docker", async () => {
  const sys = fakeMachine("systemd-user");
  const f = await gatherFacts(sys);
  assert.equal(f.openclaw.user?.name, "claw");
  assert.equal(f.openclaw.via, "light", "no vm-agent given: the light look");
  const fv = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.equal(fv.openclaw.via, "vm-agent");
  assert.deepEqual(fv.openclaw.install.runs, { kind: "systemd-user", unit: "openclaw-gateway.service" });
  const v = Object.fromEntries(verdicts(fv).map((m) => [m.name, m]));
  assert.equal(v.host!.ok, true);
  assert.equal(v.proxy!.ok, true);
  assert.equal(v.docker!.ok, false);
  assert.equal(v.remote!.ok, true, "remote: as host mode, with WireGuard installed by apt");
  assert.ok(warnings(fv).some((w) => /DNS stops for every program/.test(w)), "says plainly that host mode moves the host's DNS");
  const text = renderDoctor(fv);
  assert.match(text, /systemd user unit openclaw-gateway.service, user claw/);
  assert.match(text, /✓ host/);
});

test("doctor: OpenClaw run by root blocks host mode, and a sudo user is warned about", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("ps -eo", { stdout: "    0  4242 openclaw-gateway\n" });
  sys.on("/opt/vm-agent discover", { stdout: fixture("discover-systemd-user.json") });
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  const host = verdicts(f).find((m) => m.name === "host")!;
  assert.equal(host.ok, false);
  assert.match(host.blockers.join(), /runs as root/);

  const s2 = fakeMachine("systemd-user");
  s2.on("id -nG claw", { stdout: "claw sudo\n" });
  assert.ok(warnings(await gatherFacts(s2, { vmAgent: "/opt/vm-agent" })).some((w) => /can use sudo/.test(w)));
});

test("doctor: with no gateway running, the user is the one with an OpenClaw config", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("ps -eo", { stdout: "    0     1 /sbin/init\n" });
  sys.files.set("/home/claw/.openclaw/openclaw.json", "{}");
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.equal(f.openclaw.user?.name, "claw");
});

test("doctor: docker mode needs Docker 28, which leaves the host no address on the internal network", async () => {
  const sys = fakeMachine("docker");
  sys.on("docker version", { stdout: "27.5.1\n" });
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.match(verdicts(f).find((m) => m.name === "docker")!.blockers.join(), /needs Docker 28 or newer/);
});

test("doctor: OpenClaw in Docker can do docker mode only", async () => {
  const f = await gatherFacts(fakeMachine("docker"), { vmAgent: "/opt/vm-agent" });
  const ok = verdicts(f).filter((m) => m.ok).map((m) => m.name);
  assert.deepEqual(ok, ["docker"]);
  assert.equal(f.openclaw.user, null, "a container has no host user");
});

test("connect refuses a bad pairing code, a missing CA and an unknown mode", async () => {
  const sys = fakeMachine("systemd-user");
  const o = io();
  assert.equal(await run(["connect", "--mode", "host", "--firewall", "http://10.0.0.2", "--code", "4F7K"], o, sys), 2);
  assert.match(o.lines.join("\n"), /Not on the command line/);
  assert.equal(await run(["connect", "--mode", "host", "--firewall", "http://10.0.0.2"], io(), sys), 2);
  assert.equal(await run(["connect", "--mode", "wifi", "--firewall", "http://10.0.0.2", "--ca", "/tmp/ca.pem"], io(), sys), 2);
  assert.equal(await run(["connect", "--mode", "remote", "--firewall", "http://10.0.0.2", "--ca", "/tmp/ca.pem"], io(), sys), 2);
  assert.equal(loadRecord(sys), null);
});

const CONNECT_HOST = ["connect", "--mode", "host", "--firewall", "http://127.0.0.1:3940", "--proxy", "127.0.0.1:9", "--dns", "10.0.0.2", "--ca", "/tmp/ca.pem", "--firewall-key", "/tmp/fw.pem", "--vm-agent", "/opt/vm-agent"];

test("connect --mode host, then disconnect: every file is gone and every step undone, in reverse", async () => {
  const sys = fakeMachine("systemd-user");
  const before = new Map(sys.files);
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, sys), 0, o.lines.join("\n"));
  const text = o.lines.join("\n");
  assert.match(text, /Connected in host mode/);
  assert.match(text, /DNS stops for every program/);

  const nft = sys.files.get("/etc/controlclaw/capture/capture.nft")!;
  assert.match(nft, /meta skuid 1001 meta nfproto ipv4 meta l4proto tcp redirect to :12346/);
  assert.match(nft, /dnat ip to 10.0.0.2:53/);
  assert.match(sys.files.get("/etc/controlclaw/capture/redsocks.conf")!, /ip = 127.0.0.1;\n  port = 9;/);
  assert.match(sys.files.get("/etc/systemd/resolved.conf.d/controlclaw.conf")!, /DNS=10.0.0.2/);
  assert.match(sys.files.get("/home/claw/.config/systemd/user/openclaw-gateway.service.d/controlclaw.conf")!, /NODE_EXTRA_CA_CERTS=\/etc\/controlclaw\/ca.crt/);
  const agent = JSON.parse(sys.files.get("/etc/controlclaw/agent.json")!);
  assert.equal(agent.mode, "unmanaged");
  assert.match(agent.firewall.public_key, /BEGIN PUBLIC KEY/);
  assert.match(sys.files.get("/etc/systemd/system/controlclaw-agent.service")!, /User=claw/);

  const ran = sys.ran();
  assert.ok(ran.includes("env DEBIAN_FRONTEND=noninteractive apt-get install -y -q redsocks"));
  assert.ok(ran.includes("systemctl enable --now controlclaw-capture.service"));
  assert.ok(ran.includes("runuser -u claw -- env HOME=/home/claw XDG_RUNTIME_DIR=/run/user/1001 systemctl --user restart -- openclaw-gateway.service"));
  assert.equal(loadRecord(sys)?.mode, "host");

  sys.calls = [];
  assert.equal(await run(["disconnect"], io(), sys), 0);
  assert.deepEqual([...sys.files.keys()].sort(), [...before.keys()].sort(), "only the files that were there before");
  const undo = sys.ran();
  const at = (s: string) => undo.findIndex((l) => l.includes(s));
  assert.ok(at("disable --now controlclaw-capture.service") >= 0);
  assert.ok(at("/usr/sbin/nft -f /etc/controlclaw/capture/remove.nft") >= 0, "works also where the table is gone");
  assert.ok(at("apt-get purge -y -q redsocks") > at("disable --now controlclaw-redsocks.service"), "the package goes after its unit");
  assert.ok(at("systemctl --user restart -- openclaw-gateway.service") === undo.length - 1, "OpenClaw is restarted last, with its settings back");
  assert.equal(loadRecord(sys), null);
});

test("connect twice is refused; a failed connect undoes itself", async () => {
  const sys = fakeMachine("systemd-user");
  assert.equal(await run(CONNECT_HOST, io(), sys), 0);
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, sys), 1);
  assert.match(o.lines.join("\n"), /Already connected/);

  const s2 = fakeMachine("systemd-user");
  const before = new Map(s2.files);
  s2.on("systemctl enable --now controlclaw-capture.service", { code: 1, stderr: "nft: syntax error" });
  const o2 = io();
  assert.equal(await run(CONNECT_HOST, o2, s2), 1);
  assert.match(o2.lines.join("\n"), /Connect failed: could not start controlclaw-capture.service/);
  assert.deepEqual([...s2.files.keys()].sort(), [...before.keys()].sort());
  assert.equal(loadRecord(s2), null);
});

test("status reports a firewall DNS that does not answer", async () => {
  const sys = fakeMachine("systemd-user");
  // 192.0.2.1 is a documentation address: nothing answers there.
  const args = CONNECT_HOST.map((a) => (a === "10.0.0.2" ? "192.0.2.1" : a));
  assert.equal(await run(args, io(), sys), 0);
  sys.on("systemctl is-active", { stdout: "active\n" });
  const o = io();
  assert.equal(await run(["status"], o, sys), 1);
  assert.match(o.lines.join("\n"), /✗ firewall DNS: 192.0.2.1 does not answer .*DNS on this whole machine depends on it/);
});

test("disconnect and status without sudo, after a connect with sudo, say to use sudo", async () => {
  const sys = fakeMachine("systemd-user");
  assert.equal(await run(CONNECT_HOST, io(), sys), 0);
  sys.euid = 1001;
  sys.env.HOME = "/home/claw";
  for (const cmd of ["disconnect", "status"]) {
    const o = io();
    assert.equal(await run([cmd], o, sys), 1);
    assert.match(o.lines.join("\n"), new RegExp(`Run: sudo controlclaw ${cmd}`));
  }
  assert.ok(sys.files.has("/etc/controlclaw/capture/capture.nft"), "nothing was undone");
});

test("host: a user in the docker group is refused, with the fix", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("id -nG claw", { stdout: "claw docker\n" });
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, sys), 1);
  assert.match(o.lines.join("\n"), /claw is in the docker group.*gpasswd -d claw docker\), or use docker mode/);
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.ok(warnings(f).some((w) => /docker group: it can start a container/.test(w)));
});

test("the vm-agent binary already at the install path is used in place and left there", async () => {
  const sys = fakeMachine("systemd-user");
  sys.files.set("/usr/local/bin/controlclaw-vm-agent", "ELF");
  const args = CONNECT_HOST.map((a) => (a === "/opt/vm-agent" ? "/usr/local/bin/controlclaw-vm-agent" : a));
  sys.on("/usr/local/bin/controlclaw-vm-agent discover", { stdout: fixture("discover-systemd-user.json") });
  assert.equal(await run(args, io(), sys), 0);
  assert.ok(!sys.ran().some((l) => l.startsWith("install -D")));
  assert.equal(await run(["disconnect"], io(), sys), 0);
  assert.ok(!sys.ran().some((l) => l.includes("rm -f /usr/local/bin/controlclaw-vm-agent")));

  // Someone else's file at that path: set aside, and put back.
  const s2 = fakeMachine("systemd-user");
  s2.files.set("/usr/local/bin/controlclaw-vm-agent", "OTHER");
  assert.equal(await run(CONNECT_HOST, io(), s2), 0);
  assert.ok(s2.ran().includes("mv -f /usr/local/bin/controlclaw-vm-agent /usr/local/bin/controlclaw-vm-agent.before-controlclaw"));
  s2.calls = [];
  assert.equal(await run(["disconnect"], io(), s2), 0);
  const undo = s2.ran();
  assert.ok(undo.indexOf("rm -f /usr/local/bin/controlclaw-vm-agent") < undo.indexOf("mv -f /usr/local/bin/controlclaw-vm-agent.before-controlclaw /usr/local/bin/controlclaw-vm-agent"));
});

test("a vm-agent its user cannot run is run from a copy; one that cannot look stops connect", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("runuser -u claw -- env HOME=/home/claw XDG_RUNTIME_DIR=/run/user/1001 /opt/vm-agent discover", { code: 126, stderr: "runuser: failed to execute /opt/vm-agent: Permission denied" });
  sys.on("mktemp -d", { stdout: "/tmp/controlclaw-discover.abc\n" });
  sys.on("runuser -u claw -- env HOME=/home/claw XDG_RUNTIME_DIR=/run/user/1001 /tmp/controlclaw-discover.abc/vm-agent discover", { stdout: fixture("discover-systemd-user.json") });
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.equal(f.openclaw.via, "vm-agent");
  assert.ok(sys.ran().includes("rm -rf /tmp/controlclaw-discover.abc"), "the copy is removed");

  const s2 = fakeMachine("systemd-user");
  s2.on("/opt/vm-agent discover", { code: 1, stderr: "discover: something broke" });
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, s2), 1);
  assert.match(o.lines.join("\n"), /could not look at this OpenClaw \(vm-agent discover: discover: something broke\)/);
  assert.equal(loadRecord(s2), null);
});

test("root writes as the user wherever a user controls the path: its folders, or a link", async () => {
  const sys = fakeMachine("systemd-user");
  // A link claw planted in its own home, and one in a root folder it could write to.
  sys.links.set("/home/claw/.local/state/controlclaw", "/etc");
  sys.owners.set("/home/claw/.local/state/controlclaw", 1001);
  assert.equal(pathOwner(sys, "/home/claw/.local/state/controlclaw/vm_private_key.pem"), 1001);
  sys.files.set("/srv/", "");
  // A root folder others may write to: refused, whoever would write.
  sys.files.set("/var/shared/", "");
  sys.modes.set("/var/shared", { mode: 0o1777, uid: 0, gid: 0 });
  assert.throws(() => pathOwner(sys, "/var/shared/proj/.env"), /\/var\/shared can be written by other users \(mode 1777\).*chmod go-w \/var\/shared/);
  sys.modes.set("/var/shared", { mode: 0o775, uid: 0, gid: 999 });
  assert.throws(() => pathOwner(sys, "/var/shared/.env"), /mode 775/, "group-writable too");
  sys.links.set("/srv/x.env", "/etc/shadow");
  sys.owners.set("/srv/x.env", 1001);
  assert.equal(pathOwner(sys, "/srv/x.env"), 1001, "a link the user owns");
  // A user's regular file in root's folder is root's to write; a root link is root's.
  sys.files.set("/srv/y.env", "A=1\n");
  sys.modes.set("/srv/y.env", { mode: 0o600, uid: 1001, gid: 1001 });
  assert.equal(pathOwner(sys, "/srv/y.env"), 0);
  assert.equal(pathOwner(sys, "/etc/controlclaw/agent.json"), 0);

  const rec = new Recorder(sys, { version: 1, mode: "host", at: "", user: null, firewall: { url: "", proxy: "", dns: null }, cli: [], ca: "", steps: [] });
  await rec.file("/srv/x.env", "PWNED\n");
  assert.ok(sys.ran().includes("as claw write /srv/x.env"));
  sys.owners.set("/srv/z.env", 4242);
  sys.links.set("/srv/z.env", "/etc/passwd");
  await assert.rejects(rec.file("/srv/z.env", "x"), /uid 4242, which has no user here/);
});

test("a binary set aside by an earlier connect is never overwritten", async () => {
  const sys = fakeMachine("systemd-user");
  sys.files.set("/usr/local/bin/controlclaw-vm-agent", "OTHER");
  sys.files.set("/usr/local/bin/controlclaw-vm-agent.before-controlclaw", "OLDER");
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, sys), 1);
  assert.match(o.lines.join("\n"), /before-controlclaw exists already/);
  assert.ok(!sys.ran().some((l) => l.startsWith("mv -f")));
  assert.equal(sys.files.get("/usr/local/bin/controlclaw-vm-agent.before-controlclaw"), "OLDER");
  assert.equal(loadRecord(sys), null);
});

test("host: groups that cannot be read, or resolved with no user of its own, refuse host mode", async () => {
  const sys = fakeMachine("systemd-user");
  sys.on("id -nG claw", { code: 1, stderr: "id: cannot find name for group ID 5000" });
  const f = await gatherFacts(sys, { vmAgent: "/opt/vm-agent" });
  assert.equal(f.groupsUnknown, true);
  const host = verdicts(f).find((m) => m.name === "host")!;
  assert.match(host.blockers.join(), /cannot read the groups of claw/);

  const s2 = fakeMachine("systemd-user");
  s2.files.set("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nclaw:x:1001:1001::/home/claw:/bin/bash\n");
  const f2 = await gatherFacts(s2, { vmAgent: "/opt/vm-agent" });
  assert.match(verdicts(f2).find((m) => m.name === "host")!.blockers.join(), /no systemd-resolve user/);
  assert.equal(f2.groupsUnknown, false);
});

test("a disconnect that fails keeps the failed steps, and can be run again", async () => {
  const sys = fakeMachine("systemd-user");
  assert.equal(await run(CONNECT_HOST, io(), sys), 0);
  sys.on("apt-get purge", { code: 100, stderr: "E: Could not get lock /var/lib/dpkg/lock-frontend" });
  const o = io();
  assert.equal(await run(["disconnect"], o, sys), 1);
  assert.match(o.lines.join("\n"), /could not remove redsocks: E: Could not get lock/);
  const left = loadRecord(sys)!;
  assert.deepEqual(left.steps.map((s) => (s.kind === "run" ? s.argv.map((a) => a.join(" ")) : s.path)), [["apt-get purge -y -q redsocks"]]);
  sys.on("apt-get purge", { code: 0 });
  sys.calls = [];
  assert.equal(await run(["disconnect"], io(), sys), 0);
  assert.deepEqual(sys.ran(), ["apt-get purge -y -q redsocks"]);
  assert.equal(loadRecord(sys), null);
});

test("the gateway process is found by what it runs, not by a command line that mentions it", async () => {
  const { isGatewayProcess } = await import("./openclaw.js");
  assert.equal(isGatewayProcess("openclaw-gateway"), true);
  assert.equal(isGatewayProcess("/usr/bin/node --max-old-space-size=3875 /home/claw/.npm-global/lib/node_modules/openclaw/dist/index.js gateway --port 18789"), true);
  assert.equal(isGatewayProcess("/usr/bin/nodejs /usr/lib/node_modules/openclaw/dist/index.js gateway"), true, "Debian's nodejs");
  assert.equal(isGatewayProcess("node dist/index.js gateway --bind lan"), false, "a container's node with no openclaw path is told apart by its cgroup, not here");
  assert.equal(isGatewayProcess("/home/claw/.npm-global/bin/openclaw gateway run"), true);
  assert.equal(isGatewayProcess("bash -c systemctl --user enable --now openclaw-gateway.service; openclaw gateway status"), false);
  assert.equal(isGatewayProcess("journalctl -u openclaw-gateway -f"), false);
  assert.equal(isGatewayProcess("/usr/bin/node /home/claw/.npm-global/lib/node_modules/openclaw/dist/process/spawn-broker/worker.js"), false);
});

test("disconnect --force gives up a step that keeps failing; a failed set-aside records nothing", async () => {
  const sys = fakeMachine("systemd-user");
  assert.equal(await run(CONNECT_HOST, io(), sys), 0);
  sys.on("apt-get purge", { code: 100, stderr: "E: broken" });
  assert.equal(await run(["disconnect"], io(), sys), 1);
  const o = io();
  assert.equal(await run(CONNECT_HOST, o, sys), 1);
  assert.match(o.lines.join("\n"), /--force gives up steps/);
  const f = io();
  assert.equal(await run(["disconnect", "--force"], f, sys), 1);
  assert.match(f.lines.join("\n"), /given up; check them by hand/);
  assert.equal(loadRecord(sys), null);
  assert.equal(await run(["status"], io(), sys), 0, "not connected any more");

  const s2 = fakeMachine("systemd-user");
  s2.files.set("/usr/local/bin/controlclaw-vm-agent", "OTHER");
  s2.on("mv -f /usr/local/bin/controlclaw-vm-agent", { code: 1, stderr: "Operation not permitted" });
  assert.equal(await run(CONNECT_HOST, io(), s2), 1);
  assert.equal(loadRecord(s2), null, "the failed connect undid itself fully");
  assert.ok(!s2.ran().some((l) => l.includes("mv -f /usr/local/bin/controlclaw-vm-agent.before-controlclaw")));
});
