import assert from "node:assert/strict";
import { test } from "node:test";
import type { Io } from "./commands.js";
import { fakeMachine } from "./fake-machine.js";
import { openclawCompose, openclawInstall } from "./openclaw-install.js";
import type { FakeSys } from "./sys.js";

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

/** A machine with no OpenClaw yet. */
function bare(): FakeSys {
  const sys = fakeMachine("systemd-user");
  sys.on("ps -eo", { stdout: "    0     1 /sbin/init\n" });
  sys.on("/opt/vm-agent discover", { stdout: '{"cli":null,"version":null,"config_file":null,"state_dir":null,"runs":{"kind":"not-found"},"gateway_port":18789}' });
  sys.on("{{.State.Health.Status}}", { stdout: "healthy\n" });
  sys.on("systemctl --user is-active openclaw-gateway.service", { stdout: "active\n" });
  return sys;
}

test("openclaw install --docker: OpenClaw's compose project, set up and started, its Control UI on loopback", async () => {
  const y = openclawCompose({ image: "ghcr.io/openclaw/openclaw:2026.10.9", dir: "/opt/openclaw" });
  assert.match(y, /^name: openclaw$/m);
  assert.match(y, /  openclaw-gateway:/);
  assert.match(y, /- "127.0.0.1:18789:18789"/, "on this machine only");
  assert.match(y, /cap_drop: \[NET_RAW, NET_ADMIN\]/);
  assert.doesNotMatch(y, /docker.sock|privileged/, "nothing docker mode would refuse");

  const sys = bare();
  const o = io();
  assert.equal(await openclawInstall(sys, o, { vmAgent: "/opt/vm-agent" }), 0, o.lines.join("\n"));
  const c = "docker compose -p openclaw --project-directory /opt/openclaw -f /opt/openclaw/compose.yaml";
  const ran = sys.ran();
  assert.ok(ran.findIndex((l) => l.includes(`${c} run --rm --no-deps -T --entrypoint node openclaw-gateway dist/index.js onboard`)) >= 0);
  assert.ok(ran.includes(`${c} up -d openclaw-gateway`));
  assert.equal(sys.stat("/opt/openclaw/.env")?.mode, 0o600);
  assert.match(o.lines.join("\n"), /Control UI: http:\/\/127.0.0.1:18789\/#token=[0-9a-f]{48}/);
  assert.match(o.lines.join("\n"), /Next, connect it to a firewall/, "no firewall here, none given");
});

test("openclaw install --host: OpenClaw's installer as root, then OpenClaw as its own user with a systemd user service", async () => {
  const sys = bare();
  sys.files.set("/etc/passwd", `${sys.files.get("/etc/passwd")}openclaw:x:1002:1002::/home/openclaw:/bin/bash\n`);
  const o = io();
  assert.equal(await openclawInstall(sys, o, { host: true, vmAgent: "/opt/vm-agent" }), 0, o.lines.join("\n"));
  const ran = sys.ran();
  assert.ok(ran.includes("loginctl enable-linger openclaw"));
  assert.ok(ran.some((l) => l.includes("https://openclaw.ai/install.sh | bash -s -- --no-onboard --no-prompt") && !l.startsWith("runuser")), "the installer as root");
  assert.ok(ran.some((l) => l.startsWith("runuser -u openclaw -- env HOME=/home/openclaw") && l.includes('cd "$HOME" && exec openclaw onboard') && l.includes("--install-daemon")));
  assert.ok(!ran.some((l) => l.startsWith("useradd")), "the user is there already");

  const root = io();
  assert.equal(await openclawInstall(bare(), root, { host: true, user: "root", vmAgent: "/opt/vm-agent" }), 2);
  assert.match(root.lines.join("\n"), /not root/);
  const nosudo = bare();
  nosudo.euid = 1001;
  assert.equal(await openclawInstall(nosudo, io(), { host: true, vmAgent: "/opt/vm-agent" }), 1);

  // OpenClaw is there already: nothing installed.
  const there = fakeMachine("systemd-user");
  const o2 = io();
  assert.equal(await openclawInstall(there, o2, { vmAgent: "/opt/vm-agent" }), 1);
  assert.match(o2.lines.join("\n"), /OpenClaw is on this machine already/);
});
