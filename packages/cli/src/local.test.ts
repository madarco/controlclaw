import assert from "node:assert/strict";
import { test } from "node:test";
import { run } from "./cli.js";
import { disconnect, type Io, status } from "./commands.js";
import { fakeMachine, fixture } from "./fake-machine.js";
import type { Ask } from "./menu.js";
import type { OpenNet } from "./open.js";
import type { Post } from "./pair.js";
import { loadRecord } from "./state.js";
import type { FakeSys } from "./sys.js";
import { uninstall } from "./up.js";

/** A panel with no admin yet. */
const NEW_PANEL: OpenNet = { session: async () => ({ setup: true }) };
const noTerminal: Ask = { pick: async () => null, line: async () => null };

function io(): Io & { lines: string[] } {
  const lines: string[] = [];
  return { lines, out: (l) => lines.push(l), err: (l) => lines.push(l) };
}

function firewall() {
  const calls: string[] = [];
  const post: Post = async (url) => {
    calls.push(url);
    return { status: 200, json: { ok: true } };
  };
  return { calls, net: { post, source: async () => "127.0.0.1", ipv4: async () => "127.0.0.1", open: NEW_PANEL, busy: async () => false } };
}

const C = "docker compose -p controlclaw-local --project-directory /opt/controlclaw-local -f /opt/controlclaw-local/compose.yaml";

/** A machine set up by 0.10.0's `sudo npx controlclaw up --all` (its files, as that code wrote them). */
function oldLocal(): { sys: FakeSys; before: string[] } {
  const sys = fakeMachine("systemd-user");
  const before = [...sys.files.keys()].sort();
  for (const [path, body] of Object.entries(JSON.parse(fixture("up-local-0.10.0.json")) as Record<string, string>)) sys.files.set(path, body);
  sys.on("com.docker.network.bridge.gateway_mode_ipv4", { stdout: "isolated\n" });
  sys.on("{{.State.Status}}", { stdout: "running healthy\n" });
  sys.on("{{json .NetworkSettings.Networks}}", { stdout: '{"controlclaw-local_agents":{}}' });
  sys.on("node -e", { stdout: "HTTP 403\n" });
  sys.on("node:net", { stdout: "ok\n" });
  sys.on(`${C} logs`, { stdout: "firewall-1  | [cc-local] no admin yet: set the password with this one-time setup token (POST /api/setup): abc123\n" });
  return { sys, before };
}

test("up --local before 0.10.1: status checks it, up --all checks it and changes nothing", async () => {
  const { sys } = oldLocal();
  assert.equal(loadRecord(sys)?.mode, "local");
  const s = io();
  assert.equal(await status(sys, s, {}), 0, s.lines.join("\n"));
  assert.match(s.lines.join("\n"), /✓ request from OpenClaw: HTTP 403/);

  const files = new Map(sys.files);
  sys.calls = [];
  const fw = firewall();
  const o = io();
  assert.equal(await run(["up", "--all"], o, sys, noTerminal, fw.net), 0, o.lines.join("\n"));
  const text = o.lines.join("\n");
  assert.match(text, /set up by up --local or up --all of 0.10.0 or earlier .* in \/opt\/controlclaw-local\): checking it/);
  assert.match(text, /✓ firewall: running/);
  assert.match(text, /Firewall panel: http:\/\/127.0.0.1:8800\/#setup=abc123/);
  assert.match(text, /To move to the current setup: sudo npx controlclaw uninstall, then npx controlclaw up --all/);
  assert.deepEqual(new Map(sys.files), files, "nothing written");
  assert.ok(!sys.ran().some((l) => / up -d | pull | install /.test(l)), sys.ran().join("\n"));

  // Without sudo: root's record is not this user's.
  sys.euid = 1001;
  sys.env.HOME = "/home/claw";
  const u = io();
  assert.equal(await run(["up", "--all"], u, sys, noTerminal, fw.net), 1);
  assert.match(u.lines.join("\n"), /set up with sudo\. Run: sudo npx controlclaw up --all/);
});

test("up --local before 0.10.1: disconnect stops its containers and keeps the data; uninstall --purge removes its volume", async () => {
  const { sys, before } = oldLocal();
  const fw = firewall();
  const d = io();
  assert.equal(await disconnect(sys, d, {}, fw.net.post), 0, d.lines.join("\n"));
  assert.ok(sys.ran().includes(`${C} down`), "the containers stop; their data stays (no -v)");
  assert.ok(fw.calls.includes("http://127.0.0.1:8801/unpair"), "the firewall forgets the agent");
  assert.ok(!sys.files.has("/etc/controlclaw/agent.json") && !sys.files.has("/etc/systemd/system/controlclaw-agent.service"));
  assert.equal(loadRecord(sys), null);

  const again = oldLocal();
  again.sys.on("docker volume inspect controlclaw-local_firewall", { code: 0 });
  const u = io();
  assert.equal(await uninstall(again.sys, u, { purge: true }, fw.net.post), 0, u.lines.join("\n"));
  assert.ok(again.sys.ran().includes(`${C} down`));
  assert.ok(again.sys.ran().includes("docker volume rm controlclaw-local_firewall"));
  assert.deepEqual([...again.sys.files.keys()].sort(), before);
});
