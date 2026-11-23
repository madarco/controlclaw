import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { brainAgentConfig, brainAgentUnit, connectKeyFile, gbrainConfigProblem, gbrainDropin, pagesNameOk, parseUnit, REVOKE } from "./brain.js";
import { BRAIN_GATE_IP, brainCompose, containerHelpers, GBRAIN_SHA256, GBRAIN_VERSION, helpers, imageFiles, imageTag } from "./brain-image.js";
import { ISOLATED_GATEWAY } from "./capture/docker.js";

test("the brain's helpers have every placeholder filled, and parse as bash", () => {
  const all = {
    ...containerHelpers(),
    ...helpers({ user: "g", home: "/home/g", env: "/home/g/.gbrain/env", keyFile: "/etc/k", keyOwner: "root:root", keyMode: "0644", gbrain: "/usr/bin/gbrain", host: "127.0.0.1", port: 4000, out: "/o", owner: "root", restart: "systemctl restart gbrain.service" }),
  };
  const dir = mkdtempSync(join(tmpdir(), "brain-helpers-"));
  for (const [name, text] of Object.entries(all)) {
    assert.doesNotMatch(text, /@[A-Z]+@/, `${name} has a placeholder left`);
    assert.doesNotMatch(text, /\{\{/, `${name} has Jinja left`);
    if (name.endsWith(".py")) continue;
    const f = join(dir, name);
    writeFileSync(f, text);
    execFileSync("bash", ["-n", f]);
  }
});

test("cc-gbrain-key takes a placeholder with its own provider's base URL, and nothing else", () => {
  const dir = mkdtempSync(join(tmpdir(), "brain-key-"));
  const keyFile = join(dir, "env");
  writeFileSync(keyFile, "GBRAIN_DATABASE_URL=postgres://x\nOPENAI_API_KEY=old\n");
  const script = join(dir, "cc-gbrain-key");
  const owner = execFileSync("id", ["-un"]).toString().trim();
  writeFileSync(script, helpers({ user: "g", home: dir, env: keyFile, keyFile, keyOwner: owner, keyMode: "0600", gbrain: "/bin/true", host: "127.0.0.1", port: 1, out: dir, owner, restart: "echo restarted >&2" })["cc-gbrain-key"]!);
  const run = (input: string) => {
    try {
      return { code: 0, out: execFileSync("bash", [script], { input, stdio: ["pipe", "pipe", "pipe"] }).toString().trim() };
    } catch (e) {
      return { code: (e as { status: number }).status, out: "" };
    }
  };
  assert.deepEqual(run("vck-cc-0123456789abcdef01234567 https://ai-gateway.vercel.sh/v1\n"), { code: 0, out: "changed" });
  assert.deepEqual(run("vck-cc-0123456789abcdef01234567 https://ai-gateway.vercel.sh/v1\n"), { code: 0, out: "unchanged" });
  const text = execFileSync("cat", [keyFile]).toString();
  assert.match(text, /^GBRAIN_DATABASE_URL=postgres:\/\/x$/m, "the other lines stay");
  assert.match(text, /^OPENAI_API_KEY=vck-cc-0123456789abcdef01234567$/m);
  assert.match(text, /^OPENAI_BASE_URL=https:\/\/ai-gateway.vercel.sh\/v1$/m);
  assert.equal(run("sk-cc-openai-0123456789abcdef01234567 https://api.openai.com/v1\n").out, "changed");
  for (const bad of [
    "sk-proj-realkey0123456789 https://api.openai.com/v1",
    "sk-cc-openai-0123456789abcdef01234567 https://evil.example/v1",
    "vck-cc-0123456789abcdef01234567 https://api.openai.com/v1",
    "vck-cc-included-abcdefgh12",
    "vck-cc-0123456789abcdef01234567",
  ]) {
    assert.equal(run(`${bad}\n`).code, 2, bad);
  }
  assert.equal(run("-\n").out, "changed");
  assert.match(execFileSync("cat", [keyFile]).toString(), /^OPENAI_API_KEY=vck-cc-included-none$/m, "taken away: a key nothing swaps");
});

test("the image pins GBrain as the Ansible role does, and its tag follows what is in it", () => {
  const files = imageFiles();
  assert.match(files.Dockerfile!, new RegExp(`${GBRAIN_SHA256}  /usr/local/bin/gbrain-${GBRAIN_VERSION}`));
  assert.match(files.Dockerfile!, /sha256sum -c -/);
  const tag = imageTag(files);
  assert.match(tag, new RegExp(`^controlclaw-brain-gbrain:${GBRAIN_VERSION}-[0-9a-f]{12}$`));
  assert.notEqual(imageTag({ ...files, "bin/cc-gbrain-svc": "changed" }), tag);
});

test("the brain's containers: an internal network, GBrain on the firewall's own network or behind the gate", () => {
  const base = { image: "img", out: "/var/lib/controlclaw/brain/gbrain-pages", ca: "/etc/controlclaw/brain/ca.crt", tz: "Europe/Rome", gatewayIsolated: ISOLATED_GATEWAY };
  const here = brainCompose({ ...base, egress: { kind: "firewall-net", network: "controlclaw-firewall_agents", firewall: "172.31.251.2", address: "172.31.251.20" } });
  // GBrain's way out is the egress relay, the one service on the firewall's `agents` network: GBrain
  // cannot reach an OpenClaw there, and the gate that publishes GBrain is not on it.
  assert.match(here, /HTTPS_PROXY: "http:\/\/172.31.248.3:8080"/);
  assert.match(here, /name: "controlclaw-firewall_agents"/);
  assert.match(here, /internal: true/);
  const service = (name: string) => here.split(/\n  (?=[a-z]+:\n)/).find((b) => b.startsWith(`${name}:`)) ?? "";
  assert.doesNotMatch(service("gbrain"), /firewall:/, "GBrain is not on the firewall's agents network");
  assert.doesNotMatch(service("gate"), /firewall:/, "nor is the gate that publishes GBrain");
  assert.match(service("egress"), /ipv4_address: 172.31.251.20/, "the brain's identity at the firewall");
  assert.match(service("egress"), /TCP-LISTEN:8080,fork,reuseaddr TCP:172.31.251.2:8080/);
  assert.doesNotMatch(service("egress"), /3130/, "no way to GBrain from agents");
  assert.match(here, /"127.0.0.1:3130:3130"/, "GBrain only on this machine's loopback");
  assert.doesNotMatch(here, /GBRAIN_PUBLIC_URL/);
  assert.match(brainCompose({ ...base, pagesName: "brain.example.com", egress: { kind: "gate", proxy: { host: "10.77.0.1", port: 8080 }, dns: null } }), /GBRAIN_PUBLIC_URL: "https:\/\/brain.example.com"/);
  const away = brainCompose({ ...base, egress: { kind: "gate", proxy: { host: "10.77.0.1", port: 8080 }, dns: "10.77.0.1" } });
  assert.match(away, new RegExp(`HTTPS_PROXY: "http://${BRAIN_GATE_IP}:8080"`));
  assert.match(away, /TCP-LISTEN:8080,fork,reuseaddr TCP:10.77.0.1:8080/);
  assert.match(away, /UDP-LISTEN:53,fork,reuseaddr UDP:10.77.0.1:53/);
  assert.doesNotMatch(away, /external: true/);
  // The database password comes from Compose's .env, never the file itself.
  assert.match(away, /\$\{GBRAIN_DB_PASSWORD\}/);
});

test("the vm-agent's brain config and unit", () => {
  const c = JSON.parse(
    brainAgentConfig({ listen: "172.31.252.1:3103", agentId: "agent_1", firewallUrl: "http://127.0.0.1:8801/", firewallKey: "PEM", allowFrom: ["172.31.252.2"], port: 3130, exec: ["docker", "exec", "-i", "-u", "0", "c"], pagesName: "brain.example.com" }),
  );
  assert.equal(c.mode, "brain");
  assert.deepEqual(c.firewall.hostnames, ["172.31.252.1"], "the address the firewall signs its tokens for");
  assert.deepEqual(c.firewall.allow_from, ["172.31.252.2"]);
  assert.deepEqual(c.gbrain.exec, ["docker", "exec", "-i", "-u", "0", "c"]);
  assert.equal(c.gbrain.pages_name, "brain.example.com");
  assert.equal(c.gbrain.gate_listen, undefined, "agents come through the firewall's relay");
  assert.ok(pagesNameOk("brain.example.com"));
  for (const bad of ["brain", "brain.example.com:443", "https://brain.example.com", "-x.example.com", "a..b", "10.0.0.5", "Brain.example.com"]) assert.ok(!pagesNameOk(bad), bad);
  const u = brainAgentUnit({ after: "wg-quick@cc-wg0.service", filesUi: true });
  assert.match(u, /After=network-online.target wg-quick@cc-wg0.service/);
  assert.match(u, /FILES_UI_DIR=/);
  assert.doesNotMatch(brainAgentUnit({ filesUi: false }), /FILES_UI_DIR/);
});

test("a connected GBrain's drop-in: the firewall only, its CA and proxy, its key's file", () => {
  const d = gbrainDropin({ keyFile: "/etc/controlclaw/brain/gbrain.env", ca: "/etc/controlclaw/brain/ca.crt", proxy: "10.77.0.1:8080", allow: ["10.77.0.1"] });
  assert.match(d, /^IPAddressDeny=any$/m);
  assert.match(d, /^IPAddressAllow=localhost 10.77.0.1$/m);
  assert.match(d, /^EnvironmentFile=-\/etc\/controlclaw\/brain\/gbrain.env$/m);
  assert.match(d, /HTTPS_PROXY=http:\/\/10.77.0.1:8080/);
  assert.match(d, /NODE_EXTRA_CA_CERTS=\/etc\/controlclaw\/brain\/ca.crt/);
});

test("GBrain's unit is found by what it runs", () => {
  const show = (exec: string, extra = "") =>
    `Id=gbrain.service\nUser=gbrain\nExecStart={ path=/usr/local/bin/gbrain ; argv[]=${exec} ; ignore_errors=no ; start_time=[n/a] }\nEnvironmentFiles=${extra}\n`;
  assert.deepEqual(parseUnit(show("/usr/local/bin/gbrain serve --http --bind 127.0.0.1 --port 3130", "/var/lib/gbrain/.gbrain/env (ignore_errors=no)")), {
    unit: "gbrain.service",
    user: "gbrain",
    bin: "/usr/local/bin/gbrain",
    port: 3130,
    envFile: "/var/lib/gbrain/.gbrain/env",
  });
  assert.equal(parseUnit(show("/usr/local/bin/gbrain serve --http --port=4000"))?.port, 4000);
  assert.equal(parseUnit(show("/usr/local/bin/gbrain serve --http"))?.port, null);
  assert.equal(parseUnit(show("/usr/bin/nginx -g daemon off;")), null);
  assert.equal(parseUnit(show("/usr/local/bin/gbrain dream")), null);
});

test("brain connect holds to the firewall only a GBrain with its database here and the brain's embedding model", () => {
  const show = (db: string, embed = "openai:text-embedding-3-small") => `  database_url: ${db}\n  embedding_model: ${embed}\n  embedding_dimensions: 1536\n`;
  assert.equal(gbrainConfigProblem(show("postgres://***@127.0.0.1:5432/gbrain")), null);
  assert.equal(gbrainConfigProblem(show("postgres://***@localhost/gbrain")), null);
  assert.equal(gbrainConfigProblem(show("undefined")), null, "a PGLite brain has no database_url");
  assert.match(gbrainConfigProblem(show("postgres://***@db.abc.supabase.co:5432/postgres")) ?? "", /on db.abc.supabase.co/);
  assert.match(gbrainConfigProblem(show("postgres://***@127.0.0.1:5432/gbrain", "openai:text-embedding-3-large")) ?? "", /text-embedding-3-large/);
});

test("disconnect revokes the brain's tokens in a connected GBrain, and no one else's", () => {
  const dir = mkdtempSync(join(tmpdir(), "brain-revoke-"));
  const tokens = [
    { name: "cc-agent_1", status: "active", created_at: "2026-11-23T15:10:27.609Z" },
    { name: "cc-agent_2", status: "active", created_at: "2026-11-23 15:11:00+00" },
    { name: "cc-theirs", status: "active", created_at: "2026-11-23T09:00:00Z" },
    { name: "controlclaw-pages", status: "active", created_at: "2026-11-01T00:00:00Z" },
    { name: "cc-agent_3", status: "revoked", created_at: "2026-11-23T15:12:00Z" },
    { name: "my-laptop", status: "active", created_at: "2026-11-23T16:00:00Z" },
  ];
  // A stand-in for runuser and gbrain: lists the tokens, logs what it is asked to revoke.
  writeFileSync(join(dir, "gbrain"), `#!/bin/bash\ncase "$1 $2" in "auth list") cat ${dir}/tokens.json ;; "auth revoke") echo "$3" >> ${dir}/revoked ;; esac\n`, { mode: 0o755 });
  writeFileSync(join(dir, "runuser"), `#!/bin/bash\nshift 3; exec "$@"\n`, { mode: 0o755 });
  writeFileSync(join(dir, "tokens.json"), JSON.stringify(tokens));
  execFileSync("bash", ["-c", REVOKE, "_", dir, join(dir, "none"), join(dir, "gbrain"), "g", "2026-11-23T15:00:00.000Z"], { env: { ...process.env, PATH: `${dir}:${process.env.PATH}` } });
  const revoked = execFileSync("cat", [join(dir, "revoked")]).toString().trim().split("\n").sort();
  assert.deepEqual(revoked, ["cc-agent_1", "cc-agent_2", "controlclaw-pages"]);
});

test("cc-gbrain-key leaves its folder's mode alone, and writes the file with the mode it is given", () => {
  const dir = mkdtempSync(join(tmpdir(), "brain-keydir-"));
  // The folder the CA sits in too (brain connect's /etc/controlclaw/brain): its mode must not change.
  const shared = join(dir, "brain");
  mkdirSync(shared);
  chmodSync(shared, 0o755);
  const keyFile = join(shared, "gbrain", "gbrain.env");
  mkdirSync(join(shared, "gbrain"), { mode: 0o750 });
  const owner = execFileSync("id", ["-un"]).toString().trim();
  const script = join(dir, "cc-gbrain-key");
  writeFileSync(script, helpers({ user: "g", home: dir, env: keyFile, keyFile, keyOwner: owner, keyMode: "0640", gbrain: "/bin/true", host: "127.0.0.1", port: 1, out: dir, owner, restart: "true" })["cc-gbrain-key"]!);
  execFileSync("bash", [script], { input: "vck-cc-0123456789abcdef01234567 https://ai-gateway.vercel.sh/v1\n" });
  assert.equal(statSync(shared).mode & 0o777, 0o755, "the shared folder keeps its mode");
  assert.equal(statSync(join(shared, "gbrain")).mode & 0o777, 0o750);
  assert.equal(statSync(keyFile).mode & 0o777, 0o640);
  // A folder that is not there yet is made, private.
  const fresh = join(dir, "fresh", "k.env");
  writeFileSync(script, helpers({ user: "g", home: dir, env: fresh, keyFile: fresh, keyOwner: owner, keyMode: "0600", gbrain: "/bin/true", host: "127.0.0.1", port: 1, out: dir, owner, restart: "true" })["cc-gbrain-key"]!);
  execFileSync("bash", [script], { input: "-\n" });
  assert.equal(statSync(join(dir, "fresh")).mode & 0o777, 0o700);
});

test("a connected GBrain's key file puts its own key out of effect from the start", () => {
  const f = connectKeyFile("http://172.31.252.2:8080", "/etc/controlclaw/brain/ca.crt");
  assert.match(f, /^OPENAI_API_KEY=vck-cc-included-none$/m, "a stand-in nothing swaps, over GBrain's real key");
  assert.match(f, /^OPENAI_BASE_URL=https:\/\/ai-gateway.vercel.sh\/v1$/m);
  assert.match(f, /^HTTPS_PROXY=http:\/\/172.31.252.2:8080$/m);
  assert.match(f, /^NODE_EXTRA_CA_CERTS=\/etc\/controlclaw\/brain\/ca.crt$/m);
});
