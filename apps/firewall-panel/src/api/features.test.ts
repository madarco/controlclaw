import assert from "node:assert/strict";
import { test } from "node:test";
import { FwApiError } from "@controlclaw/fw-api";
import { refusalText, settledChanges } from "./changes";
import { appliedAtOnce, toMcpOptions } from "./rules";
import { toExitView } from "./exit";
import { toConnectorsView, toMcpView } from "./integrations";
import { toAgentChannels } from "./channels";
import type { AgentRow } from "./agents";

const agents: AgentRow[] = [
  { vm_id: "a1", role: "openclaw", name: "atlas", private_ip: "10.0.0.3" },
  { vm_id: "a2", role: "openclaw", name: "bolt", private_ip: "10.0.0.4" },
];

test("a refusal's words, however the route says them", () => {
  assert.equal(refusalText(new FwApiError(409, "HTTP 409", { ok: false, status: "failed", message: "Bad token" })), "Bad token");
  assert.equal(refusalText(new FwApiError(409, "HTTP 409", { result: { message: "Telegram said no" }, channels: [] })), "Telegram said no");
  assert.equal(refusalText(new FwApiError(400, "host: required", { error: "host: required" })), "host: required");
});

test("a rules change is applied at once: status hands back the new rules, once", async () => {
  const rpc = appliedAtOnce<{ op: string }, { rules: string[] }>(async () => ({ ok: true, status: "applied", data: { rules: ["r1"] } }));
  const { changeId } = await rpc.change({ change: { op: "put" } });
  const s = await rpc.status({ changeId });
  assert.deepEqual([s.status, s.ok, s.snapshot], ["applied", true, { rules: ["r1"] }]);
  assert.equal((await rpc.status({ changeId })).ok, false);
  const refused = appliedAtOnce<{ op: string }, unknown>(async () => {
    throw new FwApiError(409, "HTTP 409", { ok: false, status: "failed", message: "Too broad" });
  });
  await assert.rejects(refused.change({ change: { op: "put" } }), /Too broad/);
});

test("a firewall change is kept settled; an OAuth sign-in waits until it is settled", async () => {
  const c = settledChanges((id) => ({ id, summary: "", status: "queued" as const, tofu: false, sentVia: null, attemptsLeft: null, expiresAt: null, error: null, createdAt: "", stuck: false }));
  const done = c.record({ ok: true, status: "applied", data: { changeId: "chg_1", summary: "Connect GitHub" } });
  assert.deepEqual([done.id, done.status, done.summary], ["chg_1", "applied", "Connect GitHub"]);
  const signIn = c.record({ ok: true, status: "awaiting_authorization", data: { changeId: "chg_2", expiresAt: "2099-01-01T00:00:00Z" } });
  assert.equal((await c.rpc.getChange({ changeId: "chg_2" })).status, "awaiting_authorization");
  c.settle(signIn.id, null);
  assert.equal((await c.rpc.getChange({ changeId: "chg_2" })).status, "applied");
  assert.equal((await c.rpc.getChange({ changeId: "nope" })).status, "expired");
  assert.throws(() => c.record({ ok: false, status: "failed", message: "No" }), /No/);
  // Left waiting for a code is not applied: the panel's API confirms at once, so it did not apply.
  assert.throws(() => c.record({ ok: true, status: "awaiting_code" }), /waiting for a code/);
});

test("the exit: snake_case status to the card's view", () => {
  const v = toExitView(
    { configured: true, provider: "brightdata", sticky: true, hint: "brd-…", cap_bytes: 5, country: "IT", last_check: { at: 1_700_000_000, ok: true, exit_ip: "1.2.3.4", exit_country: "IT" }, usage: { month: "2026-10", bytes_in: 10, bytes_out: 20 } },
    2,
  );
  assert.equal(v.configured, true);
  assert.equal(v.check?.at, new Date(1_700_000_000_000).toISOString());
  assert.deepEqual(v.usage, { month: "2026-10", bytesIn: 10, bytesOut: 20 });
  assert.equal(v.ruleCount, 2);
  assert.equal(toExitView(null, 0).configured, false);
});

test("connections and MCP servers: agents per connection, a missing module is unsupported", () => {
  const v = toConnectorsView(
    { connections: [{ id: "c1", service: "github", authType: "api_key", state: "active", updatedAt: "2026-10-30T00:00:00Z" }], agents: [{ vmId: "a1", connections: ["c1"] }] },
    agents,
  );
  assert.equal(v.firewall.supported, true);
  assert.deepEqual(v.connections[0].agents.map((a) => a.name), ["atlas"]);
  assert.equal(v.agents.find((a) => a.vmId === "a1")?.connections, 1);
  assert.equal(toConnectorsView(null, agents).firewall.supported, false);
  const m = toMcpView({ servers: [{ name: "docs", url: "https://mcp.example.com/sse", auth: "none", state: "active", agents: ["a2"], updatedAt: "2026-10-30T00:00:00Z" }] }, agents);
  assert.deepEqual([m.servers[0].id, m.servers[0].host, m.servers[0].agents[0].name], ["docs", "mcp.example.com", "bolt"]);
  assert.deepEqual(toMcpOptions({ servers: [{ host: "mcp.example.com", managed: null, tools: [], agents: { a1: {} } }] })[0].mcp?.agents, ["a1"]);
});

test("one agent's channels: its own, and the spare ones", () => {
  const v = toAgentChannels(
    "a1",
    [
      { id: "t1", type: "telegram", hint: "…abcd", vmId: "a1", approvedSenders: 1 },
      { id: "s1", type: "slack", hint: "…wxyz", approvedSenders: 0 },
      { id: "t2", type: "telegram", hint: "…efgh", vmId: "a2", approvedSenders: 0 },
    ],
    agents,
  );
  assert.deepEqual(v.assigned.map((c) => c.id), ["t1"]);
  assert.deepEqual(v.available.map((c) => c.id), ["s1"]);
  assert.equal(v.assigned[0].secretHint, "…abcd");
  assert.equal(v.vm.name, "atlas");
});

test("a Google client file: the id, the secret, the project and its redirect addresses", async () => {
  const { parseGoogleClient } = await import("./accounts");
  const c = parseGoogleClient(JSON.stringify({ web: { client_id: "1-x.apps.googleusercontent.com", client_secret: "s", project_id: "p-1", redirect_uris: ["http://localhost:8800/oauth/callback"] } }));
  assert.deepEqual(c, { clientId: "1-x.apps.googleusercontent.com", clientSecret: "s", projectId: "p-1", redirects: ["http://localhost:8800/oauth/callback"] });
  assert.equal(parseGoogleClient("{}"), null);
  assert.equal(parseGoogleClient("not json"), null);
});

test("addresses from the API: https, or the panel's own origin, nothing else", async () => {
  (globalThis as { window?: unknown }).window = { location: { origin: "http://localhost:8800" } };
  const { checkedUrl } = await import("./oauth");
  assert.equal(checkedUrl("https://accounts.google.com/o/oauth2/auth?x=1"), "https://accounts.google.com/o/oauth2/auth?x=1");
  assert.equal(checkedUrl("/integrations"), "http://localhost:8800/integrations");
  assert.equal(checkedUrl("javascript:alert(1)"), null);
  assert.equal(checkedUrl("data:text/html,hi"), null);
  assert.equal(checkedUrl("http://evil.example/"), null);
});
