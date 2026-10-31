import assert from "node:assert/strict";
import { test } from "node:test";
import type { Schemas } from "@controlclaw/fw-api";
import { boxOptions, toAiView, toRule } from "./egress";
import { toLive, toOverview } from "./stats";
import type { AgentRow } from "./agents";

const agents: AgentRow[] = [
  { vm_id: "agent_1", role: "openclaw", name: "atlas", private_ip: "10.0.0.3" },
  { vm_id: "agent_2", role: "gbrain", name: "brain", private_ip: null },
];

const live = (id: number, verdict: Schemas["LiveRequest"]["verdict"]): Schemas["LiveRequest"] => ({
  id,
  createdAt: `2026-10-30T10:00:0${id}Z`,
  occurredAt: `2026-10-30T10:00:0${id}Z`,
  host: "example.com",
  verdict,
  long: false,
});

test("live rows: ids become strings, recorded rows are left out, missing fields are null", () => {
  const rows = toLive([live(1, "blocked"), live(2, "recorded")]);
  assert.deepEqual(rows, [{ id: "1", createdAt: "2026-10-30T10:00:01Z", occurredAt: "2026-10-30T10:00:01Z", method: null, host: "example.com", agent: null, verdict: "blocked", durationMs: null, long: false }]);
});

test("the overview: running, the brain marked, a finding's severity narrowed, shields filled", () => {
  const o: Schemas["Overview"] = {
    generatedAt: "2026-10-30T10:00:00Z",
    hours: [],
    perMinute: { value: 1, today: 2, yesterday: 3, series: [] },
    blocked: { today: 0, yesterday: 0, series: [] },
    response: { series: [] },
    month: { count: 5, resetsAt: "2026-11-01T00:00:00Z" },
    traffic: { range: "24h", points: [] },
    live: [live(3, "allowed")],
    topHosts: [],
    byAgent: [
      { vmId: "agent_2", name: "brain", total: 4, blocked: 1, hourly: [] },
      { name: "Firewall", total: 1, blocked: 0, hourly: [] },
    ],
    ai: { enabled: true, findings: [{ id: "f", severity: "critical", title: "t", at: "2026-10-30T09:00:00Z" }] },
    shields: { siteRules: 2, aiKeys: 1 },
  };
  const v = toOverview(o, agents, true);
  assert.equal(v.running, true);
  assert.deepEqual(v.response, { value: null, today: null, yesterday: null, series: [] });
  assert.equal(v.byAgent[0].brain, true);
  assert.equal(v.byAgent[1].vmId, null);
  assert.equal(v.ai.findings[0].severity, "high");
  assert.equal(v.ai.enabled, true);
  assert.equal(v.shields.siteRules, 2);
  assert.equal(v.shields.messageRules, null);
});

test("a site rule: the fields the API leaves out are null", () => {
  const r = toRule({
    id: "r1",
    name: "Example",
    matchDomain: "example.com",
    effect: "block",
    exit: "firewall",
    priority: 10,
    enabled: true,
    aiReview: false,
    createdAt: "2026-10-30T10:00:00Z",
    updatedAt: "2026-10-30T10:00:00Z",
  } as Schemas["EgressRule"]);
  assert.equal(r.matchPath, null);
  assert.equal(r.vmId, null);
  assert.equal(r.aiPolicy, null);
});

test("agents as rule scopes, and the AI view for the panel", () => {
  assert.deepEqual(boxOptions(agents), [
    { id: "agent_1", name: "atlas", kind: "agent" },
    { id: "agent_2", name: "brain", kind: "brain" },
  ]);
  const ai = toAiView(
    {
      settings: { enabled: true, logReviewEnabled: false, model: "m", dailyCallCap: 1000, scanIntervalHours: 6, autoApprovePerHour: 10 },
      credentials: [{ id: "k", provider: "anthropic", name: "Anthropic", hint: "…wxyz", defaultModel: "claude" }],
      active: true,
    },
    agents,
  );
  assert.equal(ai.local, true);
  assert.equal(ai.settings.credentialId, null);
  const kept = toAiView(
    { settings: { enabled: true, logReviewEnabled: true, credentialId: "k", model: "m", dailyCallCap: 1000, scanIntervalHours: 6, autoApprovePerHour: 10 }, credentials: [{ id: "k", provider: "anthropic", name: "Anthropic", hint: "…wxyz", defaultModel: "claude" }], active: true },
    agents,
  );
  assert.equal(kept.settings.credentialId, "k");
  // A key removed since is not sent back.
  const gone = toAiView({ settings: { enabled: true, logReviewEnabled: true, credentialId: "k", model: "m", dailyCallCap: 1000, scanIntervalHours: 6, autoApprovePerHour: 10 }, credentials: [], active: false }, agents);
  assert.equal(gone.settings.credentialId, null);
  // The AI Firewall cannot be on without a key: shown off, so the rest can still be saved.
  assert.equal(gone.settings.enabled, false);
  assert.equal(gone.settings.logReviewEnabled, true);
  assert.equal(kept.settings.enabled, true);
  assert.equal(ai.settings.logReviewNotify, "nobody");
  assert.equal(ai.historyAvailable, false);
  assert.equal(ai.agents.length, 2);
});
