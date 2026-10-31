/**
 * The per-rule counts' pure parts (docs/plans/rule-metrics.md): which records count for which rule,
 * the hourly groups, the Firewall page's top six, and the lines under a rule.
 *
 * Run: pnpm --filter @controlclaw/console-ui test
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { emptyCounts, foldNamedApps, groupHits, hitFromCall, hitFromPermission, hitsFromActivity, outcomeLine, ruleLine, topRules, type InsertedActivity, type RuleActivityItem } from "./rule-metrics";

const at = new Date("2026-10-26T10:15:00Z");
const row = (over: Partial<InsertedActivity>): InsertedActivity => ({ source: "egress", vmId: "vm-1", status: "allowed", occurredAt: at, detail: {}, dedupeKey: "egress:f1", ...over });

test("egress rows: a rule by id or by label, the default, email; the firewall's own labels left out", () => {
  const ids: Record<string, string> = { Docs: "r-docs" };
  const hits = hitsFromActivity(
    [
      row({ status: "blocked", detail: { rule: "No pastebins", ruleId: "r-paste" } }),
      row({ detail: { rule: "Docs" } }),
      row({ detail: {} }),
      row({ detail: { rule: "agent_update" } }),
      row({ dedupeKey: "egress:res#2", detail: { rule: "Docs", ruleId: "r-docs" } }),
      row({ detail: { email: "sent" } }),
      row({ status: "asked", detail: { rule: "email" } }),
    ],
    (l) => ids[l] ?? null,
  );
  assert.deepEqual(
    hits.map((h) => `${h.type} ${h.key} ${h.outcome}`),
    ["websites r-paste blocked", "websites r-docs allowed", "websites default allowed", "email out allowed", "websites default allowed", "email out asked"],
  );
});

test("a firewall that sends ids is never matched by label; email counts only the rules' own refusals", () => {
  const hits = hitsFromActivity(
    [
      // The firewall labelled this flow itself (phone, a grant): no rule decided, ruleId null.
      row({ detail: { rule: "Docs", ruleId: null } }),
      row({ detail: { ruleId: null } }),
      row({ status: "blocked", detail: { rule: "email", emailReason: "not_allowed" } }),
      row({ status: "blocked", detail: { rule: "email", emailReason: "lookup_failed" } }),
      row({ status: "blocked", detail: { rule: "email", emailReason: "email_rules_unavailable" } }),
      row({ status: "blocked", detail: { rule: "email" } }),
    ],
    () => "r-docs",
  );
  assert.deepEqual(
    hits.map((h) => `${h.type} ${h.key} ${h.outcome}`),
    ["websites default allowed", "email out blocked"],
  );
});

test("Integrations counts kept by name go to the rule with that name now", () => {
  const at = "2026-10-26T10:00:00Z";
  const items: RuleActivityItem[] = [
    item("ar-1", 2, at, { type: "apps", name: "No deletes", counts: { ...emptyCounts(), blocked: 2 } }),
    item("name:No deletes", 3, "2026-10-26T11:00:00Z", { type: "apps", ruleId: null, name: "No deletes", counts: { ...emptyCounts(), blocked: 3 } }),
    item("name:Only by name", 1, at, { type: "apps", ruleId: null, name: "Only by name" }),
    item("name:Twice", 1, at, { type: "apps", ruleId: null, name: "Twice" }),
    item("name:Gone", 1, at, { type: "apps", ruleId: null, name: "Gone" }),
  ];
  const out = foldNamedApps(items, [
    { id: "ar-1", name: "No deletes" },
    { id: "ar-2", name: "Only by name" },
    { id: "ar-3", name: "Twice" },
    { id: "ar-4", name: "Twice" },
  ]);
  const by = (k: string) => out.find((i) => i.key === k);
  assert.deepEqual([by("ar-1")?.total, by("ar-1")?.counts.blocked, by("ar-1")?.lastAt], [5, 5, "2026-10-26T11:00:00Z"]);
  assert.equal(by("name:No deletes"), undefined);
  assert.deepEqual([by("ar-2")?.ruleId, by("ar-2")?.name], ["ar-2", "Only by name"], "no counts by id yet: it takes the id");
  assert.ok(by("name:Twice") && by("name:Gone"), "two rules with the name, or none: left as it is");
  assert.equal(items[0].total, 2, "the input is not changed");
});

test("content-rule lines and held-back mail", () => {
  const hits = hitsFromActivity(
    [
      row({ source: "content_rule", detail: { rule: "cr-1", name: "Pay", action: "hold" } }),
      row({ source: "content_rule", detail: { rule: "cr-1", action: "released" } }),
      row({ source: "content_rule", detail: { rule: "error", action: "block" } }),
      row({ source: "email_held", vmId: null, status: "blocked" }),
      row({ source: "ai_review", status: "high" }),
    ],
    () => null,
  );
  assert.deepEqual(
    hits.map((h) => `${h.type} ${h.key} ${h.outcome} ${h.name ?? ""}`),
    ["messages cr-1 held Pay", "email in held "],
  );
});

test("a call line counts when the rules decided it, once", () => {
  const base = { ts: 0, vm_id: "vm-1", decision: "blocked", by: "app_rule", rule: "No deletes" };
  assert.equal(hitFromCall({ ...base, rule_id: "ar-1" }, at)?.key, "ar-1");
  assert.equal(hitFromCall(base, at)?.key, "name:No deletes");
  assert.equal(hitFromCall({ ...base, by: "default", decision: "allowed" }, at)?.key, "default");
  assert.equal(hitFromCall({ ...base, rule_id: "ar-1", follows: "x" }, at), null);
  assert.equal(hitFromCall({ ...base, released: true }, at), null);
  assert.equal(hitFromCall({ ...base, by: "content_rule", decision: "held" }, at), null);
  assert.equal(hitFromCall({ ...base, by: "gate" }, at), null);
});

test("a permission request: the rule that answered, or Every other request", () => {
  assert.deepEqual(hitFromPermission({ vmId: null, at, ruleId: "s1", ruleName: "Small", effect: "allow" }), { vmId: null, at, type: "auto", key: "s1", outcome: "allowed", name: "Small" });
  assert.equal(hitFromPermission({ vmId: null, at, ruleId: null, ruleName: null, effect: "ask" }).key, "default");
});

test("hits group by agent, hour, rule and outcome, with the newest time and name", () => {
  const later = new Date("2026-10-26T10:50:00Z");
  const groups = groupHits([
    { vmId: "vm-1", at, type: "messages", key: "cr-1", outcome: "held", name: "Old" },
    { vmId: "vm-1", at: later, type: "messages", key: "cr-1", outcome: "held", name: "New" },
    { vmId: null, at, type: "email", key: "in", outcome: "held" },
  ]);
  assert.equal(groups.length, 2);
  const cr = groups.find((g) => g.ruleKey === "cr-1")!;
  assert.deepEqual([cr.count, cr.lastAt.toISOString(), cr.name, cr.hour.toISOString()], [2, later.toISOString(), "New", "2026-10-26T10:00:00.000Z"]);
  assert.equal(groups.find((g) => g.ruleKey === "in")!.vmId, "");
});

const item = (key: string, total: number, lastAt: string, over: Partial<RuleActivityItem> = {}): RuleActivityItem => ({
  type: "websites",
  key,
  ruleId: key,
  name: key,
  builtin: false,
  deleted: false,
  counts: { ...emptyCounts(), allowed: total },
  total,
  lastAt,
  ...over,
});

test("the Firewall page's list: most active or latest, six at most, grey rows at most two", () => {
  const items = [
    item("default", 900, "2026-10-26T10:00:00Z", { builtin: true, ruleId: null }),
    item("auto-default", 800, "2026-10-26T09:00:00Z", { type: "auto", builtin: true, ruleId: null }),
    item("email-in", 700, "2026-10-26T08:00:00Z", { type: "email", builtin: true, ruleId: null }),
    item("a", 50, "2026-10-26T07:00:00Z"),
    item("b", 40, "2026-10-26T10:30:00Z"),
    item("c", 30, "2026-10-25T07:00:00Z"),
    item("d", 20, "2026-10-24T07:00:00Z"),
    item("e", 10, "2026-10-23T07:00:00Z"),
    item("zero", 0, "2026-10-26T11:00:00Z"),
  ];
  assert.deepEqual(topRules(items, "active").map((i) => i.key), ["default", "auto-default", "a", "b", "c", "d"]);
  assert.deepEqual(topRules(items, "latest").map((i) => i.key), ["b", "default", "auto-default", "a", "c", "d"]);
  assert.deepEqual(topRules([], "active"), []);
});

test("lines", () => {
  const now = new Date("2026-10-26T12:00:00Z").getTime();
  assert.equal(ruleLine("websites", { total: 12, lastAt: "2026-10-26T10:00:00Z" }, now), "Matched 12 requests in 7 days · last 2 h ago");
  assert.equal(ruleLine("messages", { total: 1, lastAt: "2026-10-26T11:55:00Z" }, now), "Acted on 1 message in 7 days · last 5 min ago");
  assert.equal(ruleLine("apps", null, now), "Not matched in 7 days");
  assert.equal(outcomeLine("email", { ...emptyCounts(), allowed: 40, blocked: 1, held: 2 }), "40 sent, 2 held back, 1 refused");
  assert.equal(outcomeLine("messages", { ...emptyCounts(), blocked: 3, recorded: 1 }), "3 stopped, 1 recorded");
});
