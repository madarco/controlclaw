import test from "node:test";
import assert from "node:assert/strict";
import { isTimed, monthStart, nextMonthStart, rangeBuckets, rollupGroups, RESPONSE_MAX_MS, securityRulesLine } from "./firewall-stats";

test("the response time leaves out tunnels, long-polls and anything not allowed", () => {
  assert.equal(isTimed("allowed", { durationMs: 120 }), true);
  assert.equal(isTimed("allowed", { durationMs: RESPONSE_MAX_MS }), true);
  assert.equal(isTimed("allowed", { durationMs: 30_012 }), false);
  assert.equal(isTimed("allowed", { durationMs: 120, tunnel: true }), false);
  assert.equal(isTimed("blocked", { durationMs: 120 }), false);
  assert.equal(isTimed("allowed", { durationMs: null }), false);
  assert.equal(isTimed("allowed", {}), false);
});

test("inserted rows are grouped by agent, hour and status, with the timed sum", () => {
  const at = (iso: string) => new Date(iso);
  const groups = rollupGroups([
    { vmId: "a", status: "allowed", occurredAt: at("2026-10-23T14:05:00Z"), detail: { durationMs: 100 } },
    { vmId: "a", status: "allowed", occurredAt: at("2026-10-23T14:55:00Z"), detail: { durationMs: 300 } },
    { vmId: "a", status: "allowed", occurredAt: at("2026-10-23T14:56:00Z"), detail: { durationMs: 30_000 } },
    { vmId: "a", status: "allowed", occurredAt: at("2026-10-23T15:00:00Z"), detail: { durationMs: 50 } },
    { vmId: null, status: "blocked", occurredAt: at("2026-10-23T14:10:00Z"), detail: {} },
    { vmId: "a", status: "succeeded", occurredAt: at("2026-10-23T14:10:00Z"), detail: {} },
  ]);
  const key = (g: (typeof groups)[number]) => `${g.vmId}|${g.hour.toISOString()}|${g.status}`;
  const by = new Map(groups.map((g) => [key(g), g]));
  assert.equal(groups.length, 3);
  assert.deepEqual(
    (({ count, durationMsSum, durationN }) => ({ count, durationMsSum, durationN }))(by.get("a|2026-10-23T14:00:00.000Z|allowed")!),
    { count: 3, durationMsSum: 400, durationN: 2 },
  );
  assert.equal(by.get("a|2026-10-23T15:00:00.000Z|allowed")!.count, 1);
  // Traffic not tied to an agent is one group with an empty id.
  assert.equal(by.get("|2026-10-23T14:00:00.000Z|blocked")!.count, 1);
});

test("each range has the buckets the chart draws, the last one holding now", () => {
  const now = new Date("2026-10-23T14:37:20Z");
  const h = rangeBuckets("1h", now);
  assert.equal(h.length, 60);
  assert.equal(h.at(-1)!.toISOString(), "2026-10-23T14:37:00.000Z");
  const d = rangeBuckets("24h", now);
  assert.equal(d.length, 48);
  assert.equal(d.at(-1)!.toISOString(), "2026-10-23T14:30:00.000Z");
  const w = rangeBuckets("7d", now);
  assert.equal(w.length, 56);
  assert.equal(w.at(-1)!.toISOString(), "2026-10-23T12:00:00.000Z");
  assert.equal(w[0]!.toISOString(), "2026-10-16T15:00:00.000Z");
});

test("the month runs from the 1st, UTC, across the year's end", () => {
  assert.equal(monthStart(new Date("2026-12-31T23:59:00Z")).toISOString(), "2026-12-01T00:00:00.000Z");
  assert.equal(nextMonthStart(new Date("2026-12-31T23:59:00Z")).toISOString(), "2027-01-01T00:00:00.000Z");
});

test("the Security rules shield counts every type, and never says none while the firewall's are unknown", () => {
  const base = { siteRules: 0, securityRules: 0, securityAsk: 0, messageRules: 0, emailRules: 0 };
  assert.equal(securityRulesLine(base), "No rules yet");
  // Messages and Email rules only: the bug was "No rules yet" here.
  assert.equal(securityRulesLine({ ...base, messageRules: 2, emailRules: 3 }), "5 rules");
  assert.equal(securityRulesLine({ ...base, siteRules: 4, securityRules: 2, securityAsk: 1, messageRules: 1, emailRules: 0 }), "7 rules · 1 ask you first");
  assert.equal(securityRulesLine({ ...base, securityRules: 1, messageRules: null, emailRules: null }), "1 rule, plus Messages and Email");
  assert.equal(securityRulesLine({ ...base, messageRules: null }), "Messages rules on the firewall");
  assert.equal(securityRulesLine({ ...base, messageRules: null, emailRules: null }), "Messages and Email rules on the firewall");
});
