import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { matchAutoApprove, permissionTitle, type AutoRule } from "./auto-approve";

type WireRule = { id: string; name: string; kinds?: string[]; title_like?: string | null; title_match?: string | null; vm_id?: string | null; effect: string; enabled?: boolean };

const cases = JSON.parse(readFileSync(new URL("../../../../rust/crates/cc-contracts/auto-approve-cases.json", import.meta.url), "utf8")) as {
  rules: Record<string, WireRule>;
  cases: Array<{ name: string; rules: string[]; request: { kind: string; title: string; vm_id: string | null }; expect: { effect: string; rule_id: string | null } }>;
  titles: Array<{ name: string; request: Parameters<typeof permissionTitle>[0]; app_names: Record<string, string>; title: string | null }>;
};

const rule = (w: WireRule): AutoRule => ({
  id: w.id,
  name: w.name,
  kinds: w.kinds ?? [],
  titleLike: w.title_like ?? null,
  titleMatch: w.title_match ?? null,
  vmId: w.vm_id ?? null,
  effect: w.effect,
  ...(w.enabled === undefined ? {} : { enabled: w.enabled }),
});

test("the cases the firewall runs", () => {
  for (const c of cases.cases) {
    const d = matchAutoApprove(c.rules.map((n) => rule(cases.rules[n]!)), { kind: c.request.kind, title: c.request.title, vmId: c.request.vm_id });
    assert.equal(d.effect, c.expect.effect, c.name);
    assert.equal(d.matchedRule?.id ?? null, c.expect.rule_id, c.name);
  }
});

test("the titles the firewall builds", () => {
  for (const c of cases.titles) {
    assert.equal(permissionTitle(c.request, (s) => c.app_names[s] ?? s), c.title, c.name);
  }
});
