import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { BACKUP_RULE, CONTROL_PLANE_RULE, isBoxOwnCall, isRoutineRecord, MANAGED_EGRESS, MANAGED_EGRESS_PRIORITY, managedEgressRules, managedEgressSource } from "./managed-egress";

test("the same list as the firewall's", () => {
  const file = JSON.parse(readFileSync(new URL("../../../../rust/crates/cc-contracts/managed-egress.json", import.meta.url), "utf8"));
  assert.equal(file.priority, MANAGED_EGRESS_PRIORITY);
  assert.deepEqual(file.sources, MANAGED_EGRESS);
});

test("exact hosts only, and the ids the firewall makes", () => {
  for (const s of MANAGED_EGRESS) for (const h of s.hosts) assert.ok(!h.domain.includes("*"), h.domain);
  assert.deepEqual(managedEgressRules(managedEgressSource("telegram")!, "vm1"), [
    {
      id: "managed:telegram:api.telegram.org:vm1",
      name: "Channel: Telegram",
      matchDomain: "api.telegram.org",
      matchPath: null,
      vmId: "vm1",
      priority: -5,
      managed: "telegram",
    },
  ]);
  assert.equal(managedEgressRules(managedEgressSource("openai_codex")!, null)[0].matchDomain, "chatgpt.com");
});

test("routine: the owner's key through a managed rule, with no error (as the firewall's is_routine)", () => {
  const base = { effect: "allow", rule_id: "managed:telegram:api.telegram.org:a1", managed: "telegram", swapped: ["CC-TG-1"], status: 200 };
  assert.equal(isRoutineRecord(base), true);
  assert.equal(isRoutineRecord({ ...base, included: "ok" }), true);
  for (const [k, v] of [
    ["swapped", []],
    ["effect", "block"],
    ["status", 502],
    ["error", "upstream_reset"],
    ["model_error", "credit"],
    ["included", "used_up"],
    ["rule_id", "r1"],
    ["managed", null],
  ] as const) {
    assert.equal(isRoutineRecord({ ...base, [k]: v }), false, `${k}: ${String(v)}`);
  }
});

test("a box's own call: the firewall's built-in rule names", () => {
  const proxy = readFileSync(new URL("../../../../rust/bins/cc-proxy/src/http/backup.rs", import.meta.url), "utf8");
  assert.ok(proxy.includes(`CONTROL_PLANE_RULE: &str = "${CONTROL_PLANE_RULE}"`));
  assert.ok(proxy.includes(`BACKUP_RULE: &str = "${BACKUP_RULE}"`));
});

test("a box's own call: allowed to the control plane or the backup store, under no rule of the owner's (as the review's is_builtin)", () => {
  assert.equal(isBoxOwnCall({ rule: "control_plane", effect: "allow", rule_id: null }), true);
  assert.equal(isBoxOwnCall({ rule: "control_plane", effect: "allow" }), true);
  assert.equal(isBoxOwnCall({ rule: "backup_store", effect: "allow", rule_id: null }), true);
  // Refused: another bucket, a misdirected request, a failed check.
  assert.equal(isBoxOwnCall({ rule: "control_plane", effect: "block", rule_id: null }), false);
  assert.equal(isBoxOwnCall({ rule: "backup_store", effect: "block" }), false);
  assert.equal(isBoxOwnCall({ rule: "backup_store", effect: "error" }), false);
  // An owner's rule named the same carries its id.
  assert.equal(isBoxOwnCall({ rule: "control_plane", effect: "allow", rule_id: "r_123" }), false);
  // Anything else the agent did.
  assert.equal(isBoxOwnCall({ rule: "Telegram", effect: "allow", rule_id: null }), false);
  assert.equal(isBoxOwnCall({ rule: null, effect: "allow" }), false);
  assert.equal(isBoxOwnCall({ effect: "allow" }), false);
});
