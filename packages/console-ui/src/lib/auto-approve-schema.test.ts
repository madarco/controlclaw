import assert from "node:assert/strict";
import { test } from "node:test";
import { autoApproveChange, autoRuleToItem, itemToAutoRule, newAutoRuleId, patchAutoRule, type AutoApproveRule } from "./auto-approve-schema";

const RULE: AutoApproveRule = { id: "r1", name: "Allow git status", description: "", kinds: ["exec"], title_like: "git status", title_match: "exact", vm_id: "vm-a", effect: "allow", enabled: true };

test("a firewall rule is a row of the tab, its place in the list as its priority", () => {
  const item = autoRuleToItem(RULE, 3);
  assert.deepEqual(
    { id: item.id, priority: item.priority, titleLike: item.titleLike, titleMatch: item.titleMatch, vmId: item.vmId, locked: item.locked, condDisplay: item.condDisplay },
    { id: "r1", priority: 3, titleLike: "git status", titleMatch: "exact", vmId: "vm-a", locked: false, condDisplay: null },
  );
  assert.equal(item.cond, 'kind: exec · title is "git status" · vm = vm-a');
  // A rule with no title: no match kind either, and every agent.
  const any = autoRuleToItem({ ...RULE, title_like: null, title_match: null, vm_id: null }, 0);
  assert.deepEqual([any.titleLike, any.titleMatch, any.vmId], [null, "contains", null]);
});

test("the editor's values become the firewall's rule, and back", () => {
  const rule = itemToAutoRule("r1", { name: " Allow git status ", kinds: ["exec"], titleLike: " git status ", titleMatch: "exact", vmId: "vm-a", effect: "allow" });
  assert.deepEqual(rule, { ...RULE, name: "Allow git status" });
  // An empty text is no text, and its match kind goes with it.
  assert.deepEqual([itemToAutoRule("r2", { name: "x", titleLike: "  ", titleMatch: "exact", effect: "ask" }).title_like, itemToAutoRule("r2", { name: "x", titleLike: "", effect: "ask" }).title_match], [null, null]);
  assert.throws(() => itemToAutoRule("bad id", { name: "x", effect: "ask" }));
});

test("a patch changes only what it names", () => {
  assert.deepEqual(patchAutoRule(RULE, { effect: "block" }), { ...RULE, effect: "block" });
  assert.deepEqual(patchAutoRule(RULE, { enabled: false }), { ...RULE, enabled: false });
  assert.deepEqual(patchAutoRule(RULE, { vmId: null, titleLike: null }), { ...RULE, vm_id: null, title_like: null, title_match: null });
});

test("new ids are ids the firewall takes; changes parse", () => {
  const id = newAutoRuleId();
  assert.match(id, /^ar_[a-f0-9]{24}$/);
  assert.notEqual(id, newAutoRuleId());
  assert.equal(autoApproveChange.safeParse({ op: "put", rule: RULE, at: 0 }).success, true);
  assert.equal(autoApproveChange.safeParse({ op: "move", id: "r1", to: -1 }).success, false);
  assert.equal(autoApproveChange.safeParse({ op: "put", rule: { ...RULE, effect: "maybe" } }).success, false);
});
