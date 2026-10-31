import assert from "node:assert/strict";
import { test } from "node:test";
import { BRAIN_RULE_PRIORITY_ALLOW, BRAIN_RULE_PRIORITY_BLOCK, isBrainManagedRule } from "./brain-rules";

const brains = new Set(["vm-brain"]);

test("the brain's own rules: on the brain box, at one of its two orders", () => {
  assert.equal(isBrainManagedRule({ vmId: "vm-brain", priority: BRAIN_RULE_PRIORITY_ALLOW }, brains), true);
  assert.equal(isBrainManagedRule({ vmId: "vm-brain", priority: BRAIN_RULE_PRIORITY_BLOCK }, brains), true);
});

test("anything else is the owner's", () => {
  assert.equal(isBrainManagedRule({ vmId: "vm-brain", priority: 100 }, brains), false);
  assert.equal(isBrainManagedRule({ vmId: "vm-agent", priority: BRAIN_RULE_PRIORITY_ALLOW }, brains), false);
  assert.equal(isBrainManagedRule({ vmId: null, priority: BRAIN_RULE_PRIORITY_BLOCK }, brains), false);
  assert.equal(isBrainManagedRule({ vmId: "vm-brain", priority: BRAIN_RULE_PRIORITY_ALLOW }, new Set()), false);
});
