/**
 * The brain's own site rules: the few hosts it may reach, then a block on everything else. They are
 * written by `brainEgressRules()` (provisioning.ts), scoped to the brain box, and kept by
 * ControlClaw, so the Internet access page shows them read-only and the egress RPCs refuse to
 * change them.
 *
 * No server imports here: the page's client list reads these too.
 */

export const BRAIN_RULE_PRIORITY_ALLOW = -20;
export const BRAIN_RULE_PRIORITY_BLOCK = -10;

/**
 * Whether a rule is one of the brain's managed rules. Both halves are needed: the rule must be
 * scoped to a brain box (`brainVmIds`: the org's vm rows with role `gbrain`), and sit at one of the
 * two priorities the brain's rules are written at. A rule the owner scoped to the brain themselves,
 * at any other order, stays theirs.
 */
export function isBrainManagedRule(
  rule: { vmId: string | null; priority: number },
  brainVmIds: ReadonlySet<string>,
): boolean {
  return (
    rule.vmId !== null &&
    brainVmIds.has(rule.vmId) &&
    (rule.priority === BRAIN_RULE_PRIORITY_ALLOW || rule.priority === BRAIN_RULE_PRIORITY_BLOCK)
  );
}

export const BRAIN_RULE_LOCKED_MESSAGE =
  "This rule belongs to your brain and is managed by ControlClaw, so it can’t be changed or deleted.";
