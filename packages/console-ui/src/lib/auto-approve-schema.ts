import { z } from "zod";
import { deriveCondFromMatchers } from "./auto-approve";
import { permissionKindSchema } from "./permission-kinds";
import type { RuleEffect, SecurityRuleListItem, TitleMatch } from "./security-schema";

/**
 * The Auto approve rules as a firewall keeps them (`autoapprove.read`, `cc_contracts::auto_approve`):
 * the firewall's order is the order they are read in. The console shows them as
 * `SecurityRuleListItem`s, the same rows as the rules it kept itself before.
 */

export const autoApproveRule = z.object({
  id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
  name: z.string().min(1).max(200),
  description: z.string().max(1000).default(""),
  kinds: z.array(permissionKindSchema).default([]),
  title_like: z.string().max(500).nullish(),
  title_match: z.enum(["contains", "exact"]).nullish(),
  vm_id: z.string().max(100).nullish(),
  effect: z.enum(["allow", "ask", "block"]),
  enabled: z.boolean().default(true),
});
export type AutoApproveRule = z.output<typeof autoApproveRule>;

export const autoApproveSnapshot = z.object({
  rules: z.array(autoApproveRule),
  unreadable: z.boolean().optional(),
  /** Which list this is (higher after every change): the console copies only a newer one. */
  version: z.number().int().nonnegative().optional(),
});
export type AutoApproveSnapshot = z.output<typeof autoApproveSnapshot>;

export const autoApproveChange = z.discriminatedUnion("op", [
  z.object({ op: z.literal("put"), rule: autoApproveRule, at: z.number().int().min(0).max(500).optional() }),
  z.object({ op: z.literal("delete"), id: z.string().min(1).max(64) }),
  z.object({ op: z.literal("move"), id: z.string().min(1).max(64), to: z.number().int().min(0).max(500) }),
]);
export type AutoApproveChange = z.output<typeof autoApproveChange>;

export const autoApproveChangeInput = z.object({ change: autoApproveChange });
export const autoApproveChangeId = z.object({ changeId: z.string().min(1).max(100) });
export const autoApproveConfirm = z.object({ changeId: z.string().min(1).max(100), code: z.string().min(1).max(20) });

/** A new rule's id on the firewall. */
export function newAutoRuleId(): string {
  return `ar_${globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`;
}

/** A firewall rule as a row of the Auto approve tab. `priority` is its place in the firewall's list. */
export function autoRuleToItem(rule: AutoApproveRule, index: number): SecurityRuleListItem {
  const titleLike = rule.title_like || null;
  const titleMatch: TitleMatch = rule.title_match === "exact" ? "exact" : "contains";
  return {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    condDisplay: null,
    cond: deriveCondFromMatchers(rule.kinds, titleLike, rule.vm_id ?? null, titleMatch),
    enabled: rule.enabled,
    locked: false,
    priority: index,
    kinds: rule.kinds,
    titleLike,
    titleMatch,
    vmId: rule.vm_id ?? null,
    effect: rule.effect as RuleEffect,
    createdAt: "",
    updatedAt: "",
  };
}

/** What a rule's editor or tool gives, as the firewall's rule. */
export function itemToAutoRule(
  id: string,
  item: { name: string; description?: string; kinds?: string[]; titleLike?: string | null; titleMatch?: TitleMatch; vmId?: string | null; effect: RuleEffect; enabled?: boolean },
): AutoApproveRule {
  const title = item.titleLike?.trim() || null;
  return autoApproveRule.parse({
    id,
    name: item.name.trim(),
    description: item.description ?? "",
    kinds: item.kinds ?? [],
    title_like: title,
    title_match: title ? (item.titleMatch ?? "contains") : null,
    vm_id: item.vmId || null,
    effect: item.effect,
    enabled: item.enabled ?? true,
  });
}

/** A rule with a patch from the editor or `security_update_rule` laid over it. */
export function patchAutoRule(
  rule: AutoApproveRule,
  patch: { name?: string; description?: string; kinds?: string[]; titleLike?: string | null; titleMatch?: TitleMatch; vmId?: string | null; effect?: RuleEffect; enabled?: boolean },
): AutoApproveRule {
  const item = autoRuleToItem(rule, 0);
  return itemToAutoRule(rule.id, {
    name: patch.name ?? item.name,
    description: patch.description ?? item.description,
    kinds: patch.kinds ?? item.kinds,
    titleLike: patch.titleLike !== undefined ? patch.titleLike : item.titleLike,
    titleMatch: patch.titleMatch ?? item.titleMatch,
    vmId: patch.vmId !== undefined ? patch.vmId : item.vmId,
    effect: patch.effect ?? item.effect,
    enabled: patch.enabled ?? item.enabled,
  });
}
