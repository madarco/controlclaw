import { z } from "zod";
import { RULE_EFFECTS } from "@controlclaw/console-ui/lib/rule-types";
import { permissionKindSchema } from "./permission-kinds";

export const ruleEffectSchema = z.enum(RULE_EFFECTS);
export type RuleEffect = z.infer<typeof ruleEffectSchema>;

export const NEXT_EFFECT: Record<RuleEffect, RuleEffect> = {
  allow: "ask",
  ask: "block",
  block: "allow",
};

export const EFFECT_TO_STATUS: Record<RuleEffect, "approved" | "denied" | "pending"> = {
  allow: "approved",
  block: "denied",
  ask: "pending",
};

export const STATUS_TO_EVENT: Record<
  "approved" | "denied" | "pending" | "expired",
  "permission.approved" | "permission.denied" | "permission.created" | "permission.expired"
> = {
  approved: "permission.approved",
  denied: "permission.denied",
  pending: "permission.created",
  expired: "permission.expired",
};

/** How `titleLike` is compared with a request title (both case-insensitive). */
export const titleMatchSchema = z.enum(["contains", "exact"]);
export type TitleMatch = z.infer<typeof titleMatchSchema>;

export const ruleKindsSchema = z.array(permissionKindSchema);

/**
 * The two protections the console shows pinned above an organisation's own rules, always on and
 * not something anyone turns off.
 *
 * They are a constant rather than rows in `security_rule`. Nothing creates them for a real
 * organisation — only `lib/db/seed.ts` ever wrote them, for the test org — so reading them from
 * the table meant production saw an empty list under a sentence claiming two core rules were
 * always on. A constant is also what they are: there is no per-organisation state to keep for a
 * rule nobody can change.
 *
 * Neither is enforced by the firewall yet; the owner is tracking that work separately
 * (see `docs/security-design.md`, "LLM proxy").
 */
export const CORE_SECURITY_RULES = [
  {
    id: "core-hidden-instructions",
    name: "Hidden instructions",
    description: "Blocks instructions slipped into messages, emails or web pages to hijack the agent.",
  },
  {
    id: "core-leaking-secrets",
    name: "Leaking secrets",
    description: "Blocks the agent from sending out passwords, keys or tokens.",
  },
] as const;

export const createSecurityRuleInputSchema = z.object({
  name: z.string().min(1).max(120),
  description: z.string().max(500).default(""),
  condDisplay: z.string().max(200).nullish(),
  enabled: z.boolean().default(true),
  priority: z.number().int().min(0).max(1_000_000).default(100),
  kinds: ruleKindsSchema.default([]),
  titleLike: z.string().max(200).nullish(),
  titleMatch: titleMatchSchema.default("contains"),
  vmId: z.string().nullish(),
  effect: ruleEffectSchema,
});

export const updateSecurityRuleInputSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(120).optional(),
  description: z.string().max(500).optional(),
  condDisplay: z.string().max(200).nullish(),
  enabled: z.boolean().optional(),
  priority: z.number().int().min(0).max(1_000_000).optional(),
  kinds: ruleKindsSchema.optional(),
  titleLike: z.string().max(200).nullish(),
  titleMatch: titleMatchSchema.optional(),
  vmId: z.string().nullish(),
  effect: ruleEffectSchema.optional(),
});

export const deleteSecurityRuleInputSchema = z.object({
  id: z.string(),
});

export const cycleSecurityRuleEffectInputSchema = z.object({
  id: z.string(),
});

export type SecurityRuleListItem = {
  id: string;
  name: string;
  description: string;
  condDisplay: string | null;
  cond: string;
  enabled: boolean;
  locked: boolean;
  priority: number;
  kinds: string[];
  titleLike: string | null;
  titleMatch: TitleMatch;
  vmId: string | null;
  effect: RuleEffect;
  createdAt: string;
  updatedAt: string;
};
