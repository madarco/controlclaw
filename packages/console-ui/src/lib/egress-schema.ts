import { z } from "zod";
import { exitCountrySchema } from "./exit-schema";

export const egressEffectSchema = z.enum(["allow", "block", "require_permission", "tunnel"]);
export type EgressEffect = z.infer<typeof egressEffectSchema>;

/**
 * Where this rule's traffic leaves from (apps/saas/docs/features/residential-exit.md). Residential
 * is a RELAY, not a route: the firewall cannot read what it carries, so a rule that says it gives
 * up inspection, the credential swap and AI review for that domain. Only offered on the effects
 * that already let traffic out.
 */
export const egressExitSchema = z.enum(["firewall", "residential"]);
export type EgressExit = z.infer<typeof egressExitSchema>;

export function residentialAllowed(effect: EgressEffect): boolean {
  return effect === "allow" || effect === "tunnel";
}

/**
 * Where this rule's residential traffic should come out. Null means "use the organisation's
 * default", which is itself allowed to mean "wherever the provider puts us".
 *
 * No confirmation code, deliberately. The code is for changes that would let the control plane
 * weaken what the firewall guarantees — a credential, the templates deciding which field it is
 * rendered into, where the exit points. A country moves none of those: the flow is already
 * relayed, already uninspected, and already leaving through an exit a code approved, so which
 * country it surfaces in is policy like the domain beside it. See `docs/security-design.md`,
 * "What bounds a residential rule". The org default is consent-coded only because it rides the
 * same `exit.propose` settings command as the account's own settings.
 */
export const ruleExitCountrySchema = exitCountrySchema.nullish();

// The quick click-cycle deliberately EXCLUDES `tunnel` (an uninspected-egress hole): it must be
// chosen explicitly via the effect select + warning, never reached by accidental cycling.
export const NEXT_EGRESS_EFFECT: Record<"allow" | "block" | "require_permission", EgressEffect> = {
  allow: "require_permission",
  require_permission: "block",
  block: "allow",
};

const httpMethod = z
  .enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
  .nullish();

const matchPort = z.number().int().min(1).max(65535).nullish();

export const createEgressRuleInputSchema = z.object({
  name: z.string().min(1).max(120),
  matchDomain: z.string().min(1).max(253),
  matchPath: z.string().max(512).nullish(),
  matchMethod: httpMethod,
  matchPort,
  effect: egressEffectSchema.default("allow"),
  exit: egressExitSchema.default("firewall"),
  exitCountry: ruleExitCountrySchema,
  priority: z.number().int().min(0).max(1_000_000).default(1000),
  enabled: z.boolean().default(true),
  vmId: z.string().nullish(),
  aiReview: z.boolean().default(false),
  aiPolicy: z.string().trim().max(1000).nullish(),
});

export const updateEgressRuleInputSchema = z.object({
  id: z.string(),
  name: z.string().min(1).max(120).optional(),
  matchDomain: z.string().min(1).max(253).optional(),
  matchPath: z.string().max(512).nullish(),
  matchMethod: httpMethod,
  matchPort,
  effect: egressEffectSchema.optional(),
  exit: egressExitSchema.optional(),
  exitCountry: ruleExitCountrySchema,
  priority: z.number().int().min(0).max(1_000_000).optional(),
  enabled: z.boolean().optional(),
  vmId: z.string().nullish(),
  aiReview: z.boolean().optional(),
  aiPolicy: z.string().trim().max(1000).nullish(),
});

/** AI review is only for rules that let traffic out: never on block or tunnel. */
export function aiReviewAllowed(effect: EgressEffect): boolean {
  return effect === "allow" || effect === "require_permission";
}

export const deleteEgressRuleInputSchema = z.object({ id: z.string() });
export const cycleEgressRuleEffectInputSchema = z.object({ id: z.string() });

export interface EgressRuleListItem {
  id: string;
  name: string;
  matchDomain: string;
  matchPath: string | null;
  matchMethod: string | null;
  matchPort: number | null;
  effect: EgressEffect;
  exit: EgressExit;
  /** Null: the org default on the Exit card. Only read while `exit` is `residential`. */
  exitCountry: string | null;
  priority: number;
  enabled: boolean;
  vmId: string | null;
  aiReview: boolean;
  aiPolicy: string | null;
  createdAt: string;
  updatedAt: string;
  /**
   * Set on a rule ControlClaw added by itself for a model provider or a channel (its key,
   * `managed-egress.ts`): read-only, and gone when the provider or the channel is.
   */
  managed?: string | null;
}

/**
 * A box a site rule can be scoped to, as the Internet access page offers it: every agent, and the
 * brain when the organisation has one. `name` is what a person calls it, not the hostname.
 */
export interface EgressBoxOption {
  id: string;
  name: string;
  kind: "agent" | "brain";
}
