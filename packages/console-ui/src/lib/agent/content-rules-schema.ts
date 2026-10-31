import { z } from "zod";

/**
 * The shape of a content rule and of a change to one (docs/plans/firewall-content-rules.md), shared
 * by the firewall (`content-rules.ts`) and the console, which imports this file so both refuse the
 * same things. Only zod: the console's bundle takes it as it is.
 */

/** Channels a rule can name today; a rule for a channel with no adapter would do nothing, so it is refused. */
export const CONTENT_CHANNELS = ["telegram", "slack", "email", "web", "webhook", "teamchat", "voice", "apps"] as const;
export type ContentChannel = (typeof CONTENT_CHANNELS)[number];
/** Channels a message only comes in on (webhooks) or only goes out on (the web). */
export const CONTENT_IN_ONLY: readonly ContentChannel[] = ["webhook"];
export const CONTENT_OUT_ONLY: readonly ContentChannel[] = ["web"];
export const CONTENT_DETECTORS = ["secrets", "iban", "card", "emails"] as const;
export const CONTENT_POLICY_MAX = 300;
export const CONTENT_RULES_MAX = 50;

/**
 * Text a person typed, kept to one plain line: no control or format characters (the ones that turn
 * text around, zero-width ones), no line or paragraph separators, nothing private-use or unassigned,
 * and no runs of spaces. A reason reaches the agent and the people in the chat, so it must read as
 * it was written.
 */
const PLAIN_LINE = /^(?! )(?!.* {2})(?!.* $)[^\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}]+$/u;
const oneLine = (max: number) => z.string().min(1).max(max).regex(PLAIN_LINE, "must be one plain line");
const ruleId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);

export const contentRule = z
  .object({
    id: ruleId,
    name: oneLine(80),
    direction: z.enum(["in", "out", "both"]),
    channels: z.array(z.enum(CONTENT_CHANNELS)).min(1).max(CONTENT_CHANNELS.length).refine((c) => new Set(c).size === c.length, "a channel is listed twice"),
    patterns: z.array(oneLine(100)).max(50),
    detectors: z.array(z.enum(CONTENT_DETECTORS)).max(CONTENT_DETECTORS.length),
    /**
     * The rule as one sentence ("Don't share salaries or pay details"), judged by the AI on the
     * firewall (docs/plans/firewall-content-rules.md §5.4). The question the model is asked.
     */
    policy: oneLine(CONTENT_POLICY_MAX).optional(),
    action: z.enum(["block", "hold", "log"]),
    reason: oneLine(200),
    enabled: z.boolean(),
  })
  .strict()
  .refine((r) => r.patterns.length + r.detectors.length > 0 || !!r.policy, "a rule needs a policy, a word or a detector")
  // Nothing holds a message coming in: the agent's next poll would have to hand it over later.
  .refine((r) => r.action !== "hold" || r.direction === "out", "only a message going out can be held")
  // A rule that could never fire is a mistake the person should see now, not a silent no-op.
  .refine((r) => r.channels.some((c) => (r.direction === "out" ? !CONTENT_IN_ONLY.includes(c) : r.direction === "in" ? !CONTENT_OUT_ONLY.includes(c) : true)), "these channels never carry messages in that direction");
export type ContentRule = z.infer<typeof contentRule>;

export const contentChange = z.discriminatedUnion("op", [
  z.object({ op: z.literal("put"), rule: contentRule }).strict(),
  z.object({ op: z.literal("delete"), id: ruleId }).strict(),
  // Accept the AI review's current model and key for the policies (the firewall reads which itself).
  z.object({ op: z.literal("ai") }).strict(),
]);
export type ContentChange = z.infer<typeof contentChange>;

/** What the firewall answers to `rules.read`. */
export const contentRulesSnapshot = z.object({
  rules: z.array(contentRule),
  /** The firewall could not open its store: the proxy refuses until a confirmed change reseals it. */
  unreadable: z.boolean().optional(),
  core: z.array(z.object({ id: z.string(), name: z.string(), direction: z.string(), action: z.string() })),
  held: z.number().int(),
  /**
   * The policies' AI: the model and key the rules accepted with a code, the AI review's current one,
   * whether that one may judge policies (Jev on the AI Gateway or the included tokens) and whether
   * it is the accepted one. Absent from a firewall before pinning.
   */
  ai: z
    .object({
      pinned: z.object({ provider: z.string(), model: z.string() }).nullable(),
      current: z.object({ provider: z.string(), model: z.string() }).nullable(),
      allowed: z.boolean(),
      matches: z.boolean(),
    })
    .optional(),
});
export type ContentRulesSnapshot = z.infer<typeof contentRulesSnapshot>;
