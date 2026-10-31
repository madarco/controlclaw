import { z } from "zod";
import { CONTENT_CHANNELS, contentChange, contentRule } from "@controlclaw/console-ui/lib/agent/content-rules-schema";

export {
  CONTENT_CHANNELS,
  CONTENT_POLICY_MAX,
  CONTENT_DETECTORS,
  contentChange,
  contentRule,
  contentRulesSnapshot,
  type ContentChange,
  type ContentChannel,
  type ContentRule,
  type ContentRulesSnapshot,
} from "@controlclaw/console-ui/lib/agent/content-rules-schema";

export const contentChangeInput = z.object({ change: contentChange });
export const contentChangeId = z.object({ changeId: z.string().min(1).max(100) });
export const contentConfirm = contentChangeId.extend({ code: z.string().regex(/^\d{6}$/) });

/** "Try a message": the firewall runs it against the rules, and the rule being edited if any. */
export const contentTryInput = z.object({
  text: z.string().trim().min(1).max(20_000),
  direction: z.enum(["in", "out"]),
  channel: z.enum(CONTENT_CHANNELS),
  draft: contentRule.optional(),
});
export type ContentTryInput = z.infer<typeof contentTryInput>;

const triedRule = z.object({ id: z.string(), name: z.string(), action: z.enum(["block", "hold", "log"]), by: z.enum(["found", "failed"]).optional() });

/** What the firewall answers to `rules.try`: never the message. */
export const contentTryResult = z.object({
  rule: triedRule.nullable(),
  hits: z.array(triedRule),
  /** The policies the AI was asked about. */
  asked: z.array(z.string()),
  probabilities: z.record(z.string(), z.number()).optional(),
  /** Why the AI could not answer (`off`, `cap`, `error`): the policies then act. */
  failed: z.string().optional(),
});
export type ContentTryResult = z.infer<typeof contentTryResult>;
