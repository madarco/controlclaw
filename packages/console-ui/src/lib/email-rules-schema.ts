import { z } from "zod";
import { emailChange, emailRules } from "@controlclaw/console-ui/lib/agent/email-rules-schema";

export {
  emailChange,
  emailRules,
  ruleEntry,
  LIMITS,
  MAX_RECIPIENTS,
  DEFAULT_RULES,
  type EmailChange,
  type EmailRules,
  type RuleEntry,
  type OutboundMode,
  type RequireAuth,
} from "@controlclaw/console-ui/lib/agent/email-rules-schema";

/** What the firewall answers to `email.read`: its rules and what it held back this week. */
export const emailRulesSnapshot = z.object({
  rules: emailRules,
  held: z.array(
    z.object({ mailbox: z.string(), reason: z.string(), domain: z.string().nullable(), count: z.number().int() }),
  ),
});
export type EmailRulesSnapshot = z.infer<typeof emailRulesSnapshot>;

/** A mailbox the rules can be narrowed to, as the console lists it. */
export type EmailMailbox = { ref: string; label: string; provider: "agentmail" | "gmail" };

export const emailChangeInput = z.object({ change: emailChange });
export const emailChangeId = z.object({ changeId: z.string().min(1).max(100) });
export const emailConfirm = emailChangeId.extend({ code: z.string().regex(/^\d{6}$/) });

/** One agent's own mailbox: how it may send. Only ever stricter than the organization's mode. */
export const setAgentOutboundInput = z.object({ vmId: z.string().min(1), mode: z.enum(["listed", "ask", "block"]) });
