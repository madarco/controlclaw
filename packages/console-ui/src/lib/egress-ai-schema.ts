import { z } from "zod";
import type { LlmProvider } from "./llm-states";

/**
 * The firewall's AI review settings (docs/features/ai-firewall-review.md): which of the org's
 * model credentials the firewall uses, which model, and its limits.
 */

/** Providers the review can use: the ones AI SDK's `experimental_evaluate` supports. */
export const AI_REVIEW_PROVIDERS = ["vercel_gateway", "controlclaw_included", "google", "anthropic", "openai"] as const satisfies readonly LlmProvider[];
export type AiReviewProvider = (typeof AI_REVIEW_PROVIDERS)[number];

export function isAiReviewProvider(p: string): p is AiReviewProvider {
  return (AI_REVIEW_PROVIDERS as readonly string[]).includes(p);
}

/**
 * Providers the review may be switched on against **by itself** (`ensureAiReviewDefault`): the two
 * that reach the AI Gateway, where the default model is Jev and a day of review costs very little.
 * A key the organisation bought for its agents is never volunteered — it is theirs to spend.
 */
export const AI_REVIEW_DEFAULT_PROVIDERS = ["vercel_gateway", "controlclaw_included"] as const satisfies readonly AiReviewProvider[];

/** A small, fast default per provider. The model id is free text; these are suggestions. */
export const DEFAULT_AI_REVIEW_MODEL: Record<AiReviewProvider, string> = {
  vercel_gateway: "typesafe-ai/jev",
  controlclaw_included: "typesafe-ai/jev",
  google: "gemini-3-flash-preview",
  anthropic: "claude-haiku-4-5",
  openai: "gpt-5.4-mini",
};

/** Mirrored in packages/mitm-agent `INSTRUCTIONS_MAX`; the firewall clips to it too. */
export const AI_INSTRUCTIONS_MAX = 2000;

/** The owner's text for the AI: trimmed; empty means none (null). */
const instructions = z
  .string()
  .max(AI_INSTRUCTIONS_MAX, `At most ${AI_INSTRUCTIONS_MAX} characters.`)
  .nullable()
  .transform((v) => v?.trim() || null);

/** Who is emailed about AI Log Review findings (docs/plans/ai-log-review-split.md). */
export const LOG_REVIEW_NOTIFY = ["admins", "members", "nobody"] as const;
export type LogReviewNotify = (typeof LOG_REVIEW_NOTIFY)[number];
/**
 * A finding's severity, also Notify from (the lowest severity that is emailed). Low findings are
 * never emailed: `low` is still accepted as Notify from, for older MCP clients, and saved as medium.
 */
export const LOG_REVIEW_SEVERITIES = ["low", "medium", "high"] as const;
export type LogReviewSeverity = (typeof LOG_REVIEW_SEVERITIES)[number];

export const updateEgressAiSettingsInputSchema = z.object({
  /** The AI Firewall: the per-request check, AI approval, and the Messages rules' AI. */
  enabled: z.boolean(),
  /**
   * AI Log Review: the review every minute and the scan. This field and the three after it are
   * optional so an MCP client from before the split keeps working: left out, they keep their saved
   * value.
   */
  logReviewEnabled: z.boolean().optional(),
  logReviewNotify: z.enum(LOG_REVIEW_NOTIFY).optional(),
  /** The people `members` emails (ids from `members` in the view); ignored otherwise. */
  logReviewNotifyUserIds: z.array(z.string().min(1).max(100)).max(100).optional(),
  logReviewNotifyMinSeverity: z.enum(LOG_REVIEW_SEVERITIES).optional(),
  credentialId: z.string().min(1).nullable(),
  model: z.string().trim().min(1).max(100),
  dailyCallCap: z.number().int().min(100).max(100_000),
  scanIntervalHours: z.number().int().min(1).max(168),
  autoApprovePerHour: z.number().int().min(0).max(1000),
  /** Left out: unchanged. */
  requestInstructions: instructions.optional(),
  reviewInstructions: instructions.optional(),
});
export type UpdateEgressAiSettingsInput = z.infer<typeof updateEgressAiSettingsInputSchema>;

/** Just the owner's instructions, for a caller (WebMCP) that should not resend every setting. */
export const updateEgressAiInstructionsInputSchema = z
  .object({
    requestInstructions: instructions.optional(),
    reviewInstructions: instructions.optional(),
  })
  .refine((v) => v.requestInstructions !== undefined || v.reviewInstructions !== undefined, { message: "Give requestInstructions, reviewInstructions or both." });
export type UpdateEgressAiInstructionsInput = z.infer<typeof updateEgressAiInstructionsInputSchema>;

export const openAiReviewHistoryInputSchema = z.object({
  vmId: z.string().min(1),
  /** A run to open straight away: a finding's id. */
  runId: z.string().regex(/^[A-Za-z0-9_-]{8,80}$/).optional(),
});

export type EgressAiCredentialOption = {
  id: string;
  provider: AiReviewProvider;
  name: string;
  hint: string | null;
  defaultModel: string;
};

export type EgressAiView = {
  canManage: boolean;
  settings: {
    enabled: boolean;
    logReviewEnabled: boolean;
    logReviewNotify: LogReviewNotify;
    logReviewNotifyUserIds: string[];
    logReviewNotifyMinSeverity: LogReviewSeverity;
    credentialId: string | null;
    model: string;
    dailyCallCap: number;
    scanIntervalHours: number;
    autoApprovePerHour: number;
    requestInstructions: string | null;
    reviewInstructions: string | null;
  };
  /**
   * The fixed questions the firewall asks, as the model reads them (without any owner text), for
   * the card's "What the AI is asked". Built from the firewall's own code.
   */
  questions: { request: string; review: string };
  /** The org's agents behind this firewall, for the review history's agent picker. */
  agents: Array<{ id: string; name: string }>;
  /** The org's people, for the Notify picker: owners and admins can pick any of them. */
  members: Array<{ userId: string; name: string; email: string; role: string }>;
  /**
   * The firewall runs the two halves apart (`ai_log_review`). False on an older firewall, which runs
   * the review whenever the AI Firewall is on, and not otherwise.
   */
  splitSupported: boolean;
  /** The firewall serves the review history (`ai_review_history`). */
  historyAvailable: boolean;
  /** The org's active credentials the review can use. */
  credentials: EgressAiCredentialOption[];
  /** Whether the org has a firewall box to run the review on. */
  hasFirewall: boolean;
  lastScan: { status: string; message: string | null; at: string } | null;
  /**
   * The firewall's own panel: no people to email (Notify is not shown), no review history page, and
   * no included AI, only the owner's own keys.
   */
  local?: boolean;
};
