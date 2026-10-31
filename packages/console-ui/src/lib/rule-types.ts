/** The kinds of rule on Security rules, and the tones and effects their rows show. */

export const RULE_TYPES = ["messages", "email", "websites", "apps", "auto"] as const;
export type RuleType = (typeof RULE_TYPES)[number];

export const RULE_TYPE_LABELS: Record<RuleType, string> = {
  messages: "Messages",
  email: "Email",
  websites: "Websites",
  apps: "Integrations",
  auto: "Auto approve",
};

/** The colour of an action chip, from the console's allow / ask / block tones. */
export type RuleTone = "allow" | "ask" | "block" | "neutral";

/** What an Auto approve rule does to a permission request. */
export const RULE_EFFECTS = ["allow", "ask", "block"] as const;
export type RuleEffect = (typeof RULE_EFFECTS)[number];
