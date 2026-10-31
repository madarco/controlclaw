import { CONTENT_CHANNELS, type ContentChannel, type ContentRule } from "@controlclaw/console-ui/lib/agent/content-rules-schema";

/**
 * The words the console uses for content rules (docs/features/content-rules.md): the Security
 * rules section, its templates and test box, and the Activity rows. No server-only imports, so
 * client components take it as it is.
 */

export const CHANNEL_LABELS: Record<ContentChannel, string> = {
  telegram: "Telegram",
  slack: "Slack",
  email: "Email",
  web: "Website requests",
  webhook: "Webhooks",
  teamchat: "Team chat",
  voice: "Meetings and calls",
  apps: "Integration actions",
};

export const DIRECTION_LABELS = {
  in: "Messages to your agents",
  out: "Messages from your agents",
  both: "Both",
} as const;

export const ACTION_LABELS = {
  block: "Stop",
  hold: "Hold for approval",
  log: "Only record",
} as const;

export const DETECTOR_LABELS = {
  secrets: "Passwords, keys and tokens",
  iban: "Bank account numbers (IBAN)",
  card: "Card numbers",
  emails: "More than five email addresses",
} as const;

/**
 * One Activity row's line: "Content rule salary: stopped by the AI, Telegram, from the agent".
 * Metadata only.
 */
export function contentActivityLine(r: { rule: string; channel: string; direction: "in" | "out"; action: string; ai?: "found" | "failed" | null }): string {
  const what = { block: "stopped", hold: "held", log: "recorded", released: "sent on approval", dropped: "not sent" }[r.action] ?? r.action;
  const by = r.ai === "found" ? " by the AI" : r.ai === "failed" ? " (the AI check could not run)" : "";
  const channel = CHANNEL_LABELS[r.channel as ContentChannel] ?? r.channel;
  return `Content rule ${r.rule}: ${what}${by}, ${channel}, ${r.direction === "in" ? "to the agent" : "from the agent"}`;
}

/**
 * Every channel a message from an agent can leave by, but websites: an agent's browser sends many
 * requests, each one a call to the AI, so a template leaves them out and the owner adds them.
 */
const OUT_CHANNELS: ContentChannel[] = ["telegram", "slack", "email", "teamchat", "voice"];

/**
 * What "Add a rule" starts from (docs/plans/firewall-content-rules.md §5.4). A rule is a sentence
 * first, judged by the AI on the firewall; words and detectors are extras ("Also match exactly").
 * Each fills the editor; the person reads it and saves it with a code. Leaking secrets is the core
 * rule, not a template. A new rule only records until the person picks another action (§3.3).
 */
export const CONTENT_TEMPLATES: ReadonlyArray<{ key: string; label: string; help: string; rule: Omit<ContentRule, "id" | "enabled"> }> = [
  {
    key: "salary",
    label: "Salaries and pay",
    help: "Questions about pay, and answers that give it away, either way, meetings included.",
    // Not websites (as for OUT_CHANNELS).
    rule: { name: "Salaries and pay", policy: "Don't ask about or share anyone's salary, pay or bonus.", direction: "both", channels: CONTENT_CHANNELS.filter((c) => c !== "web"), patterns: [], detectors: [], action: "log", reason: "Pay is not discussed through the agents." },
  },
  {
    key: "customer",
    label: "Customer data",
    help: "Customer lists and customers' contact details leaving the company.",
    rule: { name: "Customer data", policy: "No customer lists or customers' contact details leave the company.", direction: "out", channels: OUT_CHANNELS, patterns: [], detectors: [], action: "log", reason: "Customer data stays inside the company." },
  },
  {
    key: "bank",
    label: "Bank and card numbers",
    help: "Bank account and card details, and IBANs and card numbers that pass their check digits.",
    rule: { name: "Bank and card numbers", policy: "Don't share bank account or payment card details.", direction: "out", channels: OUT_CHANNELS, patterns: [], detectors: ["iban", "card"], action: "log", reason: "Bank and card numbers are not sent from here." },
  },
  {
    key: "bulk",
    label: "Personal data in bulk",
    help: "Lists of people with their contact details, and messages with more than five email addresses.",
    rule: { name: "Personal data in bulk", policy: "Don't send lists of people with their email addresses, phone numbers or home addresses.", direction: "out", channels: OUT_CHANNELS, patterns: [], detectors: ["emails"], action: "log", reason: "Lists of people's details are not sent from here." },
  },
  {
    key: "own",
    label: "Your own rule",
    help: "Start empty: the rule in one sentence, the channels and what happens.",
    rule: { name: "", policy: "", direction: "out", channels: OUT_CHANNELS, patterns: [], detectors: [], action: "log", reason: "" },
  },
];

/** A new rule's id, from its name: `customer-data-x7k2`. */
export function contentRuleId(name: string, random: () => number = Math.random): string {
  const slug = name.toLowerCase().normalize("NFKD").replace(/\p{M}+/gu, "").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "rule";
  const tail = Math.floor(random() * 36 ** 4).toString(36).padStart(4, "0");
  return `${/^[a-z0-9]/.test(slug) ? slug : "r"}-${tail}`;
}
