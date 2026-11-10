import { CONTENT_CHANNELS, type ContentChannel, type ContentRule } from "@controlclaw/console-ui/lib/agent/content-rules-schema";
import { isBrainManagedRule } from "./brain-rules";
import type { EgressBoxOption, EgressRuleListItem } from "./egress-schema";
import type { EmailMailbox, RuleEntry } from "./email-rules-schema";
import { ACTION_LABELS, CHANNEL_LABELS, DETECTOR_LABELS, DIRECTION_LABELS } from "./content-rules-words";
import type { SecurityRuleListItem } from "./security-schema";
import { describeMatch, isMcpService, type AppOption, type AppRule } from "./app-rules-schema";
import { RULE_TYPES, RULE_TYPE_LABELS, type RuleTone, type RuleType } from "@controlclaw/console-ui/lib/rule-types";

/**
 * The one list on Security rules (docs/plans/unified-security-rules.md): the rules of five kinds,
 * each kept where it always was (content, email and apps rules on the firewall, site rules and
 * Auto approve rules in the database), turned into rows that read the same. No client or server
 * imports, so the page and the tests share it.
 */

export { RULE_TYPES, RULE_TYPE_LABELS, type RuleTone, type RuleType };

/** Which change needs a code: every one (Messages), only adding (Email), only loosening (Apps), none (the other two). */
export type RuleCode = "every" | "adding" | "loosening" | null;

interface RowBase {
  key: string;
  name: string;
  /** What it matches, one line. */
  match: string;
  /** A second line: a Messages rule's sentence, a site rule's note for the AI. */
  detail: string | null;
  scope: string;
  action: { label: string; tone: RuleTone };
  /** Checked by the AI: a Messages rule with a sentence, a site rule with AI review. */
  ai: boolean;
  /** "Acted on 3 messages in 7 days"; null where the type has no count. */
  count: string | null;
  /** Null when the type has no on/off (an email entry is listed or removed). */
  enabled: boolean | null;
  code: RuleCode;
}

export type RuleRow =
  | (RowBase & { type: "messages"; rule: ContentRule })
  | (RowBase & { type: "email"; list: "senders" | "recipients"; entry: RuleEntry })
  | (RowBase & {
      type: "websites";
      rule: EgressRuleListItem;
      /** Kept by ControlClaw: the brain's own, or added for a provider or a channel. */
      managed: boolean;
      /** One of the brain's own: listed only under the brain. */
      brain: boolean;
    })
  | (RowBase & { type: "apps"; rule: AppRule; app: AppOption | null })
  | (RowBase & { type: "auto"; rule: SecurityRuleListItem });

function channelsLine(channels: readonly string[]): string {
  if (CONTENT_CHANNELS.every((c) => channels.includes(c))) return "All channels";
  return channels.map((c) => CHANNEL_LABELS[c as ContentChannel] ?? c).join(", ");
}

/** The channels in a table cell: "All channels", two names, or two names and "+3". */
export function channelsShort(channels: readonly string[]): string {
  if (CONTENT_CHANNELS.every((c) => channels.includes(c))) return "All channels";
  const names = channels.map((c) => CHANNEL_LABELS[c as ContentChannel] ?? c);
  return names.length <= 2 ? names.join(", ") : `${names.slice(0, 2).join(", ")} +${names.length - 2}`;
}

export function contentHitsLine(n: number): string {
  return n === 0 ? "Not acted on in 7 days" : `Acted on ${n} ${n === 1 ? "message" : "messages"} in 7 days`;
}

export function autoHitsLine(n: number): string {
  // An Ask rule only hands the request to a person, so "matched" rather than "decided".
  return n === 0 ? "No requests in 7 days" : `Matched ${n} ${n === 1 ? "request" : "requests"} in 7 days`;
}

const CONTENT_TONE: Record<ContentRule["action"], RuleTone> = { block: "block", hold: "ask", log: "neutral" };

/** A Messages rule's detectors and words, one line: "Also: Card numbers, “salary”" after a sentence. */
export function messagesExtras(rule: ContentRule): string {
  const extras = [...rule.detectors.map((d) => DETECTOR_LABELS[d]), ...rule.patterns.slice(0, 4).map((p) => `“${p}”`)];
  const more = rule.patterns.length > 4 ? ` and ${rule.patterns.length - 4} more` : "";
  return extras.length ? `${rule.policy ? "Also: " : ""}${extras.join(", ")}${more}` : "";
}

export function messagesRow(rule: ContentRule, counts: Record<string, number> | null): RuleRow {
  const also = messagesExtras(rule);
  return {
    type: "messages",
    rule,
    key: `messages:${rule.id}`,
    name: rule.name,
    match: [`${DIRECTION_LABELS[rule.direction]} · ${channelsLine(rule.channels)}`, rule.policy ? also : ""].filter(Boolean).join(" · "),
    detail: rule.policy ?? (also || null),
    scope: "All agents",
    action: { label: ACTION_LABELS[rule.action], tone: CONTENT_TONE[rule.action] },
    ai: !!rule.policy,
    count: counts ? contentHitsLine(counts[rule.id] ?? 0) : null,
    enabled: rule.enabled,
    code: "every",
  };
}

export function mailboxLabel(mailboxes: EmailMailbox[], ref: string | null): string {
  if (!ref) return "All mailboxes";
  return mailboxes.find((m) => m.ref === ref)?.label ?? ref.replace(/^[a-z]+:/, "");
}

export function emailRow(list: "senders" | "recipients", entry: RuleEntry, mailboxes: EmailMailbox[]): RuleRow {
  return {
    type: "email",
    list,
    entry,
    key: `email:${list}:${entry.value}|${entry.mailbox ?? ""}`,
    name: entry.value,
    match: list === "senders" ? "Can email your agents" : "Your agents can email them without asking",
    detail: null,
    scope: mailboxLabel(mailboxes, entry.mailbox),
    action: { label: "Allowed", tone: "allow" },
    ai: false,
    count: null,
    enabled: null,
    code: "adding",
  };
}

const EGRESS_ACTION: Record<EgressRuleListItem["effect"], { label: string; tone: RuleTone }> = {
  allow: { label: "Allow", tone: "allow" },
  require_permission: { label: "Ask", tone: "ask" },
  block: { label: "Block", tone: "block" },
  tunnel: { label: "Not inspected", tone: "neutral" },
};

function boxLabel(vmId: string | null, boxes: EgressBoxOption[]): string {
  if (!vmId) return "All agents";
  return boxes.find((b) => b.id === vmId)?.name ?? "One agent";
}

export function websitesRow(rule: EgressRuleListItem, boxes: EgressBoxOption[], brainIds: ReadonlySet<string>): RuleRow {
  const match = [rule.matchMethod ? `${rule.matchMethod} ` : "", rule.matchDomain, rule.matchPort != null ? `:${rule.matchPort}` : "", rule.matchPath ?? ""].join("");
  const via = rule.exit === "residential" ? "via home internet, not inspected" : rule.effect === "tunnel" ? "not inspected" : "";
  return {
    type: "websites",
    rule,
    managed: !!rule.managed || isBrainManagedRule(rule, brainIds),
    brain: isBrainManagedRule(rule, brainIds),
    key: `websites:${rule.id}`,
    name: rule.name,
    match: [match, via, `order ${rule.priority}`].filter(Boolean).join(" · "),
    detail: rule.aiReview && rule.aiPolicy ? `${rule.effect === "require_permission" ? "The AI may approve" : "What the AI looks for"}: ${rule.aiPolicy}` : null,
    scope: boxLabel(rule.vmId, boxes),
    action: EGRESS_ACTION[rule.effect],
    ai: rule.aiReview,
    count: null,
    enabled: rule.enabled,
    code: null,
  };
}

const APP_ACTION: Record<AppRule["then"], { label: string; tone: RuleTone }> = {
  allow: { label: "Allow", tone: "allow" },
  ask: { label: "Ask", tone: "ask" },
  block: { label: "Block", tone: "block" },
};

/** "All agents", the one agent's name, or "3 agents". */
function agentsLabel(agents: string[], boxes: EgressBoxOption[]): string {
  if (agents.length === 0) return "All agents";
  if (agents.length === 1) return boxes.find((b) => b.id === agents[0])?.name ?? "One agent";
  return `${agents.length} agents`;
}

export function appsRow(rule: AppRule, boxes: EgressBoxOption[], apps: AppOption[]): RuleRow {
  const app = rule.service ? (apps.find((a) => a.service === rule.service) ?? null) : null;
  const connection = rule.connectionId ? (app?.connections.find((c) => c.id === rule.connectionId)?.label ?? "one connection") : null;
  return {
    type: "apps",
    rule,
    app,
    key: `apps:${rule.id}`,
    name: rule.name,
    match: describeMatch(rule, app?.name ?? (isMcpService(rule.service) ? undefined : (rule.service ?? undefined))),
    detail: [connection ? `Connection: ${connection}` : null, rule.sentence ? `When the call fits: ${rule.sentence}` : null].filter(Boolean).join(" · ") || null,
    scope: agentsLabel(rule.agents, boxes),
    action: APP_ACTION[rule.then],
    ai: false,
    count: null,
    enabled: rule.enabled,
    code: "loosening",
  };
}

const AUTO_TONE: Record<SecurityRuleListItem["effect"], RuleTone> = { allow: "allow", ask: "ask", block: "block" };
const AUTO_LABEL: Record<SecurityRuleListItem["effect"], string> = { allow: "Allow", ask: "Ask", block: "Block" };

export function autoRow(rule: SecurityRuleListItem, boxes: EgressBoxOption[], counts: Record<string, number> | null): RuleRow {
  return {
    type: "auto",
    rule,
    key: `auto:${rule.id}`,
    name: rule.name,
    match: rule.cond || "Every request",
    detail: rule.description || null,
    scope: boxLabel(rule.vmId, boxes),
    action: { label: AUTO_LABEL[rule.effect], tone: AUTO_TONE[rule.effect] },
    ai: false,
    count: counts ? autoHitsLine(counts[rule.name] ?? 0) : null,
    enabled: rule.enabled,
    code: null,
  };
}

export interface RuleSources {
  /** Null while the firewall has not answered (or could not). */
  content: ContentRule[] | null;
  contentCounts: Record<string, number> | null;
  email: { senders: RuleEntry[]; recipients: RuleEntry[] } | null;
  mailboxes: EmailMailbox[];
  websites: EgressRuleListItem[];
  /** Null while the firewall has not answered (or could not). */
  apps?: AppRule[] | null;
  appOptions?: AppOption[];
  auto: SecurityRuleListItem[];
  autoCounts: Record<string, number> | null;
  boxes: EgressBoxOption[];
}

/**
 * Every row, in the page's order: Messages, Email, Websites, Apps, Auto approve, each in its own
 * order (site, app and Auto approve rules are read first match first, so that order is the one shown).
 */
export function buildRows(s: RuleSources): RuleRow[] {
  const brainIds = new Set(s.boxes.filter((b) => b.kind === "brain").map((b) => b.id));
  return [
    ...(s.content ?? []).map((r) => messagesRow(r, s.contentCounts)),
    ...(s.email?.senders ?? []).map((e) => emailRow("senders", e, s.mailboxes)),
    ...(s.email?.recipients ?? []).map((e) => emailRow("recipients", e, s.mailboxes)),
    ...s.websites.map((r) => websitesRow(r, s.boxes, brainIds)),
    ...(s.apps ?? []).map((r) => appsRow(r, s.boxes, s.appOptions ?? [])),
    ...s.auto.map((r) => autoRow(r, s.boxes, s.autoCounts)),
  ];
}

export interface RuleFilter {
  type: RuleType | null;
  /** A box id, or null for every agent. */
  box: string | null;
  /** Whether that box is the brain. */
  brain?: boolean;
}

/**
 * The rows that apply to one box: its own rules and the rules for all of them, as the firewall
 * reads them. Messages and Email rules have no agent (content rules apply to all, email rules are
 * per mailbox), so they stay under every agent. The brain sends no messages and asks for nothing:
 * only site rules apply to it, its managed ones included. Unfiltered, the brain's own rules are
 * left out, as on Internet access; the ones added for providers and channels stay.
 */
export function filterRows(rows: RuleRow[], f: RuleFilter): RuleRow[] {
  return rows.filter((r) => {
    if (f.type && r.type !== f.type) return false;
    if (!f.box) return !(r.type === "websites" && r.brain);
    if (f.brain && r.type !== "websites") return false;
    if (r.type === "websites" || r.type === "auto") return r.rule.vmId === null || r.rule.vmId === f.box;
    if (r.type === "apps") return r.rule.agents.length === 0 || r.rule.agents.includes(f.box);
    return true;
  });
}

/** How many rows each type has under the agent filter, for the type chips. */
export function typeCounts(rows: RuleRow[], f: Omit<RuleFilter, "type">): Record<RuleType, number> {
  const c: Record<RuleType, number> = { messages: 0, email: 0, websites: 0, apps: 0, auto: 0 };
  for (const r of filterRows(rows, { ...f, type: null })) c[r.type] += 1;
  return c;
}

/**
 * The tabs' counts. The agent filter is only on Websites, Apps and Auto approve, and the brain is only
 * a choice on Websites: under it, Auto approve counts every agent's rules, as its tab shows them.
 */
export function tabCounts(rows: RuleRow[], f: Omit<RuleFilter, "type">): Record<RuleType, number> {
  const c = typeCounts(rows, f.brain ? { box: null } : f);
  if (f.brain) c.websites = filterRows(rows, { ...f, type: "websites" }).length;
  return c;
}

export function isRuleType(v: string | null): v is RuleType {
  return !!v && (RULE_TYPES as readonly string[]).includes(v);
}

/**
 * The page's tabs: one per rule type, then Settings, which holds the AI Firewall and AI Log Review
 * (org-wide, used by every type's AI checks). Settings has no rows, so no count and no agent filter.
 */
export const SECURITY_TABS = [...RULE_TYPES, "settings"] as const;
export type SecurityTab = (typeof SECURITY_TABS)[number];

export const SECURITY_TAB_LABELS: Record<SecurityTab, string> = { ...RULE_TYPE_LABELS, settings: "Settings" };

export function isSecurityTab(v: string | null): v is SecurityTab {
  return !!v && (SECURITY_TABS as readonly string[]).includes(v);
}
