import type { ContentRule } from "@controlclaw/console-ui/lib/agent/content-rules-schema";
import { topRules, type RuleCounts, type RuleOutcome, type RuleOverviewItem, type RuleSort } from "./rule-metrics";
import { describeMatch, isMcpService, type AppRule } from "./app-rules-schema";
import { messagesRow } from "./security-rules-list";

/**
 * The Firewall page's "Most used rules" and "Security rules" (T-183, docs/features/firewall-overview.md):
 * the read's items with the parts only the firewall knows (what a Messages or Integrations rule does,
 * and whether an Integrations rule is for an app or an MCP server), and the totals the section shows.
 * No client or server imports, so the page, the demo and the tests share it.
 */

/** The section's tabs. Integrations rules are split: Apps (OpenConnector apps) and MCP tools (MCP servers). */
export const RULE_CATS = ["websites", "email", "apps", "mcp", "messages", "auto"] as const;
export type RuleCat = (typeof RULE_CATS)[number];

export const RULE_CAT_LABELS: Record<RuleCat, string> = {
  websites: "Websites",
  email: "Email",
  apps: "Apps",
  mcp: "MCP tools",
  messages: "Messages",
  auto: "Auto approve",
};

/** Always a tab; Messages and Auto approve only when they matched something. */
export const FIXED_CATS: readonly RuleCat[] = ["websites", "email", "apps", "mcp"];

export interface ShownRule extends RuleOverviewItem {
  cat: RuleCat;
  /** What the rule does, one line. */
  detail: string;
}

/** What the firewall holds, when it answered: Integrations and Messages rules; null while unknown. */
export interface FirewallRules {
  apps: readonly AppRule[] | null;
  content: { rules: readonly ContentRule[]; core: ReadonlyArray<{ id: string; name: string }> } | null;
}

/** `ruleMetrics.firewallRules`: nothing is asked of a firewall that is not running. */
export interface FirewallRulesView {
  running: boolean;
  apps: AppRule[] | null;
  content: { rules: ContentRule[]; core: Array<{ id: string; name: string }> } | null;
}

const APP_VERB: Record<AppRule["then"], string> = { allow: "Allows", ask: "Asks you before", block: "Blocks" };

/** What an Integrations rule does: "Blocks the tool delete_repo in the MCP server mcp.github.com". */
export function appDetail(rule: Pick<AppRule, "service" | "match" | "then">): string {
  return `${APP_VERB[rule.then]} ${describeMatch(rule)}`;
}

/** What a Messages rule does: its sentence, else its words and detectors, else where it looks. */
export function messagesDetail(rule: ContentRule): string {
  const row = messagesRow(rule, null);
  return row.detail ?? row.match;
}

const FALLBACK: Record<RuleCat, string> = {
  websites: "Checks the sites your agents reach",
  email: "Checks the mail your agents send and get",
  apps: "Checks calls to your integrations",
  mcp: "Checks calls to your MCP servers",
  messages: "Checks messages to and from your agents",
  auto: "Answers your agents' permission requests",
};

/**
 * The items with their tab and a description for every one. Once the firewall has answered, an
 * Integrations or Messages rule it no longer holds is deleted: there is nothing to open.
 */
export function enrichRules(items: readonly RuleOverviewItem[], fw: FirewallRules): ShownRule[] {
  const apps = new Map((fw.apps ?? []).map((r) => [r.id, r]));
  const content = new Map((fw.content?.rules ?? []).map((r) => [r.id, r]));
  const core = new Set((fw.content?.core ?? []).map((r) => r.id));
  return items.map((i) => {
    if (i.type === "apps") {
      const rule = i.ruleId ? apps.get(i.ruleId) : undefined;
      const cat: RuleCat = rule && isMcpService(rule.service) ? "mcp" : "apps";
      const gone = !!fw.apps && !!i.ruleId && !i.builtin && !rule;
      return { ...i, cat, deleted: i.deleted || gone, detail: i.detail ?? (rule ? appDetail(rule) : FALLBACK[cat]) };
    }
    if (i.type === "messages") {
      const rule = content.get(i.key);
      const detail = i.detail ?? (rule ? messagesDetail(rule) : core.has(i.key) ? "Always on, set by ControlClaw" : FALLBACK.messages);
      const gone = !!fw.content && !rule && !core.has(i.key);
      return { ...i, cat: "messages", deleted: i.deleted || gone, detail };
    }
    return { ...i, cat: i.type, detail: i.detail ?? FALLBACK[i.type] };
  });
}

/** Matches per tab. */
export function catTotals(rules: readonly ShownRule[]): Record<RuleCat, number> {
  const out = Object.fromEntries(RULE_CATS.map((c) => [c, 0])) as Record<RuleCat, number>;
  for (const r of rules) out[r.cat] += r.total;
  return out;
}

/**
 * The header's numbers: blocked, asked you (asked and held), allowed, and every match. Only rules:
 * the grey rows (Every other site, the Email rows) are what no rule decided, and stay out.
 */
export function outcomeTotals(rules: readonly ShownRule[]): { blocked: number; asked: number; allowed: number; total: number } {
  const t = { blocked: 0, asked: 0, allowed: 0, total: 0 };
  for (const r of rules) {
    if (r.builtin) continue;
    t.blocked += r.counts.blocked;
    t.asked += r.counts.asked + r.counts.held;
    t.allowed += r.counts.allowed;
    t.total += r.total;
  }
  return t;
}

/** The tabs shown: the four fixed ones, then Messages and Auto approve when they matched. */
export function shownCats(totals: Record<RuleCat, number>): RuleCat[] {
  return RULE_CATS.filter((c) => FIXED_CATS.includes(c) || totals[c] > 0);
}

/** The cards of a tab, the most active or the most recent. "Every other site" takes a place only on its own tab or when little else matched. */
export function sectionRules(rules: readonly ShownRule[], cat: RuleCat | "all", sort: RuleSort, limit = 3): ShownRule[] {
  return topRules(
    rules.filter((r) => cat === "all" || r.cat === cat),
    sort,
    limit,
    1,
  );
}

/** "Most used rules": the busiest over 24 hours, the grey rows at most two of them. */
export function mostUsed(rules: readonly ShownRule[], limit = 8): ShownRule[] {
  return topRules(rules, "active", limit, 2);
}

/** The sparkline's colour: the outcome it mostly had. */
export function mainOutcome(c: RuleCounts): "allow" | "ask" | "block" | "neutral" {
  const ask = c.asked + c.held;
  if (c.blocked > 0 && c.blocked >= c.allowed && c.blocked >= ask) return "block";
  if (ask > c.allowed) return "ask";
  if (c.allowed > 0) return "allow";
  return "neutral";
}

/** The pills: allowed, asked you, held, blocked, recorded, in that order, the ones that happened. */
export function outcomePills(c: RuleCounts): Array<{ outcome: RuleOutcome; n: number; label: string }> {
  const pills: Array<{ outcome: RuleOutcome; n: number; label: string }> = [
    { outcome: "allowed", n: c.allowed, label: "allowed" },
    { outcome: "asked", n: c.asked, label: "asked you" },
    { outcome: "held", n: c.held, label: "held" },
    { outcome: "blocked", n: c.blocked, label: "blocked" },
    { outcome: "recorded", n: c.recorded, label: "recorded" },
  ];
  return pills.filter((p) => p.n > 0);
}

/**
 * "All N rules": every rule Security rules lists. Null when a part is unknown (the firewall never
 * said how many Messages or Email rules it holds, or did not answer for Integrations).
 */
export function allRulesCount(shields: { siteRules: number; securityRules: number; messageRules: number | null; emailRules: number | null } | null, apps: readonly AppRule[] | null): number | null {
  if (!shields || shields.messageRules === null || shields.emailRules === null || apps === null) return null;
  return shields.siteRules + shields.securityRules + shields.messageRules + shields.emailRules + apps.filter((r) => r.enabled).length;
}
