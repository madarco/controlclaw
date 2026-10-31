import type { RuleType } from "./rule-types";

/**
 * Matches per Security rule (docs/plans/rule-metrics.md): which records count for which rule, and
 * how the Firewall page and Security rules show them. No client or server imports, so the ingest,
 * the read, the pages and the tests share it.
 */

export const RULE_OUTCOMES = ["allowed", "asked", "held", "blocked", "recorded"] as const;
export type RuleOutcome = (typeof RULE_OUTCOMES)[number];

export const RULE_METRIC_RANGES = ["24h", "7d", "30d"] as const;
export type RuleMetricRange = (typeof RULE_METRIC_RANGES)[number];
export const RANGE_HOURS: Record<RuleMetricRange, number> = { "24h": 24, "7d": 168, "30d": 720 };

/** The key of the grey "no rule matched" row of a type. */
export const DEFAULT_KEY = "default";
/** Email counts only what "Everyone else" did: mail held back coming in, and new recipients going out. */
export const EMAIL_IN = "in";
export const EMAIL_OUT = "out";
/** An Integrations record from a firewall too old to send the rule's id. */
export const NAME_KEY_PREFIX = "name:";

/** One match, before it is added to `rule_hourly`. */
export interface RuleHit {
  vmId: string | null;
  at: Date;
  type: RuleType;
  key: string;
  outcome: RuleOutcome;
  name?: string | null;
}

/** An `agent_activity` row as the ingest's `RETURNING` gives it back. */
export interface InsertedActivity {
  source: string;
  vmId: string | null;
  status: string;
  occurredAt: Date;
  detail: Record<string, unknown>;
  dedupeKey: string;
}

/**
 * Why the email rules refuse a send. Anything else on a refused send is the firewall failing (the
 * rules unreadable, a lookup that failed, a draft being sent): no rule decided it.
 */
export const EMAIL_RULE_REASONS: readonly string[] = ["not_allowed", "sending_off", "hourly_limit", "daily_limit", "no_recipients", "too_many_recipients"];

const STATUS_OUTCOME: Record<string, RuleOutcome> = { allowed: "allowed", asked: "asked", blocked: "blocked" };
const CONTENT_OUTCOME: Record<string, RuleOutcome> = { block: "blocked", hold: "held", log: "recorded" };

const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/**
 * The matches in the rows one ingest batch really inserted. `websiteIdOf` names the Websites rule a
 * record from an older firewall carries only by its label (the rule's name, or its domain when it
 * has none); a label that is no rule of the organization (the firewall's own, such as
 * `agent_update` or `content: …`) gives null and is not counted. A firewall that sends rule ids puts
 * `ruleId` on every record, null when no rule decided, and its labels are never matched: a flow it
 * labelled itself (the phone, a grant) must not count for a rule that happens to share the name.
 */
export function hitsFromActivity(rows: readonly InsertedActivity[], websiteIdOf: (label: string) => string | null): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const r of rows) {
    const d = r.detail ?? {};
    if (r.source === "content_rule") {
      const outcome = CONTENT_OUTCOME[String(d.action)];
      const rule = str(d.rule);
      // `error` is a check that could not run, not a rule; a Send or Don't send is the same message again.
      if (outcome && rule && rule !== "error") hits.push({ vmId: r.vmId, at: r.occurredAt, type: "messages", key: rule, outcome, name: str(d.name) });
    } else if (r.source === "email_held") {
      hits.push({ vmId: r.vmId, at: r.occurredAt, type: "email", key: EMAIL_IN, outcome: "held" });
    } else if (r.source === "egress") {
      // A residential flow's later records (`<flow>#<n>`) bill more bytes of the same request.
      if (r.dedupeKey.includes("#")) continue;
      const outcome = STATUS_OUTCOME[r.status];
      if (!outcome) continue;
      const label = str(d.rule);
      const code = typeof d.statusCode === "number" ? d.statusCode : null;
      if (d.email === "sent" && (code === null || code < 400)) hits.push({ vmId: r.vmId, at: r.occurredAt, type: "email", key: EMAIL_OUT, outcome: "allowed" });
      if (label === "email" && outcome !== "allowed") {
        if (outcome === "asked" || EMAIL_RULE_REASONS.includes(String(d.emailReason))) hits.push({ vmId: r.vmId, at: r.occurredAt, type: "email", key: EMAIL_OUT, outcome });
        continue;
      }
      const sendsIds = "ruleId" in d;
      const id = str(d.ruleId) ?? (label && !sendsIds ? websiteIdOf(label) : null);
      if (id) hits.push({ vmId: r.vmId, at: r.occurredAt, type: "websites", key: id, outcome });
      else if (!label) hits.push({ vmId: r.vmId, at: r.occurredAt, type: "websites", key: DEFAULT_KEY, outcome });
    }
  }
  return hits;
}

/** A `connector_call` record as the ingest reads it (activity-ingest.schema.ts). */
export interface CallRecordLike {
  ts: number;
  vm_id: string;
  decision: string;
  by: string;
  rule?: string | null;
  rule_id?: string | null;
  follows?: string;
  released?: boolean;
}

/**
 * The Integrations match of one call line, or null. Only the line the rules decided counts: a run
 * that follows an ask (the same call, approved) and a held call sent on are not counted again, and a
 * call a Messages rule held or a gate refusal (rules loading, an emergency stop) is no Integrations rule's.
 */
export function hitFromCall(r: CallRecordLike, at: Date): RuleHit | null {
  if (r.follows || r.released) return null;
  const outcome = STATUS_OUTCOME[r.decision];
  if (!outcome) return null;
  if (r.by === "default") return { vmId: r.vm_id, at, type: "apps", key: DEFAULT_KEY, outcome };
  if (r.by !== "app_rule") return null;
  if (r.rule_id) return { vmId: r.vm_id, at, type: "apps", key: r.rule_id, outcome, name: r.rule ?? null };
  return r.rule ? { vmId: r.vm_id, at, type: "apps", key: `${NAME_KEY_PREFIX}${r.rule}`, outcome, name: r.rule } : null;
}

/** An Auto approve decision: the rule that answered, or the grey row when the request went to a person. */
export function hitFromPermission(input: { vmId: string | null; at: Date; ruleId: string | null; ruleName: string | null; effect: "allow" | "ask" | "block" }): RuleHit {
  const outcome: RuleOutcome = input.effect === "allow" ? "allowed" : input.effect === "block" ? "blocked" : "asked";
  return { vmId: input.vmId, at: input.at, type: "auto", key: input.ruleId ?? DEFAULT_KEY, outcome, name: input.ruleId ? input.ruleName : null };
}

/** One row per (agent, hour, type, key, outcome), in a fixed order so two batches lock the same rows in the same order. */
export interface RuleHourGroup {
  vmId: string;
  hour: Date;
  ruleType: RuleType;
  ruleKey: string;
  outcome: RuleOutcome;
  count: number;
  lastAt: Date;
  name: string | null;
}

export function hourOf(at: Date): Date {
  const h = new Date(at);
  h.setUTCMinutes(0, 0, 0);
  return h;
}

export function groupHits(hits: readonly RuleHit[]): RuleHourGroup[] {
  const by = new Map<string, RuleHourGroup>();
  for (const h of hits) {
    const hour = hourOf(h.at);
    const vmId = h.vmId ?? "";
    const k = `${vmId}|${hour.getTime()}|${h.type}|${h.key}|${h.outcome}`;
    const g = by.get(k);
    if (!g) by.set(k, { vmId, hour, ruleType: h.type, ruleKey: h.key, outcome: h.outcome, count: 1, lastAt: h.at, name: h.name ?? null });
    else {
      g.count += 1;
      if (h.at > g.lastAt) g.lastAt = h.at;
      if (h.name) g.name = h.name;
    }
  }
  return [...by.values()].sort(
    (a, b) =>
      a.vmId.localeCompare(b.vmId) ||
      a.hour.getTime() - b.hour.getTime() ||
      a.ruleType.localeCompare(b.ruleType) ||
      a.ruleKey.localeCompare(b.ruleKey) ||
      a.outcome.localeCompare(b.outcome),
  );
}

// ---------------------------------------------------------------------------------------------
// What the pages show

export type RuleCounts = Record<RuleOutcome, number>;

/** One rule's matches over a range, as the read returns them. */
export interface RuleActivityItem {
  type: RuleType;
  key: string;
  /** The rule's id, for the edit link; null on a grey row and on a rule known only by name. */
  ruleId: string | null;
  name: string;
  /** A grey row: no rule matched (or, for Email, "Everyone else"). */
  builtin: boolean;
  /** The rule is gone from the console (Websites, Auto approve); there is nothing to edit. */
  deleted: boolean;
  counts: RuleCounts;
  total: number;
  /** ISO time of the newest match in the range. */
  lastAt: string;
}

export const DEFAULT_NAMES: Partial<Record<RuleType, string>> = {
  websites: "Every other site",
  apps: "Every other call",
  auto: "Every other request",
};
export const EMAIL_NAMES: Record<string, string> = {
  [EMAIL_IN]: "Everyone else, incoming",
  // Sends to listed recipients count here too: the firewall does not say which entry let one through.
  [EMAIL_OUT]: "Outgoing email",
};

export function emptyCounts(): RuleCounts {
  return { allowed: 0, asked: 0, held: 0, blocked: 0, recorded: 0 };
}

export type RuleSort = "active" | "latest";

/**
 * The rows the Firewall page shows: the most active, or the most recent, up to `limit`. The grey
 * rows count like the others but take at most `maxBuiltin` places: "Every other site" is nearly
 * always the busiest and would otherwise fill the list with what no rule decided.
 */
export function topRules<T extends RuleActivityItem>(items: readonly T[], sort: RuleSort, limit = 6, maxBuiltin = 2): T[] {
  const sorted = [...items]
    .filter((i) => i.total > 0)
    .sort((a, b) => (sort === "active" ? b.total - a.total || b.lastAt.localeCompare(a.lastAt) : b.lastAt.localeCompare(a.lastAt) || b.total - a.total) || a.name.localeCompare(b.name));
  const out: T[] = [];
  let builtin = 0;
  for (const i of sorted) {
    if (out.length >= limit) break;
    if (i.builtin) {
      if (builtin >= maxBuiltin) continue;
      builtin += 1;
    }
    out.push(i);
  }
  return out;
}

export const OUTCOME_LABELS: Record<RuleOutcome, string> = {
  allowed: "allowed",
  asked: "asked",
  held: "held",
  blocked: "blocked",
  recorded: "recorded",
};

/** Email says what happened to mail in its own words. */
export function outcomeLabel(type: RuleType, o: RuleOutcome): string {
  if (type === "email") return o === "allowed" ? "sent" : o === "blocked" ? "refused" : o === "held" ? "held back" : OUTCOME_LABELS[o];
  if (type === "messages" && o === "blocked") return "stopped";
  return OUTCOME_LABELS[o];
}

/** The outcomes that happened, in order: [["allowed", 214], ["blocked", 12]]. */
export function outcomeList(counts: RuleCounts): Array<[RuleOutcome, number]> {
  return RULE_OUTCOMES.flatMap((o) => (counts[o] > 0 ? [[o, counts[o]] as [RuleOutcome, number]] : []));
}

/** "214 allowed, 12 blocked". */
export function outcomeLine(type: RuleType, counts: RuleCounts): string {
  return outcomeList(counts)
    .map(([o, n]) => `${n.toLocaleString("en-US")} ${outcomeLabel(type, o)}`)
    .join(", ");
}

const NOUN: Record<RuleType, [string, string]> = {
  messages: ["message", "messages"],
  email: ["email", "emails"],
  websites: ["request", "requests"],
  apps: ["call", "calls"],
  auto: ["request", "requests"],
};

/** "18m", "3h", "2d". */
export function agoShort(iso: string, now: number): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 172_800) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} days ago`;
}

/** "last 2 h ago", or "just now". */
export function lastMatched(iso: string, now: number): string {
  const ago = agoShort(iso, now);
  return ago === "just now" ? ago : `last ${ago}`;
}

/**
 * The line under a rule on Security rules: "Matched 12 requests in 7 days · last 2 h ago", or
 * "Not matched in 7 days". Messages rules "act on" messages: a rule that matched did something.
 */
export function ruleLine(type: RuleType, item: Pick<RuleActivityItem, "total" | "lastAt"> | null | undefined, now: number, days = 7): string {
  const span = `${days} ${days === 1 ? "day" : "days"}`;
  if (!item || item.total === 0) return type === "messages" ? `Not acted on in ${span}` : `Not matched in ${span}`;
  const [one, many] = NOUN[type];
  const verb = type === "messages" ? "Acted on" : "Matched";
  return `${verb} ${item.total.toLocaleString("en-US")} ${item.total === 1 ? one : many} in ${span} · ${lastMatched(item.lastAt, now)}`;
}

/** The read's items by `type:key`, for the rows of Security rules. */
export function byRuleKey(items: readonly RuleActivityItem[]): Map<string, RuleActivityItem> {
  return new Map(items.map((i) => [`${i.type}:${i.key}`, i]));
}

/**
 * Integrations counts kept by the rule's name (the backfill, a firewall too old to send ids) go to the
 * rule that has that name now, when exactly one does: added to its counts, or taking its id when it
 * has none of its own in the range. `rules` is the firewall's list (id and name). Returns new items.
 */
export function foldNamedApps<T extends RuleActivityItem & { series?: number[] }>(items: readonly T[], rules: ReadonlyArray<{ id: string; name: string }>): T[] {
  const named = new Map<string, string | null>();
  for (const r of rules) named.set(r.name, named.has(r.name) ? null : r.id);
  const out = items.map((i) => ({ ...i, counts: { ...i.counts }, ...(i.series ? { series: [...i.series] } : {}) }));
  const byId = new Map(out.filter((i) => i.type === "apps" && i.ruleId).map((i) => [i.ruleId!, i]));
  return out.filter((i) => {
    if (i.type !== "apps" || !i.key.startsWith(NAME_KEY_PREFIX)) return true;
    const id = named.get(i.key.slice(NAME_KEY_PREFIX.length));
    if (!id) return true;
    const into = byId.get(id);
    if (!into) {
      byId.set(id, Object.assign(i, { key: id, ruleId: id }));
      return true;
    }
    for (const o of RULE_OUTCOMES) into.counts[o] += i.counts[o];
    into.total += i.total;
    if (i.lastAt > into.lastAt) into.lastAt = i.lastAt;
    if (into.series && i.series) into.series = addSeries(into.series, i.series);
    return false;
  });
}

/** Two sparklines added bar by bar. */
export function addSeries(a: readonly number[], b: readonly number[]): number[] {
  return Array.from({ length: Math.max(a.length, b.length) }, (_, n) => (a[n] ?? 0) + (b[n] ?? 0));
}

// ---------------------------------------------------------------------------------------------
// The Firewall page's "Most used rules" and "Security rules" (T-183)

/** Every sparkline has this many bars: an hour each over 24h, seven hours each over 7 days. */
export const SERIES_BARS = 24;

/** The first hour a range reads: the current hour and the ones before it. */
export function rangeSince(range: RuleMetricRange, now: Date): Date {
  return hourOf(new Date(now.getTime() - (RANGE_HOURS[range] - 1) * 3_600_000));
}

/** Hours per sparkline bar. */
export function barHours(range: RuleMetricRange): number {
  return RANGE_HOURS[range] / SERIES_BARS;
}

/** A rule's matches over the range, with a line saying what it does and its matches per bar, oldest first. */
export interface RuleOverviewItem extends RuleActivityItem {
  /** What the rule does, one line; null where the console cannot tell from the database (Messages, Integrations). */
  detail: string | null;
  series: number[];
}

/** What a Websites rule does: "Blocks pastebin.com", "Asks you before agents reach api.stripe.com/v1". */
export function websitesDetail(r: { effect: string; matchDomain: string; matchPath: string | null; matchMethod: string | null; exit?: string | null }): string {
  const target = `${r.matchMethod ? `${r.matchMethod} ` : ""}${r.matchDomain}${r.matchPath ?? ""}`;
  if (r.effect === "block") return `Blocks ${target}`;
  if (r.effect === "require_permission") return `Asks you before agents reach ${target}`;
  if (r.effect === "tunnel" || r.exit === "residential") return `Lets agents reach ${target}, not inspected`;
  return `Lets agents reach ${target}`;
}

/** What an Auto approve rule does: its description, or its effect and condition. */
export function autoDetail(r: { effect: string; description: string; condDisplay: string | null }): string {
  if (r.description.trim()) return r.description.trim();
  const verb = r.effect === "allow" ? "Approves" : r.effect === "block" ? "Refuses" : "Sends you";
  return r.condDisplay ? `${verb} requests where ${r.condDisplay}` : `${verb} every request`;
}

/** The grey rows in words. "Every other site" says what it did: the read cannot see the setting. */
export function builtinDetail(type: RuleType, key: string, counts: RuleCounts): string {
  if (type === "email") return key === EMAIL_IN ? "Holds back mail from senders not on your list" : "Checks the mail your agents send against your list";
  if (type === "websites") {
    if (counts.blocked > 0 && counts.allowed === 0 && counts.asked === 0) return "Blocks any site not on your list";
    if (counts.allowed > 0 && counts.blocked === 0 && counts.asked === 0) return "Lets agents reach sites no rule names";
    return "Sites no rule names";
  }
  if (type === "apps") return "Calls no integration rule names";
  if (type === "auto") return "Sends you every request no rule answers";
  return "No rule matched";
}
