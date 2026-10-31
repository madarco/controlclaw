import { HOUR_MS } from "./stats";

/**
 * The arithmetic behind the Firewall page's Overview tab (docs/plans/firewall-overview-charts.md),
 * without the database. `firewall-stats.server.ts` runs the queries.
 */

/**
 * Requests slower than this are left out of the response time: Telegram's `getUpdates` holds the
 * connection for about 30 s, and on an agent with Telegram half the rows are such long-polls.
 */
export const RESPONSE_MAX_MS = 25_000;

/** How long the hourly rollup is kept, in months. Raw rows are kept 30 days. */
export const EGRESS_HOURLY_RETENTION_MONTHS = 13;

export const ROLLUP_STATUSES = ["allowed", "blocked", "asked"] as const;
export type RollupStatus = (typeof ROLLUP_STATUSES)[number];

export type TrafficRange = "1h" | "24h" | "7d";

/** One point of the traffic chart. `at` is the start of its bucket, ISO. */
export type TrafficPoint = { at: string; allowed: number; asked: number; blocked: number };

/** Bucket size and count per range: 1h by minute, 24h by half hour, 7d by three hours. */
export const RANGE_BUCKETS: Record<TrafficRange, { count: number; ms: number }> = {
  "1h": { count: 60, ms: 60_000 },
  "24h": { count: 48, ms: HOUR_MS / 2 },
  "7d": { count: 56, ms: 3 * HOUR_MS },
};

/** The bucket starts of a range, oldest first, the last one holding `now`. */
export function rangeBuckets(range: TrafficRange, now: Date): Date[] {
  const { count, ms } = RANGE_BUCKETS[range];
  const last = Math.floor(now.getTime() / ms) * ms;
  return Array.from({ length: count }, (_, i) => new Date(last - (count - 1 - i) * ms));
}

/** Whether an egress row counts for the response time: allowed, seen inside, and not a long-poll. */
export function isTimed(status: string, detail: Record<string, unknown>): boolean {
  const ms = typeof detail.durationMs === "number" ? Math.round(detail.durationMs) : null;
  // Rounded first, as the SQL and the migration do, so the 25 s edge falls the same way in all three.
  return status === "allowed" && detail.tunnel !== true && ms !== null && ms >= 0 && ms <= RESPONSE_MAX_MS;
}

export type RollupGroup = {
  vmId: string;
  hour: Date;
  status: RollupStatus;
  count: number;
  durationMsSum: number;
  durationN: number;
};

/**
 * Inserted egress rows grouped by (agent, hour, status), as the rollup stores them. Statuses other
 * than the three are not egress verdicts and are skipped.
 */
export function rollupGroups(
  rows: ReadonlyArray<{ vmId: string | null; status: string; occurredAt: Date; detail: Record<string, unknown> }>,
): RollupGroup[] {
  const groups = new Map<string, RollupGroup>();
  for (const r of rows) {
    if (!(ROLLUP_STATUSES as readonly string[]).includes(r.status)) continue;
    const hour = new Date(Math.floor(r.occurredAt.getTime() / HOUR_MS) * HOUR_MS);
    const vmId = r.vmId ?? "";
    const key = `${vmId}\u0000${hour.getTime()}\u0000${r.status}`;
    let g = groups.get(key);
    if (!g) {
      g = { vmId, hour, status: r.status as RollupStatus, count: 0, durationMsSum: 0, durationN: 0 };
      groups.set(key, g);
    }
    g.count++;
    if (isTimed(r.status, r.detail)) {
      g.durationMsSum += Math.round(r.detail.durationMs as number);
      g.durationN++;
    }
  }
  return [...groups.values()];
}

/** The first day of next month, UTC: when "This month" starts again. */
export function nextMonthStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
}

export function monthStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
}

/**
 * The Security rules shield's line: every rule the Security rules page lists (Messages, Email,
 * Websites, Auto approve). Messages and Email rules live on the firewall, so their counts are the
 * firewall's last answer; while it has never given one, the line names them instead of claiming
 * there are none.
 */
export function securityRulesLine(c: {
  siteRules: number;
  securityRules: number;
  securityAsk: number;
  messageRules: number | null;
  emailRules: number | null;
}): string {
  const total = c.siteRules + c.securityRules + (c.messageRules ?? 0) + (c.emailRules ?? 0);
  const unknown = [c.messageRules === null ? "Messages" : null, c.emailRules === null ? "Email" : null].filter(Boolean).join(" and ");
  const ask = c.securityAsk ? ` · ${c.securityAsk.toLocaleString("en-US")} ask you first` : "";
  if (total === 0) return unknown ? `${unknown} rules on the firewall` : "No rules yet";
  const counted = `${total.toLocaleString("en-US")} ${total === 1 ? "rule" : "rules"}`;
  return `${counted}${unknown ? `, plus ${unknown}` : ""}${ask}`;
}
