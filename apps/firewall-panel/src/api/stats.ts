import type { Schemas } from "@controlclaw/fw-api";
import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { FirewallOverviewView, LiveRequest } from "@controlclaw/console-ui/lib/firewall-stats-schema";
import { fw } from "./client";
import { listAgents, type AgentRow } from "./agents";

const SEVERITIES = ["low", "medium", "high"] as const;

/**
 * The firewall's live rows as the shared list draws them. A `recorded` row (a finding, a record)
 * is not a request, and the list has no verdict for it, so it is left out.
 */
export function toLive(rows: Schemas["LiveRequest"][]): LiveRequest[] {
  return rows.flatMap((r) =>
    r.verdict === "recorded"
      ? []
      : [{ id: String(r.id), createdAt: r.createdAt, occurredAt: r.occurredAt, method: r.method ?? null, host: r.host, agent: r.agent ?? null, verdict: r.verdict, durationMs: r.durationMs ?? null, long: r.long }],
  );
}

/**
 * `/api/overview` as the shared Overview reads it. The firewall answers, so it is running; the
 * counts it does not keep (channel tokens, webhooks, team chat) are 0 or unknown, and the panel
 * does not draw the tiles that show them.
 */
export function toOverview(o: Schemas["Overview"], agents: AgentRow[], logReview: boolean): FirewallOverviewView {
  const brains = new Set(agents.filter((a) => a.role === "gbrain").map((a) => a.vm_id));
  return {
    running: true,
    generatedAt: o.generatedAt,
    hours: o.hours,
    perMinute: o.perMinute,
    blocked: o.blocked,
    response: { value: o.response.value ?? null, today: o.response.today ?? null, yesterday: o.response.yesterday ?? null, series: o.response.series },
    month: o.month,
    traffic: o.traffic,
    live: toLive(o.live),
    topHosts: o.topHosts,
    byAgent: o.byAgent.map((a) => ({
      vmId: a.vmId ?? null,
      name: a.name,
      running: true,
      deleted: false,
      brain: a.vmId ? brains.has(a.vmId) : false,
      total: a.total,
      blocked: a.blocked,
      hourly: a.hourly,
    })),
    ai: {
      // The card is AI Log Review's; `o.ai.enabled` is the AI Firewall's switch (fw-core, backlog).
      enabled: logReview,
      findings: o.ai.findings.map((f) => ({
        id: f.id,
        // A severity the panel does not know is read as the worst, not hidden as low.
        severity: (SEVERITIES as readonly string[]).includes(f.severity) ? (f.severity as (typeof SEVERITIES)[number]) : "high",
        title: f.title,
        explanation: null,
        agent: f.agent ?? null,
        at: f.at,
      })),
    },
    shields: {
      siteRules: o.shields.siteRules,
      aiKeys: o.shields.aiKeys,
      securityRules: 0,
      securityAsk: 0,
      messageRules: null,
      emailRules: null,
      channelTokens: 0,
      webhooks: 0,
      teamChat: "off",
    },
  };
}

/**
 * `/api/live` reads after a row's id, the shared list after its newest row's time: the ids of the
 * rows handed to the list, by time, turn one into the other. A time it never handed over reads the
 * newest rows again, which the list merges by id.
 */
const liveIds = new Map<string, number>();

function handed(rows: Schemas["LiveRequest"][]): LiveRequest[] {
  for (const r of rows) liveIds.set(r.createdAt, Math.max(liveIds.get(r.createdAt) ?? 0, r.id));
  if (liveIds.size > 2000) liveIds.clear();
  return toLive(rows);
}

export const firewallStats: ConsoleApi["firewallStats"] = {
  async overview({ range, withLive }) {
    const [o, agents, ai] = await Promise.all([fw.get("/api/overview", { query: { range } }), listAgents(), fw.get("/api/egress/ai")]);
    const view = toOverview(o, agents, ai.settings.logReviewEnabled && ai.credentials.some((c) => c.id === ai.settings.credentialId));
    return withLive === false ? view : { ...view, live: handed(o.live) };
  },
  traffic: ({ range }) => fw.get("/api/traffic", { query: { range } }),
  async live({ after }) {
    const afterId = after ? liveIds.get(after) : undefined;
    return handed(await fw.get("/api/live", { query: afterId ? { afterId } : {} }));
  },
};
