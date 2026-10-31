"use client";

import { AppLink as Link } from "../../lib/link";
import {
  Archive,
  Brain,
  ChevronRight,
  Globe,
  Mail,
  MessageSquare,
  MessagesSquare,
  Shield,
  Sparkles,
  Webhook,
} from "lucide-react";
import { cn } from "../../lib/utils";
import { Card, CardHead, Dot, LiveDot } from "../../kit/console-ui";
import { HBarList, MiniBars, SparkStatCard } from "../../kit/charts";
import { HostIcon } from "../../kit/people";
import { countLabel, resetDayLabel } from "../../lib/format";
import type { AgentTraffic, AiFinding, FirewallOverviewView, ShieldCounts, TopHost } from "../../lib/firewall-stats-schema";
import { securityRulesLine } from "../../lib/firewall-stats";

/** Where the overview's links go: the console's routes, or the firewall panel's own. */
export interface OverviewHrefs {
  activity: string;
  internet: string;
  security: string;
  emailRules: string;
  channels: string;
  aiKeys: string;
  webhooks: string;
  teamChat: string;
  backups: string;
  brain: string;
  agent: (vmId: string) => string;
  /** AI Log Review's settings; the Firewall page's own Settings tab (`#ai-review`) when left out. */
  aiReview?: string;
}

/** "18m", "3h", "2d": how long ago, short, for a list's right edge. */
export function shortAgo(iso: string, now: number): string {
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 172_800) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86_400)}d`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${countLabel(n)} ${n === 1 ? one : many}`;

/**
 * The four cards across the top: Requests / min, Blocked today, Typical response time (each with
 * the last 24 hours as a line and a change against yesterday), and This month.
 */
export function StatCards({ view, allowance }: { view: FirewallOverviewView; allowance?: number | null }) {
  const off = !view.running;
  const zero = (s: readonly number[]) => (off ? s.map(() => 0) : s);
  return (
    <div className="grid grid-cols-1 gap-3 min-[460px]:grid-cols-2 lg:grid-cols-4" data-testid="firewall-cards">
      <SparkStatCard
        label="Requests / min"
        value={countLabel(off ? 0 : view.perMinute.value)}
        series={zero(view.perMinute.series)}
        hours={view.hours}
        today={off ? undefined : view.perMinute.today}
        yesterday={off ? undefined : view.perMinute.yesterday}
        format={(n) => (Number.isInteger(n) ? countLabel(n) : n.toFixed(1))}
        data-testid="firewall-card-rpm"
      />
      <SparkStatCard
        label="Blocked today"
        series={zero(view.blocked.series)}
        hours={view.hours}
        today={off ? 0 : view.blocked.today}
        yesterday={off ? undefined : view.blocked.yesterday}
        upIsBad
        tone="block"
        data-testid="firewall-card-blocked"
      />
      <SparkStatCard
        label="Typical response time"
        value={!off && view.response.value !== null ? `${countLabel(view.response.value)} ms` : "—"}
        unit=" ms"
        series={zero(view.response.series)}
        hours={view.hours}
        today={off ? undefined : (view.response.today ?? undefined)}
        yesterday={off ? undefined : (view.response.yesterday ?? undefined)}
        upIsBad
        tone="brand"
        data-testid="firewall-card-response"
      />
      <MonthCard count={view.month.count} resetsAt={view.month.resetsAt} allowance={allowance} />
    </div>
  );
}

/**
 * This month's requests. The allowance and its bar wait for the pricing decision
 * (docs/plans/firewall-overview-charts.md): pass `allowance` and the bar appears.
 */
function MonthCard({ count, resetsAt, allowance }: { count: number; resetsAt: string; allowance?: number | null }) {
  const pct = allowance ? Math.min(100, Math.round((count / allowance) * 100)) : null;
  return (
    <div className="flex h-[140px] flex-col rounded-[14px] border border-line bg-surface px-4 pt-3.5 pb-3.5" data-testid="firewall-card-month">
      <span className="text-[12.5px] text-ink-2">This month</span>
      <div className="mt-1.5 text-[22px] font-semibold tracking-[-0.02em] tabular-nums text-ink">
        {countLabel(count)}
        {allowance ? <span className="text-[13px] font-medium text-ink-2"> / {countLabel(allowance)}</span> : null}
      </div>
      {pct !== null ? (
        <div className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-muted-2">
          <span className={cn("block h-full rounded-full", pct >= 80 ? "bg-ask" : "bg-brand")} style={{ width: `${pct}%` }} />
        </div>
      ) : null}
      <div className="mt-auto text-[12px] text-ink-2">
        {pct !== null ? `${pct}% of your plan · ` : "requests · "}resets {resetDayLabel(resetsAt)}
      </div>
    </div>
  );
}

const SEVERITY: Record<AiFinding["severity"], { label: string; className: string }> = {
  high: { label: "High", className: "bg-block-soft text-block-fg" },
  medium: { label: "Medium", className: "bg-ask-soft text-ask-fg" },
  low: { label: "Low", className: "bg-bg-2 text-ink-2" },
};

/** The newest findings of the AI Log Review, with a link to all of them in Activity. */
export function AiFindings({ enabled, findings, now, hrefs }: { enabled: boolean; findings: readonly AiFinding[]; now: number; hrefs: OverviewHrefs }) {
  return (
    <Card className="flex flex-col overflow-hidden" data-testid="firewall-findings">
      <CardHead
        title="AI Log Review found"
        icon={Sparkles}
        className="px-4 py-3 sm:px-5"
        right={enabled ? <Dot tone="ok">Watching</Dot> : <Dot>Off</Dot>}
      />
      {findings.length === 0 ? (
        <p className="px-5 py-5 text-[13px] text-ink-2">
          {enabled ? (
            "Nothing suspicious so far. Findings show up here and in Activity."
          ) : (
            <>
              AI Log Review is off.{" "}
              {/* On the Firewall page a plain hash link, which its tabs follow (hashchange); elsewhere the app's route. */}
              {hrefs.aiReview ? (
                <Link href={hrefs.aiReview} className="font-medium text-brand hover:underline">
                  Turn it on in Settings
                </Link>
              ) : (
                <a href="#ai-review" className="font-medium text-brand hover:underline">
                  Turn it on in Settings
                </a>
              )}{" "}
              to check your agents’ traffic on a schedule.
            </>
          )}
        </p>
      ) : (
        findings.map((f) => (
          <div key={f.id} className="flex items-start gap-2.5 border-t border-line px-4 py-3 first-of-type:border-t-0 sm:px-5">
            <span className={cn("mt-px shrink-0 rounded-full px-[7px] py-0.5 text-[10.5px] font-semibold tracking-[0.03em] uppercase", SEVERITY[f.severity].className)}>
              {SEVERITY[f.severity].label}
            </span>
            <div className="min-w-0 flex-1">
              <div className="text-[13px] leading-snug font-semibold text-pretty text-ink">
                {f.title}
                {f.agent ? <span className="font-normal text-ink-2"> · {f.agent}</span> : null}
              </div>
              {f.explanation ? <p className="mt-0.5 text-[12.5px] text-pretty text-ink-2">{f.explanation}</p> : null}
            </div>
            <span className="shrink-0 font-mono text-[11px] text-ink-2">{shortAgo(f.at, now)}</span>
          </div>
        ))
      )}
      <div className="mt-auto border-t border-line px-4 py-2.5 text-[13px] sm:px-5">
        <Link href={hrefs.activity} className="text-brand hover:underline">
          All findings in Activity →
        </Link>
      </div>
    </Card>
  );
}

/** Where traffic goes today: the busiest hosts, blocked requests in red. */
export function TopHosts({ hosts, hrefs }: { hosts: readonly TopHost[]; hrefs: OverviewHrefs }) {
  return (
    <Card className="overflow-hidden" data-testid="firewall-top-hosts">
      <CardHead
        title={
          <>
            Where traffic goes <span className="ml-1 text-[12.5px] font-normal text-ink-2">today</span>
          </>
        }
        className="px-4 py-3 sm:px-5"
        right={
          <Link href={hrefs.internet} className="text-[13px] text-brand hover:underline">
            Rules →
          </Link>
        }
      />
      <HBarList
        items={hosts.map((h) => ({ key: h.host, label: h.host, mono: true, lead: <HostIcon host={h.host} />, value: h.total, blocked: h.blocked, title: h.host }))}
        empty="No requests today."
      />
    </Card>
  );
}

/** Requests and blocked requests per agent (and the brain) today, with its last 24 hours as bars. */
export function ByAgent({ agents, hrefs }: { agents: readonly AgentTraffic[]; hrefs: OverviewHrefs }) {
  return (
    <Card className="overflow-hidden" data-testid="firewall-by-agent">
      <CardHead
        title={
          <>
            By agent <span className="ml-1 text-[12.5px] font-normal text-ink-2">today</span>
          </>
        }
        className="px-4 py-3 sm:px-5"
      />
      {agents.length === 0 ? <p className="px-5 py-4 text-[13px] text-ink-2">No agents yet.</p> : null}
      {agents.map((a) => {
        const share = a.total > 0 ? a.blocked / a.total : 0;
        const body = (
          <>
            <span className="flex min-w-0 items-center gap-2 text-[13.5px] font-semibold text-ink">
              {a.brain ? (
                <Brain aria-hidden="true" data-testid="firewall-by-agent-brain" className={cn("h-3.5 w-3.5 shrink-0", a.running ? "text-allow" : "text-ink-2/60")} />
              ) : (
                <LiveDot size="sm" paused={!a.running} />
              )}
              <span className="truncate">{a.name}</span>
            </span>
            <MiniBars data={a.hourly} off={!a.running && a.total === 0} aria-label={`${a.name}: requests per hour, last 24 hours`} />
            <span className="flex flex-col items-end whitespace-nowrap tabular-nums">
              <b className="text-[14px] text-ink">{countLabel(a.total)}</b>
              <span className={cn("text-[11.5px]", a.blocked > 0 ? "text-block-fg" : "text-ink-2")}>{countLabel(a.blocked)} blocked</span>
            </span>
            {a.blocked > 0 ? (
              <span aria-hidden="true" className="absolute inset-x-4 bottom-0 h-0.5 sm:inset-x-5">
                <i className="block h-full bg-block opacity-50" style={{ width: `${Math.min(100, share * 800)}%` }} />
              </span>
            ) : null}
          </>
        );
        const row = "relative grid grid-cols-[minmax(0,1fr)_100px_auto] items-center gap-3 border-t border-line px-4 py-2.5 first-of-type:border-t-0 sm:px-5";
        return a.vmId && !a.deleted ? (
          <Link key={a.vmId} href={a.brain ? hrefs.brain : hrefs.agent(a.vmId)} className={cn(row, "hover:bg-bg")}>
            {body}
          </Link>
        ) : (
          <div key={a.vmId ?? "firewall"} className={row}>
            {body}
          </div>
        );
      })}
    </Card>
  );
}

type ShieldDef = { icon: React.ComponentType<{ className?: string }>; title: string; desc: string; href: string; tone?: "allow" | "ask" | "muted" };

function shieldList(c: ShieldCounts, hrefs: OverviewHrefs): ShieldDef[] {
  return [
    { icon: Globe, title: "Internet access", desc: c.siteRules ? `${plural(c.siteRules, "site rule")}` : "Default rules", href: hrefs.internet },
    {
      icon: Shield,
      title: "Security rules",
      desc: securityRulesLine(c),
      href: hrefs.security,
    },
    { icon: Mail, title: "Email rules", desc: "Who can email your agents, and whom they email", href: hrefs.emailRules },
    { icon: MessageSquare, title: "Channel tokens", desc: c.channelTokens ? `${plural(c.channelTokens, "token")} kept on the firewall` : "None connected", href: hrefs.channels },
    { icon: Sparkles, title: "AI keys", desc: c.aiKeys ? `${plural(c.aiKeys, "key")}, never leave the firewall` : "Included AI only", href: hrefs.aiKeys },
    { icon: Webhook, title: "Webhooks", desc: c.webhooks ? `${plural(c.webhooks, "service")}, checked first` : "None", href: hrefs.webhooks },
    { icon: MessagesSquare, title: "Team chat", desc: c.teamChat === "on" ? "On" : c.teamChat === "starting" ? "On, not running" : "Off", href: hrefs.teamChat, tone: c.teamChat === "on" ? "allow" : c.teamChat === "starting" ? "ask" : "muted" },
    { icon: Archive, title: "Firewall backup", desc: "Encrypted, only your recovery key opens it", href: hrefs.backups },
  ];
}

/** Protected services: one tile per shield with its count, each linking to its page. */
export function Shields({ counts, hrefs }: { counts: ShieldCounts; hrefs: OverviewHrefs }) {
  return (
    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4" data-testid="firewall-shields">
      {shieldList(counts, hrefs).map((s) => (
        <Link
          key={s.title}
          href={s.href}
          className="flex min-w-0 items-center gap-3 rounded-[14px] border border-line bg-surface px-3.5 py-3 hover:border-line-2"
        >
          <span className={cn("grid h-8 w-8 shrink-0 place-items-center rounded-[9px]", s.tone === "muted" ? "bg-bg-2 text-ink-2" : s.tone === "ask" ? "bg-ask-soft text-ask-fg" : "bg-allow-soft text-allow-fg")}>
            <s.icon className="h-4 w-4" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-[13.5px] font-semibold text-ink">{s.title}</span>
            <span className="block truncate text-[12px] text-ink-2" title={s.desc}>
              {s.desc}
            </span>
          </span>
          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-ink-2" />
        </Link>
      ))}
    </div>
  );
}
