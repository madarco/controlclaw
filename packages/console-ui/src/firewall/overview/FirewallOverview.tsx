"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useApi } from "../../lib/api";
import { Sec } from "../../kit/console-ui";
import type { TrafficPoint, TrafficRange } from "../../lib/firewall-stats";
import type { FirewallOverviewView } from "../../lib/firewall-stats-schema";
import { LiveRequests } from "./LiveRequests";
import { AiFindings, ByAgent, Shields, StatCards, TopHosts } from "./OverviewCards";
import { TrafficChart } from "./TrafficChart";
import { useRoutes } from "../../lib/routes";
import { MostUsedRules, SecurityRulesSection, useRuleOverview, type DemoRules } from "./RulesOverview";
import { allRulesCount } from "../../lib/rule-overview";

/** How often the cards, the chart and the lists are read again while the tab is visible. */
const REFRESH_MS = 60_000;

function browserZone(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return undefined;
  }
}

/**
 * The Firewall page's Overview tab (docs/plans/firewall-overview-charts.md,
 * docs/features/firewall-overview.md): the cards, the traffic chart, Live requests beside Most used
 * rules, AI findings, top hosts, by agent, the Security rules section and the shields. Loads in the browser, so "today" starts at the reader's
 * midnight, and reads everything again every minute while the tab is visible. With `initial`
 * and `live={false}` (the demo page) nothing is called.
 */
export function FirewallOverview({
  canManage,
  initial = null,
  live = true,
  demoTraffic,
  demoRules,
  shields = true,
}: {
  canManage: boolean;
  initial?: FirewallOverviewView | null;
  live?: boolean;
  /** The demo page's chart for another range, in place of the RPC. */
  demoTraffic?: (range: TrafficRange) => TrafficPoint[];
  /** The demo page's Most used rules and Security rules, in place of the RPCs. */
  demoRules?: DemoRules;
  /** Protected services. The firewall's own panel leaves them out: most of the tiles are the console's. */
  shields?: boolean;
}) {
  const api = useApi();
  const routes = useRoutes();
  const [view, setView] = useState<FirewallOverviewView | null>(initial);
  const [range, setRange] = useState<TrafficRange>(initial?.traffic.range ?? "24h");
  const [loadingRange, setLoadingRange] = useState(false);
  const [error, setError] = useState(false);
  // The refresh reads the range in force when it fires, without restarting its timer.
  const rangeRef = useRef(range);
  // A control plane that keeps no per-rule counts (the firewall's own panel) has no rules cards.
  const hasRules = !!api.ruleMetrics || !!demoRules || !live;
  const rules = useRuleOverview({ live: live && canManage && hasRules, demo: demoRules ?? (live ? undefined : { items: () => [], now: initial ? new Date(initial.generatedAt).getTime() : 0 }) });

  const load = useCallback(
    async (r: TrafficRange, withLive: boolean) => {
      try {
        const fresh = await api.firewallStats.overview({ range: r, timeZone: browserZone(), withLive });
        // A refresh that left with the old range keeps the chart the person has picked since.
        setView((v) => ({
          ...fresh,
          traffic: fresh.traffic.range === rangeRef.current || !v ? fresh.traffic : v.traffic,
          live: withLive || !v ? fresh.live : v.live,
        }));
        setError(false);
      } catch (err) {
        console.error("firewallStats.overview failed", err);
        setError(true);
      }
    },
    [api],
  );

  useEffect(() => {
    if (!live || !canManage) return;
    void load(rangeRef.current, true);
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void load(rangeRef.current, false);
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, [live, canManage, load]);

  const changeRange = async (r: TrafficRange) => {
    rangeRef.current = r;
    setRange(r);
    if (!live) {
      if (demoTraffic) setView((v) => (v ? { ...v, traffic: { range: r, points: demoTraffic(r) } } : v));
      return;
    }
    if (!view) return;
    setLoadingRange(true);
    try {
      const traffic = await api.firewallStats.traffic({ range: r });
      // Only the answer for the range still picked: a quicker click may have moved on.
      if (traffic.range === rangeRef.current) setView((v) => (v ? { ...v, traffic } : v));
    } catch (err) {
      console.error("firewallStats.traffic failed", err);
    } finally {
      setLoadingRange(false);
    }
  };

  if (!canManage) return null;
  if (!view) {
    return (
      <div className="mt-[18px] flex flex-col gap-3.5" data-testid="firewall-overview-loading" aria-busy="true">
        {error ? (
          <p className="text-[13px] text-block-fg">Couldn’t load the overview. This page tries again in a minute.</p>
        ) : (
          <>
            <div className="grid grid-cols-1 gap-3 min-[460px]:grid-cols-2 lg:grid-cols-4">
              {[0, 1, 2, 3].map((i) => (
                <div key={i} className="h-[140px] animate-pulse rounded-[14px] border border-line bg-bg-2" />
              ))}
            </div>
            <div className="h-[290px] animate-pulse rounded-[14px] border border-line bg-bg-2" />
          </>
        )}
      </div>
    );
  }

  const now = new Date(view.generatedAt).getTime();
  return (
    <div className="mt-[18px] flex flex-col gap-3.5" data-testid="firewall-overview">
      {!view.running ? (
        <p className="rounded-[12px] border border-ask-border bg-ask-soft px-4 py-2.5 text-[13px] text-ask-fg" data-testid="firewall-overview-off">
          The firewall isn’t running, so no traffic comes through. Start it to see traffic.
        </p>
      ) : null}
      <StatCards view={view} />
      <TrafficChart points={view.traffic.points} range={range} onRange={(r) => void changeRange(r)} loading={loadingRange} now={now} />
      {/* Stretched rows: Most used rules is as tall as Live requests, its rows sharing the height. */}
      {hasRules ? (
        <div className="grid grid-cols-1 gap-3.5 xl:grid-cols-2">
          <LiveRequests initial={view.live} live={live} off={!view.running} />
          <MostUsedRules data={rules.day} error={rules.dayError} />
        </div>
      ) : (
        <LiveRequests initial={view.live} live={live} off={!view.running} />
      )}
      <AiFindings enabled={view.ai.enabled} findings={view.ai.findings} now={now} hrefs={routes} />
      <div className="grid grid-cols-1 items-start gap-3.5 xl:grid-cols-2">
        <TopHosts hosts={view.topHosts} hrefs={routes} />
        <ByAgent agents={view.byAgent} hrefs={routes} />
      </div>
      {hasRules ? (
        <SecurityRulesSection data={rules.section} error={rules.sectionError} range={rules.range} onRange={rules.setRange} running={view.running} ruleCount={allRulesCount(view.shields, rules.fw.apps)} />
      ) : null}
      {shields ? (
        <Sec title="Protected services" sub="Configure each service’s protection and security rules" className="mt-6">
          <Shields counts={view.shields} hrefs={routes} />
        </Sec>
      ) : null}
    </div>
  );
}
