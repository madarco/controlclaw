"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AppLink as Link } from "../../lib/link";
import { Globe, Mail, MessageSquare, Plug, Plus, Shield, ShieldCheck, SquareTerminal, UserCheck } from "lucide-react";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { ActionMenu, Card, CardHead, Segmented } from "../../kit/console-ui";
import { RULE_TYPES, RULE_TYPE_LABELS, type RuleType } from "../../lib/security-rules-list";
import { agoShort, foldNamedApps, type RuleOverviewItem, type RuleSort } from "../../lib/rule-metrics";
import { useRoutes } from "../../lib/routes";
import {
  RULE_CAT_LABELS,
  catTotals,
  enrichRules,
  mainOutcome,
  mostUsed,
  outcomePills,
  outcomeTotals,
  sectionRules,
  shownCats,
  type FirewallRules,
  type RuleCat,
  type ShownRule,
} from "../../lib/rule-overview";

/** How often the counts are read again while the tab is visible, as the rest of the Overview. */
const REFRESH_MS = 60_000;
/** A rule that matched this recently gets the green "just now" dot. */
const LIVE_S = 60;

export type RuleRange = "24h" | "7d";

/** The demo page's data, in place of the RPCs. */
export interface DemoRules {
  items: (range: RuleRange) => RuleOverviewItem[];
  firewall?: FirewallRules;
  now: number;
}

const TYPE_ICON: Record<RuleType, typeof Globe> = { messages: MessageSquare, email: Mail, websites: Globe, apps: Plug, auto: UserCheck };
const CAT_ICON: Record<RuleCat, typeof Globe> = { ...TYPE_ICON, mcp: SquareTerminal };
const CAT_TONE: Record<RuleCat, string> = {
  websites: "bg-[color-mix(in_oklch,var(--kind-web)_14%,transparent)] text-kind-web",
  email: "bg-brand-soft text-brand-soft-fg",
  apps: "bg-[color-mix(in_oklch,var(--kind-meeting)_14%,transparent)] text-kind-meeting",
  mcp: "bg-bg-2 text-ink-2",
  messages: "bg-[color-mix(in_oklch,var(--kind-call)_14%,transparent)] text-kind-call",
  auto: "bg-[color-mix(in_oklch,var(--kind-email)_16%,transparent)] text-kind-email",
};
const PILL_TONE: Record<string, string> = {
  allowed: "bg-allow-soft text-allow-fg",
  asked: "bg-ask-soft text-ask-fg",
  held: "bg-ask-soft text-ask-fg",
  blocked: "bg-block-soft text-block-fg",
  recorded: "bg-bg-2 text-ink-2",
};
const SPARK_FILL = { allow: "fill-allow", ask: "fill-ask", block: "fill-block", neutral: "fill-ink-2" } as const;

const n = (v: number) => v.toLocaleString("en-US");

type Loaded = { items: RuleOverviewItem[]; now: number };

/**
 * The counts for "Most used rules" (always 24 hours) and the "Security rules" section (24 hours or 7
 * days), read once a minute while the tab is visible. The firewall's Integrations rules (the Apps /
 * MCP tools split, the descriptions, the count of rules) and, when one of them matched, its Messages
 * rules are read with the counts until the firewall has answered; the server asks nothing of a
 * stopped firewall and shares an answer for 30 seconds. With `demo` nothing is called.
 */
export function useRuleOverview({ live, demo }: { live: boolean; demo?: DemoRules }) {
  const api = useApi();
  const [data, setData] = useState<Partial<Record<RuleRange, Loaded>>>(() => (demo ? { "24h": { items: demo.items("24h"), now: demo.now }, "7d": { items: demo.items("7d"), now: demo.now } } : {}));
  const [errors, setErrors] = useState<Partial<Record<RuleRange, boolean>>>({});
  const [range, setRangeState] = useState<RuleRange>("24h");
  const [fw, setFw] = useState<FirewallRules>(demo?.firewall ?? { apps: null, content: null });
  const rangeRef = useRef(range);
  const fwRef = useRef(fw);
  const reading = useRef(false);

  // Until the firewall has answered: a read that got nothing (stopped, timed out) is tried again with the next counts.
  const readFirewall = useCallback(async (items: RuleOverviewItem[]) => {
    const messages = !fwRef.current.content && items.some((i) => i.type === "messages");
    if (reading.current || (fwRef.current.apps && !messages)) return;
    reading.current = true;
    try {
      if (!api.ruleMetrics) return;
      const res = await api.ruleMetrics.firewallRules({ messages });
      const next = { apps: res.apps ?? fwRef.current.apps, content: res.content ?? fwRef.current.content };
      fwRef.current = next;
      setFw(next);
    } catch (err) {
      console.error("ruleMetrics.firewallRules failed", err);
    } finally {
      reading.current = false;
    }
  }, [api]);

  const load = useCallback(
    async (r: RuleRange) => {
      if (!api.ruleMetrics) return;
      try {
        const res = await api.ruleMetrics.overview({ range: r });
        setData((d) => ({ ...d, [r]: { items: res.items, now: new Date(res.generatedAt).getTime() } }));
        setErrors((e) => ({ ...e, [r]: false }));
        void readFirewall(res.items);
      } catch (err) {
        console.error("ruleMetrics.overview failed", err);
        setErrors((e) => ({ ...e, [r]: true }));
      }
    },
    [readFirewall, api],
  );

  useEffect(() => {
    if (!live || demo) return;
    void load("24h");
    const t = setInterval(() => {
      if (document.visibilityState !== "visible") return;
      void load("24h");
      if (rangeRef.current !== "24h") void load(rangeRef.current);
    }, REFRESH_MS);
    return () => clearInterval(t);
  }, [live, demo, load]);

  const setRange = (r: RuleRange) => {
    rangeRef.current = r;
    setRangeState(r);
    if (live && !demo && r !== "24h") void load(r);
  };

  const shown = useCallback(
    (r: RuleRange): { rules: ShownRule[]; now: number } | null => {
      const d = data[r];
      if (!d) return null;
      return { rules: enrichRules(fw.apps ? foldNamedApps(d.items, fw.apps) : d.items, fw), now: d.now };
    },
    [data, fw],
  );
  return {
    day: useMemo(() => shown("24h"), [shown]),
    section: useMemo(() => shown(range), [shown, range]),
    range,
    setRange,
    dayError: !!errors["24h"],
    sectionError: !!errors[range],
    fw,
  };
}

function RuleIcon({ cat, size = "md" }: { cat: RuleCat; size?: "sm" | "md" }) {
  const Icon = CAT_ICON[cat];
  return (
    <span className={cn("grid shrink-0 place-items-center", size === "sm" ? "h-[22px] w-[22px] rounded-[6px]" : "h-[26px] w-[26px] rounded-[7px]", CAT_TONE[cat])}>
      <Icon className={size === "sm" ? "h-[13px] w-[13px]" : "h-[15px] w-[15px]"} />
    </span>
  );
}

/** A row or card that opens the rule on Security rules; a deleted rule has nothing to open. */
function RuleLink({ rule, className, children, testId }: { rule: ShownRule; className: string; children: React.ReactNode; testId: string }) {
  const routes = useRoutes();
  const title = `${RULE_CAT_LABELS[rule.cat]} · ${rule.detail}`;
  if (rule.deleted) {
    return (
      <div className={className} title={title} data-testid={testId}>
        {children}
      </div>
    );
  }
  return (
    <Link href={routes.rule(rule)} className={className} title={title} data-testid={testId} aria-label={rule.builtin ? `${RULE_TYPE_LABELS[rule.type]} rules: ${rule.name}` : `Open ${rule.name}`}>
      {children}
    </Link>
  );
}

/**
 * "Most used rules", beside Live requests: the busiest rules of the last 24 hours, how often each
 * fired and how often it blocked. Rows grow to fill the card, so it is as tall as Live requests.
 */
export function MostUsedRules({ data, error }: { data: { rules: ShownRule[] } | null; error: boolean }) {
  const routes = useRoutes();
  const rows = data ? mostUsed(data.rules) : [];
  return (
    <Card className="flex flex-col overflow-hidden" data-testid="most-used-rules">
      <CardHead
        icon={Shield}
        title={
          <span className="flex items-baseline gap-2">
            Most used rules <span className="text-[12px] font-normal text-ink-2">24h</span>
          </span>
        }
        className="px-4 py-3 sm:px-5"
        right={
          <Link href={routes.security} className="text-[13px] text-brand hover:underline" data-testid="most-used-rules-all">
            All rules →
          </Link>
        }
      />
      {data === null ? (
        error ? (
          <p className="px-5 py-4 text-[13px] text-block-fg">Couldn’t load the rule counts. This page tries again in a minute.</p>
        ) : (
          <div className="space-y-2 px-5 py-4" aria-busy="true">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-8 animate-pulse rounded-[8px] bg-bg-2" />
            ))}
          </div>
        )
      ) : rows.length === 0 ? (
        <p className="px-5 py-6 text-[13px] text-ink-2" data-testid="most-used-rules-empty">
          No rule has acted in the last 24 hours.
        </p>
      ) : (
        <>
          <div className="grid grid-cols-[22px_minmax(0,1fr)_52px_56px] gap-2.5 bg-bg-2 px-4 py-1.5 text-[11px] font-medium text-ink-2 sm:px-5">
            <span />
            <span>Rule</span>
            <span className="text-right">Fired</span>
            <span className="text-right">Blocked</span>
          </div>
          {rows.map((r) => (
            <RuleLink
              key={`${r.type}:${r.key}`}
              rule={r}
              testId={`most-used-${r.type}-${r.key}`}
              className="grid flex-1 grid-cols-[22px_minmax(0,1fr)_52px_56px] items-center gap-2.5 border-t border-line px-4 py-[7px] text-[12.5px] hover:bg-bg-2 sm:px-5"
            >
              <RuleIcon cat={r.cat} size="sm" />
              <span className="flex min-w-0 items-baseline gap-2 whitespace-nowrap">
                <b className={cn("min-w-0 truncate font-semibold", r.deleted || r.builtin ? "text-ink-2" : "text-ink")}>{r.name}</b>
                <span className="hidden shrink-0 text-[11.5px] text-ink-2 min-[420px]:inline">{r.deleted ? "deleted" : RULE_CAT_LABELS[r.cat]}</span>
              </span>
              <span className="text-right font-semibold tabular-nums">{n(r.total)}</span>
              <span className={cn("text-right tabular-nums", r.counts.blocked ? "font-semibold text-block-fg" : "text-ink-2")}>{r.counts.blocked ? n(r.counts.blocked) : "—"}</span>
            </RuleLink>
          ))}
        </>
      )}
    </Card>
  );
}

function Spark({ rule }: { rule: ShownRule }) {
  const max = Math.max(1, ...rule.series);
  const fill = SPARK_FILL[mainOutcome(rule.counts)];
  return (
    <svg className={cn("h-[22px] w-[96px] shrink-0 opacity-75", fill)} viewBox="0 0 96 22" preserveAspectRatio="none" aria-hidden="true">
      {rule.series.map((v, i) => {
        const h = v > 0 ? Math.max(1.5, (v / max) * 22) : 0;
        return <rect key={i} x={i * 4 + 0.5} width="3" y={22 - h} height={h} rx="1" />;
      })}
    </svg>
  );
}

function OutcomeBar({ rule }: { rule: ShownRule }) {
  const c = rule.counts;
  return (
    <span className="mt-1 flex h-2 w-full gap-[2px] overflow-hidden rounded-full bg-bg-2">
      <i className="min-w-0 bg-allow" style={{ flex: c.allowed }} />
      <i className="min-w-0 bg-ask" style={{ flex: c.asked + c.held }} />
      <i className="min-w-0 bg-block" style={{ flex: c.blocked }} />
    </span>
  );
}

function Pills({ rule }: { rule: ShownRule }) {
  return (
    <span className="mt-1 flex flex-wrap gap-[5px]">
      {outcomePills(rule.counts).map((p) => (
        <span key={p.outcome} className={cn("rounded-full px-2 py-0.5 text-[11.5px] font-semibold whitespace-nowrap tabular-nums", PILL_TONE[p.outcome])}>
          {n(p.n)} {p.label}
        </span>
      ))}
    </span>
  );
}

function RuleCard({ rule, now }: { rule: ShownRule; now: number }) {
  const ago = (now - new Date(rule.lastAt).getTime()) / 1000;
  const fresh = ago < LIVE_S;
  return (
    <RuleLink
      rule={rule}
      testId={`security-rule-card-${rule.type}-${rule.key}`}
      className="flex min-w-0 flex-col gap-1.5 rounded-[12px] border border-line bg-surface p-3.5 text-left transition-[border-color,box-shadow] hover:border-line-2 hover:shadow-[0_4px_14px_rgba(0,0,0,0.06)]"
    >
      <span className="flex items-center gap-2">
        <RuleIcon cat={rule.cat} />
        <span className="text-[11.5px] font-semibold tracking-[0.04em] text-ink-2 uppercase">{RULE_CAT_LABELS[rule.cat]}</span>
        <span className="flex-1" />
        <span className={cn("inline-flex items-center gap-[5px] text-[11.5px] whitespace-nowrap", fresh ? "font-semibold text-allow-fg" : "text-ink-2")}>
          {fresh ? <i className="h-1.5 w-1.5 rounded-full bg-allow motion-safe:animate-pulse" /> : null}
          {now ? agoShort(rule.lastAt, now) : "—"}
        </span>
      </span>
      <span className={cn("mt-1 truncate text-[14.5px] leading-[1.3] font-semibold", rule.deleted || rule.builtin ? "text-ink-2" : "text-ink")}>
        {rule.name}
        {rule.deleted ? <span className="font-normal"> · deleted</span> : null}
      </span>
      <span className="line-clamp-2 min-h-[34px] text-[12.5px] leading-[1.35] text-pretty text-ink-2">{rule.detail}</span>
      <span className="mt-1 flex items-end gap-[5px]">
        <b className="text-[28px] leading-none font-semibold tracking-[-0.03em] tabular-nums">{n(rule.total)}</b>
        <span className="pb-[3px] text-[12px] text-ink-2">{rule.total === 1 ? "time" : "times"}</span>
        <span className="flex-1" />
        <Spark rule={rule} />
      </span>
      <OutcomeBar rule={rule} />
      <Pills rule={rule} />
    </RuleLink>
  );
}

/**
 * "Security rules", at the bottom of the Firewall page's Overview: how often the rules stepped in,
 * what they decided, a tab per kind (Integrations split into Apps and MCP tools), and a card for
 * each of the top three rules. A card opens the rule on Security rules.
 */
export function SecurityRulesSection({
  data,
  error,
  range,
  onRange,
  running,
  ruleCount,
}: {
  data: { rules: ShownRule[]; now: number } | null;
  error: boolean;
  range: RuleRange;
  onRange: (r: RuleRange) => void;
  /** The firewall is up: the badge pulses. */
  running: boolean;
  /** Every rule Security rules lists, or null when part of it is unknown. */
  ruleCount: number | null;
}) {
  const routes = useRoutes();
  const [cat, setCat] = useState<RuleCat | "all">("all");
  const [sort, setSort] = useState<RuleSort>("active");
  const rules = data?.rules ?? [];
  const totals = outcomeTotals(rules);
  const perCat = catTotals(rules);
  const cats = shownCats(perCat);
  const tab = cat !== "all" && !cats.includes(cat) ? "all" : cat;
  const cards = sectionRules(rules, tab, sort);
  const when = range === "24h" ? "today" : "this week";

  return (
    <Card className="@container overflow-hidden" data-testid="security-rules-section">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-3 bg-gradient-to-b from-bg-2 to-transparent px-4 pt-4 pb-3.5 sm:px-5">
        <div className="flex min-w-0 flex-[1_1_260px] items-center gap-3">
          <span className="relative grid h-[38px] w-[38px] shrink-0 place-items-center rounded-[11px] bg-ink text-surface">
            <ShieldCheck className="h-[18px] w-[18px]" />
            {running ? <span className="absolute -inset-[3px] rounded-[13px] border-2 border-ink/25 motion-safe:animate-pulse" /> : null}
          </span>
          <div className="min-w-0">
            <h2 className="m-0 text-[17px] font-semibold tracking-[-0.01em] text-ink">Security rules</h2>
            <p className="m-0 mt-0.5 text-[13px] text-ink-2" data-testid="security-rules-line">
              {totals.total > 0 ? (
                <>
                  Your rules acted <b className="text-ink tabular-nums">{n(totals.total)}</b> {totals.total === 1 ? "time" : "times"} {when}.
                </>
              ) : (
                `Your rules have not acted ${when}.`
              )}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {(
            [
              ["blocked", totals.blocked, "bg-block-soft text-block-fg"],
              ["asked you", totals.asked, "bg-ask-soft text-ask-fg"],
              ["allowed", totals.allowed, "bg-allow-soft text-allow-fg"],
            ] as const
          ).map(([label, v, tone]) => (
            <div key={label} className={cn("flex min-w-[84px] flex-col rounded-[10px] px-3 py-1.5 sm:min-w-[92px] sm:px-3.5 sm:py-2", tone)}>
              <b className="text-[20px] leading-[1.1] font-semibold tracking-[-0.02em] tabular-nums sm:text-[22px]">{n(v)}</b>
              <span className="text-[11.5px] font-medium">{label}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-y border-line px-4 py-2.5 sm:px-5">
        <div className="flex flex-wrap gap-1" role="tablist" aria-label="Kind of rule">
          {(["all", ...cats] as const).map((c) => {
            const on = tab === c;
            const Icon = c === "all" ? null : CAT_ICON[c];
            return (
              <button
                key={c}
                type="button"
                role="tab"
                aria-selected={on}
                onClick={() => setCat(c)}
                data-testid={`security-rules-tab-${c}`}
                className={cn(
                  "inline-flex h-[30px] items-center gap-1.5 rounded-full px-[11px] text-[12.5px] font-medium whitespace-nowrap transition-colors",
                  on ? "bg-ink text-surface" : "text-ink-2 hover:bg-bg-2 hover:text-ink",
                )}
              >
                {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
                {c === "all" ? "All rules" : RULE_CAT_LABELS[c]}
                {c === "all" ? null : <span className={cn("text-[11px] tabular-nums", on ? "opacity-70" : "text-ink-2")}>{n(perCat[c])}</span>}
              </button>
            );
          })}
        </div>
        <span className="flex-1" />
        <div className="flex flex-wrap items-center gap-2">
          <Segmented
            size="sm"
            value={sort}
            onChange={setSort}
            options={[
              { value: "active", label: "Most active", "data-testid": "security-rules-active" },
              { value: "latest", label: "Latest", "data-testid": "security-rules-latest" },
            ]}
          />
          <Segmented size="sm" value={range} onChange={onRange} options={[{ value: "24h", label: "24h" }, { value: "7d", label: "7d", "data-testid": "security-rules-7d" }]} />
        </div>
      </div>

      {data === null ? (
        error ? (
          <p className="px-5 py-4 text-[13px] text-block-fg">Couldn’t load the rule counts. This page tries again in a minute.</p>
        ) : (
          <div className="grid grid-cols-1 gap-3 px-4 py-4 sm:px-5 @3xl:grid-cols-3" aria-busy="true">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-[190px] animate-pulse rounded-[12px] bg-bg-2" />
            ))}
          </div>
        )
      ) : !rules.some((r) => r.total > 0) ? (
        <EmptyRules range={range} />
      ) : cards.length === 0 ? (
        <p className="px-5 py-5 text-[13px] text-ink-2" data-testid="security-rules-tab-empty">
          No {tab === "all" ? "" : `${RULE_CAT_LABELS[tab]} `}rule acted {range === "24h" ? "in the last 24 hours" : "in the last 7 days"}.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-3 px-4 py-4 sm:px-5 @3xl:grid-cols-3">
          {cards.map((r) => (
            <RuleCard key={`${r.type}:${r.key}`} rule={r} now={data.now} />
          ))}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-t border-line px-4 py-3 text-[13px] sm:px-5">
        <Link href={routes.security} className="text-brand hover:underline" data-testid="security-rules-all">
          {ruleCount === null ? "All rules →" : `All ${n(ruleCount)} ${ruleCount === 1 ? "rule" : "rules"} →`}
        </Link>
        <span className="text-[12.5px] text-ink-2">Rules that never match are listed there too.</span>
        <span className="ml-auto">
          <ActionMenu
            icon={Plus}
            label="New rule"
            ariaLabel="New rule"
            data-testid="security-rules-new"
            items={RULE_TYPES.map((t) => ({ label: `${RULE_TYPE_LABELS[t]} rule`, icon: TYPE_ICON[t], href: routes.newRule(t), "data-testid": `security-rules-new-${t}` }))}
          />
        </span>
      </div>
    </Card>
  );
}

/** Nothing matched in the range: a new organization, or a quiet one. One way in per type. */
function EmptyRules({ range }: { range: RuleRange }) {
  const routes = useRoutes();
  return (
    <div className="px-4 py-4 sm:px-5" data-testid="security-rules-empty">
      <p className="m-0 text-[13px] text-ink-2">
        No rule has matched anything {range === "24h" ? "in the last 24 hours" : "in the last 7 days"}. Add one to decide what your agents may send, reach and do.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {RULE_TYPES.map((t) => {
          const Icon = TYPE_ICON[t];
          return (
            <Link key={t} href={routes.newRule(t)} className="inline-flex h-8 items-center gap-1.5 rounded-[9px] border border-line bg-surface px-2.5 text-[12.5px] font-medium text-ink hover:border-line-2">
              <Icon className="h-3.5 w-3.5 text-ink-2" />
              {RULE_TYPE_LABELS[t]}
            </Link>
          );
        })}
      </div>
    </div>
  );
}

