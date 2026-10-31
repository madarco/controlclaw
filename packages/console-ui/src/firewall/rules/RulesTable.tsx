"use client";

import type { ReactNode } from "react";
import { cn } from "../../lib/utils";
import type { RuleTone, RuleType } from "../../lib/rule-types";
import { lastMatched, outcomeLine, ruleLine, type RuleActivityItem } from "../../lib/rule-metrics";

/**
 * The tables on Security rules (theme/v3/p-security.jsx): a header row, one row per rule, and a grey
 * built-in row at the end for what happens when no rule matches. Each tab has its own columns. On a
 * phone the header goes, the cells stack under the rule's name and the row's controls stay at the
 * top right.
 */

export const COLS = {
  messages: "md:grid-cols-[minmax(0,2fr)_minmax(0,1.1fr)_130px_92px]",
  websites: "md:grid-cols-[24px_minmax(0,2fr)_minmax(0,1fr)_130px_112px]",
  apps: "md:grid-cols-[24px_minmax(0,1.6fr)_minmax(0,1.3fr)_minmax(0,0.9fr)_110px_112px]",
  auto: "md:grid-cols-[24px_minmax(0,2fr)_minmax(0,1.2fr)_130px_92px]",
  email: "md:grid-cols-[minmax(0,1fr)_auto]",
} as const;

export type Cols = keyof typeof COLS;

const TONE: Record<RuleTone, string> = {
  allow: "border-allow-border bg-allow-soft text-allow-fg",
  ask: "border-ask-border bg-ask-soft text-ask-fg",
  block: "border-block-border bg-block-soft text-block-fg",
  neutral: "border-line bg-bg-2 text-ink-2",
};

/** What a rule does: Allow, Ask, Block, Stop, Hold. A button where a tap cycles it. */
export function ActionPill({ tone, children, onClick, title, testId }: { tone: RuleTone; children: ReactNode; onClick?: () => void; title?: string; testId?: string }) {
  const pill = (
    <span className={cn("inline-flex h-[28px] items-center rounded-full border px-3 text-[12px] font-semibold whitespace-nowrap", TONE[tone], onClick && "hover:opacity-80")}>
      {children}
    </span>
  );
  if (!onClick) return <span data-testid={testId}>{pill}</span>;
  return (
    <button type="button" onClick={onClick} title={title} data-testid={testId} className="cursor-pointer">
      {pill}
    </button>
  );
}

export function TRow({
  cols,
  head,
  builtin,
  off,
  className,
  children,
  "data-testid": testId,
}: {
  cols: Cols;
  head?: boolean;
  /** The grey row at the end: what happens when no rule matches. */
  builtin?: boolean;
  off?: boolean;
  className?: string;
  children: ReactNode;
  "data-testid"?: string;
}) {
  return (
    <div
      role="row"
      data-testid={testId}
      className={cn(
        "grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1.5 border-b border-line px-4 py-3 last:border-b-0",
        COLS[cols],
        head && "hidden bg-bg-2 py-2 text-[12px] font-semibold text-ink-2 md:grid",
        builtin && "bg-bg-2",
        off && "[&>*:not([data-acts])]:opacity-50",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** The order number of a rule read first match first. Not on a phone. */
export function Ord({ children }: { children?: ReactNode }) {
  return <span className="hidden text-[12px] text-ink-2 tabular-nums md:block">{children}</span>;
}

/** The rule's name and a line under it. */
export function Main({ title, sub, mono, builtin }: { title: ReactNode; sub?: ReactNode; mono?: boolean; builtin?: boolean }) {
  return (
    <div className="col-start-1 grid min-w-0 gap-0.5 md:col-auto">
      <b
        className={cn(
          "inline-flex flex-wrap items-center gap-1.5 [overflow-wrap:anywhere]",
          mono ? "font-mono text-[13px] font-medium" : "text-[13.5px] font-semibold",
          builtin ? "font-medium text-ink-2" : "text-ink",
        )}
      >
        {title}
      </b>
      {sub ? <small className="text-[12.5px] leading-[1.4] text-ink-2 [overflow-wrap:anywhere]">{sub}</small> : null}
    </div>
  );
}

export function Cell({ children, sub }: { children?: ReactNode; sub?: ReactNode }) {
  return (
    <div className="col-start-1 grid min-w-0 justify-items-start gap-[3px] text-[13px] text-ink md:col-auto">
      {children}
      {sub ? <small className="text-[12.5px] leading-[1.4] text-ink-2 [overflow-wrap:anywhere]">{sub}</small> : null}
    </div>
  );
}

/** The row's controls: at the top right on a phone, the last column from `md`. */
export function Acts({ children }: { children?: ReactNode }) {
  return (
    <div data-acts className="col-start-2 row-start-1 flex items-center justify-end gap-1.5 md:col-auto md:row-auto">
      {children}
    </div>
  );
}

export function EmptyLine({ children }: { children: ReactNode }) {
  return <p className="m-0 border-b border-line px-4 py-4 text-[13px] text-ink-2 last:border-b-0">{children}</p>;
}

/**
 * How often a rule matched in the last 7 days and when (docs/plans/rule-metrics.md), under its
 * action: "12 in 7 days · 2 h ago", with what happened on hover. Nothing while the counts load or
 * when it did not match.
 */
export function Hits({ item, now, type, block, testId }: { item: RuleActivityItem | undefined; now: number; type: RuleType; block?: boolean; testId?: string }) {
  if (!now || !item || item.total === 0) return null;
  // Two lines: the narrow Then column would otherwise break the line in the middle of the time.
  return (
    <span title={`${ruleLine(type, item, now)}: ${outcomeLine(type, item.counts)}`} data-testid={testId} className={block ? "block" : undefined}>
      {item.total.toLocaleString("en-US")} in 7 days
      <span className="block">{lastMatched(item.lastAt, now)}</span>
    </span>
  );
}
