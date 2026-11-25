"use client";

import { cn } from "../lib/utils";

/**
 * Shared pieces of the pages a box serves itself (`/__cc/*`): the agent's (Meetings, Calls, Files,
 * Logs, Screen, WhatsApp), in the look of `theme/Agent Pages.html`, and the firewall's React pages
 * (Logs, Doctor start). Its vanilla twin for the pages the firewall draws without React is
 * `rust/bins/mitm-agent/src/core/fw_kit.js`: change the classes of both together. Both box stylesheet
 * builds (`apps/saas/scripts/build-box-files.mjs`, `apps/firewall-panel/scripts/build-fw-files.mjs`)
 * scan this file.
 */

/** A page's title and line, with its own buttons at the end. */
export function BoxPageHead({ title, sub, children, className }: { title: string; sub?: React.ReactNode; children?: React.ReactNode; className?: string }) {
  return (
    <div className={cn("mb-5 flex flex-wrap items-end gap-x-4 gap-y-3", className)}>
      <div className="min-w-0 flex-1 basis-[280px]">
        <h1 className="text-[24px] font-semibold tracking-[-0.02em] text-ink">{title}</h1>
        {sub ? <p className="mt-1 text-[13.5px] text-pretty text-ink-2">{sub}</p> : null}
      </div>
      {children ? <div className="flex flex-wrap items-center gap-2">{children}</div> : null}
    </div>
  );
}

/** The page's column inside the shell's main panel. */
export function BoxPageBody({ children, wide, className }: { children: React.ReactNode; wide?: boolean; className?: string }) {
  return <div className={cn("mx-auto w-full min-w-0 px-4 pt-6 pb-16 md:px-9 md:pt-8", wide ? "max-w-[1180px]" : "max-w-[1100px]", className)}>{children}</div>;
}

export type StatTone = "brand" | "allow" | "ask" | "block";
const STAT_TONE: Record<StatTone, string> = { brand: "text-brand", allow: "text-allow-fg", ask: "text-ask-fg", block: "text-block-fg" };

/** One number with its label and a note under it. */
export function StatTile({ label, value, sub, tone, className }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: StatTone; className?: string }) {
  return (
    <div className={cn("min-w-0 p-4", className)}>
      <div className="text-[12.5px] text-ink-2">{label}</div>
      <div className={cn("mt-1 text-[24px] leading-tight font-semibold tracking-[-0.02em] tabular-nums", tone ? STAT_TONE[tone] : "text-ink")}>{value}</div>
      {sub ? <div className="mt-0.5 text-[12px] text-ink-2">{sub}</div> : null}
    </div>
  );
}

/** Stat tiles in a bordered grid: two across on a phone, `cols` from `sm` up. */
export function StatGrid({ children, cols = 4, className }: { children: React.ReactNode; cols?: 2 | 3 | 4; className?: string }) {
  return (
    <div
      className={cn(
        "grid grid-cols-2 overflow-hidden rounded-xl border border-line bg-surface [&>*]:border-line [&>*:nth-child(2n)]:border-l [&>*:nth-child(n+3)]:border-t",
        cols === 3 && "sm:grid-cols-3 sm:[&>*]:border-t-0 sm:[&>*]:border-l sm:[&>*:first-child]:border-l-0",
        cols === 4 && "sm:grid-cols-4 sm:[&>*]:border-t-0 sm:[&>*]:border-l sm:[&>*:first-child]:border-l-0",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** The heading of one day's rows in a list ("Today 2"). */
export function DayHeading({ label, count }: { label: string; count?: number }) {
  return (
    <div className="border-y border-line bg-bg-2 px-4 py-1.5 text-[11.5px] font-semibold tracking-[0.06em] text-ink-2 uppercase">
      {label}
      {count !== undefined ? <span className="ml-2 font-medium tabular-nums">{count}</span> : null}
    </div>
  );
}

const DAY = 86_400_000;

function startOfDay(t: number): number {
  const d = new Date(t);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** "Today", "Yesterday", or "Sunday 22 Nov", in the browser's own time zone. */
export function dayLabel(at: number, now: number = Date.now()): string {
  const diff = Math.round((startOfDay(now) - startOfDay(at)) / DAY);
  if (diff === 0) return "Today";
  if (diff === 1) return "Yesterday";
  return new Date(at).toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short", ...(diff > 300 ? { year: "numeric" } : {}) });
}

/** Rows grouped by day, newest day first if the rows are; the order inside each day is kept. */
export function groupByDay<T>(rows: T[], at: (row: T) => number, now: number = Date.now()): { label: string; rows: T[] }[] {
  const out: { label: string; key: number; rows: T[] }[] = [];
  for (const row of rows) {
    const key = startOfDay(at(row));
    const last = out.find((g) => g.key === key);
    if (last) last.rows.push(row);
    else out.push({ label: dayLabel(at(row), now), key, rows: [row] });
  }
  return out.map(({ label, rows }) => ({ label, rows }));
}

/** "45s", "12m 05s", "1h 20m". */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  return `${Math.floor(s / 3600)}h ${Math.round((s % 3600) / 60)}m`;
}

/** "HH:MM" in the browser's time zone. */
export function clockTime(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** Up to two initials of a name, "(guest)" and the like left out. */
export function initials(name: string): string {
  const words = name.replace(/\(.*?\)/g, "").trim().split(/[\s-]+/).filter(Boolean);
  return words.slice(0, 2).map((w) => [...w][0] ?? "").join("").toUpperCase() || "?";
}

/** A speaker's colour, fixed by name; the agent is always the brand colour. */
const SPEAKER_TONES = [
  "bg-[oklch(0.93_0.04_250)] text-[oklch(0.42_0.12_250)] dark:bg-[oklch(0.35_0.08_250)] dark:text-[oklch(0.9_0.05_250)]",
  "bg-[oklch(0.93_0.04_180)] text-[oklch(0.4_0.09_180)] dark:bg-[oklch(0.35_0.06_180)] dark:text-[oklch(0.9_0.05_180)]",
  "bg-[oklch(0.93_0.04_300)] text-[oklch(0.42_0.12_300)] dark:bg-[oklch(0.35_0.08_300)] dark:text-[oklch(0.9_0.05_300)]",
  "bg-[oklch(0.94_0.05_70)] text-[oklch(0.42_0.1_60)] dark:bg-[oklch(0.36_0.07_60)] dark:text-[oklch(0.9_0.06_70)]",
  "bg-[oklch(0.93_0.05_140)] text-[oklch(0.4_0.1_140)] dark:bg-[oklch(0.35_0.07_140)] dark:text-[oklch(0.9_0.06_140)]",
  "bg-[oklch(0.93_0.04_20)] text-[oklch(0.45_0.13_20)] dark:bg-[oklch(0.36_0.08_20)] dark:text-[oklch(0.9_0.05_20)]",
] as const;

export function speakerTone(name: string, isAgent = false): string {
  if (isAgent) return "bg-brand text-white";
  let sum = 0;
  for (const c of name) sum += c.codePointAt(0) ?? 0;
  return SPEAKER_TONES[sum % SPEAKER_TONES.length];
}

/** A round avatar with a speaker's initials, or the agent's mark. */
export function SpeakerAvatar({ name, isAgent, size = 28 }: { name: string; isAgent?: boolean; size?: 22 | 28 | 32 }) {
  const box = size === 22 ? "h-[22px] w-[22px] text-[9.5px]" : size === 32 ? "h-8 w-8 text-[11.5px]" : "h-7 w-7 text-[10.5px]";
  return (
    <span aria-hidden="true" className={cn("inline-grid shrink-0 place-items-center rounded-full font-semibold", box, speakerTone(name, isAgent))}>
      {isAgent ? (
        <svg viewBox="0 0 24 24" className="h-1/2 w-1/2" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 8V4H8" />
          <rect width="16" height="12" x="4" y="8" rx="2" />
          <path d="M2 14h2" />
          <path d="M20 14h2" />
          <path d="M15 13v2" />
          <path d="M9 13v2" />
        </svg>
      ) : (
        initials(name)
      )}
    </span>
  );
}
