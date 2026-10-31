"use client";

import { useId, useState } from "react";
import { cn } from "../lib/utils";
import { changeLabel, changePct } from "../lib/stats";

/**
 * The small charts of Console v3: a sparkline, mini bars, the stat card that carries a sparkline,
 * and a list of horizontal bars. Hand-written SVG, no chart library: they are a line or a row of
 * rectangles, and `recharts` is kept for the two charts that need axes (the Firewall's traffic,
 * the Brain's growth). Colours come from the theme tokens, so dark mode needs nothing here.
 */

export type ChartTone = "brand" | "allow" | "ask" | "block" | "muted";

const TONE_TEXT: Record<ChartTone, string> = {
  brand: "text-brand",
  allow: "text-allow",
  ask: "text-ask",
  block: "text-block",
  muted: "text-ink-2/50",
};

const TONE_BG: Record<ChartTone, string> = {
  brand: "bg-brand",
  allow: "bg-allow",
  ask: "bg-ask",
  block: "bg-block",
  muted: "bg-ink-2/50",
};

type Point = [x: number, y: number];

/** The sparkline's drawing box; it stretches to its element, so only the ratio matters. */
const W = 220;
const H = 56;
/** Room at each end, so the dot on the last point is not cut by the card's edge. */
const PAD_X = 6;

/**
 * Where each value sits in a `w` × `h` box, leaving `pad` at the top and bottom. The lowest value
 * sits a little above the floor (the design's `min * 0.8`), so a busy day's line does not look
 * empty; an all-zero series is a flat line on the floor. With two values or fewer the floor is zero
 * and the highest sits at 80%. A null value (no sample: the agent was off) has no point, and the
 * line has a gap there.
 */
export function sparkPoints(data: readonly (number | null)[], w: number, h: number, padX = 0, padY = 4): (Point | null)[] {
  const values = data.length === 1 ? [data[0]!, data[0]!] : data.length === 0 ? [0, 0] : data;
  const known = values.filter((v): v is number => v !== null);
  // Two values or fewer (a new agent's first points, one point between gaps) say nothing about a
  // range: lifting the floor to `min * 0.8` stretched them into a stroke the height of the card.
  // They sit on a zero floor with room above instead.
  const sparse = known.length <= 2;
  const max = known.length ? Math.max(...known) * (sparse ? 1.25 : 1) : 0;
  const min = known.length && !sparse ? Math.min(...known) * 0.8 : 0;
  const range = max - min || 1;
  return values.map((v, i) =>
    v === null ? null : [padX + (i / (values.length - 1)) * (w - 2 * padX), h - padY - ((v - min) / range) * (h - 2 * padY - 2)],
  );
}

/** The runs of points between gaps. */
function segments(points: (Point | null)[]): Point[][] {
  const out: Point[][] = [[]];
  for (const p of points) {
    if (p) out[out.length - 1]!.push(p);
    else if (out[out.length - 1]!.length) out.push([]);
  }
  return out.filter((s) => s.length > 0);
}

function linePath(points: Point[]): string {
  // A lone point between two gaps is drawn as a dot-length line, so it does not vanish.
  const pts = points.length === 1 ? [points[0]!, [points[0]![0] + 0.5, points[0]![1]] as Point] : points;
  return pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`).join(" ");
}

/** The newest point at or before `i`: where the dot goes when `i` itself has no value. */
function pointAt(points: (Point | null)[], i: number): Point | undefined {
  for (let j = Math.min(i, points.length - 1); j >= 0; j--) if (points[j]) return points[j]!;
  return undefined;
}

/**
 * A line with a soft fill under it. Stretches to its box (`className` sets the size). With
 * `onHover`, it reports the index under the pointer and draws a guide at `active`.
 */
export function Sparkline({
  data,
  tone = "brand",
  fill = true,
  active,
  onHover,
  className,
  "aria-label": ariaLabel,
}: {
  /** null: no value there; the line has a gap. */
  data: readonly (number | null)[];
  tone?: ChartTone;
  fill?: boolean;
  /** The index to mark with a dashed guide (the hovered hour). */
  active?: number | null;
  onHover?: (index: number | null) => void;
  className?: string;
  "aria-label"?: string;
}) {
  // React's ids carry characters `url(#…)` does not take.
  const id = `spark${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const points = sparkPoints(data, W, H, PAD_X);
  const runs = segments(points);
  const line = runs.map(linePath).join(" ");
  const guideX = active != null && data.length > 0 ? PAD_X + (active / Math.max(1, data.length - 1)) * (W - 2 * PAD_X) : undefined;
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      className={cn("block h-14 w-full overflow-visible", TONE_TEXT[tone], onHover && "cursor-crosshair", className)}
      onMouseMove={
        onHover
          ? (e) => {
              const b = e.currentTarget.getBoundingClientRect();
              const last = Math.max(0, data.length - 1);
              const i = Math.round(((e.clientX - b.left) / b.width) * last);
              onHover(Math.max(0, Math.min(last, i)));
            }
          : undefined
      }
      onMouseLeave={onHover ? () => onHover(null) : undefined}
    >
      {fill ? (
        <>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor="currentColor" stopOpacity="0.22" />
              <stop offset="1" stopColor="currentColor" stopOpacity="0" />
            </linearGradient>
          </defs>
          {runs.map((run, i) => (
            <path key={i} d={`${linePath(run)} L${run[run.length - 1]![0]} ${H} L${run[0]![0]} ${H} Z`} fill={`url(#${id})`} />
          ))}
        </>
      ) : null}
      <path
        d={line}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
      {guideX !== undefined ? (
        <line
          x1={guideX}
          x2={guideX}
          y1="0"
          y2={H}
          stroke="currentColor"
          strokeOpacity="0.35"
          strokeDasharray="2 2"
          vectorEffect="non-scaling-stroke"
        />
      ) : null}
    </svg>
  );
}

/**
 * A row of bars, one per value (an agent's last hours on the Firewall's "By agent" list). `off`
 * draws them as a flat floor, for an agent that is not running.
 */
export function MiniBars({
  data,
  tone = "brand",
  off,
  className,
  "aria-label": ariaLabel,
}: {
  data: readonly number[];
  tone?: ChartTone;
  off?: boolean;
  className?: string;
  "aria-label"?: string;
}) {
  const BAR_H = 20;
  const n = Math.max(1, data.length);
  const slot = 100 / n;
  const max = Math.max(1, ...data);
  return (
    <svg
      viewBox={`0 0 100 ${BAR_H}`}
      preserveAspectRatio="none"
      role={ariaLabel ? "img" : undefined}
      aria-label={ariaLabel}
      aria-hidden={ariaLabel ? undefined : true}
      className={cn("block h-5 w-[100px]", TONE_TEXT[off ? "muted" : tone], className)}
    >
      {data.map((v, i) => {
        const h = off ? 1 : (v / max) * (BAR_H - 3) + (v > 0 ? 2 : 1);
        return <rect key={i} x={i * slot + slot * 0.1} width={slot * 0.8} y={BAR_H - h} height={h} rx="1" fill="currentColor" opacity="0.7" />;
      })}
    </svg>
  );
}

/**
 * A number with its change against yesterday and a 24-hour sparkline (the design's `LvSpark`).
 * Hovering the line shows that hour's value in place of the total.
 */
export function SparkStatCard({
  label,
  value,
  unit,
  series,
  hours,
  today,
  yesterday,
  upIsBad,
  tone = "brand",
  format = (n) => Math.round(n).toLocaleString("en-US"),
  className,
  "data-testid": testId,
}: {
  label: string;
  /** The headline; defaults to `today` formatted. */
  value?: React.ReactNode;
  unit?: string;
  /** One value per hour (or per slot of `hours`), oldest first; null where nothing is known. */
  series: readonly (number | null)[];
  /** ISO hour starts matching `series`, for the hover readout ("at 14:00"). */
  hours?: readonly string[];
  /** With `yesterday`, makes the change badge. No badge when yesterday is 0 or either is missing. */
  today?: number;
  yesterday?: number;
  /** For counts where more is worse (Blocked): an increase is red instead of green. */
  upIsBad?: boolean;
  tone?: ChartTone;
  format?: (n: number) => string;
  className?: string;
  "data-testid"?: string;
}) {
  const [hover, setHover] = useState<number | null>(null);
  const pct = today !== undefined && yesterday !== undefined ? changePct(today, yesterday) : null;
  const badge = changeLabel(pct);
  const points = sparkPoints(series, W, H, PAD_X);
  const marker = hover != null ? (points[hover] ?? undefined) : pointAt(points, points.length - 1);
  const at = hover != null && hours?.[hover] ? hourLabel(hours[hover]!) : null;
  const hovered = hover != null ? series[hover] : undefined;
  const shown = hover != null ? (hovered === null ? "–" : `${format(hovered ?? 0)}${unit ?? ""}`) : (value ?? `${format(today ?? 0)}${unit ?? ""}`);
  return (
    <div
      data-testid={testId}
      className={cn("flex h-[140px] flex-col overflow-hidden rounded-[14px] border border-line bg-surface px-4 pt-3.5", className)}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-[12.5px] text-ink-2">{label}</span>
        {badge ? (
          <span
            className={cn(
              "shrink-0 rounded-full px-[7px] py-0.5 text-[11.5px] font-semibold tabular-nums",
              pct! > 0 ? (upIsBad ? "bg-block-soft text-block-fg" : "bg-allow-soft text-allow-fg") : "bg-bg-2 text-ink-2",
            )}
            title="Compared with yesterday at this time"
          >
            {badge}
          </span>
        ) : null}
      </div>
      <div className="mt-0.5 min-h-[34px] text-[26px] font-semibold tracking-[-0.02em] whitespace-nowrap tabular-nums text-ink" aria-live="polite">
        {shown}
        {at ? <small className="ml-1 text-[12px] font-medium tracking-normal text-ink-2">at {at}</small> : null}
      </div>
      <div className="relative -mx-4 mt-auto h-14">
        <Sparkline data={series} tone={tone} active={hover} onHover={setHover} className="h-full" />
        {marker ? (
          <span
            aria-hidden="true"
            className={cn("pointer-events-none absolute h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-[3px] ring-surface", TONE_BG[tone])}
            style={{ left: `${(marker[0] / W) * 100}%`, top: `${(marker[1] / H) * 100}%` }}
          />
        ) : null}
      </div>
    </div>
  );
}

/** "14:00" in the reader's own time. */
function hourLabel(iso: string): string {
  return new Date(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

export type HBarItem = {
  key: string;
  label: React.ReactNode;
  /** Left of the label: a host icon, an avatar. */
  lead?: React.ReactNode;
  value: number;
  /** The part of `value` drawn red after the rest (blocked requests). */
  blocked?: number;
  /** Monospace label (hosts, paths). */
  mono?: boolean;
  title?: string;
};

/**
 * A ranked list of horizontal bars: label, bar, count (the design's `fwl-bar`: top sites, agents
 * by requests, channels by messages). Bars are scaled to the largest value in the list.
 */
export function HBarList({
  items,
  tone = "allow",
  format = (n) => n.toLocaleString("en-US"),
  empty,
  className,
  "data-testid": testId,
}: {
  items: readonly HBarItem[];
  tone?: ChartTone;
  format?: (n: number) => string;
  /** Shown instead of the list when it has no items. */
  empty?: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  if (items.length === 0) return empty ? <div className="px-5 py-4 text-[13px] text-ink-2">{empty}</div> : null;
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul data-testid={testId} className={cn("flex flex-col py-1.5", className)}>
      {items.map((i) => {
        const blocked = Math.min(i.blocked ?? 0, i.value);
        return (
          <li
            key={i.key}
            title={i.title}
            className="grid grid-cols-[24px_minmax(0,110px)_minmax(0,1fr)_46px] items-center gap-2.5 px-3.5 py-[7px] text-[12.5px] sm:grid-cols-[24px_minmax(0,150px)_minmax(0,1fr)_46px] sm:px-5"
          >
            <span className="grid h-6 w-6 place-items-center">{i.lead}</span>
            <span className={cn("truncate text-ink", i.mono && "font-mono text-[11.5px]")}>{i.label}</span>
            <span className="flex h-2 overflow-hidden rounded-full bg-muted-2" aria-hidden="true">
              <span className={cn("h-full", TONE_BG[tone])} style={{ width: `${((i.value - blocked) / max) * 100}%` }} />
              {blocked > 0 ? <span className="h-full bg-block" style={{ width: `${(blocked / max) * 100}%` }} /> : null}
            </span>
            <span className="text-right font-semibold tabular-nums text-ink">
              {format(i.value)}
              {blocked > 0 ? <span className="sr-only">, {format(blocked)} blocked</span> : null}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
