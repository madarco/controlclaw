"use client";

import { useId, useState } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "../../lib/utils";
import { Card, Segmented } from "../../kit/console-ui";
import type { TrafficPoint, TrafficRange } from "../../lib/firewall-stats";

/**
 * Requests over time (the design's `FwlTraffic`): allowed as a line with a soft fill, the busiest
 * "asked you" buckets as amber dots on it, blocked as red bars in their own band under the axis,
 * so a spike of refusals never hides under the allowed curve. Hand-written SVG like the kit's
 * sparkline: the band under the axis is not a shape a chart library draws without fighting it.
 */

const W = 720;
const H = 200;
const TOP = 140;
const GAP = 14;
const BAND = H - TOP - GAP;
const ASK_MARKS = 5;

const RANGES: ReadonlyArray<{ value: TrafficRange; label: string }> = [
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

/** A Catmull-Rom curve through the points, as the design draws it. */
function smooth(p: ReadonlyArray<[number, number]>): string {
  return p.reduce((d, pt, i) => {
    if (i === 0) return `M${pt[0].toFixed(1)} ${pt[1].toFixed(1)}`;
    const p0 = p[i - 2] ?? p[i - 1]!;
    const p1 = p[i - 1]!;
    const p3 = p[i + 1] ?? pt;
    const c1 = [p1[0] + (pt[0] - p0[0]) / 6, p1[1] + (pt[1] - p0[1]) / 6];
    const c2 = [pt[0] - (p3[0] - p1[0]) / 6, pt[1] - (p3[1] - p1[1]) / 6];
    return `${d} C${c1[0]!.toFixed(1)} ${c1[1]!.toFixed(1)} ${c2[0]!.toFixed(1)} ${c2[1]!.toFixed(1)} ${pt[0].toFixed(1)} ${pt[1].toFixed(1)}`;
  }, "");
}

/** "12m ago", "5h ago", "3d ago", from a bucket's start. */
function agoLabel(at: string, range: TrafficRange, now: number): string {
  const ms = Math.max(0, now - new Date(at).getTime());
  if (range === "1h") return `${Math.round(ms / 60_000)}m ago`;
  if (range === "24h") return `${Math.round(ms / 3_600_000)}h ago`;
  return `${Math.round(ms / 86_400_000)}d ago`;
}

const fmt = (n: number) => n.toLocaleString("en-US");

export function TrafficChart({
  points,
  range,
  onRange,
  loading,
  now,
}: {
  points: readonly TrafficPoint[];
  range: TrafficRange;
  onRange: (r: TrafficRange) => void;
  loading?: boolean;
  /** For the "ago" labels; the server's `generatedAt`, so server and client agree. */
  now: number;
}) {
  const gradient = `fw${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const [hover, setHover] = useState<number | null>(null);
  const n = Math.max(2, points.length);
  const maxA = Math.max(1, ...points.map((p) => p.allowed)) * 1.12;
  const maxB = Math.max(1, ...points.map((p) => p.blocked));
  const x = (i: number) => (i / (n - 1)) * W;
  const y = (v: number) => TOP - (v / maxA) * (TOP - 8);
  const line = smooth(points.map((p, i) => [x(i), y(p.allowed)]));
  const barW = (W / n) * 0.62;
  const asked = new Set(
    points
      .map((p, i) => [p.asked, i] as const)
      .filter(([a]) => a > 0)
      .sort((a, b) => b[0] - a[0])
      .slice(0, ASK_MARKS)
      .map(([, i]) => i),
  );
  const totals = points.reduce((t, p) => ({ allowed: t.allowed + p.allowed, asked: t.asked + p.asked, blocked: t.blocked + p.blocked }), { allowed: 0, asked: 0, blocked: 0 });
  const shown = hover !== null && points[hover] ? points[hover] : totals;
  const empty = totals.allowed + totals.asked + totals.blocked === 0;

  return (
    <Card className="px-4 pt-3.5 pb-3 sm:px-5" data-testid="firewall-traffic">
      <div className="mb-3 flex flex-wrap items-center gap-x-3 gap-y-2">
        <dl className="flex flex-wrap gap-x-6 gap-y-1">
          {(
            [
              ["Requests", shown.allowed + shown.asked + shown.blocked, null],
              ["Allowed", shown.allowed, "bg-allow"],
              ["Asked you", shown.asked, "bg-ask"],
              ["Blocked", shown.blocked, "bg-block"],
            ] as const
          ).map(([k, v, dot]) => (
            <div key={k} className="flex flex-col">
              <dt className="flex items-center gap-1.5 text-[11.5px] text-ink-2">
                {dot ? <i className={cn("h-2 w-2 rounded-full", dot)} /> : null}
                {k}
              </dt>
              <dd className="text-[20px] font-semibold tracking-[-0.02em] tabular-nums text-ink">{fmt(v)}</dd>
            </div>
          ))}
        </dl>
        <span className="flex-1" />
        {hover !== null && points[hover] ? <span className="text-[12px] text-ink-2">{agoLabel(points[hover]!.at, range, now)}</span> : null}
        {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin text-ink-2" aria-label="Loading" /> : null}
        <Segmented size="sm" value={range} options={RANGES} onChange={onRange} data-testid="firewall-traffic-range" />
      </div>
      <div className="relative">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={`Requests over the last ${range}: ${fmt(totals.allowed)} allowed, ${fmt(totals.asked)} asked you, ${fmt(totals.blocked)} blocked`}
          className="block h-[200px] w-full cursor-crosshair overflow-visible"
          onMouseMove={(e) => {
            const b = e.currentTarget.getBoundingClientRect();
            setHover(Math.max(0, Math.min(n - 1, Math.round(((e.clientX - b.left) / b.width) * (n - 1)))));
          }}
          onMouseLeave={() => setHover(null)}
        >
          <defs>
            <linearGradient id={gradient} x1="0" x2="0" y1="0" y2="1">
              <stop offset="0" stopColor="var(--allow)" stopOpacity="0.28" />
              <stop offset="1" stopColor="var(--allow)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[0.33, 0.66].map((g) => (
            <line key={g} x1="0" x2={W} y1={TOP * g} y2={TOP * g} stroke="var(--line)" strokeDasharray="3 4" vectorEffect="non-scaling-stroke" />
          ))}
          <line x1="0" x2={W} y1={TOP} y2={TOP} stroke="var(--line-2)" vectorEffect="non-scaling-stroke" />
          {points.length > 1 ? (
            <>
              <path d={`${line} L${W} ${TOP} L0 ${TOP}Z`} fill={`url(#${gradient})`} />
              <path d={line} fill="none" stroke="var(--allow)" strokeWidth="2" strokeLinejoin="round" vectorEffect="non-scaling-stroke" />
            </>
          ) : null}
          {points.map((p, i) =>
            p.blocked > 0 ? (
              <rect
                key={p.at}
                x={x(i) - barW / 2}
                y={TOP + GAP}
                width={barW}
                height={Math.max(2, Math.sqrt(p.blocked / maxB) * BAND)}
                rx="1.5"
                fill="var(--block)"
                opacity={hover === null || hover === i ? 0.85 : 0.35}
              />
            ) : null,
          )}
          {hover !== null ? (
            <line x1={x(hover)} x2={x(hover)} y1="0" y2={H} stroke="var(--ink)" strokeOpacity="0.35" strokeDasharray="3 3" vectorEffect="non-scaling-stroke" />
          ) : null}
        </svg>
        {/* Dots as HTML over the stretched SVG, so they stay round at any width. */}
        {points.map((p, i) =>
          asked.has(i) ? (
            <span
              key={`a${p.at}`}
              aria-hidden="true"
              className="pointer-events-none absolute -mt-[3.5px] -ml-[3.5px] h-[7px] w-[7px] rounded-full border-[1.5px] border-surface bg-ask shadow-[0_0_0_1px_var(--ask)]"
              style={{ left: `${(x(i) / W) * 100}%`, top: `${(y(p.allowed) / H) * 100}%` }}
            />
          ) : null,
        )}
        {hover !== null && points[hover] ? (
          <span
            aria-hidden="true"
            className="pointer-events-none absolute -mt-1.5 -ml-1.5 h-3 w-3 rounded-full border-[2.5px] border-allow bg-surface shadow-[0_2px_6px_rgba(0,0,0,.15)]"
            style={{ left: `${(x(hover) / W) * 100}%`, top: `${(y(points[hover]!.allowed) / H) * 100}%` }}
          />
        ) : null}
        <span
          className="pointer-events-none absolute right-0 -translate-y-3.5 text-[10.5px] font-semibold tracking-[0.04em] text-block-fg uppercase"
          style={{ top: `${((TOP + GAP) / H) * 100}%` }}
        >
          Blocked
        </span>
        {empty ? (
          <span className="pointer-events-none absolute inset-x-0 top-[30%] text-center text-[13px] text-ink-2">No requests in this range.</span>
        ) : null}
      </div>
      <div className="mt-1.5 flex justify-between text-[11px] text-ink-2">
        <span>{points[0] ? agoLabel(points[0].at, range, now) : ""}</span>
        <span>{points[Math.floor(n / 2)] ? agoLabel(points[Math.floor(n / 2)]!.at, range, now) : ""}</span>
        <span className="font-semibold text-ink">Now</span>
      </div>
    </Card>
  );
}
