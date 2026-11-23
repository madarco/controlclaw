"use client";

import { useId, useState } from "react";
import { Area, Bar, ComposedChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card } from "../kit/console-ui";
import type { BrainGrowthDay } from "../lib/brain-stats";

/**
 * "Memory over 30 days": the brain's pages at each day's last count (the line) and what agents
 * saved each day (the bars along the bottom). Days before the first count have no line. Hovering
 * a day shows its numbers in the header.
 */
export function BrainGrowth({ days }: { days: BrainGrowthDay[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const gradient = `brainGrowth${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  const n = days.length;
  const i = hover ?? n - 1;
  const day = days[i];
  const pages = days.map((d) => d.pages).filter((p): p is number => p !== null);
  const maxSaves = Math.max(1, ...days.map((d) => d.saves));
  const lo = pages.length ? Math.min(...pages) : 0;
  const hi = pages.length ? Math.max(...pages) : 1;
  // The line fills the top of the chart and the bars the bottom fifth, as drawn.
  const pad = Math.max(1, (hi - lo) * 0.1);
  const pageDomain: [number, number] = [Math.max(0, lo - pad - (hi - lo + pad) * 0.35), hi + pad];
  const saveDomain: [number, number] = [0, maxSaves * 4.5];
  const daysAgo = n - 1 - i;

  return (
    <Card className="mt-3.5 overflow-hidden" data-testid="brain-growth">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-b border-line px-3.5 py-3 text-[13.5px]">
        <b className="font-semibold text-ink">Memory over 30 days</b>
        <span className="flex-1" />
        {day ? (
          <span className="text-[12.5px] text-ink-2 tabular-nums" aria-live="polite">
            {daysAgo === 0 ? "Today" : daysAgo === 1 ? "Yesterday" : `${daysAgo} days ago`}
            {day.pages !== null ? (
              <>
                {" · "}
                <b className="font-semibold text-ink">{day.pages.toLocaleString("en-US")}</b> pages
              </>
            ) : null}
            {" · "}+{day.saves.toLocaleString("en-US")} saved
          </span>
        ) : null}
      </div>
      {n === 0 ? (
        <p className="px-3.5 py-4 text-[13px] text-ink-2">Nothing yet. The line starts with the first count of pages.</p>
      ) : (
        <div className="px-3.5 pt-3 pb-2.5">
          <div className="h-[154px] w-full cursor-crosshair" role="img" aria-label="Pages in the brain and saves per day over the last 30 days">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart
                data={days}
                margin={{ top: 4, right: 0, bottom: 0, left: 0 }}
                barCategoryGap="22%"
                onMouseMove={(s) => {
                  const idx = s?.activeTooltipIndex;
                  setHover(idx == null ? null : Number(idx));
                }}
                onMouseLeave={() => setHover(null)}
              >
                <defs>
                  <linearGradient id={gradient} x1="0" x2="0" y1="0" y2="1">
                    <stop offset="0" stopColor="var(--brand)" stopOpacity={0.22} />
                    <stop offset="1" stopColor="var(--brand)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="day" hide />
                <YAxis yAxisId="pages" hide domain={pageDomain} />
                <YAxis yAxisId="saves" hide domain={saveDomain} />
                <Tooltip content={() => null} cursor={{ stroke: "var(--ink)", strokeOpacity: 0.3, strokeDasharray: "3 3" }} />
                <Bar yAxisId="saves" dataKey="saves" isAnimationActive={false} radius={[2, 2, 0, 0]} fill="var(--brand)" fillOpacity={0.3} activeBar={{ fillOpacity: 0.9 }} />
                <Area
                  yAxisId="pages"
                  dataKey="pages"
                  type="monotone"
                  isAnimationActive={false}
                  connectNulls={false}
                  stroke="var(--brand)"
                  strokeWidth={2}
                  fill={`url(#${gradient})`}
                  // One count so far is one point: a line of one point draws nothing.
                  dot={pages.length === 1 ? { r: 3.5, fill: "var(--brand)", stroke: "var(--surface)", strokeWidth: 2 } : false}
                  activeDot={{ r: 3.5, fill: "var(--brand)", stroke: "var(--surface)", strokeWidth: 2 }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-1.5 flex justify-between text-[11px] text-ink-2">
            <span>30 days ago</span>
            <span>Saved each day</span>
            <span className="font-semibold text-ink">Today</span>
          </div>
          {pages.length === 0 ? <p className="mt-2 text-[12.5px] text-ink-2">The line starts with the first count of pages.</p> : null}
        </div>
      )}
    </Card>
  );
}
