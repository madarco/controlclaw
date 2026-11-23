"use client";

import { SparkStatCard } from "../kit/charts";
import { formatBytes } from "../lib/format";
import type { BrainOverviewView } from "../lib/brain-stats";

/**
 * The Overview's four cards: Searches today, Saved today, Answer time (the median search today),
 * and Disk. A stopped brain shows zeros and dashes, as the design draws it.
 */
export function BrainCards({ view, running }: { view: BrainOverviewView; running: boolean }) {
  const zero = (d: number[]) => (running ? d : d.map(() => 0));
  const ms = running ? view.answerMs.today : null;
  return (
    <div className="mt-3.5 grid grid-cols-2 gap-3 lg:grid-cols-4" data-testid="brain-cards">
      <SparkStatCard
        label="Searches today"
        series={zero(view.searches.hourly)}
        hours={view.hours}
        today={running ? view.searches.today : 0}
        yesterday={running ? view.searches.yesterday : undefined}
        data-testid="brain-card-searches"
      />
      <SparkStatCard
        label="Saved today"
        tone="allow"
        series={zero(view.saves.hourly)}
        hours={view.hours}
        today={running ? view.saves.today : 0}
        yesterday={running ? view.saves.yesterday : undefined}
        data-testid="brain-card-saves"
      />
      <SparkStatCard
        label="Answer time"
        series={zero(view.answerMs.hourly)}
        hours={view.hours}
        value={ms === null ? "—" : `${ms.toLocaleString("en-US")} ms`}
        unit=" ms"
        data-testid="brain-card-answer"
      />
      <DiskCard latest={view.latest} />
    </div>
  );
}

function DiskCard({ latest }: { latest: BrainOverviewView["latest"] }) {
  const used = latest?.diskUsedBytes ?? null;
  const free = latest?.diskFreeBytes ?? null;
  const total = used !== null && free !== null ? used + free : null;
  const pct = total ? Math.min(100, (used! / total) * 100) : 0;
  // "Room for about 30× more": what is left over what is used, while that says something.
  const room = used && free !== null && used > 0 ? Math.floor(free / used) : null;
  return (
    <div className="flex h-[140px] flex-col rounded-[14px] border border-line bg-surface px-4 pt-3.5 pb-3" data-testid="brain-card-disk">
      <span className="text-[12.5px] text-ink-2">Disk</span>
      {total ? (
        <>
          <div className="mt-1.5 text-[22px] font-semibold tracking-[-0.02em] whitespace-nowrap tabular-nums text-ink">
            {formatBytes(used!)}
            <span className="ml-1 text-[13px] font-medium tracking-normal text-ink-2">/ {formatBytes(total)}</span>
          </div>
          <div
            className="mt-2.5 h-1.5 overflow-hidden rounded-full bg-muted-2"
            role="meter"
            aria-label="Disk used"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(pct)}
          >
            <span className={pct >= 90 ? "block h-full bg-block" : pct >= 75 ? "block h-full bg-ask" : "block h-full bg-brand"} style={{ width: `${Math.max(pct, 1)}%` }} />
          </div>
          <div className="mt-auto text-[12px] text-ink-2">
            {pct >= 90 ? "Almost full. Change the size in Settings." : room !== null && room >= 2 ? `Room for about ${room}× more` : `${Math.round(100 - pct)}% free`}
          </div>
        </>
      ) : (
        <>
          <div className="mt-1.5 text-[22px] font-semibold text-ink-2">—</div>
          <div className="mt-auto text-[12px] text-ink-2">Measured with the first count.</div>
        </>
      )}
    </div>
  );
}
