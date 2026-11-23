"use client";

import { useEffect, useMemo, useState } from "react";
import { filterFeed, foldCategories, type BrainOverviewView } from "../lib/brain-stats";
import { BrainCards } from "./BrainCards";
import { BrainCategories } from "./BrainCategories";
import { BrainFeed } from "./BrainFeed";
import { BrainGrowth } from "./BrainGrowth";

/**
 * The Brain page's Overview tab (docs/plans/brain-overview-charts.md): four cards, what it knows
 * by kind beside what was just saved, and the last 30 days. Counts and GBrain's type names only;
 * no page text and no search text reaches the console. Not built (owner, 2026-10-23): the Ask box
 * and "Agents disagree"; GBrain's own admin page (Open) has search.
 */
export function BrainOverview({
  view,
  running,
  live = true,
}: {
  /** Null while the first read is on its way. */
  view: BrainOverviewView | null;
  /** The brain's service is up. A stopped brain shows zeros. */
  running: boolean;
  live?: boolean;
}) {
  const [category, setCategory] = useState<string | null>(null);
  // The relative times in the feed move on without a new read.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, [live]);

  const { total, items } = useMemo(() => foldCategories(view?.latest?.byType ?? {}), [view?.latest?.byType]);
  // A tile that went away with a new count clears the filter rather than hiding the whole feed.
  const selected = category && items.some((i) => i.key === category) ? category : null;
  const feed = useMemo(() => filterFeed(view?.feed ?? [], selected, items), [view?.feed, selected, items]);

  if (!view) {
    return (
      <div className="mt-3.5 grid grid-cols-2 gap-3 lg:grid-cols-4" aria-busy="true" data-testid="brain-overview-loading">
        {[0, 1, 2, 3].map((k) => (
          <div key={k} className="h-[140px] animate-pulse rounded-[14px] border border-line bg-bg-2" />
        ))}
      </div>
    );
  }

  return (
    <div data-testid="brain-overview">
      <BrainCards view={view} running={running} />
      <div className="mt-3.5 grid items-start gap-3.5 lg:grid-cols-2">
        <BrainCategories total={view.latest?.pageCount ?? total} items={items} selected={selected} onSelect={setCategory} counting={running && !view.latest} />
        <BrainFeed items={feed} category={selected ? (items.find((i) => i.key === selected)?.label ?? null) : null} now={now} live={live && running} />
      </div>
      <BrainGrowth days={view.growth} />
    </div>
  );
}
