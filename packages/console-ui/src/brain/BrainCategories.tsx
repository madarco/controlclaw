"use client";

import { cn } from "../lib/utils";
import { Card } from "../kit/console-ui";
import { kindColour } from "../lib/brain-kinds";
import type { CategoryItem } from "../lib/brain-stats";

/**
 * "What it knows": GBrain's page types as tiles, biggest first, with their share. A tile filters
 * the feed beside it; clicking it again, or Show all, clears the filter.
 */

export function BrainCategories({
  total,
  items,
  selected,
  onSelect,
  counting,
}: {
  /** The brain's page count, as in the hero (a page with no type is in no tile). */
  total: number;
  items: CategoryItem[];
  selected: string | null;
  onSelect: (key: string | null) => void;
  /** No reading yet: the first count comes within 15 minutes of the brain starting. */
  counting: boolean;
}) {
  const biggest = Math.max(1, ...items.map((i) => i.count));
  return (
    <Card className="overflow-hidden" data-testid="brain-categories">
      <div className="flex items-center gap-2 border-b border-line px-3.5 py-3 text-[13.5px]">
        <b className="font-semibold text-ink">What it knows</b>
        {total > 0 ? <span className="text-[12.5px] text-ink-2">{total.toLocaleString("en-US")} pages</span> : null}
        <span className="flex-1" />
        {selected ? (
          <button type="button" className="text-[12.5px] font-semibold text-brand hover:underline" onClick={() => onSelect(null)} data-testid="brain-categories-all">
            Show all
          </button>
        ) : null}
      </div>
      {items.length === 0 ? (
        <p className="px-3.5 py-4 text-[13px] text-pretty text-ink-2" data-testid="brain-categories-empty">
          {counting ? "Counting pages. The first count is ready within 15 minutes." : "Nothing saved yet. Pages your agents save show up here by kind."}
        </p>
      ) : (
        <div className="grid grid-cols-2 gap-1.5 p-3 sm:grid-cols-3">
          {items.map((t) => {
            // A kind has the same colour here and on the brain's own pages.
            const colour = kindColour(t.key);
            const on = selected === t.key;
            return (
              <button
                key={t.key}
                type="button"
                aria-pressed={on}
                onClick={() => onSelect(on ? null : t.key)}
                data-testid={`brain-category-${t.key}`}
                style={{ "--c": colour } as React.CSSProperties}
                className={cn(
                  "flex min-h-[72px] min-w-0 flex-col justify-between gap-1.5 rounded-[10px] px-3 py-2.5 text-left transition-[opacity,transform] hover:-translate-y-px",
                  "shadow-[inset_0_0_0_1px_color-mix(in_oklch,var(--c)_22%,transparent)]",
                  on ? "bg-[var(--c)] text-surface" : "bg-[color-mix(in_oklch,var(--c)_14%,var(--surface))] text-ink",
                  selected && !on && "opacity-40",
                )}
              >
                <span className="truncate text-[13px] leading-tight font-semibold" title={t.label}>
                  {t.label}
                </span>
                <span
                  className={cn(
                    "flex justify-between gap-1.5 text-[12px] tabular-nums",
                    on ? "text-surface" : "text-[color-mix(in_oklch,var(--c)_70%,var(--ink))]",
                  )}
                >
                  {t.count.toLocaleString("en-US")}
                  <em className="not-italic opacity-75">{t.pct}%</em>
                </span>
                <span className={cn("block h-1 overflow-hidden rounded-full", on ? "bg-surface/30" : "bg-[color-mix(in_oklch,var(--c)_18%,transparent)]")}>
                  <i className={cn("block h-full rounded-full", on ? "bg-surface" : "bg-[var(--c)]")} style={{ width: `${(t.count / biggest) * 100}%` }} />
                </span>
              </button>
            );
          })}
        </div>
      )}
    </Card>
  );
}
