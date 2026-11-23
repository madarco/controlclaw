"use client";

import { Bot, Layers } from "lucide-react";
import { Card, LiveDot } from "../kit/console-ui";
import { Avatar } from "../kit/people";
import { changesLine, type BrainFeedItem } from "../lib/brain-stats";
import { ago } from "./useBrainOverview";

/**
 * "Just learned", without page text (owner, 2026-10-23): who saved how much, and how the counts
 * per kind moved between two readings. Newest first.
 */
export function BrainFeed({
  items,
  category,
  now,
  live,
}: {
  items: BrainFeedItem[];
  /** The selected tile's name, when the feed is filtered to it. */
  category: string | null;
  now: number;
  live: boolean;
}) {
  return (
    <Card className="flex flex-col overflow-hidden" data-testid="brain-feed">
      <div className="flex items-center gap-2 border-b border-line px-3.5 py-3 text-[13.5px]">
        <LiveDot paused={!live} />
        <b className="font-semibold text-ink">Just learned</b>
        {category ? <span className="truncate text-[12.5px] text-ink-2">· {category}</span> : null}
      </div>
      {items.length === 0 ? (
        <p className="px-3.5 py-4 text-[13px] text-ink-2" data-testid="brain-feed-empty">
          {category ? `No change in ${category} this week.` : "Nothing saved this week."}
        </p>
      ) : (
        <ul className="divide-y divide-line">
          {items.map((f) => {
            const when = ago(f.at, now);
            const fresh = now - Date.parse(f.at) < 60_000;
            return (
              <li
                key={f.id}
                className={
                  "grid grid-cols-[52px_24px_minmax(0,1fr)_auto] items-center gap-2.5 px-3.5 py-2.5" + (fresh ? " bg-brand-soft" : "")
                }
                data-testid="brain-feed-row"
              >
                <span className="font-mono text-[11px] whitespace-nowrap text-ink-2">{when === "just now" ? "now" : when?.replace(" ago", "")}</span>
                {f.kind === "saves" ? (
                  f.agentName ? (
                    <Avatar name={f.agentName} size={24} />
                  ) : (
                    <span className="grid h-6 w-6 place-items-center rounded-full bg-bg-2 text-ink-2">
                      <Bot className="h-3.5 w-3.5" />
                    </span>
                  )
                ) : (
                  <span className="grid h-6 w-6 place-items-center rounded-full bg-brand-soft text-brand">
                    <Layers className="h-3.5 w-3.5" />
                  </span>
                )}
                <div className="min-w-0">
                  {f.kind === "saves" ? (
                    // The name gives way on a narrow screen; the count never does.
                    <div className="flex min-w-0 gap-1 text-[13px] text-ink">
                      <b className="min-w-0 truncate font-semibold">{f.agentName ?? f.clientName ?? "A deleted agent"}</b>
                      <span className="shrink-0 whitespace-nowrap">saved {f.count === 1 ? "once" : `${f.count} times`}</span>
                    </div>
                  ) : (
                    <div className="text-[13px] text-pretty text-ink">{changesLine(f.changes)}</div>
                  )}
                </div>
                {f.kind === "saves" ? (
                  <span className="rounded-full bg-allow-soft px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap text-allow-fg">Saved</span>
                ) : f.changes.every((c) => c.delta < 0) ? (
                  <span className="rounded-full bg-ask-soft px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap text-ask-fg">Removed</span>
                ) : (
                  <span className="rounded-full bg-brand-soft px-2 py-0.5 text-[11px] font-semibold whitespace-nowrap text-brand-soft-fg">Learned</span>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
