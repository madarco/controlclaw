"use client";

import { useEffect, useRef, useState } from "react";
import { Pause, Play } from "lucide-react";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Button } from "../../ui/button";
import { Card, CardHead, Pill } from "../../kit/console-ui";
import { HostIcon } from "../../kit/people";
import type { LiveRequest } from "../../lib/firewall-stats-schema";

/** How often the list asks for newer rows while visible and not paused. */
export const LIVE_POLL_MS = 3_000;
const SHOWN = 9;

const VERDICT: Record<LiveRequest["verdict"], { label: string; tone: "allow" | "ask" | "block" }> = {
  allowed: { label: "Allowed", tone: "allow" },
  asked: { label: "Asked", tone: "ask" },
  blocked: { label: "Blocked", tone: "block" },
};

/**
 * The newest requests through the firewall, one line each (the design's `FwlStream`). Rows reach
 * the console in the firewall's upload batches, so the list is a few seconds behind the traffic.
 * Polls for rows newer than the newest it holds every 3 s while the tab is visible; Pause stops it.
 * A tunnel or a request over 25 s (a long-poll, a websocket) shows "long" instead of a time.
 */
export function LiveRequests({
  initial,
  live = true,
  off,
}: {
  initial: readonly LiveRequest[];
  /** False on the demo page: nothing is polled. */
  live?: boolean;
  /** The firewall is not running: nothing new can come, so the dot is still and there is no Pause. */
  off?: boolean;
}) {
  const api = useApi();
  const [rows, setRows] = useState<LiveRequest[]>(() => initial.slice(0, SHOWN));
  const [paused, setPaused] = useState(false);
  const [fresh, setFresh] = useState<ReadonlySet<string>>(new Set());
  const rowsRef = useRef(rows);
  const cursor = useRef<string | undefined>(initial[0]?.createdAt);

  useEffect(() => {
    if (!live || paused || off) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;
    const tick = async () => {
      if (document.visibilityState === "visible") {
        try {
          const newer = await api.firewallStats.live({ after: cursor.current });
          if (!cancelled && newer.length > 0) {
            // The server looks back a little before the cursor (a batch can commit after one that
            // started later), so rows already shown come back and are dropped here by id.
            const prev = rowsRef.current;
            const have = new Set(prev.map((r) => r.id));
            const added = newer.filter((r) => !have.has(r.id));
            if (added.length > 0) {
              const next = [...added, ...prev]
                .sort((x, y) => y.createdAt.localeCompare(x.createdAt) || y.occurredAt.localeCompare(x.occurredAt))
                .slice(0, SHOWN);
              rowsRef.current = next;
              setFresh(new Set(added.map((r) => r.id)));
              setRows(next);
            }
            const newest = newer.reduce((m, r) => (r.createdAt > m ? r.createdAt : m), cursor.current ?? "");
            cursor.current = newest || undefined;
          }
        } catch (err) {
          console.error("firewallStats.live failed", err);
        }
      }
      if (!cancelled) timer = setTimeout(tick, LIVE_POLL_MS);
    };
    timer = setTimeout(tick, LIVE_POLL_MS);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [live, paused, off, api]);

  const still = paused || off;
  return (
    <Card className="overflow-hidden" data-testid="firewall-live">
      <CardHead
        title="Live requests"
        live={still ? "paused" : "live"}
        className="px-4 py-3 sm:px-5"
        right={
          off ? null : (
            <Button size="sm" variant="ghost" onClick={() => setPaused((p) => !p)} data-testid="firewall-live-pause">
              {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
              {paused ? "Resume" : "Pause"}
            </Button>
          )
        }
      />
      {rows.length === 0 ? (
        <p className="px-5 py-6 text-[13px] text-ink-2">{off ? "Start the firewall to see traffic." : "No requests in the last hour."}</p>
      ) : (
        <ul>
          {rows.map((r) => (
            <li
              key={r.id}
              className={cn(
                "grid grid-cols-[24px_minmax(0,1fr)_auto] items-center gap-2.5 border-t border-line px-4 py-2 text-[12.5px] first:border-t-0 sm:grid-cols-[24px_minmax(0,1fr)_auto_56px_auto] sm:px-5",
                fresh.has(r.id) && "motion-safe:animate-in motion-safe:fade-in motion-safe:slide-in-from-top-1 motion-safe:duration-500",
              )}
            >
              <HostIcon host={r.host} />
              <span className={cn("min-w-0 truncate font-mono text-[12px]", r.verdict === "blocked" ? "text-block-fg" : "text-ink")} title={r.host}>
                <span className="inline-block min-w-[38px] text-[10.5px] text-ink-2">{r.method ?? (r.long ? "TUN" : "")}</span>
                {r.host}
              </span>
              <span className="hidden max-w-[140px] truncate text-[12px] text-ink-2 sm:block">{r.agent ?? "Firewall"}</span>
              <span className="hidden text-right font-mono text-[11px] text-ink-2 sm:block">
                {r.verdict === "blocked" ? "—" : r.long ? "long" : r.durationMs !== null ? `${r.durationMs}ms` : "—"}
              </span>
              <Pill tone={VERDICT[r.verdict].tone}>{VERDICT[r.verdict].label}</Pill>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
