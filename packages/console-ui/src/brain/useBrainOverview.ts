"use client";

import { useCallback, useEffect, useState } from "react";
import { useOptionalApi } from "../lib/api";
import type { BrainOverviewView } from "../lib/brain-stats";

/** Calls arrive every 10 s and counts every 15 minutes; a minute is as fresh as the cards need. */
const POLL_MS = 60_000;

/** The reader's time zone, so "today" is their day. */
function timeZone(): string | undefined {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return undefined;
  }
}

/**
 * The Overview's numbers, read once and then every minute while the page is open and visible.
 * `live={false}` (the demo) keeps `initial` and never calls the server. `boxId` is the brain's
 * machine: the numbers are kept with it, and nothing is read while there is none.
 */
export function useBrainOverview(initial: BrainOverviewView | null, live: boolean, boxId: string | null): BrainOverviewView | null {
  // Kept with the box it was read for: a brain deleted and created again on the same page must not
  // show the old one's numbers until the next read.
  const [read, setRead] = useState<{ boxId: string; view: BrainOverviewView } | null>(null);
  const brain = useOptionalApi()?.brain;

  const load = useCallback(async (forBox: string) => {
    if (!brain) return;
    try {
      const view = await brain.overview({ timeZone: timeZone() });
      setRead({ boxId: forBox, view });
    } catch {
      // A failed read keeps the last numbers; the next tick tries again.
    }
  }, [brain]);

  useEffect(() => {
    if (!live || !boxId) return;
    const first = setTimeout(() => void load(boxId), 0);
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void load(boxId);
    }, POLL_MS);
    return () => {
      clearTimeout(first);
      clearInterval(t);
    };
  }, [live, boxId, load]);

  if (!live) return initial;
  return read && read.boxId === boxId ? read.view : null;
}

/** "just now", "4m ago", "3h ago", "2d ago". */
export function ago(iso: string | null, now = Date.now()): string | null {
  if (!iso) return null;
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86_400)}d ago`;
}
