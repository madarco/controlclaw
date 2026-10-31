"use client";

import { useEffect, useState } from "react";

function day(date: Date, now: number): string {
  const thisYear = new Date(now).getFullYear() === date.getFullYear();
  return date.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    ...(thisYear ? {} : { year: "numeric" }),
  });
}

/**
 * Both directions. A deadline is as ordinary a thing to render as a timestamp — when an invitation
 * expires, when a backup will be deleted — and clamping the difference at zero used to read every
 * one of them as "just now", which says the opposite of what is true.
 */
export function formatRelative(date: Date, now: number): string {
  const diffSec = Math.floor((now - date.getTime()) / 1000);
  if (diffSec < 0) {
    const ahead = -diffSec;
    if (ahead < 60) return "in a moment";
    if (ahead < 3600) return `in ${Math.floor(ahead / 60)}m`;
    if (ahead < 86_400) return `in ${Math.floor(ahead / 3600)}h`;
    if (ahead < 7 * 86_400) return `in ${Math.floor(ahead / 86_400)}d`;
    return day(date, now);
  }
  if (diffSec < 45) return "just now";
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86_400) return `${Math.floor(diffSec / 3600)}h ago`;
  if (diffSec < 7 * 86_400) return `${Math.floor(diffSec / 86_400)}d ago`;
  return day(date, now);
}

function formatAbsolute(date: Date): string {
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

interface RelativeTimeProps {
  date: Date | string;
  className?: string;
}

/** Renders a relative timestamp ("7m ago", "3h ago", "2d ago") that updates client-side every 30s.
 *
 * Timezone-safe (deltas are absolute) and hydration-safe via suppressHydrationWarning: the server
 * paints whatever it computes at request time, then the client recomputes from its own clock on
 * mount, so a slight server/client clock skew won't break the diff.
 */
export function RelativeTime({ date, className }: RelativeTimeProps) {
  const d = date instanceof Date ? date : new Date(date);
  const [text, setText] = useState(() => formatRelative(d, Date.now()));

  useEffect(() => {
    const update = () => setText(formatRelative(d, Date.now()));
    update();
    const id = setInterval(update, 30_000);
    return () => clearInterval(id);
  }, [d]);

  return (
    <span className={className} title={formatAbsolute(d)} suppressHydrationWarning>
      {text}
    </span>
  );
}
