import type { FwLogLine, FwLogsResponse, FwRange, FwServiceId, FwServiceState } from "./agent/fw-logs-types";

export type { FwLogsResponse, FwRange };

/** What the viewer shows: every service, one, or the last update run. */
export type FwSelection = FwServiceId | "all" | "run";

/**
 * Where the Firewall Logs viewer reads from: the firewall's own page (same-origin fetches with its
 * cookie) or the demo's fake data.
 */
export interface FwLogSource {
  /** `signal` aborts when the viewer gives up on this read (timed out, or a newer one replaced it). */
  read(q: { range: FwRange; service: FwSelection; signal: AbortSignal }): Promise<FwLogsResponse>;
}

export const FW_RANGE_LABELS: Record<FwRange, string> = { "15m": "15 min", "1h": "1 h", "24h": "24 h" };

/** The journal is read again this often while the tab is visible. */
export const REFRESH_MS = 10_000;

/**
 * How long one read may take before the viewer gives up on it and says so. A refresh is not started
 * while a read is still out, so a slow firewall is waited for rather than asked again and again.
 */
export const READ_TIMEOUT_MS = 45_000;

export type FwLevelFilter = "all" | "warn" | "error";

export const FW_LEVEL_FILTERS: { key: FwLevelFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "warn", label: "Warnings and errors" },
  { key: "error", label: "Errors" },
];

/** systemd's own lines (Started, Stopped, exited) pass every filter: they explain the rest. */
export function fwPassesLevel(line: FwLogLine, filter: FwLevelFilter): boolean {
  if (filter === "all" || line.level === "unit") return true;
  if (filter === "warn") return line.level === "warn" || line.level === "error";
  return line.level === "error";
}

/** How a service reads at a glance. Off is not a fault for one the organization may not use. */
export function fwServiceTone(s: FwServiceState): { label: string; tone: "allow" | "ask" | "block" | "muted" } {
  if (s.active === "active") return { label: "Running", tone: "allow" };
  // Between two attempts of a crash loop systemd says activating/auto-restart: a fault, not a start.
  if (s.sub === "auto-restart") return { label: "Restarting", tone: "block" };
  if (s.active === "failed" || s.result === "exit-code" || s.result === "signal" || s.result === "core-dump" || s.result === "timeout")
    return { label: "Failed", tone: "block" };
  if (s.active === "activating" || s.active === "reloading") return { label: "Starting", tone: "ask" };
  if (s.active === "deactivating") return { label: "Stopping", tone: "ask" };
  return s.optional ? { label: "Off", tone: "muted" } : { label: "Stopped", tone: "ask" };
}

export const FW_RANGE_MS: Record<FwRange, number> = { "15m": 15 * 60_000, "1h": 60 * 60_000, "24h": 24 * 60 * 60_000 };

/** "in the last …" after the counts, and in the empty states. */
export const FW_RANGE_SPAN: Record<FwRange, string> = { "15m": "15 minutes", "1h": "hour", "24h": "24 hours" };

export interface FwHistBucket {
  start: number;
  info: number;
  warn: number;
  error: number;
}

/**
 * Lines per bucket over the range, stacked by level, for the summary's chart. systemd's own lines
 * count as info. The firewall reads only the range, so a line outside `[end - range, end]` is a clock
 * a little ahead or behind: it goes in the nearest bucket, so the chart and the counts (which the
 * errors and warnings buttons filter the journal to) agree.
 */
export function fwHistogram(lines: FwLogLine[], range: FwRange, end: number, buckets = 12): { buckets: FwHistBucket[]; errors: number; warnings: number } {
  const span = FW_RANGE_MS[range];
  const size = span / buckets;
  const start = end - span;
  const out: FwHistBucket[] = Array.from({ length: buckets }, (_, i) => ({ start: start + i * size, info: 0, warn: 0, error: 0 }));
  let errors = 0;
  let warnings = 0;
  for (const line of lines) {
    if (line.level === "error") errors++;
    else if (line.level === "warn") warnings++;
    const t = Date.parse(line.time);
    const i = Number.isNaN(t) ? buckets - 1 : Math.floor((t - start) / size);
    const b = out[Math.max(0, Math.min(buckets - 1, i))]!;
    if (line.level === "error") b.error++;
    else if (line.level === "warn") b.warn++;
    else b.info++;
  }
  return { buckets: out, errors, warnings };
}

export interface FwRecap {
  ok: number;
  changed: number;
  unreachable: number;
  failed: number;
  skipped: number;
}

/** The counts on ansible's PLAY RECAP line, the last one in the run, or null when it did not get there. */
export function fwRecap(run: string[]): FwRecap | null {
  for (let i = run.length - 1; i >= 0; i--) {
    const m = /ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)\s+skipped=(\d+)/.exec(run[i]!);
    if (m) return { ok: +m[1]!, changed: +m[2]!, unreachable: +m[3]!, failed: +m[4]!, skipped: +m[5]! };
  }
  return null;
}
