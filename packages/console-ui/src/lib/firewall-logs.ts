import type { FwLogLine, FwLogsResponse, FwRange, FwServiceId, FwServiceState } from "@controlclaw/console-ui/lib/agent/fw-logs-types";

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
  { key: "warn", label: "Warn+" },
  { key: "error", label: "Error" },
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
