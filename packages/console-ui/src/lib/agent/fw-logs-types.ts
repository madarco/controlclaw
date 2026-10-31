/**
 * The Firewall Logs page's data, as the firewall serves it (`fw-logs-page.ts`) and the viewer reads
 * it (apps/saas/app/(mitm)/components/FirewallLogs.tsx). Types only, so the console can import them.
 */

/** The services this firewall runs. `run` is not a service: it is the last update or provisioning run. */
export type FwServiceId = "mitm-agent" | "proxy" | "caddy" | "dnsmasq" | "tang" | "disk" | "team-chat" | "chrony" | "tailscale" | "update";

export type FwRange = "15m" | "1h" | "24h";

export const FW_RANGES: Record<FwRange, number> = { "15m": 15 * 60, "1h": 60 * 60, "24h": 24 * 60 * 60 };

export type FwLogLevel = "error" | "warn" | "info" | "debug" | "unit";

export interface FwLogLine {
  /** ISO time, UTC. */
  time: string;
  service: FwServiceId;
  level: FwLogLevel;
  message: string;
}

export interface FwServiceState {
  id: FwServiceId;
  label: string;
  /** What it does, one short phrase for the page. */
  about: string;
  /** systemd's ActiveState: active, inactive, failed, activating, deactivating, reloading. */
  active: string;
  sub: string;
  /** systemd's Result: success, exit-code, signal, timeout, core-dump, ... */
  result: string;
  /** When it last became active (or inactive, when it is not running). ISO, or null. */
  since: string | null;
  restarts: number;
  exitStatus: number | null;
  /** On only when the organization uses it (Team chat, Tailscale): off is not a fault. */
  optional: boolean;
}

export interface FwUpdateState {
  phase: string;
  detail: string;
  ref: string;
  at: string;
}

export interface FwLogsResponse {
  /** The firewall's public hostname, for the page header. */
  firewall: string | null;
  range: FwRange;
  /** `all`, one service id, or `run`. */
  service: FwServiceId | "all" | "run";
  services: FwServiceState[];
  /** Journal lines, newest first. Empty when `service` is `run`. */
  lines: FwLogLine[];
  /** The last update or provisioning run, oldest line first, as ansible wrote it. Only when `service` is `run`. */
  run?: string[];
  /** What `update.json` says about the last update, whatever `service` is. */
  update: FwUpdateState | null;
  /** The newest lines were kept and older ones in the range dropped. */
  truncated: boolean;
  warning?: string;
}
