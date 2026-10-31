import type { BoxSoftwareView } from "./software-schema";
import type { UpdateAvailableView } from "./update-available";
import type { VmUpdateProgress } from "./vm-states";

/**
 * What the Firewall page reads: the firewall, its box and its update. The console's own types
 * (`firewall.schema.ts`, `firewall-update.schema.ts`) carry more; these are the fields the shared
 * view draws, so a control plane that has no Hetzner server or provisioning leaves those null.
 */

export type FirewallState = "active" | "starting" | "inactive" | "none";
export type FirewallAction = "start" | "stop" | "restart";
export type ProxyServiceStatus = "active" | "inactive" | "failed";

/** An encrypted store the box could not decrypt (T-53). The console also keeps the box's error. */
export type UnreadableStore = { store: string; at: string };

/**
 * Hetzner's view of the proxy server, checked only while the box is not reporting (a heartbeat is
 * proof enough otherwise). `missing` = the server no longer exists; `unknown` = no server id or
 * the API call failed.
 */
export type FirewallServerProbe = {
  status: "running" | "off" | "starting" | "stopping" | "missing" | "unknown" | string;
  checkedAt: string;
};

/** Provisioning progress as reported by cloud-init (see `POST /api/vm-agent/provision`). */
export type FirewallProvisionView = {
  stage: "started" | "running" | "done" | "failed" | "stalled" | "silent";
  /** When the box last reported (or the row was created, for `silent`). */
  at: string;
  task: string | null;
  rc: number | null;
  tail: string[];
};

/** Server-level recovery the Restart button performs while the box is not reporting. */
export type ServerRecovery = "power_on" | "reboot" | "rebuild";

export type FirewallBoxView = {
  id: string;
  name: string;
  status: string;
  zone: string;
  serverType: string;
  privateIp: string | null;
  createdAt: string;
  lastSeenAt: string | null;
  serviceStatus: ProxyServiceStatus | null;
  /** Null while the box reports on its own. */
  server: FirewallServerProbe | null;
  /** What Restart would do to the server right now; null when nothing can be done. */
  recovery: ServerRecovery | null;
  /** The box has a server at Hetzner, so Hard reboot can be offered. */
  hasServer: boolean;
  /** Set while the box is still being provisioned (or its provisioning failed). */
  provision: FirewallProvisionView | null;
  /** What the box last said it is running; null when it has never said (created before this). */
  software: BoxSoftwareView | null;
  /**
   * Set while this firewall is being kept with no agents behind it, because the person who
   * destroyed the last one asked for it (`apps/saas/docs/features/backups.md`). It is what the
   * console reads to say "kept and idle since …" and to offer to tear it down.
   */
  idleSince: string | null;
  /**
   * Set when this firewall's Ansible came from somewhere other than the pinned production repo: a
   * dev-secured pair, built to try unmerged agent code. Null on a production firewall.
   */
  devBuild: { repo: string; branch: string } | null;
  /**
   * Encrypted stores this box reported it could not decrypt (T-53). Empty on a healthy box and on
   * one whose software predates the report.
   */
  unreadableStores: UnreadableStore[];
};

export type FirewallPendingCommandView = {
  id: string;
  action: FirewallAction;
  requestedAt: string;
  /** True once the box has had 2 minutes and never reported back. */
  stale: boolean;
};

export type FirewallView = {
  state: FirewallState;
  canManage: boolean;
  /**
   * Owners only, and separate from `canManage` (owners and admins) on purpose: tearing an idle
   * firewall down deletes the organisation's channel tokens, model keys and certificate authority,
   * which is an owner's decision rather than an operational one.
   */
  canTearDown: boolean;
  box: FirewallBoxView | null;
  /** The box has heartbeated within FIREWALL_REACHABLE_MS. */
  reachable: boolean;
  /** Secured agents whose egress goes through the proxy. */
  securedAgents: number;
  pendingCommand: FirewallPendingCommandView | null;
  /** What an idle firewall is quoted at, per day. */
  idleCostUsdPerDay: number;
};

/** A firewall update waiting for its code, or how it ended. */
export type FirewallUpdateChangeView = {
  id: string;
  vmId: string;
  summary: string;
  status: "queued" | "awaiting_code" | "applied" | "failed" | "expired" | "cancelled";
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  error: string | null;
  createdAt: string;
  stuck: boolean;
};

export type FirewallUpdateView = {
  /**
   * False on a firewall provisioned before in-place updates, which can only be rebuilt — and
   * rebuilding is the operation this feature exists to avoid. The box says so itself, by
   * advertising `self_update` only when the pin is actually on its disk.
   */
  supported: boolean;
  /** The box has heartbeated recently. It will not, for minutes, in the middle of its own update. */
  reachable: boolean;
  /**
   * A run is happening right now, as the server judges it. The same answer that stops the console
   * offering to reboot the box: the page and that guard must never disagree.
   */
  updating: boolean;
  /** Last progress the box reported. Stored, not fetched: there is no inbound path to this box. */
  progress: VmUpdateProgress | null;
  /**
   * When the run began, from the confirmed change rather than the box's clock. Null when nothing is
   * running. Shown as "started HH:MM" — this box goes quiet for minutes mid-run, and that is
   * exactly when somebody wants to know how long it has been.
   */
  startedAt: string | null;
  /** Whether pressing Update would install anything, and what. Never decides what gets installed. */
  available: UpdateAvailableView | null;
  pending: FirewallUpdateChangeView | null;
  recent: FirewallUpdateChangeView[];
};
