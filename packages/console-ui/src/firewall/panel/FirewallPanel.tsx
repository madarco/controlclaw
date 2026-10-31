"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { AppLink as Link } from "../../lib/link";
import { useRoutes } from "../../lib/routes";
import {
  Loader2,
  Play,
  RotateCw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import { Button } from "../../ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../ui/alert-dialog";
import { PageHead } from "../../kit/PageHead";
import { Pill } from "./FirewallStatusHeader";
import { StatusHero, type HeroTone } from "../../kit/StatusHero";
import { FIREWALL_TAB_ANCHORS } from "../../kit/console-tabs";
import { FirewallOverview } from "../overview/FirewallOverview";
import type { DemoRules } from "../overview/RulesOverview";
import type { FirewallOverviewView } from "../../lib/firewall-stats-schema";
import type { TrafficPoint, TrafficRange } from "../../lib/firewall-stats";
import {
  ActionMenu,
  AnchorTabs,
  Card,
  type TabDef,
  useHashTab,
  Disclosure,
  KV,
  KVPair,
  Sec,
} from "../../kit/console-ui";
import { ConfirmCodeDialog } from "../channels/ChannelDialogs";
import { SoftwareRows } from "../../kit/SoftwareRows";
import { HARD_REBOOT_TOAST, HardRebootDialog, RestartMenu } from "../../kit/RestartMenu";
import { UpdateConfirmDialog, UpdateControl, UpdateProgressLine, UpdateUnknownReason } from "../../kit/UpdateBits";
import { useFirewallUpdateChange } from "./useFirewallUpdateChange";
import { BATCH_SETTLED } from "../../lib/update-events";
import { isNoRecipients, showCodeRecipients } from "../../lib/no-recipients";
import type { FirewallAction, FirewallState, FirewallUpdateView, FirewallView, ServerRecovery, UnreadableStore } from "../../lib/firewall-view";
import type { EgressAiView } from "../../lib/egress-ai-schema";
import { EgressAiSections } from "./EgressAiCard";

/** Poll cadence: fast while a command is in flight (and briefly after), relaxed otherwise. */
const POLL_ACTIVE_MS = 3_000;
const POLL_IDLE_MS = 15_000;
const SETTLE_MS = 30_000;

const STATE_COPY: Record<FirewallState, { label: string; tone: "allow" | "ask" | "muted"; text: string }> = {
  active: {
    label: "Active",
    tone: "allow",
    text: "Every request your secured agents make leaves through this proxy. Your Internet access rules decide each one, and every call is logged.",
  },
  starting: {
    label: "Starting",
    tone: "muted",
    text: "ControlClaw is setting up your proxy box. This takes a few minutes; controls appear once it reports in.",
  },
  inactive: {
    label: "Not active",
    tone: "ask",
    text: "Your agents were created without the ControlClaw proxy, so their traffic isn’t inspected or logged. New secured agents get the proxy automatically.",
  },
  none: {
    label: "No proxy yet",
    tone: "muted",
    text: "The proxy comes with your first secured agent. Nothing to inspect yet.",
  },
};

const SERVICE_COPY: Record<string, { label: string; tone: "allow" | "ask" | "block" | "muted" }> = {
  active: { label: "Proxy running", tone: "allow" },
  inactive: { label: "Proxy stopped", tone: "ask" },
  failed: { label: "Proxy failed", tone: "block" },
};

const ACTION_COPY: Record<FirewallAction, { verb: string }> = {
  start: { verb: "Start" },
  stop: { verb: "Stop" },
  restart: { verb: "Restart" },
};

const ZONE_LABEL: Record<string, string> = { eu: "EU", usa: "US" };

/** What Restart does to the server while the box is not reporting, and the confirm copy. */
const RECOVERY_COPY: Record<ServerRecovery, { title: string; text: string; button: string; toast: string }> = {
  reboot: {
    title: "Reboot the proxy server?",
    text: "The server is up but its agent is not reporting. A reboot takes about a minute; secured agents have no outbound access while it is down. Keys and settings stay on the server.",
    button: "Reboot server",
    toast: "Reboot requested. The box reports back once it is up, in about a minute.",
  },
  power_on: {
    title: "Power the proxy server on?",
    text: "The server is powered off at Hetzner. Powering it on takes about a minute; the box reports back once its services are up.",
    button: "Power on",
    toast: "Power on requested. The box reports back once it is up, in about a minute.",
  },
  rebuild: {
    title: "Rebuild the proxy server?",
    text: "The server no longer exists at Hetzner. A new one is created with the same address, which takes a few minutes. Agents created before the rebuild keep routing through it, but they won’t trust its new certificate until you re-create them.",
    button: "Rebuild server",
    toast: "Rebuild started. The new server provisions in a few minutes; this page follows along.",
  },
};

/** Hetzner's view of the server, shown only while the box is not reporting. */
const SERVER_COPY: Record<string, { label: string; tone: "allow" | "ask" | "block" | "muted"; text: string }> = {
  running: {
    label: "Not responding",
    tone: "ask",
    text: "The server is up at Hetzner but its agent is not reporting. It may still be booting; if it stays quiet, Restart reboots the server.",
  },
  starting: { label: "Server starting", tone: "muted", text: "Hetzner is booting the server. Give it a minute." },
  initializing: {
    label: "Server initializing",
    tone: "muted",
    text: "Hetzner is setting the server up. Give it a minute.",
  },
  off: {
    label: "Server off",
    tone: "block",
    text: "The server is powered off at Hetzner, so nothing can run on it. Restart powers it on.",
  },
  stopping: { label: "Server stopping", tone: "block", text: "Hetzner is powering the server off." },
  missing: {
    label: "Server missing",
    tone: "block",
    text: "Hetzner has no server for this proxy any more: it was deleted outside ControlClaw. Restart creates a new server for it.",
  },
  unknown: {
    label: "Server unknown",
    tone: "muted",
    text: "Couldn’t get the server’s status from Hetzner. This page tries again in a few seconds.",
  },
};

/** Relative time; `now` is null until mount so server and client render the same placeholder. */
function ago(iso: string | null, now: number | null): string {
  if (!iso) return "never";
  if (now === null) return "…";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

interface FirewallPanelProps {
  initial: FirewallView;
  /** Whether this box can update itself in place, and how a running update is going. */
  update?: FirewallUpdateView | null;
  /** The firewall's AI review settings. Null on the demo page, which has no card. */
  ai?: EgressAiView | null;
  /** Off on the demo page: no polling, no RPC calls. */
  live?: boolean;
  /** Demo page only: the Overview tab's numbers. A live page loads them itself. */
  overview?: FirewallOverviewView | null;
  /** Demo page only: the traffic chart for another range. */
  demoTraffic?: (range: TrafficRange) => TrafficPoint[];
  /** Demo page only: Most used rules and the Security rules section. */
  demoRules?: DemoRules;
  /** The Confirmation codes tab: `CodeRecipientsCard`, rendered by the page. */
  codes?: ReactNode;
  /**
   * Settings rows that are the control plane's own (the console: Doctor, the agent MCP, Support
   * access and the encrypted disk before Advanced, automatic updates after it). Called with what
   * they need to know about the firewall.
   */
  settings?: (ctx: FirewallSettingsContext) => { beforeAdvanced?: ReactNode; afterAdvanced?: ReactNode };
  /**
   * Rebooting the whole server (the console: Hetzner). Left out where the control plane cannot,
   * and the Restart button then has no menu.
   */
  hardReboot?: { canReboot: (boxStatus: string) => boolean };
}

/** What the `settings` rows of the Firewall page get. */
export type FirewallSettingsContext = {
  view: FirewallView;
  live: boolean;
  /** Opens the hard reboot confirmation, when a hard reboot can be offered right now. */
  onHardReboot: (() => void) | undefined;
}

/** The page's tabs (docs/plans/console-v3.md, unit 1). Old section links open theirs. */
const TABS: TabDef[] = [
  { id: "overview", label: "Overview" },
  { id: "settings", label: "Settings" },
  { id: "codes", label: "Confirmation codes" },
];
const TAB_IDS = TABS.map((t) => t.id);

const HERO_TONE: Record<"allow" | "ask" | "block" | "muted", HeroTone> = { allow: "allow", ask: "ask", block: "block", muted: "neutral" };

/**
 * What a firewall says it could not decrypt (T-53).
 *
 * The stores are sealed under the box key, and one that will not open starts empty rather than
 * taking its feature down — so without this the page would show a firewall that is up, green and
 * quietly holding none of the organization's channel tokens. It has to say which stores, because
 * what it costs differs: the channel store is the confirmation codes, and a box that cannot mint
 * one cannot take any change at all.
 *
 * Rendered from `vm.store_health`, written on every beat. It clears itself: the first change
 * written into a store reseals it under the current key and the next beat drops it from the list.
 */
function UnreadableStores({ stores, now }: { stores: UnreadableStore[]; now: number | null }) {
  if (!stores.length) return null;
  const names = stores.map((s) => s.store).join(", ");
  return (
    <div
      className="mt-4 flex items-start gap-3 rounded-[10px] border border-block-border bg-block-soft px-3.5 py-2.5 text-[13px] text-block-fg"
      data-testid="firewall-stores-unreadable"
    >
      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="flex-1">
        <div>
          Your firewall can’t read what it stores for {names}. It keeps running, but anything set up through{" "}
          {stores.length === 1 ? "that store" : "those stores"} has stopped working.
        </div>
        <div className="mt-1 text-[12.5px]">
          This happens when the box restarts with a different key than the one that encrypted its files. To fix it and clear this notice, set
          the affected item up again. If several are listed, contact support before you rebuild the box: the files themselves are kept.
        </div>
        <div className="mt-1 text-[12px] opacity-80">Reported {ago(stores[0].at, now)}.</div>
      </div>
    </div>
  );
}

export function FirewallPanel({ initial, update: initialUpdate = null, ai = null, live = true, overview = null, demoTraffic, demoRules, codes = null, settings, hardReboot: hardRebootProp }: FirewallPanelProps) {
  const api = useApi();
  const routes = useRoutes();
  const [tab, setTab] = useHashTab("overview", TAB_IDS, FIREWALL_TAB_ANCHORS);
  const [view, setView] = useState(initial);
  const [update, setUpdate] = useState<FirewallUpdateView | null>(initialUpdate);
  const [starting, setStarting] = useState(false);
  const [busy, setBusy] = useState<FirewallAction | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const [confirmRecover, setConfirmRecover] = useState(false);
  /**
   * The "are you sure" step. Updating the firewall takes every agent's internet access away for the
   * length of the run, which is a bigger consequence than the agent's own update and was equally
   * unannounced.
   */
  const [confirmUpdate, setConfirmUpdate] = useState(false);
  const [confirmTearDown, setConfirmTearDown] = useState(false);
  const [tearingDown, setTearingDown] = useState(false);
  const [recovering, setRecovering] = useState(false);
  const [confirmHardReboot, setConfirmHardReboot] = useState(false);
  const [hardRebooting, setHardRebooting] = useState(false);
  const [now, setNow] = useState<number | null>(null);
  const settleUntil = useRef(0);
  const lastPending = useRef<string | null>(initial.pendingCommand?.id ?? null);

  const refresh = useCallback(async () => {
    try {
      const fresh = await api.firewall.get();
      setView(fresh);
      // A command just finished: tell the user how it went (the box's result is in the event log,
      // the outcome is visible in serviceStatus).
      if (lastPending.current && !fresh.pendingCommand) {
        lastPending.current = null;
        settleUntil.current = Date.now() + SETTLE_MS;
        const svc = fresh.box?.serviceStatus;
        if (svc === "failed") toast.error("The proxy service failed. Open Logs to see why.");
        else if (svc) toast.success(svc === "active" ? "Proxy is running." : "Proxy is stopped.");
      } else if (fresh.pendingCommand) {
        lastPending.current = fresh.pendingCommand.id;
      }
    } catch (err) {
      console.error("firewall.get failed", err);
    }
    if (!live) return;
    try {
      const fresh = await api.firewallUpdate.get();
      // The box stops answering in the middle of every update, because the run restarts its agent.
      // Keep what we last knew rather than letting the button and the progress line disappear —
      // except the progress line itself while a run is in flight and the server has nothing
      // current for it. What `prev` holds then is the PREVIOUS run's outcome, and printing
      // "Up to date." under a "Firewall updating" heading is worse than printing nothing.
      setUpdate((prev) =>
        fresh.reachable || !prev
          ? fresh
          : { ...fresh, supported: prev.supported, progress: fresh.progress ?? (fresh.updating ? null : prev.progress) },
      );
    } catch (err) {
      console.error("firewallUpdate.get failed", err);
    }
  }, [live, api]);

  const change = useFirewallUpdateChange({
    vmId: view.box?.id ?? "",
    live,
    initial: update?.pending ?? null,
    onSettled: () => refresh(),
  });

  /**
   * "Update everything" (T-100) lives in the console header. When a batch it started settles, the
   * firewall's own line here is re-read so it stops saying "Update available".
   */
  useEffect(() => {
    if (!live) return;
    const onSettled = () => void refresh();
    window.addEventListener(BATCH_SETTLED, onSettled);
    return () => window.removeEventListener(BATCH_SETTLED, onSettled);
  }, [live, refresh]);

  /**
   * Updating is not a systemctl round trip like Start or Restart: it returns a change id and the
   * firewall then asks the person for a code, so it does not go through `run()`.
   */
  const startUpdate = async () => {
    setStarting(true);
    try {
      await change.start(() => api.firewallUpdate.start(), "Asking your firewall to confirm with you…", { vmId: view.box?.id ?? "" });
    } finally {
      setStarting(false);
      // Closed either way: on success the code dialog takes over, on failure the toast below needs
      // to be visible.
      setConfirmUpdate(false);
    }
  };

  // `change.start` swallows the failure into `state.error` and leaves `tracking` null, so the code
  // dialog never opens. Without this, pressing Update with nobody approved would do nothing visible.
  useEffect(() => {
    if (!change.state.error || change.tracking) return;
    // "Nobody is set to get confirmation codes" is the one refusal with somewhere to go (T-83), and
    // that somewhere is further down this very page.
    toast.error(change.state.error, isNoRecipients(change.state.error) ? { action: { label: "Fix it", onClick: showCodeRecipients } } : undefined);
    change.setState({ busy: false, error: null, note: null });
  }, [change.state.error, change.tracking]); // eslint-disable-line react-hooks/exhaustive-deps

  // An update this tab did not start — begun from another tab, or from a `start` whose response
  // was lost. The hook only seeds `tracking` from its initial value, so without this the code
  // dialog never opens for it and the Update button stays enabled on a change that will only
  // answer CONFLICT.
  useEffect(() => {
    const pending = update?.pending ?? null;
    if (!live || !pending || change.tracking) return;
    change.setTracking(pending);
  }, [live, update?.pending?.id, change.tracking]); // eslint-disable-line react-hooks/exhaustive-deps

  // The server's answer, not the phase: `update.json` keeps the previous run's `done` until the
  // new run overwrites it, so reading the phase here would say "not updating" through exactly the
  // window in which the page must not invite a restart.
  const updating = update?.updating === true;
  const codeChange = change.tracking?.status === "awaiting_code" ? change.tracking : null;

  // "last seen Ns ago" ticks every second without refetching. Set on mount only, so the server
  // and the first client render agree (no hydration mismatch).
  useEffect(() => {
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    if (!live) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;
    const loop = async () => {
      await refresh();
      if (cancelled) return;
      const fast = !!view.pendingCommand || Date.now() < settleUntil.current;
      timer = setTimeout(loop, fast ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    };
    timer = setTimeout(loop, view.pendingCommand ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // Re-arm when the pending state flips so the cadence changes at once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, refresh, !!view.pendingCommand]);

  const run = async (action: FirewallAction) => {
    setBusy(action);
    try {
      const { commandId } = await api.firewall.command({ action });
      lastPending.current = commandId;
      settleUntil.current = Date.now() + SETTLE_MS;
      setView((v) => ({
        ...v,
        pendingCommand: { id: commandId, action, requestedAt: new Date().toISOString(), stale: false },
      }));
      toast.success(`${ACTION_COPY[action].verb} requested. The firewall runs it within a few seconds.`);
    } catch (err) {
      console.error("firewall.command failed", err);
      toast.error(err instanceof Error ? err.message : `Couldn’t ${action} the firewall. Try again.`);
    } finally {
      setBusy(null);
    }
  };

  const recover = async () => {
    setRecovering(true);
    try {
      const { action } = await api.firewall.recover();
      toast.success(RECOVERY_COPY[action].toast);
      settleUntil.current = Date.now() + SETTLE_MS;
      await refresh();
    } catch (err) {
      console.error("firewall.recover failed", err);
      toast.error(err instanceof Error ? err.message : "Couldn’t recover the firewall’s server. Try again.");
    } finally {
      setRecovering(false);
    }
  };

  /** Reboot the firewall's server at Hetzner (Hard reboot, under the arrow beside Restart). */
  const hardReboot = async () => {
    if (!live) {
      toast.success(HARD_REBOOT_TOAST);
      return;
    }
    setHardRebooting(true);
    try {
      await api.firewall.hardReboot();
      toast.success(HARD_REBOOT_TOAST);
      settleUntil.current = Date.now() + SETTLE_MS;
      await refresh();
    } catch (err) {
      console.error("firewall.hardReboot failed", err);
      toast.error(err instanceof Error ? err.message : "Couldn’t reboot the firewall’s server. Try again.");
    } finally {
      setHardRebooting(false);
    }
  };

  /**
   * Kept with no agents behind it, because the person who destroyed the last one asked for that.
   * It is the whole reason `idleSince` exists: a firewall holds the org's channel tokens, its model
   * keys and the CA every agent trusts, and a rebuild loses all three.
   */
  const idleSince = view.box?.idleSince ?? null;
  const canTearDown = view.canTearDown;

  const tearDown = async () => {
    setTearingDown(true);
    try {
      await api.firewall.tearDown();
      toast.success("Deleting your firewall…");
      await refresh();
    } catch (err) {
      console.error("firewall.tearDown failed", err);
      toast.error(err instanceof Error ? err.message : "Couldn’t delete the firewall. Try again.");
    } finally {
      setTearingDown(false);
      setConfirmTearDown(false);
    }
  };

  const state = STATE_COPY[view.state];
  const recovery = view.box?.recovery ?? null;
  const canRecover = view.canManage && !view.reachable && recovery !== null && !recovering;
  // Whenever there is a server, not only in the recovery state; never in the middle of an update.
  const canHardRebootBox =
    !!hardRebootProp &&
    view.canManage &&
    !!view.box?.hasServer &&
    hardRebootProp.canReboot(view.box.status) &&
    !updating &&
    busy === null &&
    !recovering &&
    !hardRebooting;
  const extra = settings?.({ view, live, onHardReboot: canHardRebootBox ? () => setConfirmHardReboot(true) : undefined }) ?? {};
  const server = view.box?.server ? (SERVER_COPY[view.box.server.status] ?? SERVER_COPY.unknown) : null;
  const service = view.box?.serviceStatus ? SERVICE_COPY[view.box.serviceStatus] : null;
  // One pill, one message: what the box reports while it is reporting, otherwise Hetzner's view
  // of the server. The separate facts stay in the Proxy box table below.
  const prov = view.box?.provision ?? null;
  const PROVISION_LABEL: Record<
    NonNullable<typeof prov>["stage"],
    { label: string; tone: "allow" | "ask" | "block" | "muted" }
  > = {
    started: { label: "Provisioning", tone: "muted" },
    running: { label: "Provisioning", tone: "muted" },
    done: { label: "Finishing setup", tone: "muted" },
    silent: { label: "Provisioning", tone: "muted" },
    stalled: { label: "Provisioning stalled", tone: "ask" },
    failed: { label: "Provisioning failed", tone: "block" },
  };
  const status: { label: string; tone: "allow" | "ask" | "block" | "muted"; key: string } | null = !view.box
    ? null
    : prov && !view.reachable
      ? { ...PROVISION_LABEL[prov.stage], key: `provision-${prov.stage}` }
      : view.reachable
        ? service
          ? { ...service, key: `proxy-${view.box.serviceStatus}` }
          : { label: "Reporting", tone: "allow", key: "reporting" }
        : server
          ? { ...server, key: `server-${view.box.server?.status}` }
          : { label: "Not reporting", tone: "ask", key: "not-reporting" };
  const pending = view.pendingCommand;
  const controlsEnabled = view.canManage && view.state === "active" && view.reachable && !pending?.stale && !pending;
  /**
   * Whether starting a self-update could actually succeed right now. One expression, because the
   * menu item and the Retry beside the failure line must agree: they call the same thing, and a
   * live Retry next to a disabled menu item only reaches the dialog before the server refuses.
   */
  const canUpdate = update?.supported === true && controlsEnabled && busy === null && !starting && !updating && !change.tracking;

  // The heading and its sentence follow the same combined status as the pill: a proxy that is
  // "active" in the database but whose server is gone or silent is not active for the user.
  const quiet = !!view.box && view.state === "active" && !view.reachable;
  const quietText = server
    ? server.text
    : view.box?.lastSeenAt
      ? `The firewall last checked in ${ago(view.box.lastSeenAt, now)}. Its controls come back when it checks in again.`
      : "The firewall hasn’t checked in yet. Its controls appear once it does.";
  const provisionText = !prov
    ? ""
    : prov.stage === "failed"
      ? `Setting up the server failed${prov.task ? ` at "${prov.task}"` : ""}${prov.rc !== null ? ` (exit ${prov.rc})` : ""}. Rebuild creates a fresh server and tries again.`
      : prov.stage === "stalled"
        ? `The server stopped reporting progress ${ago(prov.at, now)}${prov.task ? `, last at "${prov.task}"` : ""}. Rebuild creates a fresh server and tries again.`
        : prov.stage === "done"
          ? "Setup finished. Waiting for the firewall to check in."
          : prov.task
            ? `Setting up the server, last step "${prov.task}" (${ago(prov.at, now)}). This takes a few minutes.`
            : "Setting up the server. This takes a few minutes; controls appear once it reports in.";
  const heading = updating
    ? {
        label: "Firewall updating",
        tone: "muted" as const,
        text: "Your firewall is installing new software. It stops reporting partway through. Until it finishes, your agents have no internet access, DNS or permission prompts.",
      }
    : prov && !view.reachable
      ? {
          label:
            prov.stage === "failed"
              ? "Firewall setup failed"
              : prov.stage === "stalled"
                ? "Firewall setup stalled"
                : "Firewall starting",
          tone: PROVISION_LABEL[prov.stage].tone,
          text: provisionText,
        }
      : quiet
        ? {
            label: "Firewall not responding",
            tone: (status?.tone === "block" ? "block" : "ask") as "block" | "ask",
            text: quietText,
          }
        : view.reachable && view.box?.serviceStatus === "inactive"
          ? {
              label: "Firewall stopped",
              tone: "ask" as const,
              text: "The proxy service is stopped. Your secured agents have no outbound access until you start it.",
            }
          : view.reachable && view.box?.serviceStatus === "failed"
            ? {
                label: "Firewall failed",
                tone: "block" as const,
                text: "The proxy service crashed and didn’t restart. Press Restart. If the firewall then stops checking in, Restart reboots the server.",
              }
            : { label: `Firewall ${state.label.toLowerCase()}`, tone: state.tone, text: state.text };

  // Up, reporting and nothing in the way: the hero says what it is doing rather than its state.
  const protecting = !updating && !quiet && !prov && view.state === "active" && view.reachable && view.box?.serviceStatus === "active";

  let disabledReason: string | null = null;
  if (!view.canManage) disabledReason = "Only owners and admins can start, stop or restart the firewall.";
  // When the box is quiet the heading already says why; do not repeat it under the buttons.

  return (
    <div data-testid="firewall-panel">
      <PageHead title="Firewall" sub="The protected gateway between your agents and the internet." />

      {/* What it is doing right now, and the controls for the box itself. */}
      <StatusHero
        data-testid={`firewall-state-${view.state}`}
        data-tour="firewall-hero"
        tone={HERO_TONE[heading.tone]}
        icon={heading.tone === "ask" || heading.tone === "block" ? ShieldAlert : ShieldCheck}
        pulse={protecting}
        label={protecting ? `Protecting ${view.securedAgents} ${view.securedAgents === 1 ? "agent" : "agents"}` : heading.label}
        text={protecting ? "Every request from and to your agents is scanned and logged by the firewall." : heading.text}
        meta={
          view.box
            ? [
                view.box.lastSeenAt ? `Checked in ${ago(view.box.lastSeenAt, now)}` : "Hasn’t checked in yet",
                ZONE_LABEL[view.box.zone] ?? view.box.zone,
              ].join(" · ")
            : null
        }
        badges={
          <>
            {status ? (
              <Pill tone={status.tone}>
                <span data-testid="firewall-status" data-status={status.key}>
                  {status.label}
                </span>
              </Pill>
            ) : null}
            {view.box?.devBuild ? (
              <Pill tone="ask" title={`Dev build · ${view.box.devBuild.repo} · ${view.box.devBuild.branch}`}>
                Dev build · {view.box.devBuild.repo} · {view.box.devBuild.branch}
              </Pill>
            ) : null}
          </>
        }
        actions={
          view.state === "active" || (view.box && recovery) ? (
            <>
              {/* Whether there is newer software, and the button that installs it, beside Restart
                  the way the agent's page has them: "Up to date" next to a quiet button, "Update
                  available" next to one that stands out. Only offered when the box says it has an
                  update pin; an older one can only be rebuilt. */}
              {update?.supported ? (
                <UpdateControl
                  available={update.available}
                  running={updating}
                  spinning={starting || updating}
                  disabled={!canUpdate}
                  onClick={() => setConfirmUpdate(true)}
                  // On a phone the answer and its button take their own row, so Restart and the
                  // menu stay together on the next one instead of the menu wrapping on its own.
                  className="w-full justify-start sm:w-auto sm:justify-end"
                  testId="firewall-action-update"
                  lineTestId="firewall-update-available"
                />
              ) : null}
              {/* One primary action: Start when it is stopped, Restart when it is up. Stop is in the
                  menu, as the redesign has it. On a phone the row sits under the sentence rather
                  than squeezing it into a column one word wide. */}
              {view.box?.serviceStatus === "inactive" ? (
                <Button
                  size="sm"
                  disabled={!controlsEnabled || busy !== null}
                  onClick={() => run("start")}
                  data-testid="firewall-action-start"
                >
                  <Play className="h-3.5 w-3.5" /> Start
                </Button>
              ) : null}
              {/* Restart acts on the proxy service while the box reports, on the server itself when it does not. */}
              {/* The arrow beside it holds Hard reboot: the server itself, whenever there is one. */}
              <RestartMenu
                variant={canRecover ? "default" : "outline"}
                restartDisabled={busy !== null || (canRecover ? false : !controlsEnabled)}
                onRestart={() => (canRecover ? setConfirmRecover(true) : void run("restart"))}
                spinning={recovering || hardRebooting}
                label={recovery === "rebuild" && canRecover ? "Rebuild" : recovery === "power_on" && canRecover ? "Power on" : "Restart"}
                onHardReboot={hardRebootProp ? () => setConfirmHardReboot(true) : undefined}
                hardRebootDisabled={!canHardRebootBox}
                testId="firewall-action-restart"
              />
              {/* The firewall's own logs, read on the firewall (docs/features/firewall-logs.md). */}
              {view.box ? (
                <Button size="sm" variant="outline" asChild>
                  <Link href={routes.firewallLogs} data-testid="firewall-logs-link">
                    <ScrollText className="h-3.5 w-3.5" /> Logs
                  </Link>
                </Button>
              ) : null}
              {/* Stop is the only thing left in the menu, so a stopped firewall has no menu. */}
              {view.box?.serviceStatus !== "inactive" ? (
                <ActionMenu
                  data-testid="firewall-more"
                  items={[
                    {
                      label: "Stop firewall",
                      sub: "Agents lose internet access",
                      icon: Square,
                      danger: true,
                      disabled: !controlsEnabled || busy !== null,
                      onClick: () => setConfirmStop(true),
                      "data-testid": "firewall-action-stop",
                    },
                  ]}
                />
              ) : null}
            </>
          ) : null
        }
      />

      {/* Notices about the box itself stay above the tabs: a command, an update, what it cannot read. */}
      <div>
        {disabledReason ? (
          <div className="mt-3 text-[12.5px] text-ink-2" data-testid="firewall-unreachable">
            {disabledReason}
          </div>
        ) : null}

        {/* A lookup that failed is a sentence, too long for the row beside the button. */}
        <UpdateUnknownReason available={update?.available} running={updating} className="mt-3" testId="firewall-update-unknown" />

        <UpdateProgressLine
          progress={update?.progress}
          startedAt={update?.startedAt}
          updating={updating}
          installed={view.box?.software ?? null}
          available={update?.available}
          failedFallback="The update didn’t finish. Your firewall may need rebuilding."
          onRetry={canUpdate ? () => setConfirmUpdate(true) : undefined}
          className="mt-3"
          testId="firewall-update-progress"
        />

        {pending ? (
          <div
            className={cn(
              "mt-4 flex items-center gap-3 rounded-[10px] border px-3.5 py-2.5 text-[13px]",
              pending.stale ? "border-block-border bg-block-soft text-block-fg" : "border-line bg-surface text-ink-2",
            )}
            data-testid={pending.stale ? "firewall-command-stale" : "firewall-command-pending"}
          >
            {pending.stale ? (
              <>
                <ShieldAlert className="h-4 w-4 shrink-0" />
                <span className="flex-1">
                  The firewall didn’t confirm the {pending.action} you requested {ago(pending.requestedAt, now)}. Try
                  again.
                </span>
              </>
            ) : (
              <>
                <RotateCw className="h-4 w-4 shrink-0 animate-spin" />
                <span className="flex-1">
                  {ACTION_COPY[pending.action].verb} in progress, requested {ago(pending.requestedAt, now)}. Waiting for
                  the firewall to confirm.
                </span>
              </>
            )}
          </div>
        ) : null}

        <UnreadableStores stores={view.box?.unreadableStores ?? []} now={now} />
      </div>

      {prov && prov.stage === "failed" && prov.tail.length > 0 ? (
        <Card className="mt-[14px] p-5" data-testid="firewall-provision-log">
          <div className="text-[14px] font-semibold text-ink">Setup log</div>
          <p className="mt-1 text-[12.5px] text-ink-2">
            The last lines the server reported before setup stopped, {ago(prov.at, now)}.
          </p>
          <pre className="mt-3 max-h-[320px] overflow-auto rounded-[10px] bg-bg-2 p-3 font-mono text-[11.5px] leading-[1.5] whitespace-pre-wrap break-all text-ink">
            {prov.tail.join("\n")}
          </pre>
        </Card>
      ) : null}

      {idleSince ? (
        <div className="mt-[14px] rounded-[14px] border border-ask-border bg-ask-soft p-5" data-testid="firewall-idle">
          <div className="flex flex-wrap items-start gap-3">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-ask-fg" />
            <div className="min-w-0 flex-1 text-[13.5px] text-ask-fg">
              <div className="text-[15px] font-semibold text-ink">Your firewall is idle</div>
              <p className="mt-1 max-w-[70ch]">
                You have no agents, and you asked to keep this firewall when you deleted the last one. It still holds your
                channel tokens, your model keys and the certificate authority your agents trust, so your next agent picks up
                where the last one left off. It has been idle since{" "}
                <span className="text-ink">{now === null ? "…" : new Date(idleSince).toLocaleString()}</span>, at{" "}
                <span className="text-ink">${view.idleCostUsdPerDay} a day</span>.
              </p>
            </div>
            {canTearDown ? (
              <Button size="sm" variant="destructive" disabled={tearingDown} onClick={() => setConfirmTearDown(true)} data-testid="firewall-tear-down">
                {tearingDown ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                Delete firewall
              </Button>
            ) : null}
          </div>
        </div>
      ) : null}

      <AnchorTabs tabs={TABS} active={tab} onSelect={setTab} data-testid="firewall-tabs" />

      {tab === "overview" ? <FirewallOverview canManage={view.canManage} initial={overview} live={live} demoTraffic={demoTraffic} demoRules={demoRules} /> : null}

      {tab === "settings" ? (
        <div className="[&>section:first-child]:mt-6" data-testid="firewall-settings">
          {/* AI Log Review runs on the firewall itself, so its setting lives here; the AI Firewall is on Security rules. */}
          {ai ? <EgressAiSections initial={ai} page="firewall" /> : null}

          {/* Everything after AI Log Review sits under one "Other settings" heading; the Sec's stack spaces the rows. */}
          {extra.beforeAdvanced || view.box || extra.afterAdvanced ? (
            <Sec title="Other settings" data-testid="firewall-other-settings">
              {/* The control plane's own rows (Doctor, the agent MCP, Support access, the encrypted disk). */}
              {extra.beforeAdvanced}

              {view.box ? (
                <div>
                  <Disclosure title="Advanced" meta="Machine details and software" data-testid="firewall-box">
                    <div className="flex flex-col gap-5">
                      <KVPair>
                        <KV
                          rows={[
                            ["Name", view.box.name, true],
                            ["Region", `${ZONE_LABEL[view.box.zone] ?? view.box.zone} · ${view.box.serverType.toUpperCase()}`],
                            ["Private address", view.box.privateIp ?? "not assigned yet", true],
                            ["Created", now === null ? "…" : new Date(view.box.createdAt).toLocaleString()],
                          ]}
                        />
                        <KV
                          rows={[
                            ["Server status", view.box.server ? `${view.box.server.status} (Hetzner)` : view.box.status],
                            ["Proxy service", service?.label ?? "unknown"],
                            ["Last check-in", ago(view.box.lastSeenAt, now)],
                            view.box.devBuild
                              ? (["Built from", `${view.box.devBuild.repo} · ${view.box.devBuild.branch}`, true] as const)
                              : null,
                          ]}
                        />
                      </KVPair>
                      <SoftwareRows
                        title="Software"
                        software={view.box.software}
                        versionLabel="Firewall software"
                        version={update?.available?.fromVersion}
                        testId="firewall-software-rows"
                      />
                    </div>
                  </Disclosure>
                </div>
              ) : null}

              {extra.afterAdvanced}
            </Sec>
          ) : null}

          <div className="mt-9 flex gap-3 rounded-[12px] border border-line bg-bg-2 px-4 py-3 text-[13px] text-ink-2">
            <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-ink-2" />
            <div>
              Stopping the firewall doesn’t open your agents up: they are only allowed to reach the internet through it, so
              they lose access until you start it again. Decide what gets through under{" "}
              <Link href={routes.internet} className="font-semibold text-ink hover:underline">
                Internet access
              </Link>
              .
            </div>
          </div>
        </div>
      ) : null}

      {tab === "codes" ? <div className="[&>section:first-child]:mt-6">{codes}</div> : null}

      <ConfirmCodeDialog
        change={codeChange}
        state={change.state}
        onSubmit={change.confirm}
        onCancel={() => void change.cancel()}
        sender="Your firewall, through one of your agents,"
        warning={
          <>
            Confirming takes your firewall down while it installs. Your{" "}
            {view.securedAgents === 1 ? "agent loses" : `${view.securedAgents} agents lose`} internet access, name
            resolution and permission prompts for a few minutes, longer than a restart.
          </>
        }
      />

      <AlertDialog open={confirmRecover} onOpenChange={setConfirmRecover}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{recovery ? RECOVERY_COPY[recovery].title : "Restart"}</AlertDialogTitle>
            <AlertDialogDescription>
              {/* A rebuild offered while a run is still in flight is the bricked-mid-update case.
                  Say so: the reason this is the only option on offer is not obvious otherwise. */}
              {updating && recovery === "rebuild"
                ? "Your firewall started updating itself and hasn’t reported back since. Rebuilding recovers from an update that stopped halfway. It creates a new server with a new certificate. Your existing agents keep routing through it but won’t trust it until they are re-created."
                : recovery
                  ? RECOVERY_COPY[recovery].text
                  : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setConfirmRecover(false);
                void recover();
              }}
              data-testid="firewall-confirm-recover"
            >
              {recovery ? RECOVERY_COPY[recovery].button : "Restart"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {hardRebootProp ? (
      <HardRebootDialog
        open={confirmHardReboot}
        onOpenChange={setConfirmHardReboot}
        name="the firewall"
        effect="Your agents lose internet access"
        onConfirm={() => void hardReboot()}
        testId="firewall-confirm-hard-reboot"
      />
      ) : null}

      <AlertDialog open={confirmTearDown} onOpenChange={setConfirmTearDown}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete the firewall?</AlertDialogTitle>
            <AlertDialogDescription>
              This deletes the box and everything on it: your channel tokens, AgentMail and Twilio keys, model keys and the certificate
              authority your agents trust. Your Internet access rules are kept. Your next agent gets a new firewall with new keys,
              so backups taken before today need your recovery key. If you have a firewall backup, restore it afterwards
              from Backup settings. AgentMail inboxes and mail stay at AgentMail; import a key to reconnect them. Unassign Phone first to clear its voice
              routing. Twilio numbers stay in your account; a new firewall
              needs the token again.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={tearingDown}>Keep firewall</AlertDialogCancel>
            <Button variant="destructive" className="disabled:opacity-50" disabled={tearingDown} onClick={() => void tearDown()} data-testid="firewall-confirm-tear-down">
              {tearingDown ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              Delete firewall
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog open={confirmStop} onOpenChange={setConfirmStop}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Stop the firewall?</AlertDialogTitle>
            <AlertDialogDescription>
              {view.securedAgents > 0
                ? `Your ${view.securedAgents} secured ${view.securedAgents === 1 ? "agent loses" : "agents lose"} all outbound access until you start it again. Nothing bypasses the firewall while it is down.`
                : "Secured agents lose all outbound access until you start it again. Nothing bypasses the firewall while it is down."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep running</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                setConfirmStop(false);
                void run("stop");
              }}
              data-testid="firewall-confirm-stop"
            >
              Stop firewall
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* What it costs, then the code. The firewall never gets the first-use shortcut, so the code
          step always follows this one. */}
      <UpdateConfirmDialog
        open={confirmUpdate}
        busy={starting}
        onConfirm={() => void startUpdate()}
        onCancel={() => setConfirmUpdate(false)}
        available={update?.available}
        testId="firewall-update-confirm"
        copy={{
          title: "Update your firewall?",
          lines: [
            <>
              This reinstalls the firewall’s software from scratch. It takes{" "}
              <strong className="text-ink">a few minutes</strong>, and the box stops reporting in for most of that. This
              is normal, not a failure.
            </>,
            <>
              {view.securedAgents > 0
                ? `Your ${view.securedAgents} secured ${view.securedAgents === 1 ? "agent has" : "agents have"} no internet access while it runs, because everything they do goes through here.`
                : "Secured agents have no internet access while it runs, because everything they do goes through here."}{" "}
              Your Internet access rules, channel tokens and certificate authority are kept.
            </>,
            <>
              Your firewall sends a 6-digit code over a channel you already use, and nothing starts until you enter it.
            </>,
          ],
          action: "Update firewall",
        }}
      />

    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line/60 pb-2">
      <dt className="text-ink-2">{label}</dt>
      <dd className={cn("text-right text-ink", mono && "font-mono text-[12.5px]")}>{value}</dd>
    </div>
  );
}
