"use client";

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { AppLink as Link } from "../../lib/link";
import { AlertTriangle, Loader2, MessageSquare, Plus, ShieldAlert, ShieldCheck, UserCheck, XCircle } from "lucide-react";
import { useApi } from "../../lib/api";
import { openInNewTab } from "../../lib/open-in-new-tab";
import { cn } from "../../lib/utils";
import { Button } from "../../ui/button";
import { channelName, type AgentChannelsView, type ApprovedPersonView, type ConnectionView, type PairingsErrorView, type PendingPairingView } from "../../lib/channels-schema";
import type { BoxRead } from "../../lib/channel-states";
import { ConfirmCodeDialog, SlackDialog, TelegramDialog, WhatsappDialog } from "./ChannelDialogs";
import { ChangeHistory, ICON, RefreshButton, statusLine } from "./ChannelBits";
import { useChannelChange } from "./useChannelChange";
import { IDLE } from "../change/useFirewallChange";
import { closingCancels } from "../../lib/firewall-change";
import { StatusPill } from "../../kit/StatusPill";
import { ActionMenu, Pill, type MenuItem } from "../../kit/console-ui";
import { useRoutes } from "../../lib/routes";
import { ChannelConnectedBanner } from "./PairingStep";
import { pairingStepProps, usePairingSession } from "./usePairingSession";
import type { AgentChannelType } from "../../lib/channel-states";

/** Poll cadence: fast while a change or a QR is live, relaxed otherwise. */
const POLL_ACTIVE_MS = 3_000;
const POLL_IDLE_MS = 20_000;

type Dialog =
  | { kind: "telegram"; connection: ConnectionView | null }
  | { kind: "slack"; connection: ConnectionView | null }
  | { kind: "whatsapp" }
  | null;

export interface ChannelsPanelProps {
  initial: AgentChannelsView;
  /** Demo pages pass false so the panel never calls the RPC. */
  live?: boolean;
  /** Cards after the agent's own channels (the console: Team chat, which every agent is in). */
  afterCards?: (view: AgentChannelsView) => ReactNode;
  /** WhatsApp can be linked (the firewall's own panel has no WhatsApp yet). */
  whatsapp?: boolean;
  /**
   * The agent's waiting pairings are read live and approved here. Without it (the firewall's panel,
   * which reads no pairing list) neither the list nor the "approve yourself below" note is shown.
   */
  pairings?: boolean;
}

export function ChannelsPanel({ initial, live = true, afterCards, whatsapp: whatsappOn = true, pairings: pairingsOn = true }: ChannelsPanelProps) {
  const api = useApi();
  const routes = useRoutes();
  const [view, setView] = useState<AgentChannelsView>(initial);
  const [dialog, setDialog] = useState<Dialog>(null);
  /** A connect dialog is waiting for the first request: poll at the fast cadence. */
  const [pairingOn, setPairingOn] = useState(false);
  // True once "Show QR code" was pressed in this dialog session, so an old "connected" state from
  // a previous link is not mistaken for a login in progress.
  const [waStarted, setWaStarted] = useState(false);
  // The WhatsApp connection the dialog is about: the one on this agent, or a spare being linked here.
  const [waConnectionId, setWaConnectionId] = useState<string | null>(null);
  const vmId = initial.vm.vmId;
  const lastPendingId = useRef<string | null>(initial.pending?.id ?? null);
  /**
   * Whether the deferred live read has been asked for yet; see the poll loop below. Set when the
   * read runs, not when it is scheduled, so a mount that is torn down before its timer fires
   * (StrictMode does exactly that in dev) does not spend the one immediate read.
   */
  const asked = useRef(false);

  const refresh = useCallback(async () => {
    if (!live) return view;
    try {
      const fresh = await api.channels.listAgent({ vmId });
      setView(fresh);
      return fresh;
    } catch (error) {
      console.error("channels.listAgent failed", error);
      return view;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, vmId, api]);

  /** The pairing step a connect dialog moves on to; see the organization page. */
  const pairing = usePairingSession();

  const change = useChannelChange({
    live,
    initial: initial.pending,
    onSettled: () => refresh(),
    // Same as the organization page: the token dialog closes when the change lands, the WhatsApp
    // one stays because it is where the QR code appears, and a new channel's dialog moves on to
    // pairing and closes once the first request is approved there.
    onDone: (c) => {
      const next = pairing.onChangeDone(c);
      if (next === "pairing" && (c.channelType === "telegram" || c.channelType === "slack")) setDialog({ kind: c.channelType, connection: null });
      else if (next === "paired") setDialog(null);
      else setDialog((d) => (d?.kind === "whatsapp" ? d : null));
    },
  });
  const { tracking, state, setState } = change;

  // The page itself: live status, pairings, the QR.
  useEffect(() => {
    if (!live) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;
    const loop = async () => {
      if (stopped) return;
      asked.current = true;
      const fresh = await refresh();
      if (stopped) return;
      // A plugin install runs for minutes; at the idle interval the card would look stuck.
      const installing = Object.values(fresh.live.status).some((s) => s?.setup?.state === "installing");
      const fast =
        !!fresh.pending || installing || fresh.live.whatsappLogin?.state === "qr" || fresh.live.whatsappLogin?.state === "installing" || dialog?.kind === "whatsapp" || pairingOn;
      timer = setTimeout(loop, fast ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    };
    // The server renders with the live read deferred, so the first ask is this one: no delay, or
    // the cards would sit on their last known status for three seconds for no reason. Only the
    // first — this effect re-runs whenever a dialog opens, and that is not a reason to re-read.
    timer = setTimeout(loop, initial.live.boxRead === "deferred" && !asked.current ? 0 : POLL_ACTIVE_MS);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, refresh, dialog?.kind, pairingOn]);

  // A change started elsewhere (another tab, the Channels page) shows up here too.
  useEffect(() => {
    if (view.pending && view.pending.id !== lastPendingId.current) {
      lastPendingId.current = view.pending.id;
      change.setTracking(view.pending);
    }
    if (!view.pending) lastPendingId.current = null;
  }, [view.pending]); // eslint-disable-line react-hooks/exhaustive-deps

  // The code dialog takes over from a token dialog; the WhatsApp dialog stays until it is linked,
  // and a dialog on its pairing step stays behind the code dialog, to come back if it is cancelled.
  useEffect(() => {
    if (tracking?.status === "awaiting_code") setDialog((d) => (d?.kind === "whatsapp" || pairing.session ? d : null));
  }, [tracking?.status]); // eslint-disable-line react-hooks/exhaustive-deps

  const codeChange = tracking?.status === "awaiting_code" ? tracking : null;
  const canAct = view.canManage && view.firewall.reachable && !tracking;
  const whatsapp = view.assigned.find((c) => c.type === "whatsapp") ?? null;
  // The firewall's list can be a beat behind an approval that just applied, so either one counts.
  const approvedHere = view.recent.some((r) => r.kind === "approve_pairing" && r.status === "applied") || (view.approved?.length ?? 0) > 0;

  const approve = (p: PendingPairingView) => {
    if (!p.connectionId) return;
    void change.start(
      () => api.channels.approvePairing({ connectionId: p.connectionId!, code: p.code, senderId: p.senderId, label: p.label ?? undefined }),
      `Approving ${p.label ?? p.senderId}…`,
      { connectionId: p.connectionId, channelType: p.type, kind: "approve_pairing", vmId },
    );
  };

  // A new WhatsApp number (not a move or a re-link) pairs like a new bot, once it is linked.
  const waNew = pairingsOn && dialog?.kind === "whatsapp" && waConnectionId === null ? whatsapp : null;
  const waLinked = waStarted && view.live.whatsappLogin?.state === "connected";
  useEffect(() => {
    if (waNew && waLinked && pairing.session?.connectionId !== waNew.id) pairing.begin({ type: "whatsapp", connectionId: waNew.id, vmId, start: { type: "whatsapp", number: null } });
  }, [waNew?.id, waLinked]); // eslint-disable-line react-hooks/exhaustive-deps
  const pairingShown = !!pairing.session && !!dialog;
  useEffect(() => setPairingOn(pairingShown), [pairingShown]);

  /** The pairing step's props for the dialog of this type, or null when it is not pairing. */
  const pairingFor = (type: AgentChannelType) => {
    const s = pairing.session;
    if (!pairingsOn || !s || s.type !== type) return null;
    return pairingStepProps({
      session: s,
      start: s.type === "whatsapp" ? { type: "whatsapp", number: view.live.status.whatsapp?.self ?? null } : undefined,
      agentName: view.vm.displayName || view.vm.name,
      pairings: view.live.pairings,
      boxRead: view.live.boxRead,
      pairingsError: view.live.pairingsError,
      state,
      tracking,
      canApprove: canAct,
      onApprove: approve,
      onClose: closePairing,
    });
  };
  /** Closing mid-way leaves the request where it always was: under "Who can talk to it". */
  function closePairing() {
    pairing.end();
    setWaStarted(false);
    setWaConnectionId(null);
    setDialog(null);
    setState(IDLE);
  }

  /** Put a spare connection on this agent. A WhatsApp number needs a QR scan, so it opens the dialog. */
  const enable = (c: ConnectionView) => {
    if (c.type === "whatsapp") {
      setState(IDLE);
      setWaConnectionId(c.id);
      setWaStarted(false);
      setDialog({ kind: "whatsapp" });
      return;
    }
    void change.start(() => api.channels.assign({ connectionId: c.id, vmId }), "Adding it to this agent…", {
      connectionId: c.id,
      channelType: c.type,
      kind: "assign",
      vmId,
    });
  };

  return (
    <div className="grid grid-cols-1 gap-4" data-testid="channels-panel">
      {!view.firewall.reachable && (
        <div className="flex gap-3 rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13.5px] text-ask-fg" data-testid="channels-no-firewall">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            {view.firewall.state === "none" || view.firewall.state === "inactive"
              ? "This agent has no firewall, so you can’t set up channels on it. New secured agents get one automatically."
              : view.firewall.state === "starting"
                ? "Your firewall is still starting. You can set up channels once it reports in."
                : "Your firewall hasn’t reported in recently. Channel changes go through it, so they wait until it’s back."}{" "}
            <Link href={routes.firewall} className="font-medium underline">
              Open Firewall
            </Link>
          </div>
        </div>
      )}

      {pairing.connected ? <ChannelConnectedBanner type={pairing.connected} onDismiss={pairing.dismissConnected} /> : null}

      {pairingsOn && view.live.boxRead !== "unreachable" && !approvedHere && view.assigned.some((c) => c.state === "active") && (
        <div className="flex gap-3 rounded-xl border border-line bg-bg-2 px-4 py-3 text-[13.5px] text-ink-2" data-testid="channels-tofu-note">
          <UserCheck className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            Nobody is approved to talk to this agent yet. Message it on a connected channel, then approve yourself below. After that, every change
            here needs a code that the agent sends to an approved person.
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-end gap-2" data-testid="channels-actions">
        <RefreshButton onRefresh={refresh} testId="channels-refresh" />
        <AddChannelMenu
          available={view.available}
          canAct={canAct}
          hasWhatsapp={!whatsappOn || !!whatsapp || view.available.some((c) => c.type === "whatsapp")}
          onEnable={enable}
          onNew={(type) => {
            setState(IDLE);
            if (type === "whatsapp") {
              setWaConnectionId(null);
              setWaStarted(false);
              setDialog({ kind: "whatsapp" });
            } else setDialog({ kind: type, connection: null });
          }}
        />
      </div>

      {view.assigned.length === 0 ? (
        <div className="rounded-xl border border-line bg-surface p-6 text-center" data-testid="channels-empty">
          <MessageSquare className="mx-auto h-6 w-6 text-ink-2" />
          <div className="mt-2 text-sm font-semibold text-ink">This agent answers on web chat only</div>
          <p className="mx-auto mt-1 max-w-md text-[13.5px] text-ink-2">
            Add a channel so people can reach it on {whatsappOn ? "Telegram, Slack or WhatsApp" : "Telegram or Slack"}. Each channel works with one agent at a time.
          </p>
          {view.orgHasChannelOnAgent === false && (
            <p className="mx-auto mt-2 max-w-md text-[13.5px] text-ink-2" data-testid="channels-empty-codes">
              Your organization needs at least one channel. Your firewall sends security codes there, and you need a code for secure changes to your
              firewall and agents, like updates.
            </p>
          )}
          <Button asChild size="sm" variant="outline" className="mt-3">
            <Link href={routes.channels}>See all channels</Link>
          </Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          {view.assigned.map((c) => (
            <AssignedCard
              key={c.id}
              connection={c}
              liveStatus={view.live.status[c.type] ?? null}
              canAct={canAct}
              onReplace={() => (setState(IDLE), setDialog({ kind: c.type === "slack" ? "slack" : "telegram", connection: c }))}
              onRelink={() => (setState(IDLE), setWaStarted(false), setWaConnectionId(c.id), setDialog({ kind: "whatsapp" }))}
              onDisable={() =>
                void change.start(() => api.channels.unassign({ connectionId: c.id }), "Removing it from this agent…", {
                  connectionId: c.id,
                  channelType: c.type,
                  kind: "unassign",
                  vmId,
                })
              }
            />
          ))}
        </div>
      )}

      {afterCards?.(view)}

      {pairingsOn ? (
        <PairingsList
          pairings={view.live.pairings}
          pairingsError={view.live.pairingsError}
          boxRead={view.live.boxRead}
          agentRunning={view.vm.status === "running"}
          onRetry={refresh}
          canManage={canAct}
          onApprove={approve}
          approved={view.approved}
          firewallHref={`${routes.firewall}#codes`}
        />
      ) : null}

      {tracking && tracking.status !== "awaiting_code" && (
        <div className="flex items-center gap-2 rounded-xl border border-line bg-surface px-4 py-3 text-[13.5px] text-ink-2" data-testid="channels-change-pending">
          <Loader2 className="h-4 w-4 animate-spin" />
          {state.note ?? "Sending the change to your firewall…"}
        </div>
      )}
      {state.error && !dialog && (
        <div className="flex items-start gap-2 rounded-xl border border-block-border bg-block-soft px-4 py-3 text-[13.5px] text-block-fg" data-testid="channels-change-error">
          <XCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="flex-1">{state.error}</div>
          <button className="text-[12.5px] underline" onClick={() => setState(IDLE)}>
            Dismiss
          </button>
        </div>
      )}

      <ChangeHistory recent={view.recent} />

      <TelegramDialog
        open={dialog?.kind === "telegram" && !codeChange}
        replace={dialog?.kind === "telegram" && !!dialog.connection}
        state={state}
        pairing={dialog?.kind === "telegram" ? pairingFor("telegram") : null}
        onClose={() => (pairing.end(), closingCancels(tracking?.status) ? void change.cancel().then(() => setDialog(null)) : (setDialog(null), setState(IDLE)))}
        onSubmit={({ botToken, label, start }) => {
          const existing = dialog?.kind === "telegram" ? dialog.connection : null;
          if (existing) {
            void change.start(() => api.channels.replaceSecret({ connectionId: existing.id, botToken, label }), "Sending the token to your firewall…", {
              connectionId: existing.id,
              channelType: "telegram",
              kind: "replace",
              vmId,
            });
          } else {
            if (pairingsOn) pairing.arm(start);
            void change.start(() => api.channels.add({ type: "telegram", botToken, label, vmId }), "Sending the token to your firewall…", {
              channelType: "telegram",
              kind: "add",
              vmId,
            });
          }
        }}
      />
      <SlackDialog
        open={dialog?.kind === "slack" && !codeChange}
        replace={dialog?.kind === "slack" && !!dialog.connection}
        state={state}
        pairing={dialog?.kind === "slack" ? pairingFor("slack") : null}
        onClose={() => (pairing.end(), closingCancels(tracking?.status) ? void change.cancel().then(() => setDialog(null)) : (setDialog(null), setState(IDLE)))}
        onSubmit={({ botToken, appToken, label, start }) => {
          const existing = dialog?.kind === "slack" ? dialog.connection : null;
          if (existing) {
            void change.start(() => api.channels.replaceSecret({ connectionId: existing.id, botToken, appToken, label }), "Sending the tokens to your firewall…", {
              connectionId: existing.id,
              channelType: "slack",
              kind: "replace",
              vmId,
            });
          } else {
            if (pairingsOn) pairing.arm(start);
            void change.start(() => api.channels.add({ type: "slack", botToken, appToken, label, vmId }), "Sending the tokens to your firewall…", {
              channelType: "slack",
              kind: "add",
              vmId,
            });
          }
        }}
      />
      <WhatsappDialog
        // On its pairing step, it steps aside for the code dialog like the token dialogs do.
        open={dialog?.kind === "whatsapp" && !(codeChange && pairing.session?.type === "whatsapp")}
        state={state}
        pairing={dialog?.kind === "whatsapp" ? pairingFor("whatsapp") : null}
        // `installing` counts as in-progress too: coming back to the page mid-install must show
        // that it is running, not the "pick a number" chooser as if nothing had been started.
        login={waStarted || view.live.whatsappLogin?.state === "qr" || view.live.whatsappLogin?.state === "installing" ? view.live.whatsappLogin : null}
        onShowCode={() => void openInNewTab(() => api.vm.openAgentWhatsapp({ id: vmId }), "Couldn’t open the WhatsApp code")}
        onClose={() => {
          setWaStarted(false);
          setWaConnectionId(null);
          pairing.end();
          if (closingCancels(tracking?.status)) void change.cancel();
          setDialog(null);
          setState(IDLE);
          void refresh();
        }}
        onStart={(personal) => {
          setWaStarted(true);
          const connectionId = waConnectionId ?? whatsapp?.id;
          void change.start(
            // A number moved here keeps what it was linked as, so `personal` only travels when
            // this dialog is what chose it.
            () => api.channels.whatsappLogin({ vmId, connectionId, ...(connectionId ? {} : { personal }) }),
            "Asking the agent for a QR code…",
            { connectionId: connectionId ?? null, channelType: "whatsapp", kind: "whatsapp_login", vmId },
          );
        }}
      />
      <ConfirmCodeDialog change={codeChange} state={state} onSubmit={change.confirm} onCancel={() => void change.cancel()} />
    </div>
  );
}

function AssignedCard({
  connection: c,
  liveStatus,
  canAct,
  onReplace,
  onRelink,
  onDisable,
}: {
  connection: ConnectionView;
  liveStatus: { configured: boolean; running: boolean; connected: boolean; lastError: string | null } | null;
  canAct: boolean;
  onReplace: () => void;
  onRelink: () => void;
  onDisable: () => void;
}) {
  const Icon = ICON[c.type];
  const line = statusLine(c, liveStatus);
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-line bg-surface p-4 shadow-sm" data-testid={`channel-card-${c.type}`}>
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md bg-brand-soft text-brand-ink">
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-ink">{channelName(c.type)}</span>
            {c.label ? <span className="truncate text-xs text-ink-2">{c.label}</span> : null}
          </div>
          <div className="mt-0.5 text-xs text-ink-2">This agent answers on it.</div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <StatusPill tone={line.tone} data-testid={`channel-status-${c.type}`}>
          {line.text}
        </StatusPill>
        {c.secretHint && c.type !== "whatsapp" ? (
          <span className="font-mono text-ink-2" title="Last characters of the token">
            token {c.secretHint}
          </span>
        ) : null}
        {c.mode === "placeholder" ? (
          <span className="inline-flex items-center gap-1 text-ink-2" title="Your firewall keeps the real token. The agent has only a stand-in.">
            <ShieldCheck className="h-3 w-3" /> proxy-held
          </span>
        ) : null}
      </div>
      <div className="mt-auto flex gap-2 pt-1">
        <Button
          size="sm"
          variant="outline"
          className="flex-1"
          disabled={!canAct}
          onClick={c.type === "whatsapp" ? onRelink : onReplace}
          data-testid={`channel-setup-${c.type}`}
        >
          {c.type === "whatsapp" ? "Link again" : "Replace token"}
        </Button>
        <Button size="sm" variant="outline" disabled={!canAct} onClick={onDisable} data-testid={`channel-disable-${c.type}`}>
          Remove from agent
        </Button>
      </div>
    </div>
  );
}

/**
 * "Add channel": a spare connection of the organization's to put on this agent, or a new one. A
 * channel belongs to the organization and answers on one agent at a time.
 */
function AddChannelMenu({
  available,
  canAct,
  hasWhatsapp,
  onEnable,
  onNew,
}: {
  available: ConnectionView[];
  canAct: boolean;
  hasWhatsapp: boolean;
  onEnable: (c: ConnectionView) => void;
  onNew: (type: "telegram" | "slack" | "whatsapp") => void;
}) {
  const routes = useRoutes();
  const spare: MenuItem[] = available.map((c) => ({
    icon: ICON[c.type],
    label: c.label ? `${channelName(c.type)} · ${c.label}` : channelName(c.type),
    sub: c.type === "whatsapp" ? "Not on an agent: scan a new QR code to link it here" : `Not on an agent: add it here${c.secretHint ? ` · token ${c.secretHint}` : ""}`,
    onClick: () => onEnable(c),
    disabled: !canAct,
    "data-testid": "channels-enable-available",
  }));
  return (
    <ActionMenu
      label="Add channel"
      icon={Plus}
      data-testid="channels-enable"
      items={[
        ...spare,
        ...(spare.length ? ["-" as const] : []),
        { icon: ICON.telegram, label: "New Telegram bot", onClick: () => onNew("telegram"), disabled: !canAct, "data-testid": "channel-new-telegram" },
        { icon: ICON.slack, label: "New Slack app", onClick: () => onNew("slack"), disabled: !canAct, "data-testid": "channel-new-slack" },
        ...(!hasWhatsapp ? [{ icon: ICON.whatsapp, label: "Link WhatsApp", onClick: () => onNew("whatsapp"), disabled: !canAct, "data-testid": "channel-new-whatsapp" }] : []),
        "-",
        { label: "All channels", sub: "Move a channel from another agent", href: routes.channels, "data-testid": "channels-all-link" },
      ]}
    />
  );
}

function PairingsList({
  pairings,
  pairingsError,
  boxRead,
  agentRunning,
  canManage,
  onApprove,
  onRetry,
  approved,
  firewallHref,
}: {
  pairings: PendingPairingView[];
  pairingsError: PairingsErrorView | null;
  boxRead: BoxRead;
  agentRunning: boolean;
  canManage: boolean;
  onApprove: (p: PendingPairingView) => void;
  onRetry: () => Promise<unknown>;
  /** From the firewall's last report; null when it never sent one, undefined where nobody asked. */
  approved?: ApprovedPersonView[] | null;
  firewallHref: string;
}) {
  return (
    <div className="rounded-xl border border-line bg-surface p-4" data-testid="channels-pairings">
      <div className="flex items-center gap-2">
        <UserCheck className="h-4 w-4 shrink-0 text-ink-2" />
        <div className="min-w-0 flex-1 text-sm font-semibold text-ink">Who can talk to it</div>
        {agentRunning && boxRead === "ok" && !(pairings.length === 0 && pairingsError) ? (
          <Pill tone={pairings.length ? "ask" : "muted"} dot={false} testId="channels-pairings-count">
            {pairings.length ? `${pairings.length} waiting` : "No one waiting"}
          </Pill>
        ) : null}
      </div>
      <p className="mt-1 text-[13px] text-ink-2">
        When someone messages the agent for the first time, they get a pairing code and appear here. Approve them and the agent starts answering. The
        first person you approve gets the confirmation codes, and stays approved if the channel moves to another agent.
      </p>
      {!agentRunning ? (
        <div className="mt-3 text-[13px] text-ink-2">The agent isn’t running. Start it to see who is waiting.</div>
      ) : boxRead === "deferred" ? (
        <div className="mt-3 flex items-center gap-2 text-[13px] text-ink-2" data-testid="channels-pairings-loading">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Reading the agent…
        </div>
      ) : boxRead === "unreachable" ? (
        // A spinner here used to stay up for as long as the box was quiet, which reads as "still
        // loading" forever. Say what happened and offer another go.
        <div className="mt-3 flex flex-wrap items-center gap-2 text-[13px] text-ask" data-testid="channels-pairings-unreachable">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          <span>The agent didn’t answer, so ControlClaw couldn’t check who is waiting.</span>
          <RefreshButton onRefresh={onRetry} label="Try again" testId="channels-pairings-retry" />
        </div>
      ) : pairings.length === 0 && pairingsError ? (
        // Not the same as "nobody is waiting": the box could not be asked. Saying "no pending
        // requests" here is how somebody ends up waiting for a request that is sitting right there.
        <div
          className={cn("mt-3 flex items-center gap-2 text-[13px]", pairingsError.busy ? "text-ink-2" : "text-block")}
          data-testid="channels-pairings-error"
        >
          {pairingsError.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <AlertTriangle className="h-3.5 w-3.5" />}
          {pairingsError.message}
        </div>
      ) : pairings.length === 0 ? (
        <div className="mt-3 text-[13px] text-ink-2">No one is waiting for approval.</div>
      ) : (
        <ul className="mt-3 divide-y divide-line">
          {pairings.map((p) => (
            <li key={`${p.type}:${p.senderId}`} className="flex items-center gap-3 py-2 text-[13.5px]" data-testid="channels-pairing">
              <span className="shrink-0 whitespace-nowrap rounded-full bg-bg-2 px-2 py-0.5 text-xs font-medium capitalize text-ink-2">{p.type}</span>
              <span className="min-w-0 flex-1 truncate text-ink">
                {p.label ?? p.senderId}
                {p.label ? <span className="ml-1 font-mono text-xs text-ink-2">{p.senderId}</span> : null}
              </span>
              <span className="font-mono text-xs text-ink-2" title="The pairing code the agent sent them">
                {p.code}
              </span>
              <Button size="sm" disabled={!canManage || !p.connectionId} onClick={() => onApprove(p)} data-testid="channels-pairing-approve">
                Approve
              </Button>
            </li>
          ))}
        </ul>
      )}
      <ApprovedPeople approved={approved} firewallHref={firewallHref} />
    </div>
  );
}

/**
 * The people already approved on this agent's channels, under the waiting ones. The list is the
 * firewall's (the Firewall page's "Who gets confirmation codes"); without it, the copy points there.
 */
function ApprovedPeople({ approved, firewallHref }: { approved: ApprovedPersonView[] | null | undefined; firewallHref: string }) {
  if (approved === undefined) return null;
  if (approved === null) {
    return (
      <p className="mt-3 border-t border-line pt-3 text-[13px] text-ink-2" data-testid="channels-approved-elsewhere">
        People you approved are listed on the{" "}
        <Link href={firewallHref} className="font-medium underline">
          Firewall page
        </Link>
        , under Confirmation codes.
      </p>
    );
  }
  if (approved.length === 0) return null;
  return (
    <div className="mt-3 border-t border-line pt-3" data-testid="channels-approved">
      <div className="text-[13px] font-semibold text-ink">Approved</div>
      <ul className="mt-1 divide-y divide-line">
        {approved.map((p) => (
          <li key={`${p.connectionId}:${p.senderId}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-[13.5px]" data-testid="channels-approved-person">
            <span className="shrink-0 whitespace-nowrap rounded-full bg-bg-2 px-2 py-0.5 text-xs font-medium capitalize text-ink-2">{p.type}</span>
            {/* A basis, so on a phone the pill moves under the name instead of squeezing it. */}
            <span className="min-w-0 flex-1 basis-40 truncate text-ink">
              {p.label ?? p.senderId}
              {p.label ? <span className="ml-1 font-mono text-xs text-ink-2">{p.senderId}</span> : null}
            </span>
            {p.getsCodes ? null : (
              <Pill tone="muted" dot={false} testId="channels-approved-unconfirmed">
                Allowed by the agent
              </Pill>
            )}
          </li>
        ))}
      </ul>
      <p className="mt-1 text-[12.5px] text-ink-2">
        Who gets confirmation codes, and the people the agent allowed by itself, are managed on the{" "}
        <Link href={firewallHref} className="font-medium underline">
          Firewall page
        </Link>
        .
      </p>
    </div>
  );
}
