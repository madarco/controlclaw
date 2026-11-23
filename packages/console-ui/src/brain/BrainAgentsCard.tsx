"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { Bot, Loader2 } from "lucide-react";
import { useOptionalApi } from "../lib/api";
import { Switch } from "../ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Card, EmptyState } from "../kit/console-ui";
import { ConfirmCodeDialog } from "../firewall/channels/ChannelDialogs";
import { useFirewallChange, type Busy } from "../firewall/change/useFirewallChange";
import { BRAIN_SCOPE_LABEL as SCOPE_LABEL, type BrainAgentView, type BrainChangeView, type BrainScopeId } from "../lib/brain-view";
import { formatRelative } from "../kit/RelativeTime";
import type { BrainAgentUsage } from "../lib/brain-stats";

/**
 * Which of the organization's agents may use the brain (docs/plans/gbrain.md §5).
 *
 * Turning an agent on, or letting a read-only agent write, is a firewall change behind a code: the
 * firewall sends it over one of the agents' channels and the dialog here takes it. Turning an agent
 * off, or down to read only, happens at once.
 *
 * `live={false}` (the demo) renders the given state and never calls the server. The calls are the
 * `ConsoleApi`'s `brain` area, so the console and the firewall panel share this card.
 */

/** What the rows of the outside apps get from the card (the console's; the panel has none). */
export type BrainAppRowsContext = {
  /** A change is running or being followed: no other may start. */
  busy: boolean;
  /** Follow an app's change that waits for the firewall (and maybe a code). */
  track: (changeId: string, clientId: string, scope: BrainScopeId) => void;
  onError: (error: string) => void;
};

/** The outside AI apps listed with the agents, where the control plane has them. */
export type BrainAppsSlot = {
  connected: number;
  total: number;
  rows: (ctx: BrainAppRowsContext) => ReactNode;
  /** Under the list: how to add one. */
  after?: ReactNode;
};

const DEFAULT_INTRO =
  "Your agents and the outside AI apps that use the brain. Each sees everything the others saved. Turning one on needs a code your firewall sends you; turning one off is immediate.";

function blank(changeId: string): BrainChangeView {
  return {
    id: changeId,
    agentVmId: "",
    clientId: null,
    kind: "connect",
    scope: "read_write",
    summary: "",
    status: "queued",
    tofu: false,
    sentVia: null,
    attemptsLeft: null,
    expiresAt: null,
    error: null,
    createdAt: new Date().toISOString(),
    stuck: false,
  };
}

/** Why an agent cannot be switched on right now, or null. */
function blockedReason(a: BrainAgentView, brainUp: boolean): string | null {
  if (!a.secured) return "Created without a firewall, so it can’t use the brain.";
  if (!brainUp && !a.connection) return "Connect agents once the brain is running.";
  if (!a.running && !a.connection) return "Start the agent to connect it.";
  return null;
}

export function BrainAgentsCard({
  agents,
  change: initialChange,
  canManage,
  brainUp,
  live = true,
  usage,
  apps,
  title = "Connected apps",
  intro = DEFAULT_INTRO,
  captureOffNote = "Not available here.",
  onChanged,
}: {
  agents: BrainAgentView[];
  /** Outside AI apps on the brain's MCP address (T-219), listed with the agents. Left out: agents only. */
  apps?: BrainAppsSlot;
  title?: string;
  /** The line under the title. */
  intro?: ReactNode;
  /** Why "Save what it learns automatically" is off, where the API has no `setCapture`. */
  captureOffNote?: ReactNode;
  /** Searches and saves per agent over 30 days (the Agents tab). Left out: no bars. */
  usage?: BrainAgentUsage[];
  change: BrainChangeView | null;
  canManage: boolean;
  /** The brain's box is running. Connecting needs it; disconnecting does not. */
  brainUp: boolean;
  live?: boolean;
  onChanged: () => void;
}) {
  const brain = useOptionalApi()?.brain;
  if (live && !brain) throw new Error("BrainAgentsCard: the ConsoleApi has no brain area");
  const change = useFirewallChange<BrainChangeView>({
    live,
    initial: initialChange,
    onSettled: onChanged,
    rpc: brain ?? NO_RPC,
    blank,
  });
  const { tracking, state, setState } = change;
  const codeChange = tracking?.status === "awaiting_code" ? tracking : null;

  // A change started in another tab (or before the page loaded) still raises the dialog.
  const lastId = useRef<string | null>(initialChange?.id ?? null);
  useEffect(() => {
    if (initialChange && initialChange.id !== lastId.current) {
      lastId.current = initialChange.id;
      change.setTracking(initialChange);
    }
    if (!initialChange) lastId.current = null;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialChange?.id]);

  const busy = !canManage || state.busy || !!tracking;

  const connect = (a: BrainAgentView, scope: BrainScopeId) => {
    if (!live || !brain) return;
    setState({ busy: true, error: null, note: `Asking your firewall to connect ${a.name}…` });
    void brain
      .connect({ agentVmId: a.vmId, scope })
      .then((r) => {
        // No change id: the agent already has that access, so there is nothing to follow.
        if (r.changeId) change.setTracking({ ...blank(r.changeId), agentVmId: a.vmId, scope });
        else setState({ busy: false, error: null, note: null });
      })
      .catch((error: Error) => setState({ busy: false, error: error.message || "Couldn’t connect the agent. Try again.", note: null }))
      .finally(onChanged);
  };

  // "Save what it learns automatically" (T-217): no code either way, so it is set at once. The value
  // shown while the server answers is the one asked for.
  // What was asked for, until a fresh view from the server arrives: that is the truth again (also a
  // change made elsewhere, over MCP for example).
  const [asked, setAsked] = useState<{ view: BrainAgentView[]; values: Record<string, boolean> }>({ view: agents, values: {} });
  const capture = asked.view === agents ? asked.values : {};
  const setCapture = (f: (c: Record<string, boolean>) => Record<string, boolean>) => setAsked((a) => ({ view: agents, values: f(a.view === agents ? a.values : {}) }));
  const [captureBusy, setCaptureBusy] = useState<ReadonlySet<string>>(new Set());
  // Left out of the API where the agents lack the plugin it needs: the switch says so instead.
  const setCaptureCall = brain?.setCapture?.bind(brain);
  const captureOff = live && !setCaptureCall;
  const toggleCapture = (a: BrainAgentView, enabled: boolean) => {
    setCapture((c) => ({ ...c, [a.vmId]: enabled }));
    if (!live || !setCaptureCall) return;
    setCaptureBusy((b) => new Set(b).add(a.vmId));
    setState({ busy: false, error: null, note: null });
    void setCaptureCall({ agentVmId: a.vmId, enabled })
      .then(() => onChanged())
      .catch((error: Error) => {
        setCapture((c) => ({ ...c, [a.vmId]: !enabled }));
        setState({ busy: false, error: error.message || "Couldn’t change the setting. Try again.", note: null });
      })
      .finally(() =>
        setCaptureBusy((b) => {
          const next = new Set(b);
          next.delete(a.vmId);
          return next;
        }),
      );
  };

  const disconnect = (a: BrainAgentView) => {
    if (!live || !brain) return;
    setState({ busy: true, error: null, note: `Disconnecting ${a.name}…` });
    void brain
      .disconnect({ agentVmId: a.vmId })
      .then(() => setState({ busy: false, error: null, note: null }))
      .catch((error: Error) => setState({ busy: false, error: error.message || "Couldn’t disconnect the agent. Try again.", note: null }))
      .finally(onChanged);
  };

  const connected = agents.filter((a) => a.connection).length + (apps?.connected ?? 0);
  const used = new Map((usage ?? []).map((u) => [u.vmId, u]));
  const most = Math.max(1, ...(usage ?? []).map((u) => u.searches + u.saves));

  return (
    <Card className="p-5" data-testid="brain-agents">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <div className="text-[15px] font-semibold text-ink">{title}</div>
        <div className="text-[12.5px] text-ink-2" data-testid="brain-agents-count">
          {connected} of {agents.length + (apps?.total ?? 0)} connected
        </div>
      </div>
      <p className="mt-1 max-w-[70ch] text-pretty text-[13.5px] text-ink-2">{intro}</p>

      {agents.length === 0 && !apps?.total ? (
        <EmptyState icon={Bot} title="No agents yet">
          Create an agent, then connect it here.
        </EmptyState>
      ) : (
        <ul className="mt-3 divide-y divide-line rounded-[12px] border border-line" data-testid="brain-agents-list">
          {agents.map((a) => {
            const blocked = blockedReason(a, brainUp);
            const pending = tracking && tracking.agentVmId === a.vmId;
            return (
              <li key={a.vmId} className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3" data-testid={`brain-agent-${a.vmId}`}>
                {/* A floor under the name, so on a phone the controls move under it instead of squeezing it. */}
                <div className="min-w-[12rem] flex-1">
                  <div className="truncate text-[14px] font-medium text-ink" title={a.name}>
                    {a.name}
                  </div>
                  <div className="text-[12.5px] text-ink-2" data-testid={`brain-agent-state-${a.vmId}`}>
                    {pending
                      ? "Waiting for your confirmation"
                      : a.connection && a.stopped
                        ? "Connected, but locked out for now: the brain refuses its calls"
                        : a.connection
                        ? `Connected since ${new Date(a.connection.since).toLocaleDateString(undefined, { month: "short", day: "numeric" })}${lastAt(used.get(a.vmId))}`
                        : (blocked ?? "Not connected")}
                  </div>
                </div>
                {usage && (a.connection || used.has(a.vmId)) ? <UsageBar u={used.get(a.vmId)} most={most} /> : null}
                <div className="ml-auto flex shrink-0 items-center gap-3">
                  {a.connection ? (
                    <Select
                      value={a.connection.scope}
                      disabled={busy}
                      onValueChange={(v) => connect(a, v as BrainScopeId)}
                    >
                      <SelectTrigger className="h-8 w-[150px] text-[13px]" data-testid={`brain-agent-scope-${a.vmId}`}>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="read_write">{SCOPE_LABEL.read_write}</SelectItem>
                        <SelectItem value="read">{SCOPE_LABEL.read}</SelectItem>
                      </SelectContent>
                    </Select>
                  ) : null}
                  {pending && state.busy ? <Loader2 className="h-4 w-4 animate-spin text-ink-2" /> : null}
                  <Switch
                    checked={!!a.connection}
                    disabled={busy || (!a.connection && !!blocked)}
                    onCheckedChange={(on) => (on ? connect(a, "read_write") : disconnect(a))}
                    aria-label={a.connection ? `Disconnect ${a.name} from the brain` : `Connect ${a.name} to the brain`}
                    data-testid={`brain-agent-toggle-${a.vmId}`}
                  />
                </div>
                {a.connection?.scope === "read_write" && !pending ? (
                  <label
                    className="flex w-full items-start gap-2.5 rounded-[10px] bg-muted-2/60 px-3 py-2"
                    data-testid={`brain-agent-capture-${a.vmId}`}
                  >
                    <Switch
                      className="mt-0.5"
                      checked={captureOff ? false : (capture[a.vmId] ?? a.connection.autoCapture)}
                      disabled={captureOff || !canManage || captureBusy.has(a.vmId) || state.busy}
                      onCheckedChange={(on) => toggleCapture(a, on)}
                      aria-label={`Save what ${a.name} learns automatically`}
                      data-testid={`brain-agent-capture-toggle-${a.vmId}`}
                    />
                    <span className="min-w-0">
                      <span className="block text-[13px] font-medium text-ink">Save what it learns automatically</span>
                      <span className="block text-pretty text-[12.5px] text-ink-2" data-testid={captureOff ? `brain-agent-capture-off-${a.vmId}` : undefined}>
                        {captureOff
                          ? captureOffNote
                          : "After a conversation or a meeting, it saves a short summary of people, companies, meetings and projects. Never the conversation itself."}
                      </span>
                    </span>
                  </label>
                ) : null}
              </li>
            );
          })}
          {apps?.rows({
            busy: state.busy || !!tracking,
            track: (id, clientId, scope) => change.setTracking({ ...blank(id), agentVmId: null, clientId, kind: "client_change", scope }),
            onError: (error) => setState({ busy: false, error, note: null } satisfies Busy),
          })}
        </ul>
      )}
      {apps?.after}

      {state.note ? (
        <p className="mt-3 text-[13px] text-ink-2" data-testid="brain-agents-note">
          {state.note}
        </p>
      ) : null}
      {state.error ? (
        <p className="mt-3 text-[13px] text-block-fg" data-testid="brain-agents-error">
          {state.error}
        </p>
      ) : null}

      {usage ? (
        <div className="mt-3 flex gap-4 text-[12px] text-ink-2" aria-hidden="true">
          <span className="inline-flex items-center gap-1.5">
            <i className="h-2 w-2 rounded-[3px] bg-brand" />
            Searches
          </span>
          <span className="inline-flex items-center gap-1.5">
            <i className="h-2 w-2 rounded-[3px] bg-allow" />
            Saved
          </span>
          <span>· last 30 days</span>
        </div>
      ) : null}

      <ConfirmCodeDialog
        change={codeChange}
        state={state}
        sender="Your firewall"
        onSubmit={(code) => {
          setState({ busy: true, error: null, note: null });
          void change.confirm(code);
        }}
        onCancel={() => void change.cancel()}
        warning={
          codeChange?.clientId
            ? "Confirming this lets the outside app named in the message read everything in the brain, and save to it with read and write. It lasts until you remove it here or its end date."
            : "Confirming this lets the agent named in the message read what your other connected agents saved in the brain. It lasts until you turn it off here."
        }
      />
    </Card>
  );
}

/** What the change hook is given in the demo, which never calls it. */
const NO_RPC = {
  getChange: () => Promise.reject(new Error("demo")),
  confirm: () => Promise.reject(new Error("demo")),
  cancel: () => Promise.reject(new Error("demo")),
};

/** ` · last used 3h ago`, from the agent's calls of the last 30 days. */
function lastAt(u: BrainAgentUsage | undefined): string {
  return u?.lastAt ? ` · last used ${formatRelative(new Date(u.lastAt), Date.now())}` : "";
}

/** Searches and saves of one agent, as two bars scaled to the busiest agent. */
function UsageBar({ u, most }: { u: BrainAgentUsage | undefined; most: number }) {
  const searches = u?.searches ?? 0;
  const saves = u?.saves ?? 0;
  return (
    <div className="order-3 flex w-full flex-col gap-1 sm:order-none sm:w-[200px]" data-testid="brain-agent-usage">
      <span className="flex h-1.5 gap-0.5 overflow-hidden rounded-full bg-muted-2" aria-hidden="true">
        {searches > 0 ? <i className="block h-full bg-brand" style={{ width: `${(searches / most) * 100}%` }} /> : null}
        {saves > 0 ? <i className="block h-full bg-allow" style={{ width: `${(saves / most) * 100}%` }} /> : null}
      </span>
      <span className="text-[12px] text-ink-2 tabular-nums">
        {searches.toLocaleString("en-US")} {searches === 1 ? "search" : "searches"} · {saves.toLocaleString("en-US")} saved
      </span>
    </div>
  );
}
