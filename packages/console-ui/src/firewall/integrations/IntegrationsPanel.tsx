"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AppLink as Link } from "../../lib/link";
import { KeyRound, RotateCw, Trash2 } from "lucide-react";
import { useApi } from "../../lib/api";
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
import { ConfirmCodeDialog } from "../channels/ChannelDialogs";
import { RefreshButton } from "../channels/ChannelBits";
import type { ConnectorConnectionView, ConnectorsView } from "../../lib/connectors-schema";
import type { CatalogProvider } from "../../lib/connectors-schema";
import { Avatar } from "../../kit/people";
import { StatusPill } from "../../kit/StatusPill";
import { ActionMenu, Badge } from "../../kit/console-ui";
import { cn } from "../../lib/utils";
import { AuthorizeNote, ChangeHistory, FirewallNotice, PendingNote, statusLine } from "./ConnectorBits";
import { CatalogBrowser, type CatalogResult } from "./CatalogBrowser";
import { AppLogo } from "./AppLogo";
import { ConnectDialog, type ConnectSubmit } from "./ConnectDialog";
import { IDLE, useConnectorChange } from "./useConnectorChange";
import { McpServersPanel } from "./McpServersPanel";
import type { McpServersView } from "../../lib/mcp-servers-schema";
import { useRoutes } from "../../lib/routes";

/** Poll cadence: fast while a change is in flight, relaxed otherwise. */
const POLL_ACTIVE_MS = 3_000;
const POLL_IDLE_MS = 20_000;

type Dialog =
  | { kind: "connect"; provider: CatalogProvider }
  | { kind: "replace"; connection: ConnectorConnectionView; provider: CatalogProvider }
  | { kind: "remove"; connection: ConnectorConnectionView }
  | null;

export interface IntegrationsPanelProps {
  initial: ConnectorsView;
  /** Demo pages pass false so the panel never calls the RPC. */
  live?: boolean;
  /** Demo pages pass the catalog, which the panel otherwise searches on the server. */
  demoCatalog?: CatalogResult;
  /** Demo pages open the Composio tab; `?source=mcp` opens MCP servers. */
  initialSource?: Source;
  /** The organization's MCP servers, for their tab. Absent: the tab says it could not load. */
  mcp?: McpServersView | null;
}

export type Source = "open-connector" | "mcp" | "composio";

export function IntegrationsPanel({ initial, live = true, demoCatalog, initialSource = "open-connector", mcp = null }: IntegrationsPanelProps) {
  const routes = useRoutes();
  const api = useApi();
  const [view, setView] = useState<ConnectorsView>(initial);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [source, setSource] = useState<Source>(initialSource);
  const lastPendingId = useRef<string | null>(initial.pending?.id ?? null);

  const refresh = useCallback(async () => {
    if (!live) return view;
    try {
      const fresh = await api.integrations.list();
      setView(fresh);
      return fresh;
    } catch (error) {
      console.error("integrations.list failed", error);
      return view;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, api]);

  const change = useConnectorChange({ live, initial: initial.pending, onSettled: () => refresh() });
  const { tracking, state, setState } = change;

  useEffect(() => {
    if (!live) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let stopped = false;
    const loop = async () => {
      if (stopped) return;
      const fresh = await refresh();
      if (stopped) return;
      timer = setTimeout(loop, fresh.pending ? POLL_ACTIVE_MS : POLL_IDLE_MS);
    };
    timer = setTimeout(loop, POLL_ACTIVE_MS);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [live, refresh]);

  // A change started elsewhere (another tab, an agent's page) shows up here too.
  useEffect(() => {
    if (view.pending && view.pending.id !== lastPendingId.current) {
      lastPendingId.current = view.pending.id;
      change.setTracking(view.pending);
    }
    if (!view.pending) lastPendingId.current = null;
  }, [view.pending]); // eslint-disable-line react-hooks/exhaustive-deps

  // The code dialog and the OAuth hand-off take over from the connect dialog.
  useEffect(() => {
    if (tracking?.status === "awaiting_code" || tracking?.status === "awaiting_authorization") setDialog(null);
  }, [tracking?.status]);

  // A change that went through closes the dialog it was started from. One that FAILED does not:
  // the reason is rendered inside that dialog, and closing it would take the reason with it.
  const wasTracking = useRef(false);
  useEffect(() => {
    if (wasTracking.current && !tracking && !state.error) setDialog(null);
    wasTracking.current = !!tracking;
  }, [tracking, state.error]);

  const codeChange = tracking?.status === "awaiting_code" ? tracking : null;
  const authorizing = tracking?.status === "awaiting_authorization" ? tracking : null;
  const canAct = view.canManage && view.firewall.reachable && view.firewall.supported && !tracking;

  const startConnect = (provider: CatalogProvider, input: ConnectSubmit) => {
    if (input.authType === "oauth2") {
      void change.start(
        () =>
          api.integrations.oauthConnect({
            service: provider.service,
            label: input.label || undefined,
            clientFields: input.clientFields,
            authorizationOptionIds: input.authorizationOptionIds,
            vmIds: input.vmIds,
          }),
        `Connecting ${provider.name}…`,
        { service: provider.service, kind: "oauth_connect" },
      );
      return;
    }
    void change.start(
      () =>
        api.integrations.connect({
          service: provider.service,
          authType: input.authType,
          label: input.label || undefined,
          secrets: input.secrets,
          extra: input.extra,
          vmIds: input.vmIds,
        }),
      `Connecting ${provider.name}…`,
      { service: provider.service, kind: "connect" },
    );
  };

  return (
    <div className="grid grid-cols-1 gap-4" data-testid="integrations-panel">
      {/* Above the source switch, so a change in flight keeps its status and sign-in link on both tabs. */}
      <FirewallNotice firewall={view.firewall} firewallHref={routes.firewall} />
      {tracking && !codeChange && !authorizing && <PendingNote note={state.note} />}
      {authorizing && <AuthorizeNote change={authorizing} onCancel={() => void change.cancel()} />}
      {state.error && !tracking && !dialog ? (
        <div className="rounded-xl border border-block-border bg-block-soft px-4 py-3 text-[13.5px] text-block-fg" data-testid="integrations-error">
          {state.error}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-[14px] font-semibold text-ink">
          Connected <span className="font-normal text-ink-2">{view.connections.length}</span>
        </h3>
        <div className="ml-auto">
          <RefreshButton
            onRefresh={async () => {
              if (live && view.canManage && view.firewall.reachable && view.firewall.supported) {
                // Ask the firewall for its own list too, so a connection it lost goes away here.
                await api.integrations.refresh().catch((error) => console.error("integrations.refresh failed", error));
              }
              await refresh();
            }}
            testId="integrations-refresh"
          />
        </div>
      </div>

      {view.connections.length === 0 ? (
        <p className="rounded-xl border border-dashed border-line-2 px-4 py-3 text-[13px] text-ink-2" data-testid="connectors-empty">
          {view.canManage ? "No apps connected yet. Pick one below. You sign in once, then choose which agents may use it." : "Nobody has connected an app for this organization yet."}
        </p>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(300px,100%),1fr))] gap-3">
          {view.connections.map((c) => (
            <ConnectionCard
              key={c.id}
              connection={c}
              agents={view.agents}
              canAct={canAct}
              onAssign={(vmId, on) =>
                void change.start(() => api.integrations.assign({ connectionId: c.id, vmId, on }), on ? "Adding it to the agent…" : "Removing it from the agent…", {
                  connectionId: c.id,
                  service: c.service,
                  kind: on ? "assign" : "unassign",
                })
              }
              onReplace={() => (setState(IDLE), setDialog({ kind: "replace", connection: c, provider: providerOf(c) }))}
              onReconnect={() =>
                void change.start(() => api.integrations.oauthReconnect({ connectionId: c.id }), `Signing in to ${c.serviceName} again…`, {
                  connectionId: c.id,
                  service: c.service,
                  kind: "oauth_reconnect",
                })
              }
              onRemove={() => setDialog({ kind: "remove", connection: c })}
            />
          ))}
        </div>
      )}

      {/* The switch picks where new apps come from; the apps already connected stay above it. */}
      <h3 className="mt-2 text-[14px] font-semibold text-ink">Add an app</h3>
      <SourceSwitch source={source} onChange={setSource} />
      {source === "composio" ? (
        <ComposioTeaser />
      ) : source === "mcp" ? (
        mcp ? (
          <McpServersPanel initial={mcp} live={live} />
        ) : (
          <p className="rounded-xl border border-dashed border-line-2 px-4 py-3 text-[13px] text-ink-2">Couldn’t load the MCP servers. Reload the page to try again.</p>
        )
      ) : (
        <CatalogBrowser canConnect={canAct} onPick={(p) => (setState(IDLE), setDialog({ kind: "connect", provider: p }))} demo={demoCatalog} />
      )}

      <ChangeHistory recent={view.recent} />

      <ConnectDialog
        provider={dialog?.kind === "connect" ? dialog.provider : dialog?.kind === "replace" ? dialog.provider : null}
        replacing={dialog?.kind === "replace"}
        agents={view.agents.map((a) => ({ vmId: a.vmId, name: a.displayName || a.name }))}
        state={state}
        onClose={() => setDialog(null)}
        onSubmit={(input) => {
          if (dialog?.kind === "replace") {
            if (input.authType === "oauth2") return;
            void change.start(
              () => api.integrations.replace({ connectionId: dialog.connection.id, secrets: input.secrets, extra: input.extra }),
              "Replacing the credentials…",
              { connectionId: dialog.connection.id, service: dialog.connection.service, kind: "replace" },
            );
            return;
          }
          if (dialog?.kind === "connect") startConnect(dialog.provider, input);
        }}
      />
      <ConfirmCodeDialog
        change={codeChange}
        state={state}
        sender="Your agent"
        onSubmit={change.confirm}
        onCancel={() => void change.cancel()}
      />
      <AlertDialog open={dialog?.kind === "remove"} onOpenChange={(o) => !o && setDialog(null)}>
        <AlertDialogContent data-testid="integrations-remove-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {dialog?.kind === "remove" ? dialog.connection.serviceName : "this app"}?</AlertDialogTitle>
            <AlertDialogDescription>
              Your firewall deletes the credentials, and agents using it lose access. Your account at the app is unchanged, so you can connect it
              again at any time.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep it</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (dialog?.kind !== "remove") return;
                const c = dialog.connection;
                setDialog(null);
                void change.start(() => api.integrations.remove({ connectionId: c.id }), `Removing ${c.serviceName}…`, {
                  connectionId: c.id,
                  service: c.service,
                  kind: "remove",
                });
              }}
              data-testid="integrations-remove-confirm"
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

/**
 * The catalog entry behind a connection, for the replace dialog. A connection of a provider this
 * build's catalog does not know still has to render, so it falls back to the stored ids.
 */
function providerOf(c: ConnectorConnectionView): CatalogProvider {
  return { service: c.service, name: c.serviceName, categories: [], authTypes: [c.authType], actions: 0 };
}

function ConnectionCard({
  connection,
  agents,
  canAct,
  onAssign,
  onReplace,
  onReconnect,
  onRemove,
}: {
  connection: ConnectorConnectionView;
  agents: ConnectorsView["agents"];
  canAct: boolean;
  onAssign: (vmId: string, on: boolean) => void;
  onReplace: () => void;
  onReconnect: () => void;
  onRemove: () => void;
}) {
  const routes = useRoutes();
  const s = statusLine(connection);
  const isOauth = connection.authType === "oauth2";
  return (
    <div
      className={cn("grid min-w-0 grid-cols-1 gap-3 rounded-xl border bg-surface p-4", s.tone === "allow" ? "border-allow-border" : "border-line")}
      data-testid={`connector-card-${connection.service}`}
    >
      <div className="flex items-center gap-2.5">
        <AppLogo name={connection.serviceName} home={connection.home} size={36} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[14px] font-semibold text-ink">
            {connection.serviceName}
            {connection.label ? <span className="font-normal text-ink-2"> · {connection.label}</span> : null}
          </div>
          <div className="truncate text-[12.5px] text-ink-2">{connection.accountLabel ?? (isOauth ? "OAuth" : "API key")}</div>
        </div>
        <ActionMenu
          ariaLabel={`${connection.serviceName} actions`}
          data-testid="connector-menu"
          items={[
            isOauth
              ? { icon: RotateCw, label: "Sign in again", disabled: !canAct, onClick: onReconnect, "data-testid": "connector-reconnect" }
              : {
                  icon: KeyRound,
                  label: "Replace credentials",
                  disabled: !canAct || connection.state !== "active",
                  onClick: onReplace,
                  "data-testid": "connector-replace",
                },
            "-",
            { icon: Trash2, label: "Remove", danger: true, disabled: !canAct, onClick: onRemove, "data-testid": "connector-remove" },
          ]}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <StatusPill tone={s.tone} dot={false} className="text-[11.5px]" data-testid="connector-card-status">
          {s.text}
        </StatusPill>
        <Link href={routes.activity} className="ml-auto font-medium text-ink-2 underline">
          View calls
        </Link>
      </div>

      {agents.length > 0 && (
        <div className="grid grid-cols-1 gap-1 border-t border-line pt-2.5" data-testid="connector-card-agents" data-tour="connector-card-agents">
          {agents.map((a) => {
            const on = connection.agents.some((x) => x.vmId === a.vmId);
            return (
              <div key={a.vmId} className="flex items-center gap-2 text-[13px]">
                <Avatar name={a.displayName || a.name} size={22} />
                <Link href={routes.agentIntegrations(a.vmId)} className="min-w-0 flex-1 truncate text-ink hover:underline">
                  {a.displayName || a.name}
                </Link>
                <Button
                  size="sm"
                  variant={on ? "outline" : "default"}
                  disabled={!canAct || connection.state !== "active"}
                  onClick={() => onAssign(a.vmId, !on)}
                  data-testid={`connector-assign-${a.vmId}`}
                >
                  {on ? "Remove access" : "Give access"}
                </Button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/**
 * Where other apps come from. Open Connector runs on the firewall, MCP servers are the
 * organization's own remote servers (their keys on the firewall too); Composio is not built, so its
 * tab says so and nothing more.
 */
function SourceSwitch({ source, onChange }: { source: Source; onChange: (s: Source) => void }) {
  const tabs: Array<{ id: Source; mark: string; logo: string; name: string; sub: string; badge: React.ReactNode }> = [
    {
      id: "open-connector",
      mark: "OC",
      logo: "bg-ink text-surface",
      name: "Open Connector",
      sub: "Open source · runs on your firewall",
      badge: (
        <Badge tone="allow" dot>
          Active
        </Badge>
      ),
    },
    {
      id: "mcp",
      mark: "MCP",
      logo: "bg-brand text-white text-[11px]",
      name: "MCP servers",
      sub: "Any remote MCP server · key on your firewall",
      badge: (
        <Badge tone="allow" dot>
          Active
        </Badge>
      ),
    },
    {
      id: "composio",
      mark: "C",
      logo: "bg-[linear-gradient(135deg,#7c4dff,#3d5afe)] text-white",
      name: "Composio",
      sub: "850+ apps · managed sign-ins",
      badge: <Badge tone="brand">Coming soon</Badge>,
    },
  ];
  return (
    <div role="tablist" aria-label="Where apps come from" className="grid grid-cols-1 gap-2.5 lg:grid-cols-3" data-testid="integrations-sources" data-tour="integrations-sources">
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={source === t.id}
          onClick={() => onChange(t.id)}
          className={cn(
            "flex min-w-0 items-center gap-3 rounded-xl border bg-surface px-3.5 py-3 text-left transition-colors",
            source === t.id ? "border-brand shadow-[0_0_0_3px_var(--brand-soft)]" : "border-line hover:border-line-2",
          )}
          data-testid={`integrations-source-${t.id}`}
        >
          <span className={cn("grid h-9 w-9 shrink-0 place-items-center rounded-[10px] text-[13px] font-bold", t.logo)}>{t.mark}</span>
          <span className="min-w-0 flex-1">
            <span className="block text-[14px] font-semibold text-ink">{t.name}</span>
            <span className="block truncate text-[12.5px] text-ink-2">{t.sub}</span>
          </span>
          <span className="shrink-0">{t.badge}</span>
        </button>
      ))}
    </div>
  );
}

const COMPOSIO_TILES = ["#ea4335", "#ff7a59", "#00a1e0", "#2d8cff", "#e01e5a", "#fcb400", "#0052cc", "#96bf48"];

function ComposioTeaser() {
  return (
    <div className="flex flex-col items-center gap-2.5 rounded-xl border border-line bg-surface px-[18px] py-7 text-center" data-testid="integrations-composio">
      <div className="mb-1 flex gap-1.5" aria-hidden="true">
        {COMPOSIO_TILES.map((c, i) => (
          <span key={c} className={cn("h-[26px] w-[26px] rounded-[8px] opacity-85", i % 2 === 0 && "-translate-y-1")} style={{ background: c }} />
        ))}
      </div>
      <div className="text-[16px] font-semibold text-ink">Composio is coming soon</div>
      <p className="max-w-[52ch] text-[13.5px] text-ink-2">
        Salesforce, Zoom, Asana and 850 more, with sign-ins Composio manages for you. Calls will still go through your firewall and its rules.
      </p>
    </div>
  );
}
