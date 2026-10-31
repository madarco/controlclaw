"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AppLink as Link } from "../../lib/link";
import { KeyRound, Loader2, Plus, RefreshCw, RotateCw, Server, ShieldCheck, Trash2 } from "lucide-react";
import { useApi } from "../../lib/api";
import { Button } from "../../ui/button";
import { Checkbox } from "../../ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../ui/dialog";
import { Input } from "../../ui/input";
import { Label } from "../../ui/label";
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
import { Avatar } from "../../kit/people";
import { StatusPill } from "../../kit/StatusPill";
import { ActionMenu, Badge, Disclosure } from "../../kit/console-ui";
import { cn } from "../../lib/utils";
import { addMcpServerSchema, toolKind, type McpServersView, type McpServerView } from "../../lib/mcp-servers-schema";
import { AuthorizeNote, ChangeHistory, FirewallNotice, PendingNote, type Tone } from "./ConnectorBits";
import { RedirectUri } from "./SetupGuide";
import { hostOf } from "../../lib/mcp-host";
import { IDLE, type Busy } from "./useConnectorChange";
import { useMcpServerChange } from "./useMcpServerChange";
import { useRoutes } from "../../lib/routes";

const POLL_ACTIVE_MS = 3_000;
const POLL_IDLE_MS = 20_000;

type Dialog = { kind: "add" } | { kind: "replace"; server: McpServerView } | { kind: "remove"; server: McpServerView } | null;

/** The line under a server's name. */
export function mcpStatusLine(s: Pick<McpServerView, "state" | "lastError" | "agents" | "auth">): { text: string; tone: Tone } {
  if (s.state === "pending") return { text: "Waiting for the firewall to add it", tone: "ask" };
  if (s.state === "failed") return { text: s.lastError ?? "The firewall couldn’t reach it", tone: "block" };
  if (s.state === "reauth_required") return { text: "Sign in again: the firewall’s sign-in expired", tone: "block" };
  if (s.lastError) return { text: s.lastError, tone: "block" };
  if (s.agents.length === 0) return { text: "Added, no agent uses it yet", tone: "muted" };
  const failed = s.agents.find((a) => a.state === "failed");
  if (failed) return { text: `${failed.name}: ${failed.lastError ?? "not applied"}`, tone: "block" };
  if (s.agents.some((a) => a.state === "pending")) return { text: "Adding it to the agents…", tone: "ask" };
  return { text: `Used by ${s.agents.map((a) => a.name).join(", ")}`, tone: "allow" };
}

export function signInLabel(s: Pick<McpServerView, "auth" | "headerName" | "oauthIssuer" | "oauthAccount">): string {
  if (s.auth === "header") return `Key in ${s.headerName ?? "a header"}`;
  if (s.auth === "oauth") return s.oauthAccount ? `OAuth as ${s.oauthAccount}` : s.oauthIssuer ? `OAuth · ${hostOf(s.oauthIssuer)}` : "OAuth";
  return "No sign-in";
}


const KIND_TONE: Record<ReturnType<typeof toolKind>, "allow" | "ask" | "block" | "neutral"> = { read: "allow", write: "ask", destructive: "block", unknown: "neutral" };
const KIND_LABEL: Record<ReturnType<typeof toolKind>, string> = { read: "read", write: "write", destructive: "destructive", unknown: "not said" };

/** A server's tools, folded: name, what the server says it does, and whether it says it only reads. */
export function McpToolList({ server }: { server: Pick<McpServerView, "tools" | "toolsAt" | "name"> }) {
  if (server.tools.length === 0) return <p className="text-[12.5px] text-ink-2">{server.toolsAt ? "The server lists no tools." : "Tools not loaded yet."}</p>;
  return (
    <Disclosure title="Tools" meta={server.tools.length} data-testid={`mcp-tools-${server.name}`}>
      <ul className="grid gap-2">
        {server.tools.map((t) => {
          const kind = toolKind(t);
          return (
            <li key={t.name} className="grid gap-0.5">
              <div className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 truncate text-[12.5px] font-semibold text-ink">{t.name}</code>
                <Badge tone={KIND_TONE[kind]} className="shrink-0">
                  {KIND_LABEL[kind]}
                </Badge>
              </div>
              {t.description ? <p className="line-clamp-2 text-[12px] text-ink-2">{t.description}</p> : null}
            </li>
          );
        })}
      </ul>
    </Disclosure>
  );
}

export interface McpServersPanelProps {
  initial: McpServersView;
  /** Demo pages pass false so the panel never calls the RPC. */
  live?: boolean;
}

/**
 * The organization's MCP servers (docs/plans/mcp-servers.md), under Integrations → Other apps. A
 * server is added once, its key or sign-in kept by the firewall, and given to agents one by one.
 */
export function McpServersPanel({ initial, live = true }: McpServersPanelProps) {
  const api = useApi();
  const routes = useRoutes();
  const [view, setView] = useState<McpServersView>(initial);
  const [dialog, setDialog] = useState<Dialog>(null);
  const lastPendingId = useRef<string | null>(initial.pending?.id ?? null);

  const refresh = useCallback(async () => {
    if (!live) return view;
    try {
      const fresh = await api.mcpServers.list();
      setView(fresh);
      return fresh;
    } catch (error) {
      console.error("mcpServers.list failed", error);
      return view;
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, api]);

  const change = useMcpServerChange({ live, initial: initial.pending, onSettled: () => refresh() });
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

  useEffect(() => {
    if (view.pending && view.pending.id !== lastPendingId.current) {
      lastPendingId.current = view.pending.id;
      change.setTracking(view.pending);
    }
    if (!view.pending) lastPendingId.current = null;
  }, [view.pending]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (tracking?.status === "awaiting_code" || tracking?.status === "awaiting_authorization") setDialog(null);
  }, [tracking?.status]);

  const wasTracking = useRef(false);
  useEffect(() => {
    if (wasTracking.current && !tracking && !state.error) setDialog(null);
    wasTracking.current = !!tracking;
  }, [tracking, state.error]);

  const codeChange = tracking?.status === "awaiting_code" ? tracking : null;
  const authorizing = tracking?.status === "awaiting_authorization" ? tracking : null;
  const canAct = view.canManage && view.firewall.reachable && view.firewall.supported && !tracking;
  const firewall = { ...view.firewall };

  return (
    <div className="grid grid-cols-1 gap-4" data-testid="mcp-servers-panel">
      {!firewall.supported && firewall.reachable ? (
        <div className="rounded-xl border border-ask-border bg-ask-soft px-4 py-3 text-[13.5px] text-ask-fg" data-testid="mcp-servers-unsupported">
          Your firewall doesn’t support MCP servers yet. Update it on the{" "}
          <Link href={routes.firewall} className="font-medium underline">
            Firewall page
          </Link>{" "}
          to use this tab.
        </div>
      ) : (
        <FirewallNotice firewall={{ ...firewall, supported: true }} firewallHref={routes.firewall} />
      )}
      {tracking && !codeChange && !authorizing && <PendingNote note={state.note} />}
      {authorizing && <AuthorizeNote change={authorizing} onCancel={() => void change.cancel()} where="the server" />}
      {state.error && !tracking && !dialog ? (
        <div className="rounded-xl border border-block-border bg-block-soft px-4 py-3 text-[13.5px] text-block-fg" data-testid="mcp-servers-error">
          {state.error}
        </div>
      ) : null}

      <p className="text-[13px] text-ink-2">
        Add a remote MCP server once for your organization. Your firewall stores its key or sign-in and adds it to every call, so agents never see
        it. Servers an agent runs as a command on its own machine aren’t managed here.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-[14px] font-semibold text-ink">
          MCP servers <span className="font-normal text-ink-2">{view.servers.length}</span>
        </h3>
        <div className="ml-auto flex items-center gap-2">
          <RefreshButton
            onRefresh={async () => {
              // The firewall's own list too: a template can give a server, and a sign-in can end there.
              if (live && view.canManage && view.firewall.reachable && view.firewall.supported) await api.mcpServers.read().catch((error) => console.error("mcpServers.read failed", error));
              await refresh();
            }}
            testId="mcp-servers-refresh"
          />
          <Button size="sm" disabled={!canAct} onClick={() => (setState(IDLE), setDialog({ kind: "add" }))} data-testid="mcp-servers-add">
            <Plus className="h-3.5 w-3.5" /> Add a server
          </Button>
        </div>
      </div>

      {view.servers.length === 0 ? (
        <p className="rounded-xl border border-dashed border-line-2 px-4 py-3 text-[13px] text-ink-2" data-testid="mcp-servers-empty">
          {view.canManage ? "No MCP servers yet. Add one with its address, then choose which agents may use it." : "Nobody has added an MCP server for this organization yet."}
        </p>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(min(300px,100%),1fr))] gap-3">
          {view.servers.map((s) => (
            <ServerCard
              key={s.id}
              server={s}
              agents={view.agents}
              canAct={canAct}
              onAssign={(vmId, on) =>
                void change.start(() => api.mcpServers.assign({ serverId: s.id, vmId, on }), on ? "Adding it to the agent…" : "Removing it from the agent…", { serverId: s.id, name: s.name, kind: on ? "assign" : "unassign" })
              }
              onRefreshTools={() => void api.mcpServers.refreshTools({ serverId: s.id }).then(() => setTimeout(() => void refresh(), 4000)).catch((e) => setState({ busy: false, error: e instanceof Error ? e.message : "Couldn’t reach the firewall. Try again.", note: null }))}
              onReplace={() => (setState(IDLE), setDialog({ kind: "replace", server: s }))}
              onReconnect={() => void change.start(() => api.mcpServers.reconnect({ serverId: s.id }), `Signing in to ${s.name} again…`, { serverId: s.id, name: s.name, kind: "reconnect" })}
              onRemove={() => setDialog({ kind: "remove", server: s })}
            />
          ))}
        </div>
      )}

      <ChangeHistory recent={view.recent} testId="mcp-servers-history" />

      <AddServerDialog
        open={dialog?.kind === "add"}
        agents={view.agents.map((a) => ({ vmId: a.vmId, name: a.displayName || a.name }))}
        redirectUri={view.oauthRedirectUri}
        state={state}
        onClose={() => setDialog(null)}
        onSubmit={(input) => void change.start(() => api.mcpServers.add(input), `Adding ${input.name}…`, { name: input.name, kind: "add" })}
      />
      <ReplaceKeyDialog
        server={dialog?.kind === "replace" ? dialog.server : null}
        state={state}
        onClose={() => setDialog(null)}
        onSubmit={(server, headerValue) => void change.start(() => api.mcpServers.replace({ serverId: server.id, headerValue }), "Replacing the key…", { serverId: server.id, name: server.name, kind: "replace" })}
      />
      <ConfirmCodeDialog change={codeChange} state={state} sender="Your agent" onSubmit={change.confirm} onCancel={() => void change.cancel()} />
      <AlertDialog open={dialog?.kind === "remove"} onOpenChange={(o) => !o && setDialog(null)}>
        <AlertDialogContent data-testid="mcp-servers-remove-dialog">
          <AlertDialogHeader>
            <AlertDialogTitle>Remove {dialog?.kind === "remove" ? dialog.server.name : "this server"}?</AlertDialogTitle>
            <AlertDialogDescription>
              Your firewall deletes its key or sign-in, and every agent that has it loses its tools. Your account on the server is unchanged. For an OAuth sign-in,
              you can also revoke the firewall’s access there.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Keep it</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (dialog?.kind !== "remove") return;
                const s = dialog.server;
                setDialog(null);
                void change.start(() => api.mcpServers.remove({ serverId: s.id }), `Removing ${s.name}…`, { serverId: s.id, name: s.name, kind: "remove" });
              }}
              data-testid="mcp-servers-remove-confirm"
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function ServerCard({
  server,
  agents,
  canAct,
  onAssign,
  onRefreshTools,
  onReplace,
  onReconnect,
  onRemove,
}: {
  server: McpServerView;
  agents: McpServersView["agents"];
  canAct: boolean;
  onAssign: (vmId: string, on: boolean) => void;
  onRefreshTools: () => void;
  onReplace: () => void;
  onReconnect: () => void;
  onRemove: () => void;
}) {
  const routes = useRoutes();
  const s = mcpStatusLine(server);
  const usable = server.state === "active" || server.state === "reauth_required";
  return (
    <div className={cn("grid min-w-0 grid-cols-1 gap-3 rounded-xl border bg-surface p-4", s.tone === "allow" ? "border-allow-border" : "border-line")} data-testid={`mcp-server-card-${server.name}`}>
      <div className="flex items-center gap-2.5">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-[10px] bg-bg-2 text-ink-2">
          <Server className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate text-[14px] font-semibold text-ink">
            {server.name}
            {server.serverName ? <span className="font-normal text-ink-2"> · {server.serverName}</span> : null}
          </div>
          <div className="truncate text-[12.5px] text-ink-2">
            {server.host} · {signInLabel(server)}
          </div>
        </div>
        <ActionMenu
          ariaLabel={`${server.name} actions`}
          data-testid="mcp-server-menu"
          items={[
            { icon: RefreshCw, label: "Reload tools", disabled: !canAct || !usable, onClick: onRefreshTools, "data-testid": "mcp-server-refresh-tools" },
            ...(server.auth === "oauth"
              ? [{ icon: RotateCw, label: "Sign in again", disabled: !canAct, onClick: onReconnect, "data-testid": "mcp-server-reconnect" }]
              : server.auth === "header"
                ? [{ icon: KeyRound, label: "Replace key", disabled: !canAct || !usable, onClick: onReplace, "data-testid": "mcp-server-replace" }]
                : []),
            "-" as const,
            { icon: Trash2, label: "Remove", danger: true, disabled: !canAct, onClick: onRemove, "data-testid": "mcp-server-remove" },
          ]}
        />
      </div>

      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        <StatusPill tone={s.tone} dot={false} className="text-[11.5px]" data-testid="mcp-server-status">
          {s.text}
        </StatusPill>
        <Link href={routes.activity} className="ml-auto font-medium text-ink-2 underline">
          View calls
        </Link>
      </div>

      <McpToolList server={server} />

      {agents.length > 0 && (
        <div className="grid grid-cols-1 gap-1 border-t border-line pt-2.5" data-testid="mcp-server-agents">
          {agents.map((a) => {
            const on = server.agents.some((x) => x.vmId === a.vmId);
            return (
              <div key={a.vmId} className="flex items-center gap-2 text-[13px]">
                <Avatar name={a.displayName || a.name} size={22} />
                <Link href={routes.agentIntegrations(a.vmId)} className="min-w-0 flex-1 truncate text-ink hover:underline">
                  {a.displayName || a.name}
                </Link>
                <Button size="sm" variant={on ? "outline" : "default"} disabled={!canAct || !usable} onClick={() => onAssign(a.vmId, !on)} data-testid={`mcp-server-assign-${a.vmId}`}>
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

type AddSubmit = { name: string; url: string; auth: "none" | "header" | "oauth"; headerName?: string; headerValue?: string; clientId?: string; clientSecret?: string; vmIds: string[] };

function StatusLine({ state }: { state: Busy }) {
  if (state.error) return <div className="text-[12.5px] text-block">{state.error}</div>;
  if (state.note) return <div className="text-[12.5px] text-ink-2">{state.note}</div>;
  return null;
}

export function AddServerDialog({
  open,
  agents,
  redirectUri,
  state,
  onClose,
  onSubmit,
}: {
  open: boolean;
  agents: Array<{ vmId: string; name: string }>;
  redirectUri: string;
  state: Busy;
  onClose: () => void;
  onSubmit: (input: AddSubmit) => void;
}) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [auth, setAuth] = useState<AddSubmit["auth"]>("none");
  const [headerName, setHeaderName] = useState("Authorization");
  const [headerValue, setHeaderValue] = useState("");
  const [ownClient, setOwnClient] = useState(false);
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [vmIds, setVmIds] = useState<string[]>([]);

  useEffect(() => {
    if (!open) return;
    setName("");
    setUrl("");
    setAuth("none");
    setHeaderName("Authorization");
    setHeaderValue("");
    setOwnClient(false);
    setClientId("");
    setClientSecret("");
    setVmIds([]);
  }, [open]);

  const input: AddSubmit = {
    name: name.trim().toLowerCase(),
    url: url.trim(),
    auth,
    ...(auth === "header" ? { headerName: headerName.trim(), headerValue: headerValue.trim() } : {}),
    ...(auth === "oauth" && ownClient && clientId.trim() ? { clientId: clientId.trim(), ...(clientSecret.trim() ? { clientSecret: clientSecret.trim() } : {}) } : {}),
    vmIds,
  };
  const parsed = addMcpServerSchema.safeParse(input);
  const problem = name || url ? (parsed.success ? null : parsed.error.issues[0]?.message) : null;

  return (
    <Dialog open={open} onOpenChange={(o) => !o && !state.busy && onClose()}>
      <DialogContent className="flex max-h-[85vh] flex-col sm:max-w-[520px]" data-testid="mcp-server-dialog-add">
        <DialogHeader>
          <DialogTitle>Add an MCP server</DialogTitle>
          <DialogDescription>Your agents reach it through your firewall. Its key or sign-in goes to your firewall, never to ControlClaw’s database.</DialogDescription>
        </DialogHeader>
        <div className="grid min-h-0 flex-1 gap-3 overflow-y-auto px-0.5">
          <div className="grid gap-1.5">
            <Label htmlFor="mcp-name">Name</Label>
            <Input id="mcp-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="linear" autoComplete="off" spellCheck={false} data-testid="mcp-field-name" />
            <p className="text-[12px] text-ink-2">How the server appears in the agents’ settings. Use lowercase letters, digits and dashes.</p>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="mcp-url">Address</Label>
            <Input id="mcp-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" autoComplete="off" spellCheck={false} data-testid="mcp-field-url" />
            <p className="text-[12px] text-ink-2">
              The server’s Streamable HTTP address from its documentation, without anything after a “?”. Add a key as a header below. Only your firewall stores it.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label>How the firewall signs in</Label>
            <div className="flex flex-wrap gap-2" data-testid="mcp-auth">
              {(
                [
                  ["none", "No sign-in"],
                  ["header", "A key in a header"],
                  ["oauth", "OAuth"],
                ] as const
              ).map(([value, label]) => (
                <Button key={value} type="button" size="sm" variant={auth === value ? "default" : "outline"} onClick={() => setAuth(value)} data-testid={`mcp-auth-${value}`}>
                  {label}
                </Button>
              ))}
            </div>
          </div>
          {auth === "header" ? (
            <>
              <div className="grid gap-1.5">
                <Label htmlFor="mcp-header-name">Header</Label>
                <Input id="mcp-header-name" value={headerName} onChange={(e) => setHeaderName(e.target.value)} autoComplete="off" spellCheck={false} data-testid="mcp-field-header-name" />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="mcp-header-value">Value</Label>
                <Input
                  id="mcp-header-value"
                  type="password"
                  value={headerValue}
                  onChange={(e) => setHeaderValue(e.target.value)}
                  placeholder={headerName.toLowerCase() === "authorization" ? "Bearer sk-…" : "the key"}
                  autoComplete="off"
                  spellCheck={false}
                  data-testid="mcp-field-header-value"
                />
                {headerName.toLowerCase() === "authorization" ? <p className="text-[12px] text-ink-2">The whole value, for example “Bearer” and the key.</p> : null}
              </div>
            </>
          ) : null}
          {auth === "oauth" ? (
            <div className="grid gap-2 rounded-xl border border-line bg-bg-2 px-3.5 py-3 text-[12.5px] text-ink-2">
              <p>
                If the server lets the firewall register itself, you only sign in. If not, a message tells you when you continue: then create an OAuth app there with
                this callback URL and paste its client ID and secret.
              </p>
              <label className="flex items-center gap-2 text-[13px] text-ink">
                <Checkbox checked={ownClient} onCheckedChange={(on) => setOwnClient(on === true)} data-testid="mcp-own-client" />I have a client ID for this server
              </label>
              {ownClient ? (
                <>
                  <RedirectUri uri={redirectUri} tone="surface" />
                  <Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="Client ID" autoComplete="off" spellCheck={false} data-testid="mcp-field-client-id" />
                  <Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="Client secret (if it has one)" autoComplete="off" spellCheck={false} data-testid="mcp-field-client-secret" />
                </>
              ) : null}
            </div>
          ) : null}
          {agents.length > 0 && (
            <div className="grid gap-1.5" data-testid="mcp-agents">
              <Label>Which agents may use it</Label>
              {agents.map((a) => (
                <label key={a.vmId} className="flex items-center gap-2 text-[13px] text-ink">
                  <Checkbox checked={vmIds.includes(a.vmId)} onCheckedChange={(on) => setVmIds((s) => (on ? [...new Set([...s, a.vmId])] : s.filter((x) => x !== a.vmId)))} />
                  {a.name}
                </label>
              ))}
              <p className="text-[12px] text-ink-2">You can change this later, per agent.</p>
            </div>
          )}
          <div className="flex gap-2 rounded-xl border border-line bg-bg-2 px-3.5 py-2.5 text-[12.5px] text-ink-2">
            <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <span>The firewall checks that the server responds before saving it, then loads its tools. A wrong key fails here and shows the server’s own error.</span>
          </div>
          {problem ? (
            <p className="text-[12.5px] text-ask" data-testid="mcp-add-problem">
              {problem}
            </p>
          ) : null}
        </div>
        <StatusLine state={state} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            Cancel
          </Button>
          <Button onClick={() => parsed.success && onSubmit(input)} disabled={!parsed.success || state.busy} data-testid="mcp-add-submit">
            {state.busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {auth === "oauth" ? "Continue to sign-in" : "Add server"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ReplaceKeyDialog({ server, state, onClose, onSubmit }: { server: McpServerView | null; state: Busy; onClose: () => void; onSubmit: (server: McpServerView, value: string) => void }) {
  const [value, setValue] = useState("");
  useEffect(() => setValue(""), [server?.id]);
  return (
    <Dialog open={!!server} onOpenChange={(o) => !o && !state.busy && onClose()}>
      <DialogContent className="sm:max-w-[460px]" data-testid="mcp-server-dialog-replace">
        <DialogHeader>
          <DialogTitle>Replace the {server?.name} key</DialogTitle>
          <DialogDescription>Enter the new value of {server?.headerName ?? "the header"}. The firewall tests it before saving it.</DialogDescription>
        </DialogHeader>
        <Input type="password" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} data-testid="mcp-replace-value" />
        <StatusLine state={state} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={state.busy}>
            Cancel
          </Button>
          <Button onClick={() => server && onSubmit(server, value.trim())} disabled={!value.trim() || state.busy} data-testid="mcp-replace-submit">
            Replace key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
