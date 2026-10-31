import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { AppOption } from "@controlclaw/console-ui/lib/app-rules-schema";
import { CONNECTOR_VERSION, catalogCategories, catalogProvider, connectableCount, isConnectable, searchCatalog, serviceName } from "@controlclaw/console-ui/lib/connector-catalog";
import type { ConnectorChangeView, ConnectorConnectionView, ConnectorsView, ConnectorSetupView } from "@controlclaw/console-ui/lib/connectors-schema";
import type { ConnectorAuthType, ConnectorConnectionState } from "@controlclaw/console-ui/lib/connector-states";
import type { McpServerChangeView, McpServersView, McpServerView } from "@controlclaw/console-ui/lib/mcp-servers-schema";
import type { McpServerState } from "@controlclaw/console-ui/lib/mcp-server-states";
import { FwApiError, fw } from "./client";
import { send, settledChanges } from "./changes";
import { listAgents, type AgentRow } from "./agents";
import { onOauthDone, redirectUri } from "./oauth";

/** `GET /api/connectors`: the firewall's own record, untyped in the OpenAPI document. */
type StoredConnection = { id: string; service: string; authType: string; label?: string | null; accountLabel?: string | null; state: string; lastError?: string | null; updatedAt: string };
type ConnectorsRead = { connections?: StoredConnection[]; agents?: Array<{ vmId: string; name?: string; connections?: string[] }> };

/** `GET /api/mcp-servers`, the same. */
type StoredServer = {
  name: string;
  url: string;
  auth: "none" | "header" | "oauth";
  headerName?: string | null;
  state: string;
  lastError?: string | null;
  serverName?: string | null;
  tools?: McpServerView["tools"];
  toolsAt?: string | null;
  agents?: string[];
  oauth?: { issuer?: string | null; account?: string | null } | null;
  updatedAt: string;
};

const GUIDE_WORDS = new Set(["guide", "guides", "guided"]);

const notRunning = (e: unknown) => e instanceof FwApiError && e.status === 404;

/** The firewall answers (it serves this page); a module it does not run is said plainly. */
const firewall = (supported: boolean, what: string) => ({
  state: "active" as const,
  reachable: true,
  supported,
  note: `The ${what} isn't running on this firewall, so this part of the page can't be used yet.`,
});

function agentsList(agents: AgentRow[]) {
  return agents.filter((a) => a.role !== "gbrain").map((a) => ({ vmId: a.vm_id, name: a.name, displayName: null, status: "running" }));
}

const CONNECTION_STATES: readonly string[] = ["pending", "active", "failed", "removed"];

export function toConnectorsView(read: ConnectorsRead | null, agents: AgentRow[]): ConnectorsView {
  const names = new Map(agents.map((a) => [a.vm_id, a.name]));
  const byConnection = new Map<string, Array<{ vmId: string; name: string }>>();
  for (const a of read?.agents ?? []) for (const c of a.connections ?? []) byConnection.set(c, [...(byConnection.get(c) ?? []), { vmId: a.vmId, name: names.get(a.vmId) ?? a.name ?? a.vmId }]);
  const connections: ConnectorConnectionView[] = (read?.connections ?? []).map((c) => ({
    id: c.id,
    service: c.service,
    serviceName: serviceName(c.service),
    home: catalogProvider(c.service)?.home,
    authType: c.authType as ConnectorAuthType,
    label: c.label ?? null,
    accountLabel: c.accountLabel ?? null,
    state: (CONNECTION_STATES.includes(c.state) ? c.state : c.lastError ? "failed" : "active") as ConnectorConnectionState,
    runtimeState: c.state,
    lastError: c.lastError ?? null,
    agents: (byConnection.get(c.id) ?? []).map((a) => ({ ...a, state: "active" as const, lastError: null })),
    updatedAt: c.updatedAt,
  }));
  const counts = new Map((read?.agents ?? []).map((a) => [a.vmId, a.connections?.length ?? 0]));
  return {
    canManage: true,
    firewall: firewall(read !== null, "app connector"),
    connections,
    agents: agentsList(agents).map((a) => ({ ...a, connections: counts.get(a.vmId) ?? 0 })),
    pending: null,
    recent: [],
    oauthRedirectUri: redirectUri(),
  };
}

const SERVER_STATES: readonly string[] = ["pending", "active", "reauth_required", "failed", "removed"];

export function toMcpView(read: { servers?: StoredServer[] } | null, agents: AgentRow[]): McpServersView {
  const names = new Map(agents.map((a) => [a.vm_id, a.name]));
  const servers: McpServerView[] = (read?.servers ?? []).map((s) => ({
    id: s.name,
    name: s.name,
    url: s.url,
    host: (() => {
      try {
        return new URL(s.url).host;
      } catch {
        return s.url;
      }
    })(),
    auth: s.auth,
    headerName: s.headerName ?? null,
    oauthIssuer: s.oauth?.issuer ?? null,
    oauthAccount: s.oauth?.account ?? null,
    state: (SERVER_STATES.includes(s.state) ? s.state : "failed") as McpServerState,
    lastError: s.lastError ?? null,
    serverName: s.serverName ?? null,
    tools: s.tools ?? [],
    toolsAt: s.toolsAt ?? null,
    agents: (s.agents ?? []).map((vmId) => ({ vmId, name: names.get(vmId) ?? vmId, state: "active" as const, lastError: null })),
    updatedAt: s.updatedAt,
  }));
  return { canManage: true, firewall: firewall(read !== null, "MCP server gate"), servers, agents: agentsList(agents), pending: null, recent: [], oauthRedirectUri: redirectUri() };
}

/** The firewall's record, or null when it does not run that module (a 404). */
async function readOrNull<T>(call: () => Promise<unknown>): Promise<T | null> {
  try {
    return (await call()) as T;
  } catch (e) {
    if (notRunning(e)) return null;
    throw e;
  }
}

export async function connectorsView(): Promise<ConnectorsView> {
  const [read, agents] = await Promise.all([readOrNull<ConnectorsRead>(() => fw.get("/api/connectors")), listAgents()]);
  return toConnectorsView(read, agents);
}

export async function mcpView(): Promise<McpServersView> {
  const [read, agents] = await Promise.all([readOrNull<{ servers?: StoredServer[] }>(() => fw.get("/api/mcp-servers")), listAgents()]);
  return toMcpView(read, agents);
}

/** The connected apps, for Security rules' Integrations tab. */
export async function connectedApps(): Promise<AppOption[]> {
  const read = await readOrNull<ConnectorsRead>(() => fw.get("/api/connectors"));
  const by = new Map<string, AppOption>();
  for (const c of read?.connections ?? []) {
    const o = by.get(c.service) ?? { service: c.service, name: serviceName(c.service), home: catalogProvider(c.service)?.home ?? null, connections: [] };
    o.connections.push({ id: c.id, label: c.label || c.accountLabel || serviceName(c.service) });
    by.set(c.service, o);
  }
  return [...by.values()];
}

const now = () => new Date().toISOString();

const connectorChanges = settledChanges<ConnectorChangeView>((id) => ({
  id, vmId: null, connectionId: null, service: "", kind: "connect", summary: "", status: "queued", tofu: false, sentVia: null,
  attemptsLeft: null, expiresAt: null, authorizationUrl: null, error: null, createdAt: now(), stuck: false,
}));

const mcpChanges = settledChanges<McpServerChangeView>((id) => ({
  id, vmId: null, serverId: null, name: "", kind: "add", summary: "", status: "queued", tofu: false, sentVia: null,
  attemptsLeft: null, expiresAt: null, authorizationUrl: null, error: null, createdAt: now(), stuck: false,
}));

/** A sign-in's URL, from an answer still waiting for the person at the provider. */
function authUrl(ans: { data?: unknown }): string | null {
  const u = (ans.data as { authorizationUrl?: unknown } | null)?.authorizationUrl;
  return typeof u === "string" ? u : null;
}

onOauthDone(({ changeId, error }) => {
  if (!changeId) return;
  connectorChanges.settle(changeId, error);
  mcpChanges.settle(changeId, error);
});

/** A sign-in nobody finished in time reads as expired, as on the console. */
function withExpiry<T extends { status: string; expiresAt: string | null }>(v: T): T {
  return v.status === "awaiting_authorization" && v.expiresAt && Date.parse(v.expiresAt) < Date.now() ? { ...v, status: "expired" } : v;
}

let connectionAuth = new Map<string, string>();

export const integrations: ConsoleApi["integrations"] = {
  async list() {
    const v = await connectorsView();
    connectionAuth = new Map(v.connections.map((c) => [c.id, c.authType]));
    return v;
  },
  // The firewall reconciles with its runtime on every read.
  refresh: () => fw.get("/api/connectors"),
  async search(input) {
    return {
      version: CONNECTOR_VERSION,
      categories: catalogCategories().slice(0, 24),
      total: connectableCount(),
      // The setup guides are the console's: "guide" lists nothing special here, so it is a plain search.
      providers: searchCatalog(GUIDE_WORDS.has((input.q ?? "").trim().toLowerCase()) ? "" : (input.q ?? ""), input.category ?? "", input.limit ?? 24, isConnectable),
    };
  },
  async getSetup({ service }) {
    const s = (await send(() => fw.get("/api/connectors/setup/{service}", { path: { service } }))) as Omit<ConnectorSetupView, "serviceName">;
    return { service, serviceName: serviceName(service), auth: s.auth ?? [], oauthClient: s.oauthClient ?? null };
  },
  async connect(input) {
    const secrets = input.secrets ?? {};
    const body = {
      service: input.service,
      serviceName: serviceName(input.service),
      label: input.label || null,
      ...(input.authType === "api_key" ? { apiKey: String(secrets.apiKey ?? "") } : { secrets }),
      extra: input.extra ?? {},
      vmIds: input.vmIds ?? [],
    };
    const ans = await send(() => fw.post("/api/connectors", { body }));
    return connectorChanges.record(ans, { service: input.service, kind: "connect", summary: `Connect ${serviceName(input.service)}` });
  },
  async oauthConnect(input) {
    const { clientId, clientSecret, ...extra } = (input.clientFields ?? {}) as Record<string, string>;
    const ans = await send(() =>
      fw.post("/api/connectors/oauth", {
        body: {
          service: input.service,
          serviceName: serviceName(input.service),
          label: input.label || null,
          clientId: clientId || null,
          clientSecret: clientSecret || null,
          extra,
          authorizationOptionIds: input.authorizationOptionIds ?? [],
          vmIds: input.vmIds ?? [],
        },
      }),
    );
    return connectorChanges.record(ans, { service: input.service, kind: "oauth_connect", summary: `Connect ${serviceName(input.service)}`, authorizationUrl: authUrl(ans) });
  },
  async oauthReconnect({ connectionId }) {
    const ans = await send(() => fw.post("/api/connectors/{id}/reconnect", { path: { id: connectionId }, body: {} }));
    return connectorChanges.record(ans, { connectionId, kind: "oauth_reconnect", summary: "Sign in again", authorizationUrl: authUrl(ans) });
  },
  async replace(input) {
    const secrets = input.secrets ?? {};
    // The kind of credential decides the body; read the list again if this connection is not in it.
    if (!connectionAuth.has(input.connectionId)) await integrations.list();
    const body = connectionAuth.get(input.connectionId) === "api_key" ? { apiKey: String(secrets.apiKey ?? ""), extra: input.extra ?? {} } : { secrets, extra: input.extra ?? {} };
    const ans = await send(() => fw.put("/api/connectors/{id}", { path: { id: input.connectionId }, body }));
    return connectorChanges.record(ans, { connectionId: input.connectionId, kind: "replace", summary: "Replace the credential" });
  },
  async remove({ connectionId }) {
    const ans = await send(() => fw.delete("/api/connectors/{id}", { path: { id: connectionId }, body: {} }));
    return connectorChanges.record(ans, { connectionId, kind: "remove", summary: "Remove the connection" });
  },
  async assign({ connectionId, vmId, on }) {
    const ans = await send(() => fw.post("/api/connectors/{id}/assign", { path: { id: connectionId }, body: { vmId, on } }));
    return connectorChanges.record(ans, { connectionId, vmId, kind: on ? "assign" : "unassign", summary: on ? "Give it to the agent" : "Take it from the agent" });
  },
  getChange: async ({ changeId }) => withExpiry(await connectorChanges.rpc.getChange({ changeId })),
  confirm: connectorChanges.rpc.confirm,
  cancel: connectorChanges.rpc.cancel,
};

let serverHeaders = new Map<string, string | null>();

export const mcpServers: ConsoleApi["mcpServers"] = {
  async list() {
    const v = await mcpView();
    serverHeaders = new Map(v.servers.map((s) => [s.id, s.headerName]));
    return v;
  },
  read: () => fw.get("/api/mcp-servers"),
  async add(input) {
    const ans = await send(() =>
      fw.post("/api/mcp-servers", {
        body: {
          name: input.name,
          url: input.url,
          auth: input.auth,
          headerName: input.headerName || null,
          headerValue: input.headerValue || null,
          clientId: input.clientId || null,
          clientSecret: input.clientSecret || null,
          vmIds: input.vmIds ?? [],
        },
      }),
    );
    return mcpChanges.record(ans, { name: input.name, kind: "add", summary: `Add ${input.name}`, authorizationUrl: authUrl(ans) });
  },
  async replace({ serverId, headerValue }) {
    if (!serverHeaders.has(serverId)) await mcpServers.list();
    const headerName = serverHeaders.get(serverId) ?? "Authorization";
    const ans = await send(() => fw.put("/api/mcp-servers/{name}", { path: { name: serverId }, body: { headerName, headerValue } }));
    return mcpChanges.record(ans, { serverId, name: serverId, kind: "replace", summary: `Replace ${serverId}'s header` });
  },
  async reconnect({ serverId }) {
    const ans = await send(() => fw.post("/api/mcp-servers/{name}/reconnect", { path: { name: serverId }, body: {} }));
    return mcpChanges.record(ans, { serverId, name: serverId, kind: "reconnect", summary: `Sign in to ${serverId} again`, authorizationUrl: authUrl(ans) });
  },
  async remove({ serverId }) {
    const ans = await send(() => fw.delete("/api/mcp-servers/{name}", { path: { name: serverId }, body: {} }));
    return mcpChanges.record(ans, { serverId, name: serverId, kind: "remove", summary: `Remove ${serverId}` });
  },
  async assign({ serverId, vmId, on }) {
    const ans = await send(() => fw.post("/api/mcp-servers/{name}/assign", { path: { name: serverId }, body: { vmId, on } }));
    return mcpChanges.record(ans, { serverId, name: serverId, vmId, kind: on ? "assign" : "unassign", summary: on ? `Give ${serverId} to the agent` : `Take ${serverId} from the agent` });
  },
  refreshTools: ({ serverId }) => send(() => fw.post("/api/mcp-servers/{name}/tools", { path: { name: serverId }, body: {} })),
  getChange: async ({ changeId }) => withExpiry(await mcpChanges.rpc.getChange({ changeId })),
  confirm: mcpChanges.rpc.confirm,
  cancel: mcpChanges.rpc.cancel,
};
