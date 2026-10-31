import { z } from "zod";
import type { McpServerAssignmentState, McpServerAuth, McpServerChangeKind, McpServerChangeStatus, McpServerState, McpServerTool } from "./mcp-server-states";
import type { ConnectorFirewallView } from "./connectors-schema";

/**
 * The organization's MCP servers (docs/plans/mcp-servers.md): the shapes the RPC takes and the
 * views the console renders. The credential a person types travels once, to the firewall; no view
 * here carries one.
 */

/** The key in the agents' `mcp.servers`: lower-case letters, digits and dashes. `controlclaw…` is ours. */
export const mcpServerNameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9][a-z0-9-]{0,39}$/, "Use lower-case letters, digits and dashes, up to 40")
  .refine((n) => !n.startsWith("controlclaw"), "Names starting with controlclaw are ControlClaw’s own");

/** What the firewall dials: https, a name or public address, no user or password. The firewall checks the address it resolves to. */
export const mcpServerUrlSchema = z
  .string()
  .trim()
  .max(500)
  .refine((v) => {
    try {
      const u = new URL(v);
      if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash) return false;
      const host = u.hostname.toLowerCase();
      return !(host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || /^(10|127|169\.254|192\.168)\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host) || host.startsWith("["));
    } catch {
      return false;
    }
  }, "Use the server’s public https address, like https://mcp.example.com/mcp, with nothing after a ? or #. A key goes in a header, which only the firewall stores");

const HEADER_RESERVED = ["host", "content-type", "content-length", "accept", "mcp-session-id", "mcp-protocol-version", "last-event-id", "connection", "transfer-encoding", "cookie"];
export const mcpHeaderNameSchema = z
  .string()
  .trim()
  .regex(/^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/, "That isn’t a header’s name")
  .refine((h) => !HEADER_RESERVED.includes(h.toLowerCase()), "The firewall sets that header itself");

const secretValue = z.string().min(1).max(4096);

/** The fields of an add, without the checks between them (`addMcpServerSchema` has those). */
export const addMcpServerBase = z.object({
  name: mcpServerNameSchema,
  url: mcpServerUrlSchema,
  auth: z.enum(["none", "header", "oauth"]),
  /** `header`: which header, and its value (for `Authorization`, the whole value, e.g. `Bearer …`). */
  headerName: mcpHeaderNameSchema.optional(),
  headerValue: secretValue.optional(),
  /** `oauth`, for a server that does not let the firewall register itself. */
  clientId: z.string().trim().min(1).max(500).optional(),
  clientSecret: secretValue.optional(),
  vmIds: z.array(z.string().min(1)).max(50).optional().default([]),
});
export const addMcpServerSchema = addMcpServerBase
  .refine((v) => v.auth !== "header" || (!!v.headerName && !!v.headerValue), { message: "A header needs its name and its value", path: ["headerValue"] })
  .refine((v) => v.auth === "oauth" || (!v.clientId && !v.clientSecret), { message: "A client id is only for OAuth", path: ["clientId"] })
  .refine((v) => !v.clientSecret || !!v.clientId, { message: "A client secret needs its client id", path: ["clientId"] });
export type AddMcpServerInput = z.infer<typeof addMcpServerSchema>;

export const mcpServerIdSchema = z.object({ serverId: z.string().min(1) });

/** A new header value for a header server. */
export const replaceMcpServerSchema = z.object({ serverId: z.string().min(1), headerValue: secretValue });
export type ReplaceMcpServerInput = z.infer<typeof replaceMcpServerSchema>;

/** Sign in to an OAuth server again, optionally with a client typed now. */
export const reconnectMcpServerSchema = z.object({
  serverId: z.string().min(1),
  clientId: z.string().trim().min(1).max(500).optional(),
  clientSecret: secretValue.optional(),
});
export type ReconnectMcpServerInput = z.infer<typeof reconnectMcpServerSchema>;

export const assignMcpServerSchema = z.object({
  serverId: z.string().min(1),
  vmId: z.string().min(1),
  /** True to give the agent the server, false to take it away. */
  on: z.boolean(),
});
export type AssignMcpServerInput = z.infer<typeof assignMcpServerSchema>;

export const MCP_CHANGE_STUCK_MS = 2 * 60_000;
export const MCP_OAUTH_TTL_MS = 15 * 60_000;

// ---- views ----

export type McpServerChangeView = {
  id: string;
  vmId: string | null;
  serverId: string | null;
  name: string;
  kind: McpServerChangeKind;
  summary: string;
  status: McpServerChangeStatus;
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  authorizationUrl: string | null;
  error: string | null;
  createdAt: string;
  stuck: boolean;
};

export type McpServerView = {
  id: string;
  name: string;
  url: string;
  host: string;
  auth: McpServerAuth;
  headerName: string | null;
  oauthIssuer: string | null;
  /** Who the firewall is signed in as, when the server said. */
  oauthAccount: string | null;
  state: McpServerState;
  lastError: string | null;
  serverName: string | null;
  tools: McpServerTool[];
  toolsAt: string | null;
  agents: Array<{ vmId: string; name: string; state: McpServerAssignmentState; lastError: string | null }>;
  updatedAt: string;
};

export type McpServersView = {
  canManage: boolean;
  firewall: ConnectorFirewallView;
  servers: McpServerView[];
  agents: Array<{ vmId: string; name: string; displayName: string | null; status: string }>;
  pending: McpServerChangeView | null;
  recent: McpServerChangeView[];
  oauthRedirectUri: string;
};

export type AgentMcpServersView = {
  vm: { id: string; name: string; displayName: string | null; status: string };
  canManage: boolean;
  firewall: ConnectorFirewallView;
  servers: Array<McpServerView & { assigned: boolean }>;
  pending: McpServerChangeView | null;
  recent: McpServerChangeView[];
};

/** A tool's kind from its annotations, as the console shows it. Unknown when the server says neither. */
export function toolKind(t: Pick<McpServerTool, "annotations">): "read" | "destructive" | "write" | "unknown" {
  if (t.annotations.readOnlyHint === true) return "read";
  if (t.annotations.destructiveHint === true) return "destructive";
  if (t.annotations.destructiveHint === false) return "write";
  return "unknown";
}
