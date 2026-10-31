/** The states of an MCP server, its tools, assignments and changes, as the console stores them. */

/**
 * The organization's own MCP servers (docs/plans/mcp-servers.md): remote servers defined once on
 * Integrations and given to agents one by one.
 *
 * No credential is kept here, not even a hint of one. A header's value or an OAuth client secret
 * passes through once, in the encrypted part of the firewall command that carries it, and then
 * lives only in the firewall's own store, as do the OAuth tokens. What is here is what the console
 * shows: the server's name and address, how it signs in, its tools (names, descriptions,
 * annotations), which agents have it, and the history of changes.
 */

export type McpServerAuth = "none" | "header" | "oauth";

/** `pending` = handed to the firewall; `active` = the firewall holds it; `reauth_required` = sign in again. */
export type McpServerState = "pending" | "active" | "reauth_required" | "failed" | "removed";

/** One tool as the server listed it: metadata only. */
export type McpServerTool = {
  name: string;
  title: string | null;
  description: string | null;
  annotations: { title?: string; readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };
};

export type McpServerAssignmentState = "pending" | "active" | "failed" | "removed";

export type McpServerChangeKind = "add" | "replace" | "reconnect" | "remove" | "assign" | "unassign";

export type McpServerChangeStatus = "queued" | "awaiting_code" | "awaiting_authorization" | "applied" | "failed" | "expired" | "cancelled";
