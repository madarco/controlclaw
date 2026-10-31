/** The states of an app integration's connection, assignment and change, as the console stores them. */

/** `pending` = handed to the firewall, not connected yet; `active` = the runtime holds it. */
export type ConnectorConnectionState = "pending" | "active" | "failed" | "removed";
export type ConnectorAuthType = "api_key" | "custom_credential" | "oauth2";

export type ConnectorAssignmentState = "pending" | "active" | "failed" | "removed";

export type ConnectorChangeKind = "connect" | "replace" | "remove" | "assign" | "unassign" | "oauth_connect" | "oauth_reconnect";

/**
 * `queued` = waiting for the firewall; `awaiting_code` = the firewall sent a confirmation code;
 * `awaiting_authorization` = the firewall started an OAuth authorization and the person has to
 * sign in at the provider; the rest are final.
 */
export type ConnectorChangeStatus = "queued" | "awaiting_code" | "awaiting_authorization" | "applied" | "failed" | "expired" | "cancelled";
