/** The states of a channel connection and its changes, as the console stores them. */

/** The channels an agent connects (the `agent_channel_type` enum in the console's database). */
export const AGENT_CHANNEL_TYPES = ["telegram", "slack", "whatsapp"] as const;
export type AgentChannelType = (typeof AGENT_CHANNEL_TYPES)[number];

/**
 * `pending` = handed to the firewall, not yet applied on the box; `active` = applied.
 *
 * `orphaned` = the firewall that held this connection's token is gone. Tokens never leave the
 * firewall, so a box that is destroyed takes them with it and what is left here is a row nothing
 * can act on: it cannot be put on an agent, its token cannot be replaced, and only Remove is left.
 * Set when the org's firewall is torn down, and off every beat from what the firewall says it
 * holds (`reconcileChannelInventory`) — which also clears it again if the connection comes back,
 * as it does when a firewall is put back from a backup.
 *
 * Stored as text, not a pg enum, so a new value costs no migration.
 */
export type AgentChannelState = "pending" | "active" | "failed" | "orphaned" | "removed";

/** `placeholder` = the box holds a placeholder the proxy swaps; `plain` = the real token is on the box. */
export type AgentChannelMode = "placeholder" | "plain";

/** What the box last reported for this connection (a slice of OpenClaw's `channels.status`). */
export type AgentChannelBoxStatus = {
  configured: boolean;
  running: boolean;
  connected: boolean;
  lastError: string | null;
  at: string;
  /** Set while the channel's OpenClaw plugin is being installed on the box, or if that failed. */
  setup?: { state: "installing" | "failed"; message: string } | null;
};

export type AgentChannelChangeKind =
  | "add"
  | "replace"
  | "remove"
  | "assign"
  | "unassign"
  | "approve_pairing"
  /**
   * `add_sender` / `remove_sender`: who the firewall sends confirmation codes to (T-83). Not a
   * pairing approval — the person can already talk to the agent — so it changes nothing on the
   * agent box and only the firewall's own recipient list. Stored as text, so neither costs a
   * migration.
   */
  | "add_sender"
  | "remove_sender"
  | "whatsapp_login";

/**
 * `queued` = waiting for the firewall to pick the command up; `awaiting_code` = the firewall sent
 * a confirmation code to an approved sender; `applied` / `failed` / `expired` / `cancelled` are
 * final.
 *
 * `unconfirmed` is final too, and only a pairing approval reaches it: the firewall asked the agent
 * box and never got an answer, so whether the person was approved is genuinely unknown. The
 * firewall keeps asking the box and records the answer as a new row when it lands
 * (`onChannelReconcileReport`), which is why this is not a failure and must not be retried by
 * hand — the pairing code has already been consumed on the box.
 *
 * Stored as text, not a pg enum, so a new value costs no migration.
 */
export type AgentChannelChangeStatus = "queued" | "awaiting_code" | "applied" | "failed" | "expired" | "cancelled" | "unconfirmed";

/** Whether a page has asked the agent box itself yet: not asked (`deferred`), answered, or no answer. */
export type BoxRead = "deferred" | "ok" | "unreachable";
