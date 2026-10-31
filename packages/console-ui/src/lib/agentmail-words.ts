/**
 * AgentMail's answers in words: the error codes the firewall's AgentMail module gives, and the one
 * status line the Integrations card shows. Shared by the console and the firewall's own panel.
 */

export const MAIL_ERRORS: Record<string, string> = {
  user_exists:
    "That email already has an AgentMail account. Use an existing account below, or try another owner email.",
  username_taken:
    "That username is taken. Try adding -mail, -assistant, or a number.",
  organization_mismatch:
    "This key belongs to a different AgentMail organization. Only one can be connected here.",
  invalid_key:
    "AgentMail refused that key. Copy a current key from the AgentMail console.",
  permission_denied:
    "This key lacks a required permission. Import a key with API key read and management permissions.",
  scope_unverified:
    "AgentMail couldn’t confirm this key’s scope. Use a key with API key read permission.",
  signup_uncertain:
    "Signup may have completed. Check the owner email, then import a key from the AgentMail console. We won’t repeat signup and invalidate an existing key.",
  apply_failed:
    "The inbox is ready, but the agent couldn’t apply it. Update or start the agent, then retry setup.",
  unsupported_inbox:
    "ControlClaw supports only @agentmail.to inboxes.",
  claim_permissions_pending:
    "Your account is claimed. AgentMail may take up to five minutes to enable key creation. Wait, then choose Retry setup.",
  claim_required: "Claim the AgentMail account before assigning more inboxes.",
  org_key_required:
    "Import an organization key, or a fresh inbox key, to continue.",
  agent_has_inbox:
    "This agent already has an inbox. Unassign it before choosing another.",
  inbox_assigned: "Unassign this inbox from its current agent first.",
  request_uncertain:
    "AgentMail didn’t answer. Refresh the account before trying again.",
  rate_limited: "AgentMail’s rate limit was reached. Wait before trying again.",
  invalid_code: "That code is not right. Check the newest email from AgentMail and type it again.",
  confirm_required: "Type the inbox's address exactly to delete it.",
  already_connected: "An AgentMail account is already connected here. Add inboxes to it, or disconnect it first.",
  invalid_input: "AgentMail did not take that. Check the email, the inbox name (lower-case letters, digits and dashes) and try again.",
  senders_moved:
    "Who can email this inbox is now set under Email in Security rules.",
};
export function agentmailError(code: string | null) {
  return code
    ? (MAIL_ERRORS[code] ??
        "AgentMail couldn’t finish this change. Refresh the account and try again.")
    : null;
}

type AgentMailStatusInput = {
  account: { status: string } | null;
  inboxes: { vmId: string | null; status: string }[];
};

/**
 * Where AgentMail stands, in one line, for the card on the Integrations page. Same shape as the
 * Google and Drive status lines, so the four cards read alike.
 */
export function agentMailStatusLine(view: AgentMailStatusInput): {
  text: string;
  tone: "allow" | "ask" | "block" | "muted";
} {
  const status = view.account?.status ?? "disconnected";
  if (status === "disconnected") return { text: "Not set up", tone: "muted" };
  if (status === "signup_uncertain") return { text: "Sign-up not confirmed", tone: "ask" };
  if (status === "awaiting_claim") return { text: "Waiting for you to claim the account", tone: "ask" };
  if (view.inboxes.some((i) => i.status === "setup_failed" || i.status === "needs_key"))
    return { text: "An inbox needs attention", tone: "block" };
  const assigned = view.inboxes.filter((i) => i.vmId);
  if (!assigned.length) return { text: "Connected, no inboxes yet", tone: "allow" };
  const n = assigned.length;
  const agents = new Set(assigned.map((i) => i.vmId)).size;
  return {
    text: `${n} ${n === 1 ? "inbox" : "inboxes"} on ${agents} ${agents === 1 ? "agent" : "agents"}`,
    tone: view.inboxes.some((i) => i.status === "pending") ? "ask" : "allow",
  };
}
