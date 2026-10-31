import type { Schemas } from "@controlclaw/fw-api";
import { agentmailError } from "@controlclaw/console-ui/lib/agentmail-words";
import { FwApiError, fw } from "./client";
import { send } from "./changes";

/**
 * Google, AgentMail and Website logins on the firewall's API (cc-local `api/accounts.rs`). Their
 * answers are untyped in the OpenAPI document (the modules' own summaries), so they are typed here.
 * Every change applies at once (no codes on a standalone firewall), apart from Google's sign-in,
 * which finishes in the `/oauth/callback` tab, and AgentMail's own claim code, which AgentMail emails.
 */

type CommandAnswer = Schemas["CommandAnswer"];

export const GOOGLE_SERVICES = ["gmail", "calendar", "drive", "contacts", "sheets", "docs"] as const;
export type GoogleService = (typeof GOOGLE_SERVICES)[number];
export const GOOGLE_SERVICE_LABEL: Record<string, string> = { gmail: "Gmail", calendar: "Calendar", drive: "Drive", contacts: "Contacts", sheets: "Sheets", docs: "Docs" };

export type GoogleAccount = {
  accountLabel: string | null;
  services: string[];
  scopes: string[];
  gmailScope: string | null;
  driveScope: string | null;
  audience: string | null;
  projectId: string | null;
  clientId: string | null;
  connected: boolean;
  failed: string | null;
  updatedAt: string | null;
};

export type GoogleView = {
  account: GoogleAccount | null;
  /** Only the agents Google has seen; the panel joins them with every agent. */
  agents: Array<{ vmId: string; name: string; granted: boolean }>;
  redirectOk: boolean;
  redirectProblem?: string;
  /** Where Google sends the person back: register it in the OAuth client. */
  redirectUri: string;
};

export async function readGoogle(): Promise<GoogleView> {
  return (await fw.get("/api/google")) as GoogleView;
}

export type GoogleConnect = Schemas["GoogleConnect"];

export type GoogleClient = { clientId: string; clientSecret: string; projectId: string | null; redirects: string[] };

/** A client JSON from the Google Cloud console: `{"web": {client_id, client_secret, project_id, redirect_uris}}`. */
export function parseGoogleClient(text: string): GoogleClient | null {
  try {
    const j = JSON.parse(text) as { web?: Record<string, unknown>; installed?: Record<string, unknown> };
    const w = j.web ?? j.installed;
    if (!w || typeof w.client_id !== "string" || typeof w.client_secret !== "string") return null;
    return { clientId: w.client_id, clientSecret: w.client_secret, projectId: typeof w.project_id === "string" ? w.project_id : null, redirects: Array.isArray(w.redirect_uris) ? (w.redirect_uris as string[]) : [] };
  } catch {
    return null;
  }
}


/** Starts the sign-in: the answer says where to send the browser. */
export async function connectGoogle(body: GoogleConnect): Promise<{ authorizeUrl: string; changeId: string | null }> {
  const ans = await send(() => fw.post("/api/google", { body }));
  const data = (ans.data ?? {}) as { authorizeUrl?: unknown; changeId?: unknown };
  if (typeof data.authorizeUrl !== "string") throw new Error(ans.message || "The firewall did not start the Google sign-in");
  return { authorizeUrl: data.authorizeUrl, changeId: typeof data.changeId === "string" ? data.changeId : null };
}

/** A change that applied with agents it could not reach: the first such reason, if any. */
function partial(ans: CommandAnswer): string | null {
  const failed = (ans.data as { failed?: Array<{ error?: string }> } | null)?.failed ?? [];
  return failed[0]?.error ?? null;
}

export async function grantGoogle(vmId: string, granted: boolean): Promise<string | null> {
  return partial(await send(() => fw.post("/api/google/agents/{vmId}", { path: { vmId }, body: { granted } })));
}

export async function pushGoogle(vmId: string): Promise<void> {
  await send(() => fw.post("/api/google/agents/{vmId}/push", { path: { vmId }, body: {} }));
}

export async function googleServices(services: string[]): Promise<void> {
  await send(() => fw.put("/api/google/services", { body: { services } }));
}

export async function forgetGoogle(): Promise<void> {
  await send(() => fw.delete("/api/google", { body: {} }));
}

export type AgentMailInbox = {
  inboxId: string;
  vmId: string | null;
  status: "awaiting_claim" | "pending" | "active" | "setup_failed" | "unassigned" | "needs_key" | string;
  allowedSenders: string[];
};

export type AgentMailView = {
  orgId: string | null;
  humanEmail: string | null;
  authType: string | null;
  status: "disconnected" | "signup_uncertain" | "awaiting_claim" | "active" | string;
  limits: Record<string, number | undefined>;
  canCreate: boolean;
  inboxes: AgentMailInbox[];
  /** Set when the firewall could not reach AgentMail: the summary is still the last it knew. */
  errorCode?: string | null;
};

/** The summary, also when AgentMail itself did not answer (a 409 whose data is still the summary). */
export async function readAgentMail(): Promise<AgentMailView> {
  try {
    return (await fw.get("/api/agentmail")) as AgentMailView;
  } catch (e) {
    const data = e instanceof FwApiError ? (e.body as { data?: AgentMailView } | null)?.data : undefined;
    if (data) return data;
    throw e;
  }
}

export type AgentMailAction = "signup" | "claim" | "check" | "create" | "import" | "attach" | "forget" | "delete" | "push";

/**
 * One AgentMail action. A refusal's message is AgentMail's own code (`claim_required`), said here in
 * words; the answer's data is the account as it is now.
 */
export async function agentMail(action: AgentMailAction, body: Record<string, unknown>): Promise<AgentMailView> {
  try {
    const ans = await fw.post("/api/agentmail/{action}", { path: { action }, body });
    return ans.data as AgentMailView;
  } catch (e) {
    if (e instanceof FwApiError) {
      const b = e.body as { message?: unknown; error?: unknown } | null;
      const code = typeof b?.message === "string" ? b.message : null;
      throw new Error((code && agentmailError(code)) || (typeof b?.error === "string" ? b.error : e.message), { cause: e });
    }
    throw e;
  }
}

export type WebsiteLogin = {
  id: string;
  name: string;
  sites: string[];
  loginUrl: string | null;
  username: string | null;
  mode: "swap" | "type";
  kind: "password" | "session";
  totp: boolean;
  source: "vault" | "1password";
  vmIds: string[];
  needsSignInPage?: boolean;
  lastUsedAt: string | null;
  updatedAt: string | null;
};

export type OnePassword = { vaults: Array<{ id: string; name: string }>; lastSyncAt: string | null; lastError: string | null; items?: number } | null;

export type LoginsView = { logins: WebsiteLogin[]; onePassword: OnePassword };

export async function readLogins(): Promise<LoginsView> {
  return (await fw.get("/api/logins")) as LoginsView;
}

/** Name, sites and agents go together: the firewall checks the whole login. */
export async function updateLogin(l: Pick<WebsiteLogin, "id" | "name" | "sites" | "vmIds" | "mode">): Promise<LoginsView> {
  const ans = await send(() => fw.post("/api/logins/change", { body: { action: "update", id: l.id, name: l.name, sites: l.sites, vmIds: l.vmIds, mode: l.mode } }));
  return ans.data as LoginsView;
}

export async function deleteLogin(id: string): Promise<LoginsView> {
  const ans = await send(() => fw.post("/api/logins/change", { body: { action: "delete", id } }));
  return ans.data as LoginsView;
}

export async function syncOnePassword(): Promise<string> {
  const ans = await send(() => fw.post("/api/logins/1password/sync", { body: {} }));
  return ans.message || "Reading 1Password now. Refresh in a minute.";
}

export async function disconnectOnePassword(): Promise<void> {
  await send(() => fw.post("/api/logins/1password/disconnect", { body: {} }));
}

/** A one-time link to one of the firewall's own pages (60 seconds), where passwords are typed. */
export async function openFirewallPage(page: "logins" | "firewall-logs"): Promise<string> {
  const res = (await send(() => fw.post("/api/open", { body: { page } }))) as { url?: string };
  if (!res.url) throw new Error("The firewall gave no link");
  return res.url;
}
