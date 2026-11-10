import type { AgentChannelType, BoxRead } from "./channel-states";
import type { PairingsErrorView } from "./channels-schema";

/**
 * The step after a channel is connected: the person messages the bot, the agent answers with a
 * pairing code, and the request shows up in the dialog to approve. Pure and client-safe.
 *
 * The first approval matters more than it looks: the firewall sends its confirmation codes to the
 * people approved on a channel, so until somebody is, nothing that needs a code can be done.
 */

/** How long to wait for the first message before saying what to check. */
export const PAIRING_WAIT_MS = 3 * 60_000;
/** How long the agent may fail to say who is waiting before the dialog stops promising to show it. */
export const PAIRING_UNREADABLE_MS = 45_000;

/**
 * `waiting`: no request yet. `slow`: still none after `PAIRING_WAIT_MS`. `unreadable`: the agent
 * has not said who is waiting for a while (it is down, or runs software that does not report it).
 * `request`: somebody is waiting. A request that arrives later wins over every other phase.
 */
export type PairingPhase = "waiting" | "slow" | "unreadable" | "request";

/** A read that says nothing about who is waiting. `busy` is OpenClaw restarting, which passes. */
export function isUnreadable(boxRead: BoxRead, pairingsError: PairingsErrorView | null): boolean {
  return boxRead === "unreachable" || (!!pairingsError && !pairingsError.busy);
}

export function pairingPhase(input: { requests: number; waitingSince: number; unreadableSince: number | null; now: number }): PairingPhase {
  if (input.requests > 0) return "request";
  if (input.unreadableSince !== null && input.now - input.unreadableSince >= PAIRING_UNREADABLE_MS) return "unreadable";
  if (input.now - input.waitingSince >= PAIRING_WAIT_MS) return "slow";
  return "waiting";
}

/** Where the person starts the chat, per channel. Every field is optional: a lookup may fail. */
export type StartChat =
  | { type: "telegram"; username: string | null }
  | { type: "slack"; appId: string | null; teamId: string | null; appName: string | null }
  | { type: "whatsapp"; number: string | null };

export function emptyStart(type: AgentChannelType): StartChat {
  if (type === "telegram") return { type, username: null };
  if (type === "slack") return { type, appId: null, teamId: null, appName: null };
  return { type, number: null };
}

/** The link that opens the chat, when there is enough to build one. */
export function startChatHref(start: StartChat): string | null {
  switch (start.type) {
    case "telegram":
      return start.username ? `https://t.me/${encodeURIComponent(start.username.replace(/^@/, ""))}` : null;
    case "slack":
      // Slack's documented deep link to an app's Messages tab. `team` picks the workspace when the
      // person is signed in to several.
      return start.appId ? `https://slack.com/app_redirect?app=${encodeURIComponent(start.appId)}${start.teamId ? `&team=${encodeURIComponent(start.teamId)}` : ""}` : null;
    case "whatsapp": {
      const digits = start.number?.replace(/\D/g, "") ?? "";
      return digits.length >= 6 ? `https://wa.me/${digits}` : null;
    }
  }
}

/** What the link says: "@marcobot", "Ops agent", "+44 7700 900123". */
export function startChatName(start: StartChat): string | null {
  switch (start.type) {
    case "telegram":
      return start.username ? `@${start.username.replace(/^@/, "")}` : null;
    case "slack":
      return start.appName;
    case "whatsapp":
      return start.number;
  }
}

/** The app id inside an app-level token (`xapp-1-A0123ABCD-…`), which is all the Slack link needs. */
export function slackAppIdOf(appToken: string): string | null {
  return /^xapp-\d+-(A[A-Z0-9]+)-/.exec(appToken.trim())?.[1] ?? null;
}

/**
 * Who a token belongs to, asked of the chat service from the person's browser. The token is
 * already in this browser and goes to the same service anyway; nothing here reaches ControlClaw.
 *
 * `invalid` is the service saying no, which is worth stopping for. Anything else (offline, slow,
 * blocked) is `unknown`, and the dialog carries on without the name.
 */
export type TokenLookup<T> = { kind: "ok"; value: T } | { kind: "invalid" } | { kind: "unknown" };

const LOOKUP_TIMEOUT_MS = 5_000;

async function getJson(url: string, init?: RequestInit): Promise<{ status: number; body: Record<string, unknown> } | null> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { ...init, signal: ctl.signal, credentials: "omit", referrerPolicy: "no-referrer" });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    return { status: res.status, body };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Telegram's `getMe`: the bot's username. */
export async function lookupTelegramBot(botToken: string, fetchJson = getJson): Promise<TokenLookup<{ username: string | null }>> {
  const r = await fetchJson(`https://api.telegram.org/bot${botToken.trim()}/getMe`);
  if (!r) return { kind: "unknown" };
  if (r.status === 401 || r.status === 404) return { kind: "invalid" };
  const result = r.body.ok === true ? (r.body.result as Record<string, unknown> | undefined) : undefined;
  if (!result) return { kind: "unknown" };
  return { kind: "ok", value: { username: typeof result.username === "string" ? result.username : null } };
}

/** Slack's `auth.test`: the workspace and the app's bot user. A form body, so no preflight. */
export async function lookupSlackApp(botToken: string, fetchJson = getJson): Promise<TokenLookup<{ teamId: string | null; team: string | null; appName: string | null }>> {
  const r = await fetchJson("https://slack.com/api/auth.test", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: botToken.trim() }).toString(),
  });
  if (!r) return { kind: "unknown" };
  if (r.body.ok !== true) {
    return r.body.error === "invalid_auth" || r.body.error === "not_authed" || r.body.error === "account_inactive" || r.body.error === "token_revoked"
      ? { kind: "invalid" }
      : { kind: "unknown" };
  }
  const s = (k: string) => (typeof r.body[k] === "string" && r.body[k] ? (r.body[k] as string) : null);
  return { kind: "ok", value: { teamId: s("team_id"), team: s("team"), appName: s("user") } };
}
