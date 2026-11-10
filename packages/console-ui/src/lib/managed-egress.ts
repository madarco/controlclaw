/**
 * The site rules a control plane adds by itself when a model provider or a channel is set up, so an
 * agent keeps reaching them when every other site is blocked. The same list as the firewall's
 * (`rust/crates/cc-contracts/managed-egress.json`; `managed-egress.test.ts` checks they agree).
 *
 * A managed rule carries `managed` (its source's key). Only the control plane's code sets it; the
 * firewall copies it into each request's record, and the AI log review and Activity tell these
 * requests apart by it, never by the rule's name or host.
 *
 * No server imports here: the pages' client lists read these too.
 */

export interface ManagedEgressHost {
  domain: string;
  /** A part of the path, as `matchPath` is. */
  path?: string;
}

export interface ManagedEgressSource {
  key: string;
  kind: "provider" | "channel";
  name: string;
  hosts: ManagedEgressHost[];
}

/** Before every rule a person adds (theirs are 0 or more), after the brain's own (-20, -10). */
export const MANAGED_EGRESS_PRIORITY = -5;

/** Every managed rule's id starts with this. */
export const MANAGED_EGRESS_ID_PREFIX = "managed:";

export const MANAGED_EGRESS: readonly ManagedEgressSource[] = [
  { key: "anthropic", kind: "provider", name: "Anthropic", hosts: [{ domain: "api.anthropic.com" }] },
  { key: "openai", kind: "provider", name: "OpenAI", hosts: [{ domain: "api.openai.com" }] },
  // The sign-in's model calls (`chatgpt.com/backend-api/codex`). The whole host: a path is matched as a
  // part of the URL, query included, so it would not narrow anything. The sign-in and its refresh are
  // the console's and the firewall's own calls.
  { key: "openai_codex", kind: "provider", name: "ChatGPT sign-in", hosts: [{ domain: "chatgpt.com" }] },
  { key: "google", kind: "provider", name: "Google Gemini", hosts: [{ domain: "generativelanguage.googleapis.com" }] },
  { key: "openrouter", kind: "provider", name: "OpenRouter", hosts: [{ domain: "openrouter.ai" }] },
  { key: "vercel_gateway", kind: "provider", name: "Vercel AI Gateway", hosts: [{ domain: "ai-gateway.vercel.sh" }] },
  { key: "controlclaw_included", kind: "provider", name: "Included AI", hosts: [{ domain: "ai-gateway.vercel.sh" }] },
  { key: "telegram", kind: "channel", name: "Telegram", hosts: [{ domain: "api.telegram.org" }] },
  {
    key: "slack",
    kind: "channel",
    name: "Slack",
    hosts: [{ domain: "slack.com" }, { domain: "wss-primary.slack.com" }, { domain: "wss-backup.slack.com" }],
  },
  { key: "whatsapp", kind: "channel", name: "WhatsApp", hosts: [{ domain: "web.whatsapp.com" }, { domain: "mmg.whatsapp.net" }] },
  { key: "agentmail", kind: "channel", name: "AgentMail", hosts: [{ domain: "api.agentmail.to" }, { domain: "ws.agentmail.to" }] },
  { key: "gmail", kind: "channel", name: "Gmail", hosts: [{ domain: "gmail.googleapis.com" }] },
];

export function managedEgressSource(key: string | null | undefined): ManagedEgressSource | null {
  return MANAGED_EGRESS.find((s) => s.key === key) ?? null;
}

/** The rule's name, as the rules list and the traffic log show it. */
export function managedEgressRuleName(s: ManagedEgressSource): string {
  return s.kind === "provider" ? `Model provider: ${s.name}` : `Channel: ${s.name}`;
}

/** What added the rule, in a few words for its row. */
export function managedEgressReason(key: string | null | undefined): string {
  const s = managedEgressSource(key);
  if (!s) return "Added by ControlClaw";
  return s.kind === "provider" ? `Added because ${s.name} is set up` : `Added for this agent’s ${s.name}`;
}

export interface ManagedEgressRule {
  id: string;
  name: string;
  matchDomain: string;
  matchPath: string | null;
  vmId: string | null;
  priority: number;
  managed: string;
}

/** The rules for one source, for every agent (`vmId` null) or one. */
export function managedEgressRules(s: ManagedEgressSource, vmId: string | null): ManagedEgressRule[] {
  return s.hosts.map((h) => ({
    id: `${MANAGED_EGRESS_ID_PREFIX}${s.key}:${h.domain}${vmId ? `:${vmId}` : ""}`,
    name: managedEgressRuleName(s),
    matchDomain: h.domain,
    matchPath: h.path ?? null,
    vmId,
    priority: MANAGED_EGRESS_PRIORITY,
    managed: s.key,
  }));
}

/** The parts of a traffic record `isRoutineRecord` reads, as the firewall sends them. */
export interface RoutineRecordFields {
  managed?: string | null;
  effect?: string | null;
  rule_id?: string | null;
  swapped?: readonly string[] | null;
  error?: string | null;
  model_error?: string | null;
  included?: string | null;
  status?: number | null;
}

/**
 * Routine traffic, as the firewall decides it (`cc_contracts::managed::is_routine`, the same
 * conditions): let through under a managed rule, carrying the organization's own key or token
 * (`swapped`), answered without an error. The AI log review does not read these; Activity leaves them
 * out unless asked. Decided once, when the record comes in.
 */
export function isRoutineRecord(r: RoutineRecordFields): boolean {
  return (
    !!r.managed &&
    r.effect === "allow" &&
    !!r.rule_id?.startsWith(MANAGED_EGRESS_ID_PREFIX) &&
    (r.swapped?.length ?? 0) > 0 &&
    !r.error &&
    !r.model_error &&
    (!r.included || r.included === "ok") &&
    (r.status == null || r.status < 400)
  );
}
