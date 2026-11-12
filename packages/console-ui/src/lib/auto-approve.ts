/**
 * The Auto approve check, as the firewall runs it (`rust/crates/cc-contracts/src/auto_approve.rs`).
 * The console runs this copy only for firewalls that do not check the rules yet (`evaluateRules`).
 * Both run the cases in `rust/crates/cc-contracts/auto-approve-cases.json`, so they cannot drift.
 */

export type AutoRuleEffect = "allow" | "ask" | "block";

export type AutoRule = {
  id: string;
  name: string;
  /** Empty: every kind. */
  kinds: string[];
  titleLike: string | null;
  /** `contains` (the default) or `exact`, both ignoring case. */
  titleMatch?: string | null;
  vmId: string | null;
  effect: string;
  enabled?: boolean;
};

export type AutoDecision = {
  effect: AutoRuleEffect;
  matchedRule: { id: string; name: string } | null;
};

/** Kinds a person always answers: no rule matches them. */
export const PERSON_ONLY_KINDS: readonly string[] = ["settings_change", "meeting_request"];

/** A title is cut to this many characters (UTF-16 units). */
export const TITLE_MAX = 200;

/**
 * A tool or action name as MCP and the app catalog spell them. An app call's title is
 * "Run the tool <name> on the MCP server <host>", and the name comes from the agent: one with a
 * space in it could hold another rule's text ("x on the MCP server search.parallel.ai").
 */
const PLAIN_ACTION = /^Run the tool [A-Za-z0-9_.:/-]{1,128} on the MCP server \S+$|^Run [A-Za-z0-9_.:/-]{1,128} in \S/;

const EFFECTS: readonly string[] = ["allow", "ask", "block"];
const ASK: AutoDecision = { effect: "ask", matchedRule: null };

/**
 * The first rule that matches, else Ask. `vmId` is the box the rules are matched against: the
 * agent for its approvals and app calls, the firewall for its website and email asks.
 */
export function matchAutoApprove(rules: readonly AutoRule[], req: { kind: string; title: string; vmId: string | null }): AutoDecision {
  if (PERSON_ONLY_KINDS.includes(req.kind)) return ASK;
  // An app call an Integrations rule asks about is answered only by a rule written for it: one that
  // names the kind or the title. A catch-all allow written for shell commands or websites must not
  // start approving deletes in connected apps. The approval is still for one call; the firewall keeps
  // the input and runs it once, as it does for a person's.
  const appCall = req.kind === "app_call";
  if (appCall && !PLAIN_ACTION.test(req.title)) return ASK;
  const title = req.title.toLowerCase();
  for (const r of rules) {
    if (r.enabled === false) continue;
    if (r.kinds.length > 0 && !r.kinds.includes(req.kind)) continue;
    if (appCall && r.kinds.length === 0 && !r.titleLike) continue;
    if (r.titleLike) {
      const needle = r.titleLike.toLowerCase();
      const hit = r.titleMatch === "exact" ? title === needle : title.includes(needle);
      if (!hit) continue;
    }
    if (r.vmId && r.vmId !== req.vmId) continue;
    if (!EFFECTS.includes(r.effect)) continue;
    return { effect: r.effect as AutoRuleEffect, matchedRule: { id: r.id, name: r.name } };
  }
  return ASK;
}

/** What a box raised, as far as its title goes. */
export type RaiseForTitle = {
  kind?: string;
  title?: string;
  summary?: string;
  method?: string;
  host?: string;
  app?: { service: string; action: string; connection?: string | null };
};

/**
 * The title a raise gets on its card, which is what rules are written against: an app call is
 * "Run the tool <tool> on the MCP server <host>" or "Run <action> in <App> (<connection>)", a
 * website or email ask its summary (else "METHOD host"), anything else its title. Trimmed and cut
 * at {@link TITLE_MAX}. Null when empty. The firewall builds the same.
 */
export function permissionTitle(raise: RaiseForTitle, appName: (service: string) => string): string | null {
  const kind = raise.kind ?? "access";
  let raw: string | undefined;
  if (kind === "app_call" && raise.app) {
    const { service, action, connection } = raise.app;
    raw = service.startsWith("mcp:")
      ? `Run the tool ${action} on the MCP server ${service.slice(4)}`
      : `Run ${action} in ${appName(service)}${connection ? ` (${connection})` : ""}`;
  } else if (kind === "access" || kind === "email_recipient" || kind === "app_call") {
    raw = raise.summary ?? `${raise.method ?? "GET"} ${raise.host ?? ""}`;
  } else {
    raw = raise.title;
  }
  const t = raw?.trim();
  if (!t) return null;
  if (t.length <= TITLE_MAX) return t;
  // Never half a surrogate pair, as the firewall cuts it.
  const cut = t.slice(0, TITLE_MAX - 1);
  return `${/[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut}…`;
}

/** The condition a rule shows when it has no `condDisplay` of its own. */
export function deriveCondFromMatchers(kinds: string[], titleLike: string | null, vmId: string | null, titleMatch: string = "contains"): string {
  const parts: string[] = [];
  parts.push(kinds.length > 0 ? `kind: ${kinds.join(", ")}` : "any kind");
  if (titleLike) parts.push(titleMatch === "exact" ? `title is "${titleLike}"` : `title contains "${titleLike}"`);
  if (vmId) parts.push(`vm = ${vmId}`);
  return parts.join(" · ");
}
