import { z } from "zod";

/**
 * Integrations rules, called Apps rules before T-179 (docs/plans/connector-inspection.md,
 * docs/plans/mcp-inspection.md): what an agent may do through the organization's app connections
 * and in any remote MCP server. One ordered list per organization, held on the firewall (`apps-rules.ts`) and
 * read by the connector gate on every call. The first enabled rule that matches decides; when none
 * does, the call is allowed and recorded. Shared with the console, so both refuse the same things:
 * only zod here.
 */

export const APP_RULES_MAX = 100;
export const APP_RULE_ACTIONS_MAX = 50;
export const APP_RULE_AGENTS_MAX = 50;

/** Strictest to loosest. */
export const APP_EFFECTS = ["block", "ask", "allow"] as const;
export type AppEffect = (typeof APP_EFFECTS)[number];
/** OpenConnector's own word for what an action does to the provider (`operationType`). */
export const APP_OPERATIONS = ["read", "write", "destructive"] as const;
export type AppOperation = (typeof APP_OPERATIONS)[number];
export const PROXY_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;

const PLAIN_LINE = /^(?! )(?!.* {2})(?!.* $)[^\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Cs}\p{Zl}\p{Zp}]+$/u;
const ruleId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);
/** OpenConnector's service ids (`connectors.ts` `SERVICE_RE`). */
export const connectorServiceId = z.string().regex(/^[a-z0-9][a-z0-9_]{0,60}$/);
/** An MCP server, by host: `mcp:mcp.deepwiki.com`. The same for the organization's own and an agent's. */
export const MCP_SERVICE_RE = /^mcp:[a-z0-9](?:[a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}(?::\d{1,5})?$/;
/** An integration: an OpenConnector app, or an MCP server by host. */
export const serviceId = z.string().max(270).refine((s) => connectorServiceId.safeParse(s).success || MCP_SERVICE_RE.test(s), "must be an app's id or mcp:<host>");
export function isMcpService(service: string | null | undefined): boolean {
  return !!service && service.startsWith("mcp:");
}
/** An MCP tool's name, or one with `*`: `delete_*`. */
export type ToolAnnotations = { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean };

/** The kind an MCP server's own hints give a tool, or null when they say nothing (the firewall and the console both read it so). */
export function kindFromAnnotations(a: ToolAnnotations | null | undefined): AppOperation | null {
  if (a?.readOnlyHint === true) return "read";
  if (a?.destructiveHint === true) return "destructive";
  if (a?.destructiveHint === false) return "write";
  return null;
}

export const toolPattern = z.string().regex(/^[A-Za-z0-9_.:/*-]{1,128}$/);
export const APP_RULE_TOOLS_MAX = 50;
/** The rule as one sentence, judged by the AI against the call (docs/plans/mcp-inspection.md §6). */
export const RULE_SENTENCE_MAX = 300;
const vmId = z.string().min(1).max(100);
/** `github.create_issue`, or with `*` for any run of characters: `github.delete_*`, `*.delete_*`. */
export const actionPattern = z.string().regex(/^[a-z0-9_*][a-z0-9_*]{0,60}\.[A-Za-z0-9_.*-]{1,120}$/);
/** A provider path a proxy rule matches by prefix: `/repos/`, never a query. */
const proxyPath = z
  .string()
  .max(300)
  .regex(/^\/[^\s?#\\]*$/)
  .refine((p) => !p.split("/").some((seg) => seg === "." || seg === ".."), "no . or .. segments");

export const appMatch = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("any") }).strict(),
  z.object({ kind: z.literal("actions"), actions: z.array(actionPattern).min(1).max(APP_RULE_ACTIONS_MAX) }).strict(),
  z.object({ kind: z.literal("operation"), operations: z.array(z.enum(APP_OPERATIONS)).min(1).max(3) }).strict(),
  z.object({ kind: z.literal("proxy"), method: z.enum(PROXY_METHODS).nullable(), path: proxyPath.nullable() }).strict(),
  /** MCP tools by name. */
  z.object({ kind: z.literal("tools"), tools: z.array(toolPattern).min(1).max(APP_RULE_TOOLS_MAX) }).strict(),
]);
export type AppMatch = z.infer<typeof appMatch>;

export const appRuleName = z.string().min(1).max(80).regex(PLAIN_LINE, "must be one plain line");

export const appRule = z
  .object({
    id: ruleId,
    name: appRuleName,
    enabled: z.boolean(),
    /** Empty: every agent. */
    agents: z.array(vmId).max(APP_RULE_AGENTS_MAX).refine((a) => new Set(a).size === a.length, "an agent is listed twice"),
    /** Null: any app. */
    service: serviceId.nullable(),
    /** OpenConnector's connection id, of `service`. Null: any connection of it. */
    connectionId: z.string().min(1).max(100).nullable(),
    match: appMatch,
    then: z.enum(APP_EFFECTS),
    /** Optional: the AI judges whether the call fits it, and the rule acts only when it does. */
    sentence: z.string().min(3).max(RULE_SENTENCE_MAX).regex(PLAIN_LINE, "must be one plain line").optional(),
  })
  .strict()
  .refine((r) => r.connectionId === null || r.service !== null, "a connection belongs to one app")
  .refine((r) => r.connectionId === null || !isMcpService(r.service), "an MCP server has no connections")
  .refine((r) => (r.match.kind !== "tools" && r.match.kind !== "actions" && r.match.kind !== "proxy") || r.service === null || (r.match.kind === "tools") === isMcpService(r.service), "tools are an MCP server's; actions and direct calls are an app's")
  .refine((r) => r.match.kind !== "actions" || r.service === null || r.match.actions.every((a) => a.startsWith(`${r.service}.`) || a.startsWith("*.")), "the actions must be the app's");
export type AppRule = z.infer<typeof appRule>;

export const appRulesChange = z.discriminatedUnion("op", [
  /** A new rule (at `at`, else last), or a rule replaced in place. */
  z.object({ op: z.literal("put"), rule: appRule, at: z.number().int().min(0).max(APP_RULES_MAX).optional() }).strict(),
  z.object({ op: z.literal("delete"), id: ruleId }).strict(),
  z.object({ op: z.literal("move"), id: ruleId, to: z.number().int().min(0).max(APP_RULES_MAX) }).strict(),
]);
export type AppRulesChange = z.infer<typeof appRulesChange>;

export const appRulesSnapshot = z.object({
  rules: z.array(appRule),
  /** The firewall could not open its store: every call is refused until a change reseals it. */
  unreadable: z.boolean().optional(),
});
export type AppRulesSnapshot = z.infer<typeof appRulesSnapshot>;

/** The seeded rule's name before T-179; a firewall that finds it unchanged renames it (`apps-rules.ts`). */
export const SEEDED_APP_RULE_OLD_NAME = "Ask before destructive app actions";
/** Every organization starts with this one (owner decision, 2026-10-25). It only narrows. */
export const SEEDED_APP_RULE: AppRule = {
  id: "ask-destructive",
  name: "Ask before destructive integration actions",
  enabled: true,
  agents: [],
  service: null,
  connectionId: null,
  match: { kind: "operation", operations: ["destructive"] },
  then: "ask",
};

/** One call as the gate read it. */
export interface AppCall {
  vmId: string;
  service: string;
  /** Null when the call names no connection the gate could pin down; see `decideApp`. */
  connectionId: string | null;
  /** Execute calls. */
  actionId: string | null;
  operation: AppOperation | null;
  /** Proxy calls: the method and the path without its query. */
  proxy: { method: string; path: string } | null;
  /** MCP calls (`service` is `mcp:<host>`): the tool. */
  tool?: string | null;
  /** The call's input or arguments: only for judging a rule's sentence, never matched on. */
  input?: unknown;
}

/** `judged`: the rule had a sentence, and how the AI answered (or that it could not). */
export type AppDecision = { then: AppEffect; rule: AppRule | null; judged?: "fits" | "unavailable" };

/**
 * Whether a call fits a rule's sentence, from the AI: "fits", "no", or "unavailable" when it could
 * not answer (no model, the day's allowance used, a timeout). Only asked for a rule whose fields match.
 */
export type SentenceJudge = (rule: AppRule, call: AppCall) => Promise<"fits" | "no" | "unavailable">;

/** A proxy call's kind, from its method: what an action's `operationType` says for actions. */
export function proxyOperation(method: string): AppOperation {
  const m = method.toUpperCase();
  return m === "GET" || m === "HEAD" ? "read" : m === "DELETE" ? "destructive" : "write";
}

/**
 * What a call does, for an operation rule. An action the catalog gives no kind (or one this
 * firewall does not know) counts as destructive: a rule that asks before deleting must not be
 * stepped around by an action nobody labelled.
 */
export function operationOf(call: Pick<AppCall, "operation" | "proxy">): AppOperation {
  return call.operation ?? (call.proxy ? proxyOperation(call.proxy.method) : "destructive");
}

/**
 * Whether a (decoded) provider path is at or under a rule's path, segment by segment and ignoring
 * case: `/repos` covers `/repos` and `/repos/a`, not `/repos-archive`.
 */
export function pathUnder(path: string, prefix: string): boolean {
  const p = path.toLowerCase();
  const r = prefix.toLowerCase();
  if (r === "/" || p === r || p === r.replace(/\/+$/, "")) return true;
  return p.startsWith(r.endsWith("/") ? r : `${r}/`);
}

function globMatch(pattern: string, value: string): boolean {
  if (!pattern.includes("*")) return pattern === value;
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return re.test(value);
}

export function ruleMatches(rule: AppRule, call: AppCall): boolean {
  if (!rule.enabled) return false;
  if (rule.agents.length && !rule.agents.includes(call.vmId)) return false;
  if (rule.service !== null && rule.service !== call.service) return false;
  if (rule.connectionId !== null && rule.connectionId !== call.connectionId) return false;
  const m = rule.match;
  switch (m.kind) {
    case "any":
      return true;
    case "actions":
      // An app's direct API calls can do what its actions do. A rule that asks or blocks actions of one
      // app covers that app's direct calls too; an allow for some actions never lets them through.
      if (call.actionId === null) return call.proxy !== null && rule.service !== null && rule.service === call.service && rule.then !== "allow";
      return m.actions.some((p) => globMatch(p, call.actionId!));
    case "operation":
      return m.operations.includes(operationOf(call));
    case "proxy":
      return call.proxy !== null && (m.method === null || m.method === call.proxy.method.toUpperCase()) && (m.path === null || pathUnder(call.proxy.path, m.path));
    case "tools":
      return !!call.tool && m.tools.some((p) => globMatch(p, call.tool!));
  }
}

const RANK: Record<AppEffect, number> = { block: 0, ask: 1, allow: 2 };

/** The rule that decides one call: the first enabled match, or the default (allow). A rule with a sentence is passed over here: `decideAppJudged` asks about it. */
export function decideOne(rules: readonly AppRule[], call: AppCall): AppDecision {
  for (const rule of rules) if (ruleMatches(rule, call)) return rule.sentence ? sentenceUnjudged(rule) : { then: rule.then, rule };
  return { then: "allow", rule: null };
}

/** A rule with a sentence that nobody could judge acts with the stricter of its own action and Ask. */
function sentenceUnjudged(rule: AppRule): AppDecision {
  return { then: RANK[rule.then] <= RANK.ask ? rule.then : "ask", rule, judged: "unavailable" };
}

/** `decideOne`, asking the AI about each rule with a sentence whose fields match. */
export async function decideOneJudged(rules: readonly AppRule[], call: AppCall, judge: SentenceJudge | null): Promise<AppDecision> {
  for (const rule of rules) {
    if (!ruleMatches(rule, call)) continue;
    if (!rule.sentence) return { then: rule.then, rule };
    const answer = judge ? await judge(rule, call).catch(() => "unavailable" as const) : "unavailable";
    if (answer === "fits") return { then: rule.then, rule, judged: "fits" };
    if (answer === "unavailable") return sentenceUnjudged(rule);
  }
  return { then: "allow", rule: null };
}

/** `decideApp` with sentences judged. */
export async function decideAppJudged(rules: readonly AppRule[], call: AppCall, connections: readonly string[] = [], judge: SentenceJudge | null = null): Promise<AppDecision> {
  const candidates = call.connectionId !== null || connections.length === 0 ? [call] : connections.map((id) => ({ ...call, connectionId: id }));
  let worst: AppDecision | null = null;
  for (const c of candidates) {
    const d = await decideOneJudged(rules, c, judge);
    if (!worst || RANK[d.then] < RANK[worst.then]) worst = d;
  }
  return worst!;
}

/**
 * The decision for a call that may use any of `connections` (the agent's connections of that app
 * when it named none the gate can pin down): the strictest of them, so a rule on one connection
 * cannot be stepped around by leaving the name out.
 */
export function decideApp(rules: readonly AppRule[], call: AppCall, connections: readonly string[] = []): AppDecision {
  const candidates = call.connectionId !== null || connections.length === 0 ? [call] : connections.map((id) => ({ ...call, connectionId: id }));
  let worst: AppDecision | null = null;
  for (const c of candidates) {
    const d = decideOne(rules, c);
    if (!worst || RANK[d.then] < RANK[worst.then]) worst = d;
  }
  return worst!;
}

export function applyAppChange(rules: readonly AppRule[], change: AppRulesChange): AppRule[] {
  const i = change.op === "put" ? rules.findIndex((r) => r.id === change.rule.id) : rules.findIndex((r) => r.id === change.id);
  if (change.op === "delete") {
    if (i < 0) throw new Error("no such rule");
    return rules.filter((_, j) => j !== i);
  }
  if (change.op === "move") {
    if (i < 0) throw new Error("no such rule");
    const rest = rules.filter((_, j) => j !== i);
    rest.splice(Math.min(change.to, rest.length), 0, rules[i]);
    return rest;
  }
  if (i >= 0) return rules.map((r, j) => (j === i ? change.rule : r));
  if (rules.length >= APP_RULES_MAX) throw new Error("too many rules");
  const next = [...rules];
  next.splice(Math.min(change.at ?? next.length, next.length), 0, change.rule);
  return next;
}

/** Whether every enabled rule in `list` is at least as strict as `effect` (`stricter`) or at least as loose. */
function all(list: readonly AppRule[], test: (r: AppRule) => boolean): boolean {
  return list.every((r) => !r.enabled || test(r));
}

/** A rule taken out of the list at `i`: what it matched now falls to the rules below it and the default allow. */
function removalWidens(rule: AppRule): boolean {
  return rule.enabled && rule.then !== "allow";
}

/** A rule put in at `i`: what it matches now gets its effect instead of what the rules below gave. */
function insertionWidens(rule: AppRule, below: readonly AppRule[]): boolean {
  return rule.enabled && !all(below, (r) => RANK[r.then] >= RANK[rule.then]);
}

function sameScope(a: AppRule, b: AppRule): boolean {
  return JSON.stringify([a.agents, a.service, a.connectionId, a.match]) === JSON.stringify([b.agents, b.service, b.connectionId, b.match]);
}

/**
 * A sentence change (owner, 2026-10-25): any edit counts as letting more through, except taking the
 * sentence off a Block or Ask rule, which only makes it stop or ask about more.
 */
function sentenceWidens(old: AppRule, next: AppRule): boolean {
  if ((old.sentence ?? null) === (next.sentence ?? null)) return false;
  return !(next.sentence === undefined && next.then !== "allow" && old.then === next.then);
}

/**
 * Whether a change lets any call through that was stopped or asked before (block → ask → allow).
 * Those changes need the firewall's code; a change that only narrows applies at once. Decided per
 * change, conservatively: a change that might widen counts as widening.
 */
export function widens(rules: readonly AppRule[], change: AppRulesChange): boolean {
  if (change.op === "delete") {
    const old = rules.find((r) => r.id === change.id);
    return !!old && removalWidens(old);
  }
  if (change.op === "move") {
    const i = rules.findIndex((r) => r.id === change.id);
    if (i < 0) return false;
    const rule = rules[i];
    if (!rule.enabled) return false;
    const rest = rules.filter((_, j) => j !== i);
    const to = Math.min(change.to, rest.length);
    // Up: what it shares with the rules it passes now gets its effect. Down: theirs.
    if (to < i) return !all(rest.slice(to, i), (r) => RANK[r.then] >= RANK[rule.then]);
    return !all(rest.slice(i, to), (r) => RANK[r.then] <= RANK[rule.then]);
  }
  const i = rules.findIndex((r) => r.id === change.rule.id);
  const next = change.rule;
  if (i < 0) {
    const at = Math.min(change.at ?? rules.length, rules.length);
    return insertionWidens(next, rules.slice(at));
  }
  const old = rules[i];
  const below = rules.slice(i + 1);
  if (old.enabled && next.enabled && sentenceWidens(old, next)) return true;
  // A rename, or the same calls answered more strictly.
  if (sameScope(old, next) && (!old.enabled || next.enabled) && RANK[next.then] <= RANK[old.then]) return old.enabled ? false : insertionWidens(next, below);
  return removalWidens(old) || insertionWidens(next, below);
}

const EFFECT_WORDS: Record<AppEffect, string> = { allow: "allows", ask: "asks a person before", block: "blocks" };
const OPERATION_WORDS: Record<AppOperation, string> = { read: "reading", write: "changing", destructive: "deleting" };

/** What a rule covers, in words: from the rule's enums and ids only. */
export function describeMatch(rule: Pick<AppRule, "service" | "match">, appName?: string): string {
  const app = rule.service ? (appName ?? (isMcpService(rule.service) ? `the MCP server ${rule.service.slice(4)}` : rule.service)) : "any integration";
  const m = rule.match;
  switch (m.kind) {
    case "any":
      return `every call to ${app}`;
    case "actions":
      return `${m.actions.length === 1 ? m.actions[0] : `${m.actions.length} actions`} in ${app}`;
    case "operation":
      return `${m.operations.map((o) => OPERATION_WORDS[o]).join(" or ")} in ${app}`;
    case "proxy":
      return `direct ${m.method ?? "API"} calls${m.path ? ` to ${m.path}` : ""} in ${app}`;
    case "tools":
      return `${m.tools.length === 1 ? `the tool ${m.tools[0]}` : `${m.tools.length} tools`} in ${app}`;
  }
}

/** The one line a person reads next to the code. Written on the firewall, never by the console. */
export function describeAppChange(change: AppRulesChange, rules: readonly AppRule[]): string {
  if (change.op === "delete") {
    const old = rules.find((r) => r.id === change.id);
    return old ? `Delete the integration rule that ${EFFECT_WORDS[old.then]} ${describeMatch(old)}` : "Delete an integration rule";
  }
  if (change.op === "move") {
    const old = rules.find((r) => r.id === change.id);
    return `Move the integration rule ${old ? `that ${EFFECT_WORDS[old.then]} ${describeMatch(old)} ` : ""}to position ${change.to + 1}`;
  }
  const r = change.rule;
  const exists = rules.some((x) => x.id === r.id);
  const who = r.agents.length === 0 ? "all agents" : r.agents.length === 1 ? "one agent" : `${r.agents.length} agents`;
  const old = rules.find((x) => x.id === r.id);
  // The sentence is the owner's own words and part of what the code confirms: said in full.
  const sentence = r.sentence ? `, when the call fits "${r.sentence}"` : old?.sentence ? ", with no sentence" : "";
  return `${exists ? "Change" : "Add"} an integration rule that ${EFFECT_WORDS[r.then]} ${describeMatch(r)}${sentence}, for ${who}${r.enabled ? "" : " (turned off)"}`;
}
