import { z } from "zod";
import { APP_EFFECTS, APP_OPERATIONS, appMatch, appRuleName, appRulesChange, isMcpService, serviceId } from "@controlclaw/console-ui/lib/agent/apps-rules-schema";

export {
  APP_EFFECTS,
  APP_OPERATIONS,
  APP_RULES_MAX,
  APP_RULE_TOOLS_MAX,
  PROXY_METHODS,
  SEEDED_APP_RULE,
  appRule,
  appRulesChange,
  appRulesSnapshot,
  describeMatch,
  isMcpService,
  kindFromAnnotations,
  RULE_SENTENCE_MAX,
  toolPattern,
  type AppEffect,
  type AppMatch,
  type AppOperation,
  type AppRule,
  type AppRulesChange,
  type AppRulesSnapshot,
} from "@controlclaw/console-ui/lib/agent/apps-rules-schema";

export const appRulesChangeInput = z.object({ change: appRulesChange });
export const appRulesChangeId = z.object({ changeId: z.string().min(1).max(100) });
export const appRulesConfirm = appRulesChangeId.extend({ code: z.string().regex(/^\d{6}$/) });
export const appActionsInput = z.object({ service: serviceId });

/** One agent's own rule, as an agent may ask for it over its MCP: appended last, for that agent only. */
export const appRuleForAgentInput = z.object({
  vmId: z.string().min(1).max(100),
  name: appRuleName,
  service: serviceId.nullable().describe("The integration: an app (`github`, `notion`) or an MCP server as mcp:<host> (`mcp:mcp.deepwiki.com`); null for any"),
  connectionId: z.string().min(1).max(100).nullable().default(null).describe("One connection of that app; null for any"),
  match: appMatch.describe("What it matches: an app's actions, an MCP server's tools, the kind of action or tool (read, write, destructive), direct API calls by method and path, or every call"),
  then: z.enum(APP_EFFECTS).describe("allow, ask (a person approves each call) or block"),
});
export const appRuleRemoveInput = z.object({ vmId: z.string().min(1).max(100), ruleId: z.string().min(1).max(64) });

/** One action of an app, for the rule dialog's picker: its id and what it does. */
export type AppActionOption = { id: string; name: string; operation: "read" | "write" | "destructive" };

/** One tool of an MCP server, for the rule dialog's picker: what the server or the AI says it does. */
export type McpToolOption = { name: string; description: string | null; kind: "read" | "write" | "destructive" | null; kindBy: "annotation" | "ai" | null };

/**
 * An integration, for the rule dialog and the table: an app the organization connected (its name,
 * colour and connections), or an MCP server (`service` is `mcp:<host>`), with its tools and the agents
 * that listed them.
 */
export type AppOption = {
  service: string;
  name: string;
  home: string | null;
  /** A logo is bundled for it. */
  icon?: boolean;
  connections: Array<{ id: string; label: string }>;
  mcp?: { host: string; managed: string | null; tools: McpToolOption[]; agents: string[] };
};

/** A new rule's id: from its name, and unique (`crypto.getRandomValues`, in the browser and on the server). */
export function appRuleId(name: string): string {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "rule";
  return `${slug}-${Array.from(crypto.getRandomValues(new Uint8Array(4)), (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

/** How a rule's integration is named where no app or server name is known: an MCP server by its host. */
export function integrationLabel(service: string): string {
  return isMcpService(service) ? `${service.slice(4)} (MCP server)` : service;
}

/**
 * One server of the firewall's MCP catalog (`mcpcatalog.read`), read field by field: a firewall of
 * another version may send more, less, or something else, and a bad tool is dropped, not shown.
 */
const catalogTool = z.object({
  name: z.string().min(1).max(128),
  description: z.string().max(500).nullable().catch(null),
  kind: z.enum(APP_OPERATIONS).nullable().catch(null),
  kindBy: z.enum(["annotation", "ai"]).nullable().catch(null),
});
export const mcpCatalogServer = z.object({
  host: z.string().min(1).max(260),
  managed: z.string().max(100).nullable().catch(null),
  tools: z
    .array(z.unknown())
    .catch([])
    .transform((list) => list.slice(0, 500).flatMap((t) => {
      const r = catalogTool.safeParse(t);
      return r.success ? [r.data] : [];
    })),
  agents: z.record(z.string(), z.unknown()).catch({}),
});
