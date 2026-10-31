import type { Schemas } from "@controlclaw/fw-api";
import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import type { RulesChangeRpc } from "@controlclaw/console-ui/firewall/rules";
import { mcpCatalogServer, type AppOption, type AppRulesSnapshot } from "@controlclaw/console-ui/lib/app-rules-schema";
import type { ContentRulesSnapshot } from "@controlclaw/console-ui/lib/content-rules-schema";
import type { EmailRulesSnapshot } from "@controlclaw/console-ui/lib/email-rules-schema";
import { fw } from "./client";
import { refusalText } from "./changes";

export { refusalText };

type CommandAnswer = Schemas["CommandAnswer"];

/**
 * The console's rules change: propose, follow it, confirm with a code. The panel's API applies a
 * change at once and answers with the new rules (`data`), so `status` hands back that answer the
 * first time it is asked, and the view never shows a code. A refusal throws from `change`.
 */
export function appliedAtOnce<C, S>(send: (change: C) => Promise<CommandAnswer>): RulesChangeRpc<C, S> {
  const answers = new Map<string, CommandAnswer>();
  let n = 0;
  return {
    async change({ change }) {
      let ans: CommandAnswer;
      try {
        ans = await send(change);
      } catch (e) {
        throw new Error(refusalText(e), { cause: e });
      }
      // A change still waiting for a code has no way to be confirmed here: the API always confirms.
      if (!ans.ok || ans.status === "awaiting_code") throw new Error(ans.message ?? "The firewall did not apply the change");
      const changeId = `local-${++n}`;
      answers.set(changeId, ans);
      return { changeId };
    },
    async status({ changeId }) {
      const ans = answers.get(changeId);
      answers.delete(changeId);
      if (!ans) return { status: "failed", ok: false, message: "This change is not known any more", attemptsLeft: null, sentVia: null, snapshot: null };
      return { status: ans.status || "applied", ok: true, message: null, attemptsLeft: null, sentVia: null, snapshot: (ans.data ?? null) as S | null };
    },
    confirm: () => Promise.reject(new Error("No code is needed on this firewall")),
    cancel: ({ changeId }) => Promise.resolve({ changeId }),
  };
}

export const contentRules: ConsoleApi["contentRules"] = {
  ...appliedAtOnce((change) => fw.post("/api/content-rules/change", { body: { change } })),
  get: async () => (await fw.get("/api/content-rules")) as ContentRulesSnapshot & { aiOn: boolean },
  try: async (input) => (await fw.post("/api/content-rules/try", { body: input })) as Awaited<ReturnType<ConsoleApi["contentRules"]["try"]>>,
  open: async () => {
    const res = (await fw.post("/api/open", { body: { page: "content-rules" } })) as { url?: string };
    if (!res.url) throw new Error("The firewall gave no link");
    return { url: res.url };
  },
};

/** The firewall's MCP servers as integrations for the app rule dialog, as the console builds them. */
export function toMcpOptions(res: unknown): AppOption[] {
  const servers = (res as { servers?: unknown[] } | null)?.servers ?? [];
  return servers.flatMap((s) => {
    const r = mcpCatalogServer.safeParse(s);
    if (!r.success) return [];
    const m = r.data;
    return [{ service: `mcp:${m.host}`, name: m.host, home: null, connections: [], mcp: { host: m.host, managed: m.managed, tools: m.tools, agents: Object.keys(m.agents) } }];
  });
}

export const appRules: ConsoleApi["appRules"] = {
  ...appliedAtOnce((change) => fw.post("/api/app-rules/change", { body: { change } })),
  get: async () => (await fw.get("/api/app-rules")) as AppRulesSnapshot,
  // The console reads a catalog of each app's actions; the firewall has none, and the dialog then
  // offers no action picker.
  actions: async () => [],
  mcpServers: async () => toMcpOptions(await fw.get("/api/app-rules/mcp")),
};

export const emailRules: ConsoleApi["emailRules"] = {
  ...appliedAtOnce((change) => fw.post("/api/email-rules/change", { body: { change } })),
  get: async () => (await fw.get("/api/email-rules")) as EmailRulesSnapshot,
};
