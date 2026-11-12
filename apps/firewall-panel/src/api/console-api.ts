import type { ConsoleApi } from "@controlclaw/console-ui/lib/api";
import { egress, egressRules } from "./egress";
import { channels } from "./channels";
import { exit } from "./exit";
import { integrations, mcpServers } from "./integrations";
import { appRules, autoApprove, contentRules, emailRules } from "./rules";
import { firewallStats } from "./stats";

/**
 * The `ConsoleApi` the shared views read, on this firewall's REST API. An area whose API the
 * firewall does not have yet answers every call with a readable refusal; its page says "coming
 * soon", so a view never makes one. Left out: `security` (the Auto approve rules are on the
 * firewall: `autoApprove`), and `ruleMetrics`, which only Security rules gets (`pages/Security.tsx`):
 * the firewall counts the Auto approve rules only, so the Overview leaves its rule cards out.
 */
function notYet<T extends object>(area: string): T {
  return new Proxy({} as T, {
    get: (_, name) => () => Promise.reject(new Error(`This firewall does not have ${area} yet (${String(name)})`)),
  });
}

export const panelApi: ConsoleApi = {
  firewall: notYet("firewall controls"),
  firewallUpdate: notYet("updates"),
  firewallStats,
  egress,
  egressRules,
  exit,
  channels,
  vm: notYet("agent pages"),
  integrations,
  mcpServers,
  contentRules,
  appRules,
  emailRules,
  autoApprove,
};
