import type { ConsoleRoutes } from "@controlclaw/console-ui/lib/routes";

/**
 * Where the shared views link to in the panel. A console page the panel does not have (team chat,
 * backups, webhooks) goes to the nearest one it has.
 */
export const PANEL_ROUTES: ConsoleRoutes = {
  activity: "/activity",
  internet: "/internet",
  security: "/security",
  emailRules: "/security",
  channels: "/channels",
  aiKeys: "/settings#ai-models",
  webhooks: "/internet",
  teamChat: "/channels",
  backups: "/settings",
  brain: "/agents",
  agent: () => "/agents",
  firewall: "/",
  firewallLogs: "/activity",
  aiFirewall: "/internet#ai-firewall",
  aiReview: "/internet#ai-review",
  agentMailIntegration: "/integrations/agentmail",
  googleIntegration: "/integrations/google",
  agentIntegrations: () => "/integrations",
  rule: () => "/security",
  newRule: () => "/security",
};
