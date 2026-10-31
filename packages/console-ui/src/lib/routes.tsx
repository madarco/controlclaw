"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { OverviewHrefs } from "../firewall/overview/OverviewCards";
import type { RuleActivityItem } from "./rule-metrics";
import type { RuleType } from "./rule-types";

/**
 * Where the shared views link to: the console's routes, or the firewall panel's own. The app
 * passes them to `RoutesProvider` once at the root, next to `LinkProvider`.
 */
export interface ConsoleRoutes extends OverviewHrefs {
  firewall: string;
  firewallLogs: string;
  /** The AI Firewall settings on Security rules. */
  aiFirewall: string;
  /** The page where an organization's AgentMail and Google mailboxes are set up. */
  agentMailIntegration: string;
  googleIntegration: string;
  /** An agent's own integrations. */
  agentIntegrations: (vmId: string) => string;
  /** A rule on Security rules, or its tab. */
  rule: (item: Pick<RuleActivityItem, "type" | "ruleId" | "deleted">) => string;
  /** Security rules opened on a type's add dialog. */
  newRule: (type: RuleType) => string;
}

const RoutesContext = createContext<ConsoleRoutes | null>(null);

export function RoutesProvider({ routes, children }: { routes: ConsoleRoutes; children: ReactNode }) {
  return <RoutesContext.Provider value={routes}>{children}</RoutesContext.Provider>;
}

export function useRoutes(): ConsoleRoutes {
  const routes = useContext(RoutesContext);
  if (!routes) throw new Error("useRoutes: no RoutesProvider above this view");
  return routes;
}
