"use client";

import { createContext, useContext, type ReactNode } from "react";
import type { z } from "zod";
import type { EgressRuleSource } from "../firewall/egress/useEgressRules";
import type { FirewallChangeRpc } from "../firewall/change/useFirewallChange";
import type { RulesChangeRpc } from "../firewall/rules/useRulesChange";
import type { AppActionOption, AppOption, AppRulesChange, AppRulesSnapshot } from "./app-rules-schema";
import type { FirewallRules } from "./rule-overview";
import type { AgentChannelChangeView, AgentChannelsView, WhatsappLoginInput } from "./channels-schema";
import type { CodeTapView } from "./code-tap-schema";
import type { ConnectorChangeView, ConnectorSetupView, ConnectorsView, connectSchema, oauthConnectSchema, replaceSchema, searchCatalogSchema } from "./connectors-schema";
import type { ContentChange, ContentRulesSnapshot } from "./content-rules-schema";
import type { ContentTryInput, ContentTryResult } from "./content-rules-schema";
import type { EgressAiView, UpdateEgressAiInstructionsInput, UpdateEgressAiSettingsInput } from "./egress-ai-schema";
import type { EmailChange, EmailRulesSnapshot } from "./email-rules-schema";
import type { ExitChangeView, ExitCheckView, ExitView, connectExitInputSchema, updateExitSettingsInputSchema } from "./exit-schema";
import type { FirewallOverviewView, LiveRequest, firewallOverviewInputSchema } from "./firewall-stats-schema";
import type { FirewallAction, FirewallUpdateChangeView, FirewallUpdateView, FirewallView, ServerRecovery } from "./firewall-view";
import type { TrafficRange } from "./firewall-stats";
import type { AddMcpServerInput, McpServerChangeView, McpServersView } from "./mcp-servers-schema";
import type { RecoveryChallengeView } from "./recovery-confirm-schema";
import type { CatalogResult } from "../firewall/integrations/CatalogBrowser";
import type { RuleActivityItem, RuleMetricRange, RuleOverviewItem } from "./rule-metrics";
import type { SecurityRuleListItem, createSecurityRuleInputSchema, updateSecurityRuleInputSchema } from "./security-schema";
import type { AutoApproveChange, AutoApproveSnapshot } from "./auto-approve-schema";

/**
 * What the shared views read and change, by area. The console passes its oRPC client (whose
 * procedures have these names and shapes); the firewall panel passes a client of its own REST API.
 * Every call returns what the view draws next, or throws with a message a person can read.
 *
 * A call that starts a change the firewall confirms with a code answers with the change, or with
 * just its id; the view then follows it with the area's `getChange`.
 */
type Started<T> = Promise<{ changeId: string } | T>;
type ChangeId = { changeId: string };

export interface ConsoleApi {
  firewall: {
    get(): Promise<FirewallView>;
    command(input: { action: FirewallAction }): Promise<{ commandId: string }>;
    recover(): Promise<{ action: ServerRecovery }>;
    hardReboot(): Promise<unknown>;
    tearDown(): Promise<unknown>;
    codeTap(input: ChangeId): Promise<CodeTapView | null>;
    recoveryChallenge(input: ChangeId): Promise<RecoveryChallengeView | null>;
  };
  firewallUpdate: FirewallChangeRpc<FirewallUpdateChangeView> & {
    get(): Promise<FirewallUpdateView>;
    start(): Started<FirewallUpdateChangeView>;
  };
  firewallStats: {
    overview(input: z.input<typeof firewallOverviewInputSchema>): Promise<FirewallOverviewView>;
    traffic(input: { range: TrafficRange }): Promise<FirewallOverviewView["traffic"]>;
    live(input: { after?: string }): Promise<LiveRequest[]>;
  };
  /** Per-rule counts (Most used rules, the Security rules counts). Left out where the control plane keeps none. */
  ruleMetrics?: {
    overview(input: { range: "24h" | "7d" }): Promise<{ items: RuleOverviewItem[]; generatedAt: string }>;
    list(input: { range: RuleMetricRange; agentId?: string }): Promise<{ items: RuleActivityItem[]; generatedAt: string }>;
    firewallRules(input: { messages: boolean }): Promise<Partial<FirewallRules>>;
  };
  egress: {
    getEgressAiSettings(): Promise<EgressAiView>;
    updateEgressAiSettings(input: UpdateEgressAiSettingsInput): Promise<EgressAiView>;
    updateEgressAiInstructions(input: UpdateEgressAiInstructionsInput): Promise<EgressAiView>;
    scanEgressNow(): Promise<unknown>;
    openAiReviewHistory(input: { vmId?: string | null }): Promise<{ url: string }>;
  };
  /** The site rules (Internet access, Security rules → Websites). */
  egressRules: EgressRuleSource;
  exit: {
    getExit(input: Record<string, never>): Promise<ExitView>;
    connectExit(input: z.input<typeof connectExitInputSchema>): Started<ExitChangeView>;
    updateExitSettings(input: z.input<typeof updateExitSettingsInputSchema>): Started<ExitChangeView>;
    removeExit(input: Record<string, never>): Started<ExitChangeView>;
    checkExitNow(input: Record<string, never>): Promise<ExitCheckView | unknown>;
    getExitChange(input: ChangeId): Promise<ExitChangeView | null>;
    confirmExit(input: ChangeId & { code: string }): Promise<unknown>;
    cancelExit(input: ChangeId): Promise<unknown>;
  };
  /** The console's own residential exit (ControlClaw's relay). Left out where there is none. */
  exitAllowance?: {
    connect(input: { sticky: boolean }): Started<ExitChangeView>;
  };
  channels: FirewallChangeRpc<AgentChannelChangeView> & {
    listAgent(input: { vmId: string }): Promise<AgentChannelsView>;
    add(input: { type: "telegram"; botToken: string; label?: string; vmId?: string } | { type: "slack"; botToken: string; appToken: string; label?: string; vmId?: string }): Started<AgentChannelChangeView>;
    replaceSecret(input: { connectionId: string; botToken: string; appToken?: string; label?: string }): Started<AgentChannelChangeView>;
    assign(input: { connectionId: string; vmId: string }): Started<AgentChannelChangeView>;
    unassign(input: { connectionId: string }): Started<AgentChannelChangeView>;
    approvePairing(input: { connectionId: string; code: string; senderId: string; label?: string }): Started<AgentChannelChangeView>;
    whatsappLogin(input: WhatsappLoginInput): Started<AgentChannelChangeView>;
  };
  vm: {
    /** Opens the agent's own WhatsApp page, where the QR code is. */
    openAgentWhatsapp(input: { id: string }): Promise<{ url: string }>;
  };
  integrations: FirewallChangeRpc<ConnectorChangeView> & {
    list(): Promise<ConnectorsView>;
    refresh(): Promise<unknown>;
    search(input: z.input<typeof searchCatalogSchema>): Promise<CatalogResult>;
    getSetup(input: { service: string }): Promise<ConnectorSetupView>;
    connect(input: z.input<typeof connectSchema>): Started<ConnectorChangeView>;
    oauthConnect(input: z.input<typeof oauthConnectSchema>): Started<ConnectorChangeView>;
    oauthReconnect(input: { connectionId: string }): Started<ConnectorChangeView>;
    replace(input: z.input<typeof replaceSchema>): Started<ConnectorChangeView>;
    remove(input: { connectionId: string }): Started<ConnectorChangeView>;
    assign(input: { connectionId: string; vmId: string; on: boolean }): Started<ConnectorChangeView>;
  };
  mcpServers: FirewallChangeRpc<McpServerChangeView> & {
    list(): Promise<McpServersView>;
    read(): Promise<unknown>;
    add(input: AddMcpServerInput): Started<McpServerChangeView>;
    replace(input: { serverId: string; headerValue: string }): Started<McpServerChangeView>;
    reconnect(input: { serverId: string }): Started<McpServerChangeView>;
    remove(input: { serverId: string }): Started<McpServerChangeView>;
    assign(input: { serverId: string; vmId: string; on: boolean }): Started<McpServerChangeView>;
    refreshTools(input: { serverId: string }): Promise<unknown>;
  };
  /** Auto approve rules: what the firewall answers an agent's permission request with. Left out where the control plane has none (the Auto approve tab is not shown). */
  security?: {
    createSecurityRule(input: z.input<typeof createSecurityRuleInputSchema>): Promise<SecurityRuleListItem>;
    updateSecurityRule(input: z.input<typeof updateSecurityRuleInputSchema>): Promise<SecurityRuleListItem>;
    deleteSecurityRule(input: { id: string }): Promise<unknown>;
    cycleSecurityRuleEffect(input: { id: string }): Promise<SecurityRuleListItem>;
  };
  /**
   * Auto approve rules on a firewall that keeps them: read from it and changed like the Integrations
   * rules (a change that lets more through waits for its code). Left out where nothing keeps them there.
   */
  autoApprove?: RulesChangeRpc<AutoApproveChange, AutoApproveSnapshot> & {
    get(): Promise<AutoApproveSnapshot>;
    /** A change waiting for its code that was started elsewhere (a template's step), if any. */
    waiting?(): Promise<{ changeId: string; sentVia: string | null } | null>;
  };
  contentRules: RulesChangeRpc<ContentChange, ContentRulesSnapshot> & {
    /** The rules and whether the AI check is on. */
    get(): Promise<ContentRulesSnapshot & { aiOn: boolean }>;
    try(input: ContentTryInput): Promise<ContentTryResult>;
    /** Opens the firewall's record of what the rules caught. */
    open(): Promise<{ url: string }>;
  };
  appRules: RulesChangeRpc<AppRulesChange, AppRulesSnapshot> & {
    get(): Promise<AppRulesSnapshot>;
    actions(input: { service: string }): Promise<AppActionOption[]>;
    mcpServers(): Promise<AppOption[]>;
  };
  emailRules: RulesChangeRpc<EmailChange, EmailRulesSnapshot> & {
    get(): Promise<EmailRulesSnapshot>;
  };
}

const ApiContext = createContext<ConsoleApi | null>(null);

/**
 * `api` must be the same object from one render to the next (a module constant, or memoised): the
 * views list it in their effects, and a new object each render would refetch and restart their polls.
 */
export function ApiProvider({ api, children }: { api: ConsoleApi; children: ReactNode }) {
  return <ApiContext.Provider value={api}>{children}</ApiContext.Provider>;
}

export function useApi(): ConsoleApi {
  const api = useContext(ApiContext);
  if (!api) throw new Error("useApi: no ApiProvider above this view");
  return api;
}

/**
 * The same, or null where no app passed one: the firewall's own pages (the Doctor start page)
 * render the code dialog with loaders of their own and nothing else.
 */
export function useOptionalApi(): ConsoleApi | null {
  return useContext(ApiContext);
}
