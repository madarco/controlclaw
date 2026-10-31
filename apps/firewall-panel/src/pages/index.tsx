import type { ComponentType, JSX } from "react";
import { Activity, Bot, Gauge, Globe, KeyRound, MessageSquare, Plug, Settings, ShieldCheck, Hand } from "lucide-react";
import { AgentsPage } from "./Agents";
import { SettingsPage } from "./Settings";
import { OverviewPage } from "./Overview";
import { InternetPage } from "./Internet";
import { RequestsPage } from "./Requests";
import { ActivityPage } from "./Activity";
import { SecurityPage } from "./Security";
import { ChannelsPage } from "./Channels";
import { IntegrationsPage } from "./Integrations";
import { OauthCallbackPage } from "./OauthCallback";
import { LoginsPage } from "./Logins";
import { GooglePage } from "./Google";
import { AgentMailPage } from "./AgentMail";

export interface PanelPage {
  path: string;
  title: string;
  icon: ComponentType<{ className?: string }>;
  component: () => JSX.Element;
}

/** The V1 pages (plan §7), in the sidebar's order. */
export const NAV: PanelPage[] = [
  { path: "/", title: "Overview", icon: Gauge, component: OverviewPage },
  { path: "/agents", title: "Agents", icon: Bot, component: AgentsPage },
  { path: "/internet", title: "Internet access", icon: Globe, component: InternetPage },
  { path: "/security", title: "Security rules", icon: ShieldCheck, component: SecurityPage },
  { path: "/channels", title: "Channels", icon: MessageSquare, component: ChannelsPage },
  { path: "/integrations", title: "Integrations", icon: Plug, component: IntegrationsPage },
  { path: "/logins", title: "Website logins", icon: KeyRound, component: LoginsPage },
  { path: "/requests", title: "Permission requests", icon: Hand, component: RequestsPage },
  { path: "/activity", title: "Activity", icon: Activity, component: ActivityPage },
  { path: "/settings", title: "Settings", icon: Settings, component: SettingsPage },
];

/** Pages with no place in the sidebar: where providers send the person back after a sign-in. */
export const HIDDEN: PanelPage[] = [
  { path: "/oauth/callback", title: "Signing in", icon: Plug, component: OauthCallbackPage },
  { path: "/integrations/google", title: "Google", icon: Plug, component: GooglePage },
  { path: "/integrations/agentmail", title: "AgentMail", icon: Plug, component: AgentMailPage },
];
