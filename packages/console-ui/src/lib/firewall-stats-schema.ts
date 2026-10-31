import { z } from "zod";
import type { TrafficPoint, TrafficRange } from "./firewall-stats";

/** The Firewall page's Overview tab (docs/plans/firewall-overview-charts.md). */

export const trafficRangeSchema = z.enum(["1h", "24h", "7d"]);

/** An IANA zone from the browser, so "today" starts at the reader's midnight. */
const timeZone = z.string().trim().max(64).optional();

export const firewallOverviewInputSchema = z.object({
  range: trafficRangeSchema.optional().default("24h"),
  timeZone,
  /** False for the page's own refresh: the live list polls by itself. */
  withLive: z.boolean().optional().default(true),
});
export const firewallTrafficInputSchema = z.object({ range: trafficRangeSchema });
export const firewallLiveInputSchema = z.object({
  /** `createdAt` of the newest row the list holds; omitted for the first read. */
  after: z.string().datetime().optional(),
});

export type CardSeries = {
  /** Today so far, and yesterday up to the same time, for the change badge. */
  today: number;
  yesterday: number;
  /** One value per hour, oldest first, matching `FirewallOverviewView.hours`. */
  series: number[];
};

export type LiveRequest = {
  id: string;
  /** When it reached the console, the list's cursor. */
  createdAt: string;
  occurredAt: string;
  method: string | null;
  host: string;
  agent: string | null;
  verdict: "allowed" | "asked" | "blocked";
  durationMs: number | null;
  /** A tunnel or a request over 25 s: a long-poll or a websocket, shown folded. */
  long: boolean;
};

export type TopHost = { host: string; total: number; blocked: number };

export type AgentTraffic = {
  /** Null for traffic not tied to an agent (the firewall's own), shown as "Firewall". */
  vmId: string | null;
  name: string;
  running: boolean;
  /** Traffic of an agent deleted since: listed, not linked. */
  deleted: boolean;
  /** The organization's brain box (vm role "gbrain"), shown as "Brain" and linked to the Brain page. */
  brain?: boolean;
  total: number;
  blocked: number;
  /** Requests per hour over the last 24 hours. */
  hourly: number[];
};

export type AiFinding = {
  id: string;
  severity: "low" | "medium" | "high";
  /** The category label and the hosts, as the Activity page has it. */
  title: string;
  explanation: string | null;
  agent: string | null;
  at: string;
};

export type ShieldCounts = {
  /** Enabled Websites rules (Internet access). */
  siteRules: number;
  /** Enabled Auto approve rules, and how many of them ask a person. */
  securityRules: number;
  securityAsk: number;
  /** Enabled Messages rules and Email rule entries, as the firewall last told them; null when it never did. */
  messageRules: number | null;
  emailRules: number | null;
  channelTokens: number;
  aiKeys: number;
  webhooks: number;
  /** "starting" is switched on but not running (yet, or it failed to start). */
  teamChat: "on" | "off" | "starting";
};

export type FirewallOverviewView = {
  /** The firewall is up and reporting; off, the numbers are zeros and the page says so. */
  running: boolean;
  generatedAt: string;
  /** ISO hour starts of the cards' sparklines. */
  hours: string[];
  /** Requests in the last full minute; the series is the average per minute of each hour. */
  perMinute: { value: number } & CardSeries;
  blocked: CardSeries;
  /** Median ms of allowed requests, leaving out tunnels and requests over 25 s. Null with none. */
  response: { value: number | null; today: number | null; yesterday: number | null; series: number[] };
  month: { count: number; resetsAt: string };
  traffic: { range: TrafficRange; points: TrafficPoint[] };
  live: LiveRequest[];
  topHosts: TopHost[];
  byAgent: AgentTraffic[];
  ai: { enabled: boolean; findings: AiFinding[] };
  shields: ShieldCounts;
};
