import { z } from "zod";
import { COUNTRY_CODE_RE } from "./countries";

/**
 * The residential exit, console side (apps/saas/docs/features/residential-exit.md). The control
 * plane never holds the provider password: it goes into one firewall command's encrypted half and
 * lives on the firewall from then on. Everything here is what the console shows.
 */

export const exitSchemeSchema = z.enum(["http", "https", "socks5"]);
export type ExitScheme = z.infer<typeof exitSchemeSchema>;

export const exitChangeKindSchema = z.enum(["add", "replace", "remove", "settings"]);
export type ExitChangeKind = z.infer<typeof exitChangeKindSchema>;

/** 5 GB. On for a new account, and editable: a surprise invoice is worse than a stop. */
export const DEFAULT_CAP_BYTES = 5 * 1024 ** 3;

/**
 * An ISO 3166-1 alpha-2 country, stored and sent uppercase. An empty string is how a form says
 * "any country", and it arrives as null so it is never confused with "say nothing about it".
 *
 * Nothing here checks the country against the provider: a provider that has no addresses in a
 * country refuses the connection and the firewall reports its words (see the feature doc). A
 * table of who sells what would be wrong within a month.
 */
export const exitCountrySchema = z
  .string()
  .trim()
  .transform((v) => v.toUpperCase())
  .refine((v) => v === "" || COUNTRY_CODE_RE.test(v), "Enter a two-letter country code, or leave it empty for any country.")
  .transform((v) => (v === "" ? null : v));

export const connectExitInputSchema = z.object({
  provider: z.string().min(1).max(40),
  scheme: exitSchemeSchema.default("http"),
  host: z.string().min(1).max(253),
  port: z.number().int().min(1).max(65535),
  /**
   * Empty for a provider whose templates never render `{username}` — Apify puts the group and the
   * country there and identifies the account by the password alone, so asking for one made a
   * customer invent a value the template then threw away.
   */
  username: z.string().max(200).default(""),
  password: z.string().min(1).max(400),
  usernameTemplate: z.string().min(1).max(200),
  passwordTemplate: z.string().min(1).max(200),
  sticky: z.boolean().default(false),
  /** Null removes the ceiling; omitted keeps whatever is set. */
  capBytes: z.number().int().min(0).nullish(),
  /** Null is "any country". Absent means the same on a first connect; there is nothing to keep. */
  country: exitCountrySchema.nullish(),
});

export const updateExitSettingsInputSchema = z.object({
  sticky: z.boolean().optional(),
  capBytes: z.number().int().min(0).nullish(),
  /**
   * Tri-state, like the cap: absent leaves the country alone, null makes it "any country", a code
   * sets it. Collapsing absent and null would have a sticky toggle silently move every
   * residential rule in the org to a different country.
   */
  country: exitCountrySchema.nullish(),
});

export const confirmExitInputSchema = z.object({ changeId: z.string(), code: z.string().min(1).max(12) });
export const cancelExitInputSchema = z.object({ changeId: z.string() });
export const getExitChangeInputSchema = z.object({ changeId: z.string().optional() });

export interface ExitCheckView {
  at: string;
  ok: boolean;
  exitIp: string | null;
  /** Where that address actually is, when the echo service said. Null on an older firewall. */
  exitCountry: string | null;
  error: string | null;
}

export interface ExitView {
  configured: boolean;
  provider: string;
  providerName: string;
  scheme: ExitScheme;
  host: string;
  port: number;
  usernameHint: string | null;
  sticky: boolean;
  /** The org default exit country, or null for "wherever the provider puts us". */
  country: string | null;
  /** False when this provider's templates have no country placeholder to render one into. */
  supportsCountry: boolean;
  state: string;
  lastError: string | null;
  capBytes: number | null;
  check: ExitCheckView | null;
  usage: { month: string | null; bytesIn: number; bytesOut: number };
  /** How many enabled rules send their traffic through it — what "Remove" would break. */
  ruleCount: number;
  canManage: boolean;
  /** False when the org has no firewall box yet, so the card can say why it is not offering. */
  hasFirewall: boolean;
}

export interface ExitChangeView {
  id: string;
  kind: ExitChangeKind;
  summary: string;
  /** The states `useFirewallChange` follows; this family never uses the login/authorization ones. */
  status: "queued" | "awaiting_code" | "applied" | "failed" | "expired" | "cancelled";
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  error: string | null;
  createdAt: string;
  /** The change applied with no code, because the org has nobody approved on any channel yet. */
  tofu: boolean;
  /** The console gave up waiting; the firewall never answered. */
  stuck: boolean;
}

export function bytesLabel(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
