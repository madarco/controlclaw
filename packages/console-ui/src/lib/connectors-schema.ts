import { z } from "zod";
import type {
  ConnectorAssignmentState,
  ConnectorAuthType,
  ConnectorChangeKind,
  ConnectorChangeStatus,
  ConnectorConnectionState,
} from "./connector-states";

/**
 * App integrations: the shapes the RPC takes and the views the console renders. The provider
 * catalog itself is in `connector-catalog.ts` — it is public data, pinned with the OpenConnector
 * version, and read from disk rather than asked of the firewall.
 */

/** OpenConnector provider ids: lower-case, digits and underscores. */
export const serviceSchema = z
  .string()
  .trim()
  .min(1)
  .max(61)
  .regex(/^[a-z0-9][a-z0-9_]*$/, "That isn’t a provider id");

const labelSchema = z.string().trim().max(80).optional();

/** One credential form field's value. Keys come from the provider's own descriptor. */
const fieldValues = z.record(
  z.string().regex(/^[A-Za-z0-9_]{1,64}$/),
  z.string().max(8192),
);

export const connectSchema = z.object({
  service: serviceSchema,
  authType: z.enum(["api_key", "custom_credential"]),
  label: labelSchema,
  /** `apiKey` for an API-key provider; the provider's own fields for a custom credential. */
  secrets: fieldValues,
  /** The non-secret fields of the same form (an instance URL, a region, an account id). */
  extra: fieldValues.optional().default({}),
  /** Agents to give it to straight away. */
  vmIds: z.array(z.string().min(1)).max(50).optional().default([]),
});
export type ConnectInput = z.infer<typeof connectSchema>;

export const replaceSchema = z.object({
  connectionId: z.string().min(1),
  secrets: fieldValues,
  extra: fieldValues.optional().default({}),
});
export type ReplaceInput = z.infer<typeof replaceSchema>;

export const oauthConnectSchema = z.object({
  service: serviceSchema,
  label: labelSchema,
  /**
   * Every client field the provider declares, as typed. `clientId` and `clientSecret` for most,
   * but 14 of the catalog's OAuth providers require more — a `tenant` (Outlook, Teams, OneDrive),
   * an `instanceUrl` (GitLab), a `subdomain` (Zendesk, Okta), a `developerToken` (Google Ads).
   * The server splits them by the provider's own descriptor, so the browser never decides which
   * of them is a secret.
   */
  clientFields: fieldValues,
  /** Provider-declared optional scope groups the person ticked. */
  authorizationOptionIds: z.array(z.string().min(1).max(120)).max(40).optional().default([]),
  vmIds: z.array(z.string().min(1)).max(50).optional().default([]),
});
export type OauthConnectInput = z.infer<typeof oauthConnectSchema>;

export const connectionIdSchema = z.object({ connectionId: z.string().min(1) });

export const assignSchema = z.object({
  connectionId: z.string().min(1),
  vmId: z.string().min(1),
  /** True to let the agent use it, false to take it away. */
  on: z.boolean(),
});
export type AssignInput = z.infer<typeof assignSchema>;

export const confirmConnectorChangeSchema = z.object({
  changeId: z.string().min(1),
  code: z
    .string()
    .trim()
    .transform((s) => s.replace(/\s+/g, ""))
    .pipe(z.string().regex(/^\d{6}$/, "The code is 6 digits")),
});

export const changeIdSchema = z.object({ changeId: z.string().min(1) });
export const vmIdSchema = z.object({ vmId: z.string().min(1) });

export const searchCatalogSchema = z.object({
  q: z.string().trim().max(80).optional().default(""),
  category: z.string().trim().max(60).optional().default(""),
  limit: z.number().int().min(1).max(60).optional().default(24),
});

export const setupSchema = z.object({ service: serviceSchema });

/** How long a queued change may wait for the firewall before the console calls it stuck. */
export const CONNECTOR_CHANGE_STUCK_MS = 2 * 60_000;
/** How long a person has to finish an OAuth sign-in at the provider. */
export const CONNECTOR_OAUTH_TTL_MS = 15 * 60_000;
/** How many run records the Activity tab of a connection shows. */
export const CONNECTOR_RUNS_LIMIT = 25;

// ---- views ----

export type ConnectorChangeView = {
  id: string;
  vmId: string | null;
  connectionId: string | null;
  service: string;
  kind: ConnectorChangeKind;
  summary: string;
  status: ConnectorChangeStatus;
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  /** While an OAuth sign-in is open: where to send the person. */
  authorizationUrl: string | null;
  error: string | null;
  createdAt: string;
  stuck: boolean;
};

export type ConnectorConnectionView = {
  id: string;
  service: string;
  /** The catalog's display name for `service`, resolved here so cards need no lookup. */
  serviceName: string;
  /** The app's home page from the catalog, for the colour of its logo tile. */
  home?: string;
  /** The catalog has a logo for it (`connectorIconUrl`). */
  icon?: boolean;
  authType: ConnectorAuthType;
  label: string | null;
  accountLabel: string | null;
  state: ConnectorConnectionState;
  runtimeState: string | null;
  lastError: string | null;
  /** Agents that may use it. */
  agents: Array<{ vmId: string; name: string; state: ConnectorAssignmentState; lastError: string | null }>;
  updatedAt: string;
};

export type ConnectorFirewallView = {
  state: "none" | "starting" | "active" | "inactive";
  reachable: boolean;
  /** False when the firewall box has no connector runtime (provisioned before it existed). */
  supported: boolean;
  /**
   * What to say when it is not supported, in place of the console's "update the firewall", with no
   * link to the Firewall page (the firewall's own panel: the connector is not running there).
   */
  note?: string;
};

export type ConnectorsView = {
  canManage: boolean;
  firewall: ConnectorFirewallView;
  connections: ConnectorConnectionView[];
  agents: Array<{ vmId: string; name: string; displayName: string | null; status: string; connections: number }>;
  pending: ConnectorChangeView | null;
  recent: ConnectorChangeView[];
  /** The callback URL a customer has to register in their own OAuth app. */
  oauthRedirectUri: string;
};

export type AgentConnectorsView = {
  vm: { id: string; name: string; displayName: string | null; status: string };
  canManage: boolean;
  firewall: ConnectorFirewallView;
  /** Every connection of the organization, with `assigned` saying which this agent holds. */
  connections: Array<ConnectorConnectionView & { assigned: boolean }>;
  pending: ConnectorChangeView | null;
  recent: ConnectorChangeView[];
};

/** One redacted run record from OpenConnector's audit log. Never an input or an output. */
export type ConnectorRunView = {
  id: string;
  service: string | null;
  actionId: string | null;
  caller: string | null;
  at: string | null;
  durationMs: number | null;
  ok: boolean;
  vmId: string | null;
  errorCode: string | null;
};

/** One credential field as the provider declares it (from `GET /v1/providers/:service/setup`). */
export type ConnectorFieldDescriptor = {
  key: string;
  label: string;
  inputType: string;
  required: boolean;
  secret: boolean;
  placeholder?: string;
  description?: string;
};

/**
 * How to register the app at the provider, shown above the credential form.
 *
 * OpenConnector's descriptor has `clientSetup: { docsUrl, steps }` on its OAuth entries, but
 * only 11 of the 1,542 providers fill it in and none of the ones people actually connect do.
 * So the same shape carries our own guides (`connector-guides.ts`), merged over the descriptor
 * at read time, with a few fields the upstream shape has no room for.
 */
export type ConnectorClientSetup = {
  /** The provider's own page for this. */
  docsUrl?: string;
  /**
   * Whose documentation `docsUrl` is and who the guide was written for, when that is not the app
   * on screen: one Google guide serves Gmail, Calendar, Drive, Sheets and Docs.
   */
  docsLabel?: string;
  /** Ordered steps, each one self-contained sentence. */
  steps: string[];
  /** Extra help for one field of the form, keyed by the descriptor's own field key. */
  help?: Record<string, string>;
  /** Which permissions to grant and why. */
  scopesNote?: string;
  /** Pictures, served from `public/connector-guides/<service>/`. */
  screenshots?: Array<{ src: string; alt: string }>;
  /** The two or three things that usually go wrong. */
  pitfalls?: string[];
  /**
   * Who wrote it. Optional only so the generated JSON — which carries the upstream two-field
   * shape — types as a descriptor; `applyConnectorGuides` always sets it.
   */
  source?: "provider" | "controlclaw";
};

export type ConnectorAuthDescriptor =
  | { type: "api_key"; fields: ConnectorFieldDescriptor[]; clientSetup?: ConnectorClientSetup }
  | { type: "custom_credential"; fields: ConnectorFieldDescriptor[]; clientSetup?: ConnectorClientSetup }
  | {
      type: "oauth2";
      clientFields: ConnectorFieldDescriptor[];
      scopes?: string[];
      authorizationOptions?: Array<{ id: string; label: string; description?: string; required?: boolean; defaultSelected?: boolean; risk?: string; requires?: string[] }>;
      clientSetup?: ConnectorClientSetup;
    }
  | { type: "no_auth" };

export type ConnectorSetupView = {
  service: string;
  serviceName: string;
  auth: ConnectorAuthDescriptor[];
  /** Null for a provider that does not offer OAuth at all. */
  oauthClient: { configured: boolean; expectedRedirectUri: string | null; missingFields: string[] } | null;
};

/** Every field of a descriptor, whichever kind it is: an OAuth client form is a form too. */
export function fieldsOf(auth: ConnectorAuthDescriptor): ConnectorFieldDescriptor[] {
  if (auth.type === "api_key" || auth.type === "custom_credential") return auth.fields;
  if (auth.type === "oauth2") return auth.clientFields;
  return [];
}

/** The secret fields of a descriptor, which the console sends in the encrypted part. */
export function secretKeysOf(auth: ConnectorAuthDescriptor): string[] {
  return fieldsOf(auth)
    .filter((f) => f.secret)
    .map((f) => f.key);
}

export function plainKeysOf(auth: ConnectorAuthDescriptor): string[] {
  return fieldsOf(auth)
    .filter((f) => !f.secret)
    .map((f) => f.key);
}

/** A provider in the pinned OpenConnector catalog (`connector-catalog.json` in the console). */
export type CatalogProvider = {
  service: string;
  name: string;
  categories: string[];
  authTypes: string[];
  /** How many actions the runtime can run for it. */
  actions: number;
  desc?: string;
  home?: string;
  /** A logo is bundled for it (`packages/console-ui/connector-icons/`, see `connectorIconUrl`). */
  icon?: boolean;
};

/** A catalog entry as the picker sees it: the pinned row plus whether we wrote a setup guide. */
export type CatalogProviderView = CatalogProvider & { guide: boolean };
