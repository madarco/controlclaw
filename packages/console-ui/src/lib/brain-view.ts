/**
 * What the shared brain views read (docs/plans/gbrain.md §5, docs/plans/standalone-brain.md part C).
 * The console's `brain.schema.ts` re-exports them; the firewall panel builds them from its own API.
 */

/** Read only, or read and write. */
export type BrainScopeId = "read" | "read_write";

export const BRAIN_SCOPE_LABEL: Record<BrainScopeId, string> = { read_write: "Read and write", read: "Read only" };

/** A connection on its way: waiting for the firewall, or for a code. */
export type BrainChangeView = {
  id: string;
  /** The agent, or null for an outside app's change (`clientId`). */
  agentVmId: string | null;
  clientId: string | null;
  kind: "connect" | "rescope" | "client_connect" | "client_change";
  scope: BrainScopeId;
  summary: string;
  status: "queued" | "awaiting_code" | "applied" | "failed" | "expired" | "cancelled";
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  error: string | null;
  createdAt: string;
  stuck: boolean;
};

/** One agent, as the connected-agents card lists it. */
export type BrainAgentView = {
  vmId: string;
  name: string;
  /** The agent's own status; it has to be running to be connected (its config is written live). */
  running: boolean;
  /** Created without a firewall: nothing can confirm the connection, so it cannot have one. */
  secured: boolean;
  /**
   * `autoCapture` is the owner's switch; it acts only on a Read and write connection (a read-only
   * agent cannot save).
   */
  connection: null | { scope: BrainScopeId; since: string; autoCapture: boolean };
  /** Kept out of the brain for now (the emergency stop, or a lock): its calls are refused. Left out where nobody says. */
  stopped?: boolean;
};

/** A model the brain's own calls can run on. */
export type BrainModelChoice = {
  id: string;
  label: string;
  /** One line under the name. */
  blurb?: string;
  /** What it costs, on the right ("about 4¢ a night"). Left out: nothing shown. */
  cost?: string;
};
