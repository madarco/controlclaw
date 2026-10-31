import { fw } from "./client";

/** `GET /api/agents` (cc-local `api/panel.rs`): untyped in the OpenAPI document, so typed here. */
export interface AgentRow {
  vm_id: string;
  role: string;
  name: string;
  private_ip: string | null;
  hostname?: string | null;
}

let inFlight: Promise<AgentRow[]> | null = null;

/** The agents; calls made while one read is on its way share it (a page reads several areas at once). */
export function listAgents(): Promise<AgentRow[]> {
  inFlight ??= (async () => {
    try {
      const res = (await fw.get("/api/agents")) as { agents?: AgentRow[] } | null;
      return res?.agents ?? [];
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}

export const AGENTS_KEY = ["agents"] as const;
