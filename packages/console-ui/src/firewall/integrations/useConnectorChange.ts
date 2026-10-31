"use client";

import { useApi } from "../../lib/api";
import { useFirewallChange } from "../change/useFirewallChange";
import type { ConnectorChangeView } from "../../lib/connectors-schema";

export { IDLE, type Busy } from "../change/useFirewallChange";

/**
 * Follows one app-connection change from proposal to outcome. The mechanics are shared with the
 * channel connections and the model providers (`useFirewallChange`); this only binds the
 * integrations RPC and the shape of a provisional row.
 */
export function useConnectorChange(opts: { live: boolean; initial: ConnectorChangeView | null; onSettled: () => void | Promise<unknown> }) {
  const api = useApi();
  return useFirewallChange<ConnectorChangeView>({
    live: opts.live,
    initial: opts.initial,
    onSettled: opts.onSettled,
    rpc: { getChange: api.integrations.getChange, confirm: api.integrations.confirm, cancel: api.integrations.cancel },
    blank: (changeId) => ({
      id: changeId,
      vmId: null,
      connectionId: null,
      service: "",
      kind: "connect",
      summary: "",
      status: "queued",
      tofu: false,
      sentVia: null,
      attemptsLeft: null,
      expiresAt: null,
      authorizationUrl: null,
      error: null,
      createdAt: new Date().toISOString(),
      stuck: false,
    }),
  });
}
