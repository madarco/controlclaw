"use client";

import { useApi } from "../../lib/api";
import { useFirewallChange } from "../change/useFirewallChange";
import type { FirewallUpdateChangeView } from "../../lib/firewall-view";
import { announceUpdatesChanged } from "../../lib/update-events";

/**
 * Follows one firewall self-update from proposal to outcome. The mechanics — the poll loop, the
 * wrong-code handling, the stuck note — are shared with channels, model providers and agent
 * updates; this only binds the firewall-update RPC and the shape of a provisional row.
 */
export function useFirewallUpdateChange(opts: { vmId: string; live: boolean; initial: FirewallUpdateChangeView | null; onSettled: () => void | Promise<unknown> }) {
  const api = useApi();
  return useFirewallChange<FirewallUpdateChangeView>({
    live: opts.live,
    initial: opts.initial,
    // The header's update count is about to be wrong; tell it.
    onSettled: () => {
      announceUpdatesChanged();
      return opts.onSettled();
    },
    rpc: { getChange: api.firewallUpdate.getChange, confirm: api.firewallUpdate.confirm, cancel: api.firewallUpdate.cancel },
    blank: (changeId) => ({
      id: changeId,
      vmId: opts.vmId,
      summary: "",
      status: "queued",
      tofu: false,
      sentVia: null,
      attemptsLeft: null,
      expiresAt: null,
      error: null,
      createdAt: new Date().toISOString(),
      stuck: false,
    }),
  });
}
