"use client";

import { useApi } from "../../lib/api";
import type { AgentChannelChangeView } from "../../lib/channels-schema";
import { useFirewallChange } from "../change/useFirewallChange";

/**
 * Follows one channel change from proposal to outcome. The mechanics are shared with the model
 * providers (`useFirewallChange`); this only binds the channel RPC and the shape of a provisional
 * row, and is used by both the organization page and an agent's Channels page.
 */
export function useChannelChange(opts: { live: boolean; initial: AgentChannelChangeView | null; onSettled: () => void | Promise<unknown>; onDone?: () => void }) {
  const api = useApi();
  return useFirewallChange<AgentChannelChangeView>({
    live: opts.live,
    initial: opts.initial,
    onSettled: opts.onSettled,
    onDone: opts.onDone,
    rpc: { getChange: api.channels.getChange, confirm: api.channels.confirm, cancel: api.channels.cancel },
    blank: (changeId) => ({
      id: changeId,
      connectionId: null,
      vmId: null,
      channelType: "telegram",
      kind: "add",
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
