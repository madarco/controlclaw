"use client";

import { useApi } from "../../lib/api";
import { useFirewallChange } from "../change/useFirewallChange";
import type { ExitChangeView } from "../../lib/exit-schema";

export { IDLE, type Busy } from "../change/useFirewallChange";

/**
 * Follows one residential-exit change from proposal to outcome. The mechanics are shared with
 * channel connections and model providers (`useFirewallChange`); this only binds the RPC and the
 * shape of a provisional row.
 */
export function useExitChange(opts: { live: boolean; initial: ExitChangeView | null; onSettled: () => void | Promise<unknown> }) {
  const api = useApi();
  return useFirewallChange<ExitChangeView>({
    live: opts.live,
    initial: opts.initial,
    onSettled: opts.onSettled,
    rpc: {
      // The RPC can answer null (the change was swept away); the hook only ever asks about one it
      // is already tracking, so a null there means "gone" and the last known row stands.
      getChange: async (input) => (await api.exit.getExitChange(input)) ?? { ...blank(input.changeId), status: "expired" as const, error: "That change is no longer there." },
      confirm: api.exit.confirmExit,
      cancel: api.exit.cancelExit,
    },
    blank,
  });
}

function blank(changeId: string): ExitChangeView {
  return {
    id: changeId,
    kind: "add",
    summary: "",
    status: "queued",
    sentVia: null,
    attemptsLeft: null,
    expiresAt: null,
    error: null,
    createdAt: new Date().toISOString(),
    tofu: false,
    stuck: false,
  };
}
