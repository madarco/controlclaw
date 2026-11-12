"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApi } from "../../lib/api";
import { autoRuleToItem, type AutoApproveChange, type AutoApproveSnapshot } from "../../lib/auto-approve-schema";
import type { SecurityRuleListItem } from "../../lib/security-schema";
import { useRulesChange, type RulesPending } from "./useRulesChange";

/**
 * Where an organization's Auto approve rules are kept (docs/features/security-rules.md):
 * - `firewall`: its firewall keeps and checks them; the tab reads them from it and changes them like
 *   the Integrations rules, a change that lets more through waiting for the firewall's code;
 * - `old`: its firewall has not updated yet, so ControlClaw keeps and checks them, as before;
 * - `console`: no firewall; ControlClaw keeps them.
 */
export type AutoKept = "firewall" | "old" | "console";

export interface AutoDemo {
  snapshot: AutoApproveSnapshot | null;
  pending?: RulesPending;
  error?: string;
  loading?: boolean;
}

const NO_RPC = {
  change: async () => ({ changeId: "" }),
  status: async () => ({ status: "failed", ok: false, message: null, attemptsLeft: null, sentVia: null, snapshot: null }),
  confirm: async () => ({ changeId: "" }),
  cancel: async () => ({ changeId: "" }),
};

/** The rules from a firewall that keeps them, and the change waiting for its code. */
export function useAutoRules(enabled: boolean, demo?: AutoDemo, onSaved?: () => void) {
  const api = useApi();
  const [snapshot, setSnapshot] = useState<AutoApproveSnapshot | null>(demo?.snapshot ?? null);
  const [loading, setLoading] = useState(demo ? !!demo.loading : false);
  const read = useRef(false);
  const change = useRulesChange<AutoApproveChange, AutoApproveSnapshot>({ rpc: api.autoApprove ?? NO_RPC, demo, onSnapshot: setSnapshot, onSaved });
  const { setError, adopt } = change;
  const refresh = useCallback(async () => {
    if (demo || !enabled || !api.autoApprove) return;
    setLoading(true);
    setError("");
    try {
      setSnapshot(await api.autoApprove.get());
      const waiting = await api.autoApprove.waiting?.().catch(() => null);
      if (waiting) adopt({ changeId: waiting.changeId, status: "awaiting_code", sentVia: waiting.sentVia });
    } catch (e) {
      setError(e instanceof Error && /update/i.test(e.message) ? e.message : "Your firewall didn’t answer. Start or update it, then reload.");
    } finally {
      setLoading(false);
    }
    // `adopt` is a new function each render; it only ever sets state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [demo, enabled, setError, api]);
  useEffect(() => {
    if (!enabled || read.current || demo) return;
    read.current = true;
    void refresh();
  }, [enabled, demo, refresh]);
  const items: SecurityRuleListItem[] = useMemo(() => (snapshot ? snapshot.rules.map(autoRuleToItem) : []), [snapshot]);
  return { snapshot, items, loading, refresh, ...change };
}
