"use client";

import { useState } from "react";

/**
 * One change to rules the firewall keeps (email rules, content rules): propose it, wait for the
 * firewall, take the code it sent, confirm or cancel, and hand back the new snapshot. The RPC
 * methods are passed in; the card shows `RulesCodePanel` while a change is pending.
 */

export type RulesPending = { changeId: string; status: string; sentVia?: string | null };

type Status<S> = {
  status: string;
  ok: boolean | null;
  message: string | null;
  attemptsLeft: number | null;
  sentVia: string | null;
  snapshot: S | null;
};

export interface RulesChangeRpc<C, S> {
  change: (input: { change: C }) => Promise<{ changeId: string }>;
  status: (input: { changeId: string }) => Promise<Status<S>>;
  confirm: (input: { changeId: string; code: string }) => Promise<{ changeId: string }>;
  cancel: (input: { changeId: string }) => Promise<{ changeId: string }>;
}

export function useRulesChange<C, S>({
  rpc,
  demo,
  onSnapshot,
  onSaved,
}: {
  rpc: RulesChangeRpc<C, S>;
  /** The demo page: no firewall; a change asks for a code and confirming ends it. */
  demo?: { pending?: RulesPending; error?: string };
  onSnapshot: (snapshot: S) => void;
  /** A change applied (not cancelled). */
  onSaved?: () => void;
}) {
  const [pending, setPending] = useState<RulesPending | null>(demo?.pending ?? null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(demo?.error ?? "");
  const [notice, setNotice] = useState("");

  async function settle(changeId: string, originalId?: string) {
    for (let i = 0; i < 90; i++) {
      const result = await rpc.status({ changeId });
      if (["queued", "sent"].includes(result.status)) {
        await new Promise((r) => setTimeout(r, 2000));
        continue;
      }
      if (result.status === "awaiting_code") {
        setPending({ changeId, status: result.status, sentVia: result.sentVia });
        return;
      }
      if (result.status === "invalid" && originalId && result.attemptsLeft) {
        setPending({ changeId: originalId, status: "awaiting_code" });
        throw new Error(`Incorrect code. ${result.attemptsLeft} attempts left.`);
      }
      setPending(null);
      if (!result.ok) throw new Error(result.message ?? "This change expired or couldn’t be applied. Try again.");
      if (result.snapshot) onSnapshot(result.snapshot);
      if (result.status === "cancelled") setNotice("Change cancelled.");
      else {
        setNotice("Saved on your firewall.");
        onSaved?.();
      }
      return;
    }
    setPending(null);
    throw new Error("Your firewall didn’t finish this change. Reload the page to check.");
  }

  async function send(change: C): Promise<void> {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      if (demo) {
        setPending({ changeId: "demo", status: "awaiting_code", sentVia: "Telegram" });
        return;
      }
      const result = await rpc.change({ change });
      setPending({ changeId: result.changeId, status: "queued" });
      await settle(result.changeId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn’t save this change. Try again.");
    } finally {
      setBusy(false);
    }
  }

  async function confirm(cancel = false): Promise<void> {
    if (!pending) return;
    setBusy(true);
    setError("");
    const entered = code;
    setCode("");
    try {
      if (demo) {
        setPending(null);
        setNotice(cancel ? "Change cancelled." : "Saved on your firewall.");
        if (!cancel) onSaved?.();
        return;
      }
      const result = cancel ? await rpc.cancel({ changeId: pending.changeId }) : await rpc.confirm({ changeId: pending.changeId, code: entered });
      await settle(result.changeId, pending.changeId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn’t confirm this change. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return { pending, code, setCode, busy, error, setError, notice, setNotice, send, confirm };
}
