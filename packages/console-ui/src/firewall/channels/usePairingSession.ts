"use client";

import { useCallback, useRef, useState } from "react";
import type { AgentChannelType, BoxRead } from "../../lib/channel-states";
import type { AgentChannelChangeView, PairingsErrorView, PendingPairingView } from "../../lib/channels-schema";
import type { StartChat } from "../../lib/pairing-step";
import type { Busy } from "../change/useFirewallChange";
import type { PairingStepProps } from "./PairingStep";

/** The connection a connect dialog is pairing, once it is on an agent. */
export type PairingSession = { type: AgentChannelType; connectionId: string; vmId: string; start: StartChat };

/**
 * What a Channels page needs to keep a connect dialog open after the channel is connected, and to
 * close it with a green line once the first request is approved. Both pages (the organization's
 * and an agent's) use it, with their own source of pairing requests.
 *
 *   - `arm(start)` when the person submits a new token for an agent; the `add` landing then opens
 *     the pairing step (`onChangeDone` returns "pairing").
 *   - `begin(session)` for WhatsApp, whose link is not an `add`: the dialog starts pairing once
 *     the number is linked.
 *   - `onChangeDone(change)` from the change hook's `onDone`: "paired" when the approval made from
 *     the dialog applied.
 */
export function usePairingSession() {
  const [session, setSession] = useState<PairingSession | null>(null);
  const [connected, setConnected] = useState<AgentChannelType | null>(null);
  const armed = useRef<StartChat | null>(null);
  const current = useRef(session);
  current.current = session;

  const arm = useCallback((start: StartChat) => {
    armed.current = start;
    setConnected(null);
  }, []);

  const begin = useCallback((s: PairingSession) => {
    setConnected(null);
    setSession(s);
  }, []);

  const end = useCallback(() => {
    armed.current = null;
    setSession(null);
  }, []);

  const onChangeDone = useCallback((c: AgentChannelChangeView): "pairing" | "paired" | null => {
    const start = armed.current;
    if (c.kind === "add" && start && start.type === c.channelType) {
      armed.current = null;
      // Kept in the organization (no agent): nobody can message it yet, so nothing to pair.
      if (c.status !== "applied" || !c.vmId || !c.connectionId) return null;
      setSession({ type: c.channelType, connectionId: c.connectionId, vmId: c.vmId, start });
      return "pairing";
    }
    const s = current.current;
    if (c.kind === "approve_pairing" && s && c.connectionId === s.connectionId) {
      setSession(null);
      // `unconfirmed`: the agent has not said yet. The toast says so; no green line for a guess.
      if (c.status !== "applied") return null;
      setConnected(s.type);
      return "paired";
    }
    return null;
  }, []);

  return { session, connected, dismissConnected: () => setConnected(null), arm, begin, end, onChangeDone };
}

/** The pairing step's props from a page's view of the agent and its change state. */
export function pairingStepProps(input: {
  session: PairingSession;
  /** Overrides the session's start: WhatsApp's number arrives with a later read. */
  start?: StartChat;
  agentName: string | null;
  pairings: PendingPairingView[];
  boxRead: BoxRead;
  pairingsError: PairingsErrorView | null;
  state: Busy;
  /** The change in flight, if any. */
  tracking: Pick<AgentChannelChangeView, "kind" | "connectionId"> | null;
  canApprove: boolean;
  onApprove: (p: PendingPairingView) => void;
  onClose: () => void;
}): PairingStepProps {
  const { session } = input;
  const approving = !!input.tracking && input.tracking.kind === "approve_pairing" && input.tracking.connectionId === session.connectionId;
  return {
    start: input.start ?? session.start,
    agentName: input.agentName,
    requests: input.pairings.filter((p) => p.connectionId === session.connectionId),
    boxRead: input.boxRead,
    pairingsError: input.pairingsError,
    approving: approving || (input.state.busy && !!input.tracking),
    error: input.state.error,
    note: input.state.note,
    canApprove: input.canApprove,
    onApprove: input.onApprove,
    onClose: input.onClose,
  };
}
