"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, ExternalLink, Loader2, UserCheck, X } from "lucide-react";
import { Button } from "../../ui/button";
import { DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "../../ui/dialog";
import type { BoxRead } from "../../lib/channel-states";
import { channelName, type PairingsErrorView, type PendingPairingView } from "../../lib/channels-schema";
import { isUnreadable, pairingPhase, startChatHref, startChatName, type PairingPhase, type StartChat } from "../../lib/pairing-step";

/**
 * The second half of a connect dialog (Telegram, Slack, WhatsApp): message the bot, then approve
 * the request that message makes. Only "how to start the chat" differs per channel; waiting,
 * approving, the timeout and the fallback for an agent that does not report requests are here once.
 *
 * It renders the dialog's header, body and footer, so the dialog that collected the token stays
 * open and only its content changes.
 */
export type PairingStepProps = {
  start: StartChat;
  /** The agent the channel is on, for the "check that it is running" hint. */
  agentName: string | null;
  /** Requests waiting on this connection. */
  requests: PendingPairingView[];
  boxRead: BoxRead;
  pairingsError: PairingsErrorView | null;
  /** An approval is on its way to the firewall. */
  approving: boolean;
  /** Why the last approval failed. */
  error: string | null;
  /** What the approval is doing right now ("Approving Marco…"). */
  note: string | null;
  canApprove: boolean;
  onApprove: (p: PendingPairingView) => void;
  onClose: () => void;
  /** Demo pages only: show this phase whatever the clock says. */
  phase?: PairingPhase;
};

const TICK_MS = 5_000;

export function PairingStep({ start, agentName, requests, boxRead, pairingsError, approving, error, note, canApprove, onApprove, onClose, phase: fixedPhase }: PairingStepProps) {
  const [waitingSince, setWaitingSince] = useState(() => Date.now());
  const [unreadableSince, setUnreadableSince] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const unreadable = isUnreadable(boxRead, pairingsError);
  useEffect(() => {
    // Since when the agent has said nothing useful; any good read starts the count again.
    setUnreadableSince((since) => (unreadable ? (since ?? Date.now()) : null));
  }, [unreadable, boxRead, pairingsError]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), TICK_MS);
    return () => clearInterval(t);
  }, []);
  const phase = fixedPhase ?? pairingPhase({ requests: requests.length, waitingSince, unreadableSince, now });
  // The row whose Approve was pressed: only that one shows the spinner, or "Try again".
  const [clicked, setClicked] = useState<string | null>(null);
  const keyOf = (p: PendingPairingView) => `${p.type}:${p.senderId}`;
  const active = clicked ?? (requests[0] ? keyOf(requests[0]) : null);
  const channel = channelName(start.type);

  return (
    <>
      <DialogHeader>
        <DialogTitle>{channel} is connected</DialogTitle>
        <DialogDescription>Now approve yourself, so the agent answers you and can send you security codes.</DialogDescription>
      </DialogHeader>

      <ol className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-4" data-testid="pairing-step" data-phase={phase}>
        <li className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-1.5">
          <div className="text-[13.5px] font-semibold text-ink">1. {start.type === "telegram" ? "Message the bot" : start.type === "slack" ? "Message the app" : "Message the number"}</div>
          <StartChatLine start={start} />
          <div className="text-[12.5px] text-ink-2">The agent replies with a pairing code, and your request shows up below.</div>
        </li>

        <li className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-2">
          <div className="text-[13.5px] font-semibold text-ink">2. Approve your request</div>
          {phase === "request" ? (
            <>
              <div className="text-[12.5px] text-ink-2">Check that it’s you before you approve. Anyone who messages the {start.type === "whatsapp" ? "number" : start.type === "slack" ? "app" : "bot"} shows up here.</div>
              <ul className="min-w-0 divide-y divide-line rounded-lg border border-line bg-bg-2 px-3" data-testid="pairing-requests">
                {requests.map((p) => (
                  <li key={keyOf(p)} className="flex flex-wrap items-center gap-x-3 gap-y-1.5 py-2.5 text-[13.5px]" data-testid="pairing-request">
                    <UserCheck className="h-4 w-4 shrink-0 text-ink-2" />
                    <span className="min-w-0 flex-1 basis-[10rem]">
                      <span className="block truncate font-medium text-ink">{p.label ?? p.senderId}</span>
                      <span className="block break-words font-mono text-xs text-ink-2">
                        {p.label ? `${p.senderId} · ` : ""}code {p.code}
                      </span>
                    </span>
                    <Button
                      size="sm"
                      disabled={!canApprove || approving || !p.connectionId}
                      onClick={() => {
                        setClicked(keyOf(p));
                        onApprove(p);
                      }}
                      data-testid="pairing-approve"
                    >
                      {approving && active === keyOf(p) ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                      {approving && active === keyOf(p) ? "Approving…" : error && active === keyOf(p) ? "Try again" : "Approve"}
                    </Button>
                  </li>
                ))}
              </ul>
            </>
          ) : phase === "slow" ? (
            <div className="grid gap-2 rounded-xl border border-ask-border bg-ask-soft px-3 py-2.5 text-[13px] text-ask-fg" data-testid="pairing-slow">
              <div className="flex gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  No message has arrived yet. Check that you messaged {startChatName(start) ?? `the right ${start.type === "telegram" ? "bot" : start.type === "slack" ? "app" : "number"}`}
                  {agentName ? `, and that ${agentName} is running` : ", and that the agent is running"}. After you connect a channel, the agent can take a minute to restart.
                </div>
              </div>
              <div>
                <Button size="sm" variant="outline" onClick={() => setWaitingSince(Date.now())} data-testid="pairing-keep-waiting">
                  Keep waiting
                </Button>
              </div>
            </div>
          ) : phase === "unreadable" ? (
            <div className="flex gap-2 rounded-xl border border-ask-border bg-ask-soft px-3 py-2.5 text-[13px] text-ask-fg" data-testid="pairing-unreadable">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                {agentName ?? "The agent"} isn’t saying who is waiting, so your request can’t show here. You can close this window. When the agent reports your request, it shows on
                the channel’s card on this page.
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-[13px] text-ink-2" data-testid="pairing-waiting">
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
              Waiting for your message…
            </div>
          )}
          {approving && note ? (
            <div className="flex items-center gap-2 text-[12.5px] text-ink-2" data-testid="pairing-note">
              <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin" />
              {note}
            </div>
          ) : null}
          {error && !approving ? (
            <div className="rounded-xl border border-block-border bg-block-soft px-3 py-2 text-[13px] text-block-fg" role="alert" data-testid="pairing-error">
              {error}
            </div>
          ) : null}
        </li>
      </ol>

      <DialogFooter>
        <Button variant="outline" onClick={onClose} disabled={approving} data-testid="pairing-close">
          Close
        </Button>
      </DialogFooter>
    </>
  );
}

/** The one line that differs per channel: where to send the first message. */
function StartChatLine({ start }: { start: StartChat }) {
  const href = startChatHref(start);
  const name = startChatName(start);
  const link = href ? (
    <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 font-medium text-link hover:underline" data-testid="pairing-start-link">
      {name ?? href.replace(/^https:\/\//, "")}
      <ExternalLink className="h-3 w-3" />
    </a>
  ) : null;
  const cls = "text-[13.5px] text-ink-2";
  switch (start.type) {
    case "telegram":
      return link ? <div className={cls}>Open {link} in Telegram and send it any message.</div> : <div className={cls}>In Telegram, open the bot you just made and send it any message.</div>;
    case "slack":
      return link ? (
        <div className={cls}>Open {link} in Slack and send it a direct message.</div>
      ) : (
        <div className={cls}>In Slack, find the app under Apps in the sidebar and send it a direct message.</div>
      );
    case "whatsapp":
      return link ? (
        <div className={cls}>From your own phone, send any message to {link} on WhatsApp.</div>
      ) : (
        <div className={cls}>From your own phone, send any message on WhatsApp to the number you just linked.</div>
      );
  }
}

/** The green line at the top of the Channels page once the first person is approved from the dialog. */
export function ChannelConnectedBanner({ type, onDismiss }: { type: StartChat["type"]; onDismiss: () => void }) {
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-allow-border bg-allow-soft px-4 py-3 text-[13.5px] text-allow-fg" role="status" data-testid="channels-connected-banner">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="font-semibold">You’re connected on {channelName(type)}</div>
        <div>To let other people talk to your agent, approve them on this page when they message it.</div>
      </div>
      <button type="button" className="shrink-0 rounded p-0.5 hover:bg-black/5" onClick={onDismiss} aria-label="Dismiss" data-testid="channels-connected-dismiss">
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
