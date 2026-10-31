"use client";

import { useState } from "react";
import { CheckCircle2, Clock, Loader2, MessageSquare, RefreshCw, Send, XCircle } from "lucide-react";
import { cn } from "../../lib/utils";
import { Disclosure } from "../../kit/console-ui";
import { Button } from "../../ui/button";
import type { AgentChannelType } from "../../lib/channel-states";
import { RelativeTime } from "../../kit/RelativeTime";
import { channelName, type AgentChannelChangeView, type ConnectionView, type LiveChannelStatus } from "../../lib/channels-schema";
import { boxErrorMessage } from "../../lib/box-error";

/** Pieces both the organization page and an agent's Channels page draw the same way. */

export const ICON: Record<AgentChannelType | "imessage", React.ComponentType<{ className?: string }>> = {
  telegram: Send,
  slack: MessageSquare,
  whatsapp: MessageSquare,
  imessage: MessageSquare,
};

/**
 * Read the boxes again now. Both pages already poll (3s while something is in flight, 20s
 * otherwise), so this is for the wait in between: someone has just messaged the bot and is
 * waiting to be approved, or a channel was fixed on the box. It only re-reads — nothing is
 * changed — so it stays enabled while a change is in flight.
 */
export function RefreshButton({ onRefresh, testId, label = "Refresh" }: { onRefresh: () => Promise<unknown>; testId?: string; label?: string }) {
  const [busy, setBusy] = useState(false);
  return (
    <Button
      size="sm"
      variant="outline"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await onRefresh();
        } finally {
          setBusy(false);
        }
      }}
      data-testid={testId ?? "channels-refresh"}
      title="Check the agents again"
    >
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
      {label}
    </Button>
  );
}

export type Tone = "allow" | "ask" | "block" | "muted";

/**
 * What a connection card says under its name: the control plane's own state first (it knows
 * about changes in flight), then whatever the box last reported.
 */
export function statusLine(c: ConnectionView, liveStatus?: LiveChannelStatus | null): { text: string; tone: Tone } {
  const status = liveStatus ?? c.boxStatus ?? null;
  // Before anything else about the channel itself: Slack and WhatsApp are OpenClaw plugins the box
  // fetches on first use, and until that lands the channel is not misconfigured, just not there yet.
  if (status?.setup?.state === "installing") return { text: `Setting up ${channelName(c.type)} on the agent…`, tone: "ask" };
  if (status?.setup?.state === "failed") return { text: status.setup.message, tone: "block" };
  // Before the box's own report: an orphaned connection's last status is whatever the box said
  // before its firewall was destroyed, and "Connected" is the one thing it is certainly not.
  if (c.state === "orphaned") return { text: "Its firewall no longer exists", tone: "block" };
  // A write the agent has not confirmed yet (T-86). It is still pending, but "waiting for the
  // firewall" is no longer what is happening — the firewall has done its part and the agent is
  // slow, which usually means it is restarting OpenClaw to pick the channel up.
  if (c.state === "pending" && c.lastError) return { text: boxErrorMessage(c.lastError) ?? "Waiting for the agent to confirm it", tone: "ask" };
  if (c.state === "pending") return { text: "Waiting for the firewall to apply it", tone: "ask" };
  if (c.state === "failed") return { text: boxErrorMessage(c.lastError) ?? "Setup failed", tone: "block" };
  // A change that did not go through (a token that was not replaced, a move that failed) leaves
  // the connection working but wrong; the card has to say so, not read "Connected".
  if (c.lastError) return { text: boxErrorMessage(c.lastError) ?? "The last change didn’t go through", tone: "block" };
  if (!c.assignedVm) return { text: "Ready, not on an agent yet", tone: "muted" };
  if (c.assignedVm.status !== "running") return { text: `The agent is ${c.assignedVm.status}`, tone: "muted" };
  if (status?.connected) return { text: "Connected", tone: "allow" };
  if (status?.lastError) return { text: boxErrorMessage(status.lastError) ?? "The agent reported a problem", tone: "block" };
  // Telegram polls the Bot API; OpenClaw reports it running, never "connected".
  if (c.type === "telegram" && status?.running) return { text: "Connected", tone: "allow" };
  if (status && !status.running) return { text: "Set up, but not running", tone: "ask" };
  if (!status) return { text: "Applied, waiting for the agent to report", tone: "muted" };
  return { text: c.type === "whatsapp" ? "Waiting for the QR scan" : "Connecting…", tone: "ask" };
}

const STATUS_ICON: Record<AgentChannelChangeView["status"], { Icon: React.ComponentType<{ className?: string }>; cls: string; label: string }> = {
  applied: { Icon: CheckCircle2, cls: "text-allow", label: "applied" },
  failed: { Icon: XCircle, cls: "text-block", label: "failed" },
  expired: { Icon: XCircle, cls: "text-ink-2", label: "expired" },
  cancelled: { Icon: XCircle, cls: "text-ink-2", label: "cancelled" },
  awaiting_code: { Icon: Loader2, cls: "text-ask", label: "waiting for the code" },
  queued: { Icon: Loader2, cls: "text-ink-2", label: "queued" },
  unconfirmed: { Icon: Clock, cls: "text-ask", label: "waiting for the agent" },
};

export function ChangeHistory({ recent }: { recent: AgentChannelChangeView[] }) {
  if (recent.length === 0) return null;
  const failed = recent.filter((c) => c.status === "failed").length;
  return (
    <Disclosure
      title="Recent changes"
      meta={failed > 0 ? `${recent.length} · ${failed} failed` : String(recent.length)}
      data-testid="channels-history"
    >
      <ul className="divide-y divide-line">
        {recent.map((c) => {
          const s = STATUS_ICON[c.status];
          return (
            // The reason goes under the line, not on it: a sentence-long one used to squeeze the
            // summary — the half that says WHAT happened — down to nothing.
            <li key={c.id} className="flex items-start gap-3 py-2 text-[13px]">
              <s.Icon className={cn("mt-0.5 h-4 w-4 shrink-0", s.cls)} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-ink">{c.summary || c.kind}</div>
                {c.error ? <div className="mt-0.5 text-xs text-ink-2">{boxErrorMessage(c.error)}</div> : null}
              </div>
              <span className="shrink-0 text-xs text-ink-2">
                {s.label}
                {c.status === "applied" ? (c.tofu ? " · first use" : c.sentVia ? ` · code via ${c.sentVia.split(":")[0]}` : "") : ""}
              </span>
              <RelativeTime className="shrink-0 text-xs text-ink-2" date={c.createdAt} />
            </li>
          );
        })}
      </ul>
    </Disclosure>
  );
}
