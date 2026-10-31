"use client";

import { ShieldAlert, ShieldCheck } from "lucide-react";
import { cn } from "../../lib/utils";
import { Card, IconBox, Pill as ConsolePill } from "../../kit/console-ui";

export type FirewallHeadingTone = "allow" | "ask" | "block" | "muted";

/**
 * A pill next to the firewall's heading: the proxy service's own state, a dev build, a badge.
 * The console's `Pill` without its dot; why it never wraps (T-73) is written there.
 */
export function Pill({ tone, title, children }: { tone: FirewallHeadingTone; title?: string; children: React.ReactNode }) {
  return (
    <ConsolePill tone={tone} dot={false} title={title}>
      {children}
    </ConsolePill>
  );
}

/**
 * The head of the Firewall page's status card: what the firewall is doing, and the controls for
 * the box itself.
 *
 * Presentational on purpose — every piece of state behind the buttons lives in `FirewallPanel`,
 * which passes them in as `actions`. Split out so `app/demo/firewall-status` can render the card
 * in states a dev organisation will not produce on demand, at any width.
 *
 * The layout is the whole point of the split. The text column carries a `basis` so that when the
 * card is narrow the actions wrap to their own line; with `flex-1` alone they kept their width
 * and squeezed the sentence into a column one word wide.
 */
export function FirewallStatusHeader({
  tone,
  label,
  text,
  badges,
  checkedIn,
  actions,
  children,
  icon,
  "data-testid": testId,
}: {
  tone: FirewallHeadingTone;
  label: React.ReactNode;
  text: React.ReactNode;
  /** The proxy-state pill, a dev-build pill, anything else that belongs beside the heading. */
  badges?: React.ReactNode;
  /** The "checked in 11s ago" line under the sentence. */
  checkedIn?: React.ReactNode;
  actions?: React.ReactNode;
  /** Notices that belong inside the card, under the header: progress, a pending command. */
  children?: React.ReactNode;
  /** The Brain page draws the same card with its own icon; the firewall's shield is the default. */
  icon?: React.ComponentType<{ className?: string }>;
  "data-testid"?: string;
}) {
  const StateIcon = icon ?? (tone === "ask" || tone === "block" ? ShieldAlert : ShieldCheck);
  return (
    <Card
      className={cn(
        "p-5",
        // A firewall that is broken has to look broken; one that is merely starting or stopped
        // is amber; a healthy one is the page's own surface.
        tone === "block" ? "border-block-border bg-block-soft" : tone === "ask" ? "border-ask-border bg-ask-soft" : "",
      )}
      data-testid={testId}
    >
      <div className="flex flex-wrap items-start gap-[14px]">
        <IconBox icon={StateIcon} tone={tone === "block" ? "block" : tone === "ask" ? "ask" : "brand"} />
        <div className="min-w-0 flex-1 basis-[18rem]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[16px] font-semibold text-ink">{label}</span>
            {badges}
          </div>
          <p className="mt-1 max-w-[62ch] text-pretty text-[13.5px] text-ink-2">{text}</p>
          {checkedIn ? <div className="mt-1.5 text-[12.5px] text-ink-2">{checkedIn}</div> : null}
        </div>
        {actions ? (
          <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto sm:shrink-0">{actions}</div>
        ) : null}
      </div>
      {children}
    </Card>
  );
}
