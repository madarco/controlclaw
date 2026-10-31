import { cn } from "../lib/utils";
import { Card } from "./console-ui";

/**
 * The band at the top of a service page that says, in one line, whether the thing is doing its
 * job: "Protecting 3 agents" on the Firewall, "Remembering 10,412 pages" on the Brain, "4 people
 * and 2 agents talking" on Team chat (the design's `fwl-hero`, `br-hero`, `tc-hero`).
 *
 * The same layout as `FirewallStatusHeader` (the text column takes a `basis` so a narrow card
 * puts the actions under it), with a tone that colours the icon tile and a gradient fading into
 * the card, and a pulse ring around the icon while the service is up.
 */

export type HeroTone = "allow" | "ask" | "block" | "brand" | "neutral";

const TILE: Record<HeroTone, string> = {
  allow: "bg-allow text-surface",
  ask: "bg-ask text-surface",
  block: "bg-block text-surface",
  brand: "bg-brand text-surface",
  neutral: "bg-bg-2 text-ink-2",
};

const RING: Record<HeroTone, string> = {
  allow: "border-allow",
  ask: "border-ask",
  block: "border-block",
  brand: "border-brand",
  neutral: "border-line-2",
};

// The gradient runs from the tone's soft colour into the card's own surface, so dark mode
// fades into the dark card instead of into white.
const WASH: Record<HeroTone, string> = {
  allow: "bg-[linear-gradient(90deg,var(--allow-soft),var(--surface)_55%)]",
  ask: "bg-[linear-gradient(90deg,var(--ask-soft),var(--surface)_55%)]",
  block: "bg-[linear-gradient(90deg,var(--block-soft),var(--surface)_55%)]",
  brand: "bg-[linear-gradient(90deg,var(--brand-soft),var(--surface)_55%)]",
  neutral: "",
};

export function StatusHero({
  tone,
  icon: Icon,
  pulse = tone === "allow" || tone === "brand",
  label,
  text,
  badges,
  meta,
  actions,
  children,
  "data-testid": testId,
  "data-tour": tour,
}: {
  tone: HeroTone;
  icon: React.ComponentType<{ className?: string }>;
  /** The ring around the icon; on by default for a healthy (green or purple) hero. */
  pulse?: boolean;
  /** The headline: "Protecting 3 agents". */
  label: React.ReactNode;
  /** One sentence under it. */
  text?: React.ReactNode;
  /** Pills beside the headline. */
  badges?: React.ReactNode;
  /** The small line under the sentence: "Checked in 11s ago · Falkenstein". */
  meta?: React.ReactNode;
  actions?: React.ReactNode;
  /** Notices inside the card, under the hero: progress, a pending command. */
  children?: React.ReactNode;
  "data-testid"?: string;
  /** A page-help anchor. */
  "data-tour"?: string;
}) {
  return (
    <Card className={cn("overflow-hidden", tone === "block" && "border-block-border")} data-testid={testId} data-tour={tour}>
      <div className={cn("flex flex-wrap items-center gap-[14px] px-4 py-3.5", WASH[tone])}>
        <span className={cn("relative grid h-11 w-11 shrink-0 place-items-center rounded-[12px]", TILE[tone])}>
          {pulse ? (
            <span
              aria-hidden="true"
              className={cn("absolute inset-0 rounded-[12px] border-2 opacity-0 motion-safe:animate-hero-pulse", RING[tone])}
            />
          ) : null}
          <Icon className="h-[22px] w-[22px]" />
        </span>
        <div className="min-w-0 flex-1 basis-[16rem]">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[16px] font-semibold tracking-[-0.01em] text-ink">{label}</span>
            {badges}
          </div>
          {text ? <p className="mt-0.5 max-w-[62ch] text-pretty text-[13.5px] text-ink-2">{text}</p> : null}
          {meta ? <div className="mt-1 text-[12.5px] text-ink-2">{meta}</div> : null}
        </div>
        {actions ? <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto sm:shrink-0">{actions}</div> : null}
      </div>
      {children ? <div className="border-t border-line px-4 py-3">{children}</div> : null}
    </Card>
  );
}
