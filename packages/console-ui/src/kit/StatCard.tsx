import { cn } from "../lib/utils";

type Tone = "default" | "allow" | "ask" | "block";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: React.ReactNode;
  icon: React.ComponentType<{ className?: string }>;
  tone?: Tone;
  /** Marks the card as a console-tour anchor (`data-tour`). */
  tourId?: string;
}

const TONE_ICON_CLASSES: Record<Tone, string> = {
  default: "bg-brand-soft text-brand-soft-fg",
  allow: "bg-allow-soft text-allow-fg",
  ask: "bg-ask-soft text-ask-fg",
  block: "bg-block-soft text-block-fg",
};

/**
 * One number at the top of a page.
 *
 * On a phone it is a strip, not a card: four of these stacked full width used the whole first
 * screen of the overview before anything else, and the subtitle and icon are what made each one
 * tall. Under 640px the label shrinks, the icon and the subtitle go, and four fit in a row. The
 * grid that does the fitting is `StatGrid`.
 */
export function StatCard({ label, value, sub, icon: Icon, tone = "default", tourId }: StatCardProps) {
  return (
    <div
      className="relative flex flex-col gap-0.5 overflow-hidden rounded-[10px] border border-line bg-surface px-2.5 py-2.5 sm:min-h-[112px] sm:gap-1.5 sm:rounded-[14px] sm:px-[18px] sm:py-4"
      data-tour={tourId}
    >
      <div
        className={cn(
          "absolute top-[15px] right-[15px] hidden h-[30px] w-[30px] place-items-center rounded-[9px] sm:grid",
          TONE_ICON_CLASSES[tone],
        )}
      >
        <Icon className="h-4 w-4" />
      </div>
      <div className="text-[10px] leading-[1.25] font-semibold uppercase tracking-[0.03em] text-ink-2 sm:truncate sm:pr-10 sm:text-[11.5px] sm:tracking-[0.04em]">
        {label}
      </div>
      <div className="text-[22px] font-semibold leading-none tracking-[-0.03em] tabular-nums text-ink sm:text-[31px]">
        {value}
      </div>
      {sub ? (
        <div className="mt-auto hidden flex-wrap items-center gap-1.5 text-[12.5px] text-ink-2 sm:flex">
          {sub}
        </div>
      ) : null}
    </div>
  );
}

/**
 * The row a page's stat cards live in. Four across on a phone — a compact strip rather than four
 * full-width blocks — then two, then as many as the page asks for.
 */
export function StatGrid({
  columns = 4,
  className,
  children,
}: {
  /** How many the row holds once there is room. Pages with fewer stats pass their count. */
  columns?: 2 | 3 | 4;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "grid gap-1.5 sm:gap-[14px]",
        columns === 2 ? "grid-cols-2" : columns === 3 ? "grid-cols-3" : "grid-cols-4 sm:grid-cols-2",
        columns === 4 ? "lg:grid-cols-4" : "",
        className,
      )}
    >
      {children}
    </div>
  );
}
