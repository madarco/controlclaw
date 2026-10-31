"use client";

import { useRef, useState } from "react";
import { Info, ShieldOff } from "lucide-react";
import { Popover, PopoverContent, PopoverTrigger } from "../../ui/popover";
import { Badge } from "../../kit/console-ui";
import { cn } from "../../lib/utils";

/**
 * What the residential exit gives up, said the same way everywhere it is chosen or shown.
 *
 * The firewall relays these connections still encrypted (docs/plans/residential-exit.md §4), so
 * nothing that needs to read a request can run on them. Website rules still pick which sites go
 * this way, and the firewall still records the site and the bytes.
 */
export const RESIDENTIAL_NOT_INSPECTED =
  "Traffic to these sites goes out encrypted through the residential exit. AI review, content rules and website logins don’t apply to it.";

/** The small mark a residential rule carries in a list. */
export function NotInspectedBadge({ "data-testid": testId }: { "data-testid"?: string }) {
  return (
    <Badge tone="ask" icon={ShieldOff} data-testid={testId}>
      Not inspected
    </Badge>
  );
}

/**
 * The (i) next to the Exit card's subtitle. A popover rather than a tooltip so a tap opens it on a
 * phone; with a mouse it also opens on hover.
 */
export function NotInspectedInfo({ "data-testid": testId }: { "data-testid"?: string }) {
  const [open, setOpen] = useState(false);
  // A hover that opened it should not be undone by the click that follows.
  const byHover = useRef(false);
  const hover = (next: boolean) => (e: React.PointerEvent) => {
    if (e.pointerType !== "mouse") return;
    byHover.current = next;
    setOpen(next);
  };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger
        type="button"
        aria-label="What the residential exit doesn’t inspect"
        onPointerEnter={hover(true)}
        onPointerLeave={hover(false)}
        onClick={(e) => {
          if (byHover.current) {
            e.preventDefault();
            byHover.current = false;
          }
        }}
        className="inline-flex h-4 w-4 shrink-0 items-center align-[-3px] justify-center rounded-full text-ink-2 outline-none hover:text-ink focus-visible:ring-2 focus-visible:ring-brand/30"
        data-testid={testId}
      >
        <Info className="h-3.5 w-3.5" />
      </PopoverTrigger>
      <PopoverContent
        side="bottom"
        align="start"
        collisionPadding={16}
        onOpenAutoFocus={(e) => e.preventDefault()}
        onPointerEnter={hover(true)}
        onPointerLeave={hover(false)}
        className="w-[300px] max-w-[calc(100vw-32px)] border-line bg-surface p-3 text-[12.5px] leading-[1.45] text-ink"
        data-testid={testId ? `${testId}-content` : undefined}
      >
        <p className="flex items-center gap-1.5 font-semibold">
          <ShieldOff className="h-3.5 w-3.5 text-ask-fg" /> Not inspected
        </p>
        <p className="mt-1">{RESIDENTIAL_NOT_INSPECTED}</p>
        <p className="mt-1.5 text-ink-2">
          Website rules still decide which sites use it, and each connection is still recorded (site and bytes).
        </p>
      </PopoverContent>
    </Popover>
  );
}

/** A one-line amber notice: the Connect dialog. */
export function NotInspectedNotice({
  children,
  className,
  "data-testid": testId,
}: {
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn("flex items-start gap-2 rounded-[10px] border border-ask-border bg-ask-soft p-2.5 text-[12.5px] text-ask-fg", className)}
    >
      <ShieldOff className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{children}</span>
    </div>
  );
}
