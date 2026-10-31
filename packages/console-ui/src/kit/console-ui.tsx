"use client";

import { useEffect, useRef, useState } from "react";
import { AppLink as Link } from "../lib/link";
import { ChevronRight, CheckCircle2, MinusCircle, MoreHorizontal, XCircle } from "lucide-react";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { cn } from "../lib/utils";
import { CopyButton } from "../ui/copy-button";
import { NativeSelect } from "../ui/native-select";
import { tabForHash, type TabAnchors } from "./console-tabs";

/**
 * Console v2 primitives. One place for the shapes the redesign repeats on every page: a titled
 * section, a one-line status, a collapsed "Advanced" disclosure, a key/value list, a change log.
 * Pages compose these instead of re-spelling the same Tailwind.
 */

export type Tone = "neutral" | "ok" | "warn" | "err";

const STATUS_BOX: Record<Tone, string> = {
  neutral: "border-line bg-surface",
  ok: "border-allow-border bg-allow-soft",
  warn: "border-ask-border bg-ask-soft",
  err: "border-block-border bg-block-soft",
};

const STATUS_DOT: Record<Tone, string> = {
  neutral: "bg-ink-2",
  ok: "bg-allow",
  warn: "bg-ask",
  err: "bg-block",
};

/** A section: heading, optional icon and subtitle, an action on the right, a stacked body. */
export function Sec({
  id,
  icon: Icon,
  title,
  sub,
  right,
  children,
  className,
  "data-testid": testId,
  "data-tour": tour,
}: {
  id?: string;
  icon?: React.ComponentType<{ className?: string }>;
  title: React.ReactNode;
  sub?: React.ReactNode;
  right?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  "data-testid"?: string;
  /** A console-tour or page-help anchor. */
  "data-tour"?: string;
}) {
  return (
    <section id={id} data-testid={testId} data-tour={tour} className={cn("mt-9 scroll-mt-[70px]", className)}>
      <div className={cn("flex items-start gap-4", children ? "mb-[14px]" : "")}>
        <div className="min-w-0 flex-1">
          <h2 className="flex items-center gap-[9px] text-[17px] font-semibold tracking-[-0.015em] text-ink">
            {Icon ? <Icon className="h-[17px] w-[17px] text-ink-2" /> : null}
            {title}
          </h2>
          {sub ? <p className="mt-1 max-w-[68ch] text-pretty text-[13.5px] text-ink-2">{sub}</p> : null}
        </div>
        {right ? <div className="flex shrink-0 items-center gap-2">{right}</div> : null}
      </div>
      {children ? <Stack>{children}</Stack> : null}
    </section>
  );
}

/** The vertical rhythm inside a section or a card. */
export function Stack({
  className,
  children,
  "data-testid": testId,
}: {
  className?: string;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <div data-testid={testId} className={cn("flex flex-col gap-3", className)}>
      {children}
    </div>
  );
}

/** A one-line status: the redesign's replacement for a paragraph of explanation. */
export function StatusLine({
  tone = "neutral",
  plain,
  right,
  children,
  className,
  "data-testid": testId,
}: {
  tone?: Tone;
  /** No box, no padding — for a status that sits inside a card that already has a border. */
  plain?: boolean;
  right?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn(
        // On a phone the action goes under the sentence rather than squeezing it into a
        // one-word column: `flex-wrap` plus a dot that only leads the first line.
        "flex flex-wrap items-center gap-x-[9px] gap-y-2 text-[13.5px] text-ink-2",
        plain ? "" : cn("rounded-[10px] border px-[14px] py-[10px]", STATUS_BOX[tone]),
        className,
      )}
    >
      <span className={cn("h-2 w-2 shrink-0 rounded-full", STATUS_DOT[tone])} />
      <span className="min-w-[12rem] flex-1 [&_b]:font-semibold [&_b]:text-ink [&_strong]:font-semibold [&_strong]:text-ink">
        {children}
      </span>
      {right ? <span className="ml-auto shrink-0">{right}</span> : null}
    </div>
  );
}

const INLINE_TONE: Record<Tone, string> = {
  neutral: "text-ink-2",
  ok: "text-allow-fg",
  warn: "text-ask-fg",
  err: "text-block-fg",
};

/** A dot plus a word, for a status that has to sit inside a row of other text. */
export function Dot({
  tone = "neutral",
  children,
  className,
  "data-testid": testId,
}: {
  tone?: Tone;
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <span
      data-testid={testId}
      className={cn("inline-flex items-center gap-[7px] text-[13px]", INLINE_TONE[tone], className)}
    >
      <span className={cn("h-[7px] w-[7px] shrink-0 rounded-full", STATUS_DOT[tone])} />
      {children}
    </span>
  );
}

/**
 * The "Advanced" disclosure. Everything rare or detailed in the redesign lives behind one of
 * these, closed by default.
 */
export function Disclosure({
  id,
  title,
  meta,
  defaultOpen = false,
  open: openProp,
  onOpenChange,
  flat,
  children,
  className,
  "data-testid": testId,
}: {
  /** An anchor. A link to `#<id>` scrolls here and opens it, so a folded section can be linked to. */
  id?: string;
  title: React.ReactNode;
  /** Shown next to the title so the summary is readable while it is closed. */
  meta?: React.ReactNode;
  defaultOpen?: boolean;
  /** Controlled mode, for a section that opens itself (a repair in progress). */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  /** No border or background — for a disclosure already inside a card. */
  flat?: boolean;
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  const [openState, setOpenState] = useState(defaultOpen);
  const open = openProp ?? openState;
  const onOpenChangeRef = useRef(onOpenChange);
  useEffect(() => {
    onOpenChangeRef.current = onOpenChange;
  }, [onOpenChange]);
  const setOpen = (next: boolean) => {
    setOpenState(next);
    onOpenChangeRef.current?.(next);
  };
  useEffect(() => {
    if (!id) return;
    const follow = () => {
      if (window.location.hash !== `#${id}`) return;
      setOpenState(true);
      onOpenChangeRef.current?.(true);
      document.getElementById(id)?.scrollIntoView();
    };
    follow();
    window.addEventListener("hashchange", follow);
    return () => window.removeEventListener("hashchange", follow);
  }, [id]);
  return (
    <div
      id={id}
      data-testid={testId}
      className={cn(flat ? "" : "rounded-xl border border-line bg-surface", id && "scroll-mt-4", className)}
    >
      <button
        type="button"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className={cn(
          "flex w-full items-center gap-[10px] text-left text-[13.5px] font-semibold text-ink",
          flat ? "py-2" : "px-4 py-3",
        )}
      >
        <ChevronRight
          className={cn("h-[15px] w-[15px] shrink-0 text-ink-2 transition-transform", open && "rotate-90")}
        />
        <span>{title}</span>
        {meta ? <span className="truncate text-[12.5px] font-normal text-ink-2">{meta}</span> : null}
      </button>
      {open ? (
        <div className={cn(flat ? "pt-1 pb-2 pl-[26px]" : "px-4 pb-4 pl-[42px]")}>{children}</div>
      ) : null}
    </div>
  );
}

export type KVRow = [key: React.ReactNode, value: React.ReactNode, mono?: boolean];

/** A key/value list: label left, value right, hairline between rows. */
export function KV({
  rows,
  className,
  "data-testid": testId,
}: {
  rows: (KVRow | null | false)[];
  className?: string;
  "data-testid"?: string;
}) {
  const visible = rows.filter(Boolean) as KVRow[];
  return (
    <dl data-testid={testId} className={cn("grid grid-cols-[minmax(120px,auto)_minmax(0,1fr)] text-[13px]", className)}>
      {visible.map(([k, v, mono], i) => {
        const last = i === visible.length - 1;
        return (
          <div key={i} className="contents">
            <dt className={cn("py-2 text-ink-2", last ? "" : "border-b border-line")}>{k}</dt>
            <dd
              className={cn(
                "py-2 text-right break-words text-ink",
                mono && "font-mono text-[12.5px]",
                last ? "" : "border-b border-line",
              )}
            >
              {v}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

/** Two KV lists side by side, stacking under 800px. */
export function KVPair({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-1 gap-x-8 md:grid-cols-2">{children}</div>;
}

export type ChangeItem = {
  /** true applied, false failed, null/undefined neither (cancelled, pending). */
  ok?: boolean | null;
  what: React.ReactNode;
  meta?: React.ReactNode;
  err?: React.ReactNode;
};

/** "Recent changes": what was asked for, whether it landed, and why it did not. */
export function ChangeList({ items, className }: { items: ChangeItem[]; className?: string }) {
  return (
    <div className={cn("flex flex-col", className)}>
      {items.map((c, i) => (
        <div
          key={i}
          className="grid grid-cols-[18px_minmax(0,1fr)_auto] items-start gap-[10px] border-b border-line py-[9px] text-[13px] text-ink last:border-b-0"
        >
          <span className="mt-px">
            {c.ok === true ? (
              <CheckCircle2 className="h-4 w-4 text-allow" />
            ) : c.ok === false ? (
              <XCircle className="h-4 w-4 text-block" />
            ) : (
              <MinusCircle className="h-4 w-4 text-ink-2" />
            )}
          </span>
          <span className="min-w-0">
            {c.what}
            {c.err ? <span className="mt-0.5 block text-[12px] text-block-fg">{c.err}</span> : null}
          </span>
          {c.meta ? <span className="whitespace-nowrap text-[12px] text-ink-2">{c.meta}</span> : null}
        </div>
      ))}
    </div>
  );
}

/** A value to copy: monospace on a tinted field with a copy button. */
export function CodeField({
  text,
  className,
  "data-testid": testId,
}: {
  text: string;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn(
        "flex items-center gap-2 rounded-[10px] border border-line bg-bg py-1.5 pr-1.5 pl-3",
        className,
      )}
    >
      <code className="min-w-0 flex-1 font-mono text-[12.5px] break-all text-ink">{text}</code>
      <CopyButton value={text} variant="ghost" />
    </div>
  );
}

/** The empty state used inside a card. */
export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  className,
  "data-testid": testId,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  title?: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div data-testid={testId} className={cn("px-4 py-10 text-center text-[13.5px] text-ink-2", className)}>
      {Icon ? (
        <div className="mx-auto mb-3 grid h-10 w-10 place-items-center rounded-full bg-bg text-ink-2">
          <Icon className="h-5 w-5" />
        </div>
      ) : null}
      {title ? <div className="mb-1 text-[14.5px] font-semibold text-ink">{title}</div> : null}
      {children ? <div className="mx-auto max-w-[460px] text-pretty">{children}</div> : null}
      {action ? <div className="mt-[14px]">{action}</div> : null}
    </div>
  );
}

/** A small inert label. */
export function Chip({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-[7px] border border-line bg-bg px-[9px] text-[12px] whitespace-nowrap text-ink-2",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Chips({ children, className }: { children: React.ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap gap-1.5", className)}>{children}</div>;
}

/** The rounded icon square that heads a card or a row. */
export function IconBox({
  icon: Icon,
  tone = "brand",
  size = 40,
  className,
}: {
  icon: React.ComponentType<{ className?: string }>;
  tone?: "brand" | "muted" | "ask" | "allow" | "block";
  size?: number;
  className?: string;
}) {
  const tones = {
    brand: "bg-brand-soft text-brand-soft-fg",
    muted: "bg-bg text-ink-2",
    ask: "bg-ask-soft text-ask-fg",
    allow: "bg-allow-soft text-allow-fg",
    block: "bg-block-soft text-block-fg",
  };
  return (
    <div
      style={{ width: size, height: size }}
      className={cn("grid shrink-0 place-items-center rounded-[11px]", tones[tone], className)}
    >
      <Icon className={size >= 40 ? "h-5 w-5" : "h-4 w-4"} />
    </div>
  );
}

/** A usage bar with a caption under it. */
export function UsageBar({
  percent,
  left,
  right,
  className,
  warnAt,
  "data-testid": testId,
}: {
  percent: number;
  left?: React.ReactNode;
  right?: React.ReactNode;
  className?: string;
  /**
   * Turn the fill amber past this percentage and red at 100. For an allowance that runs out and
   * breaks something; without it a full bar reads as a healthy brand-coloured one.
   */
  warnAt?: number;
  "data-testid"?: string;
}) {
  const fill =
    warnAt === undefined
      ? "bg-brand"
      : percent >= 100
        ? "bg-block"
        : percent >= warnAt
          ? "bg-ask"
          : "bg-brand";
  return (
    <div className={className} data-testid={testId}>
      <div className="h-[7px] overflow-hidden rounded-full bg-bg-2">
        <div
          className={cn("h-full min-w-[6px] rounded-full", fill)}
          style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
        />
      </div>
      {left || right ? (
        <div className="mt-[7px] flex justify-between text-[12.5px] text-ink-2 [&_b]:font-semibold [&_b]:text-ink">
          <span>{left}</span>
          <span>{right}</span>
        </div>
      ) : null}
    </div>
  );
}

/** A card with the console's border and surface. */
export function Card({
  className,
  children,
  "data-testid": testId,
  "data-tour": tour,
}: {
  className?: string;
  children: React.ReactNode;
  "data-testid"?: string;
  "data-tour"?: string;
}) {
  return (
    <div
      data-testid={testId}
      data-tour={tour}
      className={cn("rounded-[14px] border border-line bg-surface", className)}
    >
      {children}
    </div>
  );
}

/** A link that reads as one: used for the "AI models →" affordances next to section headings. */
export function LinkButton({
  href,
  onClick,
  children,
  className,
  "data-testid": testId,
}: {
  href?: string;
  onClick?: () => void;
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  const style = cn(
    "inline-flex items-center gap-1 text-[13px] font-medium whitespace-nowrap text-brand hover:text-brand-ink hover:underline",
    className,
  );
  if (href) {
    return (
      <Link href={href} data-testid={testId} className={style}>
        {children}
      </Link>
    );
  }
  return (
    <button type="button" onClick={onClick} data-testid={testId} className={style}>
      {children}
    </button>
  );
}

/** Small muted helper text. */
export function Hint({
  className,
  children,
  "data-testid": testId,
}: {
  className?: string;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <span data-testid={testId} className={cn("text-[12.5px] text-ink-2", className)}>
      {children}
    </span>
  );
}

/** A warning panel: title line plus body, in the "ask" tone. */
export function AlertCard({
  icon: Icon,
  title,
  children,
  className,
  "data-testid": testId,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  title: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn("rounded-xl border border-ask-border bg-ask-soft px-4 py-[14px]", className)}
    >
      <div className="flex items-center gap-2 text-[13.5px] font-semibold text-ask-fg">
        {Icon ? <Icon className="h-[15px] w-[15px] shrink-0" /> : null}
        {title}
      </div>
      {children ? <div className="mt-1 text-[12.5px] text-ink-2">{children}</div> : null}
    </div>
  );
}

/** The bordered list of destructive actions at the bottom of a page. */
export function DangerCard({ children, "data-testid": testId }: { children: React.ReactNode; "data-testid"?: string }) {
  return (
    <div data-testid={testId} className="overflow-hidden rounded-[14px] border border-block-border">
      {children}
    </div>
  );
}

export function DangerRow({
  title,
  children,
  action,
}: {
  title: React.ReactNode;
  children?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-center gap-4 border-t border-block-border px-5 py-4 first:border-t-0">
      <div className="min-w-[240px] flex-1">
        <div className="text-[14px] font-semibold text-ink">{title}</div>
        {children ? <div className="mt-0.5 text-[13px] text-ink-2">{children}</div> : null}
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

/** A row in a service / toggle list inside a card. */
export function ServiceRow({
  name,
  desc,
  note,
  off,
  right,
  className,
  "data-testid": testId,
}: {
  name: React.ReactNode;
  desc?: React.ReactNode;
  note?: React.ReactNode;
  off?: boolean;
  right?: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn("flex items-center gap-[14px] border-b border-line px-4 py-3 last:border-b-0", className)}
    >
      <div className="min-w-0 flex-1">
        <div
          className={cn(
            "flex items-center gap-2 text-[13.5px] font-semibold",
            off ? "text-ink-2" : "text-ink",
          )}
        >
          {name}
        </div>
        {desc ? <div className="mt-px text-[12.5px] text-ink-2">{desc}</div> : null}
        {note ? <div className="mt-[3px] text-[12px] text-ask-fg">{note}</div> : null}
      </div>
      {right ? <div className="flex shrink-0 items-center gap-2">{right}</div> : null}
    </div>
  );
}

/**
 * A row in the firewall's "what it is doing" recap: icon, title, one line of state, and a way in.
 * Rendered as a link when it has an href, as a plain row otherwise.
 */
export function RecapRow({
  icon: Icon,
  tone = "muted",
  title,
  desc,
  href,
  right,
  "data-testid": testId,
}: {
  icon: React.ComponentType<{ className?: string }>;
  tone?: "muted" | "warn" | "allow";
  title: React.ReactNode;
  desc?: React.ReactNode;
  href?: string;
  right?: React.ReactNode;
  "data-testid"?: string;
}) {
  const body = (
    <>
      <IconBox
        icon={Icon}
        size={34}
        tone={tone === "warn" ? "ask" : tone === "allow" ? "allow" : "muted"}
        className="rounded-[10px]"
      />
      <div className="min-w-0">
        <div className="text-[14px] font-semibold text-ink">{title}</div>
        {desc ? <div className="text-pretty text-[13px] text-ink-2">{desc}</div> : null}
      </div>
      {href ? (
        <span className="text-[13px] whitespace-nowrap text-ink-2 group-hover:text-ink">Open →</span>
      ) : (
        <div className="flex items-center gap-2.5">{right}</div>
      )}
    </>
  );
  const shell = "grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-[14px] border-t border-line px-[18px] py-[14px] text-left first:border-t-0";
  if (href) {
    return (
      <Link href={href} data-testid={testId} className={cn(shell, "group hover:bg-bg")}>
        {body}
      </Link>
    );
  }
  return (
    <div data-testid={testId} className={shell}>
      {body}
    </div>
  );
}

export type TabDef = {
  id: string;
  label: string;
  /** A coloured dot before the label, for a tab that needs attention. */
  flag?: "warn" | "err";
};

/**
 * The sticky tab strip the redesign puts under a detail page's header. The active tab lives in
 * the URL fragment, so a tab is linkable and survives a reload without a server round trip.
 */
export function AnchorTabs({
  tabs,
  active,
  onSelect,
  className,
  "data-testid": testId,
  "data-tour": tour,
}: {
  tabs: TabDef[];
  active: string;
  onSelect: (id: string) => void;
  className?: string;
  "data-testid"?: string;
  /** A page-help anchor for the whole tab bar. */
  "data-tour"?: string;
}) {
  return (
    <nav
      role="tablist"
      data-testid={testId}
      data-tour={tour}
      className={cn(
        "sticky top-0 z-20 -mx-6 mt-[22px] flex gap-1 overflow-x-auto border-b border-line bg-surface/90 px-6 py-2.5 backdrop-blur md:-mx-9 md:px-9",
        className,
      )}
    >
      {tabs.map((t) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          aria-selected={active === t.id}
          data-testid={`agent-tab-${t.id}`}
          data-tour={`tab-${t.id}`}
          onClick={() => onSelect(t.id)}
          className={cn(
            "inline-flex shrink-0 items-center gap-1.5 rounded-[7px] px-2.5 py-1.5 text-[13px] whitespace-nowrap",
            active === t.id ? "bg-bg font-semibold text-ink" : "text-ink-2 hover:bg-bg hover:text-ink",
          )}
        >
          {t.flag ? (
            <span
              className={cn("h-1.5 w-1.5 rounded-full", t.flag === "err" ? "bg-block" : "bg-ask")}
              aria-hidden="true"
            />
          ) : null}
          {t.label}
        </button>
      ))}
    </nav>
  );
}

/**
 * Reads and writes the active tab in the URL fragment. `window.history.replaceState` rather than
 * the router, so switching tabs never asks the server for anything.
 *
 * `anchors` maps a section's id to the tab that holds it, so a link written before the page had
 * tabs (`/dashboard/firewall#code-recipients`) opens that tab and scrolls to the section.
 */
export function useHashTab(
  defaultTab: string,
  valid: readonly string[],
  anchors?: TabAnchors,
): [string, (id: string) => void] {
  const [tab, setTab] = useState(defaultTab);
  // Strings, so the effect re-runs when a conditional tab appears or goes away rather than on
  // every render. A fragment naming a tab that is not there falls back to the default, instead
  // of selecting nothing and leaving the page blank.
  const validKey = valid.join(",");
  const anchorsKey = anchors ? JSON.stringify(anchors) : "";
  useEffect(() => {
    const map: TabAnchors = anchorsKey ? JSON.parse(anchorsKey) : {};
    const read = () => {
      const h = window.location.hash.slice(1);
      const next = tabForHash(h, validKey.split(","), map, defaultTab);
      setTab(next);
      // An anchor: the section renders with the tab, maybe after its data, so look for it for
      // a couple of seconds and scroll once it is there.
      if (h && h !== next && Object.hasOwn(map, h)) {
        let tries = 120;
        const seek = () => {
          const el = document.getElementById(h);
          if (el) el.scrollIntoView({ block: "start" });
          else if (--tries > 0) requestAnimationFrame(seek);
        };
        requestAnimationFrame(seek);
      }
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, [defaultTab, validKey, anchorsKey]);
  const select = (id: string) => {
    const url = id === defaultTab ? window.location.pathname + window.location.search : `#${id}`;
    window.history.replaceState(null, "", url);
    setTab(id);
  };
  return [tab, select];
}

/** A grid of one-click actions, as the redesign's agent Home tab has them. */
export function ActionGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-[repeat(auto-fill,minmax(160px,1fr))] gap-2.5">{children}</div>;
}

export function ActionButton({
  icon: Icon,
  label,
  href,
  onClick,
  disabled,
  title,
  "data-testid": testId,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: React.ReactNode;
  href?: string;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  "data-testid"?: string;
}) {
  const style =
    "flex items-center gap-2.5 rounded-[10px] border border-line bg-surface px-3.5 py-3 text-left text-[13.5px] font-medium text-ink hover:bg-bg disabled:cursor-not-allowed disabled:opacity-50";
  const body = (
    <>
      <Icon className="h-4 w-4 shrink-0 text-ink-2" />
      <span className="truncate">{label}</span>
    </>
  );
  if (href && !disabled) {
    return (
      <Link href={href} title={title} data-testid={testId} className={style}>
        {body}
      </Link>
    );
  }
  return (
    <button type="button" onClick={onClick} disabled={disabled} title={title} data-testid={testId} className={style}>
      {body}
    </button>
  );
}

export type MenuItem =
  | "-"
  | {
      label: React.ReactNode;
      /** A second line under the label, for the consequence of choosing it. */
      sub?: React.ReactNode;
      icon?: React.ComponentType<{ className?: string }>;
      danger?: boolean;
      disabled?: boolean;
      onClick?: () => void;
      /** A page to go to instead of an action: the item is a real link (middle-click, copy address). */
      href?: string;
      "data-testid"?: string;
    };

/**
 * The "…" menu the redesign puts next to a section's one primary action, so the rarer controls
 * are one tap away instead of a row of equal-looking buttons.
 */
export function ActionMenu({
  items,
  label,
  icon: Icon = MoreHorizontal,
  ariaLabel,
  align = "end",
  size = "sm",
  disabled,
  "data-testid": testId,
}: {
  items: MenuItem[];
  /** Given a label the trigger reads as a button; without one it is the square "…". */
  label?: string;
  /** The trigger's icon, when the menu is not "more": the wrench on Security rules, the plus on "Add channel". */
  icon?: React.ComponentType<{ className?: string }>;
  ariaLabel?: string;
  align?: "start" | "end";
  /** `default` next to full-size buttons, as in a page header. */
  size?: "sm" | "default";
  disabled?: boolean;
  "data-testid"?: string;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size={size} aria-label={ariaLabel ?? label ?? "More actions"} disabled={disabled} data-testid={testId}>
          <Icon className="h-[15px] w-[15px]" />
          {label}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align={align} className="w-[230px]">
        {items.map((it, i) =>
          it === "-" ? (
            <DropdownMenuSeparator key={i} />
          ) : (
            <DropdownMenuItem
              key={i}
              disabled={it.disabled}
              onSelect={() => it.onClick?.()}
              asChild={!!it.href && !it.disabled}
              data-testid={it["data-testid"]}
              className={cn("cursor-pointer items-start gap-2.5", it.danger && "text-block-fg focus:text-block-fg")}
            >
              {it.href && !it.disabled ? (
                <Link href={it.href}>
                  <MenuItemBody item={it} />
                </Link>
              ) : (
                <MenuItemBody item={it} />
              )}
            </DropdownMenuItem>
          ),
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function MenuItemBody({ item: it }: { item: Exclude<MenuItem, "-"> }) {
  return (
    <>
      {it.icon ? <it.icon className={cn("mt-0.5 h-4 w-4 shrink-0", it.danger ? "text-block-fg" : "text-ink-2")} /> : null}
      <span className="min-w-0">
        <span className="block">{it.label}</span>
        {it.sub ? <span className="block text-[11.5px] text-ink-2">{it.sub}</span> : null}
      </span>
    </>
  );
}

/**
 * A card's inner band. The redesign's exit card and its usage block are one card split by a
 * hairline, not two cards, so `CardBody` is what a page stacks inside `Card`.
 */
export function CardBody({
  divided,
  className,
  children,
  "data-testid": testId,
}: {
  /** A hairline above this band, for every band after the first. */
  divided?: boolean;
  className?: string;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      className={cn("p-5", divided && "border-t border-line", className)}
    >
      {children}
    </div>
  );
}

/** The heading band of a card: a title, an optional subtitle, and an action on the right. */
export function CardHead({
  title,
  sub,
  right,
  icon: Icon,
  live,
  className,
}: {
  title: React.ReactNode;
  sub?: React.ReactNode;
  right?: React.ReactNode;
  /** A small icon before the title. */
  icon?: React.ComponentType<{ className?: string }>;
  /** A dot before the title for a card that updates on its own: blinking, or still while paused. */
  live?: "live" | "paused";
  className?: string;
}) {
  return (
    <div className={cn("flex items-start gap-2 border-b border-line px-5 py-4", className)}>
      <div className="min-w-0 flex-1">
        <h3 className="flex items-center gap-2 text-[15px] font-semibold tracking-[-0.01em] text-ink">
          {live ? <LiveDot paused={live === "paused"} /> : null}
          {Icon ? <Icon className="h-[15px] w-[15px] shrink-0 text-ink-2" /> : null}
          <span className="min-w-0">{title}</span>
        </h3>
        {sub ? <p className="mt-0.5 text-[13px] text-ink-2">{sub}</p> : null}
      </div>
      {right ? <div className="flex shrink-0 items-center gap-2">{right}</div> : null}
    </div>
  );
}

const BADGE_TONE: Record<"neutral" | "brand" | "allow" | "ask" | "block", string> = {
  neutral: "border-line bg-bg text-ink-2",
  brand: "border-brand-border bg-brand-soft text-brand-soft-fg",
  allow: "border-allow-border bg-allow-soft text-allow-fg",
  ask: "border-ask-border bg-ask-soft text-ask-fg",
  block: "border-block-border bg-block-soft text-block-fg",
};

const BADGE_DOT: Record<"neutral" | "brand" | "allow" | "ask" | "block", string> = {
  neutral: "bg-ink-2",
  brand: "bg-brand",
  allow: "bg-allow",
  ask: "bg-ask",
  block: "bg-block",
};

/**
 * The redesign's pill. Three pages were each spelling their own out; `dot` is the little
 * coloured circle the "Connected" / "Running" pills carry.
 */
export function Badge({
  tone = "neutral",
  dot,
  icon: Icon,
  children,
  className,
  "data-testid": testId,
}: {
  tone?: "neutral" | "brand" | "allow" | "ask" | "block";
  dot?: boolean;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <span
      data-testid={testId}
      className={cn(
        "inline-flex h-[24px] items-center gap-1.5 rounded-full border px-[10px] text-[11.5px] font-semibold whitespace-nowrap",
        BADGE_TONE[tone],
        className,
      )}
    >
      {dot ? <span className={cn("h-[6px] w-[6px] shrink-0 rounded-full", BADGE_DOT[tone])} /> : null}
      {Icon ? <Icon className="h-[13px] w-[13px] shrink-0" /> : null}
      {children}
    </span>
  );
}

/** A labelled control with optional helper text under it. */
export function Field({
  label,
  hint,
  htmlFor,
  className,
  children,
}: {
  label: React.ReactNode;
  hint?: React.ReactNode;
  htmlFor?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div className={cn("grid gap-1.5", className)}>
      <label htmlFor={htmlFor} className="text-[12.5px] font-medium text-ink-2">
        {label}
      </label>
      {children}
      {hint ? <span className="text-[12px] text-ink-2">{hint}</span> : null}
    </div>
  );
}

/** The console's native `<select>`, styled once so every page's dropdown matches. */
export const selectClass =
  "h-9 w-full rounded-[9px] border border-line bg-bg px-2.5 text-[13px] text-ink disabled:cursor-not-allowed disabled:opacity-60";

export function Select({
  className,
  children,
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <NativeSelect className={cn(selectClass, className)} {...props}>
      {children}
    </NativeSelect>
  );
}

/** Two fields side by side, stacking under 640px. */
export function FieldGrid({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("grid grid-cols-1 gap-3.5 sm:grid-cols-2", className)}>{children}</div>;
}

/**
 * The redesign's segmented control: a small set of mutually exclusive choices shown at once,
 * used wherever a dropdown of three options would be heavier than the choice deserves.
 */
export function Segmented<T extends string>({
  value,
  options,
  onChange,
  disabled,
  size = "md",
  className,
  "data-testid": testId,
}: {
  value: T;
  options: ReadonlyArray<{ value: T; label: React.ReactNode; "data-testid"?: string }>;
  onChange: (value: T) => void;
  disabled?: boolean;
  /** `sm`: as wide as its labels, for a chart's range (1h / 24h / 7d) or a Cards / List switch. */
  size?: "sm" | "md";
  className?: string;
  "data-testid"?: string;
}) {
  const sm = size === "sm";
  return (
    <div
      data-testid={testId}
      role="group"
      className={cn(
        "flex flex-wrap rounded-[9px] border border-line bg-bg p-[3px]",
        sm ? "inline-flex w-auto rounded-[8px] p-[2px]" : "w-full",
        className,
      )}
    >
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          disabled={disabled}
          aria-pressed={value === o.value}
          onClick={() => onChange(o.value)}
          data-testid={o["data-testid"]}
          className={cn(
            // `basis` rather than a bare `flex-1`: four labels do not fit across a 375px dialog,
            // and they have to wrap onto a second row rather than push the control off the side.
            "min-w-0 rounded-[7px] font-medium whitespace-nowrap transition-colors disabled:cursor-not-allowed disabled:opacity-60",
            sm ? "inline-flex items-center gap-1 px-2.5 py-1 text-[12px]" : "flex-1 basis-[7rem] px-3 py-1.5 text-[13px]",
            value === o.value ? "bg-surface text-ink shadow-xs" : "text-ink-2 hover:text-ink",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/**
 * One rule in a rule list: an optional handle, the name with any badges, the condition under it,
 * and the controls that end the row. Security rules and site rules are the same shape, so they
 * share it rather than each carrying their own grid.
 */
export function RuleRow({
  lead,
  name,
  cond,
  children,
  faded,
  onClick,
  className,
  "data-testid": testId,
}: {
  /** The grip or lock at the start of the row. */
  lead?: React.ReactNode;
  name: React.ReactNode;
  cond?: React.ReactNode;
  /** The action chip, toggles and delete button that close the row. */
  children?: React.ReactNode;
  /** A disabled rule reads as off without leaving the list. */
  faded?: boolean;
  onClick?: () => void;
  className?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      data-testid={testId}
      onClick={onClick}
      className={cn(
        "flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-4 py-3 last:border-b-0",
        faded && "opacity-55",
        onClick && "cursor-pointer hover:bg-bg",
        className,
      )}
    >
      {lead ? <span className="grid shrink-0 place-items-center text-line-2">{lead}</span> : null}
      <div className="min-w-[10rem] flex-1">
        <div className="flex flex-wrap items-center gap-1.5 text-[13.5px] font-semibold text-ink">{name}</div>
        {cond ? <div className="mt-0.5 text-[12.5px] text-ink-2">{cond}</div> : null}
      </div>
      {children ? <div className="flex shrink-0 items-center gap-2">{children}</div> : null}
    </div>
  );
}

export type PillTone = "allow" | "ask" | "block" | "muted";

const PILL_TONE: Record<PillTone, string> = {
  allow: "border-allow-border bg-allow-soft text-allow-fg",
  ask: "border-ask-border bg-ask-soft text-ask-fg",
  block: "border-block-border bg-block-soft text-block-fg",
  muted: "border-line bg-bg-2 text-ink-2",
};

const PILL_DOT: Record<PillTone, string> = {
  allow: "bg-allow",
  ask: "bg-ask",
  block: "bg-block",
  muted: "bg-ink-2/50",
};

/**
 * A state next to a heading: "Running", "Unsecured box", a dev build. One line always: the label
 * is cut with an ellipsis rather than wrapping inside the pill (T-73), and `max-w-full` stops a
 * long one from pushing the page sideways.
 */
export function Pill({
  tone,
  dot = true,
  title,
  children,
  testId,
}: {
  tone: PillTone;
  /** The coloured circle before the label. */
  dot?: boolean;
  title?: string;
  children: React.ReactNode;
  testId?: string;
}) {
  return (
    <span
      title={title}
      data-testid={testId}
      className={cn(
        "inline-flex h-[24px] max-w-full items-center gap-1.5 overflow-hidden whitespace-nowrap rounded-full border px-2.5 text-[12px] font-semibold",
        PILL_TONE[tone],
      )}
    >
      {dot ? <span className={cn("h-[6px] w-[6px] shrink-0 rounded-full", PILL_DOT[tone])} /> : null}
      {/* The ellipsis needs a block box: on the inline-flex above, bare text is an anonymous flex
          item and `text-overflow` is ignored. */}
      <span className="truncate">{children}</span>
    </span>
  );
}

/** A clickable filter: a chip that is on or off, with an optional count ("Gmail 12"). */
export function FilterChip({
  active,
  onClick,
  count,
  children,
  "data-testid": testId,
}: {
  active: boolean;
  onClick: () => void;
  count?: number;
  children: React.ReactNode;
  "data-testid"?: string;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      data-testid={testId}
      className={cn(
        "inline-flex h-[28px] shrink-0 items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium whitespace-nowrap transition-colors",
        active ? "border-brand-border bg-brand-soft text-brand-soft-fg" : "border-line bg-surface text-ink-2 hover:bg-bg-2 hover:text-ink",
      )}
    >
      {children}
      {count !== undefined ? <span className={cn("tabular-nums", active ? "" : "text-ink-2/80")}>{count}</span> : null}
    </button>
  );
}

/**
 * Radio cards: a few choices where each needs a sentence of its own, one picked. A grid of
 * bordered cards, the picked one outlined in the brand colour; one column on a phone.
 */
export function ChoiceCards<T extends string>({
  name,
  value,
  options,
  onChange,
  disabled,
  columns = 3,
  "aria-label": ariaLabel,
  "data-testid": testId,
}: {
  /** The radio group's name; one per page section. */
  name: string;
  value: T;
  options: ReadonlyArray<{
    value: T;
    title: React.ReactNode;
    text?: React.ReactNode;
    icon?: React.ComponentType<{ className?: string }>;
    badge?: React.ReactNode;
    "data-testid"?: string;
  }>;
  onChange: (value: T) => void;
  disabled?: boolean;
  columns?: 2 | 3 | 4;
  "aria-label"?: string;
  "data-testid"?: string;
}) {
  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      data-testid={testId}
      className={cn(
        "grid grid-cols-1 gap-2.5",
        columns === 2 ? "sm:grid-cols-2" : columns === 4 ? "sm:grid-cols-2 lg:grid-cols-4" : "sm:grid-cols-3",
      )}
    >
      {options.map((o) => {
        const on = o.value === value;
        const Icon = o.icon;
        return (
          <label
            key={o.value}
            data-testid={o["data-testid"]}
            className={cn(
              "relative flex cursor-pointer gap-3 rounded-[12px] border bg-surface p-3.5 transition-colors has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-ring/50",
              on ? "border-brand bg-brand-soft/40 shadow-[0_0_0_1px_var(--brand)]" : "border-line hover:border-line-2 hover:bg-bg",
              disabled && "cursor-not-allowed opacity-60",
            )}
          >
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={on}
              disabled={disabled}
              onChange={() => onChange(o.value)}
              className="sr-only"
            />
            <span
              aria-hidden="true"
              className={cn(
                "mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border",
                on ? "border-brand bg-brand" : "border-line-2 bg-surface",
              )}
            >
              {on ? <span className="h-1.5 w-1.5 rounded-full bg-surface" /> : null}
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex flex-wrap items-center gap-1.5 text-[13.5px] font-semibold text-ink">
                {Icon ? <Icon className="h-[15px] w-[15px] shrink-0 text-ink-2" /> : null}
                {o.title}
                {o.badge}
              </span>
              {o.text ? <span className="mt-1 block text-[12.5px] leading-snug text-ink-2">{o.text}</span> : null}
            </span>
          </label>
        );
      })}
    </div>
  );
}

/** The dot a live card carries: green and blinking, or grey and still while paused. */
export function LiveDot({ paused, size = "md", className }: { paused?: boolean; size?: "sm" | "md"; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "inline-block shrink-0 rounded-full",
        size === "sm" ? "h-1.5 w-1.5" : "h-2 w-2",
        paused ? "bg-ink-2/50" : "bg-allow motion-safe:animate-live-blink",
        className,
      )}
    />
  );
}
