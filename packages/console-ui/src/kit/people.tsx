import { cn } from "../lib/utils";
import { hueFor, initialsOf, serviceForHost } from "../lib/host-services";

/**
 * Round marks for who and what: a person's or an agent's avatar, a service's icon for a host, and
 * an overlapping stack of either (the design's `lv-fav`, `tc-av`, `in-av`, `LvStack`). Sizes are
 * pixels; the mark's text scales with them.
 */

function sizeStyle(size: number): React.CSSProperties {
  return { width: size, height: size, fontSize: Math.round(size * 0.42) };
}

const ROUND = "inline-grid shrink-0 place-items-center rounded-full font-bold leading-none select-none";

/** Initials on a colour that follows the name, so the same person looks the same everywhere. */
export function Avatar({ name, size = 24, className }: { name: string; size?: number; className?: string }) {
  return (
    <span
      title={name}
      className={cn(ROUND, "font-semibold text-white", className)}
      style={{ ...sizeStyle(size), background: `oklch(0.6 0.13 ${hueFor(name)})` }}
    >
      {initialsOf(name)}
    </span>
  );
}

/** The service a host belongs to (Gmail, Telegram), or its first letter on grey. */
export function HostIcon({ host, size = 24, className }: { host: string; size?: number; className?: string }) {
  const service = serviceForHost(host);
  if (!service) {
    const letter = [...host.replace(/^www\./, "")][0]?.toUpperCase() ?? "?";
    return (
      <span title={host} className={cn(ROUND, "border border-line bg-bg-2 text-ink-2", className)} style={sizeStyle(size)}>
        {letter}
      </span>
    );
  }
  return (
    <span title={service.name} className={cn(ROUND, "text-white", className)} style={{ ...sizeStyle(size), background: service.color }}>
      {service.mark}
    </span>
  );
}

/**
 * Marks overlapping by a third, each ringed in the card's colour so the overlap reads in both
 * themes; past `max`, a "+N" mark.
 */
export function AvatarStack({
  items,
  max = 4,
  size = 24,
  label,
  className,
}: {
  /** `Avatar`s or `HostIcon`s, in order. */
  items: React.ReactNode[];
  max?: number;
  size?: number;
  /** Read out instead of the marks: "Anna, Luca and 2 more". */
  label?: string;
  className?: string;
}) {
  const shown = items.slice(0, max);
  const more = items.length - shown.length;
  return (
    <span className={cn("inline-flex items-center", className)} role={label ? "img" : undefined} aria-label={label}>
      {shown.map((item, i) => (
        <span
          key={i}
          aria-hidden={label ? true : undefined}
          className="inline-flex rounded-full ring-2 ring-surface"
          style={i ? { marginLeft: -Math.round(size * 0.3) } : undefined}
        >
          {item}
        </span>
      ))}
      {more > 0 ? (
        <span
          aria-hidden={label ? true : undefined}
          className={cn(ROUND, "bg-bg-2 font-semibold text-ink-2 ring-2 ring-surface")}
          style={{ ...sizeStyle(size), marginLeft: -Math.round(size * 0.3), fontSize: Math.round(size * 0.38) }}
        >
          +{more}
        </span>
      ) : null}
    </span>
  );
}
