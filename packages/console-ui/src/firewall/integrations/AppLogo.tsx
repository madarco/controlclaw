import { cn } from "../../lib/utils";
import { hueFor, serviceForHost } from "../../lib/host-services";

/**
 * The square logo tile in front of an app (the design's `in-logo`): a mark in white on the app's
 * colour. The official four pass their own; a catalog app gets the host map's colour when its home
 * page is a host the console knows (GitHub, Slack), or a colour that follows its name.
 */
export function AppLogo({
  name,
  mark,
  color,
  home,
  size = 40,
  className,
}: {
  name: string;
  mark?: string;
  color?: string;
  /** The app's home page, to find its colour in the host map. */
  home?: string;
  size?: number;
  className?: string;
}) {
  const known = !mark && !color && home ? serviceForHome(home) : null;
  const m = mark ?? known?.mark ?? ([...name.trim()][0]?.toUpperCase() || "?");
  const bg = color ?? known?.color ?? `oklch(0.55 0.14 ${hueFor(name)})`;
  return (
    <span
      aria-hidden="true"
      className={cn("inline-grid shrink-0 place-items-center font-bold leading-none text-white shadow-[inset_0_-2px_0_rgb(0_0_0/0.12)] select-none", className)}
      style={{ width: size, height: size, borderRadius: Math.round(size * 0.26), fontSize: Math.round(size * (m.length > 1 ? 0.34 : 0.42)), background: bg }}
    >
      {m}
    </span>
  );
}

function serviceForHome(home: string) {
  try {
    return serviceForHost(new URL(home).host);
  } catch {
    return null;
  }
}
