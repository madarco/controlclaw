"use client";

import { useState } from "react";
import { cn } from "../../lib/utils";
import { connectorIconUrl } from "../../lib/connector-icons";
import { hueFor, serviceForHost } from "../../lib/host-services";

/**
 * The square logo tile in front of an app (the design's `in-logo`).
 *
 * A catalog app with a bundled logo (`service` and `icon`) shows it on a white tile, so dark logos
 * stay visible in dark mode. Otherwise, or when the image does not load, a mark in white on the
 * app's colour: the official four pass their own; a catalog app gets the host map's colour when its
 * home page is a host the console knows (GitHub, Slack), or a colour that follows its name.
 */
export function AppLogo({
  name,
  mark,
  color,
  home,
  service,
  icon,
  size = 40,
  className,
}: {
  name: string;
  mark?: string;
  color?: string;
  /** The app's home page, to find its colour in the host map. */
  home?: string;
  /** The catalog id, for the bundled logo. */
  service?: string;
  /** The catalog has a logo for `service`; without it no image is requested. */
  icon?: boolean;
  size?: number;
  className?: string;
}) {
  const src = icon && service && !mark ? connectorIconUrl(service) : null;
  const [broken, setBroken] = useState<string | null>(null);
  const radius = Math.round(size * 0.26);

  if (src && broken !== src) {
    const pad = Math.max(1, Math.round(size * 0.12));
    return (
      <span
        aria-hidden="true"
        className={cn("inline-grid shrink-0 place-items-center bg-white ring-1 ring-line ring-inset select-none", className)}
        style={{ width: size, height: size, borderRadius: radius, padding: pad }}
        data-testid="app-logo-image"
      >
        <img
          src={src}
          alt=""
          width={size - 2 * pad}
          height={size - 2 * pad}
          loading="lazy"
          decoding="async"
          draggable={false}
          onError={() => setBroken(src)}
          className="h-full w-full object-contain"
          style={{ borderRadius: Math.max(0, radius - pad) }}
        />
      </span>
    );
  }

  const known = !mark && !color && home ? serviceForHome(home) : null;
  const m = mark ?? known?.mark ?? ([...name.trim()][0]?.toUpperCase() || "?");
  const bg = color ?? known?.color ?? `oklch(0.55 0.14 ${hueFor(name)})`;
  return (
    <span
      aria-hidden="true"
      className={cn("inline-grid shrink-0 place-items-center font-bold leading-none text-white shadow-[inset_0_-2px_0_rgb(0_0_0/0.12)] select-none", className)}
      style={{ width: size, height: size, borderRadius: radius, fontSize: Math.round(size * (m.length > 1 ? 0.34 : 0.42)), background: bg }}
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
