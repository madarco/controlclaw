export const HOUR_MS = 60 * 60 * 1000;
export const DAY_MS = 24 * HOUR_MS;

/**
 * Today against yesterday at the same time, in percent, rounded. Null when yesterday had nothing:
 * "+∞%" helps nobody, so the card shows no badge then.
 */
export function changePct(today: number, yesterday: number): number | null {
  if (yesterday <= 0) return null;
  return Math.round(((today - yesterday) / yesterday) * 100);
}

/** "+12%", "−8%", "0%"; null passes through. A real minus sign, so the column lines up. */
export function changeLabel(pct: number | null): string | null {
  if (pct === null) return null;
  if (pct > 0) return `+${pct}%`;
  if (pct < 0) return `−${Math.abs(pct)}%`;
  return "0%";
}
