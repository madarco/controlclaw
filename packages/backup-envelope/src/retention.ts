/**
 * Which backups survive. One grid, shared by the nightly sweep that applies it and the console that
 * tells someone how long a backup has left, because two implementations of "how long do I keep this"
 * is how a customer loses the one they needed.
 *
 * The grid: the newest backup of each of the last DAILY_KEEP days, plus the newest of each of the
 * last WEEKLY_KEEP weeks. A backup can satisfy both and is counted once. Everything else falls out.
 *
 * Deliberately not clever:
 *   - days and weeks are UTC, so the grid does not shift under a customer who moves timezone;
 *   - a week starts on Monday, computed from the epoch rather than from `now`, so the same backup
 *     never changes week between two runs of the sweep;
 *   - the newest backup is always kept, even if the grid is otherwise empty, so no sweep can ever
 *     leave an agent with nothing;
 *   - a backup that is still running is never swept: it has no bytes to bill and no row to reuse,
 *     and the sweep is not the thing that should decide an upload has failed.
 */

export const DAILY_KEEP = 7;
export const WEEKLY_KEEP = 4;

/**
 * Grace between falling out of the grid and being deleted. A restore started just before the sweep
 * must not have its object pulled out from under it, and someone who sees "expiring" has a day to
 * say so.
 */
export const EXPIRY_GRACE_MS = 24 * 60 * 60 * 1000;

const DAY_MS = 24 * 60 * 60 * 1000;

export interface RetainableBackup {
  id: string;
  /** When the backup was taken. Rows are grouped per agent by the caller. */
  takenAt: Date;
}

export interface RetentionPlan<T extends RetainableBackup> {
  keep: T[];
  expire: T[];
  /** Why each kept row is kept, for the console's "kept as" line. */
  reason: Map<string, "daily" | "weekly" | "newest">;
}

export function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Monday-anchored week index since the epoch. 1970-01-01 was a Thursday, hence the +3. */
export function weekKey(d: Date): number {
  return Math.floor((Math.floor(d.getTime() / DAY_MS) + 3) / 7);
}

export function planRetention<T extends RetainableBackup>(backups: T[]): RetentionPlan<T> {
  const newestFirst = [...backups].sort((a, b) => b.takenAt.getTime() - a.takenAt.getTime());
  const reason = new Map<string, "daily" | "weekly" | "newest">();

  const days = new Set<string>();
  const weeks = new Set<number>();
  for (const b of newestFirst) {
    const day = dayKey(b.takenAt);
    if (!days.has(day)) {
      days.add(day);
      if (days.size <= DAILY_KEEP) reason.set(b.id, "daily");
    }
  }
  for (const b of newestFirst) {
    const week = weekKey(b.takenAt);
    if (!weeks.has(week)) {
      weeks.add(week);
      if (weeks.size <= WEEKLY_KEEP && !reason.has(b.id)) reason.set(b.id, "weekly");
    }
  }
  // Never nothing. If the grid somehow held none of them, the newest one still stands.
  if (newestFirst.length > 0 && reason.size === 0) reason.set(newestFirst[0]!.id, "newest");

  return {
    keep: newestFirst.filter((b) => reason.has(b.id)),
    expire: newestFirst.filter((b) => !reason.has(b.id)),
    reason,
  };
}

/** When a row that just fell out of the grid should actually be deleted. */
export function expiryFor(now: Date): Date {
  return new Date(now.getTime() + EXPIRY_GRACE_MS);
}
