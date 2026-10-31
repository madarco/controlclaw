/**
 * Fired by the single-box update flows when their change settles, so the header re-reads the plan
 * rather than keeping a count that the update just made wrong.
 */
export const UPDATES_CHANGED = "controlclaw:updates-changed";

/** Fired by the provider when a batch settles, for pages that read their own update state. */
export const BATCH_SETTLED = "controlclaw:update-all-settled";

export function announceUpdatesChanged(): void {
  if (typeof window !== "undefined") window.dispatchEvent(new Event(UPDATES_CHANGED));
}
