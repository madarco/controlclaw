/**
 * The refusal a change gets when it needs a confirmation code and the firewall has nobody to send
 * one to (T-83, `packages/mitm-agent/src/consent-codes.ts` → `noRecipients`).
 *
 * The firewall writes the sentence, because only the firewall knows how many people the agents have
 * allowed. What the console adds is the way there: both refusals happen on the Firewall page, which
 * is where "Who gets confirmation codes" lives, so the link is an anchor rather than a route.
 *
 * Matched on the message and not on `data`, deliberately. `data` carries the flag, but the console's
 * change views keep only `error` — a string — and threading a structured field through every one of
 * them to decide whether to show a link would be a lot of surface for a link. The sentence is the
 * firewall's own and is asserted on both sides, so it cannot drift silently.
 */
export const CODE_RECIPIENTS_ANCHOR = "code-recipients";

export function isNoRecipients(message: string | null | undefined): boolean {
  return !!message && /Nobody is set to get confirmation codes/i.test(message);
}

/** Bring "Who gets confirmation codes" into view; it is further down the same page. */
export function showCodeRecipients(): void {
  const el = typeof document === "undefined" ? null : document.getElementById(CODE_RECIPIENTS_ANCHOR);
  if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  else if (typeof window !== "undefined") window.location.hash = `#${CODE_RECIPIENTS_ANCHOR}`;
}
