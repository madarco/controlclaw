/**
 * What a firewall change's status means to the console, away from React so it can be read and
 * tested on its own. The hook that follows a change lives in
 * `app/(channels)/components/useFirewallChange.ts`.
 */

/**
 * `awaiting_login` is the ChatGPT device flow; `awaiting_authorization` an app connection waiting
 * for an OAuth sign-in at the provider. Both mean "the person has to do something elsewhere now".
 *
 * `unconfirmed` is a pairing approval the agent box never answered: terminal, but not a failure —
 * the firewall keeps asking the box and the answer arrives as its own row in the history.
 *
 * `open` is shell access (`app/(ssh)`): the grant went through and a session is now live. `closed`
 * is shaped like `cancelled` for the same reason.
 */
export const FIREWALL_CHANGE_STATUSES = [
  "queued",
  "awaiting_code",
  "awaiting_login",
  "awaiting_authorization",
  "applied",
  "open",
  "closed",
  "failed",
  "expired",
  "cancelled",
  "unconfirmed",
  // A whole-organization update only (T-100). Its code is confirmed at `running` rather than at the
  // end, because what the code authorised then takes tens of minutes of boxes installing; `done` is
  // where every other change's `applied` is. Neither is produced by any other feature, and
  // `endsTheForm` leaves both alone: the batch's own `isFinished` decides when its loop stops.
  "running",
  "done",
] as const;
export type FirewallChangeStatus = (typeof FIREWALL_CHANGE_STATUSES)[number];

/**
 * Whether the form that started this change has nothing left to do: it landed, or the agent never
 * confirmed it and no retry is possible. A dialog that collected a token closes on these.
 *
 * `failed` and `expired` are terminal too and deliberately NOT here: the error belongs in the
 * dialog, next to the field that has to change. `cancelled` and `closed` are the person's own
 * doing, and whoever cancelled has already closed what they were looking at.
 */
export function endsTheForm(status: FirewallChangeStatus): boolean {
  return status === "applied" || status === "open" || status === "unconfirmed";
}

/**
 * Whether dismissing the form that collected a change should also cancel it.
 *
 * Not once the firewall has sent a code: from then on the change belongs to the code dialog, which
 * is the only place that can finish it and the only place with a button that says "Cancel change".
 * A dialog still mounted underneath reports a click INSIDE the code dialog as an outside click of
 * its own, and that was enough to throw away changes before anybody had typed a digit — two of
 * them in one afternoon on production, cancelled 6 and 22 seconds in with all five tries unused.
 *
 * A terminal change has nothing left to cancel; a change that is only queued, or waiting for a
 * sign-in the dismissed dialog was itself showing, is the person's to abandon.
 */
export function closingCancels(status: FirewallChangeStatus | null | undefined): boolean {
  if (!status) return false;
  return status === "queued" || status === "awaiting_login" || status === "awaiting_authorization";
}
