import { cn } from "../lib/utils";

export type StatusPillTone = "allow" | "ask" | "block" | "muted";

export const STATUS_PILL_TONE: Record<StatusPillTone, string> = {
  allow: "bg-allow/10 text-allow",
  ask: "bg-ask/15 text-ask",
  block: "bg-block/10 text-block",
  muted: "bg-bg-2 text-ink-2",
};

/**
 * Longer than this, a label is a sentence — in practice an error from the firewall or the agent box
 * — and it is drawn as a small box that wraps, not as a pill. Every short status ("Connected",
 * "Sign in again: the access token expired") stays under it, and 40 characters still fit on one
 * line in the narrowest card row at 375px, so a pill is not cut in practice.
 */
const PILL_MAX_CHARS = 40;

/**
 * The status label on a card: "Connected", "Not set up", "2 of 3 agents can use it".
 *
 * A pill never wraps. A label that wraps inside a rounded pill breaks out of its own shape on a
 * phone, which is what the Google card did at 390px. It is capped at its row's width and ends in an
 * ellipsis rather than pushing the page sideways.
 *
 * An error message is not cut, though: the part that says what to do is usually at the end
 * ("…Connect the account again"), and a `title` tooltip never shows on a phone. So a label past
 * `PILL_MAX_CHARS` becomes a rounded box that wraps like the text it is.
 */
export function StatusPill({
  tone,
  dot = true,
  className,
  children,
  "data-testid": testId,
}: {
  tone: StatusPillTone;
  dot?: boolean;
  className?: string;
  children: string;
  "data-testid"?: string;
}) {
  if (children.length > PILL_MAX_CHARS) {
    return (
      <span
        className={cn("inline-flex max-w-full items-start gap-1.5 rounded-[8px] px-2 py-1 font-medium break-words", STATUS_PILL_TONE[tone], className)}
        data-testid={testId}
      >
        {/* The dot sits against the first line, not in the middle of a paragraph. */}
        {dot ? <span className="mt-[0.45em] h-1.5 w-1.5 shrink-0 rounded-full bg-current" /> : null}
        <span className="min-w-0">{children}</span>
      </span>
    );
  }

  return (
    <span
      title={children}
      className={cn(
        // `shrink-0` with `max-w-full`: in a wrapping row the pill moves to its own line before it
        // gives up any text, and only a label longer than the whole row is cut.
        "inline-flex max-w-full shrink-0 items-center gap-1 overflow-hidden rounded-full px-2 py-0.5 font-medium whitespace-nowrap",
        STATUS_PILL_TONE[tone],
        className,
      )}
      data-testid={testId}
    >
      {dot ? <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current" /> : null}
      {/* The ellipsis needs a block container: on the inline-flex above the text would be an
          anonymous flex item, and `text-overflow` is ignored there. */}
      <span className="truncate">{children}</span>
    </span>
  );
}
