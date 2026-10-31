/**
 * Formatting that must not depend on where the reader is.
 *
 * Anything a server component renders is painted twice — once on the server, once in the browser —
 * and a `toLocaleString()` with no locale reads the ambient one: `en-US` and UTC on the server,
 * whatever the person's machine says in the browser. The two strings differ, React reports a
 * hydration mismatch (minified error #418) and bails out of hydrating that tree, which takes the
 * rest of the page's client behaviour down with it.
 *
 * So anything a server component paints either pins its locale here, or is rendered in the browser
 * only — `RelativeTime` does the second, and is the right answer for a timestamp somebody reads as
 * "how long ago".
 */

/** A count, grouped the same way everywhere: 1,234. */
export function countLabel(n: number): string {
  return n.toLocaleString("en-US");
}

/** The day a monthly allowance rolls over, in UTC because that is where the month is counted. */
export function resetDayLabel(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", { month: "long", day: "numeric", timeZone: "UTC" });
}
