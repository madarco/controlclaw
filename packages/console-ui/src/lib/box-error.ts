/**
 * What the console shows for an error that came back from an agent box.
 *
 * Errors travel up three machines before anybody reads them. OpenClaw's gateway says
 * `gateway call config.patch timed out`, the vm-agent returns it as a 500, the firewall prefixes
 * its HTTP status, and the console used to render the result verbatim: on production (a customer's org,
 * 2026-09-28) a customer adding their first Telegram bot was shown
 *
 *   agent 500: gateway call config.patch timed out
 *
 * which says nothing about what happened and nothing about what to do — and in that case was not
 * even true: the bot was running.
 *
 * So the raw text is mapped to a sentence in the customer's terms, with the next step in it. The
 * original still goes to the logs and to the firewall's own records, which is where somebody
 * debugging it looks. Anything unrecognised is passed through rather than replaced by a vague
 * catch-all: a specific message we did not anticipate beats a generic one we did.
 *
 * `tailscale-box-error.ts` does the same job for one feature's own special case and is layered on
 * top of this one.
 */

/** The firewall prefixes an agent refusal with its HTTP status. The person needs the sentence. */
export function stripAgentStatus(message: string): string {
  return message.replace(/^agent \d{3}: /, "");
}

type Rule = { match: RegExp; say: (m: RegExpMatchArray) => string };

/**
 * Ordered, first match wins. Each one names a real shape seen on production or in the source that
 * produces it, never a guess at what an error might look like.
 */
const RULES: Rule[] = [
  {
    // `packages/vm-agent/src/gateway.ts`: the gateway RPC ran past its budget. Since T-86 a write
    // that does this is confirmed from the box rather than failed, so what is left here is a read.
    match: /gateway call ([\w.]+) timed out/i,
    say: () => "Your agent took too long to answer. It is usually busy rather than broken — wait a moment and try again.",
  },
  {
    // The socket went away mid-call, which is what a gateway restart looks like from here.
    match: /gateway disconnected|gateway not connected/i,
    say: () => "Your agent restarted while it was doing this. Try again in a moment.",
  },
  {
    match: /OpenClaw is not running on this box|The agent is not running/i,
    say: () => "OpenClaw is not running on this agent. Start it from the agent's page, then try again.",
  },
  {
    // The firewall's `AgentTimeoutError` says "did not"; the console's own fallback for an
    // unconfirmed channel change (channels.server.ts) says "didn’t".
    match: /The agent did(?: not|n[’']t) answer in time/i,
    say: () => "Your agent did not answer in time. If it was in the middle of this, it will show here within a minute.",
  },
  {
    match: /\b(ECONNREFUSED|ENOTFOUND|EHOSTUNREACH|ETIMEDOUT)\b|fetch failed/,
    say: () => "Your agent could not be reached. Check that it is running, then try again.",
  },
  {
    // OpenClaw 2026.9 refuses a `config.patch` that takes entries out of a list unless the path is
    // named. Agents from before the fix did not name them: "Remove fallback" and replacing a
    // fallback came back as `model: config.patch would remove entries from array path(s): …`.
    match: /config\.patch would remove entries from array path/i,
    say: () => "Your agent could not remove the old setting, so nothing changed. Update the agent from its page, then try again.",
  },
  {
    // OpenClaw's own words for a config write that raced another one. Ours retries once; a
    // message that still reaches here means both tries lost.
    match: /config changed since last load/i,
    say: () => "Your agent was changing its settings at the same time. Try again.",
  },
];

/**
 * A box error as the console should show it.
 *
 * Always `string | null`, with no overload promising otherwise: a non-empty input can still map
 * to null (`"agent 500: "` is a status prefix and nothing else), and a caller that believed the
 * non-null overload would render an empty status line. Callers supply their own fallback.
 */
export function boxErrorMessage(message: string | null | undefined): string | null {
  if (!message) return null;
  const text = stripAgentStatus(message).trim();
  if (!text) return null;
  for (const rule of RULES) {
    const m = text.match(rule.match);
    if (m) return rule.say(m);
  }
  return text;
}
