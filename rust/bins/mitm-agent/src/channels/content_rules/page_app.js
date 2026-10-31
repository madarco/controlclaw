const el = (id) => document.getElementById(id);
const CHANNELS = { telegram: "Telegram", slack: "Slack", email: "Email", web: "Website request", webhook: "Webhook", teamchat: "Team chat", voice: "Meeting or call", apps: "App action" };
const OUTCOMES = { waiting: "waiting", sent: "sent on approval", not_sent: "not sent", expired: "dropped after 24 hours", send_failed: "Send pressed, could not be sent", restarted: "dropped when the firewall restarted", nobody_asked: "stopped, nobody could be asked", too_many: "stopped, too many messages were waiting", refused: "stopped, the agent may not send it that way" };
let oldest = null, agents = {};
const fmt = (ms) => new Date(ms).toLocaleString();
const node = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = text; return n; };
function where(e) {
  const way = e.direction === "in" ? "to the agent" : "from the agent";
  const agent = e.vmId ? (agents[e.vmId] || e.vmId) : "";
  return [(CHANNELS[e.channel] || e.channel) + ", " + way, agent && "agent " + agent].filter(Boolean).join(" · ");
}
function body(card, e) {
  card.append(node("span", "mt-2 block text-[13px] text-ink [overflow-wrap:anywhere]", "Reason: " + e.rule.reason));
  if (e.rule.ai === "found") card.append(node("span", "mt-1 block text-[12.5px] text-ink-2 [overflow-wrap:anywhere]", "Found by the AI, from the rule's policy."));
  else if (e.rule.ai === "failed") card.append(node("span", "mt-1 block text-[12.5px] text-ink-2 [overflow-wrap:anywhere]", "The AI check could not run, so the rule acted."));
  if (e.withheld === "flood") card.append(node("span", "mt-2 block text-[12.5px] text-ink-2 italic", e.count + " more " + (e.count === 1 ? "message" : "messages") + " to this agent were stopped in this minute. Their text is not kept."));
  else if (e.text === null) card.append(node("span", "mt-2 block text-[12.5px] text-ink-2 italic", "The text is not kept: the rule looks for secrets."));
  else card.append(node("pre", "mt-2 max-h-[18rem] overflow-auto rounded-lg bg-bg px-3 py-2 font-mono text-[12.5px] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]", e.text + (e.cut ? " (cut)" : "")));
}
function heldCard(h) {
  const card = node("article", "min-w-0 rounded-xl border border-line px-4 py-3.5"), head = node("div", "flex flex-wrap items-baseline gap-x-2 gap-y-1");
  head.append(node("span", "text-[14px] font-semibold text-ink [overflow-wrap:anywhere]", h.rule.name), node("span", "inline-block rounded border px-1.5 font-mono text-[11px] leading-[1.6] uppercase border-line-2 text-ink-2", "Held"));
  card.append(head, node("span", "mt-1 block text-[12.5px] text-ink-2 [overflow-wrap:anywhere]", h.what + " for " + h.where + " · " + where(h)), node("span", "mt-1 block text-[12.5px] text-ink-2 [overflow-wrap:anywhere]", "Held " + fmt(h.at) + " · dropped " + fmt(h.expiresAt) + " if nobody answers"));
  body(card, h);
  return card;
}
function stoppedCard(e) {
  const card = node("article", "min-w-0 rounded-xl border border-line px-4 py-3.5"), head = node("div", "flex flex-wrap items-baseline gap-x-2 gap-y-1");
  const label = e.action === "hold" ? "Held" + (e.outcome ? ": " + (OUTCOMES[e.outcome] || e.outcome) : "") : "Stopped";
  head.append(node("span", "text-[14px] font-semibold text-ink [overflow-wrap:anywhere]", e.rule.name), node("span", "inline-block rounded border px-1.5 font-mono text-[11px] leading-[1.6] uppercase " + (e.action === "hold" ? "border-line-2 text-ink-2" : "border-block text-block"), label));
  card.append(head, node("span", "mt-1 block text-[12.5px] text-ink-2 [overflow-wrap:anywhere]", fmt(e.at) + " · " + where(e)));
  body(card, e);
  return card;
}
async function load(more) {
  el("error").textContent = "";
  try {
    const r = await fetch("data" + (more && oldest ? "?before=" + oldest.at + "&beforeId=" + encodeURIComponent(oldest.id) : ""), { credentials: "same-origin" });
    if (!r.ok) throw new Error(r.status === 403 ? "Access expired. Open the content rules record from the console again." : "Could not load. Try again.");
    const data = await r.json();
    agents = Object.assign(agents, data.agents);
    if (!more) {
      el("held").replaceChildren(...(data.held.length ? data.held.map(heldCard) : [node("p", "text-[13px] text-ink-2", "Nothing is waiting.")]));
      el("stopped").replaceChildren();
    }
    for (const e of data.stopped) el("stopped").append(stoppedCard(e));
    if (!more && !data.stopped.length) el("stopped").append(node("p", "text-[13px] text-ink-2", "Nothing was held or stopped in the last seven days."));
    oldest = data.stopped.length ? data.stopped[data.stopped.length - 1] : oldest;
    el("more").hidden = data.stopped.length < 50;
  } catch (e) { el("error").textContent = e.message; }
}
el("more").onclick = () => load(true);
load(false);
