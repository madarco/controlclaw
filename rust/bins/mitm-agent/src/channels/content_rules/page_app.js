(() => {
  const K = window.ccKit, h = K.h, icon = K.icon;
  const CHANNELS = { telegram: "Telegram", slack: "Slack", email: "Email", web: "Website request", webhook: "Webhook", teamchat: "Team chat", voice: "Meeting or call", apps: "App action" };
  const CH_ICON = { telegram: "send", slack: "message", email: "mail", web: "globe", webhook: "webhook", teamchat: "message", voice: "phone", apps: "app" };
  const OUT = {
    waiting: ["Held", "ask"],
    sent: ["Sent on approval", "allow"],
    not_sent: ["Not sent", "muted"],
    expired: ["Dropped after 24 h", "muted"],
    restarted: ["Dropped at a restart", "muted"],
    send_failed: ["Send failed", "block"],
    nobody_asked: ["Stopped: nobody to ask", "block"],
    too_many: ["Stopped: too many waiting", "block"],
    refused: ["Stopped: not its own way", "block"],
  };
  const TILE = { ask: "bg-ask-soft text-ask-fg", allow: "bg-allow-soft text-allow-fg", block: "bg-block-soft text-block-fg", muted: "bg-bg-2 text-ink-2" };
  const PAGE = 50;
  const ANSWERED = new Set(["sent", "not_sent", "send_failed"]);
  const root = document.getElementById("content-rules");
  let held = [], stopped = [], agents = {}, filter = "all", more = false, loaded = false, error = null, busy = false, firstOpen = null;
  const opened = new Set();

  // "Edit rules": the console's Security rules → Messages, or the panel's Security page on a
  // standalone firewall (page.rs puts it on the mount point; empty when there is none).
  const editUrl = root.getAttribute("data-edit-url") || null;

  function outcome(e) {
    if (e.action === "hold") return OUT[e.outcome || "waiting"] || [e.outcome, "muted"];
    return ["Stopped", "block"];
  }
  /** "tomorrow 09:38" or "09:38": a hold lasts a day. */
  function until(at) {
    const d = new Date(at), today = new Date();
    return d.toDateString() === today.toDateString() ? K.clock(at) : (d.getDate() === new Date(today.getTime() + 86400000).getDate() ? "tomorrow " + K.clock(at) : K.when(at));
  }
  const agentName = (vm) => (vm ? agents[vm] || vm : "");

  /** Channel, direction and agent, one line. */
  function whereLine(e) {
    const agent = agentName(e.vmId);
    return h(
      "span",
      { class: "inline-flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 [overflow-wrap:anywhere]" },
      icon(CH_ICON[e.channel] || "message", "h-3 w-3 shrink-0"),
      CHANNELS[e.channel] || e.channel,
      h("span", { class: "inline-flex items-center gap-0.5" }, icon(e.direction === "in" ? "arrowDownLeft" : "arrowUpRight", "h-3 w-3 shrink-0"), e.direction === "in" ? "to" : "from"),
      agent ? h("span", { class: "font-mono text-[11.5px]" }, agent) : "an agent",
    );
  }

  function chTile(e, tone) {
    return h("span", { class: "grid h-8 w-8 shrink-0 place-items-center rounded-lg " + (TILE[tone] || TILE.muted) }, icon(CH_ICON[e.channel] || "message", "h-[15px] w-[15px]"));
  }

  /** The reason, the AI's note, and the text (or why it is not kept). */
  function details(e) {
    const ai =
      e.rule.ai === "found"
        ? h("p", { class: "mt-2 flex items-center gap-1.5 text-[12.5px] text-brand-ink" }, icon("sparkles", "h-3 w-3 shrink-0"), "Found by the AI, from the rule's policy.")
        : e.rule.ai === "failed"
          ? h("p", { class: "mt-2 flex items-center gap-1.5 text-[12.5px] text-ask-fg" }, icon("alert", "h-3 w-3 shrink-0"), "The AI check could not run, so the rule acted.")
          : null;
    let text;
    if (e.withheld === "flood") text = h("p", { class: "mt-3 text-[12.5px] text-ink-2 italic" }, e.count + " more " + (e.count === 1 ? "message" : "messages") + " to this agent were stopped in this minute. Their text is not kept.");
    else if (e.text === null || e.text === undefined) text = h("p", { class: "mt-3 flex items-center gap-1.5 text-[12.5px] text-ink-2 italic" }, icon("lock", "h-3 w-3 shrink-0"), "The text is not kept: the rule looks for secrets.");
    else text = h("pre", { class: "mt-3 max-h-[18rem] overflow-auto rounded-lg border border-line bg-bg px-3 py-2 font-mono text-[12.5px] leading-[1.6] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]" }, e.text, e.cut ? h("span", { class: "text-ink-2" }, " (cut)") : null);
    return h(
      "div",
      { class: "min-w-0" },
      h("div", { class: "text-[11px] font-semibold tracking-[0.06em] text-ink-2 uppercase" }, "Reason"),
      h("p", { class: "mt-0.5 text-[13px] text-ink [overflow-wrap:anywhere]" }, e.rule.reason),
      ai,
      text,
    );
  }

  function heldRow(m) {
    return h(
      "div",
      { class: "border-t border-line px-4 py-4 first:border-t-0" },
      h(
        "div",
        { class: "flex flex-wrap items-start gap-3" },
        chTile(m, "ask"),
        h(
          "div",
          { class: "min-w-0 flex-1 basis-[220px]" },
          h("div", { class: "text-[13.5px] font-semibold text-ink [overflow-wrap:anywhere]" }, m.rule.name),
          h("div", { class: "mt-0.5 text-[12.5px] text-ink-2 [overflow-wrap:anywhere]" }, m.what + " for " + m.where + (m.vmId ? " · from " + agentName(m.vmId) : "")),
        ),
        h(
          "div",
          { class: "flex flex-col items-start gap-1 sm:items-end" },
          K.pill("Held " + K.clock(m.at), "ask", "clock"),
          h("span", { class: "text-[12px] text-ink-2" }, "dropped " + until(m.expiresAt) + " if nobody answers"),
        ),
      ),
      h("div", { class: "mt-3 sm:pl-11" }, details(m)),
    );
  }

  function heldCard() {
    const n = held.length;
    return h(
      "section",
      { "aria-labelledby": "held-title", class: "mb-5 overflow-hidden rounded-xl border bg-surface " + (n ? "border-ask-border" : "border-line") },
      K.cardHead(
        h("span", { class: "inline-flex items-center gap-2" }, "Held now", n ? K.pill(String(n), "ask") : null),
        null,
        h("span", { class: "hidden text-[12px] text-ink-2 sm:inline" }, "Send and Don't send are in the firewall's Telegram message"),
        "held-title",
      ),
      n ? held.map(heldRow) : h("p", { class: "flex items-center gap-2 px-4 py-4 text-[13px] text-ink-2" }, icon("checkCircle", "h-4 w-4 shrink-0 text-allow-fg"), "Nothing is waiting."),
      h("p", { class: "flex items-start gap-1.5 border-t border-line bg-bg-2 px-4 py-2.5 text-[12px] text-ink-2" }, icon("info", "mt-px h-3.5 w-3.5 shrink-0"), "Nothing is sent from this page. A held message is dropped, not sent, if the firewall restarts."),
    );
  }

  function row(e) {
    const [label, tone] = outcome(e);
    const id = "cr-" + e.id + "-" + e.at;
    const open = opened.has(id);
    const btn = h(
      "button",
      {
        type: "button",
        "aria-expanded": open ? "true" : "false",
        "aria-controls": id,
        class: "flex w-full min-w-0 cursor-pointer items-center gap-3 px-4 py-3 text-left hover:bg-bg " + K.FOCUS,
        onclick: () => {
          if (opened.has(id)) opened.delete(id);
          else opened.add(id);
          render();
        },
      },
      chTile(e, tone),
      h(
        "span",
        { class: "flex min-w-0 flex-1 flex-col" },
        h("span", { class: "text-[13.5px] font-semibold text-ink [overflow-wrap:anywhere]" }, e.rule.name),
        h("span", { class: "mt-0.5 text-[12.5px] text-ink-2" }, whereLine(e)),
      ),
      h("span", { class: "hidden sm:inline-flex" }, K.pill(label, tone)),
      h("span", { class: "shrink-0 text-right text-[12.5px] whitespace-nowrap text-ink-2 tabular-nums" }, K.clock(e.at)),
      icon("chevronRight", "h-4 w-4 shrink-0 text-ink-2 transition-transform " + (open ? "rotate-90" : "")),
    );
    return h(
      "div",
      { class: "border-b border-line last:border-b-0" },
      btn,
      open ? h("div", { id, class: "px-4 pb-4 sm:pl-[60px]" }, h("div", { class: "mb-3 sm:hidden" }, K.pill(label, tone)), details(e)) : null,
    );
  }

  function listCard() {
    const shown = stopped.filter((e) => filter === "all" || (filter === "held" ? e.action === "hold" : e.action !== "hold"));
    const body = shown.length
      ? K.groupByDay(shown, (e) => e.at).map((g) => h("div", {}, K.dayHeading(g.label, g.rows.length), g.rows.map(row)))
      : K.empty({
          icon: "shieldCheck",
          title: "Nothing held or stopped",
          text: stopped.length ? "Nothing of this kind in the loaded days." : "No content rule acted in the last seven days.",
        });
    return K.card(
      { "aria-labelledby": "list-title" },
      K.cardHead("Last seven days", shown.length + (more && filter === "all" ? "+" : ""), K.segmented("Show", [{ key: "all", label: "All" }, { key: "held", label: "Held" }, { key: "stopped", label: "Stopped" }], filter, (k) => { filter = k; render(); }), "list-title"),
      body,
      stopped.length
        ? h(
            "div",
            { class: "flex flex-wrap items-center gap-3 border-t border-line px-4 py-3" },
            h("span", { class: "text-[12px] text-ink-2" }, "Newest first."),
            more ? K.button(busy ? "Loading…" : "Load older", { class: "ml-auto", disabled: busy, onClick: () => load(true) }) : null,
          )
        : null,
    );
  }

  function stats() {
    const plus = more ? "+" : "";
    // Answered: someone pressed Send or Don't send. A hold that expired, or was stopped instead, was not.
    const holds = stopped.filter((e) => e.action === "hold" && ANSWERED.has(e.outcome));
    const sent = holds.filter((e) => e.outcome === "sent").length;
    return K.statGrid([
      { label: "Held now", value: held.length, sub: "wait for Send or Don't send", tone: held.length ? "ask" : null },
      { label: "Stopped", value: stopped.filter((e) => e.action !== "hold").length + plus, sub: "last 7 days" },
      { label: "Held, then answered", value: holds.length + plus, sub: holds.length ? sent + " sent, " + (holds.length - sent) + " not" : "last 7 days" },
      { label: "Found by the AI", value: stopped.filter((e) => e.rule.ai === "found").length + plus, sub: "of " + stopped.length + plus },
    ]);
  }

  /** Re-rendering replaces the buttons: put focus back on the one that had it. */
  function focusKey() {
    const a = document.activeElement;
    if (!a || !root.contains(a)) return null;
    if (a.getAttribute("aria-controls")) return '[aria-controls="' + CSS.escape(a.getAttribute("aria-controls")) + '"]';
    if (a.dataset && a.dataset.key) return '[data-key="' + CSS.escape(a.dataset.key) + '"]';
    return null;
  }

  function render() {
    const key = focusKey();
    const head = K.pageHead(
      "Content rules",
      "What your content rules held or stopped in the last seven days, with the reason and the text. Kept on this firewall, encrypted, for seven days. The console sees only which rule acted, where and when.",
      editUrl ? [K.button("Edit rules", { href: editUrl, external: true })] : [],
    );
    const parts = [head];
    if (error) parts.push(h("div", { class: "mb-5" }, K.banner("block", error)));
    if (!loaded && !error) parts.push(K.card({}, K.loading("Reading the record on the firewall…")));
    if (loaded) parts.push(stats(), heldCard(), listCard());
    parts.push(K.footNote("A message stopped for a password or a key is listed without its text: this page would be one more place the key is kept."));
    root.replaceChildren(...parts);
    const again = key && root.querySelector(key);
    if (again) again.focus();
  }

  async function load(older) {
    if (busy) return;
    busy = true;
    error = null;
    if (older) render();
    const last = stopped[stopped.length - 1];
    try {
      const r = await fetch("data" + (older && last ? "?before=" + last.at + "&beforeId=" + encodeURIComponent(last.id) : ""), { credentials: "same-origin" });
      if (!r.ok) throw new Error(r.status === 403 ? "Access expired. Open What was stopped from the console again." : "Could not load. Try again.");
      const data = await r.json();
      agents = Object.assign(agents, data.agents || {});
      if (!older) {
        held = data.held || [];
        stopped = [];
      }
      stopped = stopped.concat(data.stopped || []);
      more = (data.stopped || []).length >= PAGE;
      if (!loaded && stopped.length && firstOpen === null) {
        firstOpen = "cr-" + stopped[0].id + "-" + stopped[0].at;
        opened.add(firstOpen);
      }
      loaded = true;
    } catch (e) {
      error = e.message;
    }
    busy = false;
    render();
  }

  render();
  load(false);
})();
