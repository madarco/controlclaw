
const TRANSCRIPT_KIND = {"user":"rounded-xl bg-bg px-4 py-3 sm:ml-[10%]","status":"border-l-2 border-brand pl-3 font-mono text-[12px] text-ink-2"};
function renderTranscriptEvent(item, names) {
  let node;
  if (item.kind === "tool_call" || item.kind === "tool_result") {
    node = document.createElement("details");
    node.className = "mb-4 min-w-0 rounded-lg border border-line";
    const title = document.createElement("summary");
    title.className = "cursor-pointer px-3 py-2.5 font-mono text-[12px] text-ink-2";
    title.textContent = item.title || names[item.kind];
    const pre = document.createElement("pre");
    pre.className = "m-0 max-h-80 overflow-auto border-t border-line p-4 font-mono text-[12px] leading-[1.7] text-ink";
    pre.textContent = item.text;
    node.append(title, pre);
  } else {
    node = document.createElement("div");
    node.className = "mb-5 whitespace-pre-wrap text-[14px] leading-[1.6] text-ink [overflow-wrap:anywhere] " + (TRANSCRIPT_KIND[item.kind] || "");
    const label = document.createElement("span");
    label.className = "mb-1.5 block font-mono text-[11px] tracking-[0.04em] text-ink-2 uppercase";
    label.textContent = item.title || names[item.kind] || item.kind;
    node.append(label, document.createTextNode(item.text));
  }
  return node;
}

// The page, after the shared transcript renderer above (`renderTranscriptEvent`, Doctor's chat's too).
(() => {
  const K = window.ccKit, h = K.h, icon = K.icon;
  const root = location.pathname.replace(/[/]$/, ""), page = document.getElementById("ai-review");
  const NAMES = { user: "Your instructions", text: "Verdict", status: "Result", tool_call: "Questions", tool_result: "Answers" };
  const OUTCOME = { finding: ["Finding", "block"], clear: ["Clear", "allow"], repeat: ["Repeat", "muted"], owner_marked: ["False alarm", "muted"], no_answer: ["No answer", "ask"], capped: ["Capped", "ask"] };
  const CATEGORY = { normal: "Normal traffic", data_exfiltration: "Data leaving the box", destructive_change: "Destructive change", credential_misuse: "Credential misuse", unusual_destination: "Unusual destination", policy_mismatch: "Does not fit this agent" };
  const PAGE = 50;
  const SUB = "What the firewall's AI review sent to the model and what it answered, run by run. Kept on this firewall, encrypted, for seven days. The model sees request metadata only: address, method, status and size, never bodies or keys.";
  // The runs as loaded with no filter (the tiles), and the list as shown (with Findings, the server's own filter).
  let all = [], allMore = false, runs = [], more = false, onlyFindings = false, agent = null;
  let loaded = false, error = null, loads = 0, busy = false;
  let current = null, run = null, runError = null, runLoading = false, asRaw = false;

  const outcome = (r) => OUTCOME[r.outcome] || [r.outcome, "muted"];
  const label = (r) => outcome(r)[0] + (r.severity && r.outcome === "finding" ? " · " + r.severity : "");
  const kindLabel = (r) => (r.kind === "scan" ? "Scan" : "Every minute");
  const phone = () => window.matchMedia("(max-width: 767px)").matches;

  async function get(path) {
    const r = await fetch(root + path, { credentials: "same-origin" });
    if (!r.ok) {
      let message = r.status === 403 ? "Access expired. Open the review history from the console again." : "Could not load. Try again.";
      try { message = (await r.json()).message || message; } catch {}
      throw new Error(message);
    }
    return r.json();
  }

  /* ---------- the list ---------- */

  function stats() {
    const plus = allMore ? "+" : "";
    const count = (o) => all.filter((r) => r.outcome === o).length;
    const findings = all.filter((r) => r.outcome === "finding");
    const bySev = ["high", "medium", "low"].map((s) => [s, findings.filter((r) => r.severity === s).length]).filter(([, n]) => n);
    const failed = count("no_answer"), capped = count("capped");
    return K.statGrid([
      { label: "Runs", value: all.length + plus, sub: "last 7 days" },
      { label: "Findings", value: findings.length + plus, sub: bySev.length ? bySev.map(([s, n]) => n + " " + s).join(", ") : "none posted", tone: findings.length ? "ask" : null },
      { label: "Clear", value: count("clear") + plus, sub: "no concern" },
      { label: "Not answered", value: failed + capped + plus, sub: failed + capped ? [failed && failed + " failed", capped && capped + " at the limit"].filter(Boolean).join(", ") : "every run answered" },
    ]);
  }

  function runButton(r) {
    const [, tone] = outcome(r);
    const on = r.runId === current;
    return h(
      "button",
      {
        type: "button",
        dataset: { run: r.runId },
        "aria-current": on ? "true" : null,
        class: "flex w-full min-w-0 cursor-pointer items-center gap-3 border-b border-line px-4 py-2.5 text-left last:border-b-0 hover:bg-bg " + (on ? "bg-bg shadow-[inset_3px_0_0_var(--brand)] " : "") + K.FOCUS,
        onclick: () => { location.hash = "run=" + encodeURIComponent(r.runId); },
      },
      h("span", { class: "shrink-0 text-[12.5px] whitespace-nowrap text-ink-2 tabular-nums" }, K.clock(r.at)),
      h("span", { class: "flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-1" }, K.pill(label(r), tone), h("span", { class: "text-[12.5px] text-ink-2" }, kindLabel(r))),
      icon("chevronRight", "h-4 w-4 shrink-0 text-ink-2"),
    );
  }

  function listCard() {
    const body = runs.length
      ? h("div", { class: "md:max-h-[70vh] md:overflow-auto" }, K.groupByDay(runs, (r) => r.at).map((g) => h("div", {}, K.dayHeading(g.label, g.rows.length), g.rows.map(runButton))))
      : K.empty({ icon: "review", title: onlyFindings ? "No findings" : "No runs", text: onlyFindings ? "No run in the last seven days ended in a finding." : "No runs in the last seven days." });
    return K.card(
      { "aria-labelledby": "runs-title", class: "min-w-0" + (current && phone() ? " hidden" : "") },
      K.cardHead("Runs", runs.length + (more ? "+" : ""), K.segmented("Show", [{ key: "all", label: "All" }, { key: "findings", label: "Findings" }], onlyFindings ? "findings" : "all", (k) => { onlyFindings = k === "findings"; load(false); }), "runs-title"),
      body,
      more ? h("div", { class: "flex border-t border-line px-4 py-3" }, K.button(busy ? "Loading…" : "Load older runs", { class: "ml-auto", disabled: busy, onClick: () => load(true) })) : null,
    );
  }

  /* ---------- one run ---------- */

  const parse = (t) => { try { return JSON.parse(t); } catch { return null; } };
  const kb = (b) => (typeof b !== "number" ? "—" : b < 1024 ? b + " B" : (b / 1024).toFixed(1) + " kB");
  const sh = (t) => h("div", { class: "mb-1 text-[11px] font-semibold tracking-[0.06em] text-ink-2 uppercase" }, t);

  /** None, Low, Medium, High, the level the score rounds to lit. */
  function riskScale(score) {
    const lv = Math.max(0, Math.min(3, Math.floor(score + 0.5)));
    const tones = ["bg-allow-soft text-allow-fg", "bg-ask-soft text-ask-fg", "bg-ask-soft text-ask-fg", "bg-block-soft text-block-fg"];
    return h(
      "div",
      { role: "img", "aria-label": "Risk " + ["none", "low", "medium", "high"][lv] + ", score " + score, class: "inline-flex overflow-hidden rounded-md border border-line" },
      ["None", "Low", "Medium", "High"].map((l, i) => h("span", { "aria-hidden": "true", class: "px-2 py-0.5 text-[11.5px] " + (i === lv ? "font-semibold " + tones[i] : "text-ink-2") + (i ? " border-l border-line" : "") }, l)),
    );
  }

  /** A section that opens and closes, as `<details>`. */
  function section(title, meta, open, ...children) {
    return h(
      "details",
      { open: open || null, class: "group min-w-0 border-t border-line" },
      h(
        "summary",
        { class: "flex cursor-pointer list-none items-center gap-2 px-4 py-3 text-[13.5px] font-semibold text-ink hover:bg-bg [&::-webkit-details-marker]:hidden " + K.FOCUS },
        icon("chevronRight", "h-4 w-4 shrink-0 text-ink-2 transition-transform group-open:rotate-90"),
        title,
        meta ? h("span", { class: "ml-auto truncate text-[12px] font-normal text-ink-2" }, meta) : null,
      ),
      h("div", { class: "min-w-0 px-4 pb-4" }, children),
    );
  }

  const pre = (text) => h("pre", { class: "m-0 max-h-80 overflow-auto rounded-lg border border-line bg-bg p-3 font-mono text-[12px] leading-[1.6] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]" }, text);

  /** What was sent: the requests as a table, or the state as the model got it. */
  function sentSection(ev) {
    const state = parse(ev.text);
    const reqs = state && (Array.isArray(state.requests) ? state.requests : Array.isArray(state.recent_requests) ? state.recent_requests : null);
    const hosts = state && Array.isArray(state.hosts) ? state.hosts.length : 0;
    const meta = [reqs ? reqs.length + " request" + (reqs.length === 1 ? "" : "s") : null, hosts ? hosts + " host" + (hosts === 1 ? "" : "s") : null].filter(Boolean).join(" · ");
    const flagged = run && answerOf("host");
    const table = () =>
      h(
        "div",
        { class: "overflow-x-auto rounded-lg border border-line" },
        h(
          "table",
          { class: "w-full min-w-[520px] border-collapse text-[12.5px]" },
          h("thead", {}, h("tr", { class: "bg-bg-2 text-left text-[11.5px] text-ink-2" }, ["Request", "Status", "Out", "In", "Allowed by"].map((c, i) => h("th", { scope: "col", class: "px-3 py-2 font-semibold " + (i === 2 || i === 3 ? "text-right" : "") }, c)))),
          h(
            "tbody",
            {},
            reqs.map((r) =>
              h(
                "tr",
                { class: "border-t border-line " + (flagged && r.host === flagged && run.outcome !== "clear" ? "bg-block-soft" : "") },
                h("td", { class: "px-3 py-1.5 font-mono text-[12px] text-ink [overflow-wrap:anywhere]" }, r.method ? h("span", { class: "mr-1.5 font-semibold text-ink-2" }, r.method) : null, String(r.host || "") + (r.path || "") + (r.port ? ":" + r.port : "")),
                h("td", { class: "px-3 py-1.5 whitespace-nowrap tabular-nums text-ink-2" }, r.status === undefined ? (r.effect || "—") : String(r.status)),
                h("td", { class: "px-3 py-1.5 text-right whitespace-nowrap tabular-nums text-ink-2" }, kb(r.bytes_out)),
                h("td", { class: "px-3 py-1.5 text-right whitespace-nowrap tabular-nums text-ink-2" }, kb(r.bytes_in)),
                h("td", { class: "px-3 py-1.5 whitespace-nowrap text-ink-2" }, r.allowed_by === "owner_rule" ? "Your rule" : r.allowed_by ? String(r.allowed_by) : "—"),
              ),
            ),
          ),
        ),
      );
    const holder = h("div", { class: "min-w-0" });
    const paint = () => holder.replaceChildren(asRaw || !reqs || !reqs.length ? pre(ev.text) : table());
    paint();
    return section(
      "What was sent",
      meta,
      true,
      reqs && reqs.length ? h("div", { class: "mb-3" }, K.segmented("Show as", [{ key: "table", label: "Table" }, { key: "raw", label: "As the model got it" }], asRaw ? "raw" : "table", (k) => { asRaw = k === "raw"; paint(); })) : null,
      holder,
      state && state.agent_context ? h("p", { class: "mt-2 text-[12px] text-ink-2" }, "The agent's setup from the console was sent with it (As the model got it, under agent_context).") : null,
    );
  }

  function answerOf(id) {
    const ev = run.events.find((e) => e.kind === "tool_result");
    const a = ev && parse(ev.text);
    const v = a && a[id];
    return v ? (v.type === "score" ? v.score : v.choice) : undefined;
  }

  function verdict() {
    const texts = run.events.filter((e) => e.kind === "text");
    const statuses = run.events.filter((e) => e.kind === "status");
    const score = answerOf("risk");
    const category = answerOf("category") || run.category;
    const host = answerOf("host");
    const parts = [];
    if (typeof score === "number" || category || host) {
      parts.push(
        h(
          "div",
          { class: "flex flex-wrap gap-x-8 gap-y-4" },
          typeof score === "number" ? h("div", { class: "min-w-0" }, sh("Risk"), riskScale(score), h("div", { class: "mt-1 text-[12px] text-ink-2 tabular-nums" }, "score " + score)) : null,
          category ? h("div", { class: "min-w-0" }, sh("Category"), h("div", { class: "text-[13.5px] font-semibold text-ink" }, CATEGORY[category] || category), h("div", { class: "font-mono text-[11.5px] text-ink-2" }, category)) : null,
          host ? h("div", { class: "min-w-0" }, sh("Host"), h("div", { class: "font-mono text-[13px] font-semibold text-ink [overflow-wrap:anywhere]" }, host)) : null,
        ),
      );
    }
    for (const t of texts) parts.push(h("p", { class: "mt-3 text-[13.5px] leading-[1.6] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]" }, t.text));
    for (const s of statuses) {
      const posted = /^Finding posted/.test(s.text);
      parts.push(h("p", { class: "mt-3 flex items-start gap-1.5 text-[13px] " + (posted ? "text-block-fg" : "text-ask-fg") }, icon(posted ? "checkCircle" : "alert", "mt-0.5 h-3.5 w-3.5 shrink-0"), h("span", { class: "min-w-0 [overflow-wrap:anywhere]" }, s.text)));
    }
    if (run.outcome === "repeat") parts.push(h("p", { class: "mt-3 flex items-center gap-1.5 text-[13px] text-ink-2" }, icon("info", "h-3.5 w-3.5 shrink-0"), "A repeat of a finding already posted. Nothing new was posted."));
    if (run.outcome === "owner_marked") parts.push(h("p", { class: "mt-3 flex items-center gap-1.5 text-[13px] text-ink-2" }, icon("info", "h-3.5 w-3.5 shrink-0"), "You marked this a false alarm."));
    const answered = !["no_answer", "capped"].includes(run.outcome);
    if (!answered && typeof score !== "number") {
      return h("div", { class: "px-4 pt-4" }, K.banner("ask", statuses.length ? statuses.map((s) => h("p", {}, s.text)) : run.outcome === "capped" ? "The daily limit was reached. This run was not sent to the model." : "No answer."));
    }
    if (!parts.length) return null;
    const tone = run.outcome === "finding" ? "border-block-border bg-block-soft/40" : run.outcome === "clear" ? "border-allow-border bg-allow-soft/40" : "border-line bg-bg";
    return h("div", { class: "px-4 pt-4" }, h("div", { class: "rounded-xl border p-4 " + tone }, parts));
  }

  function detail() {
    const back = K.button("", { variant: "ghost", icon: "arrowLeft", ariaLabel: "Back to the runs", class: "w-[32px] px-0 md:hidden", onClick: () => { location.hash = ""; } });
    if (!current) {
      return K.card({ class: "min-w-0 hidden md:block" }, K.empty({ icon: "review", text: "Pick a run to see what was sent and what came back." }));
    }
    if (runLoading || runError || !run) {
      return K.card(
        { class: "min-w-0" },
        h("div", { class: "flex items-center gap-2 border-b border-line px-4 py-3" }, back, h("span", { class: "text-[13.5px] font-semibold text-ink" }, "Run")),
        runError ? h("div", { class: "p-4" }, K.banner("block", runError)) : K.loading("Reading the run…"),
      );
    }
    const [, tone] = outcome(run);
    const ev = run.events;
    const used = new Set();
    const take = (pred) => ev.filter((e) => pred(e) && !used.has(e) && used.add(e));
    const instructions = take((e) => e.kind === "user");
    const sent = take((e) => e.kind === "tool_call" && /^State sent/.test(e.title || ""));
    take((e) => e.kind === "text" || e.kind === "status");
    const rest = ev.filter((e) => !used.has(e));
    const instr = instructions.map((e) => e.text.replace(/^Owner's instructions:\n/, "")).join("\n\n");
    return K.card(
      { "aria-labelledby": "run-title", class: "min-w-0" },
      h(
        "div",
        { class: "flex items-start gap-2 border-b border-line px-4 py-3" },
        back,
        h(
          "div",
          { class: "min-w-0 flex-1" },
          h("h2", { id: "run-title", class: "flex flex-wrap items-center gap-2 text-[14.5px] font-semibold text-ink" }, K.pill(label(run), tone), K.when(run.at)),
          h("p", { class: "mt-1 text-[12.5px] text-ink-2 [overflow-wrap:anywhere]" }, (run.kind === "scan" ? "Periodic scan" : "Every-minute review") + " · ", h("span", { class: "font-mono text-[12px]" }, [run.provider, run.model].filter(Boolean).join(" / ") || "unknown model")),
        ),
      ),
      verdict(),
      h(
        "div",
        { class: "mt-4" },
        instructions.length ? section("Your instructions", /^No owner instructions/.test(instr) ? "none" : null, !/^No owner instructions/.test(instr), h("p", { class: "text-[13px] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]" }, instr)) : null,
        sent.map(sentSection),
        rest.map((e) =>
          e.kind === "tool_call" || e.kind === "tool_result"
            ? section(e.title || NAMES[e.kind], e.kind === "tool_result" ? "as returned" : null, false, pre(e.text))
            : h("div", { class: "border-t border-line px-4 pt-4" }, renderTranscriptEvent(e, NAMES)),
        ),
      ),
    );
  }

  /* ---------- the page ---------- */

  function render() {
    const a = document.activeElement;
    const key = a && page.contains(a) ? (a.dataset.run ? '[data-run="' + CSS.escape(a.dataset.run) + '"]' : a.dataset.key ? '[data-key="' + CSS.escape(a.dataset.key) + '"]' : null) : null;
    const parts = [K.pageHead("AI review history", SUB, agent ? [K.pill(agent, "brand", "bot")] : [])];
    if (error) parts.push(h("div", { class: "mb-5" }, K.banner("block", error)));
    if (!loaded && !error) parts.push(K.card({}, K.loading("Reading the runs on the firewall…")));
    if (loaded) {
      if (all.length) parts.push(stats());
      parts.push(h("div", { class: "grid items-start gap-5 md:grid-cols-[minmax(250px,320px)_minmax(0,1fr)]" }, listCard(), detail()));
    }
    parts.push(K.footNote("Covers the review every minute and the scan. The check before each request is not recorded yet. Any member can read this page."));
    page.replaceChildren(...parts);
    const again = key && page.querySelector(key);
    if (again) again.focus();
  }

  async function load(older) {
    busy = true;
    if (older) render();
    error = null;
    try {
      const q = new URLSearchParams();
      if (older && runs.length) q.set("before", String(runs[runs.length - 1].at));
      if (onlyFindings) q.set("findings", "1");
      // Only the last load counts: two clicks on "Load older runs" append once.
      const seq = ++loads, data = await get("/runs?" + q);
      if (seq !== loads) return;
      agent = data.agent || null;
      runs = older ? runs.concat(data.runs) : data.runs;
      more = data.runs.length >= PAGE;
      if (!onlyFindings) { all = runs; allMore = more; }
      loaded = true;
    } catch (e) {
      error = e.message;
    }
    busy = false;
    render();
  }

  async function show(id) {
    current = id || null;
    run = null;
    runError = null;
    runLoading = !!id;
    render();
    if (!id) return;
    try {
      const r = await get("/runs/" + encodeURIComponent(id));
      // A run picked since then wins over this one's late answer.
      if (current !== id) return;
      run = r;
    } catch (e) {
      if (current !== id) return;
      runError = e.message;
    }
    runLoading = false;
    render();
    if (phone()) window.scrollTo(0, 0);
  }

  const fromHash = () => new URLSearchParams(location.hash.slice(1)).get("run");
  window.addEventListener("hashchange", () => show(fromHash()));
  render();
  load(false).then(() => { const id = fromHash(); if (id) show(id); });
})();
