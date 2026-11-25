
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

// Doctor's chat. Drawn with the page kit (`window.ccKit`, loaded first). Everything the session or
// the agent wrote is put on the page as text nodes or through `markdown` below, never as HTML: the
// transcript comes from a coding agent with root on a box.
const K = window.ccKit,
  h = K.h,
  root = "/__cc/doctor/chat",
  el = (id) => document.getElementById(id),
  FAILED = "Request failed. Reopen chat from the console if access has expired.";
let state = "",
  busy = false,
  writing = false,
  canWrite = false,
  deleted = false,
  info = {},
  retainUntil = 0,
  busySince = 0,
  queued = "",
  unsent = "",
  userCount = 0,
  stream = null;
const seen = new Set();
// The newest copy of this script owns the page (a demo can run it twice on the same markup).
const me = String(Math.random());
el("log").dataset.owner = me;
const mine = () => el("log").dataset.owner === me;

for (const n of document.querySelectorAll("[data-icon]")) n.replaceWith(K.icon(n.dataset.icon, "h-4 w-4 shrink-0 " + n.className));
// The page's buttons, from the kit: each takes the place of its `<id>-slot`.
function slot(id, b) {
  (el(id + "-slot") || el(id)).replaceWith(b);
  b.id = b.id || id;
  return b;
}
const stopBtn = slot("stop", K.button("Stop", { icon: "square" }));
const moreBtn = slot("more", K.button("", { icon: "more", ariaLabel: "More", expanded: false, class: "w-[32px] px-0" }));
const stopInline = slot("stop-inline", h("button", { type: "button", class: "rounded font-medium text-brand underline-offset-2 hover:underline " + K.FOCUS }, "Stop"));
const sendBtn = slot("send", K.button("Send", { variant: "brand", icon: "send", type: "submit" }));
const repairSend = slot("repair-send", K.button("Send to ControlClaw", { variant: "brand" }));
const repairRead = slot("repair-read", K.button("Read the changes", { variant: "ghost", icon: "refresh" }));
const draftSend = slot("draft-send", K.button("Send the draft to ControlClaw", { variant: "brand" }));
const draftReplace = slot("draft-replace", K.button("Replace the draft that is waiting", { variant: "danger" }));
const draftRead = slot("draft-read", K.button("Read the draft", { variant: "ghost", icon: "refresh" }));
const confirmCancel = slot("confirm-cancel", K.button("Cancel", { size: "md" }));
const confirmDelete = slot("confirm-delete", K.button("Delete", { variant: "danger", size: "md", icon: "trash" }));
moreBtn.setAttribute("aria-haspopup", "menu");
moreBtn.setAttribute("aria-controls", "more-menu");
for (const b of [stopBtn, repairSend, repairRead, draftSend, draftReplace, draftRead]) b.hidden = true;

// ---- the head ----
const left = (ms) => {
  const m = Math.max(0, Math.round(ms / 60000));
  // The session's end at the latest: an idle session ends sooner, which the page cannot know.
  return "up to " + (m >= 60 ? Math.floor(m / 60) + " h " + (m % 60) + " min" : m + " min") + " left";
};
const day = (at) => new Date(at).toLocaleDateString(undefined, { day: "numeric", month: "short" });
const live = () => state === "running" || state === "proposed";
function head() {
  const pill =
    deleted ? K.pill("Deleted", "muted")
    : state === "running" && busy ? K.pill("Working", "brand")
    : state === "running" ? K.pill("Waiting for you", "allow")
    : state === "proposed" ? K.pill("Starting", "muted")
    : state === "failed" ? K.pill("Failed", "block", "xCircle")
    : state ? K.pill(state === "ended" ? "Ended" : state.charAt(0).toUpperCase() + state.slice(1), "muted")
    : K.pill("Connecting", "muted");
  if (state === "running" && busy && !deleted) pill.prepend(K.spinner("h-3 w-3"));
  else if (state === "running" && !deleted) pill.prepend(h("span", { "aria-hidden": "true", class: "h-1.5 w-1.5 rounded-full bg-current" }));
  el("state").replaceChildren(pill);
  el("agent").hidden = !info.agent;
  el("agent").textContent = info.agent ? "on " + info.agent : "";
  const parts = [info.cli, info.model, info.credential].filter((v) => typeof v === "string" && v);
  // Only a running session: before the code, expiresAt is the window to enter it, not the run time.
  if (!deleted && state === "running" && info.expiresAt) parts.push(left(info.expiresAt - Date.now()));
  else if (!deleted && retainUntil && !live()) parts.push("kept until " + day(retainUntil));
  el("meta").textContent = parts.join(" · ");
}

// ---- Markdown: paragraphs, headings, lists, code, bold and italic, links. Built as DOM nodes. ----
const MD_CODE = "rounded-[5px] border border-line bg-bg-2 px-1 py-px font-mono text-[0.88em] [overflow-wrap:anywhere]";
function safeUrl(raw) {
  try {
    const u = new URL(raw);
    return ["http:", "https:", "mailto:"].includes(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}
// Where a link goes, shown beside text the model chose: "Re-authorize Google (evil.example)". The model
// can be steered by what it reads on an agent, so its link text alone is not trusted.
function linkPlace(text, url) {
  const u = new URL(url);
  const place = u.protocol === "mailto:" ? u.pathname : u.host;
  const same = (s) => s.trim().replace(/\/+$/, "").replace(/^(https?:\/\/|mailto:)/i, "").toLowerCase();
  return !place || same(text) === same(url) || same(text) === place.toLowerCase() ? "" : place;
}
function link(text, href) {
  const url = safeUrl(href);
  if (!url) return [text];
  const place = linkPlace(text, url);
  const a = h("a", { href: url, title: url, target: "_blank", rel: "noopener noreferrer nofollow", class: "rounded-sm text-brand underline underline-offset-2 [overflow-wrap:anywhere] " + K.FOCUS }, text);
  return place ? [a, h("span", { class: "text-ink-2 [overflow-wrap:anywhere]", "data-link-host": "" }, " (" + place + ")")] : [a];
}
const INLINE = /(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)|\*\*(?=\S)([\s\S]*?\S)\*\*|(?<![\w*])\*(?=[^\s*])([\s\S]*?[^\s*])\*(?![\w*])|(?<!\w)__(?=\S)([\s\S]*?\S)__(?!\w)|(?<![\w_])_(?=[^\s_])([\s\S]*?[^\s_])_(?![\w_])|\[([^\]\n]+)\]\(([^()\s]+)\)|(https?:\/\/[^\s<>()]*[^\s<>().,;:!?'"])/g;
function inline(text, depth) {
  const out = [];
  let last = 0;
  if ((depth || 0) > 3) return [text];
  for (const m of text.matchAll(INLINE)) {
    if (m.index > last) out.push(text.slice(last, m.index));
    last = m.index + m[0].length;
    if (m[1]) out.push(h("code", { class: MD_CODE }, m[2].replace(/^ (.*) $/s, "$1")));
    else if (m[3] || m[5]) out.push(h("strong", { class: "font-semibold" }, inline(m[3] || m[5], (depth || 0) + 1)));
    else if (m[4] || m[6]) out.push(h("em", {}, inline(m[4] || m[6], (depth || 0) + 1)));
    else if (m[7]) out.push(...link(m[7], m[8]));
    else out.push(...link(m[9], m[9]));
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}
const LIST_ITEM = /^\s{0,3}([-*+]|\d{1,9}[.)])\s+(.*)$/;
function markdown(text) {
  const out = [],
    lines = String(text).replace(/\r\n?/g, "\n").split("\n");
  let para = [];
  const flush = () => {
    if (para.length) out.push(h("p", { class: "whitespace-pre-line" }, inline(para.join("\n"))));
    para = [];
  };
  for (let i = 0; i < lines.length; ) {
    const line = lines[i];
    const fence = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (fence) {
      flush();
      const body = [];
      i++;
      while (i < lines.length && !lines[i].trimStart().startsWith(fence[1])) body.push(lines[i++]);
      i++;
      out.push(h("pre", { class: "max-h-96 overflow-auto rounded-lg border border-line bg-bg-2 p-3 font-mono text-[12px] leading-[1.6] text-ink" }, body.join("\n")));
      continue;
    }
    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (heading) {
      flush();
      out.push(h(heading[1].length <= 2 ? "h3" : "h4", { class: (heading[1].length <= 2 ? "text-[15.5px]" : "text-[14px]") + " font-semibold text-ink" }, inline(heading[2])));
      i++;
      continue;
    }
    const item = line.match(LIST_ITEM);
    if (item) {
      flush();
      const ordered = /\d/.test(item[1]);
      const list = h(ordered ? "ol" : "ul", { class: (ordered ? "list-decimal" : "list-disc") + " space-y-1 pl-5 marker:text-ink-2" });
      const start = parseInt(item[1], 10);
      if (ordered && start !== 1) list.setAttribute("start", String(start));
      while (i < lines.length) {
        const m = lines[i].match(LIST_ITEM);
        if (m && /\d/.test(m[1]) === ordered) {
          list.append(h("li", { class: "pl-0.5" }, inline(m[2])));
          i++;
        } else if (/^\s{2,}\S/.test(lines[i]) && list.lastChild) {
          K.append(list.lastChild, [" ", ...inline(lines[i].trim())]);
          i++;
        } else break;
      }
      out.push(list);
      continue;
    }
    if (!line.trim()) flush();
    else para.push(line.replace(/^\s{0,3}>\s?/, ""));
    i++;
  }
  flush();
  return out;
}

// ---- tool calls: one grey line each, what ran and where; the output or the change opens on click ----
function parse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}
const short = (v) => (typeof v === "string" ? v : JSON.stringify(v ?? "")).replace(/\s+/g, " ").slice(0, 200);
// A shell command as Codex runs it (`bash -lc '…'`), without the wrapper.
function unwrap(cmd) {
  const c = Array.isArray(cmd) ? cmd.join(" ") : String(cmd);
  const m = c.match(/^(?:\/usr)?(?:\/bin\/)?(?:ba|z)?sh\s+-l?c\s+(['"])([\s\S]*)\1$/);
  return (m ? m[2] : c).trim();
}
// What a tool call was: an icon, a verb and what it ran on, and the change when it was an edit.
function describe(text) {
  const v = parse(text);
  if (!v || typeof v !== "object" || Array.isArray(v) || typeof v.name !== "string") return { icon: "terminal", cmd: unwrap(Array.isArray(v) ? v : text) };
  const a = v.input || v.arguments || {},
    name = v.name.toLowerCase(),
    path = a.file_path || a.path || a.notebook_path || "";
  if (["bash", "shell", "exec", "exec_command", "run"].includes(name)) return { icon: "terminal", cmd: unwrap(a.command ?? a.cmd ?? "") };
  if (name === "read" || name === "view") return { icon: "file", verb: "Read", what: path };
  if (name === "write") return { icon: "file", verb: "Wrote", what: path, after: typeof a.content === "string" ? a.content : null };
  if (name === "edit" || name === "multiedit" || name === "str_replace") {
    const edits = Array.isArray(a.edits) ? a.edits : [a];
    const diff = [];
    for (const e of edits) if (typeof e.old_string === "string" && typeof e.new_string === "string") diff.push(...diffLines(e.old_string, e.new_string).filter(([k]) => k !== "same"));
    return { icon: "pencil", verb: "Edited", what: path, diff: diff.length ? diff : null };
  }
  if (name === "grep" || name === "glob") return { icon: "search", verb: "Searched for", what: a.pattern || "" };
  if (name === "webfetch" || name === "websearch") return { icon: "globe", verb: name === "webfetch" ? "Fetched" : "Searched the web for", what: a.url || a.query || "" };
  if (name === "todowrite") return { icon: "check", verb: "Updated its plan", what: "" };
  return { icon: "app", verb: v.name, what: short(a) };
}
// A result with no call in front of it (Codex's file changes, MCP calls, web searches).
function describeResult(text) {
  const v = parse(text);
  if (v && typeof v === "object" && !Array.isArray(v)) {
    if (v.type === "file_change" && Array.isArray(v.changes)) {
      const paths = v.changes.map((c) => String(c.path || ""));
      return { icon: "pencil", verb: "Changed", what: paths[0] + (paths.length > 1 ? " and " + (paths.length - 1) + " more" : ""), out: paths.join("\n") };
    }
    if (v.type === "mcp_tool_call") return { icon: "app", verb: "Used", what: [v.server, v.tool].filter(Boolean).join(" ") };
    if (v.type === "web_search") return { icon: "globe", verb: "Searched the web for", what: short(v.query || "") };
  }
  return { icon: "terminal", verb: "Output", what: "" };
}
// What a tool sent back, as text: Claude sends a list of parts.
function outputText(text) {
  const v = parse(text);
  if (Array.isArray(v)) return v.map((p) => (p && typeof p.text === "string" ? p.text : short(p))).join("\n");
  return text;
}
const count = (t) => (t ? t.replace(/\n$/, "").split("\n").length : 0);
const DIFF = { add: "whitespace-pre px-3 text-allow-fg bg-allow-soft/60", del: "whitespace-pre px-3 text-block-fg bg-block-soft/60", same: "whitespace-pre px-3 text-ink-2" };
function diffView(lines) {
  const box = h("div", { class: "max-h-[28rem] overflow-auto rounded-lg border border-line bg-surface py-2 font-mono text-[12px] leading-[1.7]" });
  for (const [kind, text] of lines) box.append(h("div", { class: DIFF[kind] }, (kind === "add" ? "+ " : kind === "del" ? "- " : "  ") + text));
  return box;
}
const PRE = "m-0 max-h-80 overflow-auto rounded-lg border border-line bg-bg-2 p-3 font-mono text-[12px] leading-[1.7] whitespace-pre text-ink";
// A line that opens what is under it. `body()` is drawn the first time it opens.
function opener(lineChildren, body, cls) {
  const panel = h("div", { hidden: true, class: "mt-1 mb-1 min-w-0 pl-6" });
  const chevron = K.icon("chevronRight", "h-3 w-3 shrink-0 opacity-60 transition-transform");
  const btn = h("button", { type: "button", "aria-expanded": "false", class: "flex w-full min-w-0 items-center gap-2 rounded-md px-1.5 py-1 text-left text-[12.5px] text-ink-2 hover:bg-bg-2 hover:text-ink " + K.FOCUS }, lineChildren, chevron);
  let drawn = false;
  btn.addEventListener("click", () => {
    const open = btn.getAttribute("aria-expanded") !== "true";
    if (open && !drawn) {
      panel.append(body());
      drawn = true;
    }
    btn.setAttribute("aria-expanded", String(open));
    chevron.classList.toggle("rotate-90", open);
    panel.hidden = !open;
  });
  return h("div", { class: "min-w-0 " + (cls || "") }, btn, panel);
}
function toolLine(t) {
  const label = t.cmd !== undefined ? h("span", { class: "font-mono text-[12px] text-ink/80" }, t.cmd || "(empty command)") : [t.verb, t.what ? " " : "", t.what ? h("span", { class: "font-mono text-[12px] text-ink/80" }, t.what) : null];
  const failed = /^\s*<tool_use_error>/.test(t.out || "");
  const meta = t.diff ? ["+" + t.diff.filter((d) => d[0] === "add").length, "−" + t.diff.filter((d) => d[0] === "del").length].join(" ") : t.out !== undefined ? count(t.out) + (count(t.out) === 1 ? " line" : " lines") : "";
  return [
    h("span", { class: "grid h-5 w-5 shrink-0 place-items-center" }, K.icon(t.icon, "h-3.5 w-3.5 shrink-0")),
    h("span", { class: "min-w-0 flex-1 truncate" }, label),
    failed ? h("span", { class: "shrink-0 font-semibold text-block-fg" }, "failed") : null,
    meta ? h("span", { class: "shrink-0 text-[11.5px] tabular-nums" }, meta) : null,
  ];
}
function toolNode(t) {
  const node = opener(toolLine(t), () =>
    t.diff ? diffView(t.diff)
    : t.after !== undefined && t.after !== null && t.out === undefined ? h("pre", { class: PRE }, t.after)
    : h("pre", { class: PRE }, t.out === undefined ? "No output yet." : t.out || "(no output)"),
  );
  node.tool = t;
  return node;
}
// Three or more tool calls in a row fold into one line, "N steps on <agent>".
let run = null;
function addTool(t) {
  const node = toolNode(t);
  if (!run) run = { nodes: [], group: null };
  const g = run;
  g.nodes.push(node);
  if (g.group) {
    g.body.append(node);
    groupLabel(g);
  } else if (g.nodes.length === 3) {
    const body = h("div", { class: "flex min-w-0 flex-col gap-0.5 border-l border-line pl-2" });
    g.body = body;
    g.label = h("span", { class: "min-w-0 flex-1 truncate" });
    g.group = opener([h("span", { class: "grid h-5 w-5 shrink-0 place-items-center" }, K.icon("terminal", "h-3.5 w-3.5 shrink-0")), g.label], () => body, "pl-9");
    el("events").insertBefore(g.group, g.nodes[0]);
    for (const n of g.nodes) {
      n.classList.remove("pl-9");
      body.append(n);
    }
    groupLabel(g);
  } else {
    node.classList.add("pl-9");
    el("events").append(node);
  }
  node.run = g;
  return node;
}
function groupLabel(g) {
  const n = g.nodes.length,
    failed = g.nodes.filter((x) => /^\s*<tool_use_error>/.test(x.tool.out || "")).length;
  g.label.replaceChildren(n + " steps" + (info.agent ? " on " + info.agent : ""), failed ? h("span", { class: "ml-1.5 font-semibold text-block-fg" }, failed + " failed") : "");
}
// A result goes on the line of the call it answers.
function setResult(node, text) {
  node.tool.out = outputText(text);
  const fresh = toolNode(node.tool);
  fresh.className = node.className;
  fresh.run = node.run;
  node.replaceWith(fresh);
  const g = node.run;
  g.nodes[g.nodes.indexOf(node)] = fresh;
  if (g.group) groupLabel(g);
  return fresh;
}
let lastTool = null;

// ---- one event of the transcript ----
// The first message of a template repair or a capture is the firewall's own; its label follows once the page knows.
const FIRST_FROM = () => (repairInfo ? "From the template “" + repairInfo.template + "”" : draftOpen ? "From Save as template" : "You");
let firstWho = null;
function userNode(text) {
  const long = text.length > 600 || count(text) > 8;
  const who = h("div", { class: "mb-1 text-[11.5px] font-medium text-ink-2" }, userCount === 0 ? FIRST_FROM() : "You");
  if (userCount++ === 0) firstWho = who;
  const body = h("p", { class: "whitespace-pre-wrap" + (long ? " line-clamp-6" : "") }, text);
  const node = h("div", { class: "my-2 ml-auto w-fit max-w-full min-w-0 rounded-xl bg-bg-2 px-4 py-3 text-[14px] leading-[1.6] text-ink [overflow-wrap:anywhere] sm:max-w-[85%]" }, who, body);
  if (long) {
    const more = h("button", { type: "button", "aria-expanded": "false", class: "mt-1.5 rounded text-[12.5px] font-medium text-brand hover:underline " + K.FOCUS }, "Show all");
    more.addEventListener("click", () => {
      const open = more.getAttribute("aria-expanded") !== "true";
      more.setAttribute("aria-expanded", String(open));
      body.classList.toggle("line-clamp-6", !open);
      more.textContent = open ? "Show less" : "Show all";
    });
    node.append(more);
  }
  return node;
}
function statusNode(text) {
  const bad = /fail|refused|could not|error/i.test(text);
  return h(
    "div",
    { class: "my-2 flex items-center gap-3 text-[12px] " + (bad ? "text-block-fg" : "text-ink-2") },
    h("span", { "aria-hidden": "true", class: "h-px flex-1 bg-line" }),
    h("span", { class: "max-w-[80%] text-center text-pretty" }, text === "Doctor session started." ? "Session started" + (info.cli ? " · " + [info.cli, info.model].filter(Boolean).join(" · ") : "") : text),
    h("span", { "aria-hidden": "true", class: "h-px flex-1 bg-line" }),
  );
}
function sayNode(text) {
  return h(
    "div",
    { class: "my-2 flex min-w-0 gap-3" },
    h("span", { class: "mt-0.5 grid h-6 w-6 shrink-0 place-items-center rounded-full bg-ink text-surface", "aria-hidden": "true" }, K.icon("doctor", "h-3.5 w-3.5 shrink-0")),
    h("div", { class: "min-w-0 flex-1 space-y-2.5 text-[14px] leading-[1.65] text-ink [overflow-wrap:anywhere]" }, h("span", { class: "sr-only" }, "Doctor: "), markdown(text)),
  );
}
function addEvent(item) {
  const events = el("events");
  if (item.kind === "tool_call") {
    lastTool = addTool(describe(item.text));
    return;
  }
  if (item.kind === "tool_result") {
    if (lastTool && lastTool.tool.out === undefined) lastTool = setResult(lastTool, item.text);
    else {
      const t = describeResult(item.text);
      if (t.out === undefined) t.out = outputText(item.text);
      lastTool = addTool(t);
    }
    return;
  }
  run = null;
  lastTool = null;
  if (item.kind === "user") events.append(userNode(item.text));
  else if (item.kind === "status") events.append(statusNode(item.text));
  else if (item.kind === "text") events.append(sayNode(item.text));
  else events.append(renderTranscriptEvent(item, { user: "You", text: "Doctor", status: "Session", tool_call: "Command", tool_result: "Command output" }));
}

// ---- the page's state ----
function controls() {
  const running = state === "running" && !deleted;
  el("form").hidden = !canWrite || !running;
  stopBtn.hidden = !canWrite || deleted || !live();
  el("more-wrap").hidden = !canWrite || deleted;
  sendBtn.disabled = writing;
  el("message").placeholder = busy ? "Write your next message. It goes when Doctor is done." : userCount ? "Reply to Doctor" : "What stopped working? Describe what happened.";
  el("working").hidden = !(running && busy);
  stopInline.hidden = !canWrite;
  el("ended").hidden = deleted ? false : !state || live();
  el("ended-text").textContent = deleted ? "This chat was deleted from the firewall." : retainUntil ? "This session has ended. The chat is kept on this firewall until " + day(retainUntil) + "." : "This session has ended.";
  // The session ended, failed, ran out of time or was stopped with a message still waiting: it was
// never sent.
  if (queued && !running && !writing) {
    unsent = queued;
    queued = "";
  }
  el("queued").hidden = !queued || !running;
  el("unsent").hidden = !unsent || deleted;
  if (unsent && !el("unsent").dataset.shown) showUnsent();
  head();
  tick();
}
function tick() {
  if (busy && !busySince) busySince = Date.now();
  if (!busy) busySince = 0;
  const s = busySince ? Math.round((Date.now() - busySince) / 1000) : 0;
  el("working-text").replaceChildren(K.spinner("h-3.5 w-3.5 text-brand"), " Doctor is working · " + (s >= 60 ? Math.floor(s / 60) + " min " + (s % 60) + " s" : s + " s"));
}
setInterval(() => {
  if (busy && !el("working").hidden) tick();
}, 1000);
setInterval(head, 60000);
function onMessage(e) {
  if (!mine()) return stream.close();
  const data = JSON.parse(e.data);
  el("lost").hidden = true;
  state = data.state;
  busy = data.busy;
  canWrite = data.canWrite;
  retainUntil = data.retainUntil || 0;
  for (const k of ["agent", "cli", "model", "credential", "expiresAt"]) if (data[k] !== undefined) info[k] = data[k];
  el("retention").textContent = retainUntil ? "It is deleted " + new Date(retainUntil).toLocaleString() + "." : "";
  if (data.capture && data.capture.mark !== draftMark) {
    draftMark = data.capture.mark;
    loadDraft();
  }
  if (data.repair && data.repair.mark !== repairMark) {
    repairMark = data.repair.mark;
    loadRepair();
  }
  for (const item of data.events) {
    if (seen.has(item.seq)) continue;
    seen.add(item.seq);
    el("empty").hidden = true;
    addEvent(item);
    while (el("events").children.length > 2000) el("events").firstElementChild.remove();
  }
  controls();
  if (queued && state === "running" && !busy && !writing && canWrite) sendText(queued, true);
}
function connect() {
  if (stream) stream.close();
  stream = new EventSource(root + "/events");
  stream.onmessage = onMessage;
  stream.onerror = () => {
    if (deleted || !mine()) return;
    sendBtn.disabled = true;
    el("lost").hidden = false;
  };
}
el("lost").replaceChildren(
  K.banner(
    "ask",
    "The connection to the firewall dropped. Doctor keeps working. If it does not come back, reopen the chat from the console.",
    K.button("Reconnect", { icon: "refresh", onClick: () => connect() }),
  ),
);
async function post(path, body) {
  const r = await fetch(root + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!r.ok) {
    let message = FAILED;
    try {
      message = (await r.json()).message || message;
    } catch {}
    const err = new Error(message);
    err.status = r.status;
    throw err;
  }
  return r.json();
}
// A message written while Doctor works waits here and goes when it is done.
function showQueued() {
  el("queued").replaceChildren(
    K.icon("clock", "h-3.5 w-3.5 shrink-0"),
    "Your message goes when Doctor is done.",
    h("button", { type: "button", class: "rounded font-medium text-brand hover:underline " + K.FOCUS, onclick: () => { el("message").value = queued; queued = ""; controls(); el("message").focus(); } }, "Edit"),
  );
}
// A message that never went: kept on the page with its text, so nothing typed is lost.
function showUnsent() {
  el("unsent").dataset.shown = "1";
  const copy = h("button", { type: "button", class: "rounded font-medium text-brand hover:underline " + K.FOCUS }, "Copy");
  copy.onclick = () => navigator.clipboard?.writeText(unsent).then(() => (copy.textContent = "Copied"), () => {});
  el("unsent").replaceChildren(
    h("div", { class: "flex items-start gap-2 text-[13px] text-ask-fg" }, K.icon("info", "mt-0.5 h-3.5 w-3.5 shrink-0"), h("span", { class: "min-w-0 font-medium" }, (state === "running" ? "Not sent: you stopped Doctor. " : "Not sent: the session ended before Doctor was done. "), copy)),
    h("p", { class: "mt-1.5 pl-[22px] text-[13px] whitespace-pre-wrap text-ink [overflow-wrap:anywhere]", "data-testid": "unsent-text" }, unsent),
  );
}
async function sendText(text, fromQueue) {
  writing = true;
  controls();
  el("error").textContent = "";
  try {
    await post("/message", { text });
    if (fromQueue) queued = "";
    else el("message").value = "";
    busy = true;
  } catch (e) {
    // Still busy (a turn the page had not heard of yet): it stays queued and goes at the next pause.
    if (!(fromQueue && /current doctor turn/.test(e.message))) {
      el("error").textContent = e.message;
      if (fromQueue) {
        el("message").value = queued;
        queued = "";
      }
    }
  } finally {
    writing = false;
    controls();
  }
}
el("form").onsubmit = (e) => {
  e.preventDefault();
  const text = el("message").value;
  if (!text.trim() || writing) return;
  if (busy) {
    queued = text;
    el("message").value = "";
    showQueued();
    controls();
    return;
  }
  sendText(text, false);
};
el("message").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
    e.preventDefault();
    el("form").requestSubmit();
  }
});
async function stop() {
  el("error").textContent = "";
  // Stop ends the session: a message waiting for Doctor would otherwise go in the pause the stop
  // makes. It stays on the page, not sent.
  if (queued) {
    unsent = queued;
    queued = "";
    controls();
  }
  try {
    await post("/stop");
  } catch (e) {
    el("error").textContent = e.message;
  }
}
stopBtn.addEventListener("click", stop);
stopInline.addEventListener("click", stop);

// ---- the … menu and Delete ----
function menu(open) {
  el("more-menu").hidden = !open;
  moreBtn.setAttribute("aria-expanded", String(open));
  if (open) el("delete").focus();
}
moreBtn.addEventListener("click", () => menu(el("more-menu").hidden));
document.addEventListener("click", (e) => {
  if (!el("more-menu").hidden && !el("more-wrap").contains(e.target)) menu(false);
});
el("more-wrap").addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !el("more-menu").hidden) {
    menu(false);
    moreBtn.focus();
  }
});
el("delete").addEventListener("click", () => {
  menu(false);
  el("confirm").showModal();
  confirmCancel.focus();
});
confirmCancel.addEventListener("click", () => el("confirm").close());
confirmDelete.addEventListener("click", async () => {
  confirmDelete.disabled = true;
  try {
    await post("/delete");
    el("confirm").close();
    deleted = true;
    stream.close();
    el("events").replaceChildren();
    el("repair").hidden = true;
    el("draft").hidden = true;
    el("lost").hidden = true;
    el("from").hidden = true;
    el("empty").hidden = false;
    el("empty").textContent = "Transcript deleted.";
    el("retention").textContent = "";
    queued = "";
    unsent = "";
    controls();
  } catch (e) {
    el("confirm").close();
    el("error").textContent = e.message;
  } finally {
    confirmDelete.disabled = false;
  }
});

// ---- where the session came from ----
let repairInfo = null,
  draftOpen = false;
function from() {
  const f = el("from");
  if (repairInfo) {
    f.replaceChildren(K.icon("diff", "mt-0.5 h-4 w-4 shrink-0 text-brand"), h("span", {}, "Repairing step ", h("b", { class: "font-semibold" }, repairInfo.step), " of the template ", h("b", { class: "font-semibold" }, repairInfo.template)));
    f.hidden = deleted;
  } else if (draftOpen) {
    f.replaceChildren(K.icon("file", "mt-0.5 h-4 w-4 shrink-0 text-brand"), h("span", {}, "Writing a template of this agent, from ", h("b", { class: "font-semibold" }, "Save as template")));
    f.hidden = deleted;
  }
  if (firstWho) firstWho.textContent = FIRST_FROM();
}

// ---- outcome cards: what a template repair changed, and the template a capture wrote ----
// Every file name and every line is written as a text node: the files were written on a box a model had root on.
let repairMark = "",
  draftMark = "";
function diffLines(before, after) {
  const a = before === null ? [] : before.split("\n"),
    b = after.split("\n");
  // Too long to compare line by line in a browser: the old file, then the new one.
  if (a.length * b.length > 4000000) return [...a.map((t) => ["del", t]), ...b.map((t) => ["add", t])];
  const w = b.length + 1,
    table = new Uint32Array((a.length + 1) * w);
  for (let i = a.length - 1; i >= 0; i--)
    for (let j = b.length - 1; j >= 0; j--)
      table[i * w + j] = a[i] === b[j] ? table[(i + 1) * w + j + 1] + 1 : Math.max(table[(i + 1) * w + j], table[i * w + j + 1]);
  const out = [];
  let i = 0,
    j = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) out.push(["same", a[i]]), i++, j++;
    else if (table[(i + 1) * w + j] >= table[i * w + j + 1]) out.push(["del", a[i++]]);
    else out.push(["add", b[j++]]);
  }
  while (i < a.length) out.push(["del", a[i++]]);
  while (j < b.length) out.push(["add", b[j++]]);
  return out;
}
const files = (n) => K.pill(n + (n === 1 ? " file" : " files"), "muted");
const problems = (id, list) => {
  el(id).hidden = !list.length;
  el(id).replaceChildren(...list.map((text) => h("li", {}, text)));
};
// One file of a card: a row that opens what is in it. Open at first when there are three or fewer.
function fileRow(open, rowChildren, body) {
  const li = h("li", { class: "min-w-0 border-b border-line last:border-b-0" });
  const row = opener(rowChildren, body);
  row.firstChild.className = "flex w-full min-w-0 flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-left text-[12.5px] text-ink hover:bg-bg " + K.FOCUS;
  row.lastChild.className = "min-w-0 px-3 pb-3";
  li.append(row);
  if (open) row.firstChild.click();
  return li;
}
function renderRepair(data) {
  const r = data.repair;
  el("repair").hidden = !r || deleted;
  if (!r) return;
  repairInfo = { template: r.template, step: r.step };
  from();
  const running = live();
  el("repair-count").replaceChildren(r.files.length ? files(r.files.length) : "");
  el("repair-template").textContent = "Template “" + r.template + "”";
  el("repair-note").textContent = !r.checkedAt && !running
    ? "The firewall has not read what this repair changed yet. Press Read the changes."
    : !r.checkedAt
    ? "Step \"" + r.step + "\" of template \"" + r.template + "\". When the repair ends, the firewall reads what it changed in the template's files and shows it here."
    : r.problems.length
      ? "The repair's changes cannot be proposed as they are:"
      : !r.files.length
        ? "The repair changed no file of the template, so there is nothing to propose."
        : "In use on this agent only. Send them to ControlClaw to keep them as a proposal on the Templates page; nothing is applied to any agent by sending.";
  // Which steps' files changed, as the agent worked it out. ControlClaw works it out again from its own copy.
  const others = (r.steps || []).filter((id) => id !== r.step);
  el("repair-steps").hidden = !others.length;
  el("repair-steps").replaceChildren(
    others.length ? K.banner("ask", ["It also changed ", h("b", { class: "font-semibold" }, others.join(", ")), others.length === 1 ? ", a step" : ", steps", " it wasn't asked to repair. This repair was for the step " + r.step + " only: read those changes with care before you send."]) : "",
  );
  problems("repair-problems", r.problems);
  el("repair-files").replaceChildren(
    ...r.files.map((file) => {
      const lines = diffLines(file.before, file.after);
      const step = (file.path.match(/^steps\/([^/]+)\//) || [])[1];
      return fileRow(
        r.files.length <= 3,
        [
          K.icon(file.before === null ? "file" : "pencil", "h-3.5 w-3.5 shrink-0 text-ink-2"),
          h("span", { class: "min-w-0 flex-1 basis-[9rem] truncate font-mono text-[12px]" }, file.path),
          h(
            "span",
            { class: "ml-auto flex shrink-0 items-center gap-2" },
            file.before === null ? K.pill("New file", "muted") : null,
            file.executable ? K.pill("Can be run", "muted") : null,
            step && others.includes(step) ? K.pill("Another step", "ask") : null,
            h("span", { class: "font-mono text-[11.5px] text-allow-fg tabular-nums" }, "+" + lines.filter((l) => l[0] === "add").length),
            h("span", { class: "font-mono text-[11.5px] text-block-fg tabular-nums" }, "−" + lines.filter((l) => l[0] === "del").length),
          ),
        ],
        () => diffView(lines),
      );
    }),
  );
  // Also after it was sent: the proposal in ControlClaw may have been deleted since, and sending again replaces it.
  repairSend.hidden = !canWrite || running || !r.files.length || r.problems.length > 0;
  repairSend.lastChild.textContent = r.sent ? "Send again" : "Send to ControlClaw";
  // Also before a first read: a firewall that restarted during the repair never made one by itself.
  repairRead.hidden = !canWrite || running;
  repairRead.lastChild.textContent = r.checkedAt ? "Read the changes again" : "Read the changes";
  el("repair-sent").replaceChildren(...(r.sent ? [K.icon("check", "h-3.5 w-3.5 shrink-0"), "Sent to ControlClaw. It is on the Templates page for 30 days."] : []));
}
async function loadRepair() {
  try {
    const r = await fetch(root + "/repair");
    if (r.ok) renderRepair(await r.json());
  } catch {}
}
async function busyButton(b, text, run) {
  const label = b.lastChild.textContent;
  b.disabled = true;
  if (text) b.lastChild.textContent = text;
  el("error").textContent = "";
  try {
    await run();
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    b.disabled = false;
    if (text) b.lastChild.textContent = label;
  }
}
repairSend.addEventListener("click", () => busyButton(repairSend, "", () => post("/repair/send")).then(loadRepair));
repairRead.addEventListener("click", () => busyButton(repairRead, "Reading…", () => post("/repair/read")).then(loadRepair));
function renderDraft(data) {
  const d = data.capture;
  el("draft").hidden = !d || deleted;
  if (!d) return;
  draftOpen = true;
  from();
  const running = live();
  el("draft-count").replaceChildren(d.files.length ? files(d.files.length) : "");
  el("draft-note").textContent = running
    ? "When the session ends, the firewall reads the template it wrote on the agent and shows every file here. Nothing goes to ControlClaw until you send it."
    : !d.checkedAt
      ? "The firewall has not read the template this session wrote yet. Press Read the draft."
      : d.problems.length
        ? "The template the session wrote cannot be a draft as it is:"
        : !d.files.length
          ? "The session wrote no template."
          : "A coding agent wrote these files on the agent: read every one. Sending opens them in the template editor with ControlClaw's own steps. Nothing is saved as a template and nothing is applied to any agent by sending.";
  problems("draft-problems", d.problems);
  el("draft-steps").hidden = !d.held.length;
  el("draft-steps").replaceChildren(
    ...d.held.map((step) =>
      h(
        "li",
        { class: "flex min-w-0 items-center gap-2 border-b border-line px-3 py-2 text-[12.5px] last:border-b-0" },
        K.icon(step.holds ? "check" : "xCircle", "h-3.5 w-3.5 shrink-0 " + (step.holds ? "text-allow-fg" : "text-block-fg")),
        h("span", { class: "min-w-0 flex-1 truncate font-mono text-[12px] text-ink" }, step.id),
        h("span", { class: "shrink-0 " + (step.holds ? "text-allow-fg" : "text-block-fg") }, step.holds ? "held on this agent" : "did not hold on this agent"),
      ),
    ),
  );
  el("draft-files").replaceChildren(
    ...d.files.map((file) =>
      fileRow(
        d.files.length <= 3,
        [
          K.icon("file", "h-3.5 w-3.5 shrink-0 text-ink-2"),
          h("span", { class: "min-w-0 flex-1 basis-[9rem] truncate font-mono text-[12px]" }, file.path),
          h("span", { class: "ml-auto flex shrink-0 items-center gap-2" }, file.executable ? K.pill("Can be run", "muted") : null, h("span", { class: "text-[11.5px] text-ink-2 tabular-nums" }, count(file.content) + " lines")),
        ],
        () => h("pre", { class: PRE + " bg-surface" }, file.content),
      ),
    ),
  );
  // Also after it was sent: ControlClaw keeps a draft for an hour and only if the agent answered, so it can be sent again.
  draftSend.hidden = !canWrite || running || !d.files.length || d.problems.length > 0;
  draftSend.lastChild.textContent = d.sent ? "Send the draft again" : "Send the draft to ControlClaw";
  draftRead.hidden = !canWrite || running;
  draftRead.lastChild.textContent = d.checkedAt ? "Read the draft again" : "Read the draft";
  el("draft-sent").replaceChildren(...(d.sent ? [K.icon("check", "h-3.5 w-3.5 shrink-0"), "Sent to ControlClaw. Open the draft from the agent's Template card within the hour. If it is not there, send it again."] : []));
}
async function loadDraft() {
  try {
    const r = await fetch(root + "/capture");
    if (r.ok) renderDraft(await r.json());
  } catch {}
}
async function sendDraft(path) {
  draftSend.disabled = true;
  draftReplace.disabled = true;
  draftReplace.hidden = true;
  el("error").textContent = "";
  try {
    const r = await fetch(root + path, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const answer = await r.json().catch(() => ({}));
    if (!r.ok) {
      el("error").textContent = answer.message || FAILED;
      // ControlClaw has another draft of this agent waiting: offered, never done by itself.
      draftReplace.hidden = answer.replace !== true;
    }
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    draftSend.disabled = false;
    draftReplace.disabled = false;
    loadDraft();
  }
}
draftSend.addEventListener("click", () => sendDraft("/capture/send"));
draftReplace.addEventListener("click", () => sendDraft("/capture/replace"));
draftRead.addEventListener("click", () => busyButton(draftRead, "Reading…", () => post("/capture/read")).then(loadDraft));

head();
connect();
