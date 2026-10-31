
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

const root = location.pathname.replace(/[/]$/, ""), el = (id) => document.getElementById(id);
const NAMES = { user: "Your instructions", text: "Verdict", status: "Result", tool_call: "Questions", tool_result: "Answers" };
const OUTCOME = { finding: "Finding", clear: "Clear", repeat: "Repeat", no_answer: "No answer", capped: "Capped" };
let runs = [], oldest = null, current = null, loads = 0;
const outcome = (o) => OUTCOME[o] || o;
const fmt = (ms) => new Date(ms).toLocaleString();
async function get(path) {
  const r = await fetch(root + path, { credentials: "same-origin" });
  if (!r.ok) {
    let message = r.status === 403 ? "Access expired. Open the review history from the console again." : "Could not load. Try again.";
    try { message = (await r.json()).message || message; } catch {}
    throw new Error(message);
  }
  return r.json();
}
function item(run) {
  const li = document.createElement("li"), b = document.createElement("button");
  b.type = "button"; b.className = "block w-full cursor-pointer border-b border-line px-3.5 py-3 text-left hover:bg-bg aria-[current=true]:bg-bg aria-[current=true]:shadow-[inset_3px_0_0_var(--brand)]"; b.dataset.run = run.runId;
  const when = document.createElement("span"); when.className = "block text-[13.5px] font-semibold text-ink"; when.textContent = fmt(run.at);
  const badge = document.createElement("span"); badge.className = "ml-1.5 inline-block rounded border px-1.5 font-mono text-[11px] leading-[1.6] font-normal uppercase " + (run.outcome === "finding" ? "border-block text-block" : "border-line-2 text-ink-2");
  badge.textContent = outcome(run.outcome) + (run.severity && run.outcome === "finding" ? " · " + run.severity : "");
  when.append(badge);
  const meta = document.createElement("span"); meta.className = "block font-mono text-[12px] text-ink-2 [overflow-wrap:anywhere]";
  meta.textContent = (run.kind === "scan" ? "Scan" : "Every minute") + " · " + (run.model || "unknown model");
  b.append(when, meta); b.onclick = () => { location.hash = "run=" + encodeURIComponent(run.runId); };
  li.append(b); return li;
}
async function load(more) {
  el("error").textContent = "";
  try {
    const q = new URLSearchParams();
    if (more && oldest) q.set("before", String(oldest));
    if (el("findings").checked) q.set("findings", "1");
    // Only the last load counts: two clicks on "Load older runs" append once.
    const seq = ++loads, data = await get("/runs?" + q);
    if (seq !== loads) return;
    el("agent").textContent = data.agent ? "Agent: " + data.agent : "";
    if (!more) { runs = []; el("runs").replaceChildren(); }
    runs = runs.concat(data.runs);
    for (const r of data.runs) el("runs").append(item(r));
    oldest = runs.length ? runs[runs.length - 1].at : null;
    el("more").hidden = data.runs.length < 50;
    el("count").textContent = runs.length ? runs.length + " run" + (runs.length === 1 ? "" : "s") : "No runs in the last seven days";
    mark();
  } catch (e) { el("error").textContent = e.message; }
}
function mark() {
  for (const b of el("runs").querySelectorAll("button")) b.setAttribute("aria-current", String(b.dataset.run === current));
}
async function show(id) {
  current = id; mark();
  const box = el("events");
  if (!id) {
    const p = document.createElement("p"); p.id = "empty"; p.className = "text-[14px] text-ink-2"; p.textContent = "Pick a run to see what was sent and what came back."; box.replaceChildren(p);
    return;
  }
  try {
    const run = await get("/runs/" + encodeURIComponent(id));
    // A run picked since then wins over this one's late answer.
    if (current !== id) return;
    const h = document.createElement("h2"); h.className = "text-[16px] font-semibold tracking-[-0.01em] text-ink"; h.textContent = outcome(run.outcome) + (run.severity ? " · " + run.severity : "") + " · " + fmt(run.at);
    const meta = document.createElement("p"); meta.className = "block font-mono text-[12px] text-ink-2 [overflow-wrap:anywhere] mb-4";
    meta.textContent = (run.kind === "scan" ? "Periodic scan" : "Every-minute review") + " · " + [run.provider, run.model].filter(Boolean).join(" / ");
    box.replaceChildren(h, meta);
    for (const ev of run.events) box.append(renderTranscriptEvent(ev, NAMES));
    if (window.matchMedia("(max-width: 767px)").matches) el("detail").scrollIntoView();
  } catch (e) {
    if (current !== id) return;
    const p = document.createElement("p"); p.id = "empty"; p.className = "text-[14px] text-ink-2"; p.textContent = e.message; box.replaceChildren(p);
  }
}
const fromHash = () => new URLSearchParams(location.hash.slice(1)).get("run");
window.addEventListener("hashchange", () => show(fromHash()));
el("findings").onchange = () => load(false);
el("more").onclick = () => load(true);
load(false).then(() => { const id = fromHash(); if (id) show(id); });
