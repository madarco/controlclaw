
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

const root = "/__cc/doctor/chat",
  el = (id) => document.getElementById(id);
let state = "",
  busy = false,
  writing = false,
  canWrite = false;
const seen = new Set();
const stream = new EventSource(root + "/events");
function controls() {
  el("form").hidden = !canWrite || state !== "running";
  el("stop").hidden = !canWrite || !["running", "proposed"].includes(state);
  el("delete").hidden = !canWrite;
  el("send").disabled = busy || writing;
}
stream.onmessage = (e) => {
  const data = JSON.parse(e.data);
  state = data.state;
  busy = data.busy;
  canWrite = data.canWrite;
  el("state").textContent =
    state === "running"
      ? busy
        ? "Doctor is working..."
        : "Ready for your message"
      : state;
  el("retention").textContent =
    "Deletes " + new Date(data.retainUntil).toLocaleString() + ".";
  controls();
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
    el("events").append(
      renderTranscriptEvent(item, { user: "You", text: "Doctor", status: "Session", tool_call: "Command", tool_result: "Command output" }),
    );
    while (el("events").children.length > 2001)
      el("events").children[1].remove();
  }
};
stream.onerror = () => {
  el("state").textContent =
    "Connection lost. Reopen chat from the console if it does not reconnect.";
  el("send").disabled = true;
};
async function post(path, body) {
  const r = await fetch(root + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!r.ok) {
    let message =
      "Request failed. Reopen chat from the console if access has expired.";
    try {
      message = (await r.json()).message || message;
    } catch {}
    throw new Error(message);
  }
  return r.json();
}
el("form").onsubmit = async (e) => {
  e.preventDefault();
  const text = el("message").value;
  if (!text.trim() || writing) return;
  writing = true;
  controls();
  el("error").textContent = "";
  try {
    await post("/message", { text });
    el("message").value = "";
    busy = true;
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    writing = false;
    controls();
  }
};
// What a template repair changed, as the firewall keeps it. Every file name and every line is
// written as a text node: the files were written on a box a model had root on.
const DIFF = { add: "whitespace-pre px-3 text-allow", del: "whitespace-pre px-3 text-block", same: "whitespace-pre px-3 text-ink-2" };
let repairMark = "";
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
function renderRepair(data) {
  const r = data.repair;
  el("repair").hidden = !r;
  if (!r) return;
  const running = state === "running" || state === "proposed";
  el("repair-note").textContent = !r.checkedAt && !running
    ? "The firewall has not read what this repair changed yet. Press Read the changes."
    : !r.checkedAt
    ? "Step \"" + r.step + "\" of template \"" + r.template + "\". When the repair ends, the firewall reads what it changed in the template's files and shows it here."
    : r.problems.length
      ? "The repair's changes cannot be proposed as they are:"
      : !r.files.length
        ? "The repair changed no file of the template, so there is nothing to propose."
        : "The repair changed these files of template \"" + r.template + "\" for step \"" + r.step + "\". They are in use on this agent only. Send them to ControlClaw to keep them as a proposal on the Templates page; nothing is applied to any agent by sending.";
  // Which steps' files changed, as the agent worked it out. ControlClaw works it out again from its own copy.
  const others = (r.steps || []).filter((id) => id !== r.step);
  el("repair-steps").hidden = !others.length;
  el("repair-steps").textContent = others.length
    ? "Files of other steps changed too (" + others.join(", ") + "). This repair was for the step " + r.step + " only: read those changes with care before you send."
    : "";
  el("repair-problems").hidden = !r.problems.length;
  el("repair-problems").replaceChildren(
    ...r.problems.map((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    }),
  );
  el("repair-files").replaceChildren(
    ...r.files.map((file) => {
      const box = document.createElement("details");
      box.className = "mb-3 min-w-0 rounded-lg border border-line bg-surface";
      box.open = r.files.length <= 3;
      const title = document.createElement("summary");
      title.className = "cursor-pointer px-3 py-2.5 font-mono text-[12px] text-ink [overflow-wrap:anywhere]";
      title.textContent = file.path + (file.before === null ? " (new file)" : "") + (file.executable ? " (can be run)" : "");
      const pre = document.createElement("div");
      pre.className = "max-h-[28rem] overflow-auto border-t border-line py-2 font-mono text-[12px] leading-[1.7]";
      for (const [kind, text] of diffLines(file.before, file.after)) {
        const line = document.createElement("div");
        line.className = DIFF[kind];
        line.textContent = (kind === "add" ? "+ " : kind === "del" ? "- " : "  ") + text;
        pre.append(line);
      }
      box.append(title, pre);
      return box;
    }),
  );
  // Also after it was sent: the proposal in ControlClaw may have been deleted since, and sending again replaces it.
  el("repair-send").hidden = !canWrite || running || !r.files.length || r.problems.length > 0;
  el("repair-send").textContent = r.sent ? "Send again" : "Send to ControlClaw";
  // Also before a first read: a firewall that restarted during the repair never made one by itself.
  el("repair-read").hidden = !canWrite || running;
  el("repair-read").textContent = r.checkedAt ? "Read the changes again" : "Read the changes";
  el("repair-sent").textContent = r.sent ? "Sent to ControlClaw. It is on the Templates page for 30 days." : "";
}
async function loadRepair() {
  try {
    const r = await fetch(root + "/repair");
    if (r.ok) renderRepair(await r.json());
  } catch {}
}
el("repair-send").onclick = async () => {
  el("repair-send").disabled = true;
  el("error").textContent = "";
  try {
    await post("/repair/send");
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    el("repair-send").disabled = false;
    loadRepair();
  }
};
el("repair-read").onclick = async () => {
  el("repair-read").disabled = true;
  el("repair-read").textContent = "Reading...";
  el("error").textContent = "";
  try {
    await post("/repair/read");
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    el("repair-read").disabled = false;
    loadRepair();
  }
};
// The template a capture session wrote, as the firewall keeps it. Every file name and every line
// of a file is written as text: the files were written on a box a model had root on.
let draftMark = "";
function renderDraft(data) {
  const d = data.capture;
  el("draft").hidden = !d;
  if (!d) return;
  const running = state === "running" || state === "proposed";
  el("draft-note").textContent = running
    ? "When the session ends, the firewall reads the template it wrote on the agent and shows every file here. Nothing goes to ControlClaw until you send it."
    : !d.checkedAt
      ? "The firewall has not read the template this session wrote yet. Press Read the draft."
      : d.problems.length
        ? "The template the session wrote cannot be a draft as it is:"
        : !d.files.length
          ? "The session wrote no template."
          : "The session wrote these files on the agent. A coding agent wrote them: read every one. Send them to ControlClaw to open them in the template editor with ControlClaw's own steps; nothing is saved as a template and nothing is applied to any agent by sending.";
  el("draft-problems").hidden = !d.problems.length;
  el("draft-problems").replaceChildren(
    ...d.problems.map((text) => {
      const li = document.createElement("li");
      li.textContent = text;
      return li;
    }),
  );
  el("draft-steps").hidden = !d.held.length;
  el("draft-steps").replaceChildren(
    ...d.held.map((step) => {
      const li = document.createElement("li");
      li.textContent = step.id + ": " + (step.holds ? "held on this agent when the draft was read" : "did not hold on this agent when the draft was read");
      return li;
    }),
  );
  el("draft-files").replaceChildren(
    ...d.files.map((file) => {
      const box = document.createElement("details");
      box.className = "mb-3 min-w-0 rounded-lg border border-line bg-surface";
      box.open = d.files.length <= 3;
      const title = document.createElement("summary");
      title.className = "cursor-pointer px-3 py-2.5 font-mono text-[12px] text-ink [overflow-wrap:anywhere]";
      title.textContent = file.path + (file.executable ? " (can be run)" : "");
      const pre = document.createElement("pre");
      pre.className = "m-0 max-h-[28rem] overflow-auto border-t border-line p-3 font-mono text-[12px] leading-[1.7] text-ink";
      pre.textContent = file.content;
      box.append(title, pre);
      return box;
    }),
  );
  // Also after it was sent: ControlClaw keeps a draft for an hour and only if the agent answered, so it can be sent again.
  el("draft-send").hidden = !canWrite || running || !d.files.length || d.problems.length > 0;
  el("draft-send").textContent = d.sent ? "Send the draft again" : "Send the draft to ControlClaw";
  el("draft-read").hidden = !canWrite || running;
  el("draft-read").textContent = d.checkedAt ? "Read the draft again" : "Read the draft";
  el("draft-sent").textContent = d.sent ? "Sent to ControlClaw. Open the draft from the agent's Template card within the hour. If it is not there, send it again." : "";
}
async function loadDraft() {
  try {
    const r = await fetch(root + "/capture");
    if (r.ok) renderDraft(await r.json());
  } catch {}
}
async function sendDraft(path) {
  el("draft-send").disabled = true;
  el("draft-replace").disabled = true;
  el("draft-replace").hidden = true;
  el("error").textContent = "";
  try {
    const r = await fetch(root + path, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const answer = await r.json().catch(() => ({}));
    if (!r.ok) {
      el("error").textContent = answer.message || "Request failed. Reopen chat from the console if access has expired.";
      // ControlClaw has another draft of this agent waiting: offered, never done by itself.
      el("draft-replace").hidden = answer.replace !== true;
    }
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    el("draft-send").disabled = false;
    el("draft-replace").disabled = false;
    loadDraft();
  }
}
el("draft-send").onclick = () => sendDraft("/capture/send");
el("draft-replace").onclick = () => sendDraft("/capture/replace");
el("draft-read").onclick = async () => {
  el("draft-read").disabled = true;
  el("draft-read").textContent = "Reading...";
  el("error").textContent = "";
  try {
    await post("/capture/read");
  } catch (e) {
    el("error").textContent = e.message;
  } finally {
    el("draft-read").disabled = false;
    loadDraft();
  }
};
el("stop").onclick = async () => {
  try {
    await post("/stop");
  } catch (e) {
    el("error").textContent = e.message;
  }
};
el("delete").onclick = async () => {
  if (!confirm("Stop this repair and permanently delete its transcript?"))
    return;
  try {
    await post("/delete");
    stream.close();
    el("events").replaceChildren();
    el("state").textContent = "Transcript deleted";
    el("form").hidden = true;
    el("stop").hidden = true;
    el("delete").hidden = true;
    el("retention").textContent = "";
  } catch (e) {
    el("error").textContent = e.message;
  }
};
