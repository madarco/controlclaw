const el = (id) => document.getElementById(id);
const kit = window.ccKit;
const params = new URLSearchParams(location.search);
const loginId = params.get("login") || "";
const requestId = params.get("request") || "";
let request = null;
let agents = [];
async function api(path, body) {
  const r = await fetch("/__cc/logins/" + path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
  let data = {};
  try { data = await r.json(); } catch {}
  if (!r.ok) throw new Error(data.message || "That did not work. Open Logins again.");
  return data;
}
// The icons the markup asks for (`data-icon`), drawn by the firewall's page kit.
function paintIcons(root) {
  for (const s of root.querySelectorAll("[data-icon]")) {
    const svg = kit.icon(s.dataset.icon, "shrink-0 " + (s.dataset.iconClass || "h-4 w-4"));
    s.replaceWith(svg);
  }
}
paintIcons(document);
const CARD = "rounded-xl border border-line bg-surface p-5 sm:p-6";
const CHIP = "inline-flex min-h-[38px] cursor-pointer items-center gap-2 rounded-[10px] border border-line-2 bg-surface px-2.5 py-1.5 has-[:checked]:border-brand has-[:checked]:bg-brand-soft has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-brand";
const ROW = "flex items-center gap-2.5 border-b border-line px-3 py-2.5 last:border-b-0";
// One agent as a chip with a box to tick.
function agentChip(a, checked) {
  return kit.h("label", { class: CHIP },
    kit.h("input", { type: "checkbox", class: "h-4 w-4 shrink-0 accent-brand", value: a.vmId, checked: checked || null }),
    kit.h("span", { class: "grid h-6 w-6 shrink-0 place-items-center rounded-md bg-bg-2 text-ink-2" }, kit.icon("bot", "h-3.5 w-3.5")),
    kit.h("span", { class: "min-w-0 [overflow-wrap:anywhere]" }, a.name));
}
function fillAgents(box, pick) {
  box.textContent = "";
  if (!agents.length) { box.textContent = "This organization has no agents yet."; return; }
  for (const a of agents) box.append(agentChip(a, pick(a)));
}
const ticked = (box) => [...el(box).querySelectorAll("input:checked")].map((b) => b.value);
// A list of rows to tick (vaults, addresses read off the sign-in page), in one bordered box.
const rowList = () => kit.h("div", { class: "overflow-hidden rounded-xl border border-line" });
function checkRow(value, label, checked, after) {
  return kit.h("label", { class: ROW + " cursor-pointer hover:bg-bg" },
    kit.h("input", { type: "checkbox", class: "h-4 w-4 shrink-0 accent-brand", value, checked: checked || null }),
    label, after || null);
}
// A page that only says something: the request is gone, or the pass is.
function fail(title, text, iconName) {
  const s = el("status");
  s.hidden = false;
  s.removeAttribute("role");
  s.className = requestId ? "py-4 text-center" : "rounded-xl border border-line bg-surface";
  s.textContent = "";
  if (requestId) {
    s.append(
      kit.h("span", { class: "mx-auto mb-3 grid h-11 w-11 place-items-center rounded-full bg-bg-2 text-ink-2" }, kit.icon(iconName || "clock", "h-5 w-5")),
      kit.h("h1", { class: "text-[18px] font-semibold tracking-[-0.01em] text-ink" }, title),
      kit.h("p", { class: "mx-auto mt-1.5 max-w-[44ch] text-[13.5px] text-pretty text-ink-2" }, text));
  } else {
    const all = el("alllogins");
    const href = all.getAttribute("href");
    const action = href && href !== "#" ? kit.button("All logins", { href, external: true, variant: "brand" }) : null;
    all.hidden = true;
    s.append(kit.empty({ icon: iconName || "lock", title, text, action }));
  }
  el("ask").hidden = true;
  el("askintro").hidden = true;
  el("tabs").hidden = true;
  el("formcard").hidden = true;
  el("aside").hidden = true;
  el("layout").className = "grid";
}
// The minimal page for a request an agent sent: no title row, no ways in, no notes.
if (requestId) {
  el("head").hidden = true;
  el("aside").hidden = true;
  el("layout").className = "grid";
  el("status").className = "flex items-center justify-center gap-2 py-8 text-[13px] text-ink-2";
} else {
  el("formcard").className = CARD;
}
let tab = "type";
function showTab(k) {
  tab = k;
  el("formcard").hidden = k !== "type";
  el("import").hidden = k !== "import";
  el("op").hidden = k !== "op";
}
async function load() {
  try {
    const state = await api("state" + (loginId ? "?login=" + encodeURIComponent(loginId) : requestId ? "?request=" + encodeURIComponent(requestId) : ""));
    agents = state.agents || [];
    const login = state.login;
    request = state.request && !state.request.expired ? state.request : null;
    if (requestId && !request) return fail("This request has expired", "It was already answered, or its 30 minutes are up. Ask the agent to send a new link.");
    if (request) {
      el("askreason").textContent = request.reason ? "“" + request.reason + "”" : "";
      el("askreason").hidden = !request.reason;
      if (request.answered) return fail("This request was already answered", "Someone saved a login for it. Ask the agent to send a new link if it still needs one.", "checkCircle");
      el("ask").hidden = false;
      if (request.kind === "session") {
        document.title = "Sign the agent in";
        el("asktitle").textContent = "Sign " + request.agent + " in to " + request.site;
        el("session").hidden = false;
        el("status").hidden = true;
        return;
      }
      document.title = "A login for " + request.agent;
      el("asktitle").textContent = request.agent + " asks for a login for " + request.site;
      el("askintro").hidden = false;
      el("name").value = request.site;
      el("sites").value = request.site;
      // The agent's address is shown, not filled in: the sign-in page decides where the password
      // may go, so a person has to take it over on purpose.
      if (request.url) {
        el("suggesturl").textContent = request.url;
        el("suggest").hidden = false;
        el("usesuggest").onclick = () => { el("url").value = request.url; el("suggest").hidden = true; el("url").focus(); };
      }
    }
    if (loginId && !login) return fail("That login is gone", "It may have been deleted. Open it again from the list of logins.");
    if (login) {
      el("title").textContent = login.name;
      document.title = login.name;
      if (!el("alllogins").hidden) el("back").hidden = false;
      el("alllogins").hidden = true;
      el("sub").textContent = login.source === "1password" ? "Kept in 1Password. Its sign-in settings are kept on this firewall." : "Type a new password, or change how it signs in. Nothing is changed until you save.";
      el("titlepills").replaceChildren(login.source === "1password" ? kit.pill("1Password", "brand", "key") : "", login.totp ? kit.pill("Two-step key", "muted") : "");
      el("name").value = login.name;
      el("sites").value = login.sites.join("\n");
      el("url").value = login.loginUrl || "";
      el("username").value = login.username;
      el("password").required = false;
      el("password").placeholder = "Type the new password";
      el("pwhint").textContent = "The old one is not shown. It is replaced when you save.";
      el("delete").hidden = false;
      for (const r of document.querySelectorAll("input[name=mode]")) r.checked = r.value === (login.mode || "swap");
      for (const r of document.querySelectorAll("input[name=auth]")) r.checked = r.value === (login.auth || "form");
      el("paths").value = (login.signInPaths || []).join("\n");
      if (el("paths").value) el("extra").open = true;
      el("learned").hidden = false;
      el("needspage").hidden = !login.needsSignInPage;
      if (login.source === "1password") {
        // Its name, sites and password are 1Password's. What says where the password may go is kept here.
        el("opnote").hidden = false;
        el("pwhint").textContent = "";
        for (const f of ["name", "sites", "username", "password", "show"]) el(f).disabled = true;
        el("password").placeholder = "";
        el("save").hidden = true;
        el("delete").hidden = true;
        el("formfoot").hidden = true;
      }
      const targets = login.learnedTargets || [];
      el("learnedlist").textContent = "";
      if (!targets.length) el("learnedlist").append(kit.h("p", { class: "text-[13px] text-ink-2" }, "Nothing yet. It fills in the first time the agent opens the sign-in page."));
      else {
        const list = rowList();
        for (const t of targets) {
          const note = t.expired ? kit.h("span", { class: "basis-full pl-[26px] text-[12px] text-pretty text-ink-2" }, "No longer used: it has not been on the sign-in page for 30 days, so sign-ins there are blocked again. It is used again once the agent opens the sign-in page and it is still there.") : null;
          const row = checkRow(t.url, kit.h("span", { class: "min-w-0 flex-1 font-mono text-[12.5px]" }, t.url), t.approved, t.approved ? null : kit.pill("Not used", "muted"));
          if (note) { row.classList.add("flex-wrap"); row.append(note); }
          row.querySelector("input").dataset.was = t.approved ? "1" : "";
          list.append(row);
        }
        el("learnedlist").append(list);
      }
      if (login.totp) {
        el("totp").placeholder = "Stored. Paste to replace";
        el("totphint").textContent = "A two-step key is stored. Leave this empty to keep it.";
        el("totpremove").hidden = false;
      }
    }
    fillAgents(el("agents"), (a) => (login ? login.vmIds.includes(a.vmId) : request ? a.vmId === request.vmId : agents.length === 1));
    el("form").hidden = false;
    if (!login && !request) {
      el("tabs").replaceChildren(kit.segmented("How to add logins", [
        { key: "type", label: "Type it in", icon: "pencil" },
        { key: "import", label: "Import a CSV", icon: "file" },
        { key: "op", label: "1Password", icon: "key" },
      ], tab, showTab));
      el("tabs").hidden = false;
      fillAgents(el("importagents"), () => agents.length === 1);
      fillAgents(el("opagents"), () => agents.length === 1);
      showOp(state.onePassword);
    }
    el("status").hidden = true;
  } catch (e) {
    fail("That did not work", e.message);
  }
}
el("show").onclick = () => {
  const p = el("password");
  const shown = p.type === "password";
  p.type = shown ? "text" : "password";
  el("show").setAttribute("aria-pressed", String(shown));
  el("show").setAttribute("aria-label", shown ? "Hide the password" : "Show the password");
  el("show").replaceChildren(kit.icon(shown ? "eyeOff" : "eye", "h-[15px] w-[15px] shrink-0"));
};
const readPaths = () => el("paths").value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
el("savescope").onclick = async () => {
  el("error").textContent = "";
  el("scopesaved").textContent = "";
  el("savescope").disabled = true;
  try {
    const boxes = [...el("learnedlist").querySelectorAll("input")];
    const forget = boxes.filter((b) => !b.checked && b.dataset.was).map((b) => b.value);
    const approve = boxes.filter((b) => b.checked).map((b) => b.value);
    const auth = (document.querySelector("input[name=auth]:checked") || {}).value || "form";
    const out = await api("scope", { id: loginId, loginUrl: el("url").value.trim() || null, auth, signInPaths: readPaths(), approve, forget });
    for (const b of boxes) {
      const row = b.closest("label");
      if (forget.includes(b.value)) row.remove();
      else if (b.checked) {
        b.dataset.was = "1";
        for (const extra of [...row.children].slice(2)) extra.remove();
      }
    }
    el("needspage").hidden = !out.login.needsSignInPage;
    el("scopesaved").textContent = "Saved.";
  } catch (err) {
    el("error").textContent = err.message;
  } finally {
    el("savescope").disabled = false;
  }
};
// What was saved, in place of the form.
function done(title, text) {
  el("donetitle").textContent = title;
  el("donetext").textContent = text;
  for (const id of ["form", "formcard", "import", "op", "tabs", "aside", "session", "askintro", "ask"]) el(id).hidden = true;
  if (requestId) {
    el("done").className = "flex flex-col items-center gap-2 py-4 text-center focus:outline-none";
    el("donetitle").className = "mt-1 text-[18px] font-semibold tracking-[-0.01em] text-ink";
  } else el("again").hidden = false;
  el("layout").className = "grid";
  el("done").hidden = false;
  el("done").setAttribute("tabindex", "-1");
  el("done").focus();
}
el("form").onsubmit = async (e) => {
  e.preventDefault();
  el("error").textContent = "";
  const vmIds = ticked("agents");
  if (!vmIds.length) { el("error").textContent = "Pick at least one agent."; return; }
  // An international name is sent the way it is on the wire (punycode), which is what the firewall compares.
  const wire = (h) => { try { const star = h.startsWith("*.") ? "*." : ""; return star + new URL("https://" + h.slice(star.length)).hostname; } catch { return h; } };
  const sites = el("sites").value.split(/[\s,]+/).map((s) => s.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "")).filter(Boolean).map(wire);
  el("save").disabled = true;
  try {
    const totp = el("totp").value.trim();
    const mode = (document.querySelector("input[name=mode]:checked") || {}).value || "swap";
    const auth = (document.querySelector("input[name=auth]:checked") || {}).value || "form";
    const out = await api("save", { auth, signInPaths: readPaths(), id: loginId || undefined, requestId: request ? request.id : undefined, name: el("name").value, sites, loginUrl: el("url").value.trim() || null, username: el("username").value, password: el("password").value, vmIds, mode, totp: totp || undefined, removeTotp: el("removetotp").checked || undefined });
    el("password").value = "";
    el("totp").value = "";
    const names = agents.filter((a) => vmIds.includes(a.vmId)).map((a) => a.name).join(", ");
    done("Saved on your firewall", names + " can now sign in to " + out.login.sites.join(", ") + " with " + out.login.name + "." + (request ? " The agent sees that you answered, signs in, and sends you a screenshot in the chat." : " Ask the agent to try it."));
  } catch (err) {
    el("error").textContent = err.message;
  } finally {
    el("save").disabled = false;
  }
};
el("delete").onclick = async () => {
  if (!confirm("Delete this login? Agents can no longer use it.")) return;
  try {
    await api("delete", { id: loginId });
    done("Deleted", "The login is gone from your firewall.");
  } catch (err) {
    el("error").textContent = err.message;
  }
};
// CSV import. RFC 4180 with the column names 1Password, Bitwarden and Chrome use.
function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((v) => v !== "")) rows.push(row);
  return rows;
}
const COLUMNS = {
  name: ["name", "title"],
  url: ["url", "login_uri", "website", "uri", "urls"],
  username: ["username", "login_username", "user name", "email", "login"],
  password: ["password", "login_password"],
  totp: ["otpauth", "login_totp", "totp", "one-time password", "otp"],
  type: ["type"],
};
let importRows = [];
function readExport(text) {
  const all = parseCsv(text.replace(/^﻿/, ""));
  if (all.length < 2) return { rows: [], skipped: 0 };
  const head = all[0].map((h) => h.trim().toLowerCase());
  const col = (k) => head.findIndex((h) => COLUMNS[k].includes(h));
  const at = Object.fromEntries(Object.keys(COLUMNS).map((k) => [k, col(k)]));
  if (at.password < 0 || at.url < 0) throw new Error("This file has no password or URL column. Export a CSV of logins from your password manager.");
  const rows = [];
  let skipped = 0;
  for (const r of all.slice(1)) {
    const get = (k) => (at[k] >= 0 ? (r[at[k]] || "").trim() : "");
    if (at.type >= 0 && get("type") && get("type").toLowerCase() !== "login") { skipped++; continue; }
    const password = at.password >= 0 ? r[at.password] || "" : "";
    let host = "";
    try { const raw = get("url").split(/[\s,]+/)[0]; host = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : "https://" + raw).hostname.toLowerCase(); } catch {}
    if (!password || !host || !host.includes(".")) { skipped++; continue; }
    const url = get("url").split(/[\s,]+/)[0];
    // What the firewall would refuse is dropped here, so one odd row never stops the file.
    if (password.length > 1024 || /[\x00-\x1f\x7f]/.test(password)) { skipped++; continue; }
    const name = (get("name") || host).replace(/[\x00-\x1f\x7f]+/g, " ").trim().slice(0, 64) || host;
    const totp = get("totp");
    rows.push({ name, sites: [host], loginUrl: /^https?:\/\//i.test(url) && url.length <= 2048 ? url : null, username: get("username").replace(/[\x00-\x1f\x7f]+/g, " ").slice(0, 256), password, totp: /^otpauth:\/\/totp\//i.test(totp) || /^[A-Za-z2-7\s=-]{16,}$/.test(totp) ? totp : undefined });
  }
  return { rows, skipped };
}
function showFile(name, line, ok) {
  el("dropname").textContent = name;
  el("dropname").classList.toggle("font-mono", !!ok);
  el("preview").textContent = line;
  el("drop").classList.toggle("border-allow-border", !!ok);
  el("drop").classList.toggle("bg-allow-soft", !!ok);
  el("drop").classList.toggle("border-dashed", !ok);
  el("dropicon").classList.toggle("text-allow-fg", !!ok);
  el("dropchange").hidden = !ok;
  el("importwho").hidden = !ok;
}
el("csv").onchange = async () => {
  el("importerror").textContent = "";
  el("doimport").disabled = true;
  el("doimportlabel").textContent = "Import";
  importRows = [];
  const file = el("csv").files[0];
  if (!file) { showFile("Choose a CSV file", "Read in this page, never uploaded to ControlClaw", false); return; }
  try {
    const { rows, skipped } = readExport(await file.text());
    importRows = rows;
    showFile(file.name, rows.length ? rows.length + " login(s) to import" + (skipped ? " · " + skipped + " row(s) skipped (no password or no site)" : "") : "No logins found in this file.", rows.length > 0);
    el("doimportlabel").textContent = rows.length ? "Import " + rows.length + " login(s)" : "Import";
    el("doimport").disabled = !rows.length;
  } catch (err) {
    showFile(file.name, "Not read.", false);
    el("importerror").textContent = err.message;
  }
};
el("doimport").onclick = async () => {
  el("importerror").textContent = "";
  const vmIds = ticked("importagents");
  if (!vmIds.length) { el("importerror").textContent = "Tick at least one agent."; return; }
  el("doimport").disabled = true;
  try {
    let added = 0, skipped = 0, full = false;
    for (let i = 0; i < importRows.length && !full; i += 200) {
      const out = await api("import", { rows: importRows.slice(i, i + 200), vmIds });
      added += out.added; skipped += out.skipped; full = out.full;
    }
    importRows = [];
    el("csv").value = "";
    done("Imported to your firewall", added + " login(s) imported" + (skipped ? ", " + skipped + " skipped" : "") + (full ? ". Your firewall is full (1000 logins), so the rest were not imported" : "") + ". Delete the CSV file from your computer now.");
  } catch (err) {
    el("importerror").textContent = err.message;
    el("doimport").disabled = false;
  }
};
const STEP = "grid h-7 w-7 shrink-0 place-items-center rounded-full text-[12.5px] font-semibold ";
const STEP_TONE = { done: "bg-allow-soft text-allow-fg", now: "bg-brand text-white", next: "bg-bg-2 text-ink-2" };
function opSteps(found) {
  el("opstep2").className = STEP + STEP_TONE[found ? "done" : "now"];
  el("opstep3").className = STEP + STEP_TONE[found ? "now" : "next"];
}
function showOp(op) {
  el("opoff").hidden = !!op;
  el("opon").hidden = !op;
  el("opbusy").textContent = "";
  if (op) {
    const names = agents.filter((a) => op.vmIds.includes(a.vmId)).map((a) => a.name).join(", ") || "no agents";
    el("opcount").replaceChildren(kit.pill(op.items + " login(s)", "allow"));
    el("opstatus").textContent = "Vaults " + op.vaults.map((v) => v.name).join(", ") + " · for " + names + (op.lastSyncAt ? " · last read " + kit.when(new Date(op.lastSyncAt).getTime()) : "") + ", then every hour";
    el("oplast").textContent = op.lastError ? "Last attempt: " + op.lastError : "";
    el("oplast").hidden = !op.lastError;
  } else {
    el("opvaults").textContent = "";
    el("opwho").hidden = true;
    el("opconnect").disabled = true;
    opSteps(false);
  }
}
el("opfind").onclick = async () => {
  el("operror").textContent = "";
  el("opvaults").textContent = "";
  el("opwho").hidden = true;
  el("opconnect").disabled = true;
  opSteps(false);
  el("opfind").disabled = true;
  try {
    const out = await api("1password/vaults", { token: el("optoken").value.trim() });
    if (!out.vaults.length) { el("operror").textContent = "This token cannot open any vault."; return; }
    const list = rowList();
    for (const v of out.vaults) list.append(checkRow(v.id, kit.h("span", { class: "min-w-0 flex-1 [overflow-wrap:anywhere]" }, v.name), out.vaults.length === 1));
    el("opvaults").append(kit.h("fieldset", { class: "min-w-0" }, kit.h("legend", { class: "sr-only" }, "Vaults"), list));
    el("opwho").hidden = false;
    el("opconnect").disabled = false;
    opSteps(true);
  } catch (err) {
    el("operror").textContent = err.message;
  } finally {
    el("opfind").disabled = false;
  }
};
el("opconnect").onclick = async () => {
  el("operror").textContent = "";
  const vaultIds = ticked("opvaults");
  const vmIds = ticked("opagents");
  if (!vaultIds.length) { el("operror").textContent = "Pick at least one vault."; return; }
  if (!vmIds.length) { el("operror").textContent = "Tick at least one agent."; return; }
  el("opconnect").disabled = true;
  try {
    const out = await api("1password/connect", { token: el("optoken").value.trim(), vaultIds, vmIds });
    el("optoken").value = "";
    showOp(out.onePassword);
  } catch (err) {
    el("operror").textContent = err.message;
    el("opconnect").disabled = false;
  }
};
el("opsync").onclick = async () => {
  el("opbusy").textContent = "Reading 1Password…";
  el("opsync").disabled = true;
  try { showOp((await api("1password/sync", {})).onePassword); } catch (err) { el("opbusy").textContent = err.message; } finally { el("opsync").disabled = false; }
};
el("opdisconnect").onclick = async () => {
  if (!confirm("Disconnect 1Password? Its logins are removed from your firewall, and the token is forgotten.")) return;
  try { await api("1password/disconnect", {}); showOp(null); } catch (err) { el("opbusy").textContent = err.message; }
};
// Which of the three steps is next.
function sessionStep(n) {
  [...el("steps").children].forEach((li, i) => {
    li.firstElementChild.className = STEP + STEP_TONE[i + 1 < n ? "done" : i + 1 === n ? "now" : "next"];
  });
}
el("opentab").onclick = async () => {
  el("sessionerror").textContent = "";
  const tab = window.open("", "_blank");
  if (tab) tab.opener = null;
  try {
    const out = await api("open-tab", { requestId });
    if (!out.opened) el("sessionerror").textContent = "The agent's browser did not answer, so open the site there yourself: " + request.site;
    if (tab && out.screenUrl) tab.location.href = out.screenUrl;
    else if (tab) tab.close();
    sessionStep(out.opened ? 3 : 2);
  } catch (err) {
    if (tab) tab.close();
    el("sessionerror").textContent = err.message;
  }
};
el("sessiondone").onclick = async () => {
  el("sessionerror").textContent = "";
  el("sessiondone").disabled = true;
  try {
    const out = await api("session", { requestId });
    done("Signed in", request.agent + " is signed in to " + out.login.sites.join(", ") + ". The agent sees that you answered and carries on.");
  } catch (err) {
    el("sessionerror").textContent = err.message;
    el("sessiondone").disabled = false;
  }
};
load();
