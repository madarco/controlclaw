
const el = (id) => document.getElementById(id);
const params = new URLSearchParams(location.search);
const loginId = params.get("login") || "";
const requestId = params.get("request") || "";
let request = null;
let agents = [];
async function api(path, body) {
  const r = await fetch("/__cc/logins/" + path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {});
  let data = {};
  try { data = await r.json(); } catch {}
  if (!r.ok) throw new Error(data.message || "That did not work. Open Logins again from your ControlClaw console.");
  return data;
}
function agentBox(a, checked) {
  const label = document.createElement("label");
  label.className = "flex items-center gap-2 py-1 text-[14px] text-ink";
  const box = document.createElement("input");
  box.type = "checkbox"; box.className = "h-[18px] w-[18px] shrink-0 accent-brand"; box.value = a.vmId; box.checked = checked;
  label.append(box, document.createTextNode(a.name));
  return label;
}
async function load() {
  try {
    const state = await api("state" + (loginId ? "?login=" + encodeURIComponent(loginId) : requestId ? "?request=" + encodeURIComponent(requestId) : ""));
    agents = state.agents || [];
    const login = state.login;
    request = state.request && !state.request.expired ? state.request : null;
    if (requestId && !request) throw new Error("This request has expired or was already answered elsewhere. Ask the agent to send a new link.");
    if (request) {
      el("ask").textContent = "";
      const who = document.createElement("strong");
      who.textContent = request.agent;
      el("ask").append(who, document.createTextNode(" asks for a login for "), Object.assign(document.createElement("strong"), { textContent: request.site }), document.createTextNode(request.reason ? ": " + request.reason : "."));
      el("ask").hidden = false;
      if (request.answered) throw new Error("This request was already answered.");
      if (request.kind === "session") {
        document.title = "Sign the agent in";
        el("title").textContent = "Sign " + request.agent + " in to " + request.site;
        el("session").hidden = false;
        el("status").hidden = true;
        return;
      }
      el("title").textContent = "Add a login for " + request.agent;
      el("name").value = request.site;
      el("sites").value = request.site;
      // The agent's address is shown, not filled in: the sign-in page decides where the password
      // may go, so a person has to take it over on purpose.
      if (request.url) {
        el("suggesturl").textContent = request.url;
        el("suggest").hidden = false;
        el("usesuggest").onclick = () => { el("url").value = request.url; el("suggest").hidden = true; };
      }
    }
    if (loginId && !login) throw new Error("That login is gone. It may have been deleted.");
    if (login) {
      el("title").textContent = "Replace " + login.name;
      document.title = "Replace " + login.name;
      el("name").value = login.name;
      el("sites").value = login.sites.join("\n");
      el("url").value = login.loginUrl || "";
      el("username").value = login.username;
      el("pwhint").textContent = "Type the new password. The old one is not shown, and is replaced when you save.";
      el("delete").hidden = false;
      for (const r of document.querySelectorAll("input[name=mode]")) r.checked = r.value === (login.mode || "swap");
      for (const r of document.querySelectorAll("input[name=auth]")) r.checked = r.value === (login.auth || "form");
      el("paths").value = (login.signInPaths || []).join("\n");
      el("learned").hidden = false;
      el("learnedlist").textContent = (login.learnedTargets || []).length ? "" : "Nothing yet. It fills in the first time the agent opens the sign-in page.";
      el("needspage").hidden = !login.needsSignInPage;
      if (login.source === "1password") {
        // Its name, sites and password are 1Password's. What says where the password may go is kept here.
        el("pwhint").textContent = "This login comes from 1Password: change its name, sites and password there. The sign-in page, the kind and the addresses below are kept on your firewall: press Save sign-in settings.";
        el("password").required = false;
        el("password").disabled = true;
        el("save").hidden = true;
        el("delete").hidden = true;
      }
      for (const t of login.learnedTargets || []) {
        const label = document.createElement("label");
        label.className = "flex items-center gap-2 py-1 text-[14px] text-ink";
        const box = document.createElement("input");
        box.type = "checkbox"; box.className = "h-[18px] w-[18px] shrink-0 accent-brand"; box.value = t.url; box.checked = !!t.approved; box.dataset.was = t.approved ? "1" : "";
        label.append(box, document.createTextNode(t.url + (t.expired ? " (no longer used: it has not been on the sign-in page for 30 days, so sign-ins there are blocked again. It is used again once the agent opens the sign-in page and it is still there.)" : t.approved ? "" : " (not used)")));
        el("learnedlist").append(label);
      }
      if (login.totp) {
        el("totphint").textContent = "A two-step key is stored. Paste a new one to replace it, or leave this empty to keep it.";
        el("totpremove").hidden = false;
      }
    }
    if (!agents.length) el("agents").textContent = "This organization has no agents yet.";
    for (const a of agents) el("agents").append(agentBox(a, login ? login.vmIds.includes(a.vmId) : request ? a.vmId === request.vmId : agents.length === 1));
    el("form").hidden = false;
    el("import").hidden = !!(login || request);
    el("op").hidden = !!(login || request);
    showOp(state.onePassword);
    el("status").hidden = true;
  } catch (e) {
    el("status").textContent = e.message;
  }
}
el("show").onclick = () => {
  const p = el("password");
  p.type = p.type === "password" ? "text" : "password";
  el("show").textContent = p.type === "password" ? "Show" : "Hide";
};
const readPaths = () => el("paths").value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
el("savescope").onclick = async () => {
  el("error").textContent = "";
  el("scopesaved").textContent = "";
  try {
    const boxes = [...el("learnedlist").querySelectorAll("input")];
    const forget = boxes.filter((b) => !b.checked && b.dataset.was).map((b) => b.value);
    const approve = boxes.filter((b) => b.checked).map((b) => b.value);
    const auth = (document.querySelector("input[name=auth]:checked") || {}).value || "form";
    const out = await api("scope", { id: loginId, loginUrl: el("url").value.trim() || null, auth, signInPaths: readPaths(), approve, forget });
    for (const b of boxes) { if (forget.includes(b.value)) b.parentElement.remove(); else if (b.checked) { b.dataset.was = "1"; b.parentElement.lastChild.textContent = b.value; } }
    el("needspage").hidden = !out.login.needsSignInPage;
    el("scopesaved").textContent = "Saved.";
  } catch (err) {
    el("error").textContent = err.message;
  }
};
el("form").onsubmit = async (e) => {
  e.preventDefault();
  el("error").textContent = "";
  const vmIds = [...el("agents").querySelectorAll("input:checked")].map((b) => b.value);
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
    el("form").hidden = true;
    const names = agents.filter((a) => vmIds.includes(a.vmId)).map((a) => a.name).join(", ");
    el("donetext").textContent = names + " can now sign in to " + out.login.sites.join(", ") + " with " + out.login.name + "." + (request ? " The agent sees that you answered, signs in, and sends you a screenshot." : " Ask the agent to try it.");
    el("done").hidden = false;
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
    el("form").hidden = true;
    el("done").querySelector("h2").textContent = "Deleted";
    el("donetext").textContent = "The login is gone from your firewall.";
    el("done").hidden = false;
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
  const all = parseCsv(text.replace(/^\ufeff/, ""));
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
el("csv").onchange = async () => {
  el("importerror").textContent = "";
  el("doimport").hidden = true;
  importRows = [];
  const file = el("csv").files[0];
  if (!file) return;
  try {
    const { rows, skipped } = readExport(await file.text());
    importRows = rows;
    el("preview").textContent = rows.length ? rows.length + " login(s) to import" + (skipped ? ", " + skipped + " row(s) skipped (no password or no site)" : "") + ". Each gets its site from its URL." : "No logins found in this file.";
    el("doimport").textContent = "Import " + rows.length + " login(s)";
    el("doimport").hidden = !rows.length;
  } catch (err) {
    el("importerror").textContent = err.message;
  }
};
el("doimport").onclick = async () => {
  el("importerror").textContent = "";
  const vmIds = [...el("agents").querySelectorAll("input:checked")].map((b) => b.value);
  if (!vmIds.length) { el("importerror").textContent = "Tick at least one agent in the form above."; return; }
  el("doimport").disabled = true;
  try {
    let added = 0, skipped = 0, full = false;
    for (let i = 0; i < importRows.length && !full; i += 200) {
      const out = await api("import", { rows: importRows.slice(i, i + 200), vmIds });
      added += out.added; skipped += out.skipped; full = out.full;
    }
    importRows = [];
    el("csv").value = "";
    el("form").hidden = true;
    el("import").hidden = true;
    el("donetext").textContent = added + " login(s) imported" + (skipped ? ", " + skipped + " skipped" : "") + (full ? ". Your firewall is full (1000 logins), so the rest were not imported" : "") + ". Delete the CSV file from your computer now.";
    el("done").hidden = false;
  } catch (err) {
    el("importerror").textContent = err.message;
  } finally {
    el("doimport").disabled = false;
  }
};
function showOp(op) {
  el("opoff").hidden = !!op;
  el("opon").hidden = !op;
  if (op) {
    const names = agents.filter((a) => op.vmIds.includes(a.vmId)).map((a) => a.name).join(", ") || "no agents";
    el("opstatus").textContent = "Connected to " + op.vaults.map((v) => v.name).join(", ") + " for " + names + ". " + op.items + " login(s)" + (op.lastSyncAt ? ", last read " + new Date(op.lastSyncAt).toLocaleString() : "") + "." + (op.lastError ? " Last attempt: " + op.lastError : "");
  }
}
el("opfind").onclick = async () => {
  el("operror").textContent = "";
  el("opvaults").textContent = "";
  try {
    const out = await api("1password/vaults", { token: el("optoken").value.trim() });
    for (const v of out.vaults) {
      const l = document.createElement("label");
      l.className = "flex items-center gap-2 py-1 text-[14px] text-ink";
      const b = document.createElement("input");
      b.type = "checkbox"; b.className = "h-[18px] w-[18px] shrink-0 accent-brand"; b.value = v.id; b.checked = out.vaults.length === 1;
      l.append(b, document.createTextNode(v.name));
      el("opvaults").append(l);
    }
    if (!out.vaults.length) el("opvaults").textContent = "This token cannot open any vault.";
    el("opconnect").hidden = !out.vaults.length;
  } catch (err) {
    el("operror").textContent = err.message;
  }
};
el("opconnect").onclick = async () => {
  el("operror").textContent = "";
  const vaultIds = [...el("opvaults").querySelectorAll("input:checked")].map((b) => b.value);
  const vmIds = [...el("agents").querySelectorAll("input:checked")].map((b) => b.value);
  if (!vaultIds.length) { el("operror").textContent = "Pick at least one vault."; return; }
  if (!vmIds.length) { el("operror").textContent = "Tick at least one agent in the form above."; return; }
  el("opconnect").disabled = true;
  try {
    const out = await api("1password/connect", { token: el("optoken").value.trim(), vaultIds, vmIds });
    el("optoken").value = "";
    showOp(out.onePassword);
  } catch (err) {
    el("operror").textContent = err.message;
  } finally {
    el("opconnect").disabled = false;
  }
};
el("opsync").onclick = async () => {
  el("operror").textContent = "";
  try { showOp((await api("1password/sync", {})).onePassword); } catch (err) { el("operror").textContent = err.message; }
};
el("opdisconnect").onclick = async () => {
  if (!confirm("Disconnect 1Password? Its logins are removed from your firewall, and the token is forgotten.")) return;
  try { await api("1password/disconnect", {}); showOp(null); } catch (err) { el("operror").textContent = err.message; }
};
el("opentab").onclick = async () => {
  el("sessionerror").textContent = "";
  const tab = window.open("", "_blank");
  if (tab) tab.opener = null;
  try {
    const out = await api("open-tab", { requestId });
    if (!out.opened) el("sessionerror").textContent = "The agent's browser did not answer, so open the site there yourself: " + request.site;
    if (tab && out.screenUrl) tab.location.href = out.screenUrl;
    else if (tab) tab.close();
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
    el("session").hidden = true;
    el("donetext").textContent = request.agent + " is signed in to " + out.login.sites.join(", ") + ". The agent sees that you answered and carries on.";
    el("done").hidden = false;
  } catch (err) {
    el("sessionerror").textContent = err.message;
    el("sessiondone").disabled = false;
  }
};
load();
