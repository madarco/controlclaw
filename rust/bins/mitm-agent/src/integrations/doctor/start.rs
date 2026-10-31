//! Starting a Doctor repair on the firewall itself (`doctor-start.ts`, docs/plans/doctor-rescue.md,
//! Phase 1): pick the agent, coding agent, credential and model, describe the problem, confirm the
//! code. The problem never leaves this box; the console signs the intent and later learns the
//! session's metadata from the upload.
//!
//! The viewer is the console's `DoctorStartPage` (packages/console-ui), built by
//! `apps/firewall-panel/scripts/build-fw-files.mjs` into `dist-ui/doctor-start.js`. The TS inlines it at build time;
//! here it is read from the `dist-ui/` the pages' stylesheet comes from (`fw_shell::ui_dir`: next to the
//! binary, as the release ships it, or `CC_FW_UI_DIR`), and is empty without it.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use cc_http::{Req, Resp};

use super::chat::{DoctorChat, cookie_token, form_get, notice, read_body, same_origin};
use super::firewall::DoctorFirewall;

/// This firewall as a Doctor target, `(vmId, name)`, or None while Firewall Doctor is not installed.
pub type Firewall = Arc<dyn Fn() -> Option<(String, String)> + Send + Sync>;
use crate::app::App;
use crate::integrations::js;

pub const ROOT: &str = "/__cc/doctor/start";
const COOKIE: &str = "__Secure-cc_doctor_start";
const GRANT_MS: i64 = 30 * 60_000;
/// How long a proposed repair keeps its problem text here while the code is entered.
const PENDING_MS: i64 = 10 * 60_000;
const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src data:; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
static SESSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,80}$").expect("pattern"));
static CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:\d{6}|[0-9a-hjkmnp-tv-z]{16})$").expect("pattern"));

pub fn owns(path: &str) -> bool {
    path == ROOT || path.strip_prefix(ROOT).is_some_and(|r| r.starts_with('/'))
}

fn hash(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

fn send(status: u16, text: String, kind: &str) -> Resp {
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        &format!("{kind}; charset=utf-8"),
        text,
    );
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    r
}

fn plain(status: u16) -> Resp {
    send(status, String::new(), "text/plain")
}

fn reply(status: u16, v: Value) -> Resp {
    send(status, js::stringify(&v), "application/json")
}

fn redirect(status: u16, to: &str) -> Resp {
    let mut r = plain(status);
    r.headers_mut().remove(http::header::CONTENT_TYPE);
    if let Ok(v) = HeaderValue::from_str(to) {
        r.headers_mut().insert(http::header::LOCATION, v);
    }
    r
}

/// The checks the console makes on Start, made again here against the intent's own choices.
pub fn choice_allows(choices: &[Value], cli: &str, credential_id: &str, model: &str) -> bool {
    let Some(c) = choices
        .iter()
        .find(|c| c.get("id").and_then(Value::as_str) == Some(credential_id))
    else {
        return false;
    };
    if !c
        .get("clis")
        .and_then(Value::as_array)
        .is_some_and(|l| l.iter().any(|x| x == cli))
    {
        return false;
    }
    // An AI Gateway key takes any gateway model: its catalog is open-ended.
    c.get("provider").and_then(Value::as_str) == Some("vercel_gateway")
        || c.get("models")
            .and_then(Value::as_array)
            .is_some_and(|l| l.iter().any(|m| m.get("id").and_then(Value::as_str) == Some(model)))
}

#[derive(Clone)]
struct Grant {
    user_id: String,
    device_id: String,
    choices: Vec<Value>,
    agent: Option<String>,
    expires_at: i64,
}

struct Pending {
    user_id: String,
    device_id: String,
    vm_id: String,
    problem: String,
    expires_at: i64,
}

pub struct DoctorStart {
    app: Arc<App>,
    doctor: Arc<DoctorFirewall>,
    chat: Arc<DoctorChat>,
    agents: Arc<dyn Fn() -> Vec<super::Target> + Send + Sync>,
    /// This firewall as a target when Firewall Doctor is installed: `(vmId, name)`. Asked on every
    /// request, as the TS checks for the helpers each time.
    firewall: Firewall,
    grants: Mutex<HashMap<String, Grant>>,
    pending: Mutex<HashMap<String, Pending>>,
    ui_dir: String,
    now: super::Clock,
}

impl DoctorStart {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        app: &Arc<App>,
        doctor: Arc<DoctorFirewall>,
        chat: Arc<DoctorChat>,
        agents: Arc<dyn Fn() -> Vec<super::Target> + Send + Sync>,
        firewall: Firewall,
        ui_dir: String,
        now: super::Clock,
    ) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            doctor,
            chat,
            agents,
            firewall,
            grants: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            ui_dir,
            now,
        })
    }

    fn refused(&self) -> Resp {
        let t = "Start a repair from the console (an agent's Doctor tab, then Doctor on your firewall) as an owner or admin, in an enrolled browser. Open a working agent first to enroll this browser.";
        send(
            403,
            notice(&self.app, Some("Doctor unavailable"), t, None, None),
            "text/html",
        )
    }

    fn grant(&self, headers: &HeaderMap) -> Option<Grant> {
        let token = cookie_token(headers, COOKIE)?;
        let g = self
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash(&token))
            .cloned()?;
        let access = self.app.contracts.page_access.get()?;
        (g.expires_at > (self.now)() && access.device_active(headers, "doctor-start", &g.user_id, &g.device_id, None))
            .then_some(g)
    }

    fn prune(&self) {
        let now = (self.now)();
        self.grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, g| g.expires_at > now);
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, p| p.expires_at > now);
    }

    /// `consoleDoctorFirewallUrl`: the console route that opens this page.
    fn doctor_url(&self) -> Option<String> {
        let f = &self.app.config.firewall_url;
        if !f.starts_with("http") {
            return None;
        }
        let mut u = url::Url::parse(f).ok()?.join("/dashboard/doctor/firewall").ok()?;
        if !self.app.config.box_id.is_empty() {
            u.query_pairs_mut().append_pair("vm", &self.app.config.box_id);
        }
        Some(u.to_string())
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let path = cc_http::pathname(&req.uri().to_string());
        let get = req.method() == Method::GET;
        if path == format!("{ROOT}/open.js") && get {
            let js = format!(
                r#"const p=new URLSearchParams(location.hash.slice(1)),intent=p.get("i");history.replaceState(null,"",location.pathname);if(!intent){{document.getElementById("status").textContent="Start a repair from the console."}}else{{const form=document.createElement("form");form.method="POST";form.action="{ROOT}/open";const input=document.createElement("input");input.type="hidden";input.name="intent";input.value=intent;form.append(input);document.body.append(form);form.submit()}}"#
            );
            return send(200, js, "text/javascript");
        }
        if path == format!("{ROOT}/open") && get {
            let script = format!("{ROOT}/open.js");
            return send(
                200,
                notice(&self.app, None, "Opening Doctor...", Some("status"), Some(&script)),
                "text/html",
            );
        }
        if path == format!("{ROOT}/open") && req.method() == Method::POST {
            if !same_origin(&self.app, req.headers()) {
                return plain(403);
            }
            if !req
                .headers()
                .get(http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"))
            {
                return plain(415);
            }
            let (parts, body) = req.into_parts();
            let Some(raw) = read_body(body, &parts.headers, 16_384).await else {
                return plain(500);
            };
            let Some(access) = self.app.contracts.page_access.get() else {
                return self.refused();
            };
            let Some(p) = access
                .authorize(&parts.headers, form_get(&raw, "intent"), "doctor-start")
                .await
            else {
                return self.refused();
            };
            // Members cannot start Doctor: `authorizeFirewallPage` refuses a doctor-start intent
            // without `canWrite`, whatever the provider of the contract does.
            if !p.can_write {
                return self.refused();
            }
            let Some(choices) = p.extra.get("doctorChoices").and_then(Value::as_array).cloned() else {
                return self.refused();
            };
            self.prune();
            if self.grants.lock().unwrap_or_else(|e| e.into_inner()).len() >= 1000 {
                return plain(429);
            }
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            let agent = p
                .extra
                .get("doctorAgent")
                .and_then(Value::as_str)
                .filter(|a| !a.is_empty())
                .map(String::from);
            self.grants.lock().unwrap_or_else(|e| e.into_inner()).insert(
                hash(&token),
                Grant {
                    user_id: p.user_id,
                    device_id: p.device_id,
                    choices,
                    agent,
                    expires_at: (self.now)() + GRANT_MS,
                },
            );
            let mut r = redirect(303, &format!("{ROOT}/"));
            let cookie = format!(
                "{COOKIE}={token}; Path={ROOT}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                GRANT_MS / 1000
            );
            if let Ok(v) = HeaderValue::from_str(&cookie) {
                r.headers_mut().insert(http::header::SET_COOKIE, v);
            }
            return r;
        }
        let Some(grant) = self.grant(req.headers()) else {
            // The page's own address, typed or bookmarked: the console signs an intent and sends the browser back.
            if get
                && (path == ROOT || path == format!("{ROOT}/"))
                && let Some(entry) = self.doctor_url()
            {
                return redirect(303, &entry);
            }
            return self.refused();
        };
        if get {
            if path == ROOT {
                return redirect(308, &format!("{ROOT}/"));
            }
            if path == format!("{ROOT}/") {
                return send(200, self.page(), "text/html");
            }
            if path == format!("{ROOT}/app.js") {
                let js = std::fs::read_to_string(std::path::Path::new(&self.ui_dir).join("doctor-start.js"))
                    .unwrap_or_default();
                return send(200, js, "text/javascript");
            }
            if path == format!("{ROOT}/state") {
                let mut agents: Vec<Value> = Vec::new();
                if let Some((vm, _)) = (self.firewall)() {
                    agents.push(json!({"vmId": vm, "name": "This firewall", "ready": true, "firewall": true}));
                }
                agents.extend((self.agents)().into_iter().map(
                    |a| json!({"vmId": a.vm_id, "name": a.name, "ready": a.key_ready && !a.ssh_host_key.is_empty()}),
                ));
                let mut out = crate::integrations::as_map(json!({"agents": agents, "choices": grant.choices}));
                if let Some(a) = grant.agent.as_ref().filter(|a| agents.iter().any(|x| x["vmId"] == **a)) {
                    out.insert("selected".into(), json!(a));
                }
                return reply(200, Value::Object(out));
            }
            return plain(404);
        }
        if req.method() != Method::POST {
            return plain(405);
        }
        if !same_origin(&self.app, req.headers()) {
            return plain(403);
        }
        if !req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/json"))
        {
            return plain(415);
        }
        let (parts, body) = req.into_parts();
        let Some(raw) = read_body(body, &parts.headers, 40_000).await else {
            return plain(400);
        };
        let Some(body) = serde_json::from_slice::<Value>(&raw)
            .ok()
            .filter(|b| b.is_object() || b.is_array())
        else {
            return plain(400);
        };
        match path.strip_prefix(ROOT).unwrap_or("") {
            "/propose" => self.propose(&grant, &body).await,
            "/confirm" => self.confirm(&grant, &body).await,
            _ => plain(404),
        }
    }

    fn page(&self) -> String {
        let console = super::chat::fw_console_url(&self.app, "");
        let tail = r#"<script type="module" src="app.js"></script>"#;
        match self.app.contracts.fw_shell.get() {
            Some(s) => s.shell_page(
                "Agent Doctor",
                "doctor",
                r#"<div id="root"></div>"#,
                console.as_deref(),
                tail,
            ),
            None => format!(
                r#"<!doctype html><meta charset="utf-8"><title>Agent Doctor</title><div id="root"></div>{tail}"#
            ),
        }
    }

    async fn propose(&self, grant: &Grant, body: &Value) -> Resp {
        let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("");
        let (vm_id, cli, credential_id) = (
            s("vmId").to_string(),
            s("cli").to_string(),
            s("credentialId").to_string(),
        );
        let model = js::trim(s("model")).to_string();
        let problem = js::trim(s("problem")).to_string();
        let fail = |status: u16, m: &str| reply(status, json!({"ok": false, "status": "failed", "message": m}));
        if !["claude", "codex", "pi"].contains(&cli.as_str())
            || vm_id.is_empty()
            || model.is_empty()
            || model.encode_utf16().count() > 150
        {
            return fail(400, "Choose an agent, a coding agent and a model.");
        }
        if problem.is_empty() || problem.encode_utf16().count() > 8000 {
            return fail(400, "Describe the problem (up to 8,000 characters).");
        }
        if !choice_allows(&grant.choices, &cli, &credential_id, &model) {
            return fail(400, "Choose a credential and model offered for this coding agent.");
        }
        let known =
            (self.firewall)().is_some_and(|(v, _)| v == vm_id) || (self.agents)().iter().any(|a| a.vm_id == vm_id);
        if !known {
            return fail(400, "This firewall does not know that agent.");
        }
        self.prune();
        if self.pending.lock().unwrap_or_else(|e| e.into_inner()).len() >= 100 {
            return plain(429);
        }
        let session_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 18]>());
        let p = crate::integrations::as_map(
            json!({"sessionId": session_id, "vmId": vm_id, "cli": cli, "credentialId": credential_id, "model": model}),
        );
        let out = self.doctor.start_local(p, &grant.user_id).await;
        let data = out.data.clone().unwrap_or_default();
        if out.ok {
            self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(
                session_id.clone(),
                Pending {
                    user_id: grant.user_id.clone(),
                    device_id: grant.device_id.clone(),
                    vm_id,
                    problem,
                    expires_at: (self.now)() + PENDING_MS,
                },
            );
        }
        let mut r = Map::new();
        r.insert("ok".into(), json!(out.ok));
        r.insert("status".into(), json!(out.status));
        if let Some(m) = &out.message {
            r.insert("message".into(), json!(m));
        }
        r.insert("sessionId".into(), json!(session_id));
        for k in ["summary", "sentVia"] {
            if let Some(v) = data.get(k).filter(|v| v.is_string()) {
                r.insert(k.into(), v.clone());
            }
        }
        if let Some(c) = data
            .get("recovery")
            .and_then(|r| r.get("challenge"))
            .filter(|c| c.is_string())
        {
            r.insert("challenge".into(), c.clone());
        }
        if let Some(a) = data.get("attemptsLeft").filter(|a| a.is_number()) {
            r.insert("attemptsLeft".into(), a.clone());
        }
        if let Some(e) = data.get("expiresAt") {
            let iso = match e {
                Value::String(s) => js::parse_iso(s).map(js::iso),
                Value::Number(n) => n.as_f64().map(|f| js::iso(f as i64)),
                _ => None,
            };
            if let Some(i) = iso {
                r.insert("expiresAt".into(), json!(i));
            }
        }
        reply(if out.ok { 200 } else { 409 }, Value::Object(r))
    }

    async fn confirm(&self, grant: &Grant, body: &Value) -> Resp {
        let sid = body.get("sessionId").and_then(Value::as_str).unwrap_or("").to_string();
        let code = js::trim(body.get("code").and_then(Value::as_str).unwrap_or("")).to_string();
        let pending = {
            let now = (self.now)();
            let p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            p.get(&sid)
                .filter(|p| p.user_id == grant.user_id && p.device_id == grant.device_id && p.expires_at > now)
                .map(|p| (p.vm_id.clone(), p.problem.clone()))
        };
        // The code belongs to the person and browser that proposed the repair.
        let Some((vm_id, problem)) = pending.filter(|_| SESSION.is_match(&sid)) else {
            return reply(
                409,
                json!({"ok": false, "status": "expired", "message": "This repair request expired. Start a new one."}),
            );
        };
        if !CODE.is_match(&code) {
            return reply(
                400,
                json!({"ok": false, "status": "invalid_code", "message": "Enter the 6-digit code or the 16-character recovery answer."}),
            );
        }
        let out = self.doctor.confirm_local(&sid, &code, &grant.user_id).await;
        let data = out.data.clone().unwrap_or_default();
        if out.status != "running" {
            if out.status != "invalid_code" || data.get("attemptsLeft") == Some(&json!(0)) {
                self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sid);
            }
            let mut r = crate::integrations::as_map(json!({"ok": false, "status": out.status, "sessionId": sid}));
            if let Some(m) = &out.message {
                r.insert("message".into(), json!(m));
            }
            if let Some(a) = data.get("attemptsLeft").filter(|a| a.is_number()) {
                r.insert("attemptsLeft".into(), a.clone());
            }
            return reply(409, Value::Object(r));
        }
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&sid);
        self.doctor.reply(&sid, &problem).await;
        let cookie = self.chat.issue(&sid, &vm_id, &grant.user_id, &grant.device_id, true);
        let mut r = reply(
            200,
            json!({"ok": true, "status": "running", "sessionId": sid, "chat": "/__cc/doctor/chat/"}),
        );
        if let Some(c) = cookie.and_then(|c| HeaderValue::from_str(&c).ok()) {
            r.headers_mut().insert(http::header::SET_COOKIE, c);
        }
        r
    }
}

#[cfg(test)]
mod tests;
