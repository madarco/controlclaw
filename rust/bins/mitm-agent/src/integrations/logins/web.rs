//! The page where a person types a website login (`logins-web.ts`, docs/plans/website-credentials.md
//! §4.7), served by the firewall on its own public name. The console only ever opens it: the
//! password goes from this page straight to the firewall and is sealed here, so the control plane
//! never carries it.
//!
//!   GET  /__cc/logins/open     a page that posts the console's open intent back here
//!   POST /__cc/logins/open     intent (owner or admin) + enrolled browser → grant cookie → the form
//!   GET  /__cc/logins/         the form
//!   GET  /__cc/logins/state    the agents, and the login being replaced
//!   POST /__cc/logins/save     create, or replace with `id`
//!   POST /__cc/logins/delete   delete `id`
//!   POST /__cc/logins/scope    extra sign-in paths and learned targets of `id`, without the password
//!   POST /__cc/logins/open-tab open a chat request's site in the agent's browser; answers the Screen link
//!   POST /__cc/logins/session  a person signed the agent in themselves: record it
//!   POST /__cc/logins/import   many logins at once, from a password manager's CSV the page read
//!   POST /__cc/logins/1password/vaults|connect|sync|disconnect   a 1Password service account
//!
//! The grant lives 30 minutes in memory and only while the browser stays enrolled for that person.
//!
//! `page/` holds the page's markup and script exactly as `logins-page.ts` builds them. After a
//! change there, write them again: `tsx` a script that imports `LOGINS_BODY`, `LOGINS_TAIL` and
//! `LOGINS_APP_JS` and writes them to `page/body.html`, `page/tail.html` and `page/app.js`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use base64::Engine;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use cc_http::{Req, Resp};

use super::firewall::{LoginsFirewall, Refused};
use super::schema::{Issue, LOGIN_ID, REQUEST_ID};
use crate::app::App;
use crate::integrations::js;

pub const LOGINS_ROOT: &str = "/__cc/logins";
const COOKIE: &str = "__Secure-cc_logins";
const GRANT_MS: i64 = 30 * 60_000;
const MAX_GRANTS: usize = 500;
const BODY_BYTES: usize = 16 * 1024;
/// A CSV import: 200 logins of a few hundred bytes each.
const IMPORT_BYTES: usize = 512 * 1024;
const OPEN_BYTES: usize = 8 * 1024;

const LOGINS_BODY: &str = include_str!("page/body.html");
const LOGINS_TAIL: &str = include_str!("page/tail.html");
const LOGINS_APP_JS: &str = include_str!("page/app.js");

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{43}$").expect("pattern"));

pub fn owns_logins_path(path: &str) -> bool {
    path == LOGINS_ROOT || path.strip_prefix(LOGINS_ROOT).is_some_and(|r| r.starts_with('/'))
}

const HEADERS: &[(&str, &str)] = &[
    ("cache-control", "no-store"),
    // Not `no-referrer`: with it Chrome sends `Origin: null` on the open page's own form POST.
    ("referrer-policy", "same-origin"),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    // Styles only from this firewall's own stylesheet (fw-shell), which carries Inter as a data
    // URL: no inline styles, and nothing from anywhere else.
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src data:; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ),
];

const OPEN_JS: &str = concat!(
    r#"const h=new URLSearchParams(location.hash.slice(1));const i=h.get("i");const l=h.get("login")||"";const q=h.get("request")||"";history.replaceState(null,"",location.pathname);"#,
    r#"if(!i){document.getElementById("s").textContent="Open Logins from your ControlClaw console."}else{"#,
    r#"const f=document.createElement("form");f.method="POST";f.action="/__cc/logins/open";"#,
    r#"for(const[k,v]of[["intent",i],["login",l],["request",q]]){const n=document.createElement("input");n.type="hidden";n.name=k;n.value=v;f.append(n)}"#,
    "document.body.append(f);f.submit()}",
);

fn send(status: u16, body: String, kind: &str) -> Resp {
    let mut r = cc_http::full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        &format!("{kind}; charset=utf-8"),
        body,
    );
    for (k, v) in HEADERS {
        r.headers_mut().insert(*k, HeaderValue::from_static(v));
    }
    r
}

fn html(status: u16, body: String) -> Resp {
    send(status, body, "text/html")
}

fn bare(status: u16) -> Resp {
    html(status, String::new())
}

fn reply(status: u16, body: Value) -> Resp {
    send(status, js::stringify(&body), "application/json")
}

fn message(status: u16, m: &str) -> Resp {
    reply(status, json!({"message": m}))
}

fn hash(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

/// What is wrong with the sign-in page or an extra address, in the schema's own words: these two
/// are easy to get wrong.
fn scope_issue(i: &Issue) -> Option<String> {
    let label = match i.path.as_str() {
        "loginUrl" => "Sign-in page",
        "signInPaths" => "Extra sign-in addresses",
        _ => return None,
    };
    (!i.message.is_empty()).then(|| format!("{label}: {}.", i.message))
}

/// `err instanceof Error && !("issues" in err) ? err.message : (scopeIssue(err) ?? fallback)`.
fn refused_message(r: Refused, fallback: &str, scope: bool) -> String {
    match r {
        Refused::Message(m) => m,
        Refused::Invalid(i) => scope
            .then(|| scope_issue(&i))
            .flatten()
            .unwrap_or_else(|| fallback.into()),
    }
}

struct Grant {
    user_id: String,
    device_id: String,
    email: Option<String>,
    expires_at: i64,
}

impl Grant {
    fn by(&self) -> String {
        self.email.clone().unwrap_or_else(|| self.user_id.clone())
    }
}

/// A body read up to `cap`, refused past it, as `readBody` (Content-Length over the cap first).
async fn read_body(req: Req, cap: usize) -> Option<(http::request::Parts, Vec<u8>)> {
    let (parts, body) = req.into_parts();
    let declared = parts
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if declared.is_some_and(|d| d > cap as u64) {
        return None;
    }
    let got = http_body_util::Limited::new(body, cap).collect().await.ok()?;
    Some((parts, got.to_bytes().to_vec()))
}

fn query_get(uri: &http::Uri, k: &str) -> String {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .find(|(n, _)| n == k)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub struct LoginsWeb {
    app: Arc<App>,
    logins: Arc<LoginsFirewall>,
    grants: Mutex<HashMap<String, Grant>>,
    now: fn() -> i64,
}

impl LoginsWeb {
    pub fn new(app: &Arc<App>, logins: Arc<LoginsFirewall>) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            logins,
            grants: Mutex::new(HashMap::new()),
            now: js::now_ms,
        })
    }

    /// Where "Back to console" goes: the console's Website logins list.
    fn console_url(&self) -> Option<String> {
        let f = &self.app.config.firewall_url;
        if !f.starts_with("http") {
            return None;
        }
        url::Url::parse(f)
            .ok()?
            .join("/settings/secrets")
            .ok()
            .map(|u| u.to_string())
    }

    fn origin(&self) -> Option<String> {
        self.app.contracts.page_access.get().and_then(|a| a.origin())
    }

    // The notices are drawn when asked for, by the firewall's shell. Without one on this build, a
    // bare page with the same words.
    fn notice(&self, title: &str, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
        match self.app.contracts.fw_shell.get() {
            Some(s) => s.notice(title, heading, text, id, script),
            None => format!(
                "<!doctype html><meta charset=\"utf-8\"><title>{}</title><p{}>{}</p>{}",
                js::escape_html(title),
                id.map(|i| format!(" id=\"{}\"", js::escape_html(i)))
                    .unwrap_or_default(),
                js::escape_html(text),
                script
                    .map(|s| format!("<script src=\"{}\"></script>", js::escape_html(s)))
                    .unwrap_or_default()
            ),
        }
    }

    fn refused(&self) -> String {
        let t = "Logins could not open";
        self.notice(t, Some(t), "Open Logins from your ControlClaw console (Secrets, Logins) as an owner or admin, in a browser you have already used to open one of your agents. Links from the console work for one minute.", None, None)
    }

    fn expired(&self) -> String {
        let t = "This page has expired";
        self.notice(
            t,
            Some(t),
            "Open Logins again from your ControlClaw console.",
            None,
            None,
        )
    }

    /// The form in the firewall's shell, or, for a request an agent sent in a chat (`?request=`),
    /// alone under the ControlClaw mark: that link is opened to do one thing, usually on a phone.
    fn page(&self, uri: &http::Uri) -> String {
        let Some(shell) = self.app.contracts.fw_shell.get() else {
            return format!(
                "<!doctype html><meta charset=\"utf-8\"><title>Website logins</title>{LOGINS_BODY}{LOGINS_TAIL}"
            );
        };
        if REQUEST_ID.is_match(&query_get(uri, "request")) {
            return shell.minimal_page("Website login", LOGINS_BODY, LOGINS_TAIL);
        }
        let body = shell.content(&format!("<div class=\"max-w-[36rem]\">{LOGINS_BODY}</div>"));
        shell.shell_page(
            "Website logins",
            "logins",
            &body,
            self.console_url().as_deref(),
            LOGINS_TAIL,
        )
    }

    fn grant(&self, headers: &HeaderMap) -> Option<Grant> {
        let cookies: Vec<&str> = headers
            .get_all(http::header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let joined = cookies.join("; ");
        let prefix = format!("{COOKIE}=");
        let found: Vec<&str> = joined
            .split(';')
            .map(str::trim)
            .filter(|s| s.starts_with(&prefix))
            .collect();
        if found.len() != 1 {
            return None;
        }
        let token = &found[0][prefix.len()..];
        if !TOKEN.is_match(token) {
            return None;
        }
        let grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
        let g = grants.get(&hash(token))?;
        let access = self.app.contracts.page_access.get()?;
        if g.expires_at <= (self.now)() || !access.device_active(headers, "logins", &g.user_id, &g.device_id, None) {
            return None;
        }
        Some(Grant {
            user_id: g.user_id.clone(),
            device_id: g.device_id.clone(),
            email: g.email.clone(),
            expires_at: g.expires_at,
        })
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let path = cc_http::pathname(&req.uri().to_string());
        let method = req.method().clone();
        let open = format!("{LOGINS_ROOT}/open");
        if path == format!("{LOGINS_ROOT}/open.js") && method == Method::GET {
            return send(200, OPEN_JS.into(), "text/javascript");
        }
        if path == open && method == Method::GET {
            let script = format!("{LOGINS_ROOT}/open.js");
            return html(
                200,
                self.notice("Logins", None, "Opening Logins…", Some("s"), Some(&script)),
            );
        }
        if path == open && method == Method::POST {
            return self.open(req).await;
        }

        let root = path == LOGINS_ROOT || path == format!("{LOGINS_ROOT}/");
        let Some(grant) = self.grant(req.headers()) else {
            if method == Method::GET && root {
                return html(403, self.expired());
            }
            return message(
                403,
                "This page has expired. Open Logins again from your ControlClaw console.",
            );
        };
        if method == Method::GET {
            if root {
                return html(200, self.page(req.uri()));
            }
            if path == format!("{LOGINS_ROOT}/app.js") {
                return send(200, LOGINS_APP_JS.into(), "text/javascript");
            }
            if path == format!("{LOGINS_ROOT}/state") {
                return self.state(req.uri()).await;
            }
            return bare(404);
        }
        if method != Method::POST {
            return bare(405);
        }
        let origin = req.headers().get(http::header::ORIGIN).and_then(|v| v.to_str().ok());
        if self.origin().is_none() || origin != self.origin().as_deref() {
            return bare(403);
        }
        let json_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/json"));
        if !json_type {
            return bare(415);
        }
        let cap = if path == format!("{LOGINS_ROOT}/import") {
            IMPORT_BYTES
        } else {
            BODY_BYTES
        };
        let body = match read_body(req, cap).await {
            Some((_, b)) => serde_json::from_str::<Value>(&String::from_utf8_lossy(&b)).ok(),
            None => None,
        };
        // `!body || typeof body !== "object"`: an array gets through, as in the TS.
        let Some(body) = body.filter(|b| b.is_object() || b.is_array()) else {
            return message(400, "That could not be read.");
        };
        self.post(&path, &grant, body).await
    }

    async fn state(&self, uri: &http::Uri) -> Resp {
        let id = query_get(uri, "login");
        let valid = LOGIN_ID.is_match(&id);
        if valid {
            self.logins.ingest_learned_targets().await;
        }
        let login = if valid { self.logins.get(&id) } else { None };
        let agents: Vec<(String, String)> = self
            .app
            .contracts
            .identities
            .require()
            .ok()
            .map(|i| i.agents())
            .unwrap_or_default()
            .into_iter()
            .map(|a| {
                let name = a
                    .name
                    .filter(|n| !n.is_empty())
                    .or(a.hostname.filter(|h| !h.is_empty()))
                    .unwrap_or_else(|| a.vm_id.clone());
                (a.vm_id, name)
            })
            .collect();
        let rid = query_get(uri, "request");
        let request = if !REQUEST_ID.is_match(&rid) {
            Value::Null
        } else {
            match self.logins.get_request(&rid) {
                None => json!({"expired": true}),
                Some(r) => json!({
                    "id": r.id,
                    "site": r.site,
                    "kind": r.kind,
                    "reason": r.reason,
                    "url": r.url,
                    "vmId": r.vm_id,
                    "agent": agents.iter().find(|(v, _)| *v == r.vm_id).map(|(_, n)| n.clone()).unwrap_or_else(|| r.vm_id.clone()),
                    "answered": r.login_id.is_some(),
                    "expiresAt": js::iso(r.expires_at),
                }),
            }
        };
        let agents: Vec<Value> = agents.into_iter().map(|(v, n)| json!({"vmId": v, "name": n})).collect();
        reply(
            200,
            json!({"agents": agents, "login": login, "request": request, "onePassword": self.logins.one_password_status()}),
        )
    }

    async fn post(&self, path: &str, grant: &Grant, body: Value) -> Resp {
        let l = &self.logins;
        let id = body.get("id").and_then(Value::as_str).filter(|i| LOGIN_ID.is_match(i));
        let sub = path.strip_prefix(LOGINS_ROOT).unwrap_or("");
        if sub == "/save" {
            return match l.put(&grant.by(), &body, id).await {
                Ok(saved) => reply(200, json!({"ok": true, "login": saved})),
                Err(e) => message(
                    400,
                    &refused_message(
                        e,
                        "Check the fields: a name, at least one site, a password and at least one agent.",
                        true,
                    ),
                ),
            };
        }
        let request_id = body
            .get("requestId")
            .and_then(Value::as_str)
            .filter(|r| REQUEST_ID.is_match(r));
        if let (Some(rid), "/open-tab") = (request_id, sub) {
            let opened = l.open_tab(rid).await;
            return reply(
                200,
                json!({"ok": true, "opened": opened, "screenUrl": l.screen_link(rid)}),
            );
        }
        if let (Some(rid), "/session") = (request_id, sub) {
            return match l.record_session(&grant.by(), rid).await {
                Ok(saved) => reply(200, json!({"ok": true, "login": saved})),
                Err(e) => message(400, &refused_message(e, "That could not be saved.", false)),
            };
        }
        if let Some(what) = sub.strip_prefix("/1password/") {
            let fallback = "Check the token, and pick at least one vault and one agent.";
            let out = match what {
                "vaults" => {
                    let token = body.get("token").and_then(Value::as_str).unwrap_or("");
                    l.one_password_vaults(token).await.map(|v| {
                        let v: Vec<Value> = v.into_iter().map(|x| json!({"id": x.id, "name": x.name})).collect();
                        json!({"vaults": v})
                    })
                }
                "connect" => l
                    .one_password_connect(&grant.by(), &body)
                    .await
                    .map(|s| json!({"ok": true, "onePassword": s})),
                "sync" => {
                    l.one_password_sync().await;
                    Ok(json!({"ok": true, "onePassword": l.one_password_status()}))
                }
                "disconnect" => l
                    .one_password_disconnect("on the firewall page")
                    .await
                    .map(|ok| json!({"ok": ok})),
                _ => return bare(404),
            };
            return match out {
                Ok(v) => reply(200, v),
                Err(e) => message(400, &refused_message(e, fallback, false)),
            };
        }
        if sub == "/import" {
            return match l.import_rows(&grant.by(), &body).await {
                Ok((added, skipped, full)) => reply(
                    200,
                    json!({"ok": true, "added": added, "skipped": skipped, "full": full}),
                ),
                Err(e) => message(
                    400,
                    &refused_message(
                        e,
                        "Some rows could not be read. Every row needs a name, a site and a password.",
                        false,
                    ),
                ),
            };
        }
        if let (Some(_), "/scope") = (id, sub) {
            return match l.set_scope(&body).await {
                Ok(login) => reply(200, json!({"ok": true, "login": login})),
                Err(e) => message(
                    400,
                    &refused_message(
                        e,
                        "Check the sign-in page (an https address) and the extra addresses: one per line, a path such as /session or a site and a path such as api.example.com/auth/.",
                        true,
                    ),
                ),
            };
        }
        if let (Some(id), "/delete") = (id, sub) {
            return match l.remove(id, "on the firewall page").await {
                Ok(gone) => reply(if gone { 200 } else { 404 }, json!({"ok": gone})),
                Err(Refused::Message(m)) => message(400, &m),
                Err(Refused::Invalid(i)) => message(400, &i.message),
            };
        }
        bare(404)
    }

    async fn open(&self, req: Req) -> Resp {
        let origin = req.headers().get(http::header::ORIGIN).and_then(|v| v.to_str().ok());
        if self.origin().is_none() || origin != self.origin().as_deref() {
            return bare(403);
        }
        let form_type = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"));
        if !form_type {
            return bare(415);
        }
        let Some((parts, raw)) = read_body(req, OPEN_BYTES).await else {
            return bare(400);
        };
        let text = String::from_utf8_lossy(&raw).into_owned();
        let form = |k: &str| {
            url::form_urlencoded::parse(text.as_bytes())
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default()
        };
        let Some(access) = self.app.contracts.page_access.get() else {
            return html(403, self.refused());
        };
        // An owner or admin only (`canWrite`): checked by the access module, and again here.
        let Some(person) = access
            .authorize(&parts.headers, form("intent"), "logins")
            .await
            .filter(|p| p.can_write)
        else {
            return html(403, self.refused());
        };
        let now = (self.now)();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        {
            let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            grants.retain(|_, g| g.expires_at > now);
            if grants.len() >= MAX_GRANTS {
                drop(grants);
                let t = "Too many open pages";
                return html(429, self.notice(t, Some(t), "Try again in a few minutes.", None, None));
            }
            grants.insert(
                hash(&token),
                Grant {
                    user_id: person.user_id.clone(),
                    device_id: person.device_id.clone(),
                    email: person.email.clone(),
                    expires_at: now + GRANT_MS,
                },
            );
        }
        let (login, request) = (form("login"), form("request"));
        let next = if LOGIN_ID.is_match(&login) {
            format!("{LOGINS_ROOT}/?login={login}")
        } else if REQUEST_ID.is_match(&request) {
            format!("{LOGINS_ROOT}/?request={request}")
        } else {
            format!("{LOGINS_ROOT}/")
        };
        tracing::info!("[logins] the logins page was opened ({})", person.device_id);
        let mut r = bare(303);
        // `res.writeHead(303, {...HEADERS, location, set-cookie})`: no content type on this one.
        r.headers_mut().remove(http::header::CONTENT_TYPE);
        r.headers_mut().insert(
            http::header::LOCATION,
            HeaderValue::from_str(&next).unwrap_or(HeaderValue::from_static("/")),
        );
        let cookie = format!(
            "{COOKIE}={token}; Path={LOGINS_ROOT}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
            GRANT_MS / 1000
        );
        if let Ok(v) = HeaderValue::from_str(&cookie) {
            r.headers_mut().insert(http::header::SET_COOKIE, v);
        }
        r
    }
}

/// Serve `/__cc/logins` and everything under it on the ingress.
pub fn route(reg: &mut crate::app::Registry, web: Arc<LoginsWeb>) {
    reg.ingress.route(
        crate::stages::INGRESS_PAGES,
        |_, p| owns_logins_path(p),
        move |req, _| {
            let web = web.clone();
            async move { web.handle(req).await }
        },
    );
}

#[cfg(test)]
mod tests;
