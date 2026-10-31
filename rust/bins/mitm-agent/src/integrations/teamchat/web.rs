//! The people's way into Team chat (`teamchat-web.ts`), on this firewall's public name (Caddy
//! hands `/__cc/team-chat/*` here, and asks `/__cc/team-chat/verify` about everything else it would
//! send to ClickClack).
//!
//!   GET  /__cc/team-chat/open        a page that posts the console's open intent back here
//!   POST /__cc/team-chat/open        intent + enrolled browser → member, magic link, grant cookie
//!   GET  /__cc/team-chat/verify      Caddy's forward_auth: 200 with a live grant, else a bare 404
//!
//! The magic link is single use; the page posts it to ClickClack's own `/api/auth/magic/consume`
//! from this same origin, which sets ClickClack's session cookie, and goes on to `/app`. The grant
//! cookie is what Caddy checks on every request after that, and it is only good while the browser
//! that opened it is still enrolled.

use std::sync::Arc;

use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;

use cc_http::{Req, Resp};

use super::firewall::{Person, TEAMCHAT_GRANT_MS, TeamChatFirewall};
use crate::app::App;
use crate::integrations::js;

pub const TEAMCHAT_ROOT: &str = "/__cc/team-chat";
pub const TEAMCHAT_VERIFY: &str = "/__cc/team-chat/verify";
const COOKIE: &str = "__Host-cc_team_chat";

pub fn owns_team_chat_path(path: &str) -> bool {
    path == TEAMCHAT_ROOT || path.strip_prefix(TEAMCHAT_ROOT).is_some_and(|r| r.starts_with('/'))
}

const HEADERS: &[(&str, &str)] = &[
    ("cache-control", "no-store"),
    // Not `no-referrer`: with it Chrome sends `Origin: null` on the open page's own form POST.
    ("referrer-policy", "same-origin"),
    ("x-content-type-options", "nosniff"),
    (
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    ),
];

const OPEN_JS: &str = concat!(
    r#"const i=new URLSearchParams(location.hash.slice(1)).get("i");history.replaceState(null,"",location.pathname);"#,
    r#"if(!i){document.getElementById("s").textContent="Open Team chat from your ControlClaw console."}else{"#,
    r#"const f=document.createElement("form");f.method="POST";f.action="/__cc/team-chat/open";const n=document.createElement("input");"#,
    r#"n.type="hidden";n.name="intent";n.value=i;f.append(n);document.body.append(f);f.submit()}"#,
);

// The CSRF header: a browser that already has a ClickClack session sends that cookie with the
// consume, and ClickClack then requires the header on any unsafe request.
const LOGIN_JS: &str = concat!(
    r#"const m=document.querySelector("meta[name=cc-team-chat]");const t=m&&m.content;"#,
    r#"if(m)m.remove();(async()=>{try{if(!t)throw 0;const r=await fetch("/api/auth/magic/consume",{method:"POST",credentials:"same-origin","#,
    r#"headers:{"content-type":"application/json","x-clickclack-csrf":"1"},body:JSON.stringify({token:t})});if(!r.ok)throw 0;location.replace("/app")}"#,
    r#"catch{document.getElementById("s").textContent="Team chat could not sign you in. Open it again from your ControlClaw console."}})()"#,
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

fn bare(status: u16) -> Resp {
    let mut r = cc_http::empty(status);
    r.headers_mut()
        .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut()
        .insert(http::header::CONTENT_LENGTH, HeaderValue::from(0));
    r
}

/// The grant cookie, or None when there is none or more than one.
fn grant_cookie(headers: &HeaderMap) -> Option<String> {
    let joined = headers
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    let prefix = format!("{COOKIE}=");
    let found: Vec<&str> = joined
        .split(';')
        .map(str::trim)
        .filter(|s| s.starts_with(&prefix))
        .collect();
    (found.len() == 1).then(|| found[0][prefix.len()..].to_string())
}

fn escape_attr(v: &str) -> String {
    v.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

pub struct TeamChatWeb {
    app: Arc<App>,
    chat: Arc<TeamChatFirewall>,
}

impl TeamChatWeb {
    pub fn new(app: &Arc<App>, chat: Arc<TeamChatFirewall>) -> Arc<Self> {
        Arc::new(Self { app: app.clone(), chat })
    }

    // Drawn when asked for, by the firewall's shell; without one on this build, a bare page.
    fn notice(&self, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
        match self.app.contracts.fw_shell.get() {
            Some(s) => s.notice("Team chat", heading, text, id, script),
            None => format!(
                "<!doctype html><meta charset=\"utf-8\"><title>Team chat</title><p{}>{}</p>{}",
                id.map(|i| format!(" id=\"{}\"", js::escape_html(i)))
                    .unwrap_or_default(),
                js::escape_html(text),
                script
                    .map(|s| format!("<script src=\"{}\"></script>", js::escape_html(s)))
                    .unwrap_or_default()
            ),
        }
    }

    /// Caddy's question for every request it would hand to ClickClack. A status and nothing else.
    pub fn verify(&self, headers: &HeaderMap) -> bool {
        if !self.chat.serving() {
            return false;
        }
        let Some(grant) = grant_cookie(headers).and_then(|c| self.chat.grant(&c)) else {
            return false;
        };
        self.app
            .contracts
            .page_access
            .get()
            .is_some_and(|a| a.device_active(headers, "team-chat", &grant.user_id, &grant.device_id, None))
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let path = cc_http::pathname(&req.uri().to_string());
        let get = req.method() == Method::GET;
        if path == TEAMCHAT_VERIFY {
            return bare(if self.verify(req.headers()) { 200 } else { 404 });
        }
        if path == format!("{TEAMCHAT_ROOT}/open.js") && get {
            return send(200, OPEN_JS.into(), "text/javascript");
        }
        if path == format!("{TEAMCHAT_ROOT}/login.js") && get {
            return send(200, LOGIN_JS.into(), "text/javascript");
        }
        let open = format!("{TEAMCHAT_ROOT}/open");
        if path == open && get {
            let script = format!("{TEAMCHAT_ROOT}/open.js");
            return send(
                200,
                self.notice(None, "Opening Team chat…", Some("s"), Some(&script)),
                "text/html",
            );
        }
        if path == open && req.method() == Method::POST {
            return self.open(req).await;
        }
        bare(404)
    }

    /// The same question when it arrives as an upgrade (Caddy copies the browser's headers onto its
    /// check). Answered with a plain status, and the socket is never upgraded.
    pub fn verify_upgrade(&self, headers: &HeaderMap) -> Resp {
        let mut r = bare(if self.verify(headers) { 200 } else { 404 });
        r.headers_mut()
            .insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        r
    }

    async fn open(&self, req: Req) -> Resp {
        let access = self.app.contracts.page_access.get();
        let origin = req.headers().get(http::header::ORIGIN).and_then(|v| v.to_str().ok());
        // Same-origin only: the page above posts here, and nothing else should.
        let mine = access.as_ref().and_then(|a| a.origin());
        if mine.is_none() || origin != mine.as_deref() {
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
        let (parts, body) = req.into_parts();
        let declared = parts
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        if declared.is_some_and(|d| d > 8 * 1024) {
            return bare(400);
        }
        let Ok(got) = http_body_util::Limited::new(body, 8 * 1024).collect().await else {
            return bare(400);
        };
        let raw = got.to_bytes();
        let text = String::from_utf8_lossy(&raw);
        let intent = url::form_urlencoded::parse(text.as_bytes())
            .find(|(k, _)| k == "intent")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let refused = || {
            send(
                403,
                self.notice(Some("Team chat could not open"), "Open Team chat from your ControlClaw console, in a browser you have already used to open one of your agents. Links from the console work for one minute.", None, None),
                "text/html",
            )
        };
        let Some(access) = access else { return refused() };
        let Some(person) = access.authorize(&parts.headers, intent, "team-chat").await else {
            return refused();
        };
        if !self.chat.serving() {
            return send(
                503,
                self.notice(
                    Some("Team chat is off"),
                    "An owner or admin can turn it on from the Firewall page of your ControlClaw console.",
                    None,
                    None,
                ),
                "text/html",
            );
        }
        let p = Person {
            user_id: person.user_id.clone(),
            device_id: person.device_id.clone(),
            name: person.extra.get("name").and_then(|v| v.as_str()).map(String::from),
            email: person.email.clone(),
            can_write: person.can_write,
        };
        let (magic, cookie) = match self.chat.admit(&p).await {
            Ok(x) => x,
            Err(e) => {
                tracing::info!("[teamchat] could not let a browser in: {e}");
                return send(
                    503,
                    self.notice(
                        Some("Team chat is not ready"),
                        "It is starting. Try again in a minute from your ControlClaw console.",
                        None,
                        None,
                    ),
                    "text/html",
                );
            }
        };
        tracing::info!(
            "[teamchat] {} opened Team chat ({})",
            if p.can_write { "an owner or admin" } else { "a member" },
            p.device_id
        );
        let body = format!(
            "<meta name=\"cc-team-chat\" content=\"{}\"><p id=\"s\" class=\"text-[14px] text-ink-2\" role=\"status\">Signing you in…</p>",
            escape_attr(&magic)
        );
        let tail = format!("<script src=\"{TEAMCHAT_ROOT}/login.js\"></script>");
        let page = match self.app.contracts.fw_shell.get() {
            Some(s) => s.minimal_page("Team chat", &body, &tail),
            None => format!("<!doctype html><meta charset=\"utf-8\"><title>Team chat</title>{body}{tail}"),
        };
        let mut r = send(200, page, "text/html");
        let set = format!(
            "{COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
            TEAMCHAT_GRANT_MS / 1000
        );
        if let Ok(v) = HeaderValue::from_str(&set) {
            r.headers_mut().insert(http::header::SET_COOKIE, v);
        }
        r
    }
}

/// Serve `/__cc/team-chat/*` on the ingress, and Caddy's upgrade-shaped `verify`.
pub fn route(reg: &mut crate::app::Registry, web: Arc<TeamChatWeb>) {
    let w = web.clone();
    reg.ingress.route(
        crate::stages::INGRESS_PAGES,
        |_, p| owns_team_chat_path(p),
        move |req, _| {
            let w = w.clone();
            async move { w.handle(req).await }
        },
    );
    if let Some(up) = reg.ingress.upgrades_mut() {
        up.route(
            crate::stages::INGRESS_UPGRADE,
            |_, p| p == TEAMCHAT_VERIFY,
            move |req, _| {
                let w = web.clone();
                async move { w.verify_upgrade(req.headers()) }
            },
        );
    }
}

#[cfg(test)]
mod tests;
