//! `/__cc/local/open`, a standalone firewall's door to its own pages. `mitm-agent open <page>`
//! prints a link here with an intent in the fragment; the page posts it, the access module enrolls
//! the browser (`AccessFirewall::local_enroll`), and the firewall sends it on to the page's own
//! Open with a fresh intent, where the usual flow takes over. Not served in SaaS mode.

use std::sync::Arc;

use super::access::{AccessFirewall, access_request_read};
use super::fw_logs::{PageReply, page_response};
use super::fw_shell::fw_notice;
use super::local_intent;

pub const LOCAL_OPEN_PATH: &str = "/__cc/local/open";
const LOCAL_OPEN_JS: &str = "/__cc/local/open.js";
const TITLE: &str = "ControlClaw firewall";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub fn owns(path: &str) -> bool {
    path == LOCAL_OPEN_PATH || path == LOCAL_OPEN_JS
}

fn reply(status: u16, ty: &str, body: String, more: Vec<(String, String)>) -> cc_http::Resp {
    let mut headers = vec![
        ("cache-control".into(), "no-store".into()),
        // same-origin, not no-referrer: with no-referrer Chrome posts the form with `Origin: null`,
        // and the origin check refuses it.
        ("referrer-policy".into(), "same-origin".into()),
        ("x-content-type-options".into(), "nosniff".into()),
        ("content-security-policy".into(), CSP.into()),
    ];
    headers.extend(more);
    page_response(PageReply {
        status,
        headers,
        content_type: (!ty.is_empty()).then(|| format!("{ty}; charset=utf-8")),
        body,
    })
}

fn notice(status: u16, text: &str) -> cc_http::Resp {
    reply(
        status,
        "text/html",
        fw_notice(TITLE, Some("This link did not open"), text, None, None),
        Vec::new(),
    )
}

/// The fragment's intent, posted as a form (the fragment never reaches a server).
const JS: &str = r#"const i=new URLSearchParams(location.hash.slice(1)).get("i");history.replaceState(null,"",location.pathname);if(!i){document.getElementById("status").textContent="Make a new link with: mitm-agent open <page>"}else{const f=document.createElement("form");f.method="POST";f.action="/__cc/local/open";const n=document.createElement("input");n.type="hidden";n.name="intent";n.value=i;f.append(n);document.body.append(f);f.submit()}"#;

pub async fn handle(access: Arc<AccessFirewall>, config: crate::app::Config, req: cc_http::Req) -> cc_http::Resp {
    let path = cc_http::pathname(req.uri().path());
    let method = req.method().as_str().to_string();
    match (path.as_str(), method.as_str()) {
        (LOCAL_OPEN_JS, "GET") => return reply(200, "text/javascript", JS.into(), Vec::new()),
        (LOCAL_OPEN_PATH, "GET") => {
            let page = fw_notice(TITLE, None, "Opening…", Some("status"), Some(LOCAL_OPEN_JS));
            return reply(200, "text/html", page, Vec::new());
        }
        (LOCAL_OPEN_PATH, "POST") => {}
        _ => return reply(405, "", String::new(), Vec::new()),
    }
    // An oversized body is 413 and a slow or broken one 400; a 500 is this firewall's own failure.
    let (req, body) = match access_request_read(req).await {
        (r, Ok(body)) => (r, body),
        (_, Err(status)) => return reply(status, "", String::new(), Vec::new()),
    };
    if !req.content_type.starts_with("application/x-www-form-urlencoded") {
        return reply(415, "", String::new(), Vec::new());
    }
    let intent = url::form_urlencoded::parse(&body)
        .find(|(k, _)| k == "intent")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default();
    let (next, cookie) = match access.local_enroll(&req, &intent).await {
        Ok(Some(x)) => x,
        Ok(None) => {
            return notice(
                403,
                "It was used already, it is older than a minute, or it was made for another address. Make a new one with mitm-agent open.",
            );
        }
        Err(e) => {
            tracing::error!("[access] local open: {e}");
            return cc_http::empty(500);
        }
    };
    // The page's own Open takes a fresh intent: the one just used is spent.
    let Some(path) = local_intent::PAGES.iter().find(|(n, _)| *n == next).map(|(_, p)| *p) else {
        return notice(404, "This firewall does not serve that page.");
    };
    let fresh = match local_intent::mint(&config.keys_dir, &config.org_id, &config.box_id, &next) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("[access] local open: {e}");
            return cc_http::empty(500);
        }
    };
    reply(
        303,
        "",
        String::new(),
        vec![
            ("location".into(), format!("{path}#i={fresh}")),
            ("set-cookie".into(), cookie),
        ],
    )
}
