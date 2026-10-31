//! The AI review history page (`ai-review-history.ts`, apps/saas/docs/features/ai-firewall-review.md):
//! one agent's review runs, read from the trace store, for an owner in an enrolled browser. Same
//! door as Doctor's chat: an open intent for that agent, posted from this firewall's own origin by
//! a browser that is already enrolled, buys a two-hour cookie scoped to that agent's own path, so
//! two agents' histories open side by side. Read-only. The body and scripts are the TS's, as it
//! renders them (`page/`), with Rust-only fixes in `history_app.js` (a late answer for a run no
//! longer picked is dropped, a cleared hash empties the view, one load at a time counts, an unknown
//! outcome is shown as itself). Until W3's page access is on the build, every open is refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::Engine;
use http::{HeaderValue, Method};
use serde_json::json;
use sha2::{Digest, Sha256};

use cc_http::{Req, Resp};

use super::trace_store::AiReviewTraceStore;
use crate::app::App;
use crate::core::fw_shell::{fw_notice, fw_shell_page};
use crate::integrations::doctor::chat::{cookie_token, form_get, read_body, same_origin, send};
use crate::integrations::js;

pub const ROOT: &str = "/__cc/doctor/ai-review";
const COOKIE: &str = "__Secure-cc_ai_review";
const GRANT_MS: i64 = 2 * 60 * 60_000;
const MAX_GRANTS: usize = 1000;
const PAGE_BODY: &str = include_str!("page/history_body.html");
const PAGE_JS: &str = include_str!("page/history_app.js");
const OPEN_JS: &str = include_str!("page/history_open.js");

pub fn owns(path: &str) -> bool {
    path == ROOT || path.starts_with(&format!("{ROOT}/"))
}

fn agent_root(vm_id: &str) -> String {
    format!("{ROOT}/a/{vm_id}")
}

/// `^[A-Za-z0-9_-]{1,80}$`.
fn agent_id(s: &str) -> bool {
    (1..=80).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn hash(v: &str) -> String {
    hex::encode(Sha256::digest(v.as_bytes()))
}

#[derive(Clone)]
struct Grant {
    vm_id: String,
    user_id: String,
    device_id: String,
    expires_at: i64,
}

type NameOf = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub struct AiReviewHistory {
    app: Arc<App>,
    store: Arc<AiReviewTraceStore>,
    /// The agent's name as the org knows it, for the page header.
    agent_name: NameOf,
    grants: Mutex<HashMap<String, Grant>>,
    now: Clock,
}

fn plain(status: u16) -> Resp {
    send(status, String::new(), "text/plain")
}

fn with_header(mut r: Resp, name: http::header::HeaderName, value: &str) -> Resp {
    if let Ok(v) = HeaderValue::from_str(value) {
        r.headers_mut().insert(name, v);
    }
    r
}

impl AiReviewHistory {
    pub fn new(app: &Arc<App>, store: Arc<AiReviewTraceStore>, agent_name: NameOf, now: Clock) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            store,
            agent_name,
            grants: Mutex::new(HashMap::new()),
            now,
        })
    }

    fn refused(&self) -> Resp {
        send(
            403,
            fw_notice(
                "AI review history",
                Some("Review history unavailable"),
                "Open the review history from the console in an enrolled browser. Open a working agent first to enroll this browser.",
                None,
                None,
            ),
            "text/html",
        )
    }

    fn grant(&self, headers: &http::HeaderMap, vm_id: &str) -> Option<Grant> {
        let token = cookie_token(headers, COOKIE)?;
        let g = self
            .grants
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&hash(&token))
            .cloned()?;
        let access = self.app.contracts.page_access.get()?;
        (g.vm_id == vm_id
            && g.expires_at > (self.now)()
            && access.device_active(headers, "ai-review", &g.user_id, &g.device_id, Some(&g.vm_id)))
        .then_some(g)
    }

    pub async fn handle(self: Arc<Self>, req: Req) -> Resp {
        let target = req.uri().to_string();
        let path = cc_http::pathname(&target);
        let method = req.method().clone();
        if path == format!("{ROOT}/open.js") && method == Method::GET {
            return send(200, OPEN_JS.into(), "text/javascript");
        }
        if path == format!("{ROOT}/open") && method == Method::GET {
            let script = format!("{ROOT}/open.js");
            let html = fw_notice(
                "AI review history",
                None,
                "Opening the review history...",
                Some("status"),
                Some(&script),
            );
            return send(200, html, "text/html");
        }
        if path == format!("{ROOT}/open") && method == Method::POST {
            return self.open(req).await;
        }
        let rest = path.strip_prefix(&format!("{ROOT}/a/")).unwrap_or("");
        let (vm, sub) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        let grant = (path.starts_with(&format!("{ROOT}/a/")) && agent_id(vm))
            .then(|| self.grant(req.headers(), vm))
            .flatten();
        let Some(grant) = grant else {
            return self.refused();
        };
        if method != Method::GET {
            return plain(405);
        }
        let home = agent_root(&grant.vm_id);
        match sub {
            // The page's script and fetches are relative.
            "" => {
                let mut r = plain(308);
                r.headers_mut().remove(http::header::CONTENT_TYPE);
                with_header(r, http::header::LOCATION, &format!("{home}/"))
            }
            "/" => {
                let html = fw_shell_page(
                    "AI review history",
                    None,
                    PAGE_BODY,
                    None,
                    r#"<script src="app.js"></script>"#,
                    None,
                );
                send(200, html, "text/html")
            }
            "/app.js" => send(200, PAGE_JS.into(), "text/javascript"),
            "/runs" => {
                let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
                let first = |k: &str| {
                    url::form_urlencoded::parse(query.as_bytes())
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.into_owned())
                };
                // `Number(query.get("before"))`, kept when finite and above 0; a run is older when
                // its whole-millisecond time is below it.
                let before = first("before")
                    .map(|b| crate::core::ingress::js_number(Some(&json!(b))))
                    .filter(|b| b.is_finite() && *b > 0.0)
                    .map(|b| b.ceil() as i64);
                let findings = first("findings").as_deref() == Some("1");
                // The store refuses an agent id it does not take, as the TS's throw: a 500.
                let Ok(runs) = self.store.list(Some(&grant.vm_id), before, findings, 50) else {
                    return plain(500);
                };
                let body = json!({"agent": (self.agent_name)(&grant.vm_id), "runs": runs});
                send(200, js::stringify(&body), "application/json")
            }
            _ => match sub.strip_prefix("/runs/").filter(|id| {
                (8..=80).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            }) {
                Some(id) => match self.store.get(Some(&grant.vm_id), id) {
                    Err(_) => plain(500),
                    Ok(Some(run)) => send(
                        200,
                        js::stringify(&serde_json::to_value(run).unwrap_or_default()),
                        "application/json",
                    ),
                    Ok(None) => send(
                        404,
                        js::stringify(&json!({"message": "That run is not on this firewall any more."})),
                        "application/json",
                    ),
                },
                None => plain(404),
            },
        }
    }

    async fn open(&self, req: Req) -> Resp {
        if !same_origin(&self.app, req.headers()) {
            return plain(403);
        }
        let form = req
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|t| t.starts_with("application/x-www-form-urlencoded"));
        if !form {
            return plain(415);
        }
        let (parts, body) = req.into_parts();
        let Some(raw) = read_body(body, &parts.headers, 8192).await else {
            return plain(500);
        };
        let Some(access) = self.app.contracts.page_access.get() else {
            return self.refused();
        };
        let person = access
            .authorize(&parts.headers, form_get(&raw, "intent"), "ai-review")
            .await;
        let Some((p, vm_id)) = person.and_then(|p| {
            let vm = p
                .extra
                .get("vmId")
                .and_then(|v| v.as_str())
                .filter(|v| agent_id(v))?
                .to_string();
            Some((p, vm))
        }) else {
            return self.refused();
        };
        let now = (self.now)();
        let token = {
            let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            grants.retain(|_, g| g.expires_at > now);
            if grants.len() >= MAX_GRANTS {
                return plain(429);
            }
            let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
            grants.insert(
                hash(&token),
                Grant {
                    vm_id: vm_id.clone(),
                    user_id: p.user_id,
                    device_id: p.device_id,
                    expires_at: now + GRANT_MS,
                },
            );
            token
        };
        // The run to show rides in the fragment, which the browser keeps across this redirect.
        let home = agent_root(&vm_id);
        let mut r = plain(303);
        r.headers_mut().remove(http::header::CONTENT_TYPE);
        let r = with_header(r, http::header::LOCATION, &format!("{home}/"));
        with_header(
            r,
            http::header::SET_COOKIE,
            &format!(
                "{COOKIE}={token}; Path={home}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                GRANT_MS / 1000
            ),
        )
    }
}
