//! The meetings routes (`routes/meetings.ts`, apps/saas/docs/features/meetings.md):
//!
//!   POST /meetings/apply               the firewall's signed settings
//!   GET|POST /meetings/instructions    the owner's standing orders (read: console or firewall; write: firewall)
//!   GET  /meetings/status              the settings' metadata, for the console or the firewall
//!   GET  /__cc/meetings[/<id>]         the page, for an enrolled browser that may write
//!   GET  /__cc/meetings/state          settings, the active meeting, how many are saved
//!   GET  /__cc/meetings/list?page=N    a page of saved meetings, newest first
//!   GET  /__cc/meetings/item/<id>      one saved meeting with its transcript and notes
//!   GET  /__cc/meetings/schedule       the meetings the agent will join by itself
//!   GET  /__cc/meetings/session?key=   an OpenClaw session in the agent's dashboard, pairing this browser
//!   GET  /__cc/meetings/instructions   the standing orders, read-only here
//!   POST /__cc/meetings/{join,leave,set-mode,delete}
//!   POST /__cc/meetings/schedule/{cancel,restore}, followup/{approve,dismiss}, signin/{start,finish,clear}
//!
//! Sessions, the page shell and the "not signed in" page are W7's (`app.contracts.access`); while
//! that slot is empty every request is answered as one without a session. The schedule exists with
//! the service, the Google sign-in on a box whose role has its window; the after-meeting run comes
//! next in M4b, and until then its commands answer as unavailable.

use std::sync::{Arc, LazyLock};

use cc_http::{
    BodyBinding, FirewallBody, FirewallRequest, ReadBody, Req, Resp, Router, firewall_request, full, read_json_body,
    send_json,
};
use http::{HeaderValue, StatusCode};
use regex::Regex;
use serde_json::{Value, json};

use super::pages::{meeting_detail, meetings_page, session_path};
use super::service::{FollowUpError, MeetingService};
use crate::app::App;
use crate::boxside::access::DashboardAttempt;
use crate::boxside::shell::{agent_name_of, escape_html, inline_json, shell_page};
use crate::stages;

const UUID: &str = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
static MEETING_PAGE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^/__cc/meetings/({UUID})$")).expect("regex"));
static MEETING_ITEM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^/__cc/meetings/item/({UUID})$")).expect("regex"));
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
/// When W7's shell is not there to draw its own refusal page.
const BARE_DENIED: &str = "<!doctype html><title>These meetings are private</title><h1>These meetings are private</h1>";

/// `isMeetingsPath`: what index.ts hands to `handleMeetings`.
pub fn is_meetings_path(path: &str) -> bool {
    path.starts_with("/meetings/") || path == "/__cc/meetings" || path.starts_with("/__cc/meetings/")
}

/// `meetingsTabUrl`: this agent's Meetings tab in the console, from its page there.
pub fn meetings_tab_url(console_url: &str) -> Option<String> {
    static PAGE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^https://[^/]+/dashboard/agents/[^/?#]+$").expect("regex"));
    PAGE.is_match(console_url).then(|| format!("{console_url}/meetings"))
}

/// Every answer: never cached, no referrer.
fn done(mut r: Resp) -> Resp {
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    r
}

fn page(status: u16, html: String) -> Resp {
    let mut r = full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
        "text/html; charset=utf-8",
        html,
    );
    let h = r.headers_mut();
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("content-security-policy", HeaderValue::from_static(CSP));
    r
}

/// What the routes reach: the app, and the service once OpenClaw's gateway is there (`meetings`).
pub struct Context {
    pub app: Arc<App>,
    pub service: Arc<dyn Fn() -> Option<Arc<MeetingService>> + Send + Sync>,
    pub schedule: Arc<dyn Fn() -> Option<Arc<super::schedule::MeetingSchedule>> + Send + Sync>,
    pub signin: Arc<dyn Fn() -> Option<Arc<super::signin::MeetingSignin>> + Send + Sync>,
}

pub fn register(router: &mut Router, ctx: Arc<Context>) {
    router.route(
        stages::MEETINGS,
        |_, p| is_meetings_path(p),
        move |req, _| {
            let ctx = ctx.clone();
            // A Node handler ran to its end when the browser went away; a dropped future would stop
            // halfway (a sign-in left pending, a delete with OpenClaw stopped). Each request runs
            // in a task of its own.
            async move {
                tokio::spawn(async move { done(handle(&ctx, req).await) })
                    .await
                    .unwrap_or_else(|_| done(send_json(500, &json!({"error": "Internal error"}))))
            }
        },
    );
}

fn unavailable() -> Resp {
    send_json(503, &json!({"error": "Meetings unavailable"}))
}

/// The console's token for this request (`verifyRequest`).
fn console(app: &App, parts: &http::request::Parts) -> bool {
    let target = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    app.console_auth
        .verify(parts.method.as_str(), target, cc_http::header(parts, "authorization"))
        .is_some()
}

async fn handle(ctx: &Context, req: Req) -> Resp {
    let path = cc_http::pathname(&req.uri().to_string());
    let method = req.method().clone();
    let app = &ctx.app;
    let service = (ctx.service)();

    if path == "/meetings/apply" && method == http::Method::POST {
        let read = ReadBody::Json { limit: 16384 };
        let body = match firewall_request(&app.firewall_auth, req, "meetings", 0, read).await {
            FirewallRequest::Refused { .. } => {
                return send_json(401, &json!({"error": "Firewall signature required"}));
            }
            FirewallRequest::Accepted { body, .. } => body,
        };
        let Some(service) = service else { return unavailable() };
        let FirewallBody::Json(body) = body else {
            return send_json(400, &json!({"error": "Invalid request"}));
        };
        return match service.apply(body).await {
            Ok(v) => send_json(200, &v),
            Err(e) => {
                // The firewall only reports "not applied": the reason belongs in this agent's journal.
                tracing::error!(
                    "[meetings] settings were not applied: {}",
                    super::js::head16(&e.to_string(), 300)
                );
                send_json(
                    409,
                    &json!({"error": "Meetings settings could not be applied. Update the agent and check its size."}),
                )
            }
        };
    }

    // The meeting instructions, from the console: it reads them; only the firewall writes them,
    // after the owner typed its code.
    if path == "/meetings/instructions" && (method == http::Method::GET || method == http::Method::POST) {
        let write = method == http::Method::POST;
        let read = if write {
            ReadBody::Json { limit: 16384 }
        } else {
            ReadBody::No
        };
        let (body, allowed) = match firewall_request(&app.firewall_auth, req, "meetings", 0, read).await {
            FirewallRequest::Accepted { body, .. } => (body, true),
            FirewallRequest::Refused { parts, .. } => (FirewallBody::NotRead, !write && console(app, &parts)),
        };
        if !allowed {
            return send_json(
                401,
                &json!({"error": if write { "Firewall signature required" } else { "Unauthorized" }}),
            );
        }
        let Some(service) = service else { return unavailable() };
        let result = if !write {
            service.orders()
        } else {
            let FirewallBody::Json(body) = body else {
                return send_json(400, &json!({"error": "Invalid request"}));
            };
            service.save_orders(Value::Object(body))
        };
        return match result {
            Ok(v) => send_json(200, &v),
            Err(FollowUpError::Orders(m)) => send_json(409, &json!({"error": m})),
            Err(FollowUpError::Other(e)) => {
                tracing::error!("[meetings] instructions: {}", super::js::head16(&e, 200));
                send_json(
                    409,
                    &json!({"error": "The meeting instructions could not be read or saved."}),
                )
            }
        };
    }

    if path == "/meetings/status" && method == http::Method::GET {
        let ok = match firewall_request(&app.firewall_auth, req, "meetings", 0, ReadBody::No).await {
            FirewallRequest::Accepted { .. } => true,
            FirewallRequest::Refused { parts, .. } => console(app, &parts),
        };
        if !ok {
            return send_json(401, &json!({"error": "Unauthorized"}));
        }
        return match service {
            Some(s) => send_json(200, &s.metadata()),
            None => unavailable(),
        };
    }

    let access = app.contracts.access.get();
    let (parts, body) = req.into_parts();
    let vm_id = app.keys.vm_id().unwrap_or_default();
    // Node joins a repeated `Cookie` header with "; ".
    let cookies: Vec<&str> = parts
        .headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let cookie = (!cookies.is_empty()).then(|| cookies.join("; "));
    let session = access
        .as_ref()
        .and_then(|a| a.sessions.read_session(cookie.as_deref(), &vm_id));
    let allowed = session.as_ref().is_some_and(|s| s.device_id.is_some() && s.can_write);
    let denied = || {
        access
            .as_ref()
            .map_or_else(|| BARE_DENIED.to_string(), |a| a.denied_meetings_page())
    };

    let page_id = MEETING_PAGE.captures(&path).map(|c| c[1].to_string());
    if (path == "/__cc/meetings" || page_id.is_some()) && method == http::Method::GET {
        let Some(access) = access.as_ref().filter(|_| allowed) else {
            return page(403, denied());
        };
        let shell = access.shell_context();
        let agent = agent_name_of(shell.hostname.as_deref());
        let body = format!(
            r#"<div id="root"></div><script id="cc-meetings" type="application/json">{}</script><script type="module" src="/__cc/files-ui/meetings.js"></script>"#,
            inline_json(
                &json!({"agentName": agent, "meetingId": page_id, "consoleUrl": meetings_tab_url(&shell.console_url)})
            )
        );
        let html = shell_page(
            &shell,
            &format!("{agent} · meetings"),
            Some("meetings"),
            &body,
            "",
            access.nav(),
        );
        return page(200, html);
    }

    // A session in the agent's OpenClaw dashboard, with a fresh pairing on the way. Only a person's
    // own click may start that: a top-level navigation from this agent's pages, or an address typed in.
    if path == "/__cc/meetings/session" && method == http::Method::GET {
        let h = |n: &str| cc_http::header(&parts, n).unwrap_or_default().to_string();
        let site = h("sec-fetch-site");
        if !(site == "same-origin" || site == "none")
            || h("sec-fetch-mode") != "navigate"
            || h("sec-fetch-dest") != "document"
        {
            return send_json(403, &json!({"error": "Open this link from the agent's Meetings page"}));
        }
        let Some(access) = access.as_ref().filter(|_| allowed) else {
            return page(403, denied());
        };
        // Only this box's own agent: its sessions are all under agent:main.
        let key = query(&parts, "key").unwrap_or_default();
        let target = key.starts_with("agent:main:").then(|| session_path(&key)).flatten();
        let Some(target) = target else {
            return send_json(404, &json!({"error": "Not an OpenClaw session of this agent"}));
        };
        let shell = access.shell_context();
        let boot = match shell.hostname.as_deref() {
            Some(host) => access.dashboard_bootstrap_url(host).await,
            None => DashboardAttempt::Failed {
                reason: "this box does not know its own hostname".into(),
                retryable: false,
            },
        };
        if let DashboardAttempt::Url(u) = &boot
            && let Some(fragment) = u.strip_prefix('/')
            && fragment.starts_with('#')
        {
            let mut r = full(StatusCode::FOUND, "text/plain", String::new());
            if let Ok(v) = HeaderValue::from_str(&format!("{target}{fragment}")) {
                r.headers_mut().insert(http::header::LOCATION, v);
            }
            return r;
        }
        // As Open does: say why this browser was not paired, and offer the plain link.
        let reason = match boot {
            DashboardAttempt::Failed { reason, .. } => reason,
            DashboardAttempt::Url(_) => "OpenClaw could not issue a pairing link".into(),
        };
        let body = format!(
            r#"<main style="max-width:640px;margin:48px auto;padding:0 16px;font:15px/1.5 system-ui,sans-serif"><h1 style="font-size:20px">The dashboard could not pair this browser</h1><p>OpenClaw said: {}.</p><p>If this browser opened the agent's dashboard before, the session still opens.</p><p><a href="{}">Open the session anyway</a></p></main>"#,
            escape_html(&reason),
            escape_html(&target)
        );
        let agent = agent_name_of(shell.hostname.as_deref());
        return page(
            200,
            shell_page(
                &shell,
                &format!("{agent} · session"),
                Some("meetings"),
                &body,
                "",
                access.nav(),
            ),
        );
    }

    if !allowed {
        return send_json(
            403,
            &json!({"error": "Press Meeting controls on the agent’s Meetings tab in the console, from an enrolled owner browser."}),
        );
    }
    let Some(service) = service else { return unavailable() };
    // Every box is one site with its neighbours: same origin only, no top-level navigation.
    let own = access.as_ref().and_then(|a| a.allowed_origins().0);
    let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
    let policy = cc_origin::OriginPolicy {
        allowed: vec![own],
        allow_top_level_navigation: false,
        ..Default::default()
    };
    if let cc_origin::OriginVerdict::Denied { reason, origin } = cc_origin::check_origin(&facts, &policy) {
        tracing::warn!("[meetings] {}", cc_origin::denial_message(reason, origin.as_deref()));
        return send_json(403, &json!({"error": "Use this agent's own Meetings page"}));
    }

    if path == "/__cc/meetings/state" && method == http::Method::GET {
        // The list and each meeting have their own reads; the state polled every few seconds stays small.
        let mut state = service.status();
        let total = state
            .as_object_mut()
            .and_then(|m| m.remove("meetings"))
            .and_then(|m| m.as_array().map(Vec::len))
            .unwrap_or(0);
        state["total"] = json!(total);
        return send_json(200, &state);
    }
    if path == "/__cc/meetings/list" && method == http::Method::GET {
        // `Number(url.searchParams.get("page") ?? "1")`.
        let page_no = query(&parts, "page").map_or(1.0, |p| super::js::js_number(Some(&json!(p))));
        return send_json(200, &meetings_page(&service.meetings(), page_no));
    }
    if let Some(item) = MEETING_ITEM.captures(&path)
        && method == http::Method::GET
    {
        let id = &item[1];
        let Some(mut meeting) = service.meetings().into_iter().find(|m| m.get("id") == Some(&json!(id))) else {
            return send_json(404, &json!({"error": "This meeting was deleted or never saved."}));
        };
        // A task can end after the meeting: its row comes from the voice adapter's file.
        let tasks = service.tasks(id);
        if !tasks.is_empty() {
            meeting["tasks"] = Value::Array(tasks);
        }
        return send_json(200, &meeting_detail(&meeting));
    }
    if path == "/__cc/meetings/schedule" && method == http::Method::GET {
        return send_json(
            200,
            &(ctx.schedule)().map_or_else(
                || json!({"enabled": false, "mode": "transcript", "entries": []}),
                |s| s.list(),
            ),
        );
    }
    if path == "/__cc/meetings/instructions" && method == http::Method::GET {
        return match service.orders() {
            Ok(v) => send_json(200, &v),
            Err(FollowUpError::Orders(e) | FollowUpError::Other(e)) => {
                tracing::error!("[meetings] instructions: {}", super::js::head16(&e, 200));
                send_json(
                    409,
                    &json!({"error": "The meeting instructions could not be read. Update this agent and try again."}),
                )
            }
        };
    }
    // Agent configuration is changed from the console, confirmed with the firewall's code.
    if path == "/__cc/meetings/instructions" && method == http::Method::POST {
        return send_json(
            405,
            &json!({"error": "Change the meeting instructions on this agent's Meetings tab in your console."}),
        );
    }
    if method != http::Method::POST {
        return send_json(404, &json!({"error": "Not found"}));
    }
    if let Some(step) = path.strip_prefix("/__cc/meetings/signin/") {
        let Some(signin) = (ctx.signin)().filter(|_| ["start", "finish", "clear"].contains(&step)) else {
            return send_json(404, &json!({"error": "Not found"}));
        };
        let result = match step {
            "start" => signin.start().await.map(|s| json!({"signin": s})),
            "finish" => signin.finish(false).await,
            _ => signin.clear().await.map(|s| json!({"signin": s})),
        };
        return match result {
            Ok(v) => send_json(200, &v),
            Err(e) => {
                // These messages are our own and say what to do next.
                tracing::error!("[meetings] sign-in step failed: {}", super::js::head16(&e, 300));
                let own = [
                    "Connect a Google account",
                    "Stop the current meeting",
                    "The Google sign-in could not be removed",
                ]
                .iter()
                .any(|p| e.starts_with(p));
                send_json(
                    409,
                    &json!({"error": if own { e } else { "The Google sign-in step failed. Update this agent and retry.".into() }}),
                )
            }
        };
    }
    let Some(body) = read_json_body(body, 16384, &BodyBinding::not_firewall()).await else {
        return send_json(400, &json!({"error": "Invalid request"}));
    };
    let result = match path.as_str() {
        "/__cc/meetings/join" => service.join(body).await.map_err(|e| e.to_string()),
        "/__cc/meetings/leave" => service.leave(body).await.map_err(|e| e.to_string()),
        "/__cc/meetings/set-mode" => service.set_mode(body).await.map_err(|e| e.to_string()),
        "/__cc/meetings/delete" => service.delete(body).await.map_err(|e| e.to_string()),
        "/__cc/meetings/schedule/cancel" | "/__cc/meetings/schedule/restore" => match (ctx.schedule)() {
            Some(s) => s.set(
                &body,
                if path.ends_with("cancel") {
                    "cancelled"
                } else {
                    "scheduled"
                },
            ),
            None => return send_json(404, &json!({"error": "Not found"})),
        },
        "/__cc/meetings/followup/approve" => service.answer("approve", Value::Object(body)).await,
        "/__cc/meetings/followup/dismiss" => service.answer("dismiss", Value::Object(body)).await,
        _ => return send_json(404, &json!({"error": "Not found"})),
    };
    match result {
        Ok(v) => send_json(200, &v),
        Err(e) => {
            // The page gets one sentence; why it failed belongs in this agent's journal.
            tracing::warn!("[meetings] {path}: {}", super::js::head16(&e, 300));
            send_json(
                409,
                &json!({"error": "The meeting command could not complete. Refresh the page and check status before retrying."}),
            )
        }
    }
}

/// `url.searchParams.get(name)`.
fn query(parts: &http::request::Parts, name: &str) -> Option<String> {
    let q = parts.uri.query()?;
    url::form_urlencoded::parse(q.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}
