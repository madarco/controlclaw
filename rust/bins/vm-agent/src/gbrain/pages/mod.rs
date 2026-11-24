//! The brain's own pages (T-218, apps/saas/docs/features/brain.md "The brain's pages"): Pages,
//! Lately, Ask, Import and Export, under `/__cc/brain`, for an owner or admin the console signed
//! in. They show and change everything in the brain, so they are served here, in the shell the
//! agents' pages use, and nothing they show reaches ControlClaw: the console hears only that a
//! person edited, imported or exported, and when (`brain_page` on Activity).
//!
//! The browser gets here the way it gets to an agent's Files: the console opens the brain with the
//! firewall's `files` destination, and the brain's sign-in lands that ticket on `/__cc/brain`
//! (`LANDING`), not on GBrain's admin page.
//!
//! - Pages: `GET /__cc/brain` and the page bundle `files-ui/brain.js` (the console's
//!   `app/(brain)/box/brain-main.tsx`), one view per path.
//! - The pages' API, `/__cc/brain/api/*`: the session cookie of a writer, from this box's own
//!   origin (or the console's, while they are one site, as Files).
//! - GBrain over loopback MCP (`client.rs`); export and import through a root helper (`port.rs`).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use cc_http::{Req, Resp, Router};
use cc_origin::OriginPolicy;
use hyper::Method;
use serde_json::{Map, Value, json};

use super::activity::BrainActivity;
use super::gate::BrainGate;
use super::now_ms;
use crate::app::App;
use crate::boxside::access::{Access, same_site};
use crate::boxside::shell::{self, NavItem, ShellHeader};
use crate::boxside::web::{self, query, send_json};

pub mod client;
pub mod port;

use client::{BrainClient, PagesError, unquote, unquote_all, unquote_snippet, without_agent_note};

/// A login ticket's `next` that lands on these pages, and where.
pub const LANDING: &[(&str, &str)] = &[("files", "/__cc/brain")];

/// (view, label, path, icon)
const VIEWS: &[(&str, &str, &str, &str)] = &[
    ("pages", "Pages", "/__cc/brain", "pages"),
    ("lately", "Lately", "/__cc/brain/lately", "lately"),
    ("ask", "Ask", "/__cc/brain/ask", "ask"),
    ("import", "Import", "/__cc/brain/import", "import"),
    ("export", "Export", "/__cc/brain/export", "export"),
];

const CALL: Duration = Duration::from_secs(30);
/// Ask waits for the model; GBrain's own budget for an answer is about this.
const ASK: Duration = Duration::from_secs(180);
const QUESTION_MAX: usize = 2000;
const PAGE_MAX_BYTES: usize = 2 * 1024 * 1024;
/// The root helper for GBrain's token, export, import and costs (the Ansible role's
/// `gbrain-pages.yml`). Its sudoers line names this exact path.
pub(crate) const HELPER: &str = "/usr/local/bin/cc-gbrain-pages";
/// Lately reads at most this many changed pages.
const LATELY_PAGES: usize = 500;
/// Rows Lately reads at most: past this it stops, whether or not their times could be read.
const LATELY_ROWS_READ: u64 = 2_000;
/// Facts Lately and One person read at most (GBrain's own cap for one `recall`).
const FACTS_MAX: usize = 100;
/// One page's side panel: the pages that link to it, its saved versions (each a change), its
/// dated entries. Each is one GBrain read, bounded.
const RELATED_LINKS: u64 = 30;
const RELATED_VERSIONS: u64 = 100;
const RELATED_TIMELINE: u64 = 20;
/// Ask's sources read for their title, kind and opening lines; any after these keep their name only.
const ASK_SOURCES_READ: usize = 8;
const EXCERPT_CHARS: usize = 220;

/// Whether the brain may spend AI on an answer: the firewall's last word on its model key
/// (`key.rs`), written beside the state, and the emergency stop (the gate's lock).
pub fn key_state_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("gbrain-key.state")
}

pub struct BrainPages {
    app: Arc<App>,
    access: Arc<Access>,
    gate: Arc<BrainGate>,
    client: BrainClient,
    port: port::Port,
    /// The Activity reader, once it runs: Activity's records and GBrain's page counts per kind.
    pub activity: OnceLock<Arc<BrainActivity>>,
    asking: tokio::sync::Mutex<()>,
    /// One-time export tickets and when each runs out (`POST /export`, then the download with it):
    /// a link from another site cannot start an export, and a refusal is shown, not downloaded.
    export_tickets: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

/// How long an export ticket is good for: the download starts at once.
const EXPORT_TICKET_MS: i64 = 60_000;

/// A `brain_page` record for Activity: what and when, the browser's name, never the page.
fn page_record(action: &str, device: Option<&str>, ok: bool, count: Option<u64>) -> Value {
    json!({
        "source": "brain_page",
        "event_id": uuid::Uuid::new_v4().to_string(),
        "ts": now_ms().div_euclid(1000),
        "action": action,
        "device_id": device,
        "ok": ok,
        "count": count,
    })
}

impl BrainPages {
    pub fn new(app: &Arc<App>, access: Arc<Access>, gate: Arc<BrainGate>, gbrain_url: &str) -> Arc<Self> {
        let state = app.config.state_dir.clone();
        Arc::new(Self {
            app: app.clone(),
            access,
            gate,
            client: BrainClient::new(gbrain_url, state.join("gbrain-pages.token"), app.runner.clone()),
            port: port::Port::new(app.runner.clone(), state.join("gbrain-pages")),
            activity: OnceLock::new(),
            asking: tokio::sync::Mutex::new(()),
            export_tickets: std::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn vm_id(&self) -> Option<String> {
        self.app.keys.read("vm_id").filter(|v| !v.is_empty())
    }

    /// What a person did here, for Activity.
    fn record(&self, action: &str, device: Option<&str>, ok: bool, count: Option<u64>) {
        if let Some(a) = self.activity.get() {
            a.enqueue(page_record(action, device, ok, count));
        }
    }

    /// A one-time export ticket.
    fn export_ticket(&self) -> String {
        let t = uuid::Uuid::new_v4().simple().to_string();
        let now = now_ms();
        let mut m = self.export_tickets.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, until| *until > now);
        m.insert(t.clone(), now + EXPORT_TICKET_MS);
        t
    }

    fn take_export_ticket(&self, t: Option<&str>) -> bool {
        let now = now_ms();
        let mut m = self.export_tickets.lock().unwrap_or_else(|e| e.into_inner());
        t.and_then(|t| m.remove(t)).is_some_and(|until| until > now)
    }
}

pub fn register(router: &mut Router, pages: &Arc<BrainPages>, stage: &'static str) {
    let p = pages.clone();
    router.route(
        stage,
        |m, path| (m == Method::GET || m == Method::HEAD) && VIEWS.iter().any(|v| v.2 == path),
        move |req, _| {
            let p = p.clone();
            async move { p.page(req) }
        },
    );
    let p = pages.clone();
    router.exact(stage, Method::GET, "/__cc/brain/admin", move |req, _| {
        let p = p.clone();
        async move { p.admin(req).await }
    });
    let p = pages.clone();
    router.prefix(stage, "/__cc/brain/api/", move |req, _| {
        let p = p.clone();
        async move { p.api(req).await }
    });
}

impl BrainPages {
    fn page(&self, req: Req) -> Resp {
        let headers = [
            ("cache-control", "no-store".to_string()),
            ("x-frame-options", "DENY".to_string()),
            (
                "content-security-policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".to_string(),
            ),
        ];
        let html = |code: u16, body: String| {
            web::with_headers(
                cc_http::full(
                    http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::OK),
                    "text/html; charset=utf-8",
                    body,
                ),
                &headers,
            )
        };
        let (parts, _) = req.into_parts();
        let path = cc_http::pathname(&parts.uri.to_string());
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let session = self
            .vm_id()
            .and_then(|vm| self.access.sessions.read_session(cookie.as_deref(), &vm));
        if !session.is_some_and(|s| s.can_write) {
            return html(
                401,
                self.access
                    .denied("The brain's pages are private", include_str!("denied.html")),
            );
        }
        let view = VIEWS.iter().find(|v| v.2 == path).map_or("pages", |v| v.0);
        let ctx = self.access.shell_context();
        let name = shell::agent_name_of(ctx.hostname.as_deref());
        let data = json!({
            "view": view,
            "brainName": name,
            "consoleUrl": ctx.console_url,
            "importMaxBytes": port::IMPORT_MAX_BYTES,
        });
        html(200, brain_shell(&ctx, view, &data))
    }
}

impl BrainPages {
    /// GBrain's own admin page, from the sidebar: a sign-in through the pages did not get GBrain's
    /// admin cookie (Open's landing does that), so this asks GBrain for a single-use link, as Open
    /// does, for a browser that holds a writer's session.
    async fn admin(&self, req: Req) -> Resp {
        let (parts, _) = req.into_parts();
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let writer = self
            .vm_id()
            .and_then(|vm| self.access.sessions.read_session(cookie.as_deref(), &vm))
            .is_some_and(|s| s.can_write);
        let headers = [("cache-control", "no-store".to_string())];
        if !writer {
            return web::with_headers(
                cc_http::full(
                    http::StatusCode::UNAUTHORIZED,
                    "text/html; charset=utf-8",
                    self.access
                        .denied("The brain's pages are private", include_str!("denied.html")),
                ),
                &headers,
            );
        }
        match super::login::login_path(self.app.runner.as_ref()).await {
            Ok(path) => {
                let mut r = cc_http::full(http::StatusCode::SEE_OTHER, "text/plain", "");
                if let Ok(v) = http::HeaderValue::from_str(&path) {
                    r.headers_mut().insert(http::header::LOCATION, v);
                }
                web::with_headers(r, &headers)
            }
            Err(e) => {
                tracing::error!("[brain-pages] admin: {e}");
                web::with_headers(
                    cc_http::full(
                        http::StatusCode::BAD_GATEWAY,
                        "text/plain; charset=utf-8",
                        "GBrain did not give a sign-in link. It may be starting; try again in a minute.",
                    ),
                    &headers,
                )
            }
        }
    }
}

/// The shell with the brain's sidebar: its five pages, and GBrain's own admin page last.
pub fn brain_shell(ctx: &shell::ShellContext, view: &str, data: &Value) -> String {
    let mut items: Vec<NavItem> = VIEWS
        .iter()
        .map(|(v, label, href, icon)| NavItem {
            label: (*label).into(),
            href: Some((*href).into()),
            icon,
            active: *v == view,
            badge: None,
            external: false,
            group: None,
        })
        .collect();
    items.push(NavItem {
        label: "GBrain admin".into(),
        href: Some("/__cc/brain/admin".into()),
        icon: "admin",
        active: false,
        badge: None,
        external: false,
        group: None,
    });
    let name = shell::agent_name_of(ctx.hostname.as_deref());
    let sub = ctx.hostname.clone().unwrap_or_default();
    let header = ShellHeader {
        mark: "mark",
        name: &name,
        sub: &sub,
        console_url: Some(&ctx.console_url),
    };
    let label = VIEWS.iter().find(|v| v.0 == view).map_or("Pages", |v| v.1);
    let card = shell::ShellCard {
        mark: "mark",
        name: &name,
        sub: &sub,
        status: None,
    };
    let foot = shell::shell_foot(
        "Served by this brain",
        "What you see here is read straight from the brain. It never passes through ControlClaw.",
    );
    shell::shell_frame(&shell::Frame {
        title: &format!("{name} · {}", label.to_lowercase()),
        header: &header,
        page: label,
        card: &card,
        nav_label: "Brain pages",
        nav: &items,
        foot: &foot,
        body: &format!(
            r#"<div id="root"></div><script id="cc-brain" type="application/json">{}</script><script type="module" src="/__cc/files-ui/brain.js"></script>"#,
            shell::inline_json(data)
        ),
        head: r#"<link rel="stylesheet" href="/__cc/files-ui/brain.css">"#,
        tail: "",
    })
}

fn err_resp(e: &PagesError, cors: &[(&str, String)]) -> Resp {
    send_json(e.status, &json!({"error": e.message, "code": e.code}), cors)
}

fn bad(message: &str) -> PagesError {
    PagesError::new(400, "bad_request", message)
}

impl BrainPages {
    /// The origins that may call with this box's cookie (as `files.rs`).
    fn origins(&self) -> Vec<String> {
        let (box_origin, console) = self.access.allowed_origins();
        let console_if_same = same_site(box_origin.as_deref(), console.as_deref())
            .then_some(console)
            .flatten();
        [box_origin, console_if_same]
            .into_iter()
            .flatten()
            .filter(|o| !o.is_empty())
            .collect()
    }

    async fn api(&self, req: Req) -> Resp {
        let (parts, body) = req.into_parts();
        let origins = self.origins();
        let cors = vec![
            ("vary", "Origin".to_string()),
            ("cache-control", "no-store".to_string()),
        ];
        let policy = OriginPolicy {
            allowed: origins.iter().cloned().map(Some).collect(),
            allow_top_level_navigation: true,
            uncredentialed: cc_origin::Uncredentialed::Allow,
        };
        let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
        if let cc_origin::OriginVerdict::Denied { reason, origin } = cc_origin::check_origin(&facts, &policy) {
            tracing::warn!("[brain-pages] {}", cc_origin::denial_message(reason, origin.as_deref()));
            return send_json(
                403,
                &json!({"error": "This request did not come from the brain's pages.", "code": "bad_origin"}),
                &cors,
            );
        }
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let session = self
            .vm_id()
            .and_then(|vm| self.access.sessions.read_session(cookie.as_deref(), &vm));
        let Some(session) = session.filter(|s| s.can_write) else {
            return send_json(
                401,
                &json!({"error": "Your pass for the brain has expired. Open the brain's pages from the console again.", "code": "unpaired"}),
                &cors,
            );
        };
        let device = session.device_id.clone();
        let path = cc_http::pathname(&parts.uri.to_string());
        let route = path.trim_start_matches("/__cc/brain/api");
        let get = parts.method == Method::GET;
        let post = parts.method == Method::POST;
        let out = match route {
            "/kinds" if get => self.kinds().await,
            "/pages" if get => self.list(&parts).await,
            "/page" if get => self.read(query(&parts, "slug").as_deref()).await,
            "/page" if post => {
                let body = read_json(body, PAGE_MAX_BYTES + 4096).await;
                let r = match body {
                    Ok(b) => self.save(&b).await,
                    Err(e) => Err(e),
                };
                if r.is_ok() {
                    self.record("edit", device.as_deref(), true, None);
                }
                r
            }
            "/lately" if get => self.lately(query(&parts, "days").as_deref()).await,
            "/person" if get => self.person(query(&parts, "slug").as_deref()).await,
            "/related" if get => self.related(query(&parts, "slug").as_deref()).await,
            "/ask" if get => Ok(self.ask_state()),
            "/ask" if post => match read_json(body, 16 * 1024).await {
                Ok(b) => self.ask(&b).await,
                Err(e) => Err(e),
            },
            "/import" if get => Ok(self.port.import_status()),
            "/import" if post => {
                let declared = cc_http::header(&parts, "content-length");
                let me = self.activity.get().cloned();
                let dev = device.clone();
                let done = Box::new(move |ok: bool, imported: Option<u64>| {
                    if let Some(a) = me {
                        a.enqueue(page_record("import", dev.as_deref(), ok, imported));
                    }
                });
                self.port.import(body, declared, done).await
            }
            "/export" if post => Ok(json!({"url": format!("/__cc/brain/api/export?t={}", self.export_ticket())})),
            "/export" if get => {
                if !self.take_export_ticket(query(&parts, "t").as_deref()) {
                    return send_json(
                        403,
                        &json!({"error": "This download link has expired. Press Download again.", "code": "expired"}),
                        &cors,
                    );
                }
                return self.export(device, &cors).await;
            }
            _ => Err(PagesError::new(404, "not_found", "Not found")),
        };
        match out {
            Ok(v) => send_json(200, &v, &cors),
            Err(e) => err_resp(&e, &cors),
        }
    }

    /// GBrain's page count per kind, from its admin stats (the counts the console sees by kind,
    /// here with every kind's own name: they stay on the brain).
    async fn kinds(&self) -> Result<Value, PagesError> {
        let Some(a) = self.activity.get() else {
            return Ok(json!({"total": null, "kinds": []}));
        };
        let stats = a.full_stats().await.map_err(|e| {
            tracing::error!("[brain-pages] kinds: {e}");
            PagesError::new(
                503,
                "unavailable",
                "The brain is not answering. It may be starting; try again in a minute.",
            )
        })?;
        let mut kinds: Vec<(String, u64)> = stats
            .get("pages_by_type")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        let n = v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))?;
                        (n > 0).then(|| (k.clone(), n))
                    })
                    .collect()
            })
            .unwrap_or_default();
        kinds.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let total = stats
            .get("page_count")
            .and_then(|v| v.as_u64().or_else(|| v.as_str()?.parse().ok()));
        Ok(json!({
            "total": total,
            "kinds": kinds.into_iter().map(|(k, n)| json!({"kind": k, "count": n})).collect::<Vec<_>>(),
        }))
    }

    /// Browse (a kind, newest first, 50 at a time) or search (names first, then text).
    async fn list(&self, parts: &http::request::Parts) -> Result<Value, PagesError> {
        let kind = query(parts, "type").filter(|t| !t.is_empty() && t.len() <= 64);
        let q = query(parts, "q")
            .map(|q| q.trim().to_string())
            .filter(|q| !q.is_empty());
        let offset = query(parts, "offset")
            .and_then(|o| o.parse::<u64>().ok())
            .unwrap_or(0)
            .min(100_000);
        let Some(q) = q else {
            let mut args = json!({"limit": 50, "offset": offset, "sort": "updated_desc"});
            if let Some(k) = &kind {
                args["type"] = json!(k);
            }
            let a = self.client.call("list_pages", args, CALL).await?;
            let rows = a.result.as_array().cloned().unwrap_or_default();
            let more = a.meta.pointer("/pagination/truncated").and_then(Value::as_bool) == Some(true);
            return Ok(json!({
                "pages": rows.iter().map(row).collect::<Vec<_>>(),
                "next": more.then_some(offset + rows.len() as u64),
            }));
        };
        if q.chars().count() > 200 {
            return Err(bad("Search for at most 200 characters."));
        }
        let mut find = json!({"pattern": q, "limit": 50});
        let mut search = json!({"query": q, "limit": 30, "snippet_chars": 200});
        if let Some(k) = &kind {
            find["type"] = json!(k);
            search["types"] = json!([k]);
        }
        let (names, text) = tokio::join!(
            self.client.call("find_pages", find, CALL),
            self.client.call("search", search, CALL)
        );
        let names = names?;
        let mut seen = std::collections::HashSet::new();
        let mut pages = Vec::new();
        let found = names
            .result
            .get("pages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for r in &found {
            let r = row(r);
            if let Some(s) = r["slug"].as_str()
                && seen.insert(s.to_string())
            {
                pages.push(r);
            }
        }
        // Text hits come after the names; a search that fails still leaves the names.
        let hits = match text {
            Ok(a) => a
                .result
                .as_array()
                .cloned()
                .or_else(|| a.result.get("results").and_then(Value::as_array).cloned())
                .unwrap_or_default(),
            Err(e) => {
                tracing::warn!("[brain-pages] search: {}", e.code);
                Vec::new()
            }
        };
        for h in &hits {
            let Some(slug) = h.get("slug").and_then(Value::as_str) else {
                continue;
            };
            if !seen.insert(slug.to_string()) {
                continue;
            }
            let mut r = row(h);
            r["snippet"] = json!(h.get("chunk_text").and_then(Value::as_str).map(|t| {
                unquote_snippet(without_agent_note(t))
                    .chars()
                    .take(240)
                    .collect::<String>()
            }));
            pages.push(r);
        }
        Ok(json!({"pages": pages, "next": null}))
    }

    async fn read(&self, slug: Option<&str>) -> Result<Value, PagesError> {
        let slug = valid_slug(slug)?;
        // A link's slug is the page's guess at GBrain's (`slugify`); when it misses, GBrain's own
        // fuzzy match finds the page the name means.
        let a = match self
            .client
            .call("get_page", json!({"slug": slug, "include_content": true}), CALL)
            .await
        {
            Err(e) if not_found(e.clone()).status == 404 => self
                .client
                .call(
                    "get_page",
                    json!({"slug": slug, "include_content": true, "fuzzy": true}),
                    CALL,
                )
                .await
                .map_err(not_found)?,
            other => other.map_err(not_found)?,
        };
        let p = &a.result;
        let content = p
            .get("content")
            .and_then(Value::as_str)
            .map(unquote)
            .unwrap_or_default();
        Ok(json!({
            "slug": p.get("slug").and_then(Value::as_str).unwrap_or(slug),
            "title": p.get("title").and_then(Value::as_str).map(unquote),
            "type": p.get("type").and_then(Value::as_str),
            "content": content,
            "revision": p.get("revision").and_then(Value::as_str),
            "updatedAt": p.get("updated_at").and_then(Value::as_str),
            "trustTier": p.get("trust_tier").and_then(Value::as_str),
            "tooLarge": content.len() > PAGE_MAX_BYTES,
        }))
    }

    /// Through GBrain's own write: its links, chunks and index follow. `revision` is what was read;
    /// without it the page is written over whatever changed.
    async fn save(&self, body: &Map<String, Value>) -> Result<Value, PagesError> {
        let slug = valid_slug(body.get("slug").and_then(Value::as_str))?;
        let content = body
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("content is required"))?;
        if content.len() > PAGE_MAX_BYTES {
            return Err(bad("A page can be at most 2 MB here."));
        }
        if content.trim().is_empty() {
            return Err(bad(
                "A page cannot be empty. To remove it, ask an agent or use GBrain's admin page.",
            ));
        }
        let mut args = json!({
            "slug": slug,
            "content": content,
            "request_id": uuid::Uuid::new_v4().to_string(),
            "reason": "Edited by a person on the brain's Pages page",
        });
        match body.get("revision").and_then(Value::as_str) {
            Some(r) if !r.is_empty() => args["expected_revision"] = json!(r),
            _ => args["force"] = json!(true),
        }
        let a = self.client.call("put_page", args, CALL).await.map_err(|e| {
            if e.code == "revision_conflict" {
                PagesError::new(409, "conflict", "This page changed since you opened it.")
            } else {
                e
            }
        })?;
        Ok(json!({
            "slug": slug,
            "revision": a.result.get("revision").and_then(Value::as_str),
            "status": a.result.get("status").and_then(Value::as_str),
        }))
    }

    /// What the brain learned lately: the pages that changed and the facts it saved, with their
    /// times (the browser puts them under days in its own time zone).
    async fn lately(&self, days: Option<&str>) -> Result<Value, PagesError> {
        let days = days.and_then(|d| d.parse::<i64>().ok()).unwrap_or(14).clamp(1, 60);
        let since_ms = now_ms() - days * 86_400_000;
        let since = crate::platform::time::iso_ms(since_ms);
        let mut pages = Vec::new();
        let mut truncated = false;
        let mut offset = 0u64;
        'read: loop {
            let a = self
                .client
                .call(
                    "list_pages",
                    json!({"limit": 100, "offset": offset, "sort": "updated_desc"}),
                    CALL,
                )
                .await?;
            let rows = a.result.as_array().cloned().unwrap_or_default();
            for r in &rows {
                // Newest first: the first page older than the window ends it. One whose time does
                // not read is left out, not taken for the end.
                let Some(at) = r
                    .get("updated_at")
                    .and_then(Value::as_str)
                    .and_then(super::activity::parse_iso)
                else {
                    continue;
                };
                if (at as i64) < since_ms {
                    break 'read;
                }
                if pages.len() >= LATELY_PAGES {
                    truncated = true;
                    break 'read;
                }
                pages.push(row(r));
            }
            let more = a.meta.pointer("/pagination/truncated").and_then(Value::as_bool) == Some(true);
            if !more || rows.is_empty() {
                break;
            }
            offset += rows.len() as u64;
            if offset >= LATELY_ROWS_READ {
                truncated = true;
                break;
            }
        }
        let facts = match self
            .client
            .call("recall", json!({"since": since, "limit": FACTS_MAX}), CALL)
            .await
        {
            Ok(a) => facts_of(&a.result),
            Err(e) => {
                tracing::warn!("[brain-pages] lately facts: {}", e.code);
                Vec::new()
            }
        };
        // GBrain gives at most this many facts for one read: the page says "at least".
        let facts_truncated = facts.len() >= FACTS_MAX;
        Ok(json!({
            "since": since,
            "days": days,
            "pages": pages,
            "facts": facts,
            "truncated": truncated,
            "factsTruncated": facts_truncated,
        }))
    }

    /// One person (or any page): GBrain's card, the page's timeline and the facts about it.
    async fn person(&self, slug: Option<&str>) -> Result<Value, PagesError> {
        let slug = valid_slug(slug)?;
        let (card, timeline, facts) = tokio::join!(
            self.client
                .call("entity", json!({"name": slug, "variants": false}), CALL),
            self.client
                .call("get_timeline", json!({"slug": slug, "limit": 100}), CALL),
            self.client
                .call("recall", json!({"entity": slug, "limit": FACTS_MAX}), CALL),
        );
        let card = card?.result;
        if card.get("found").and_then(Value::as_bool) == Some(false) {
            return Err(PagesError::new(
                404,
                "not_found",
                "There is no page with that name in the brain.",
            ));
        }
        let c = card.get("card").cloned().unwrap_or(Value::Null);
        let referenced: Vec<Value> = c
            .get("referenced_by")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .flat_map(|g| g.get("rows").and_then(Value::as_array).cloned().unwrap_or_default())
            .map(|r| {
                json!({
                    "slug": r.get("slug"),
                    "title": r.get("title").and_then(Value::as_str).map(unquote),
                    "type": r.get("type"),
                    "date": r.get("date"),
                })
            })
            .collect();
        let timeline = timeline.ok().map(|a| timeline_of(&a.result)).unwrap_or_default();
        Ok(json!({
            "slug": slug,
            "title": c.pointer("/entity/title").and_then(Value::as_str).map(unquote),
            "type": c.pointer("/entity/type"),
            "summary": c.get("summary").and_then(Value::as_str).map(unquote),
            "lastTouched": c.pointer("/last_touched/updated_at"),
            "referencedBy": referenced,
            "timeline": timeline,
            "facts": facts.ok().map(|a| facts_of(&a.result)).unwrap_or_default(),
        }))
    }

    /// One page's side panel: the pages that link to it (newest first), when it changed (GBrain
    /// keeps the version each save replaced), and its dated entries. Three bounded reads at once;
    /// one that fails leaves its part empty, so the page itself still shows.
    async fn related(&self, slug: Option<&str>) -> Result<Value, PagesError> {
        let slug = valid_slug(slug)?;
        let (links, versions, timeline) = tokio::join!(
            self.client.call(
                "get_backlinks",
                json!({"slug": slug, "group": "page", "limit": RELATED_LINKS}),
                CALL
            ),
            self.client
                .call("get_versions", json!({"slug": slug, "limit": RELATED_VERSIONS}), CALL),
            self.client
                .call("get_timeline", json!({"slug": slug, "limit": RELATED_TIMELINE}), CALL),
        );
        let (backlinks, backlinks_total) = match links {
            Ok(a) => {
                let rows = a
                    .result
                    .get("rows")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let total = a.result.get("total").and_then(Value::as_u64);
                // A page that links to itself is not "linked from": not listed, not counted.
                let own = rows.iter().any(|r| r.get("slug").and_then(Value::as_str) == Some(slug));
                let total = total.map(|t| if own { t.saturating_sub(1) } else { t });
                let rows: Vec<Value> = rows
                    .iter()
                    .filter(|r| r.get("slug").and_then(Value::as_str).is_some_and(|s| s != slug))
                    .map(|r| {
                        json!({
                            "slug": r.get("slug"),
                            "title": r.get("title").and_then(Value::as_str).map(unquote),
                            "type": r.get("type"),
                        })
                    })
                    .collect();
                (rows, total)
            }
            Err(e) => {
                tracing::warn!("[brain-pages] backlinks: {}", e.code);
                (Vec::new(), None)
            }
        };
        let changes: Vec<Value> = match versions {
            Ok(a) => a
                .result
                .as_array()
                .cloned()
                .or_else(|| a.result.get("versions").and_then(Value::as_array).cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|v| v.get("snapshot_at").and_then(Value::as_str))
                .map(|t| json!(t))
                .collect(),
            Err(e) => {
                tracing::warn!("[brain-pages] versions: {}", e.code);
                Vec::new()
            }
        };
        let changes_more = changes.len() as u64 >= RELATED_VERSIONS;
        let timeline = match timeline {
            Ok(a) => timeline_of(&a.result),
            Err(e) => {
                tracing::warn!("[brain-pages] timeline: {}", e.code);
                Vec::new()
            }
        };
        Ok(json!({
            "backlinks": backlinks,
            "backlinksTotal": backlinks_total,
            "changes": changes,
            "changesMore": changes_more,
            "timeline": timeline,
        }))
    }

    /// Why the brain cannot answer now, or `None`.
    fn ask_refusal(&self) -> Option<PagesError> {
        if self.gate.lock().all {
            return Some(PagesError::new(
                409,
                "stopped",
                "Your organization is stopped, so the brain cannot use AI. Release the emergency stop in the console to ask it.",
            ));
        }
        let key = std::fs::read_to_string(key_state_path(&self.app.config.state_dir)).unwrap_or_default();
        if key.trim() == "clear" {
            return Some(PagesError::new(
                409,
                "no_ai",
                "The brain has no AI to answer with: your plan's included AI is used up or turned off. It comes back on the 1st.",
            ));
        }
        None
    }

    fn ask_state(&self) -> Value {
        match self.ask_refusal() {
            Some(e) => json!({"ready": false, "code": e.code, "reason": e.message}),
            None => json!({"ready": true}),
        }
    }

    /// A question, answered by GBrain from the pages (`synthesize`), with the pages it used and what
    /// the answer cost. One at a time.
    async fn ask(&self, body: &Map<String, Value>) -> Result<Value, PagesError> {
        let question = body
            .get("question")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|q| !q.is_empty())
            .ok_or_else(|| bad("Type a question."))?;
        if question.chars().count() > QUESTION_MAX {
            return Err(bad("A question can be at most 2,000 characters."));
        }
        if let Some(e) = self.ask_refusal() {
            return Err(e);
        }
        let Ok(_one) = self.asking.try_lock() else {
            return Err(PagesError::new(
                429,
                "busy",
                "The brain is answering another question. Ask again when it has finished.",
            ));
        };
        let started = crate::platform::time::iso_ms(now_ms() - 1000);
        let a = self
            .client
            .call("synthesize", json!({"question": question}), ASK)
            .await
            .map_err(|e| match e.code.as_str() {
                "unavailable" => PagesError::new(
                    502,
                    "no_answer",
                    "The brain could not answer: its AI did not respond. Try again in a minute.",
                ),
                _ => e,
            })?;
        let r = &a.result;
        // The pages it used, each once, in the order GBrain cites them.
        let mut seen = std::collections::HashSet::new();
        let slugs: Vec<String> = r
            .get("sources")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|s| seen.insert(s.to_string()))
            .map(str::to_string)
            .collect();
        // The sources are read while the cost is looked up, so neither waits for the other.
        let estimate = r.pointer("/cost/usd_estimate").and_then(Value::as_f64);
        let (sources, ledger) = tokio::join!(self.sources(&slugs), async {
            match estimate {
                Some(_) => None,
                None => self.ledger_cost(&started).await,
            }
        });
        let cost = estimate.or(ledger);
        Ok(json!({
            "answer": r.get("answer").and_then(Value::as_str).map(unquote_all).unwrap_or_default(),
            "sources": sources,
            "status": r.get("synthesis_status"),
            "model": r.pointer("/cost/model"),
            "costUsd": cost,
        }))
    }

    /// Each source with its title, kind and opening lines: the first few read at once, the rest by
    /// name only. A page that cannot be read keeps its name.
    async fn sources(&self, slugs: &[String]) -> Vec<Value> {
        let reads = futures_util::future::join_all(slugs.iter().take(ASK_SOURCES_READ).map(|s| {
            self.client
                .call("get_page", json!({"slug": s, "include_content": true}), CALL)
        }))
        .await;
        slugs
            .iter()
            .enumerate()
            .map(|(i, slug)| match reads.get(i) {
                Some(Ok(a)) => json!({
                    "slug": slug,
                    "title": a.result.get("title").and_then(Value::as_str).map(unquote),
                    "type": a.result.get("type"),
                    "excerpt": a.result.get("content").and_then(Value::as_str).map(|c| excerpt(&unquote(c))),
                }),
                _ => json!({"slug": slug, "title": null, "type": null, "excerpt": null}),
            })
            .collect()
    }

    /// What GBrain logged for its model calls since `since`: the answer's cost when GBrain cannot
    /// price the model itself. Anything else the brain asked a model for in those seconds counts too.
    async fn ledger_cost(&self, since: &str) -> Option<f64> {
        let cmd = super::helper(HELPER)
            .arg("cost")
            .arg(since)
            .timeout(Duration::from_secs(30));
        let out = super::run_helper(self.app.runner.as_ref(), cmd).await.ok()?;
        out.split_whitespace()
            .next()?
            .parse::<f64>()
            .ok()
            .filter(|c| c.is_finite() && *c >= 0.0)
    }

    async fn export(&self, device: Option<String>, cors: &[(&str, String)]) -> Resp {
        let date = crate::platform::time::iso_ms(now_ms());
        let base = format!("brain-{}", &date[..10]);
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let me = self.activity.get().cloned();
        let done = Box::new(move |completed: bool| {
            if let Some(a) = me {
                a.enqueue(page_record("export", device.as_deref(), completed, None));
            }
        });
        if let Err(e) = self.port.export(tx, base.clone(), done).await {
            return err_resp(&e, cors);
        }
        let mut h = cors.to_vec();
        h.push(("content-type", "application/zip".into()));
        h.push((
            "content-disposition",
            crate::boxside::files::content_disposition(&format!("{base}.zip")),
        ));
        h.push(("x-content-type-options", "nosniff".into()));
        web::streamed(200, rx, &h)
    }
}

/// A page as the lists show it.
fn row(r: &Value) -> Value {
    json!({
        "slug": r.get("slug"),
        "title": r.get("title").and_then(Value::as_str).map(unquote),
        "type": r.get("type"),
        "updatedAt": r.get("updated_at"),
    })
}

fn facts_of(v: &Value) -> Vec<Value> {
    v.get("facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|f| {
            json!({
                "fact": f.get("fact").and_then(Value::as_str).map(unquote),
                "entity": f.get("entity_slug"),
                "kind": f.get("kind"),
                "at": f.get("created_at").or_else(|| f.get("valid_from")),
            })
        })
        .collect()
}

fn timeline_of(v: &Value) -> Vec<Value> {
    v.as_array()
        .cloned()
        .or_else(|| v.get("entries").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            json!({
                "date": r.get("date"),
                "summary": r.get("summary").and_then(Value::as_str).map(unquote),
                "detail": r.get("detail").and_then(Value::as_str).map(unquote),
                "source": r.get("source").and_then(Value::as_str).map(unquote),
            })
        })
        .collect()
}

/// A page's opening words for a source card: past its frontmatter and headings, on one line, cut
/// at a character.
pub(super) fn excerpt(content: &str) -> String {
    let content = content.replace("\r\n", "\n");
    let body = match content.strip_prefix("---\n") {
        // Frontmatter that never closes is all frontmatter: nothing of it is the page's words.
        Some(rest) => rest.find("\n---").map_or("", |end| {
            let after = &rest[end + 4..];
            after.split_once('\n').map_or("", |(_, b)| b)
        }),
        None => content.as_str(),
    };
    let text = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("```") && *l != "---")
        .map(list_item_text)
        .collect::<Vec<_>>()
        .join(" ");
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= EXCERPT_CHARS {
        return text;
    }
    let cut: String = text.chars().take(EXCERPT_CHARS).collect();
    format!("{}…", cut.trim_end())
}

/// A line without its list or quote marker (`- `, `* `, `> `, `1. `); text that only starts
/// like one (`**bold**`, `-5%`) stays as it is.
fn list_item_text(line: &str) -> &str {
    for m in ["- ", "* ", "+ ", "> "] {
        if let Some(rest) = line.strip_prefix(m) {
            return rest.trim_start();
        }
    }
    let digits = line.bytes().take_while(u8::is_ascii_digit).count();
    if digits > 0
        && let Some(rest) = line[digits..].strip_prefix(". ")
    {
        return rest.trim_start();
    }
    line
}

/// A slug as GBrain writes them: no control characters, at most 512 characters.
fn valid_slug(slug: Option<&str>) -> Result<&str, PagesError> {
    let s = slug
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("slug is required"))?;
    if s.chars().count() > 512 || s.chars().any(char::is_control) {
        return Err(bad("That is not a page name."));
    }
    Ok(s)
}

fn not_found(e: PagesError) -> PagesError {
    if e.code == "page_not_found" || e.code == "not_found" {
        PagesError::new(404, "not_found", "There is no page with that name in the brain.")
    } else {
        e
    }
}

async fn read_json(body: hyper::body::Incoming, limit: usize) -> Result<Map<String, Value>, PagesError> {
    use http_body_util::BodyExt;
    let bytes = http_body_util::Limited::new(body, limit)
        .collect()
        .await
        .map_err(|_| PagesError::new(413, "too_large", "That is too large to save here."))?
        .to_bytes();
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(bad("The request was not JSON.")),
    }
}

#[cfg(test)]
mod tests;
