//! The brain's one MCP address for outside AI apps, `https://<brain>/mcp`, and the OAuth server in
//! front of it (T-219, apps/saas/docs/features/brain.md "Outside AI apps"). Caddy sends `/mcp`,
//! `/oauth/*` and `/.well-known/oauth-*` here; GBrain's own OAuth and metadata routes are never
//! reached from outside.
//!
//! - `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`: where
//!   an app learns to sign in (RFC 9728, RFC 8414).
//! - `POST /oauth/register`: dynamic client registration (RFC 7591). It grants nothing.
//! - `GET /oauth/authorize`: PKCE (S256) required. The sign-in waits here and the browser goes to
//!   the console, where a person chooses Read only or Read and write; an owner or admin then types
//!   the firewall's code, and the firewall approves the sign-in on this box (`clients.rs`).
//! - `GET /oauth/authorize/done`: the console sends the browser back here; once approved it goes on
//!   to the app with a one-time code. Only the browser that started the sign-in (a cookie on the
//!   brain's name) and showed the approval secret the asking Connect page holds gets it.
//! - `POST /oauth/token`: the code (with the PKCE verifier) or a refresh token for a new pair.
//! - `/mcp`: our access token in, the client's GBrain token out, as the agents' gate does.

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use cc_http::{Ctx, Req, Resp, Router, full, header, send_json};
use http::StatusCode;
use hyper::Method;
use serde_json::{Value, json};

use super::clients::{
    self, BrainClients, ClientAdmission, Finish, Grant, browser_cookie, clean_name, redirect_matches,
};
use super::gate::BrainGate;
use super::now_ms;
use crate::app::App;
use crate::stages;

/// Where an app's call ends up: GBrain on loopback.
pub struct Public {
    pub clients: Arc<BrainClients>,
    pub gate: Arc<BrainGate>,
    /// This brain's own hostname (`vm_hostname`). Without it nothing here answers.
    pub host: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// The console's base URL, where a person approves a sign-in.
    pub console: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// GBrain at `127.0.0.1:<port>`.
    pub target: String,
}

const PATHS: &[&str] = &[
    "/mcp",
    "/oauth/register",
    "/oauth/authorize",
    "/oauth/authorize/done",
    "/oauth/token",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
];

pub fn is_public_path(path: &str) -> bool {
    PATHS.contains(&path)
}

pub fn register(router: &mut Router, app: &Arc<App>, clients: &Arc<BrainClients>, gate: &Arc<BrainGate>) {
    let keys = app.keys.clone();
    let k2 = app.keys.clone();
    let public = Arc::new(Public {
        clients: clients.clone(),
        gate: gate.clone(),
        host: Arc::new(move || keys.read("vm_hostname").filter(|h| !h.is_empty())),
        console: Arc::new(move || {
            std::env::var("CONTROLCLAW_URL")
                .ok()
                .filter(|u| !u.is_empty())
                .or_else(|| {
                    k2.read("config_api_url")
                        .filter(|u| !u.is_empty())
                        .map(|u| match u.find("/api/") {
                            Some(i) => u[..i].to_string(),
                            None => u,
                        })
                })
                .map(|u| u.trim_end_matches('/').to_string())
        }),
        target: format!("127.0.0.1:{}", super::gbrain_port()),
    });
    router.route(
        stages::BRAIN_OPEN,
        |_, p| is_public_path(p),
        move |req, ctx| {
            let public = public.clone();
            async move { handle(&public, req, ctx).await }
        },
    );
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(status: u16, title: &str, body: &str) -> Resp {
    let html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{t}</title><style>body{{font:16px/1.5 system-ui,sans-serif;max-width:32rem;margin:15vh auto;padding:0 16px;color:#1f1f24;background:#fff}}@media (prefers-color-scheme:dark){{body{{color:#ececf1;background:#141418}}}}h1{{font-size:1.25rem}}</style></head><body><h1>{t}</h1><p>{b}</p></body></html>",
        t = esc(title),
        b = body
    );
    let mut r = full(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
        "text/html; charset=utf-8",
        html,
    );
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    h.insert("x-frame-options", http::HeaderValue::from_static("DENY"));
    h.insert(
        "content-security-policy",
        http::HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'"),
    );
    r
}

/// A cookie's value from the request's `Cookie` headers.
fn cookie<'a>(req: &'a Req, name: &str) -> Option<&'a str> {
    req.headers()
        .get_all(http::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn redirect(to: &str) -> Resp {
    let mut r = full(StatusCode::FOUND, "", Bytes::new());
    if let Ok(v) = http::HeaderValue::from_str(to) {
        r.headers_mut().insert(http::header::LOCATION, v);
    }
    r.headers_mut()
        .insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    r
}

fn oauth_error(status: u16, error: &str, description: &str) -> Resp {
    send_json(status, &json!({"error": error, "error_description": description}))
}

fn limited(wait: u64) -> Resp {
    let mut r = oauth_error(429, "temporarily_unavailable", "Too many requests. Try again shortly.");
    if let Ok(v) = http::HeaderValue::from_str(&wait.to_string()) {
        r.headers_mut().insert(http::header::RETRY_AFTER, v);
    }
    r
}

fn query_of(req: &Req) -> Vec<(String, String)> {
    req.uri()
        .query()
        .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect())
        .unwrap_or_default()
}

fn get<'a>(q: &'a [(String, String)], k: &str) -> Option<&'a str> {
    q.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
}

pub async fn handle(p: &Public, req: Req, _ctx: Ctx) -> Resp {
    let Some(host) = (p.host)() else {
        return send_json(503, &json!({"error": "This brain has no public name yet."}));
    };
    let issuer = format!("https://{host}");
    let path = cc_http::pathname(&req.uri().to_string());
    let method = req.method().clone();
    match (method.as_str(), path.as_str()) {
        (_, "/mcp") => mcp(p, &issuer, req).await,
        ("GET", "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp") => send_json(
            200,
            &json!({
                "resource": format!("{issuer}/mcp"),
                "authorization_servers": [issuer],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["read", "write"],
                "resource_name": "ControlClaw brain",
            }),
        ),
        ("GET", "/.well-known/oauth-authorization-server" | "/.well-known/oauth-authorization-server/mcp") => {
            send_json(200, &metadata(&issuer))
        }
        ("POST", "/oauth/register") => {
            if let Err(w) = p.clients.take_public(clients::PublicCall::Register, now_ms()) {
                return limited(w);
            }
            register_client(p, req).await
        }
        ("GET", "/oauth/authorize") => authorize(p, &issuer, &host, &query_of(&req)),
        ("GET", "/oauth/authorize/done") => {
            let q = query_of(&req);
            let Some(r) = get(&q, "req") else {
                return page(400, "Sign-in not found", "Start again in the app you were connecting.");
            };
            let browser = cookie(&req, &browser_cookie(r));
            match p.clients.finish(r, browser, get(&q, "approval"), &issuer, now_ms()) {
                Finish::Code(to) | Finish::Denied(to) => redirect(&to),
                Finish::Waiting => page(
                    409,
                    "Not approved yet",
                    "This app has not been approved for the brain. Go back to ControlClaw and type the code, or start again in the app.",
                ),
                Finish::NotHere => page(
                    403,
                    "Open this in the browser you started in",
                    "This sign-in was started in another browser, or it has ended. Start again in the app you were connecting, and approve it in the browser the app opens.",
                ),
            }
        }
        ("POST", "/oauth/token") => token(p, req).await,
        _ => send_json(405, &json!({"error": "Method not allowed"})),
    }
}

pub fn metadata(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth/authorize"),
        "token_endpoint": format!("{issuer}/oauth/token"),
        "registration_endpoint": format!("{issuer}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": ["read", "write"],
        "authorization_response_iss_parameter_supported": true,
    })
}

async fn register_client(p: &Public, req: Req) -> Resp {
    let Some(raw) = cc_http::read_body(req.into_body(), 16 * 1024).await else {
        return oauth_error(
            400,
            "invalid_client_metadata",
            "The registration must be JSON of at most 16 KB.",
        );
    };
    let Ok(Value::Object(b)) = serde_json::from_slice::<Value>(&raw) else {
        return oauth_error(
            400,
            "invalid_client_metadata",
            "The registration must be a JSON object.",
        );
    };
    let uris: Vec<String> = b
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    let method = b
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("none");
    if !matches!(method, "none" | "client_secret_post" | "client_secret_basic") {
        return oauth_error(
            400,
            "invalid_client_metadata",
            "token_endpoint_auth_method is not supported.",
        );
    }
    let name = b.get("client_name").and_then(Value::as_str).unwrap_or("");
    match p.clients.register(name, uris, method != "none", now_ms()) {
        Ok((reg, secret)) => {
            let mut out = json!({
                "client_id": reg.client_id,
                "client_id_issued_at": reg.created_ms / 1000,
                "client_name": reg.name,
                "redirect_uris": reg.redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": method,
            });
            if let Some(s) = secret {
                out["client_secret"] = json!(s);
                out["client_secret_expires_at"] = json!(0);
            }
            send_json(201, &out)
        }
        Err(e) => oauth_error(400, "invalid_redirect_uri", e),
    }
}

fn authorize(p: &Public, issuer: &str, host: &str, q: &[(String, String)]) -> Resp {
    let (Some(client_id), Some(redirect_uri)) = (get(q, "client_id"), get(q, "redirect_uri")) else {
        return page(
            400,
            "This sign-in link is incomplete",
            "Start again in the app you were connecting.",
        );
    };
    let Some(reg) = p.clients.registration(client_id) else {
        return page(
            400,
            "This app is not registered",
            "Start again in the app you were connecting.",
        );
    };
    if !redirect_matches(&reg.redirect_uris, redirect_uri) {
        return page(
            400,
            "This sign-in link is not valid",
            "The app asked to go back to an address it did not register.",
        );
    }
    if let Err(w) = p.clients.take_authorize(client_id, now_ms()) {
        let mut r = page(
            429,
            "Too many sign-ins",
            "This app started too many sign-ins. Wait a minute, then start again in the app.",
        );
        if let Ok(v) = http::HeaderValue::from_str(&w.to_string()) {
            r.headers_mut().insert(http::header::RETRY_AFTER, v);
        }
        return r;
    }
    // Errors before a person approved anything are a page here, never a redirect: a registered
    // redirect is the app's own word, and sending a browser there unasked makes this an open
    // redirector.
    let bad = |why: &str| page(400, "This sign-in link is not valid", why);
    if get(q, "response_type") != Some("code") {
        return bad("The app asked for a kind of sign-in this brain does not offer.");
    }
    let (Some(challenge), Some("S256")) = (get(q, "code_challenge"), get(q, "code_challenge_method")) else {
        return bad("The app did not use PKCE (S256), which this brain requires.");
    };
    if let Some(res) = get(q, "resource")
        && res.trim_end_matches('/') != format!("{issuer}/mcp")
        && res.trim_end_matches('/') != issuer
    {
        return bad("The app asked to sign in to another address.");
    }
    let Some(console) = (p.console)() else {
        return page(503, "The brain cannot reach ControlClaw", "Try again in a minute.");
    };
    let state = get(q, "state").map(String::from);
    let started = match p.clients.begin(client_id, redirect_uri, challenge, state, now_ms()) {
        Ok(s) => s,
        Err(_) => {
            return page(
                503,
                "Too many sign-ins are waiting",
                "Wait a few minutes, then start again in the app.",
            );
        }
    };
    let mut u = match url::Url::parse(&format!("{console}/dashboard/brain/connect")) {
        Ok(u) => u,
        Err(_) => return page(503, "The brain cannot reach ControlClaw", "Try again in a minute."),
    };
    u.query_pairs_mut()
        .append_pair("req", &started.req)
        .append_pair("brain", host)
        .append_pair("name", &clean_name(&reg.name))
        .append_pair("site", &super::clients::site_of(redirect_uri));
    let mut r = redirect(u.as_str());
    // Host-only (`__Host-`), so no other name under the brain's domain can read or set it. Lax, as
    // the browser comes back from the console with a top-level GET.
    let c = format!(
        "{}={}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        browser_cookie(&started.req),
        started.browser,
        // Past the sign-in's own life, so a browser that comes back late is told it ran out.
        (clients::PENDING_MS + 10 * 60_000) / 1000
    );
    if let Ok(v) = http::HeaderValue::from_str(&c) {
        r.headers_mut().append(http::header::SET_COOKIE, v);
    }
    r
}

/// The client's id and secret, from the form or from HTTP Basic (`client_secret_basic`).
fn credentials(parts: &http::request::Parts, form: &[(String, String)]) -> (Option<String>, Option<String>) {
    if let Some(basic) = header(parts, "authorization").and_then(|a| a.strip_prefix("Basic "))
        && let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(basic.trim())
        && let Ok(s) = String::from_utf8(raw)
        && let Some((id, secret)) = s.split_once(':')
    {
        let dec = |v: &str| {
            url::form_urlencoded::parse(format!("x={v}").as_bytes())
                .next()
                .map(|(_, v)| v.into_owned())
        };
        return (dec(id), dec(secret));
    }
    (
        get(form, "client_id").map(String::from),
        get(form, "client_secret").map(String::from),
    )
}

fn granted(g: Grant) -> Resp {
    send_json(
        200,
        &json!({
            "access_token": g.access,
            "token_type": "Bearer",
            "expires_in": g.expires_in,
            "refresh_token": g.refresh,
            "scope": g.scope,
        }),
    )
}

/// Token bodies read at once: the same size as the refused-body drain's cap, but a pool of its own,
/// so neither can starve the other.
const TOKEN_READS: usize = DRAINING;
static TOKEN_READ: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(TOKEN_READS);

/// A token call's body, read before any bucket is charged (which one depends on the body): a short
/// deadline, and only as many at once as `slots` allows. A body it gives up on is left unread, so
/// the answer closes the connection (see `refuse`).
pub(crate) async fn token_body<B>(slots: &tokio::sync::Semaphore, body: B) -> Result<Bytes, Box<Resp>>
where
    B: http_body::Body<Data = Bytes> + Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let Ok(_permit) = slots.try_acquire() else {
        let mut r = limited(1);
        r.headers_mut()
            .insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
        return Err(Box::new(r));
    };
    let close = |mut r: Resp| {
        r.headers_mut()
            .insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
        Box::new(r)
    };
    match tokio::time::timeout(std::time::Duration::from_secs(5), cc_http::read_body(body, 16 * 1024)).await {
        Ok(Some(raw)) => Ok(raw),
        Ok(None) => Err(close(oauth_error(
            400,
            "invalid_request",
            "The request body is too large.",
        ))),
        Err(_) => Err(close(oauth_error(
            400,
            "invalid_request",
            "The request body came too slowly.",
        ))),
    }
}

async fn token(p: &Public, req: Req) -> Resp {
    let (parts, body) = req.into_parts();
    let raw = match token_body(&TOKEN_READ, body).await {
        Ok(raw) => raw,
        Err(r) => return *r,
    };
    let form: Vec<(String, String)> = url::form_urlencoded::parse(&raw).into_owned().collect();
    let (client_id, secret) = credentials(&parts, &form);
    let now = now_ms();
    if let Err(w) = p.clients.take_token(
        client_id.as_deref().unwrap_or(""),
        get(&form, "refresh_token"),
        get(&form, "code"),
        now,
    ) {
        return limited(w);
    }
    let Some(client_id) = client_id else {
        return oauth_error(401, "invalid_client", "client_id is required.");
    };
    let r = match get(&form, "grant_type") {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (get(&form, "code"), get(&form, "code_verifier")) else {
                return oauth_error(400, "invalid_request", "code and code_verifier are required.");
            };
            p.clients.exchange_code(
                code,
                &client_id,
                get(&form, "redirect_uri"),
                verifier,
                secret.as_deref(),
                now,
            )
        }
        Some("refresh_token") => {
            let Some(refresh) = get(&form, "refresh_token") else {
                return oauth_error(400, "invalid_request", "refresh_token is required.");
            };
            p.clients.refresh(refresh, &client_id, secret.as_deref(), now)
        }
        _ => {
            return oauth_error(
                400,
                "unsupported_grant_type",
                "Use authorization_code or refresh_token.",
            );
        }
    };
    match r {
        Ok(g) => granted(g),
        Err("invalid_client") => oauth_error(401, "invalid_client", "The client could not be authenticated."),
        Err("server_error") => oauth_error(500, "server_error", "The token could not be saved."),
        Err(e) => oauth_error(400, e, "The code or refresh token is not valid."),
    }
}

fn challenge(issuer: &str, status: u16, error: Option<&str>, message: &str) -> Resp {
    let mut r = send_json(status, &json!({"error": message}));
    let mut v = format!("Bearer resource_metadata=\"{issuer}/.well-known/oauth-protected-resource\"");
    if let Some(e) = error {
        v.push_str(&format!(", error=\"{e}\""));
    }
    if let Ok(h) = http::HeaderValue::from_str(&v) {
        r.headers_mut().insert(http::header::WWW_AUTHENTICATE, h);
    }
    r
}

/// How much of a refused call's body is read, at most, and by how many calls at once.
const DRAIN_MAX: usize = 64 * 1024;
const DRAINING: usize = 64;
static DRAIN: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(DRAINING);

/// A refused call's body is read and thrown away (a little of it, briefly) before the answer:
/// hyper closes a keep-alive connection whose request body was left unread, and Caddy, which reuses
/// it for the next request and does not retry a POST, would answer that one with a bare 502. A body
/// that is longer, slower, or comes while many others drain gets `Connection: close` instead, which
/// Caddy does not reuse.
async fn refuse(req: Req, mut resp: Resp) -> Resp {
    use http_body_util::BodyExt;
    let drained = match DRAIN.try_acquire() {
        Ok(_permit) => {
            let mut body = req.into_body();
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                let mut seen = 0usize;
                while let Some(frame) = body.frame().await {
                    let Ok(frame) = frame else { return false };
                    if let Some(d) = frame.data_ref() {
                        seen += d.len();
                        if seen > DRAIN_MAX {
                            return false;
                        }
                    }
                }
                true
            })
            .await
            .unwrap_or(false)
        }
        Err(_) => false,
    };
    if !drained {
        resp.headers_mut()
            .insert(http::header::CONNECTION, http::HeaderValue::from_static("close"));
    }
    resp
}

/// What an internet caller sent that GBrain has no business seeing: cookies (the brain's sign-in
/// cookie among them) and forwarding headers it could forge.
fn strip_for_gbrain(req: &mut Req) {
    let h = req.headers_mut();
    h.remove(http::header::COOKIE);
    h.remove("forwarded");
    h.remove("x-real-ip");
    let forwarded: Vec<http::HeaderName> = h
        .keys()
        .filter(|k| k.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect();
    for k in forwarded {
        h.remove(&k);
    }
}

async fn mcp(p: &Public, issuer: &str, req: Req) -> Resp {
    if !matches!(*req.method(), Method::POST | Method::GET | Method::DELETE) {
        return refuse(req, send_json(405, &json!({"error": "Method not allowed"}))).await;
    }
    let bearer = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(|t| t.trim().to_string());
    let Some(bearer) = bearer.filter(|b| !b.is_empty()) else {
        return refuse(req, challenge(issuer, 401, None, "Sign in to use this brain.")).await;
    };
    let stopped = p.gate.lock().all;
    let (id, token) = match p.clients.admit(&bearer, stopped, now_ms()) {
        ClientAdmission::Token { id, token } => (id, token),
        ClientAdmission::Unknown => {
            let r = challenge(
                issuer,
                401,
                Some("invalid_token"),
                "This sign-in is not valid. Connect the app again.",
            );
            return refuse(req, r).await;
        }
        ClientAdmission::Expired => {
            let r = challenge(
                issuer,
                401,
                Some("invalid_token"),
                "This app's access to the brain has ended.",
            );
            return refuse(req, r).await;
        }
        ClientAdmission::Stopped => {
            let r = send_json(403, &json!({"error": "The organization is under an emergency stop."}));
            return refuse(req, r).await;
        }
        ClientAdmission::Limited(w) => return refuse(req, limited(w)).await,
    };
    let path = req
        .uri()
        .path_and_query()
        .map(|q| q.as_str())
        .unwrap_or("/mcp")
        .to_string();
    let mut req = req;
    strip_for_gbrain(&mut req);
    match super::gate::forward(&p.target, &token, &path, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("[gbrain-clients] {id}'s call did not reach GBrain: {e}");
            send_json(
                503,
                &json!({"error": "The brain is stopped or starting. Try again in a minute."}),
            )
        }
    }
}
