//! Inbound webhooks (`ingress.ts`): where a delivery from the internet enters the organization.
//! Caddy terminates TLS and hands `/hook/*` to the ingress listener; each delivery is checked
//! against its registration's rules (HMAC, OIDC, URL form, all must pass), counted against two
//! budgets (delivered and unverified, apart, so junk cannot spend the real sender's), and
//! forwarded to the agent box. No refusal has a body; why is on Activity.
//!
//! The order is load-bearing: slot, read, verify, then charge.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use bytes::Bytes;
use cc_http::{BoxFuture, Req, Resp};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

use super::url_form::{decode_form, hook_query, url_form_signature, verify_url_form};

pub const INGRESS_PATH_PREFIX: &str = "/hook/";
pub const INGRESS_DEFAULT_BODY_BYTES: f64 = 256.0 * 1024.0;
pub const INGRESS_MAX_BODY_BYTES: f64 = 1024.0 * 1024.0;
pub const INGRESS_DEFAULT_PER_MINUTE: f64 = 60.0;
pub const INGRESS_MAX_PER_MINUTE: f64 = 180.0;
pub const INGRESS_ORG_PER_MINUTE: usize = 180;
pub const INGRESS_IN_FLIGHT_PER_VM: usize = 4;
pub const INGRESS_IN_FLIGHT_ORG: usize = 16;
/// Longer than the agent box's own budget for its loopback listener (3 s) plus the hops.
pub const INGRESS_FORWARD_TIMEOUT_MS: u64 = 8_000;
pub const INGRESS_UNVERIFIED_PER_MINUTE: usize = 20;
pub const INGRESS_UNVERIFIED_LOCKOUT_MS: u64 = 15 * 60_000;
pub const INGRESS_TARGET_PORT_MIN: f64 = 8700.0;
pub const INGRESS_TARGET_PORT_MAX: f64 = 8799.0;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(5);

const FORWARD_HEADER_ALLOWLIST: &[&str] = &["content-type", "authorization"];
const FORWARD_HEADER_PREFIXES: &[&str] = &["x-goog-", "x-hub-signature", "x-github-", "x-slack-"];

/// `targetPortAllowed`: 8700-8799, the range a hook listener on the box binds in.
pub fn target_port_allowed(port: f64) -> bool {
    port.fract() == 0.0 && (INGRESS_TARGET_PORT_MIN..=INGRESS_TARGET_PORT_MAX).contains(&port)
}

pub fn owns_ingress_path(path: &str) -> bool {
    path.starts_with(INGRESS_PATH_PREFIX)
}

/// One check a delivery must pass.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyRule {
    Hmac(HmacRule),
    Oidc {
        issuer: String,
        audience: String,
        subject_email: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct HmacRule {
    /// `input: "url-form"`: the signature is over the public URL and the form (phone, W4).
    pub url_form: bool,
    pub public_url: Option<String>,
    pub resign_secret: Option<String>,
    pub header: String,
    pub sha1: bool,
    pub base64: bool,
    pub prefix: Option<String>,
    pub secret: String,
    pub timestamp_header: Option<String>,
    pub signed_format: Option<String>,
    pub max_age_s: Option<f64>,
}

fn str_of(v: &Map<String, Value>, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}

/// `Number(v)` for the values a payload carries.
pub fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse().unwrap_or(f64::NAN)
            }
        }
        Some(_) => f64::NAN,
    }
}

impl VerifyRule {
    /// `parseVerify` / `parseVerifyRules`: `strict` (a command's payload) refuses an empty secret,
    /// header or issuer, as `parseVerifyRules` does.
    pub fn parse_list(raw: Option<&Value>, strict: bool) -> Vec<VerifyRule> {
        let Some(Value::Array(list)) = raw else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in list {
            let empty = Map::new();
            let v = entry.as_object().unwrap_or(&empty);
            let kind = v.get("kind").and_then(Value::as_str);
            let ok = |k: &str| {
                v.get(k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !strict || !s.is_empty())
            };
            if kind == Some("hmac") && ok("secret") && ok("header") {
                let age = js_number(v.get("maxAgeS"));
                out.push(VerifyRule::Hmac(HmacRule {
                    header: str_of(v, "header").unwrap_or_default(),
                    sha1: v.get("algo").and_then(Value::as_str) == Some("sha1"),
                    base64: v.get("encoding").and_then(Value::as_str) == Some("base64"),
                    prefix: str_of(v, "prefix"),
                    secret: str_of(v, "secret").unwrap_or_default(),
                    timestamp_header: str_of(v, "timestampHeader"),
                    signed_format: str_of(v, "signedFormat"),
                    max_age_s: (age.is_finite() && age > 0.0).then_some(age),
                    ..Default::default()
                }));
            } else if kind == Some("oidc")
                && ok("issuer")
                && v.get("audience").and_then(Value::as_str).is_some_and(|a| !a.is_empty())
            {
                out.push(VerifyRule::Oidc {
                    issuer: str_of(v, "issuer").unwrap_or_default(),
                    audience: str_of(v, "audience").unwrap_or_default(),
                    subject_email: str_of(v, "subjectEmail"),
                });
            }
        }
        out
    }

    /// As the store keeps it (`JSON.stringify` of what `parseVerifyRules` made).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        match self {
            VerifyRule::Hmac(h) => {
                m.insert("kind".into(), json!("hmac"));
                if h.url_form {
                    m.insert("input".into(), json!("url-form"));
                }
                if let Some(u) = &h.public_url {
                    m.insert("publicUrl".into(), json!(u));
                }
                if let Some(u) = &h.resign_secret {
                    m.insert("resignSecret".into(), json!(u));
                }
                m.insert("header".into(), json!(h.header));
                m.insert("algo".into(), json!(if h.sha1 { "sha1" } else { "sha256" }));
                m.insert("encoding".into(), json!(if h.base64 { "base64" } else { "hex" }));
                if let Some(p) = &h.prefix {
                    m.insert("prefix".into(), json!(p));
                }
                m.insert("secret".into(), json!(h.secret));
                if let Some(t) = &h.timestamp_header {
                    m.insert("timestampHeader".into(), json!(t));
                }
                if let Some(f) = &h.signed_format {
                    m.insert("signedFormat".into(), json!(f));
                }
                if let Some(a) = h.max_age_s {
                    m.insert("maxAgeS".into(), num(a));
                }
            }
            VerifyRule::Oidc {
                issuer,
                audience,
                subject_email,
            } => {
                m.insert("kind".into(), json!("oidc"));
                m.insert("issuer".into(), json!(issuer));
                m.insert("audience".into(), json!(audience));
                if let Some(e) = subject_email {
                    m.insert("subjectEmail".into(), json!(e));
                }
            }
        }
        Value::Object(m)
    }
}

/// A JS number as JSON: whole numbers without a fraction.
pub fn num(v: f64) -> Value {
    if v.fract() == 0.0 && v.abs() < 9_007_199_254_740_992.0 {
        json!(v as i64)
    } else {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Target {
    pub vm_id: String,
    pub hostname: String,
    pub port: f64,
    pub path: String,
}

pub type Authorize = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;
pub type ResponseAllowed = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// An error refuses the delivery (503), as a throw does in the TS.
pub type PrepareDelivery = Arc<dyn Fn(&[u8], &str) -> Result<Map<String, Value>, String> + Send + Sync>;
/// An error refuses the delivery (503), as a throw does in the TS.
pub type RewriteResponse = Arc<dyn Fn(&str, &[u8], &str) -> Result<String, String> + Send + Sync>;

/// `WebhookRegistration`. The closures are firewall-local policy (W4's phone callbacks), never
/// accepted from the console.
#[derive(Clone)]
pub struct Registration {
    pub id: String,
    pub name: String,
    pub target: Target,
    pub verify: Vec<VerifyRule>,
    pub max_body_bytes: f64,
    pub per_minute: f64,
    pub enabled: bool,
    pub bounded: bool,
    pub authorize: Option<Authorize>,
    pub response_allowed: Option<ResponseAllowed>,
    pub prepare_delivery: Option<PrepareDelivery>,
    pub rewrite_response: Option<RewriteResponse>,
}

impl Registration {
    pub fn plain(
        id: &str,
        name: &str,
        target: Target,
        verify: Vec<VerifyRule>,
        max_body: f64,
        per_minute: f64,
        enabled: bool,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            target,
            verify,
            max_body_bytes: max_body,
            per_minute,
            enabled,
            bounded: false,
            authorize: None,
            response_allowed: None,
            prepare_delivery: None,
            rewrite_response: None,
        }
    }
}

fn clamp(v: f64, low: f64, high: f64) -> f64 {
    v.max(low).min(high)
}

/// `parseRegistrations`: the legacy plain file (`WEBHOOKS_PATH`).
pub fn parse_registrations(json: &Value) -> Vec<Registration> {
    let Value::Array(list) = json else { return Vec::new() };
    let mut out = Vec::new();
    for raw in list {
        let empty = Map::new();
        let r = raw.as_object().unwrap_or(&empty);
        let t = r.get("target").and_then(Value::as_object).unwrap_or(&empty);
        let port = js_number(t.get("port"));
        let Some(id) = r.get("id").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
            continue;
        };
        let (Some(vm), Some(host)) = (str_of(t, "vmId"), str_of(t, "hostname")) else {
            continue;
        };
        if !target_port_allowed(port) {
            continue;
        }
        let truthy_or = |k: &str, d: f64| {
            let n = js_number(r.get(k));
            if n.is_nan() || n == 0.0 { d } else { n }
        };
        out.push(Registration::plain(
            id,
            &str_of(r, "name").unwrap_or_else(|| id.to_string()),
            Target {
                vm_id: vm,
                hostname: host,
                port,
                path: str_of(t, "path")
                    .filter(|p| p.starts_with('/'))
                    .unwrap_or_else(|| "/".into()),
            },
            VerifyRule::parse_list(r.get("verify"), false),
            clamp(
                truthy_or("maxBodyBytes", INGRESS_DEFAULT_BODY_BYTES),
                1.0,
                INGRESS_MAX_BODY_BYTES,
            ),
            clamp(
                truthy_or("perMinute", INGRESS_DEFAULT_PER_MINUTE),
                1.0,
                INGRESS_MAX_PER_MINUTE,
            ),
            r.get("enabled") != Some(&Value::Bool(false)),
        ));
    }
    out
}

/// What the box is handed.
#[derive(Debug, Clone)]
pub struct Delivery {
    pub headers: Map<String, Value>,
    pub body_b64: String,
    pub query: String,
    pub bounded: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub status: Value,
    pub body_b64: Option<String>,
    pub content_type: Option<String>,
}

pub type Deliver = Arc<dyn Fn(Registration, Delivery) -> BoxFuture<Result<Reply, String>> + Send + Sync>;
/// The content rules on a verified body: `None` to forward it, or `(status, reason)` (W4). It gets
/// the registration, the body, its `Content-Type` and its `Content-Encoding`.
pub type Screen = Arc<dyn Fn(Registration, Bytes, String, String) -> BoxFuture<Option<(u16, String)>> + Send + Sync>;
pub type Registrations = Arc<dyn Fn() -> Vec<Registration> + Send + Sync>;

#[derive(Default)]
struct Budgets {
    delivered: HashMap<String, Vec<u64>>,
    org: Vec<u64>,
    unverified: Vec<u64>,
    locked_until: u64,
    in_flight_org: usize,
    in_flight: HashMap<String, usize>,
}

pub struct Ingress {
    pub registrations: Registrations,
    pub deliver: Deliver,
    pub screen: Option<Screen>,
    pub log_path: Option<String>,
    pub jwks: super::oidc::Jwks,
    http: reqwest::Client,
    budgets: Mutex<Budgets>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    #[cfg(test)]
    pub test_keys: Option<Vec<Value>>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn empty(status: u16, close: bool) -> Resp {
    let mut r = cc_http::empty(status);
    if close && let Ok(v) = "close".parse() {
        r.headers_mut().insert("connection", v);
    }
    r
}

fn header(parts: &http::request::Parts, name: &str) -> String {
    parts
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

fn to_base36(mut n: u64) -> String {
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(digits[(n % 36) as usize]);
        n /= 36;
        if n == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// Why a body could not be read.
enum ReadError {
    TooLarge,
    Stopped,
}

/// `readBody`: at most `cap` bytes, refusing past it rather than buffering it first.
async fn read_body(
    parts: &http::request::Parts,
    body: hyper::body::Incoming,
    cap: usize,
) -> Result<Vec<u8>, ReadError> {
    let declared = js_number(
        parts
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .map(|s| Value::String(s.into()))
            .as_ref(),
    );
    if declared.is_finite() && declared > cap as f64 {
        return Err(ReadError::TooLarge);
    }
    let read = async {
        let mut body = body;
        let mut buf = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| ReadError::Stopped)?;
            if let Some(d) = frame.data_ref() {
                buf.extend_from_slice(d);
                if buf.len() > cap {
                    return Err(ReadError::TooLarge);
                }
            }
        }
        Ok(buf)
    };
    tokio::time::timeout(UPLOAD_TIMEOUT, read)
        .await
        .unwrap_or(Err(ReadError::Stopped))
}

/// `forwardHeaders`: what the box is given of the request's headers.
pub fn forward_headers(parts: &http::request::Parts) -> Map<String, Value> {
    let mut out = Map::new();
    for name in parts.headers.keys() {
        let lower = name.as_str().to_lowercase();
        if (FORWARD_HEADER_ALLOWLIST.contains(&lower.as_str())
            || FORWARD_HEADER_PREFIXES.iter().any(|p| lower.starts_with(p)))
            && let Some(v) = parts.headers.get(name).and_then(|v| v.to_str().ok())
        {
            out.insert(lower, json!(v));
        }
    }
    out
}

struct Ctx {
    id: String,
    started: u64,
}

impl Ingress {
    pub fn new(
        registrations: Registrations,
        deliver: Deliver,
        screen: Option<Screen>,
        log_path: Option<String>,
    ) -> Self {
        Self {
            registrations,
            deliver,
            screen,
            log_path,
            jwks: super::oidc::Jwks::default(),
            http: reqwest::Client::builder().no_proxy().build().unwrap_or_default(),
            budgets: Mutex::new(Budgets::default()),
            now: Arc::new(now_ms),
            #[cfg(test)]
            test_keys: None,
        }
    }

    #[cfg(test)]
    pub fn with_clock(mut self, now: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        self.now = now;
        self
    }

    fn b(&self) -> std::sync::MutexGuard<'_, Budgets> {
        self.budgets.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One delivery.
    pub async fn handle(&self, req: Req, path: &str) -> Resp {
        let started = (self.now)();
        let ctx = Ctx {
            id: format!(
                "wh_{}_{}",
                to_base36(started),
                (0..8)
                    .map(|_| to_base36(rand::random::<u64>() % 36))
                    .collect::<String>()
            ),
            started,
        };
        let (parts, body) = req.into_parts();
        if parts.method != http::Method::POST {
            return cc_http::empty(405);
        }
        let id = &path[INGRESS_PATH_PREFIX.len()..];
        let reg = (self.registrations)().into_iter().find(|r| r.id == id && r.enabled);
        let Some(reg) = reg else {
            self.count_unverified();
            return self.refuse(
                &ctx,
                404,
                "unknown_hook",
                "no registration with that id",
                None,
                0,
                false,
            );
        };
        if reg.verify.is_empty() {
            return self.refuse(
                &ctx,
                503,
                "needs_setup",
                "this webhook has no checks on this firewall yet",
                Some(&reg),
                0,
                false,
            );
        }
        if !self.take_slot(&reg.target.vm_id) {
            return self.refuse(
                &ctx,
                503,
                "agent_unreachable",
                "too many deliveries in flight for that agent",
                Some(&reg),
                0,
                false,
            );
        }
        // Released however this ends, a client that goes away mid-upload included.
        struct Slot<'a>(&'a Ingress, String);
        impl Drop for Slot<'_> {
            fn drop(&mut self) {
                self.0.release_slot(&self.1);
            }
        }
        let _slot = Slot(self, reg.target.vm_id.clone());
        self.with_slot(&ctx, &reg, &parts, body).await
    }

    async fn with_slot(
        &self,
        ctx: &Ctx,
        reg: &Registration,
        parts: &http::request::Parts,
        body: hyper::body::Incoming,
    ) -> Resp {
        // A registration's cap, never above the hard maximum (registrations are clamped to 1 and up).
        let asked = if reg.max_body_bytes == 0.0 || reg.max_body_bytes.is_nan() {
            INGRESS_DEFAULT_BODY_BYTES
        } else {
            reg.max_body_bytes
        };
        let cap = asked.clamp(0.0, INGRESS_MAX_BODY_BYTES) as usize;
        let body = match read_body(parts, body, cap).await {
            Ok(b) => b,
            Err(ReadError::TooLarge) => {
                self.count_unverified();
                return self.refuse(ctx, 413, "too_large", "body over the cap", Some(reg), 0, true);
            }
            Err(ReadError::Stopped) => {
                return self.refuse(
                    ctx,
                    400,
                    "refused",
                    "the sender stopped before the body arrived",
                    Some(reg),
                    0,
                    true,
                );
            }
        };
        for rule in &reg.verify {
            if let Err(reason) = self.check(rule, parts, &body).await {
                self.count_unverified();
                if self.b().locked_until > (self.now)() {
                    return self.refuse(
                        ctx,
                        429,
                        "rate_limited",
                        "too many refused deliveries",
                        Some(reg),
                        body.len(),
                        false,
                    );
                }
                return self.refuse(ctx, 401, "refused", &reason, Some(reg), body.len(), false);
            }
        }
        // It verified: whoever sent it holds the secret, so the run of bad attempts is forgotten.
        {
            let mut b = self.b();
            b.unverified.clear();
            b.locked_until = 0;
        }
        if !self.charge_delivered(reg) {
            return self.refuse(
                ctx,
                429,
                "rate_limited",
                "over this webhook's rate",
                Some(reg),
                body.len(),
                false,
            );
        }
        if let Some(a) = &reg.authorize
            && !a(&body)
        {
            return self.refuse(
                ctx,
                403,
                "refused",
                "delivery outside the confirmed policy",
                Some(reg),
                body.len(),
                false,
            );
        }
        if !reg.bounded
            && let Some(screen) = &self.screen
            && let Some((status, reason)) = screen(
                reg.clone(),
                Bytes::from(body.clone()),
                header(parts, "content-type"),
                header(parts, "content-encoding"),
            )
            .await
        {
            return self.refuse(ctx, status, "refused", &reason, Some(reg), body.len(), false);
        }
        self.forward(ctx, reg, parts, body).await
    }

    async fn forward(&self, ctx: &Ctx, reg: &Registration, parts: &http::request::Parts, body: Vec<u8>) -> Resp {
        let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let result: Result<Resp, String> = async {
            let form_rule = reg.verify.iter().find_map(|r| match r {
                VerifyRule::Hmac(h) if h.url_form => Some(h),
                _ => None,
            });
            let query = match form_rule {
                Some(_) => hook_query(target).map_err(|e| e.0.to_string())?,
                None => String::new(),
            };
            let mut headers = match form_rule {
                Some(_) => {
                    let mut m = Map::new();
                    m.insert("content-type".into(), json!("application/x-www-form-urlencoded"));
                    m
                }
                None => forward_headers(parts),
            };
            if let Some(h) = form_rule
                && let (Some(secret), Some(url)) = (&h.resign_secret, &h.public_url)
            {
                let form = decode_form(&body).map_err(|e| e.0.to_string())?;
                headers.insert(
                    h.header.to_lowercase(),
                    json!(url_form_signature(secret, &format!("{url}{query}"), &form)),
                );
            }
            if let Some(prep) = &reg.prepare_delivery {
                headers.extend(prep(&body, &query)?);
            }
            let reply = (self.deliver)(
                reg.clone(),
                Delivery {
                    headers,
                    body_b64: base64::engine::general_purpose::STANDARD.encode(&body),
                    query: query.clone(),
                    bounded: reg.bounded,
                },
            )
            .await?;
            let status = reply
                .status
                .as_f64()
                .filter(|s| s.fract() == 0.0 && (200.0..=599.0).contains(s));
            let Some(status) = status.map(|s| s as u16) else {
                return Err("invalid listener status".to_string());
            };
            let ok = (200..300).contains(&status);
            let mut response = None;
            if reg.bounded && ok {
                if let Some(a) = &reg.authorize
                    && !a(&body)
                {
                    return Ok(self.refuse(
                        ctx,
                        403,
                        "refused",
                        "assignment was revoked",
                        Some(reg),
                        body.len(),
                        false,
                    ));
                }
                let xml = reply.content_type.as_deref().is_some_and(|c| {
                    let c = c.to_lowercase();
                    let base = c.split(';').next().unwrap_or_default();
                    base == "application/xml" || base == "text/xml"
                });
                let b64 = reply.body_b64.as_deref().filter(|b| b.len() <= 87384 && xml);
                let Some(b64) = b64 else {
                    return Err("invalid listener response".into());
                };
                let mut out = base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|_| "invalid listener response".to_string())?;
                if out.len() > 65536 {
                    return Err("listener response too large".into());
                }
                if let Some(rw) = &reg.rewrite_response {
                    out = rw(&String::from_utf8_lossy(&out), &body, &query)?.into_bytes();
                }
                if out.len() > 65536
                    || reg
                        .response_allowed
                        .as_ref()
                        .is_some_and(|f| !f(&String::from_utf8_lossy(&out)))
                {
                    return Err("listener response refused".into());
                }
                response = Some(cc_http::full(
                    http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK),
                    "application/xml",
                    out,
                ));
            }
            let code = if ok {
                204
            } else if status >= 500 {
                503
            } else {
                status
            };
            let verdict = if ok {
                "delivered"
            } else if status >= 500 {
                "agent_unreachable"
            } else {
                "listener_refused"
            };
            let reason = (!ok).then(|| format!("the listener on the agent answered {status}"));
            self.record(
                ctx,
                reg_fields(Some(reg)),
                verdict,
                reason.as_deref(),
                Some(status),
                body.len(),
            );
            Ok(response.unwrap_or_else(|| cc_http::empty(code)))
        }
        .await;
        match result {
            Ok(r) => r,
            Err(e) => {
                let reason = if reg.bounded {
                    "phone listener unavailable or response refused".to_string()
                } else {
                    e
                };
                self.refuse(ctx, 503, "agent_unreachable", &reason, Some(reg), body.len(), false)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn refuse(
        &self,
        ctx: &Ctx,
        status: u16,
        verdict: &str,
        reason: &str,
        reg: Option<&Registration>,
        bytes: usize,
        close: bool,
    ) -> Resp {
        self.record(ctx, reg_fields(reg), verdict, Some(reason), None, bytes);
        empty(status, close)
    }

    fn record(
        &self,
        ctx: &Ctx,
        reg: (String, String, Option<String>),
        verdict: &str,
        reason: Option<&str>,
        forward_status: Option<u16>,
        bytes: usize,
    ) {
        let (hook_id, hook_name, vm) = reg;
        let shown = if !hook_name.is_empty() {
            hook_name.clone()
        } else if !hook_id.is_empty() {
            hook_id.clone()
        } else {
            "(unknown)".into()
        };
        tracing::info!(
            "[ingress] {verdict} {shown}{}",
            reason
                .filter(|r| !r.is_empty())
                .map(|r| format!(": {r}"))
                .unwrap_or_default()
        );
        let Some(path) = &self.log_path else { return };
        let mut rec = Map::new();
        rec.insert("source".into(), json!("webhook"));
        rec.insert("delivery_id".into(), json!(ctx.id));
        rec.insert("ts".into(), json!(ctx.started / 1000));
        rec.insert("hook_id".into(), json!(hook_id));
        rec.insert("hook_name".into(), json!(hook_name));
        rec.insert("verdict".into(), json!(verdict));
        if let Some(r) = reason {
            rec.insert("reason".into(), json!(r));
        }
        if let Some(vm) = vm {
            rec.insert("target_vm_id".into(), json!(vm));
        }
        if let Some(s) = forward_status {
            rec.insert("forward_status".into(), json!(s));
        }
        rec.insert("bytes".into(), json!(bytes));
        rec.insert("duration_ms".into(), json!((self.now)().saturating_sub(ctx.started)));
        rec.insert("arrived".into(), json!("via proxy"));
        // Activity must never be what fails a delivery.
        if let Err(e) = cc_store::append_jsonl(std::path::Path::new(path), &Value::Object(rec), 0o644) {
            tracing::info!("[ingress] could not record that delivery: {e}");
        }
    }

    async fn check(&self, rule: &VerifyRule, parts: &http::request::Parts, body: &[u8]) -> Result<(), String> {
        match rule {
            VerifyRule::Hmac(h) if h.url_form => {
                let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
                let ct = header(parts, "content-type").to_lowercase();
                let form_ct = ct == "application/x-www-form-urlencoded"
                    || ct
                        .strip_prefix("application/x-www-form-urlencoded;")
                        .is_some_and(|rest| rest.trim_start() == "charset=utf-8");
                let Some(public) = h.public_url.as_ref().filter(|_| form_ct) else {
                    return Err("invalid form content type".into());
                };
                if parts.headers.get_all(h.header.to_lowercase().as_str()).iter().count() != 1 {
                    return Err("invalid signature headers".into());
                }
                let checked = (|| {
                    let url = format!("{public}{}", hook_query(target).ok()?);
                    let form = decode_form(body).ok()?;
                    Some(verify_url_form(
                        &h.secret,
                        &url,
                        &form,
                        &header(parts, &h.header.to_lowercase()),
                    ))
                })();
                match checked {
                    Some(true) => Ok(()),
                    Some(false) => Err("the signature did not match".into()),
                    None => Err("invalid signed form".into()),
                }
            }
            VerifyRule::Hmac(h) => {
                let sent = header(parts, &h.header.to_lowercase());
                if sent.is_empty() {
                    return Err(format!("no {} header", h.header));
                }
                let mut signed = body.to_vec();
                if let Some(th) = &h.timestamp_header {
                    let raw = header(parts, &th.to_lowercase());
                    let ts = js_number(Some(&Value::String(raw.clone())));
                    if raw.is_empty() || !ts.is_finite() {
                        return Err(format!("no {th} header"));
                    }
                    let age = ((self.now)() as f64 / 1000.0 - ts).abs();
                    if age > h.max_age_s.unwrap_or(300.0) {
                        return Err("the delivery was too old to accept".into());
                    }
                    let format = h.signed_format.as_deref().unwrap_or("{ts}.{body}");
                    let step = js_replace_first(format, "{ts}", &raw);
                    signed = js_replace_first(&step, "{body}", &String::from_utf8_lossy(body)).into_bytes();
                }
                let mac = if h.sha1 {
                    let mut m = Hmac::<sha1::Sha1>::new_from_slice(h.secret.as_bytes()).expect("any key");
                    m.update(&signed);
                    m.finalize().into_bytes().to_vec()
                } else {
                    let mut m = Hmac::<sha2::Sha256>::new_from_slice(h.secret.as_bytes()).expect("any key");
                    m.update(&signed);
                    m.finalize().into_bytes().to_vec()
                };
                let encoded = if h.base64 {
                    base64::engine::general_purpose::STANDARD.encode(mac)
                } else {
                    hex::encode(mac)
                };
                let want = format!("{}{encoded}", h.prefix.as_deref().unwrap_or(""));
                if cc_crypto::ct_eq(sent.as_bytes(), want.as_bytes()) {
                    Ok(())
                } else {
                    Err("the signature did not match".into())
                }
            }
            VerifyRule::Oidc {
                issuer,
                audience,
                subject_email,
            } => {
                let auth = header(parts, "authorization");
                let Some(token) = auth.strip_prefix("Bearer ") else {
                    return Err("no bearer token".into());
                };
                #[cfg(test)]
                let verified = match &self.test_keys {
                    Some(keys) => super::oidc::verify(token, keys, issuer, audience),
                    None => self.jwks.verify(&self.http, token, issuer, audience).await,
                };
                #[cfg(not(test))]
                let verified = self.jwks.verify(&self.http, token, issuer, audience).await;
                match verified {
                    Ok(claims) => {
                        if let Some(want) = subject_email
                            && claims.get("email").and_then(Value::as_str).unwrap_or("") != want
                        {
                            return Err("the token came from a different service account".into());
                        }
                        Ok(())
                    }
                    Err(super::oidc::JwtError::Audience) => Err("the token was for a different audience".into()),
                    Err(super::oidc::JwtError::Issuer) => Err("the token came from a different issuer".into()),
                    Err(super::oidc::JwtError::Expired) => Err("the token had expired".into()),
                    Err(super::oidc::JwtError::Other(_) | super::oidc::JwtError::NoKey) => {
                        Err("the token did not verify".into())
                    }
                }
            }
        }
    }

    fn count_unverified(&self) {
        let now = (self.now)();
        let mut b = self.b();
        b.unverified.retain(|t| *t + 60_000 > now);
        b.unverified.push(now);
        if b.unverified.len() < INGRESS_UNVERIFIED_PER_MINUTE {
            return;
        }
        b.locked_until = now + INGRESS_UNVERIFIED_LOCKOUT_MS;
        b.unverified.clear();
        tracing::info!(
            "[ingress] {INGRESS_UNVERIFIED_PER_MINUTE} refused deliveries in a minute; refusing unverified callers for {} minutes",
            INGRESS_UNVERIFIED_LOCKOUT_MS / 60_000
        );
    }

    fn charge_delivered(&self, reg: &Registration) -> bool {
        let now = (self.now)();
        let per = (if reg.per_minute == 0.0 || reg.per_minute.is_nan() {
            INGRESS_DEFAULT_PER_MINUTE
        } else {
            reg.per_minute
        })
        .min(INGRESS_MAX_PER_MINUTE);
        let mut b = self.b();
        let mut mine: Vec<u64> = b.delivered.get(&reg.id).cloned().unwrap_or_default();
        mine.retain(|t| *t + 60_000 > now);
        b.org.retain(|t| *t + 60_000 > now);
        if mine.len() as f64 >= per || b.org.len() >= INGRESS_ORG_PER_MINUTE {
            b.delivered.insert(reg.id.clone(), mine);
            return false;
        }
        mine.push(now);
        b.org.push(now);
        b.delivered.insert(reg.id.clone(), mine);
        true
    }

    fn take_slot(&self, vm: &str) -> bool {
        let mut b = self.b();
        let mine = b.in_flight.get(vm).copied().unwrap_or(0);
        if mine >= INGRESS_IN_FLIGHT_PER_VM || b.in_flight_org >= INGRESS_IN_FLIGHT_ORG {
            return false;
        }
        b.in_flight.insert(vm.to_string(), mine + 1);
        b.in_flight_org += 1;
        true
    }

    fn release_slot(&self, vm: &str) {
        let mut b = self.b();
        let mine = b.in_flight.get(vm).copied().unwrap_or(1);
        b.in_flight.insert(vm.to_string(), mine.saturating_sub(1));
        b.in_flight_org = b.in_flight_org.saturating_sub(1);
    }
}

/// `String.replace(pattern, replacement)` with a string pattern: the first match, and the
/// replacement's `$$`, `$&`, `` $` `` and `$'` expanded as JavaScript does.
pub fn js_replace_first(s: &str, pattern: &str, replacement: &str) -> String {
    let Some(at) = s.find(pattern) else {
        return s.to_string();
    };
    let (before, after) = (&s[..at], &s[at + pattern.len()..]);
    let mut out = String::from(before);
    let mut chars = replacement.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('$') => {
                chars.next();
                out.push('$');
            }
            Some('&') => {
                chars.next();
                out.push_str(pattern);
            }
            Some('`') => {
                chars.next();
                out.push_str(before);
            }
            Some('\'') => {
                chars.next();
                out.push_str(after);
            }
            _ => out.push('$'),
        }
    }
    out.push_str(after);
    out
}

fn reg_fields(reg: Option<&Registration>) -> (String, String, Option<String>) {
    match reg {
        Some(r) => (r.id.clone(), r.name.clone(), Some(r.target.vm_id.clone())),
        None => (String::new(), String::new(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const SECRET: &str = "s3cret-value-for-the-test";
    const ISSUER: &str = "https://accounts.example.com";
    const AUDIENCE: &str = "https://mitm.example/hook/hk_test";

    fn sign(body: &str) -> String {
        let mut m = Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).expect("key");
        m.update(body.as_bytes());
        hex::encode(m.finalize().into_bytes())
    }

    fn hmac_rule() -> VerifyRule {
        VerifyRule::Hmac(HmacRule {
            header: "x-cc-signature".into(),
            secret: SECRET.into(),
            ..Default::default()
        })
    }

    fn reg(verify: Vec<VerifyRule>, per_minute: f64) -> Registration {
        Registration::plain(
            "hk_test",
            "Test hook",
            Target {
                vm_id: "vm_agent_1".into(),
                hostname: "agent.example".into(),
                port: 8788.0,
                path: "/x".into(),
            },
            verify,
            4096.0,
            per_minute,
            true,
        )
    }

    struct Rig {
        url: String,
        delivered: Arc<AtomicUsize>,
        now: Arc<AtomicU64>,
        log: std::path::PathBuf,
        _d: tempfile::TempDir,
    }

    async fn rig(regs: Vec<Registration>, keys: Option<Vec<Value>>) -> Rig {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let delivered = Arc::new(AtomicUsize::new(0));
        let n = delivered.clone();
        let now = Arc::new(AtomicU64::new(1_780_000_000_000));
        let t = now.clone();
        let regs = Arc::new(regs);
        let mut ingress = Ingress::new(
            Arc::new(move || regs.as_ref().clone()),
            Arc::new(move |_, _| {
                n.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Ok(Reply {
                        status: json!(200),
                        ..Default::default()
                    })
                })
            }),
            None,
            Some(log.display().to_string()),
        )
        .with_clock(Arc::new(move || t.load(Ordering::SeqCst)));
        ingress.test_keys = keys;
        let ingress = Arc::new(ingress);
        let mut router = cc_http::Router::new(&["hooks"]);
        router.route(
            "hooks",
            |_, p| owns_ingress_path(p),
            move |req, _| {
                let i = ingress.clone();
                async move {
                    let path = req.uri().path().to_string();
                    i.handle(req, &path).await
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        Rig {
            url,
            delivered,
            now,
            log,
            _d: d,
        }
    }

    async fn post(r: &Rig, body: &str, headers: &[(&str, &str)]) -> u16 {
        let mut req = reqwest::Client::new()
            .post(format!("{}/hook/hk_test", r.url))
            .body(body.to_string());
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        req.send().await.expect("send").status().as_u16()
    }

    #[tokio::test]
    async fn signed_deliveries_pass_and_junk_cannot_spend_the_real_budget() {
        let r = rig(vec![reg(vec![hmac_rule()], 60.0)], None).await;
        let body = r#"{"a":1}"#;
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 204);
        assert_eq!(post(&r, body, &[("x-cc-signature", "deadbeef")]).await, 401);
        assert_eq!(post(&r, body, &[]).await, 401);
        // Junk up to the lockout: strangers are now refused 429, the real sender is not.
        for _ in 0..INGRESS_UNVERIFIED_PER_MINUTE {
            post(&r, "{}", &[("x-cc-signature", "deadbeef")]).await;
        }
        assert_eq!(post(&r, "{}", &[("x-cc-signature", "deadbeef")]).await, 429);
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 204);
        assert_eq!(r.delivered.load(Ordering::SeqCst), 2);
        // No body, no header value and no token ever reaches a record.
        let log = std::fs::read_to_string(&r.log).expect("log");
        assert!(!log.contains(SECRET) && !log.contains("deadbeef") && !log.contains("\"a\""));
        let first: Value = serde_json::from_str(log.lines().next().expect("line")).expect("json");
        assert_eq!(first["verdict"], "delivered");
        assert_eq!(first["arrived"], "via proxy");
        assert_eq!(first["forward_status"], 200);
    }

    #[tokio::test]
    async fn the_per_registration_rate_and_the_body_cap() {
        let r = rig(vec![reg(vec![hmac_rule()], 2.0)], None).await;
        let body = "{}";
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 204);
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 204);
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 429);
        r.now.fetch_add(61_000, Ordering::SeqCst);
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 204);
        let big = "x".repeat(5000);
        assert_eq!(post(&r, &big, &[("x-cc-signature", &sign(&big))]).await, 413);
        assert_eq!(r.delivered.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_timestamped_rule_refuses_a_replay() {
        let rule = VerifyRule::Hmac(HmacRule {
            header: "x-cc-signature".into(),
            secret: SECRET.into(),
            timestamp_header: Some("x-cc-timestamp".into()),
            max_age_s: Some(300.0),
            ..Default::default()
        });
        let r = rig(vec![reg(vec![rule], 60.0)], None).await;
        let ts = (r.now.load(Ordering::SeqCst) / 1000).to_string();
        let body = "{}";
        let signed = format!("{ts}.{body}");
        assert_eq!(
            post(&r, body, &[("x-cc-signature", &sign(&signed)), ("x-cc-timestamp", &ts)]).await,
            204
        );
        r.now.fetch_add(301_000, Ordering::SeqCst);
        assert_eq!(
            post(&r, body, &[("x-cc-signature", &sign(&signed)), ("x-cc-timestamp", &ts)]).await,
            401
        );
        assert_eq!(post(&r, body, &[("x-cc-signature", &sign(body))]).await, 401);
    }

    #[tokio::test]
    async fn oidc_audience_service_account_and_and() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("t").as_secs();
        let (good, jwk) = super::super::oidc::tests::sign(
            json!({"iss": ISSUER, "aud": AUDIENCE, "exp": now + 60, "email": "push@x.iam"}),
        );
        let (other_aud, _) = super::super::oidc::tests::sign(
            json!({"iss": ISSUER, "aud": "https://elsewhere", "exp": now + 60, "email": "push@x.iam"}),
        );
        let oidc = VerifyRule::Oidc {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            subject_email: Some("push@x.iam".into()),
        };
        let r = rig(vec![reg(vec![oidc.clone()], 60.0)], Some(vec![jwk.clone()])).await;
        assert_eq!(
            post(&r, "{}", &[("authorization", &format!("Bearer {good}"))]).await,
            204
        );
        assert_eq!(
            post(&r, "{}", &[("authorization", &format!("Bearer {other_aud}"))]).await,
            401
        );
        assert_eq!(post(&r, "{}", &[]).await, 401);
        let log = std::fs::read_to_string(&r.log).expect("log");
        assert!(log.contains("the token was for a different audience"));
        assert!(log.contains("no bearer token"));
        // Both checks must pass.
        let r = rig(vec![reg(vec![oidc, hmac_rule()], 60.0)], Some(vec![jwk])).await;
        assert_eq!(
            post(&r, "{}", &[("authorization", &format!("Bearer {good}"))]).await,
            401
        );
        assert_eq!(
            post(
                &r,
                "{}",
                &[
                    ("authorization", &format!("Bearer {good}")),
                    ("x-cc-signature", &sign("{}"))
                ]
            )
            .await,
            204
        );
    }

    #[test]
    fn replacements_expand_as_in_javascript() {
        assert_eq!(
            js_replace_first("{ts}.{body}", "{body}", "a$&b$$c$'d$`e$x"),
            "{ts}.a{body}b$cd{ts}.e$x"
        );
        assert_eq!(js_replace_first("x", "{ts}", "1"), "x");
    }

    #[test]
    fn registrations_are_parsed_and_clamped() {
        let regs = parse_registrations(&json!([
            {"id": "a", "target": {"vmId": "v", "hostname": "h", "port": 8788}, "verify": [], "maxBodyBytes": -5, "perMinute": 999999},
            {"id": "b", "target": {"vmId": "v", "hostname": "h", "port": 3100}},
            {"id": "c", "target": {"vmId": "v", "hostname": "h", "port": 9222}},
        ]));
        assert_eq!(regs.len(), 1);
        assert_eq!(
            (regs[0].max_body_bytes, regs[0].per_minute),
            (1.0, INGRESS_MAX_PER_MINUTE)
        );
        assert_eq!(regs[0].target.path, "/");
        assert!(!target_port_allowed(3100.0) && !target_port_allowed(8800.0) && target_port_allowed(8700.0));
    }

    /// An ingress with one registration, a delivery that answers `reply`, and `screen`.
    async fn hook_rig(
        reg: Registration,
        reply: Reply,
        screen: Option<Screen>,
    ) -> (String, Arc<AtomicUsize>, std::path::PathBuf, tempfile::TempDir) {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let delivered = Arc::new(AtomicUsize::new(0));
        let n = delivered.clone();
        let regs = Arc::new(vec![reg]);
        let ingress = Arc::new(Ingress::new(
            Arc::new(move || regs.as_ref().clone()),
            Arc::new(move |_, _| {
                n.fetch_add(1, Ordering::SeqCst);
                let r = reply.clone();
                Box::pin(async move { Ok(r) })
            }),
            screen,
            Some(log.display().to_string()),
        ));
        let mut router = cc_http::Router::new(&["hooks"]);
        router.route(
            "hooks",
            |_, p| owns_ingress_path(p),
            move |req, _| {
                let i = ingress.clone();
                async move {
                    let path = req.uri().path().to_string();
                    i.handle(req, &path).await
                }
            },
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}/hook/hk_test", listener.local_addr().expect("addr"));
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        (url, delivered, log, d)
    }

    fn xml_reply(xml: &str) -> Reply {
        Reply {
            status: json!(200),
            content_type: Some("application/xml".into()),
            body_b64: Some(base64::engine::general_purpose::STANDARD.encode(xml)),
        }
    }

    #[tokio::test]
    async fn a_hook_that_cannot_prepare_or_rewrite_a_delivery_answers_503_and_forwards_nothing() {
        let token = "tok-SECRET-in-the-error";
        let mut bounded = reg(vec![hmac_rule()], 60.0);
        bounded.bounded = true;
        let mut prep = bounded.clone();
        prep.prepare_delivery = Some(Arc::new(move |_: &[u8], _: &str| Err(format!("refused {token}"))));
        let (url, delivered, log, _d) = hook_rig(prep, xml_reply("<Response/>"), None).await;
        let res = reqwest::Client::new()
            .post(&url)
            .header("x-cc-signature", sign("a=1"))
            .body("a=1")
            .send()
            .await
            .expect("send");
        assert_eq!(res.status().as_u16(), 503);
        assert_eq!(delivered.load(Ordering::SeqCst), 0, "refused before delivery");
        let line = std::fs::read_to_string(&log).expect("log");
        assert!(line.contains("phone listener unavailable or response refused"));
        assert!(!line.contains(token));

        let mut rw = bounded;
        rw.rewrite_response = Some(Arc::new(move |_: &str, _: &[u8], _: &str| Err(format!("bad {token}"))));
        let agent_answer = "<Response><Say>from the agent</Say></Response>";
        let (url, _, log, _d) = hook_rig(rw, xml_reply(agent_answer), None).await;
        let res = reqwest::Client::new()
            .post(&url)
            .header("x-cc-signature", sign("a=1"))
            .body("a=1")
            .send()
            .await
            .expect("send");
        assert_eq!(res.status().as_u16(), 503);
        assert!(
            !res.text().await.expect("body").contains("from the agent"),
            "the agent's answer never goes out"
        );
        assert!(!std::fs::read_to_string(&log).expect("log").contains(token));
    }

    #[tokio::test]
    async fn the_screen_gets_the_content_encoding_and_its_refusal_is_never_forwarded() {
        let seen: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
        let s = seen.clone();
        let screen: Screen = Arc::new(move |_, _, ct, ce| {
            s.lock().expect("lock").push((ct, ce.clone()));
            Box::pin(async move { (ce == "zstd").then(|| (200, "content check failed".to_string())) })
        });
        let (url, delivered, _, _d) = hook_rig(
            reg(vec![hmac_rule()], 60.0),
            Reply {
                status: json!(200),
                ..Default::default()
            },
            Some(screen),
        )
        .await;
        let send = |enc: &'static str| {
            let url = url.clone();
            async move {
                reqwest::Client::new()
                    .post(&url)
                    .header("content-type", "application/json")
                    .header("content-encoding", enc)
                    .header("x-cc-signature", sign("x"))
                    .body("x")
                    .send()
                    .await
                    .expect("send")
                    .status()
                    .as_u16()
            }
        };
        assert_eq!(send("zstd").await, 200);
        assert_eq!(
            delivered.load(Ordering::SeqCst),
            0,
            "a refused delivery is not forwarded"
        );
        assert_eq!(send("gzip").await, 204);
        assert_eq!(delivered.load(Ordering::SeqCst), 1);
        assert_eq!(
            *seen.lock().expect("lock"),
            vec![
                ("application/json".to_string(), "zstd".to_string()),
                ("application/json".to_string(), "gzip".to_string())
            ]
        );
    }
}
