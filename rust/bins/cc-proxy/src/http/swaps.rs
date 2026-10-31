//! Credentials and model answers (appendix F features 4, 5, 14, 15): the placeholder swap the
//! agent's requests get on their way out (legacy `match_domain` + `locations`, and custom secrets
//! with `secret_name`), the included AI's model check and the rewording of its 402, and the
//! classification of a model provider's refusal on the record.
//!
//! Every match uses the flow's checked destination, never the Host header (plan §3: the addon's swap
//! on the Host header is not ported). Website logins, the voice key and the Twilio Basic swap are
//! W2's (`checks/`); their entries are left alone here.

use std::sync::Arc;

use bytes::Bytes;
use cc_contracts::{Maybe, MissingPolicy, MtimeCache, OnError};
use http::StatusCode;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde_json::{Value, json};

use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};
use crate::http::answer::py_json;
use crate::http::body;
use crate::http::policy::{req, truthy};
use crate::log::record::{self, PathBeforeSwap, meta_str};
use crate::net::Ctx;
use crate::net::hosts::host_matches;

/// addon.py `DEFAULT_LOCATIONS`.
const DEFAULT_LOCATIONS: &[&str] = &["header:authorization", "header:x-api-key", "header:private-token"];

pub const INCLUDED_BLOCK_STATUS: u16 = 400;
const INCLUDED_HINT: &str =
    "Pick one of your plan's models, or add your own provider key in ControlClaw under Model providers.";
const INCLUDED_EXHAUSTED: &str = "Your plan's included AI tokens are used up for this month. They reset on the 1st; until then, add your own provider key in ControlClaw under Model providers.";
const INCLUDED_NO_CREDIT: &str = "Included AI is paused: the AI provider refused this call over billing on ControlClaw's side, not yours. ControlClaw has been told. Your own provider keys still work; see Model providers in ControlClaw for where this stands.";
/// Provider wording that means "no money left", whatever the status.
const CREDIT_MARKERS: &[&str] = &[
    "insufficient_quota",
    "billing_hard_limit",
    "billing_not_active",
    "credit balance",
    "insufficient credits",
    "insufficient_credits",
    "exceeded your current quota",
    "payment required",
    "out of credits",
];
const MODEL_ERROR_READ_MAX: usize = 4096;

/// `credentials.json`, re-read when its mtime changes (`_Cache`), each entry as written: an entry
/// with an odd field costs only itself (it gets no swap), never the whole file.
pub struct Credentials {
    file: MtimeCache<Vec<Value>>,
}

impl Credentials {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            file: MtimeCache::new(path, MissingPolicy::Keep, OnError::KeepLast),
        }
    }

    /// addon.py `credentials_for`: the entries for this host and agent, one per placeholder, an
    /// agent's own entry beating an org-wide one. Custom secrets and logins are the agent's own
    /// only, on their `allowed_hosts`.
    ///
    /// The flow's one read of the file: the first step that asks reads it (deciding whether it
    /// reads the body, or running), the later ones (the included-AI check, the swaps, the
    /// model-error check) see the same entries.
    pub fn for_flow(&self, flow: &mut Flow, host: &str) -> Vec<Value> {
        let all = match flow.extensions.get::<Snapshot>() {
            Some(Snapshot(all)) => all.clone(),
            None => {
                let all = self.file.get();
                flow.extensions.insert(Snapshot(all.clone()));
                all
            }
        };
        entries_for(&all, host, flow.vm_id.as_deref())
    }
}

/// Drop the flow's credentials snapshot: the next step reads the file afresh (once the body is
/// held).
pub fn forget_credentials(flow: &mut Flow) {
    flow.extensions.remove::<Snapshot>();
}

/// `credentials.json` as one flow read it.
#[derive(Clone)]
struct Snapshot(Arc<Vec<Value>>);

/// addon.py `credentials_for` over one read of the file.
fn entries_for(all: &[Value], host: &str, vm_id: Option<&str>) -> Vec<Value> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for c in all {
        let Some(obj) = c.as_object() else { continue };
        let s = |k: &str| obj.get(k).and_then(Value::as_str);
        let cv = obj.get("vm_id").filter(|v| !v.is_null());
        if truthy(obj.get("secret_name")) || truthy(obj.get("login_id")) {
            if cv.and_then(Value::as_str).is_none_or(|v| Some(v) != vm_id) {
                continue;
            }
            let hosts = obj.get("allowed_hosts").and_then(Value::as_array);
            if !hosts.is_some_and(|hs| {
                hs.iter()
                    .filter_map(Value::as_str)
                    .any(|p| secret_host_matches(p, host))
            }) {
                continue;
            }
        } else if !host_matches(s("match_domain").unwrap_or(""), host) {
            continue;
        }
        // `cv is not None and cv != vm_id`: a vm_id that is not text is never this agent's.
        if let Some(cv) = cv
            && (cv.as_str().is_none() || cv.as_str() != vm_id)
        {
            continue;
        }
        let ph = s("placeholder").unwrap_or("").to_owned();
        match out.iter_mut().find(|(p, _)| *p == ph) {
            None => out.push((ph, c.clone())),
            // An agent's own entry beats an org-wide one for the same placeholder.
            Some((_, existing)) if existing.get("vm_id").is_none_or(Value::is_null) && cv.is_some() => {
                *existing = c.clone();
            }
            Some(_) => {}
        }
    }
    out.into_iter().map(|(_, c)| c).collect()
}

/// addon.py `secret_host_matches`: exact, or `*.example.com` for names under it (not the apex).
pub fn secret_host_matches(pattern: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    let pattern = pattern.to_ascii_lowercase();
    if let Some(base) = pattern.strip_prefix("*.") {
        return host.ends_with(&pattern[1..]) && host != base;
    }
    !pattern.contains('*') && host == pattern
}

fn str_of<'a>(c: &'a Value, k: &str) -> Option<&'a str> {
    c.get(k).and_then(Value::as_str).filter(|v| !v.is_empty())
}

// ---- percent-encoding, for query values ----

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = |c: u8| (c as char).to_digit(16);
                match (hex(b[i + 1]), hex(b[i + 2])) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 2;
                    }
                    _ => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `quote_plus`: what `urlencode` writes for a value.
fn quote_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Rewrite the query's values with `f` (given the decoded value; `Some` replaces it). Only the
/// pairs `f` changes are written again; the rest stay byte for byte.
fn rewrite_query(query: &str, mut f: impl FnMut(&str, &str) -> Option<String>) -> Option<String> {
    let mut changed = false;
    let parts: Vec<String> = query
        .split('&')
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match f(&percent_decode(k), &percent_decode(v)) {
                Some(new) if pair.contains('=') || !new.is_empty() => {
                    changed = true;
                    format!("{k}={}", quote_plus(&new))
                }
                _ => pair.to_owned(),
            }
        })
        .collect();
    changed.then(|| parts.join("&"))
}

fn set_path_and_query(req: &mut http::Request<Bytes>, pq: &str) -> bool {
    let mut parts = req.uri().clone().into_parts();
    let Ok(p) = pq.parse() else { return false };
    parts.path_and_query = Some(p);
    match http::Uri::from_parts(parts) {
        Ok(u) => {
            *req.uri_mut() = u;
            true
        }
        Err(_) => false,
    }
}

/// `cred.get("locations") or DEFAULT_LOCATIONS`.
fn locations(cred: &Value) -> Vec<String> {
    match cred.get("locations").and_then(Value::as_array) {
        Some(l) if !l.is_empty() => l.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => DEFAULT_LOCATIONS.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn path_and_query(req: &http::Request<Bytes>) -> String {
    req.uri()
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_default()
}

/// `haystack` with every `needle` replaced, as bytes (non-UTF-8 bytes stay as they are).
fn replace_bytes(haystack: &[u8], needle: &[u8], with: &[u8]) -> Option<Vec<u8>> {
    if needle.is_empty() || !haystack.windows(needle.len()).any(|w| w == needle) {
        return None;
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(with);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Whether the request goes to the site over TLS: intercepted TLS, or an absolute-form `https://`
/// request, which the proxy sends on over TLS.
fn over_tls(flow: &Flow) -> bool {
    flow.meta.get("tls") == Some(&Value::Bool(true))
        || (flow.meta.get("absolute_form") == Some(&Value::Bool(true))
            && flow.request.as_ref().and_then(|r| r.uri().scheme_str()) == Some("https"))
}

/// What one request's swaps did, for the record and the later checks.
#[derive(Default)]
struct Applied {
    placeholders: Vec<String>,
    secret_names: Vec<String>,
}

/// addon.py `apply_swaps`, for the legacy entries and the custom secrets.
fn apply_swaps(creds: &[Value], flow: &mut Flow, host: &str) -> Applied {
    let mut applied = Applied::default();
    // A real key never goes out in clear: no swap at all unless the request reaches the site over
    // TLS (production's T-sni rule).
    if !over_tls(flow) {
        return applied;
    }
    // Over TLS whose name is the destination: the request then names its own host. Never behind
    // redsocks to an address the agent chose without a TLS name (the addon requires an SNI there).
    let named = flow.sni.as_deref() == Some(host);
    let Some(req) = flow.request.as_mut() else {
        return applied;
    };
    // The request body with its encoding undone, read at most once.
    let mut decoded: Option<Option<Bytes>> = None;
    for cred in creds {
        // W2's: the voice key (after its own admission), website logins, the Twilio Basic swap.
        if truthy(cred.get("speech")) || truthy(cred.get("login_id")) {
            continue;
        }
        let (Some(placeholder), Some(secret)) = (str_of(cred, "placeholder"), str_of(cred, "secret")) else {
            continue;
        };
        if let Some(name) = str_of(cred, "secret_name") {
            // Only over TLS whose name is the destination: the agent's own address is never where
            // a secret goes (behind redsocks the addon requires https and an SNI too).
            if !named {
                continue;
            }
            let mut hit = false;
            for loc in cred
                .get("secret_locations")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let lname = loc.get("name").and_then(Value::as_str).unwrap_or("");
                match loc.get("kind").and_then(Value::as_str) {
                    Some("header") => {
                        let prefix = loc.get("prefix").and_then(Value::as_str).unwrap_or("");
                        let Ok(hname) = HeaderName::from_bytes(lname.as_bytes()) else {
                            continue;
                        };
                        let want = format!("{prefix}{placeholder}");
                        let values: Vec<HeaderValue> = req.headers().get_all(&hname).iter().cloned().collect();
                        // The whole field, prefix included: never a substring.
                        let changed: Vec<HeaderValue> = values
                            .iter()
                            .map(|v| {
                                if v.as_bytes() == want.as_bytes() {
                                    HeaderValue::from_str(&format!("{prefix}{secret}")).unwrap_or_else(|_| v.clone())
                                } else {
                                    v.clone()
                                }
                            })
                            .collect();
                        if changed != values {
                            req.headers_mut().remove(&hname);
                            for v in changed {
                                req.headers_mut().append(hname.clone(), v);
                            }
                            hit = true;
                        }
                    }
                    Some("query") => {
                        let pq = path_and_query(req);
                        if let Some((path, query)) = pq.split_once('?')
                            && let Some(q) = rewrite_query(query, |k, v| {
                                (k == lname && v == placeholder).then(|| secret.to_owned())
                            })
                            && set_path_and_query(req, &format!("{path}?{q}"))
                        {
                            hit = true;
                        }
                    }
                    _ => {}
                }
            }
            if hit {
                applied.placeholders.push(placeholder.to_owned());
                applied.secret_names.push(name.to_owned());
                tracing::info!("[mitm] secret={name} host={host} verdict=swapped");
            }
            continue;
        }
        let locations = locations(cred);
        let mut hit = false;
        for loc in &locations {
            if loc == "basic:authorization" {
                // The Twilio account's Basic credential: W2's phone check swaps it.
                continue;
            }
            if let Some(name) = loc.strip_prefix("header:") {
                let Ok(hname) = HeaderName::from_bytes(name.as_bytes()) else {
                    continue;
                };
                let values: Vec<HeaderValue> = req.headers().get_all(&hname).iter().cloned().collect();
                let mut any = false;
                let changed: Vec<HeaderValue> = values
                    .iter()
                    .map(|v| match v.to_str() {
                        Ok(t) if t.contains(placeholder) => {
                            any = true;
                            HeaderValue::from_str(&t.replace(placeholder, secret)).unwrap_or_else(|_| v.clone())
                        }
                        _ => v.clone(),
                    })
                    .collect();
                if any {
                    req.headers_mut().remove(&hname);
                    for v in changed {
                        req.headers_mut().append(hname.clone(), v);
                    }
                    hit = true;
                }
            } else if loc == "query" {
                let pq = path_and_query(req);
                if let Some((path, query)) = pq.split_once('?')
                    && let Some(q) = rewrite_query(query, |_, v| {
                        v.contains(placeholder).then(|| v.replace(placeholder, secret))
                    })
                    && set_path_and_query(req, &format!("{path}?{q}"))
                {
                    hit = true;
                }
            } else if loc == "path" {
                // Some APIs carry the token in the URL itself (Telegram: /bot<token>/method).
                let pq = path_and_query(req);
                if pq.contains(placeholder) && set_path_and_query(req, &pq.replace(placeholder, secret)) {
                    hit = true;
                }
            } else if loc == "body" {
                // Decoded once per request, then compared and replaced as bytes.
                if decoded.is_none() {
                    decoded = Some(body::decoded(req.headers(), req.body()));
                }
                if let Some(Some(b)) = &decoded
                    && let Some(out) = replace_bytes(b, placeholder.as_bytes(), secret.as_bytes())
                {
                    let mut headers = req.headers().clone();
                    let mut new_body = req.body().clone();
                    body::set_bytes(&mut headers, &mut new_body, out);
                    *req.headers_mut() = headers;
                    *req.body_mut() = new_body.clone();
                    decoded = Some(Some(new_body));
                    hit = true;
                }
            }
        }
        if hit {
            applied.placeholders.push(placeholder.to_owned());
        }
    }
    applied
}

pub struct Swaps {
    ctx: Arc<Ctx>,
    creds: Arc<Credentials>,
}

impl Step for Swaps {
    fn name(&self) -> &'static str {
        "swaps"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// The request's body only for a credential of this host that is swapped into a body.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        let host = req(flow).host;
        self.creds.for_flow(flow, &host).iter().any(|c| {
            locations(c).iter().any(|l| l == "body")
                || c.get("secret_locations")
                    .and_then(Value::as_array)
                    .is_some_and(|l| l.iter().any(|x| x.get("kind").and_then(Value::as_str) == Some("body")))
        })
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let host = req(flow).host;
            let creds = self.creds.for_flow(flow, &host);
            if flow.extensions.get::<PathBeforeSwap>().is_none()
                && let Some(r) = flow.request.as_ref()
            {
                let pq = r.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned();
                flow.extensions.insert(PathBeforeSwap(pq));
            }
            let applied = apply_swaps(&creds, flow, &host);
            if !applied.placeholders.is_empty() {
                tracing::info!(
                    "[mitm] credential swap for host={host} (tenant={})",
                    self.ctx.config.tenant
                );
            }
            let list = |m: Option<&Value>, add: Vec<String>| {
                let mut v: Vec<Value> = m.and_then(Value::as_array).cloned().unwrap_or_default();
                v.extend(add.into_iter().map(Value::String));
                Value::Array(v)
            };
            let a = list(flow.meta.get("applied"), applied.placeholders);
            flow.meta.insert("applied", a);
            if !applied.secret_names.is_empty() {
                let s = list(flow.meta.get("secret_swaps"), applied.secret_names);
                flow.meta.insert("secret_swaps", s);
            }
            Verdict::Continue
        })
    }
}

/// A credential's placeholder is in a header it may be swapped into (addon `_placeholder_in_request`).
fn placeholder_in_request(flow: &Flow, cred: &Value) -> bool {
    let (Some(ph), Some(req)) = (str_of(cred, "placeholder"), flow.request.as_ref()) else {
        return false;
    };
    locations(cred)
        .iter()
        .filter_map(|l| l.strip_prefix("header:"))
        .any(|name| {
            req.headers()
                .iter()
                .any(|(k, v)| k.as_str().eq_ignore_ascii_case(name) && v.to_str().is_ok_and(|t| t.contains(ph)))
        })
}

/// addon.py `included_model_check`: why a request on the included key is refused, or `None`.
pub fn included_model_check(method: &str, path: &str, body: &[u8], allowed: &[String]) -> Option<String> {
    let bare = path.split_once('?').map_or(path, |(p, _)| p);
    if method.eq_ignore_ascii_case("GET") {
        return if models_path(bare) {
            None
        } else {
            Some("only generation requests are included".into())
        };
    }
    if !method.eq_ignore_ascii_case("POST") {
        return Some("only generation requests are included".into());
    }
    let parsed: Option<Value> = if body.is_empty() {
        Some(json!({}))
    } else {
        serde_json::from_slice(body).ok()
    };
    let model = parsed.as_ref().and_then(|v| v.get("model")).and_then(Value::as_str);
    match model {
        None | Some("") => Some("the request names no model".into()),
        Some(m) if !allowed.iter().any(|a| a == m) => Some(format!("{m} is not included in your plan")),
        Some(_) => None,
    }
}

/// `^/v1/models(/[^/]+)*/?$` with plain segments: no `.` or `..`, no encoded dot or slash, no
/// empty segment, so a site that cleans paths cannot read it as another endpoint.
fn models_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || path.contains('\\') {
        return false;
    }
    let Some(rest) = path.strip_prefix("/v1/models") else {
        return false;
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    rest.is_empty()
        || rest
            .strip_prefix('/')
            .is_some_and(|r| r.split('/').all(|seg| !seg.is_empty() && seg != "." && seg != ".."))
}

/// OpenAI-shaped, which is what OpenClaw's transport reads (addon `_error_body`).
fn error_body(message: &str, code: &str) -> String {
    py_json(&json!({"error": {"message": message, "type": "invalid_request_error", "code": code}}))
}

pub struct IncludedAi {
    ctx: Arc<Ctx>,
    creds: Arc<Credentials>,
}

impl Step for IncludedAi {
    fn name(&self) -> &'static str {
        "included_ai"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// A POST's body on a host with the included key: the model it names is checked.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        let r = req(flow);
        r.method.eq_ignore_ascii_case("POST")
            && self
                .creds
                .for_flow(flow, &r.host)
                .iter()
                .any(|c| truthy(c.get("allowed_models")))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let r = req(flow);
            for cred in self.creds.for_flow(flow, &r.host) {
                // `if not allowed`: any non-empty value restricts the key; only its text entries
                // name models that may be called.
                if !truthy(cred.get("allowed_models")) || !placeholder_in_request(flow, &cred) {
                    continue;
                }
                let allowed: Vec<String> = cred
                    .get("allowed_models")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default();
                flow.meta.insert("included", Value::Bool(true));
                let body = flow.request.as_ref().map(|q| q.body().clone()).unwrap_or_default();
                if let Some(reason) = included_model_check(&r.method, &r.path, &body, &allowed) {
                    let text = format!("{reason}. Included models: {}. {INCLUDED_HINT}", allowed.join(", "));
                    flow.meta.insert("effect", "block".into());
                    flow.meta.insert("rule", "included_ai".into());
                    let mut rec = record::http_record(&self.ctx, flow, "block");
                    rec.status = Maybe::Value(u64::from(INCLUDED_BLOCK_STATUS).into());
                    record::log_once(&self.ctx, flow, &rec);
                    let mut resp = http::Response::new(Bytes::from(error_body(&text, "model_not_included")));
                    *resp.status_mut() = StatusCode::BAD_REQUEST;
                    resp.headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    return Verdict::Answer(Box::new(resp));
                }
            }
            Verdict::Continue
        })
    }
}

/// The answer's side, before the allow record: the included key's 402 reworded and classified
/// (`included`), a model provider's refusal classified (`model_error`). Only for a flow the rules
/// let through (`effect` none or allow), as in the addon's `response`.
pub struct ModelAnswers;

impl Step for ModelAnswers {
    fn name(&self) -> &'static str {
        "model_answers"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// An error answer to a request on the included key or with a swapped credential: it is
    /// reworded or classified from its text.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        let status = flow.response.as_ref().map_or(0, |r| r.status().as_u16());
        let swapped = flow
            .meta
            .get("applied")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
        status >= 400 && (flow.meta.get("included") == Some(&Value::Bool(true)) || swapped)
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !matches!(meta_str(flow, "effect"), None | Some("allow")) {
                return Verdict::Continue;
            }
            let included = flow.meta.get("included") == Some(&Value::Bool(true));
            let Some(resp) = flow.response.as_mut() else {
                return Verdict::Continue;
            };
            let status = resp.status().as_u16();
            // addon.py `reword_402`.
            let mut kind: Option<&str> = None;
            if included && status == 402 {
                let t = body::text(resp.headers(), resp.body()).unwrap_or_default();
                let typ = serde_json::from_str::<Value>(&t).ok().and_then(|v| {
                    v.get("error")
                        .and_then(|e| e.get("type"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                });
                let (k, msg, code) = if typ.as_deref() == Some("quota_for_entity_exceeded") {
                    ("used_up", INCLUDED_EXHAUSTED, "included_tokens_used_up")
                } else {
                    ("no_credit", INCLUDED_NO_CREDIT, "included_ai_no_credit")
                };
                let (mut parts, mut b) = (resp.headers().clone(), resp.body().clone());
                body::set_text(&mut parts, &mut b, error_body(msg, code));
                parts.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                *resp.headers_mut() = parts;
                *resp.body_mut() = b;
                kind = Some(k);
            }
            if kind.is_none() && included && status < 400 {
                kind = Some("ok");
            }
            // On the record only with a kind (`{"included": kind} if kind else {}`).
            match kind {
                Some(k) => flow.meta.insert("included", Value::String(k.into())),
                None => flow.meta.remove("included"),
            };
            if let Some(e) = self.model_error(flow, included) {
                flow.meta.insert("model_error", e.into());
            }
            Verdict::Continue
        })
    }
}

impl ModelAnswers {
    /// addon.py `classify_model_error`: `auth`, `credit` or `rate_limit` for a POST that carried a
    /// model credential the firewall swapped in and got a 4xx; never for the included key.
    fn model_error(&self, flow: &Flow, included: bool) -> Option<&'static str> {
        let resp = flow.response.as_ref()?;
        let status = resp.status().as_u16();
        if included || !(400..500).contains(&status) {
            return None;
        }
        let r = req(flow);
        if !r.method.eq_ignore_ascii_case("POST") {
            return None;
        }
        let applied: Vec<&str> = flow
            .meta
            .get("applied")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        // The entries the swap used (the flow's snapshot), not a newer read.
        let all = flow.extensions.get::<Snapshot>().map(|Snapshot(a)| a.clone());
        let swapped_model = all
            .map(|a| entries_for(&a, &r.host, flow.vm_id.as_deref()))
            .unwrap_or_default()
            .iter()
            .any(|c| truthy(c.get("model")) && str_of(c, "placeholder").is_some_and(|p| applied.contains(&p)));
        if !swapped_model {
            return None;
        }
        let text: String = body::text(resp.headers(), resp.body())
            .unwrap_or_default()
            .chars()
            .take(MODEL_ERROR_READ_MAX)
            .collect::<String>()
            .to_lowercase();
        if status == 402 || CREDIT_MARKERS.iter().any(|m| text.contains(m)) {
            return Some("credit");
        }
        if status == 401
            || (status == 403
                && ["authentication", "permission", "api key", "api_key"]
                    .iter()
                    .any(|m| text.contains(m)))
        {
            return Some("auth");
        }
        (status == 429).then_some("rate_limit")
    }
}

/// Add the swap, the included-AI check and the model-answer step in their slots.
pub fn register(pipeline: &mut Pipeline, ctx: &Arc<Ctx>) {
    let creds = Arc::new(Credentials::new(&ctx.config.credentials_path));
    pipeline.push(
        order::INCLUDED_AI,
        Arc::new(IncludedAi {
            ctx: ctx.clone(),
            creds: creds.clone(),
        }),
    );
    pipeline.push(
        order::SWAPS,
        Arc::new(Swaps {
            ctx: ctx.clone(),
            creds: creds.clone(),
        }),
    );
    pipeline.push(order::MODEL_ANSWERS, Arc::new(ModelAnswers));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hosts_and_the_model_check() {
        assert!(secret_host_matches("api.example.com", "API.example.com."));
        assert!(secret_host_matches("*.allowed.example.com", "x.allowed.example.com"));
        assert!(!secret_host_matches("*.allowed.example.com", "allowed.example.com"));
        assert!(!secret_host_matches("api.*.com", "api.x.com"));
        let allowed = vec!["anthropic/claude".to_owned()];
        assert_eq!(included_model_check("GET", "/v1/models", b"", &allowed), None);
        assert_eq!(included_model_check("GET", "/v1/models/x?y", b"", &allowed), None);
        // Only the models endpoint, in plain segments.
        for p in [
            "/v1/models/../chat/completions",
            "/v1/models/%2e%2e/chat",
            "/v1/models//x",
            "/v1/models/./x",
            "/v1/models/a%2Fb",
            "/v1/chat/completions/models/x",
            "/x/v1/models",
            "/v1/modelsx",
        ] {
            assert!(included_model_check("GET", p, b"", &allowed).is_some(), "{p}");
        }
        assert_eq!(included_model_check("GET", "/v1/models/", b"", &allowed), None);
        assert!(included_model_check("GET", "/v1/credits", b"", &allowed).is_some());
        assert!(included_model_check("DELETE", "/v1/models", b"", &allowed).is_some());
        assert_eq!(
            included_model_check("POST", "/v1/chat", br#"{"model":"anthropic/claude"}"#, &allowed),
            None
        );
        assert_eq!(
            included_model_check("POST", "/v1/chat", br#"{"model":"openai/gpt"}"#, &allowed).as_deref(),
            Some("openai/gpt is not included in your plan")
        );
        assert_eq!(
            included_model_check("POST", "/v1/chat", b"not json", &allowed).as_deref(),
            Some("the request names no model")
        );
    }

    #[test]
    fn body_swaps_keep_the_other_bytes() {
        let body = b"\xff\xfe__T\x00end";
        assert_eq!(
            replace_bytes(body, b"__T", b"secret").as_deref(),
            Some(&b"\xff\xfesecret\x00end"[..])
        );
        assert_eq!(replace_bytes(body, b"__X", b"s"), None);
    }

    #[test]
    fn query_values_are_rewritten_one_by_one() {
        let q = rewrite_query("a=1&key=__T&b=x%20y", |k, v| {
            (k == "key" && v == "__T").then(|| "s e/c".into())
        });
        assert_eq!(q.as_deref(), Some("a=1&key=s+e%2Fc&b=x%20y"));
        assert_eq!(rewrite_query("a=1", |_, _| None), None);
        assert_eq!(percent_decode("a%2Fb+c%zz"), "a/b c%zz");
    }
}
