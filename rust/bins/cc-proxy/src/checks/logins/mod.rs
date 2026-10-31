//! Website logins (appendix F feature 6, addon.py 1800-3050, docs/plans/website-credentials.md).
//!
//! The agent holds a stand-in for each login's password. The proxy puts the password in only
//! where a sign-in sends it ([`scope`]), only for the login's agent and sites, escaped for where
//! the page put the stand-in. Anywhere else the stand-in is an alarm: the request is refused and
//! recorded (the tripwire, and "not on the sign-in page"). When the agent loads a sign-in page,
//! its sign-in form says where the password goes; that address is written down for the owner to
//! approve (`login-targets.json`). A site that echoes the password back has it taken out again.
//!
//! The host a login is matched on is the flow's checked destination, never the `Host` header.

pub mod find;
pub mod forms;
pub mod scope;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use serde_json::{Map, Value, json};

use self::find::{Finder, LOGIN_SHORT};
use self::scope::{
    NAVIGATION_HEADERS, Places, basic_credentials, header_names, header_values, login_host, str_of, target,
};
use super::creds::{Creds, ascii_host, truthy};
use super::record::{host_matches, redact_path, secret_host_matches};
use super::{body, check_host};
use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};

pub const LOGIN_TRIPWIRE_RULE: &str = "login_tripwire";
const BLOCK_STATUS: u16 = 403;
/// Responses larger than this are not searched for an echoed password.
const LOGIN_REDACT_MAX: usize = 2 * 1024 * 1024;
/// The addon measured `raw_content`, the bytes as sent (compressed or not); the checks see the body
/// decoded, so the decoded limit is higher: a 2 MiB compressed page is searched as the addon
/// searched it, never passed unsearched for being larger once decoded.
const LOGIN_REDACT_DECODED_MAX: usize = 16 * LOGIN_REDACT_MAX;
/// After a swap, responses from the login's sites to that agent are searched this long.
const LOGIN_ECHO_WINDOW_S: f64 = 600.0;
const LOGIN_ECHO_MAX: usize = 16;
const LOGIN_ECHO_AGENTS_MAX: usize = 256;
const TEXT_TYPES: &[&str] = &["text/", "json", "xml", "javascript", "x-www-form-urlencoded"];

pub const META_SWAPS: &str = "cc_login_swaps";
pub const META_PAIRS: &str = "cc_login_pairs";
pub const META_IN: &str = "cc_login_in";
pub const META_SCOPE: &str = "cc_login_scope";

/// `_LOGIN_BLOCK_TEXT`: what the agent is told, by the reason the request was refused.
pub fn block_text(why: &str) -> &'static str {
    match why {
        "http" => {
            "This request is plain http. The firewall never puts a password into a connection that is not encrypted, so it blocked the request and recorded the attempt. Use the site's https address."
        }
        "header" => {
            "This login is saved as an HTTP Basic login: its password placeholder only works as the password of an HTTP Basic Authorization header. It was somewhere else in the request, so the firewall blocked it and recorded the attempt."
        }
        "page" => {
            "This password placeholder only works in the sign-in request of the login's sign-in page. This request went somewhere else on the site, so the firewall blocked it and recorded the attempt. If this is how the site signs in, ask the owner to add this address to the login on the firewall page (ControlClaw, Secrets, Website logins)."
        }
        "pending" => {
            "The firewall read this address off the login's sign-in page, but the owner has not approved it yet, so the request was blocked and recorded. Ask the owner to open the login on the firewall page (ControlClaw, Secrets, Website logins) and tick this address under 'Read off the sign-in page'. Then sign in again."
        }
        "no_page" => {
            "This login has no sign-in page, so the firewall does not know which request is the sign-in and puts the password nowhere. The request was blocked and recorded. Ask the owner to add the sign-in page to the login on the firewall page (ControlClaw, Secrets, Website logins)."
        }
        "body" => {
            "The sign-in request did not look like this site's sign-in, so the firewall blocked it and recorded the attempt. The password placeholder only works as the whole value of one field of an ordinary sign-in form (or of one top-level field of a JSON sign-in): not inside a longer text, in more than one field, in a file upload, or in a body the firewall does not read as a sign-in. Type only the placeholder into the password field of the sign-in page and submit that form. If you did exactly that, the site sends its sign-in in a way the firewall does not know: do not retry, tell the owner that Activity shows the block and that they can save the login again as 'Typed into the page' (ControlClaw, Secrets, Website logins) or sign you in themselves."
        }
        "field" => {
            "This password placeholder only works in the password field of the login's sign-in form. It was in another field, so the firewall blocked the request and recorded the attempt."
        }
        "method" => {
            "This request asks the site to run it as another kind of request (a _method field or an X-HTTP-Method-Override header). A sign-in never does that, so the firewall blocked it and recorded the attempt."
        }
        "expired" => {
            "The owner allowed this sign-in address, but it has not been on the login's sign-in page for 30 days, so the firewall stopped using it and blocked the request. Open the login's sign-in page again and retry; if it is still blocked, ask the owner to look at the login on the firewall page (ControlClaw, Secrets, Website logins)."
        }
        "place" => {
            "This password placeholder only works in the body of the sign-in form (a POST). It was in the address, a header or another kind of request, so the firewall blocked it and recorded the attempt. Type it into the password field of the sign-in page and submit the form."
        }
        "basic" => {
            "This login is not saved as an HTTP Basic login, so its password placeholder does not work in an Authorization header. The firewall blocked the request and recorded the attempt. If the site signs in with HTTP Basic, ask the owner to save the login again as HTTP Basic on the firewall page (ControlClaw, Secrets, Website logins)."
        }
        _ => {
            "The firewall could not check this request, which carries a password placeholder, so it blocked it and recorded the attempt."
        }
    }
}

/// One remembered swap: until when, the password, its stand-in, the login's sites.
#[derive(Clone)]
struct Echo {
    until: f64,
    secret: String,
    placeholder: String,
    hosts: Vec<String>,
}

pub struct Logins {
    pub creds: Arc<Creds>,
    pub control_plane_host: Option<String>,
    pub targets: forms::Targets,
    /// The agents with recent swaps, oldest first.
    echoes: Mutex<Vec<(Option<String>, Vec<Echo>)>>,
}

impl Logins {
    pub fn new(creds: Arc<Creds>, control_plane_host: Option<String>, targets_path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            creds,
            control_plane_host,
            targets: forms::Targets::new(targets_path),
            echoes: Mutex::new(Vec::new()),
        })
    }

    /// Whether this agent has a login of its own.
    pub fn has_login_for_agent(&self, vm: Option<&str>) -> bool {
        self.creds.all().iter().any(|c| {
            truthy(c.get("login_id")) && truthy(c.get("placeholder")) && c.get("vm_id").and_then(Value::as_str) == vm
        })
    }

    /// Whether any agent has a login: the tripwire looks for every login's stand-in, whoever sends it.
    pub fn any_logins(&self) -> bool {
        self.creds
            .all()
            .iter()
            .any(|c| truthy(c.get("login_id")) && truthy(c.get("placeholder")))
    }

    /// Whether this agent has a login for this host (a site of it, its own name included).
    pub fn has_login_for(&self, flow: &Flow, host: &str) -> bool {
        self.creds
            .for_host(host, flow.vm_id.as_deref())
            .iter()
            .any(|c| truthy(c.get("login_id")))
    }

    /// Every login entry (`_login_entries`).
    fn entries(&self) -> Vec<Value> {
        self.creds
            .all()
            .iter()
            .filter(|c| truthy(c.get("login_id")) && truthy(c.get("placeholder")))
            .cloned()
            .collect()
    }

    /// `_integration_host`: a host the firewall swaps one of this agent's own integration
    /// credentials into (its model, its channels, its mail). The stand-in rides its conversation.
    fn integration_host(&self, host: &str, vm_id: Option<&str>) -> bool {
        self.creds.for_host(host, vm_id).iter().any(|c| {
            !truthy(c.get("login_id"))
                && !truthy(c.get("secret_name"))
                && !matches!(c.get("match_domain"), None | Some(Value::Null))
                && !matches!(c.get("match_domain").and_then(Value::as_str), Some("" | "*"))
        })
    }

    /// `login_tripwire`: a login whose stand-in this request carries to a host that is not one of
    /// its sites.
    pub fn tripwire(&self, flow: &Flow) -> Option<Value> {
        let entries = self.entries();
        if entries.is_empty() {
            return None;
        }
        let host = check_host(flow);
        if self
            .control_plane_host
            .as_deref()
            .is_some_and(|cp| host_matches(cp, &host))
            || self.integration_host(&host, flow.vm_id.as_deref())
        {
            return None;
        }
        let text = scope::request_text(flow);
        let url = target(flow);
        let mut texts = vec![url.clone(), text.clone()];
        if url.contains('%') {
            texts.push(body::unquote(&url));
        }
        if text.contains('%') || text.contains('+') {
            texts.push(scope::unquote_plus(&text));
        }
        for name in header_names(flow) {
            if NAVIGATION_HEADERS.contains(&name.as_str()) {
                continue;
            }
            for v in header_values(flow, &name) {
                if (name == "authorization" || name == "proxy-authorization")
                    && let Some(d) = basic_credentials(&v)
                {
                    texts.push(d);
                }
                texts.push(v);
            }
        }
        let ascii = ascii_host(&host).unwrap_or_else(|| host.clone());
        entries.into_iter().find(|c| {
            let found = Finder::new(&str_of(c, "placeholder"));
            texts.iter().any(|t| found.search(t))
                && !login_host(c, &host)
                && !(!host.is_ascii() && login_host(c, &ascii))
        })
    }

    /// `login_out_of_scope`: a login whose stand-in this request carries to one of its own hosts,
    /// but not where a sign-in sends it.
    pub fn out_of_scope(&self, flow: &Flow) -> Option<(Value, &'static str)> {
        let host = check_host(flow);
        for cred in self.creds.for_host(&host, flow.vm_id.as_deref()) {
            let ph = str_of(&cred, "placeholder");
            if !truthy(cred.get("login_id")) || ph.is_empty() || ph.chars().count() < LOGIN_SHORT {
                continue;
            }
            let places = scope::places(flow, &ph);
            if !places.any() {
                continue;
            }
            if let Err(why) = self.scope(flow, &cred, &host, &places) {
                return Some((cred, why));
            }
        }
        None
    }

    /// `login_scope`: `Ok("basic" | "page")` when the password may go in, `Err(why)` when not.
    pub fn scope(&self, flow: &Flow, cred: &Value, host: &str, places: &Places) -> Result<&'static str, &'static str> {
        let ph = str_of(cred, "placeholder");
        if !scope::is_https(flow) {
            return Err("http");
        }
        if scope::method_override(flow) {
            return Err("method");
        }
        if cred.get("login_auth").and_then(Value::as_str) == Some("basic") {
            return if scope::only_basic_header(flow, places, Some(&ph)) {
                Ok("basic")
            } else {
                Err("header")
            };
        }
        let m = scope::method(flow);
        if places.in_path || places.in_query || !places.headers.is_empty() || !(m == "POST" || m == "PUT") {
            return Err(if scope::only_basic_header(flow, places, None) {
                "basic"
            } else {
                "place"
            });
        }
        if known_sign_in(flow, host) {
            return scope::google_sign_in(flow, &ph).map(|()| "page").map_err(|e| e.0);
        }
        let (field, pairs) = scope::sign_in_field(flow, &ph).map_err(|e| e.0)?;
        let base = scope::sign_in_address(&str_of(cred, "login_url"), None).ok_or("no_page")?;
        let page = scope::login_page(cred);
        let known = self.targets.fields(cred);
        let at = |a: &scope::Address| -> Result<&'static str, &'static str> {
            for (k, v) in &pairs {
                // `{fold(k): (k, v)}`: the last pair with that name wins.
                if let Some((rk, rv)) = a.query.iter().rev().find(|(rk, _)| scope::fold(rk) == scope::fold(k))
                    && (k, v) != (rk, rv)
                {
                    return Err("page");
                }
            }
            match known.get(&scope::address_text(a)) {
                Some(want) if &field != want => Err("field"),
                None if !scope::password_name(&field) => Err("field"),
                _ => Ok("page"),
            }
        };
        if let Some(p) = page.as_ref().filter(|p| scope::goes_to(flow, host, p)) {
            return at(p);
        }
        let list = |k: &str| scope::cred_list(cred, k);
        let refused: Vec<String> = list("refused_targets");
        for t in list("sign_in_targets") {
            let a = if refused.contains(&t) {
                None
            } else {
                scope::sign_in_address(&t, None)
            };
            if let Some(a) = a.filter(|a| a.path != "/" && login_host(cred, &a.host) && scope::goes_to(flow, host, a)) {
                return at(&a);
            }
        }
        for extra in list("sign_in_paths") {
            let a = scope::sign_in_address(&extra, Some((&base.host, base.port)));
            if let Some(a) = a.filter(|a| login_host(cred, &a.host) && scope::goes_to(flow, host, a)) {
                return at(&a);
            }
        }
        for t in list("expired_targets") {
            if scope::sign_in_address(&t, None).is_some_and(|a| scope::goes_to(flow, host, &a)) {
                return Err("expired");
            }
        }
        for t in self.targets.pending(cred) {
            if scope::sign_in_address(&t, None).is_some_and(|a| scope::goes_to(flow, host, &a)) {
                return Err("pending");
            }
        }
        Err("page")
    }

    /// `apply_login_swap` for one login: whether the password went in.
    fn swap_one(&self, flow: &mut Flow, cred: &Value, host: &str) -> bool {
        let ph = str_of(cred, "placeholder");
        let secret = str_of(cred, "secret");
        if ph.is_empty() || secret.is_empty() {
            return false;
        }
        let places = scope::places(flow, &ph);
        if !places.any() {
            return false;
        }
        let Ok(kind) = self.scope(flow, cred, host, &places) else {
            return false;
        };
        // Only to a checked destination, and over TLS only when the name the client handshook with
        // is that destination (`_login_destination_ok`; W1 checks the same).
        let Some(dest) = flow.destination().map(|d| d.name.clone()) else {
            return false;
        };
        if scope::wire_host(&dest) != scope::wire_host(host)
            || (scope::is_https(flow)
                && flow
                    .sni
                    .as_deref()
                    .is_none_or(|sni| scope::wire_host(sni) != scope::wire_host(host)))
        {
            return false;
        }
        let Some(req) = flow.request.as_mut() else { return false };
        if kind == "basic" {
            let values: Vec<String> = req
                .headers()
                .get_all(http::header::AUTHORIZATION)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect();
            req.headers_mut().remove(http::header::AUTHORIZATION);
            for v in values {
                if let Ok(hv) = http::HeaderValue::from_str(&swap_header(&v, &ph, &secret)) {
                    req.headers_mut().append(http::header::AUTHORIZATION, hv);
                }
            }
            push(flow, META_IN, json!("header"));
        } else {
            let Ok(text) = scope::body_text(flow) else { return false };
            let swapped = if known_sign_in(flow, host) {
                match scope::swap_google_sign_in(&text, &ph, &secret) {
                    Ok(s) => s,
                    // Not the shape the check read: no password, the other logins still run.
                    Err(e) => {
                        tracing::warn!(
                            "[mitm] login={} host={host} swap refused: not the shape of a sign-in ({})",
                            str_of(cred, "login_id"),
                            e.0
                        );
                        return false;
                    }
                }
            } else if scope::sign_in_content_type(flow) == Some("form") {
                swap_form(&text, &ph, &secret)
            } else {
                // `scope` checked that the one place the stand-in is written is the holder's whole
                // string (`quoted_whole`), so the text swap lands on the member the check read.
                swap_text(&text, &ph, &secret, "json")
            };
            if let Some(req) = flow.request.as_mut() {
                crate::checks::set_request_body(req, swapped.into_bytes());
            }
            push(flow, META_IN, json!("body"));
        }
        flow.meta.insert(META_SCOPE, json!(kind));
        true
    }

    /// The swaps for every login of this host and agent (the login part of `apply_swaps`).
    pub fn swap(&self, flow: &mut Flow) {
        let host = check_host(flow);
        let vm = flow.vm_id.clone();
        for cred in self.creds.for_host(&host, vm.as_deref()) {
            if !truthy(cred.get("login_id")) {
                continue;
            }
            if self.swap_one(flow, &cred, &host) {
                let (secret, ph) = (str_of(&cred, "secret"), str_of(&cred, "placeholder"));
                let name = login_name(&cred);
                push(flow, META_SWAPS, json!(name));
                push(flow, META_PAIRS, json!([secret, ph]));
                self.remember(vm.as_deref(), &cred, &secret, &ph);
                tracing::info!("[mitm] login={} host={host} verdict=swapped", str_of(&cred, "login_id"));
            }
        }
        record(flow);
    }

    /// `_remember_login_echo`.
    fn remember(&self, vm: Option<&str>, cred: &Value, secret: &str, ph: &str) {
        let now = super::content::rules::now();
        let hosts: Vec<String> = cred
            .get("allowed_hosts")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|h| str_of(&json!({"h": h}), "h")).collect())
            .unwrap_or_default();
        let mut all = self.echoes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = vm.map(str::to_owned);
        let mut kept: Vec<Echo> = all
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, e)| {
                e.iter()
                    .filter(|e| e.until > now && (e.secret.as_str(), e.placeholder.as_str()) != (secret, ph))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        kept.push(Echo {
            until: now + LOGIN_ECHO_WINDOW_S,
            secret: secret.to_owned(),
            placeholder: ph.to_owned(),
            hosts,
        });
        let start = kept.len().saturating_sub(LOGIN_ECHO_MAX);
        all.retain(|(k, _)| *k != key);
        all.push((key, kept.split_off(start)));
        while all.len() > LOGIN_ECHO_AGENTS_MAX {
            all.remove(0);
        }
    }

    /// `_recent_login_pairs`.
    fn recent(&self, vm: Option<&str>, host: &str) -> Vec<(String, String)> {
        let now = super::content::rules::now();
        let mut all = self.echoes.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = vm.map(str::to_owned);
        let Some(i) = all.iter().position(|(k, _)| *k == key) else {
            return Vec::new();
        };
        all[i].1.retain(|e| e.until > now);
        if all[i].1.is_empty() {
            all.remove(i);
            return Vec::new();
        }
        all[i]
            .1
            .iter()
            .filter(|e| e.hosts.iter().any(|p| secret_host_matches(p, host)))
            .map(|e| (e.secret.clone(), e.placeholder.clone()))
            .collect()
    }

    fn any_echoes(&self) -> bool {
        !self
            .echoes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// `redact_login_response`: an echoed password back to its stand-in, in the headers and the body.
    /// The stand-in and password pairs an answer may echo: swapped into this request, or lately
    /// for this agent and host.
    pub fn redact_pairs(&self, flow: &Flow) -> Vec<(String, String)> {
        let swapped_here = swapped_pairs(flow);
        let mut pairs = swapped_here.clone();
        if self.any_echoes() {
            for p in self.recent(flow.vm_id.as_deref(), &check_host(flow)) {
                if !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }
        pairs
    }

    pub fn redact(&self, flow: &mut Flow) {
        if flow.response.is_none() {
            return;
        }
        let swapped_here = swapped_pairs(flow);
        let pairs = self.redact_pairs(flow);
        if pairs.is_empty() {
            return;
        }
        let Some(resp) = flow.response.as_mut() else { return };
        let names: Vec<http::HeaderName> = {
            let mut n: Vec<http::HeaderName> = resp.headers().keys().cloned().collect();
            n.dedup();
            n
        };
        for name in names {
            let values: Vec<String> = resp
                .headers()
                .get_all(&name)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect();
            let cleaned: Vec<String> = values.iter().map(|v| redact_text(v, &pairs)).collect();
            if cleaned != values {
                resp.headers_mut().remove(&name);
                for c in cleaned {
                    if let Ok(hv) = http::HeaderValue::from_str(&c) {
                        resp.headers_mut().append(name.clone(), hv);
                    }
                }
            }
        }
        if resp.body().is_empty() || resp.body().len() > LOGIN_REDACT_MAX {
            return;
        }
        let ct = body::content_type(resp.headers());
        if swapped_here.is_empty() && !TEXT_TYPES.iter().any(|t| ct.to_lowercase().contains(t)) {
            // A later response is only searched when it is text: an image or a download is left whole.
            return;
        }
        // The plumbing passes the body still encoded: undone here (`get_text`), at most
        // LOGIN_REDACT_DECODED_MAX. The addon passes on a body it cannot decode; on the answer to
        // the request the password went out on, such a body is not passed on (fail closed).
        let Some(content) =
            crate::http::body::decoded(resp.headers(), resp.body()).filter(|c| c.len() <= LOGIN_REDACT_DECODED_MAX)
        else {
            if !swapped_here.is_empty() {
                *resp = super::raw_response(502, br#"{"error":"unreadable_response"}"#.to_vec(), "application/json");
            }
            return;
        };
        let text = body::get_text(&ct, &content);
        let changed = redact_text(&text, &pairs);
        if changed != text {
            let bytes = encode_like(&ct, &changed);
            super::set_body(resp, bytes);
        }
    }
}

/// What `_allow_record` reads of a swap, under the keys the record step takes
/// (`log::record::allow_record`): `login_placeholders`, left off `swapped`, and `login_record`,
/// the login's name (64 characters), where it went in (each place once) and the scope.
fn record(flow: &mut Flow) {
    let Some(first) = flow
        .meta
        .get(META_SWAPS)
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(|n| super::content::engine::cut(n, 64))
    else {
        return;
    };
    let placeholders: Vec<Value> = flow
        .meta
        .get(META_PAIRS)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|p| p.get(1).cloned()).collect())
        .unwrap_or_default();
    let mut places: Vec<Value> = Vec::new();
    for p in flow.meta.get(META_IN).and_then(Value::as_array).into_iter().flatten() {
        if !places.contains(p) {
            places.push(p.clone());
        }
    }
    let scope = flow.meta.get(META_SCOPE).cloned().unwrap_or(Value::Null);
    flow.meta.insert("login_placeholders", Value::Array(placeholders));
    flow.meta.insert(
        "login_record",
        json!({"login": first, "login_in": places, "login_scope": scope}),
    );
}

fn push(flow: &mut Flow, key: &'static str, v: Value) {
    let e = flow.meta.entry(key).or_insert_with(|| json!([]));
    if let Some(a) = e.as_array_mut() {
        a.push(v);
    }
}

/// `set_text`: in the body's own charset when it can hold the text (Latin-1 for a type that
/// says nothing), else UTF-8.
fn encode_like(content_type: &str, text: &str) -> Vec<u8> {
    let latin = body::get_text(content_type, "\u{e9}".as_bytes()) != "\u{e9}";
    if latin && text.chars().all(|c| (c as u32) < 256) {
        return text.chars().map(|c| c as u8).collect();
    }
    text.as_bytes().to_vec()
}

/// `_without_stand_in`: a record's path with the stand-in taken out.
pub fn without_stand_in(path: &str, cred: &Value) -> String {
    let ph = str_of(cred, "placeholder");
    if ph.is_empty() {
        return path.to_owned();
    }
    let found = Finder::new(&ph);
    if found.search(path) {
        return found.replace(path, |_| "[login stand-in]".into());
    }
    if found.search(&body::unquote(path)) {
        "/[login stand-in]".into()
    } else {
        path.to_owned()
    }
}

/// `_json_levels`: how many JSON strings the text at `at` sits inside, read off the quote that
/// opens it (`2^(k-1) - 1` backslashes before the quote of a string `k` levels deep).
fn json_levels(text: &str, at: usize) -> u32 {
    let b = text.as_bytes();
    let mut i = at;
    while i > 0 && !matches!(b[i - 1], b'"' | b'\r' | b'\n') {
        i -= 1;
    }
    if i == 0 || b[i - 1] != b'"' {
        return 0;
    }
    let mut n: u32 = 0;
    let mut j = i - 1;
    while j > 0 && b[j - 1] == b'\\' {
        n += 1;
        j -= 1;
    }
    32 - (n + 1).leading_zeros()
}

/// `_json_escape`: escaped for `levels` JSON strings, non-ASCII kept.
fn json_escape(value: &str, levels: u32) -> String {
    let mut v = value.to_owned();
    for _ in 0..levels {
        let d = super::pyjson::dumps_unicode(&v);
        v = d[1..d.len() - 1].to_owned();
    }
    v
}

fn xml_escape(v: &str) -> String {
    v.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// `_known_sign_in`: a sign-in whose path and body shape are known here (Google's).
fn known_sign_in(flow: &Flow, host: &str) -> bool {
    ascii_host(host).as_deref() == Some("accounts.google.com")
        && scope::port(flow) == 443
        && scope::plain_path(&target(flow)).is_some_and(|p| p.starts_with("/v3/signin/"))
}

/// `swap_login_text`: every stand-in replaced by the password escaped for where it sits.
pub fn swap_text(text: &str, ph: &str, secret: &str, kind: &str) -> String {
    let found = Finder::new(ph);
    found.replace(text, |at| match kind {
        "json" => json_escape(secret, json_levels(text, at)),
        "xml" => {
            let in_cdata = text[..at].rfind("<![CDATA[").map_or(-1, |i| i as i64)
                > text[..at].rfind("]]>").map_or(-1, |i| i as i64);
            if in_cdata {
                secret.replace("]]>", "]]]]><![CDATA[>")
            } else {
                xml_escape(secret)
            }
        }
        _ => secret.to_owned(),
    })
}

/// `_is_json`.
fn is_json(text: &str) -> bool {
    let s = text.trim_matches(body::is_py_space);
    s.starts_with(['[', '{', '"']) && super::json::loads(s).is_ok()
}

/// `swap_login_form`: only the fields holding the stand-in are decoded, swapped and re-encoded.
pub fn swap_form(body_text: &str, ph: &str, secret: &str) -> String {
    let found = Finder::new(ph);
    body_text
        .split('&')
        .map(|part| {
            let Some((key, value)) = part.split_once('=') else {
                return part.to_owned();
            };
            let decoded = scope::unquote_plus(value);
            if !found.search(&decoded) {
                return part.to_owned();
            }
            let kind = if is_json(&decoded) { "json" } else { "raw" };
            format!(
                "{key}={}",
                scope::quote_plus(&swap_text(&decoded, ph, secret, kind), "*")
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// `_swap_login_header` for `Authorization`.
fn swap_header(value: &str, ph: &str, secret: &str) -> String {
    let found = Finder::new(ph);
    if let Some(decoded) = basic_credentials(value) {
        if !found.search(&decoded) {
            return value.to_owned();
        }
        use base64::Engine;
        let swapped = found.replace(&decoded, |_| secret.to_owned());
        return format!(
            "{}{}",
            &value[..6],
            base64::engine::general_purpose::STANDARD.encode(swapped.as_bytes())
        );
    }
    found.replace(value, |_| secret.to_owned())
}

/// `_redact_text`: each spelling of each password back to its stand-in, longest first, not inside
/// a longer word or number.
pub fn redact_text(text: &str, pairs: &[(String, String)]) -> String {
    let mut text = text.to_owned();
    for (secret, ph) in pairs {
        let mut forms: Vec<String> = vec![
            secret.clone(),
            scope::quote(secret),
            scope::quote_plus(secret, ""),
            json_escape(secret, 1),
            json_escape(secret, 2),
            {
                let d = super::pyjson::dumps(secret);
                d[1..d.len() - 1].to_owned()
            },
            xml_escape(secret),
        ];
        forms.sort();
        forms.dedup();
        forms.sort_by_key(|f| std::cmp::Reverse(f.chars().count()));
        for form in forms {
            if form.is_empty() || !text.contains(&form) {
                continue;
            }
            let left = form.chars().next().is_some_and(super::content::detect::is_alnum);
            let right = form.chars().next_back().is_some_and(super::content::detect::is_alnum);
            let mut out = String::with_capacity(text.len());
            let mut from = 0;
            let mut last = 0;
            while let Some(off) = text[from..].find(&form) {
                let s = from + off;
                let e = s + form.len();
                let bad_left = left && text[..s].chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric());
                let bad_right = right && text[e..].chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
                if bad_left || bad_right {
                    from = s + form.chars().next().map_or(1, char::len_utf8);
                    continue;
                }
                out.push_str(&text[last..s]);
                out.push_str(ph);
                last = e;
                from = e;
            }
            out.push_str(&text[last..]);
            text = out;
        }
    }
    text
}

// ---- the steps ----------------------------------------------------------------------------------

pub fn register(pipeline: &mut Pipeline, logins: Arc<Logins>) {
    pipeline.push(order::LOGIN_TRIPWIRE, Arc::new(LoginGate(logins.clone())));
    pipeline.push(order::SWAPS, Arc::new(LoginSwap(logins.clone())));
    pipeline.push(order::RESPONSE_LOGIN_LEARN, Arc::new(LoginLearn(logins.clone())));
    pipeline.push(order::RESPONSE_LOGIN_REDACT, Arc::new(LoginRedact(logins)));
}

/// The tripwire and "not on the sign-in page" (request step 6).
pub struct LoginGate(pub Arc<Logins>);

impl Step for LoginGate {
    fn name(&self) -> &'static str {
        "login-tripwire"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// Every body while any agent has a login: a stand-in may be in it, whoever sends it and wherever.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        super::request_has_body(flow) && self.0.any_logins()
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let host = flow.claimed_host().unwrap_or_else(|| check_host(flow));
            let rec_path = |flow: &Flow, cred: &Value| without_stand_in(&redact_path(&target(flow), &host), cred);
            // A body whose `content-encoding` cannot be undone cannot be searched for a stand-in:
            // while this agent has logins, such a request is refused as one the check could not
            // read (the addon's error branch). Stricter than the addon, which reads it as empty.
            let has_body = flow.request.as_ref().is_some_and(|r| !r.body().is_empty());
            // A body that went past the checks unread (#625) is one the check could not read either.
            let streamed = super::request_streamed(flow) && super::request_has_body(flow);
            let mine_any = self.0.has_login_for_agent(flow.vm_id.as_deref());
            if streamed && !mine_any && self.0.any_logins() {
                // Another agent's stand-in could be in it: refused as unread, naming no login.
                let body = json!({"error": "login_not_on_sign_in_page", "host": host, "message": block_text("error")});
                let mut rec = Map::new();
                rec.insert("login_why".into(), json!("error"));
                return super::answer(flow, BLOCK_STATUS, &body, "block", LOGIN_TRIPWIRE_RULE, rec);
            }
            if streamed || (has_body && scope::content(flow).is_none()) {
                let vm = flow.vm_id.clone();
                let mine: Vec<Value> = self
                    .0
                    .entries()
                    .into_iter()
                    .filter(|c| c.get("vm_id").and_then(Value::as_str) == vm.as_deref())
                    .collect();
                if let Some(first) = mine
                    .iter()
                    .find(|c| login_host(c, &check_host(flow)))
                    .or_else(|| mine.first())
                    .cloned()
                {
                    let body =
                        json!({"error": "login_not_on_sign_in_page", "host": host, "message": block_text("error")});
                    let mut rec = Map::new();
                    rec.insert(
                        "login".into(),
                        json!(super::content::engine::cut(&login_name(&first), 64)),
                    );
                    rec.insert("login_why".into(), json!("error"));
                    rec.insert("path".into(), json!(rec_path(flow, &first)));
                    return super::answer(flow, BLOCK_STATUS, &body, "block", LOGIN_TRIPWIRE_RULE, rec);
                }
            }
            if let Some(cred) = self.0.tripwire(flow) {
                let body = json!({"error": "login_sent_to_another_site", "host": host,
                    "message": "This password placeholder only works on the login's own sites. The firewall blocked it and recorded the attempt."});
                let mut rec = Map::new();
                rec.insert(
                    "login".into(),
                    json!(super::content::engine::cut(&login_name(&cred), 64)),
                );
                rec.insert("path".into(), json!(rec_path(flow, &cred)));
                tracing::warn!(
                    "[mitm] login={} host={host} verdict=tripwire",
                    str_of(&cred, "login_id")
                );
                return super::answer(flow, BLOCK_STATUS, &body, "block", LOGIN_TRIPWIRE_RULE, rec);
            }
            if let Some((cred, why)) = self.0.out_of_scope(flow) {
                let body = json!({"error": "login_not_on_sign_in_page", "host": host, "message": block_text(why)});
                let mut rec = Map::new();
                rec.insert(
                    "login".into(),
                    json!(super::content::engine::cut(&login_name(&cred), 64)),
                );
                rec.insert("login_why".into(), json!(why));
                rec.insert("path".into(), json!(rec_path(flow, &cred)));
                tracing::warn!(
                    "[mitm] login={} host={host} verdict=tripwire why={why}",
                    str_of(&cred, "login_id")
                );
                return super::answer(flow, BLOCK_STATUS, &body, "block", LOGIN_TRIPWIRE_RULE, rec);
            }
            Verdict::Continue
        })
    }
}

fn login_name(cred: &Value) -> String {
    match cred.get("login_name") {
        Some(v) if truthy(Some(v)) => str_of(&json!({"n": v}), "n"),
        _ => "login".into(),
    }
}

/// The password put in (the login part of `apply_swaps`, request step 21).
pub struct LoginSwap(pub Arc<Logins>);

impl Step for LoginSwap {
    fn name(&self) -> &'static str {
        "login-swap"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    /// A body to one of the agent's logins' sites.
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        super::request_has_body(flow) && self.0.has_login_for(flow, &check_host(flow))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            self.0.swap(flow);
            Verdict::Continue
        })
    }
}

pub struct LoginLearn(pub Arc<Logins>);

impl Step for LoginLearn {
    fn name(&self) -> &'static str {
        "login-learn"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// A page from a login's site that went through (`learn` reads only those).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        scope::method(flow) == "GET"
            && flow.response.as_ref().is_some_and(|r| r.status() == 200)
            && self.0.has_login_for(flow, &check_host(flow))
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            // Reading a page and writing the file are blocking work: on the blocking pool, with a
            // copy of what they read.
            if flow.response.is_some() && scope::method(flow) == "GET" {
                let logins = self.0.clone();
                let page = snapshot(flow);
                let _ = tokio::task::spawn_blocking(move || forms::learn(&logins, &page)).await;
            }
            Verdict::Continue
        })
    }
}

pub struct LoginRedact(pub Arc<Logins>);

impl Step for LoginRedact {
    fn name(&self) -> &'static str {
        "login-redact"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response]
    }
    /// An answer that may echo a password swapped in (here, or lately for this agent and host).
    fn reads_body(&self, _: Hook, flow: &mut Flow) -> bool {
        !self.0.redact_pairs(flow).is_empty()
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            self.0.redact(flow);
            Verdict::Continue
        })
    }
}

/// The stand-in and password pairs swapped into this request.
fn swapped_pairs(flow: &Flow) -> Vec<(String, String)> {
    flow.meta
        .get(META_PAIRS)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| Some((p.get(0)?.as_str()?.to_owned(), p.get(1)?.as_str()?.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

/// What `learn` reads of a flow, as a flow of its own (requests and responses are not `Clone`).
fn snapshot(flow: &Flow) -> Flow {
    let mut f = Flow::new(flow.client_ip, flow.connect.clone());
    f.id = flow.id.clone();
    f.vm_id = flow.vm_id.clone();
    f.sni = flow.sni.clone();
    if let Some(d) = flow.destination() {
        f.set_destination(d.clone());
    }
    f.request = flow.request.as_ref().and_then(|r| {
        let mut b = http::Request::builder().method(r.method().clone()).uri(r.uri().clone());
        for (k, v) in r.headers() {
            b = b.header(k, v);
        }
        b.body(Bytes::new()).ok()
    });
    f.response = flow.response.as_ref().and_then(|r| {
        let mut b = http::Response::builder().status(r.status());
        for (k, v) in r.headers() {
            b = b.header(k, v);
        }
        b.body(r.body().clone()).ok()
    });
    f
}

/// For the tests: the stand-in places of one login.
pub fn places_of(flow: &Flow, placeholder: &str) -> Places {
    scope::places(flow, placeholder)
}

#[cfg(test)]
mod tests;
