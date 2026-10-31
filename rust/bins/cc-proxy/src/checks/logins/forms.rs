//! Sign-in forms read off a login's sign-in page (`password_form_targets`, `learn_login_targets`)
//! and the file they are kept in (`login-targets.json`, read and written as the addon does).
//!
//! The page reader is a scanner of its own, as the addon's: every step moves forward, a tag is
//! read at most 4096 bytes far, and the whole page stops at a time budget. Offsets are in bytes
//! where the addon counts characters; on pages in Latin script that is the same.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Map, Value, json};

use super::Logins;
use super::scope::{self, str_of};
use crate::checks::creds::{ascii_host, truthy};
use crate::checks::{body, check_host, mime};
use crate::flow::Flow;

const LOGIN_TARGETS_MAX: usize = 5;
const LOGIN_TARGET_TTL_S: f64 = 30.0 * 86400.0;
const LOGIN_PAGE_MAX: usize = 1024 * 1024;
const LOGIN_PAGE_TEXT_MAX: usize = 256 * 1024;
const LOGIN_PARSE_BUDGET: Duration = Duration::from_millis(200);
const LOGIN_TAG_MAX: usize = 4096;
const RAW_TEXT: &[&str] = &[
    "script",
    "style",
    "textarea",
    "template",
    "title",
    "noscript",
    "xmp",
    "iframe",
    "noembed",
    "noframes",
    "plaintext",
];

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

static ATTR: LazyLock<Regex> =
    LazyLock::new(|| re(r#"([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+)))?"#));
static TAG_NAME: LazyLock<Regex> = LazyLock::new(|| re(r"^/?([a-zA-Z][a-zA-Z0-9]*)"));
static USER_FIELD: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)user|email|e-mail|login|account|ident|name"));
static NOT_SIGN_IN_FIELD: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)confirm|repeat|retype|again|verify|new[-_ ]?pass|password[-_]?2|pass2|pw2"));
static NOT_SIGN_IN_FORM: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)regist|sign[-_ ]?up|join|create[-_ ]?account|new[-_ ]?user|enroll|subscribe"));

struct Form {
    action: String,
    post: bool,
    passwords: u32,
    field: String,
    user: bool,
    typed: u32,
    new: bool,
}

/// `password_form_targets`: (action, password field) for each POST sign-in form on a page;
/// `None` when the page cannot be trusted to say where its forms go (`<base href>`), is too long,
/// or took too long.
pub fn password_form_targets(html: &str) -> Option<Vec<(String, String)>> {
    if html.chars().count() > LOGIN_PAGE_TEXT_MAX {
        return None;
    }
    let deadline = Instant::now() + LOGIN_PARSE_BUDGET;
    let mut actions = Vec::new();
    let mut form: Option<Form> = None;
    let close = |form: &mut Option<Form>, actions: &mut Vec<(String, String)>| {
        if let Some(f) = form.take()
            && f.post
            && f.passwords == 1
            && !f.field.is_empty()
            && f.user
            && !f.new
            && f.typed <= 2
        {
            actions.push((f.action, f.field));
        }
    };
    let low = html.to_ascii_lowercase();
    let b = html.as_bytes();
    let (mut i, mut steps) = (0usize, 0u64);
    while let Some(off) = html.get(i..).and_then(|t| t.find('<')) {
        i += off;
        steps += 1;
        if steps % 64 == 0 && Instant::now() > deadline {
            return None;
        }
        if low[i..].starts_with("<!--") {
            match html[i + 4..].find("-->") {
                Some(e) => {
                    i = i + 4 + e + 3;
                    continue;
                }
                None => break,
            }
        }
        let window_end = (i + LOGIN_TAG_MAX).min(b.len());
        let Some(end) = b[i + 1..window_end].iter().position(|c| *c == b'>').map(|p| i + 1 + p) else {
            i += 1;
            continue;
        };
        let tag = &html[i + 1..end];
        i = end + 1;
        let Some(m) = TAG_NAME.captures(tag) else { continue };
        let name = m[1].to_ascii_lowercase();
        let rest = &tag[m.get(0).map_or(0, |g| g.end())..];
        if tag.starts_with('/') {
            if name == "form" {
                close(&mut form, &mut actions);
            }
            continue;
        }
        if name == "textarea"
            && let Some(f) = form.as_mut()
        {
            f.typed += 1;
        }
        if RAW_TEXT.contains(&name.as_str()) {
            match low[i..].find(&format!("</{name}")) {
                Some(e) => {
                    i += e;
                    continue;
                }
                None => break,
            }
        }
        // Attribute values are character data: `&amp;` in an action is `&`.
        let mut attrs: HashMap<String, String> = HashMap::new();
        for a in ATTR.captures_iter(rest) {
            let v = a
                .get(2)
                .or_else(|| a.get(3))
                .or_else(|| a.get(4))
                .map_or("", |g| g.as_str());
            attrs.insert(a[1].to_lowercase(), mime::unescape(v));
        }
        let get = |k: &str| attrs.get(k).cloned().unwrap_or_default();
        if name == "base" && attrs.contains_key("href") {
            return None;
        }
        if name == "form" {
            close(&mut form, &mut actions);
            let marks = ["action", "id", "name", "class"]
                .iter()
                .map(|k| get(k))
                .collect::<Vec<_>>()
                .join(" ");
            form = Some(Form {
                action: get("action"),
                post: attrs.get("method").map_or("get".into(), |m| m.trim().to_lowercase()) == "post",
                passwords: 0,
                field: String::new(),
                user: false,
                typed: 0,
                new: NOT_SIGN_IN_FORM.is_match(&marks),
            });
        } else if matches!(name.as_str(), "input" | "textarea" | "select")
            && let Some(f) = form.as_mut()
        {
            let kind = if name == "input" {
                attrs.get("type").map_or("text".into(), |t| t.trim().to_lowercase())
            } else {
                name.clone()
            };
            let label = ["name", "id", "autocomplete"]
                .iter()
                .map(|k| get(k))
                .collect::<Vec<_>>()
                .join(" ");
            if NOT_SIGN_IN_FIELD.is_match(&label) {
                f.new = true;
            }
            if kind == "password" {
                f.passwords += 1;
                f.field = get("name");
                if get("autocomplete").trim().to_lowercase() == "new-password" {
                    f.new = true;
                }
            } else if matches!(
                kind.as_str(),
                "text" | "email" | "tel" | "url" | "number" | "search" | "date" | "textarea" | "select"
            ) {
                f.typed += 1;
                if matches!(kind.as_str(), "text" | "email" | "tel") && (kind == "email" || USER_FIELD.is_match(&label))
                {
                    f.user = true;
                }
            }
        }
    }
    close(&mut form, &mut actions);
    Some(actions)
}

/// The targets this process read off sign-in pages (login id → page, address → seen, field),
/// loaded from the file once, written back when they change.
pub struct Targets {
    pub path: PathBuf,
    state: Mutex<Option<Map<String, Value>>>,
}

impl Targets {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(None),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Map<String, Value>) -> T) -> T {
        let mut st = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let m = st.get_or_insert_with(|| load(&self.path));
        f(m)
    }

    /// `_login_fields`: address → password field, what the firewall agent kept and what was read since.
    pub fn fields(&self, cred: &Value) -> HashMap<String, String> {
        let mut out: HashMap<String, String> = cred
            .get("sign_in_fields")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .filter_map(|(u, f)| f.as_str().filter(|f| !f.is_empty()).map(|f| (u.clone(), f.to_owned())))
                    .collect()
            })
            .unwrap_or_default();
        self.with(|m| {
            if let Some(mine) = m
                .get(&str_of(cred, "login_id"))
                .filter(|e| e.get("page") == cred.get("login_url"))
                && let Some(t) = mine.get("targets").and_then(Value::as_object)
            {
                for (u, e) in t {
                    if let Some(f) = e.get("field").and_then(Value::as_str).filter(|f| !f.is_empty()) {
                        out.entry(u.clone()).or_insert_with(|| f.to_owned());
                    }
                }
            }
        });
        out
    }

    /// `_login_pending`: targets read off the page that the owner has not approved.
    pub fn pending(&self, cred: &Value) -> Vec<String> {
        let list = |k: &str| scope::cred_list(cred, k);
        let mut out = list("pending_targets");
        self.with(|m| {
            if let Some(mine) = m
                .get(&str_of(cred, "login_id"))
                .filter(|e| e.get("page") == cred.get("login_url"))
                && let Some(t) = mine.get("targets").and_then(Value::as_object)
            {
                out.extend(t.keys().cloned());
            }
        });
        let (refused, approved) = (list("refused_targets"), list("sign_in_targets"));
        out.sort();
        out.dedup();
        out.retain(|u| !refused.contains(u) && !approved.contains(u));
        out
    }
}

/// `_load_login_targets`: the file as the addon reads it; anything odd in it is dropped.
fn load(path: &PathBuf) -> Map<String, Value> {
    let Some(Value::Object(data)) = std::fs::read(path)
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
    else {
        return Map::new();
    };
    let mut out = Map::new();
    for (login_id, entry) in data {
        let Some(targets) = entry.get("targets").and_then(Value::as_object) else {
            continue;
        };
        let mut kept = Map::new();
        for (url, seen) in targets {
            if let Some(s) = seen.get("seen").filter(|s| s.is_number()).and_then(Value::as_f64) {
                let field = seen
                    .get("field")
                    .filter(|f| f.is_string())
                    .cloned()
                    .unwrap_or(Value::Null);
                kept.insert(url.clone(), json!({"seen": s, "field": field}));
            }
        }
        out.insert(
            login_id,
            json!({"page": entry.get("page").cloned().unwrap_or(Value::Null), "targets": kept}),
        );
    }
    out
}

/// `learn_login_targets`: when the agent loads a login's sign-in page, the sign-in forms on it say
/// where the password goes. Written down for the owner to approve; it does not count before.
pub fn learn(logins: &Logins, flow: &Flow) {
    let Some(resp) = flow.response.as_ref() else { return };
    if scope::method(flow) != "GET" || resp.status() != 200 {
        return;
    }
    let host = check_host(flow);
    // The page has to come from the site itself: the name the client handshook with is the destination.
    let tls_ok = flow.destination().is_some()
        && flow
            .sni
            .as_deref()
            .is_some_and(|s| scope::wire_host(s) == scope::wire_host(&host));
    if !scope::is_https(flow) || !tls_ok {
        return;
    }
    let creds: Vec<Value> = logins
        .creds
        .for_host(&host, flow.vm_id.as_deref())
        .into_iter()
        .filter(|c| {
            truthy(c.get("login_id"))
                && truthy(c.get("login_url"))
                && c.get("login_auth").and_then(Value::as_str) != Some("basic")
        })
        .collect();
    let ct = body::content_type(resp.headers());
    if creds.is_empty() || !ct.to_lowercase().contains("html") {
        return;
    }
    let creds: Vec<Value> = creds
        .into_iter()
        .filter(|c| scope::login_page(c).is_some_and(|p| scope::goes_to(flow, &host, &p)))
        .collect();
    if creds.is_empty() || resp.body().is_empty() || resp.body().len() > LOGIN_PAGE_MAX {
        return;
    }
    // Still encoded from the plumbing: undone here, and a page that does not decode teaches nothing.
    let Some(content) = crate::http::body::decoded(resp.headers(), resp.body()).filter(|c| c.len() <= LOGIN_PAGE_MAX)
    else {
        return;
    };
    let Some(actions) = password_form_targets(&body::get_text(&ct, &content)).filter(|a| !a.is_empty()) else {
        return;
    };
    let port = scope::port(flow);
    let t = scope::target(flow);
    let page_url = format!(
        "https://{}{}{}",
        ascii_host(&host).unwrap_or_else(|| host.to_lowercase()),
        if port == 443 { String::new() } else { format!(":{port}") },
        t.split('#').next().unwrap_or("")
    );
    let Ok(base) = url::Url::parse(&page_url) else { return };
    let now = crate::checks::content::rules::now();
    let known_ids: Vec<String> = logins
        .creds
        .all()
        .iter()
        .filter(|c| truthy(c.get("login_id")) && truthy(c.get("placeholder")))
        .map(|c| str_of(c, "login_id"))
        .collect();
    logins.targets.with(|m| {
        let mut changed = false;
        for cred in &creds {
            let id = str_of(cred, "login_id");
            let refused: Vec<String> = scope::cred_list(cred, "refused_targets");
            let page = cred.get("login_url").cloned().unwrap_or(Value::Null);
            if m.get(&id).is_none_or(|e| e.get("page") != Some(&page)) {
                m.insert(id.clone(), json!({"page": page, "targets": {}}));
                changed = true;
            }
            let Some(targets) = m
                .get_mut(&id)
                .and_then(|e| e.get_mut("targets"))
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            for (action, field) in &actions {
                let joined = base.join(action.trim()).map(|u| u.to_string()).unwrap_or_default();
                let joined = joined.split('#').next().unwrap_or("").to_owned();
                // The top of a site is not a sign-in address a page can teach.
                let Some(a) =
                    scope::sign_in_address(&joined, None).filter(|a| a.path != "/" && scope::login_host(cred, &a.host))
                else {
                    continue;
                };
                let t = scope::address_text(&a);
                if refused.contains(&t) {
                    continue;
                }
                let known = targets.get(&t);
                let stale = known.is_none_or(|k| {
                    k["seen"].as_f64().unwrap_or(0.0) + 86400.0 < now
                        || k.get("field").and_then(Value::as_str) != Some(field.as_str())
                });
                if stale {
                    targets.insert(t, json!({"seen": now, "field": field}));
                    changed = true;
                }
            }
            let old: Vec<String> = targets
                .iter()
                .filter(|(u, e)| e["seen"].as_f64().unwrap_or(0.0) + LOGIN_TARGET_TTL_S <= now || refused.contains(u))
                .map(|(u, _)| u.clone())
                .collect();
            for u in old {
                targets.remove(&u);
                changed = true;
            }
            while targets.len() > LOGIN_TARGETS_MAX {
                let oldest = targets
                    .iter()
                    .min_by(|a, b| {
                        a.1["seen"]
                            .as_f64()
                            .unwrap_or(0.0)
                            .total_cmp(&b.1["seen"].as_f64().unwrap_or(0.0))
                    })
                    .map(|(u, _)| u.clone());
                match oldest {
                    Some(u) => {
                        targets.remove(&u);
                        changed = true;
                    }
                    None => break,
                }
            }
        }
        if changed {
            // `_save_login_targets`: logins that are gone are dropped. Written while the map is
            // held, so two pages read at once cannot write their snapshots out of order.
            m.retain(|k, _| known_ids.contains(k));
            let tmp = PathBuf::from(format!("{}.tmp", logins.targets.path.display()));
            let r = std::fs::write(&tmp, crate::checks::pyjson::dumps(&*m))
                .and_then(|()| std::fs::rename(&tmp, &logins.targets.path));
            if let Err(e) = r {
                tracing::warn!("[mitm] could not write {}: {e}", logins.targets.path.display());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_forms() {
        let page = r#"<html><form action="/session" method="post"><input name="login" type="text"><input type="password" name="password"></form>
            <form action="/signup" method="post"><input name="email" type="email"><input type="password" name="pw"></form>
            <form action="/search"><input name="q"></form><script>"<form action='/x' method=post>"</script>
            <!-- <form action="/hidden" method="post"> --></html>"#;
        assert_eq!(
            password_form_targets(page),
            Some(vec![("/session".into(), "password".into())])
        );
        assert_eq!(
            password_form_targets(r#"<base href="https://evil/"><form method=post></form>"#),
            None
        );
        let new = r#"<form action="/s" method="post"><input name="user"><input type="password" name="p" autocomplete="new-password"></form>"#;
        assert_eq!(password_form_targets(new), Some(vec![]));
        let amp = r#"<form action="/s?a=1&amp;b=2" method="POST"><input type=email name=e><input type=password name=p></form>"#;
        assert_eq!(
            password_form_targets(amp),
            Some(vec![("/s?a=1&b=2".into(), "p".into())])
        );
    }
}
