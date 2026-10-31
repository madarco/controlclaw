//! Website logins (`logins-schema.ts`, docs/plans/website-credentials.md): the shapes of a login,
//! of a change the console may propose, and of what the page posts. The TS checks them with zod;
//! the functions here refuse the same things. Nothing in the metadata is secret.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::integrations::js;

/// Logins per organization. A password manager export runs to hundreds.
pub const LOGIN_LIMIT: usize = 1000;
pub const LEARNED_TARGETS_MAX: usize = 5;
pub const LEARNED_TARGET_TTL_MS: i64 = 30 * 86_400_000;
/// An expired target the owner had allowed is still shown this long.
pub const LEARNED_TARGET_KEEP_MS: i64 = 120 * 86_400_000;

fn re(s: &str) -> Regex {
    Regex::new(s).expect("a fixed pattern")
}

static SITE: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"));
static HOST: LazyLock<Regex> =
    LazyLock::new(|| re(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"));
pub static LOGIN_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^lg_[A-Za-z0-9_-]{8,40}$"));
pub static REQUEST_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^lr_[A-Za-z0-9_-]{8,40}$"));

/// The zod error, as the page shows it for the fields it names (`scopeIssue`).
#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    /// The first path element (`loginUrl`, `signInPaths`, …), or empty.
    pub path: String,
    pub message: String,
}

pub type Checked<T> = Result<T, Issue>;

fn issue<T>(path: &str, message: &str) -> Checked<T> {
    Err(Issue {
        path: path.into(),
        message: message.into(),
    })
}

/// UTF-16 length, as zod counts.
fn len16(s: &str) -> usize {
    s.encode_utf16().count()
}

fn no_controls(s: &str) -> bool {
    !s.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

/// `z.string()` at `v`.
fn string<'a>(v: Option<&'a Value>, path: &str) -> Checked<&'a str> {
    match v {
        Some(Value::String(s)) => Ok(s),
        _ => issue(path, "Expected string"),
    }
}

/// `loginSite`: an exact host or `*.example.com`, trimmed and lower-cased.
pub fn login_site(s: &str) -> Checked<String> {
    let v = js::trim(s).to_lowercase();
    if len16(&v) > 253 || !SITE.is_match(&v) {
        return issue("sites", "Use a host name such as github.com or *.example.com");
    }
    Ok(v)
}

pub fn login_sites(v: Option<&Value>) -> Checked<Vec<String>> {
    let Some(Value::Array(a)) = v else {
        return issue("sites", "Expected array");
    };
    if a.is_empty() || a.len() > 20 {
        return issue("sites", "Use 1 to 20 sites");
    }
    a.iter().map(|s| login_site(string(Some(s), "sites")?)).collect()
}

pub fn login_name(v: Option<&Value>) -> Checked<String> {
    let s = js::trim(string(v, "name")?).to_string();
    if !(1..=64).contains(&len16(&s)) || !no_controls(&s) {
        return issue("name", "Use one line of text");
    }
    Ok(s)
}

pub fn login_username(v: Option<&Value>) -> Checked<String> {
    let s = string(v, "username")?;
    if len16(s) > 256 || !no_controls(s) {
        return issue("username", "Use one line of text");
    }
    Ok(s.to_string())
}

pub fn login_password(v: Option<&Value>) -> Checked<String> {
    let s = string(v, "password")?;
    if !(1..=1024).contains(&len16(s)) || !no_controls(s) {
        return issue("password", "Use one line of text");
    }
    Ok(s.to_string())
}

/// `loginUrl`: trimmed, at most 2048, an address `new URL` reads, http(s).
pub fn login_url(s: &str, path: &str) -> Checked<String> {
    let v = js::trim(s).to_string();
    if len16(&v) > 2048 || url::Url::parse(&v).is_err() {
        return issue(path, "Invalid url");
    }
    if !(v.starts_with("https://") || v.starts_with("http://")) {
        return issue(path, "Use an http(s) address");
    }
    Ok(v)
}

/// `swap` or `type`.
pub fn login_mode(v: Option<&Value>, default: Option<&str>) -> Checked<String> {
    match (v, default) {
        (None, Some(d)) => Ok(d.into()),
        (Some(Value::String(m)), _) if m == "swap" || m == "type" => Ok(m.clone()),
        _ => issue("mode", "Invalid enum value"),
    }
}

/// `form` or `basic`.
pub fn login_auth(v: Option<&Value>, default: Option<&str>) -> Checked<String> {
    match (v, default) {
        (None, Some(d)) => Ok(d.into()),
        (Some(Value::String(m)), _) if m == "form" || m == "basic" => Ok(m.clone()),
        _ => issue("auth", "Invalid enum value"),
    }
}

pub fn login_vm_ids(v: Option<&Value>, min: usize) -> Checked<Vec<String>> {
    let Some(Value::Array(a)) = v else {
        return issue("vmIds", "Expected array");
    };
    if a.len() > 100 || a.len() < min {
        return issue("vmIds", "Tick at least one agent");
    }
    a.iter()
        .map(|x| match x.as_str() {
            Some(s) if (1..=100).contains(&len16(s)) => Ok(s.to_string()),
            _ => issue("vmIds", "Expected string"),
        })
        .collect()
}

/// Why the firewall will not match this path (`_plain_path` in addon.py), or None.
pub fn odd_path_reason(path: &str) -> Option<&'static str> {
    static ENCODED: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)%(2f|5c|2e|00|25|3b|23|3f)"));
    if path.contains('\\') {
        return Some("it has a backslash");
    }
    if path.contains(';') {
        return Some("it has a ;");
    }
    if path.contains('#') {
        return Some("it has a #");
    }
    if path.contains("//") {
        return Some("it has a doubled /");
    }
    if ENCODED.is_match(path) {
        return Some("it has an encoded /, \\, ., ;, #, ? or %");
    }
    if path.split('/').any(|s| s == "." || s == "..") {
        return Some("it has a . or .. part");
    }
    None
}

/// What is wrong with the query of a sign-in address, or None (`_strict_pairs` in addon.py).
pub fn query_problem(query: &str) -> Option<String> {
    static NAME: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_.-]{1,64}$"));
    if query.is_empty() {
        return Some("Leave out the ? when nothing follows it".into());
    }
    if query.chars().any(|c| !('\x21'..='\x7e').contains(&c) || c == ';') {
        return Some("The part after ? has a space, a ; or a character that has to be percent-encoded".into());
    }
    let mut seen: Vec<String> = Vec::new();
    for piece in query.split('&') {
        let Some(eq) = piece.find('=') else {
            return Some("Every part after ? has to be name=value".into());
        };
        let dec = |s: &str| crate::integrations::connectors::parse::decode_uri_component(&s.replace('+', " "));
        let (Some(name), Some(_)) = (dec(&piece[..eq]), dec(&piece[eq + 1..])) else {
            return Some("The part after ? is not valid percent-encoding".into());
        };
        if !NAME.is_match(&name) {
            let short = crate::integrations::connectors::firewall::js_slice(&name, 20);
            return Some(format!(
                "The firewall does not match a query name like \"{short}\": use letters, digits, _ . and - only"
            ));
        }
        let fold = name.to_lowercase().replace('.', "_");
        if seen.contains(&fold) {
            return Some(format!("The query names \"{name}\" twice"));
        }
        seen.push(fold);
    }
    None
}

/// What is wrong with a sign-in page address, or None (`_sign_in_address` in addon.py).
pub fn sign_in_page_problem(url: Option<&str>) -> Option<String> {
    const EXAMPLE: &str = "Use the https address of the page with the password field, such as https://github.com/login";
    static SHAPE: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^https://[^/?#@\s\\]+(?:[/?]|$)"));
    static ORIGIN: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^https://[^/?]+"));
    let Some(url) = url.filter(|u| !u.is_empty()) else {
        return Some(EXAMPLE.into());
    };
    if url.chars().any(char::is_whitespace) {
        return Some("The address has a space in it".into());
    }
    if !url.to_ascii_lowercase().starts_with("https://") {
        return Some(format!("{EXAMPLE}. A password is never put into a plain http page"));
    }
    if !SHAPE.is_match(url) {
        return Some(EXAMPLE.into());
    }
    if url.contains('#') {
        return Some("Leave out the part after #".into());
    }
    // The path as written: `new URL` would tidy `/a/../b` and `\` away, and the firewall does not.
    let rest = ORIGIN.replace(url, "");
    let path = rest.split('?').next().filter(|p| !p.is_empty()).unwrap_or("/");
    if let Some(odd) = odd_path_reason(path) {
        return Some(format!("The firewall does not match this path: {odd}"));
    }
    if let Some(i) = url.find('?')
        && let Some(q) = query_problem(&url[i + 1..])
    {
        return Some(q);
    }
    match url::Url::parse(url) {
        Ok(u) if !u.username().is_empty() || u.password().is_some() => {
            Some("Leave out the user name and password".into())
        }
        Ok(u) if u.host_str().is_some_and(|h| HOST.is_match(h)) => None,
        _ => Some(EXAMPLE.into()),
    }
}

pub fn sign_in_page_ok(url: Option<&str>) -> bool {
    sign_in_page_problem(url).is_none()
}

/// `signInPage`: a login URL that is also a sign-in page this firewall can match.
pub fn sign_in_page(s: &str) -> Checked<String> {
    let u = login_url(s, "loginUrl")?;
    match sign_in_page_problem(Some(&u)) {
        Some(p) => issue("loginUrl", &p),
        None => Ok(u),
    }
}

/// What is wrong with an extra sign-in address, or None.
pub fn sign_in_path_problem(p: &str) -> Option<String> {
    static SHAPE: LazyLock<Regex> = LazyLock::new(|| re(r"^((?:[^\s/?#]+\.)+[^\s/?#.]+)?(/[^\s#]*)$"));
    let Some(m) = SHAPE.captures(p) else {
        return Some("Use a path such as /session, or a site and a path such as api.example.com/auth/login".into());
    };
    if let Some(host) = m.get(1) {
        let ok = url::Url::parse(&format!("https://{}", host.as_str()))
            .ok()
            .and_then(|u| u.host_str().map(|h| HOST.is_match(h)))
            .unwrap_or(false);
        if !ok {
            return Some("The site before the path is not a host name".into());
        }
    }
    let full = m.get(2).map(|g| g.as_str()).unwrap_or_default();
    let mut path = full.split('?').next().unwrap_or_default().to_string();
    if let Some(i) = full.find('?')
        && let Some(q) = query_problem(&full[i + 1..])
    {
        return Some(q);
    }
    if path.ends_with("/*") {
        if full.contains('?') {
            return Some("An address ending in /* cannot have a ?query".into());
        }
        path.pop();
        if path == "/" {
            return Some("/* is the whole site. Name the folder the sign-in is in, such as /auth/*".into());
        }
    }
    if path == "/" {
        return Some("The top page of a site is not a sign-in address".into());
    }
    if path.contains('*') {
        return Some("A * is only allowed as /* at the very end".into());
    }
    odd_path_reason(&path).map(|odd| format!("The firewall does not match this path: {odd}"))
}

pub fn sign_in_paths(v: Option<&Value>) -> Checked<Vec<String>> {
    let Some(v) = v else { return Ok(vec![]) };
    let Value::Array(a) = v else {
        return issue("signInPaths", "Expected array");
    };
    if a.len() > 10 {
        return issue("signInPaths", "At most 10 addresses");
    }
    a.iter()
        .map(|x| {
            let s = js::trim(string(Some(x), "signInPaths")?).to_string();
            if !(1..=512).contains(&len16(&s)) || !no_controls(&s) {
                return issue("signInPaths", "Use one line of text");
            }
            match sign_in_path_problem(&s) {
                Some(p) => issue("signInPaths", &p),
                None => Ok(s),
            }
        })
        .collect()
}

/// `hostWithin`: `next` is `previous` or under it.
fn host_within(next: &str, previous: &str) -> bool {
    next == previous || (previous.starts_with("*.") && next.ends_with(&previous[1..]) && next != &previous[2..])
}

/// True when `next` reaches a site or an agent `previous` did not.
pub fn login_widens(
    prev_sites: &[String],
    prev_vms: &[String],
    prev_mode: &str,
    sites: &[String],
    vms: &[String],
    mode: &str,
) -> bool {
    (mode == "type" && prev_mode != "type")
        || vms.iter().any(|v| !prev_vms.contains(v))
        || sites.iter().any(|s| !prev_sites.iter().any(|old| host_within(s, old)))
}

/// Whether `host` is one of `sites` (exact, or under a `*.` entry).
pub fn site_matches(sites: &[String], host: &str) -> bool {
    let h = host.to_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    sites.iter().any(|s| match s.strip_prefix("*.") {
        Some(rest) => h.ends_with(&s[1..]) && h != rest,
        None => h == s,
    })
}

/// `loginEntry`: what the page posts to create or replace a login.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub sites: Vec<String>,
    pub login_url: Option<String>,
    pub username: String,
    pub password: String,
    pub vm_ids: Vec<String>,
    pub mode: String,
    pub auth: String,
    pub sign_in_paths: Vec<String>,
    pub totp: Option<String>,
    pub remove_totp: bool,
    pub request_id: Option<String>,
}

fn optional_url(o: &Map<String, Value>, k: &str) -> Checked<Option<String>> {
    match o.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => Ok(Some(sign_in_page(string(Some(v), k)?)?)),
    }
}

pub fn parse_entry(v: &Value) -> Checked<Entry> {
    let Some(o) = v.as_object() else {
        return issue("", "Expected object");
    };
    let totp = match o.get("totp") {
        None => None,
        Some(t) => {
            let s = js::trim(string(Some(t), "totp")?).to_string();
            if len16(&s) > 1024 {
                return issue("totp", "Too long");
            }
            Some(s).filter(|s| !s.is_empty())
        }
    };
    let request_id = match o.get("requestId") {
        None => None,
        Some(r) => {
            let s = string(Some(r), "requestId")?;
            if !REQUEST_ID.is_match(s) {
                return issue("requestId", "Invalid");
            }
            Some(s.to_string())
        }
    };
    Ok(Entry {
        name: login_name(o.get("name"))?,
        sites: login_sites(o.get("sites"))?,
        login_url: optional_url(o, "loginUrl")?,
        username: login_username(o.get("username"))?,
        password: login_password(o.get("password"))?,
        vm_ids: login_vm_ids(o.get("vmIds"), 1)?,
        mode: login_mode(o.get("mode"), Some("swap"))?,
        auth: login_auth(o.get("auth"), Some("form"))?,
        sign_in_paths: sign_in_paths(o.get("signInPaths"))?,
        totp,
        remove_totp: o.get("removeTotp").and_then(Value::as_bool).unwrap_or(false),
        request_id,
    })
}

/// `loginScopeEdit`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScopeEdit {
    pub id: String,
    /// None: not given; Some(None): cleared.
    pub login_url: Option<Option<String>>,
    pub auth: Option<String>,
    pub sign_in_paths: Vec<String>,
    pub approve: Vec<String>,
    pub forget: Vec<String>,
}

fn url_list(v: Option<&Value>, path: &str) -> Checked<Vec<String>> {
    let Some(v) = v else { return Ok(vec![]) };
    let Value::Array(a) = v else {
        return issue(path, "Expected array");
    };
    if a.len() > LEARNED_TARGETS_MAX {
        return issue(path, "Too many");
    }
    a.iter()
        .map(|x| {
            let s = string(Some(x), path)?;
            if len16(s) > 2048 {
                return issue(path, "Too long");
            }
            Ok(s.to_string())
        })
        .collect()
}

pub fn parse_scope_edit(v: &Value) -> Checked<ScopeEdit> {
    let Some(o) = v.as_object() else {
        return issue("", "Expected object");
    };
    let id = string(o.get("id"), "id")?;
    if !LOGIN_ID.is_match(id) {
        return issue("id", "Invalid");
    }
    let Some(paths) = o.get("signInPaths") else {
        return issue("signInPaths", "Required");
    };
    Ok(ScopeEdit {
        id: id.into(),
        login_url: if o.contains_key("loginUrl") {
            Some(optional_url(o, "loginUrl")?)
        } else {
            None
        },
        auth: match o.get("auth") {
            None => None,
            v => Some(login_auth(v, None)?),
        },
        sign_in_paths: sign_in_paths(Some(paths))?,
        approve: url_list(o.get("approve"), "approve")?,
        forget: url_list(o.get("forget"), "forget")?,
    })
}

/// `loginChange`: what the console may change.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Update {
        id: String,
        name: String,
        sites: Vec<String>,
        vm_ids: Vec<String>,
        mode: Option<String>,
    },
    Delete {
        id: String,
    },
}

pub fn parse_change(o: &Map<String, Value>) -> Checked<Change> {
    let id = string(o.get("id"), "id")?;
    if !LOGIN_ID.is_match(id) {
        return issue("id", "Invalid");
    }
    match o.get("action").and_then(Value::as_str) {
        Some("delete") => Ok(Change::Delete { id: id.into() }),
        Some("update") => Ok(Change::Update {
            id: id.into(),
            name: login_name(o.get("name"))?,
            sites: login_sites(o.get("sites"))?,
            vm_ids: login_vm_ids(o.get("vmIds"), 0)?,
            mode: match o.get("mode") {
                None => None,
                v => Some(login_mode(v, None)?),
            },
        }),
        _ => issue("action", "Invalid discriminator value"),
    }
}

/// One row of a CSV import, after the page read it.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportRow {
    pub name: String,
    pub sites: Vec<String>,
    pub login_url: Option<String>,
    pub username: String,
    pub password: String,
    pub totp: Option<String>,
}

pub fn parse_import_row(v: &Value) -> Checked<ImportRow> {
    let Some(o) = v.as_object() else {
        return issue("", "Expected object");
    };
    Ok(ImportRow {
        name: login_name(o.get("name"))?,
        sites: login_sites(o.get("sites"))?,
        login_url: match o.get("loginUrl") {
            None | Some(Value::Null) => None,
            Some(u) => Some(login_url(string(Some(u), "loginUrl")?, "loginUrl")?),
        },
        username: login_username(o.get("username"))?,
        password: login_password(o.get("password"))?,
        totp: match o.get("totp") {
            None => None,
            Some(t) => {
                let s = js::trim(string(Some(t), "totp")?).to_string();
                if len16(&s) > 1024 {
                    return issue("totp", "Too long");
                }
                Some(s)
            }
        },
    })
}

/// `loginImport`: up to 200 rows, checked one by one later, and the agents.
pub fn parse_import(v: &Value) -> Checked<(Vec<Value>, Vec<String>)> {
    let Some(o) = v.as_object() else {
        return issue("", "Expected object");
    };
    let Some(Value::Array(rows)) = o.get("rows") else {
        return issue("rows", "Expected array");
    };
    if rows.is_empty() || rows.len() > 200 {
        return issue("rows", "1 to 200 rows");
    }
    Ok((rows.clone(), login_vm_ids(o.get("vmIds"), 1)?))
}

/// `onePasswordConnect`.
pub struct OpConnect {
    pub token: String,
    pub vault_ids: Vec<String>,
    pub vm_ids: Vec<String>,
}

/// The token part of `onePasswordConnect`.
pub fn op_token(s: &str) -> Checked<String> {
    static TOKEN: LazyLock<Regex> = LazyLock::new(|| re(r"^ops_[A-Za-z0-9+/=_-]+$"));
    let t = js::trim(s).to_string();
    if !(20..=4096).contains(&len16(&t)) || !TOKEN.is_match(&t) {
        return issue("token", "Paste a service account token: it starts with ops_.");
    }
    Ok(t)
}

pub fn parse_op_connect(v: &Value) -> Checked<OpConnect> {
    static VAULT: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9]{10,40}$"));
    let Some(o) = v.as_object() else {
        return issue("", "Expected object");
    };
    let token = op_token(string(o.get("token"), "token")?)?;
    let Some(Value::Array(vaults)) = o.get("vaultIds") else {
        return issue("vaultIds", "Expected array");
    };
    if vaults.is_empty() || vaults.len() > 20 {
        return issue("vaultIds", "Pick a vault");
    }
    let vault_ids = vaults
        .iter()
        .map(|x| match x.as_str() {
            Some(s) if VAULT.is_match(s) => Ok(s.to_string()),
            _ => issue("vaultIds", "Invalid"),
        })
        .collect::<Checked<Vec<_>>>()?;
    Ok(OpConnect {
        token,
        vault_ids,
        vm_ids: login_vm_ids(o.get("vmIds"), 1)?,
    })
}

/// `loginRequestInput`: what an agent asks for with `login_request`.
pub struct RequestInput {
    pub site: String,
    pub kind: String,
    pub reason: String,
    pub url: Option<String>,
    pub task: Option<String>,
}

pub fn parse_request_input(v: &Value) -> Option<RequestInput> {
    static SCHEME: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)^[a-z][a-z0-9+.-]*://"));
    let o = v.as_object()?;
    let raw = js::trim(o.get("site")?.as_str()?).to_string();
    if len16(&raw) > 2048 {
        return None;
    }
    let host = SCHEME.replace(&raw, "");
    let host = host.split(['/', '?', '#']).next().unwrap_or_default().to_lowercase();
    let site = login_site(&host).ok()?;
    let kind = match o.get("kind") {
        None => "password".to_string(),
        Some(Value::String(k)) if k == "password" || k == "session" => k.clone(),
        _ => return None,
    };
    let reason = match o.get("reason") {
        None => String::new(),
        Some(Value::String(r)) => {
            let r = js::trim(r).to_string();
            if len16(&r) > 200 || !no_controls(&r) {
                return None;
            }
            r
        }
        _ => return None,
    };
    // `.catch(undefined)`: a url or task that does not fit is dropped, not a refusal.
    let url = o
        .get("url")
        .and_then(Value::as_str)
        .and_then(|u| login_url(u, "url").ok());
    let task = o.get("task").and_then(Value::as_str).and_then(|t| {
        let t = js::trim(t).to_string();
        (len16(&t) <= 300 && no_controls(&t)).then_some(t)
    });
    Some(RequestInput {
        site,
        kind,
        reason,
        url,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_in_pages_and_paths_as_the_proxy_reads_them() {
        assert_eq!(sign_in_page_problem(Some("https://github.com/login")), None);
        assert!(
            sign_in_page_problem(Some("http://github.com/login"))
                .expect("p")
                .contains("plain http")
        );
        assert_eq!(
            sign_in_page_problem(Some("https://github.com/a/../login")).as_deref(),
            Some("The firewall does not match this path: it has a . or .. part")
        );
        assert_eq!(
            sign_in_page_problem(Some("https://github.com/%2e/login")).as_deref(),
            Some("The firewall does not match this path: it has an encoded /, \\, ., ;, #, ? or %")
        );
        assert_eq!(
            sign_in_page_problem(Some("https://github.com/login?a=1&a=2")).as_deref(),
            Some("The query names \"a\" twice")
        );
        assert_eq!(
            sign_in_page_problem(Some("https://u:p@github.com/login")).as_deref(),
            Some("Use the https address of the page with the password field, such as https://github.com/login")
        );
        assert_eq!(sign_in_path_problem("/session"), None);
        assert_eq!(sign_in_path_problem("api.example.com/auth/*"), None);
        assert_eq!(
            sign_in_path_problem("/*").as_deref(),
            Some("/* is the whole site. Name the folder the sign-in is in, such as /auth/*")
        );
        assert_eq!(
            sign_in_path_problem("/").as_deref(),
            Some("The top page of a site is not a sign-in address")
        );
        assert_eq!(
            sign_in_path_problem("/a*b").as_deref(),
            Some("A * is only allowed as /* at the very end")
        );
        assert_eq!(
            query_problem("x=1;y=2").as_deref(),
            Some("The part after ? has a space, a ; or a character that has to be percent-encoded")
        );
    }

    #[test]
    fn sites_widening_and_matching() {
        assert_eq!(login_site(" GitHub.com "), Ok("github.com".into()));
        assert!(login_site("not a host").is_err());
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(site_matches(&s(&["*.example.com"]), "a.example.com"));
        assert!(!site_matches(&s(&["*.example.com"]), "example.com"));
        assert!(site_matches(&s(&["github.com"]), "GitHub.com."));
        assert!(!login_widens(
            &s(&["*.example.com"]),
            &s(&["vm"]),
            "swap",
            &s(&["a.example.com"]),
            &s(&["vm"]),
            "swap"
        ));
        assert!(login_widens(
            &s(&["a.example.com"]),
            &s(&["vm"]),
            "swap",
            &s(&["*.example.com"]),
            &s(&["vm"]),
            "swap"
        ));
        assert!(login_widens(
            &s(&["x.com"]),
            &s(&["vm"]),
            "swap",
            &s(&["x.com"]),
            &s(&["vm", "vm2"]),
            "swap"
        ));
        assert!(login_widens(
            &s(&["x.com"]),
            &s(&["vm"]),
            "swap",
            &s(&["x.com"]),
            &s(&["vm"]),
            "type"
        ));
    }

    #[test]
    fn entries_and_requests() {
        let e = parse_entry(&json!({"name": "GitHub", "sites": ["github.com"], "loginUrl": "https://github.com/login", "username": "ana", "password": "pw", "vmIds": ["vm-a"]})).expect("entry");
        assert_eq!((e.mode.as_str(), e.auth.as_str()), ("swap", "form"));
        let bad = parse_entry(
            &json!({"name": "GitHub", "sites": ["github.com"], "loginUrl": "http://github.com/login", "username": "", "password": "pw", "vmIds": ["vm-a"]}),
        );
        assert_eq!(bad.expect_err("refused").path, "loginUrl");
        let r =
            parse_request_input(&json!({"site": "https://GitHub.com/login?x", "reason": "deploys"})).expect("request");
        assert_eq!((r.site.as_str(), r.kind.as_str()), ("github.com", "password"));
        assert!(parse_request_input(&json!({"site": "not a host"})).is_none());
        let dropped = parse_request_input(&json!({"site": "github.com", "url": "javascript:x"})).expect("request");
        assert!(
            dropped.url.is_none(),
            "a url that does not fit is dropped, not a refusal"
        );
    }
}
