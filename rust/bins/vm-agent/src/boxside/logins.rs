//! Website logins in the agent's browser (`logins.ts`, `routes/logins.ts`). The org firewall asks
//! (purpose `logins`) to open a site in a new tab for a person to sign the agent in, to tell the
//! agent a login request was answered, to type a password into the focused password field of one
//! of a login's sites, or to sign the agent out of some sites. Everything goes to Chrome's DevTools
//! port on loopback. The password is in this process for that one call: never logged, never sent
//! back; a cookie's value is never read back either, only a count.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Req, Resp};
use futures_util::{SinkExt, StreamExt};
use regex::Regex;
use serde_json::{Map, Value, json};
use tokio_tungstenite::tungstenite::Message;
use zeroize::{Zeroize, Zeroizing};

use super::web::{self, send_json};

const CALL: Duration = Duration::from_secs(10);
/// The whole of `/logins/type`, under the firewall's 25 s wait (`AGENT_CALL_MS`), so the box always
/// answers first. Intentional difference: the TS has no overall limit, and a few frozen tabs (up to
/// five 10 s calls each) outlasted the firewall.
const TYPE_LIMIT: Duration = Duration::from_secs(20);
const TOO_LONG: &str = "the browser took too long";

/// Every string in `v` overwritten with zeros: what a DevTools call carried (a password).
fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Array(a) => a.iter_mut().for_each(wipe),
        Value::Object(o) => o.values_mut().for_each(wipe),
        _ => {}
    }
}

/// A site as the firewall sends it: an exact host or `*.example.com`. A name, never an address.
static SITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
        .expect("regex")
});
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new("[\u{0}-\u{1f}\u{7f}]").expect("regex"));

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `parseOpenTab`: an https URL on a named host; the URL as the WHATWG parser writes it back.
pub fn parse_open_tab(raw: Option<&Map<String, Value>>) -> Option<String> {
    let url = raw?.get("url")?.as_str()?;
    if utf16_len(url) > 2048 {
        return None;
    }
    let u = url::Url::parse(url).ok()?;
    (u.scheme() == "https" && u.host_str().is_some_and(|h| SITE.is_match(h))).then(|| u.to_string())
}

/// A person answered the agent's login request: what the firewall says about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Answered {
    pub request_id: String,
    pub site: String,
    pub login: String,
    pub kind: String,
    pub url: Option<String>,
    /// UTF-16, as the TS cut it at 300 units (which may split a surrogate pair).
    pub task: Option<Vec<u16>>,
}

/// `parseAnswered`.
pub fn parse_answered(raw: Option<&Map<String, Value>>) -> Option<Answered> {
    static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^lr_[A-Za-z0-9_-]{8,40}$").expect("regex"));
    static URL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(&format!(r"^https://[^{}]+$", web::JS_SPACE_CLASS)).expect("regex"));
    static CONTROLS: LazyLock<Regex> = LazyLock::new(|| Regex::new("[\u{0}-\u{1f}\u{7f}]+").expect("regex"));
    let r = raw?;
    let s = |k: &str| r.get(k).and_then(Value::as_str);
    let request_id = s("requestId").filter(|i| ID.is_match(i))?;
    let site = s("site").filter(|x| SITE.is_match(x))?;
    let login = s("login").filter(|l| !l.is_empty() && utf16_len(l) <= 64 && !CONTROL.is_match(l))?;
    let kind = s("kind").filter(|k| *k == "password" || *k == "session")?;
    let url = s("url")
        .filter(|u| utf16_len(u) <= 2048 && URL.is_match(u))
        .map(str::to_string);
    let task = s("task").map(|t| {
        let one = CONTROLS.replace_all(t, " ");
        web::js_trim(&one).encode_utf16().take(300).collect::<Vec<u16>>()
    });
    Some(Answered {
        request_id: request_id.into(),
        site: site.into(),
        login: login.into(),
        kind: kind.into(),
        url,
        task: task.filter(|t| !t.is_empty()),
    })
}

fn quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// `answeredMessage`: the turn the agent gets when its login request is answered.
pub fn answered_message(a: &Answered) -> String {
    let where_ = a.url.clone().unwrap_or_else(|| format!("https://{}/", a.site));
    let then = a
        .task
        .as_deref()
        .map(|t| format!(" Then do what you asked for it for: {}.", web::json_quote_utf16(t)))
        .unwrap_or_default();
    let start = if a.kind == "session" {
        format!(
            "A person signed you in to {} themselves, in your browser. Open {where_} in your browser.",
            a.site
        )
    } else {
        format!(
            "A person answered your login request for {}: the login {} is ready. Open {where_} in your browser and sign in with login_use (type the username and the placeholder it gives you, never ask for the password).",
            a.site,
            quoted(&a.login)
        )
    };
    format!(
        "{start}{then} Then send the person who answered, in the chat where you sent them the link, a screenshot of the signed-in page and one sentence on what you did."
    )
}

/// `parseClearCookies`: one to twenty sites, lowercased.
pub fn parse_clear_cookies(raw: Option<&Map<String, Value>>) -> Option<Vec<String>> {
    let sites = raw?.get("sites")?.as_array()?;
    if sites.is_empty() || sites.len() > 20 {
        return None;
    }
    let clean: Vec<String> = sites
        .iter()
        .map(|s| s.as_str().map(str::to_lowercase).unwrap_or_default())
        .collect();
    clean.iter().all(|s| SITE.is_match(s)).then_some(clean)
}

/// `parseType`: a password with no control characters, and the login's sites.
pub fn parse_type(raw: Option<&Map<String, Value>>) -> Option<(Zeroizing<String>, Vec<String>)> {
    let password = raw?.get("password")?.as_str()?;
    let sites = parse_clear_cookies(raw);
    if password.is_empty() || utf16_len(password) > 1024 || CONTROL.is_match(password) {
        return None;
    }
    Some((Zeroizing::new(password.to_string()), sites?))
}

/// `hostIsSite`: exact, or under a `*.` site (not the bare base).
pub fn host_is_site(host: &str, sites: &[String]) -> bool {
    let h = host.to_lowercase();
    let h = h.strip_suffix('.').unwrap_or(&h);
    sites.iter().any(|s| match s.strip_prefix("*.") {
        Some(base) => h.ends_with(&s[1..]) && h != base,
        None => h == s,
    })
}

/// `cookieReaches`: a cookie for a parent domain is sent to the site too, so it goes with it.
/// Intentional difference for a `*.` site: the TS took only cookies under the base, so one on the
/// base or a parent of it (`.example.com` for `*.example.com`), which the browser sends to every
/// subdomain, survived the sign-out. Here it goes too: whatever the browser would send to one of
/// the site's hosts goes with it, `.example.com` for `*.app.example.com` included. A `*.` site
/// keeps a cookie with no leading dot on its base (`acme.io` for `*.acme.io`): that one is the base
/// host's own and is not sent to subdomains. For an exact site the TS rule stays as it was, which
/// also takes a parent's host-only cookie.
pub fn cookie_reaches(domain: &str, sites: &[String]) -> bool {
    let d = domain.to_lowercase();
    let dotted = d.starts_with('.');
    let d = d.strip_prefix('.').unwrap_or(&d);
    sites.iter().any(|site| match site.strip_prefix("*.") {
        Some(base) => d.ends_with(&format!(".{base}")) || (dotted && (base == d || base.ends_with(&format!(".{d}")))),
        None => site == d || site.ends_with(&format!(".{d}")),
    })
}

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// One DevTools session on the browser endpoint, for a handful of calls made one after another.
struct Cdp {
    ws: Ws,
    next: u64,
    /// While set, no call may run past it (the search for the field in `/logins/type`).
    until: Option<tokio::time::Instant>,
}

/// Counts what a serializer writes, so the message can be written into a buffer of exactly that
/// size and no partly-filled copy is ever freed with the password in it.
struct Count(usize);

impl std::io::Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len();
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Cdp {
    async fn open(base: &str, http: &reqwest::Client) -> Result<Self, String> {
        let version: Value = http
            .get(format!("{base}/json/version"))
            .timeout(CALL)
            .send()
            .await
            .map_err(|_| "the browser did not answer".to_string())?
            .json()
            .await
            .map_err(|_| "the browser did not answer".to_string())?;
        let Some(ws_url) = version
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .filter(|u| !u.is_empty())
        else {
            return Err("the browser has no DevTools endpoint".into());
        };
        let (ws, _) = tokio::time::timeout(CALL, tokio_tungstenite::connect_async(ws_url))
            .await
            .map_err(|_| "the browser's DevTools endpoint did not answer".to_string())?
            .map_err(|_| "the browser's DevTools endpoint did not answer".to_string())?;
        Ok(Self {
            ws,
            next: 0,
            until: None,
        })
    }

    /// One call; events and answers to calls that already timed out are passed over.
    async fn send(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value, String> {
        self.call(method, params, session, false).await
    }

    /// A call that carries the password: its copies are wiped once sent. The frame the WebSocket
    /// library builds from it is the library's own and cannot be reached from here.
    async fn send_secret(&mut self, method: &str, params: Value, session: Option<&str>) -> Result<Value, String> {
        self.call(method, params, session, true).await
    }

    async fn call(
        &mut self,
        method: &str,
        params: Value,
        session: Option<&str>,
        secret: bool,
    ) -> Result<Value, String> {
        let limit = match self.until {
            Some(until) => {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() {
                    return Err(format!("{method} timed out"));
                }
                left.min(CALL)
            }
            None => CALL,
        };
        self.next += 1;
        let id = self.next;
        let mut msg = json!({"id": id, "method": method, "params": params});
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let sent = if secret {
            let mut n = Count(0);
            let _ = serde_json::to_writer(&mut n, &msg);
            let mut buf = Zeroizing::new(Vec::with_capacity(n.0));
            let _ = serde_json::to_writer(&mut *buf, &msg);
            wipe(&mut msg);
            // Valid UTF-8 (serde wrote it), so this borrows; `Message::text` makes the library's copy.
            self.ws
                .send(Message::text(String::from_utf8_lossy(&buf).as_ref()))
                .await
        } else {
            self.ws.send(Message::text(msg.to_string())).await
        };
        sent.map_err(|_| format!("{method} failed"))?;
        let wait = async {
            while let Some(m) = self.ws.next().await {
                let Ok(Message::Text(t)) = m else {
                    if m.is_err() {
                        break;
                    }
                    continue;
                };
                let Ok(v) = serde_json::from_str::<Value>(&t) else {
                    continue;
                };
                if v.get("id").and_then(Value::as_u64) != Some(id) {
                    continue;
                }
                if let Some(e) = v.get("error") {
                    return Err(e
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("DevTools error")
                        .to_string());
                }
                return Ok(v.get("result").cloned().unwrap_or_else(|| json!({})));
            }
            Err("the browser closed DevTools".to_string())
        };
        tokio::time::timeout(limit, wait)
            .await
            .unwrap_or_else(|_| Err(format!("{method} timed out")))
    }

    async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

/// Which element has focus, followed into same-origin iframes and open shadow roots.
const DEEP_ACTIVE: &str = r#"function deepActive(d) {
  let a = d.activeElement;
  for (let i = 0; i < 10 && a; i++) {
    if (a.shadowRoot && a.shadowRoot.activeElement) { a = a.shadowRoot.activeElement; continue; }
    if (a.tagName === "IFRAME") { try { const f = a.contentDocument; if (f && f.activeElement) { a = f.activeElement; continue; } } catch {} }
    break;
  }
  return a;
}"#;

/// Called on the focused element: what it is and the page it belongs to.
const LOOK: &str = r#"function () {
  const loc = this.ownerDocument.location;
  return { focus: document.hasFocus(), field: this.tagName === "INPUT" && this.type === "password", host: loc.hostname, https: loc.protocol === "https:" };
}"#;

/// The focused element of this target's page, as a handle the page cannot see.
static FIND: LazyLock<String> =
    LazyLock::new(|| format!("(() => {{ {DEEP_ACTIVE}; return deepActive(document); }})()"));
/// The check and the typing in one step: nothing can run in the page between them.
static CHECK_AND_TYPE: LazyLock<String> = LazyLock::new(|| {
    check_then(r#"return this.ownerDocument.execCommand("insertText", false, password) ? "typed" : "unsupported";"#)
});
/// The check alone, for the fallback that types as keyboard input.
static CHECK: LazyLock<String> = LazyLock::new(|| check_then(r#"return "same";"#));

/// The check in the page, then `then`; `changed` when it is no longer the focused password field
/// of a page on one of the sites.
fn check_then(then: &str) -> String {
    format!(
        r#"function (password, sites) {{
  {DEEP_ACTIVE}
  let root = this.ownerDocument;
  for (let i = 0; i < 10; i++) {{ const f = root.defaultView && root.defaultView.frameElement; if (!f) break; root = f.ownerDocument; }}
  const loc = this.ownerDocument.location;
  const host = String(loc.hostname).toLowerCase().replace(/\.$/, "");
  const site = sites.some((s) => (s.startsWith("*.") ? host.endsWith(s.slice(1)) && host !== s.slice(2) : host === s));
  if (!this.isConnected || deepActive(root) !== this || !root.hasFocus() || this.tagName !== "INPUT" || this.type !== "password" || loc.protocol !== "https:" || !site) return "changed";
  {then}
}}"#
    )
}

/// `BrowserLogins`.
pub struct BrowserLogins {
    base: String,
    http: reqwest::Client,
    type_limit: Duration,
}

impl Default for BrowserLogins {
    fn default() -> Self {
        let port = std::env::var("BROWSER_CDP_PORT").unwrap_or_else(|_| "9222".into());
        Self::new(format!("http://127.0.0.1:{port}"))
    }
}

/// `type`'s outcome: typed, or why not (`field`, `site`, `changed`).
#[derive(Debug, Clone, PartialEq)]
pub enum Typed {
    Ok,
    Not(&'static str),
}

impl BrowserLogins {
    pub fn new(base: String) -> Self {
        // Loopback only, never through a proxy.
        let http = reqwest::Client::builder().no_proxy().build().unwrap_or_default();
        Self {
            base,
            http,
            type_limit: TYPE_LIMIT,
        }
    }

    #[cfg(test)]
    pub fn with_type_limit(mut self, d: Duration) -> Self {
        self.type_limit = d;
        self
    }

    pub async fn open_tab(&self, url: &str) -> Result<(), String> {
        let mut cdp = Cdp::open(&self.base, &self.http).await?;
        let r = cdp.send("Target.createTarget", json!({"url": url}), None).await;
        cdp.close().await;
        r.map(|_| ())
    }

    /// Type `password` into the focused password field of a page on one of `sites`.
    /// The search for the field has `type_limit` in all; once the field is found the typing
    /// runs to its end (each call still 10 s), so the limit never cuts off a password half typed.
    pub async fn type_password(&self, password: &str, sites: &[String]) -> Result<Typed, String> {
        let until = tokio::time::Instant::now() + self.type_limit;
        let mut cdp = tokio::time::timeout_at(until, Cdp::open(&self.base, &self.http))
            .await
            .unwrap_or_else(|_| Err(TOO_LONG.into()))?;
        cdp.until = Some(until);
        let r = Self::type_in(&mut cdp, password, sites).await;
        cdp.close().await;
        r
    }

    async fn type_in(cdp: &mut Cdp, password: &str, sites: &[String]) -> Result<Typed, String> {
        let targets = cdp.send("Target.getTargets", json!({}), None).await?;
        let mut wrong_site = false;
        let infos: Vec<Value> = targets
            .get("targetInfos")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        // Pages, and out-of-process iframes (a sign-in form on another origin is its own target).
        for t in infos
            .iter()
            .filter(|i| matches!(i["type"].as_str(), Some("page" | "iframe")))
        {
            if cdp.until.is_some_and(|u| tokio::time::Instant::now() >= u) {
                return Err(TOO_LONG.into());
            }
            let mut session: Option<String> = None;
            let mut found = false;
            let attempt: Result<Option<Typed>, String> = async {
                let attached = cdp
                    .send(
                        "Target.attachToTarget",
                        json!({"targetId": t["targetId"], "flatten": true}),
                        None,
                    )
                    .await?;
                session = attached["sessionId"].as_str().map(str::to_string);
                let sid = session.as_deref();
                let focused = cdp
                    .send(
                        "Runtime.evaluate",
                        json!({"expression": *FIND, "returnByValue": false}),
                        sid,
                    )
                    .await?;
                let Some(object_id) = focused["result"]["objectId"].as_str().map(str::to_string) else {
                    return Ok(None);
                };
                let look = cdp
                    .send(
                        "Runtime.callFunctionOn",
                        json!({"objectId": object_id, "functionDeclaration": LOOK, "returnByValue": true}),
                        sid,
                    )
                    .await?;
                let v = &look["result"]["value"];
                if v["field"] != Value::Bool(true) || v["focus"] != Value::Bool(true) {
                    return Ok(None);
                }
                if v["https"] != Value::Bool(true) || !host_is_site(v["host"].as_str().unwrap_or(""), sites) {
                    wrong_site = true;
                    return Ok(None);
                }
                found = true;
                // From here the typing runs to its end.
                cdp.until = None;
                let typed = cdp
                    .send_secret(
                        "Runtime.callFunctionOn",
                        json!({"objectId": object_id, "functionDeclaration": *CHECK_AND_TYPE,
                               "arguments": [{"value": password}, {"value": sites}], "returnByValue": true}),
                        sid,
                    )
                    .await?;
                match typed["result"]["value"].as_str() {
                    Some("typed") => return Ok(Some(Typed::Ok)),
                    Some("unsupported") => {}
                    _ => return Ok(Some(Typed::Not("changed"))),
                }
                // The page does not take inserted text from a script: check once more, then type
                // it as keyboard input; two steps, back to back.
                let again = cdp
                    .send(
                        "Runtime.callFunctionOn",
                        json!({"objectId": object_id, "functionDeclaration": *CHECK,
                               "arguments": [{"value": ""}, {"value": sites}], "returnByValue": true}),
                        sid,
                    )
                    .await?;
                if again["result"]["value"] != json!("same") {
                    return Ok(Some(Typed::Not("changed")));
                }
                cdp.send_secret("Input.insertText", json!({"text": password}), sid)
                    .await?;
                Ok(Some(Typed::Ok))
            }
            .await;
            if let Some(sid) = session {
                let _ = cdp
                    .send("Target.detachFromTarget", json!({"sessionId": sid}), None)
                    .await;
            }
            match attempt {
                Ok(Some(done)) => return Ok(done),
                Ok(None) => {}
                // Once the field was found, an error means the page went away under us.
                Err(_) if found => return Ok(Typed::Not("changed")),
                // A tab stuck on a dialog, frozen or discarded: not the one with the field.
                Err(_) => {}
            }
        }
        Ok(Typed::Not(if wrong_site { "site" } else { "field" }))
    }

    /// Remove every cookie that reaches one of `sites`, and each exact site's other storage.
    pub async fn clear_cookies(&self, sites: &[String]) -> Result<usize, String> {
        let mut cdp = Cdp::open(&self.base, &self.http).await?;
        let r = Self::clear_in(&mut cdp, sites).await;
        cdp.close().await;
        r
    }

    async fn clear_in(cdp: &mut Cdp, sites: &[String]) -> Result<usize, String> {
        let all = cdp.send("Storage.getCookies", json!({}), None).await?;
        let doomed: Vec<Value> = all
            .get("cookies")
            .and_then(Value::as_array)
            .map(|c| {
                c.iter()
                    .filter(|c| cookie_reaches(&web::js_string(&c["domain"]), sites))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for site in sites.iter().filter(|s| !s.starts_with("*.")) {
            let _ = cdp
                .send(
                    "Storage.clearDataForOrigin",
                    json!({"origin": format!("https://{site}"), "storageTypes": "local_storage,indexeddb,service_workers,cache_storage"}),
                    None,
                )
                .await;
        }
        if doomed.is_empty() {
            return Ok(0);
        }
        // Deleting one cookie needs a page session: a blank tab, made and closed for it.
        let made = cdp
            .send("Target.createTarget", json!({"url": "about:blank"}), None)
            .await?;
        let target = made["targetId"].clone();
        // Every cookie is tried, one refusal not stopping the rest; what went is read back below.
        let mut refused = false;
        let attached = cdp
            .send(
                "Target.attachToTarget",
                json!({"targetId": target, "flatten": true}),
                None,
            )
            .await;
        match &attached {
            Ok(a) => {
                let sid = a["sessionId"].as_str().map(str::to_string);
                for c in &doomed {
                    let mut params = json!({"name": c["name"], "domain": c["domain"], "path": c["path"]});
                    // A partitioned cookie is deleted only with its partition named, in the shape
                    // this browser gave it.
                    if let Some(k) = c.get("partitionKey").filter(|k| !k.is_null()) {
                        params["partitionKey"] = k.clone();
                    }
                    refused |= cdp.send("Network.deleteCookies", params, sid.as_deref()).await.is_err();
                }
            }
            Err(_) => refused = true,
        }
        let _ = cdp.send("Target.closeTarget", json!({"targetId": target}), None).await;
        // The count is what is gone, read back, not what was asked for. Intentional difference: the
        // TS counted every cookie it asked to delete, a partitioned one it could not included.
        let key = |c: &Value| {
            json!([
                c["name"],
                c["domain"],
                c["path"],
                c.get("partitionKey").cloned().unwrap_or(Value::Null)
            ])
            .to_string()
        };
        match cdp.send("Storage.getCookies", json!({}), None).await {
            Ok(after) => {
                let left: std::collections::HashSet<String> = after
                    .get("cookies")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(key).collect())
                    .unwrap_or_default();
                let gone = doomed.iter().filter(|c| !left.contains(&key(c))).count();
                if refused && gone == 0 {
                    return Err("the browser refused to delete the cookies".into());
                }
                Ok(gone)
            }
            // Nothing refused and the jar cannot be read back: every delete was taken.
            Err(_) if !refused => {
                tracing::info!("[logins] the cookies were deleted but could not be read back to count");
                Ok(doomed.len())
            }
            Err(e) => Err(e),
        }
    }
}

/// `handleLogins`: firewall-signed (`logins`), POST only.
pub async fn handle(
    app: &crate::app::App,
    browser: &BrowserLogins,
    wake: Option<Arc<super::gmail::GmailWake>>,
    req: Req,
) -> Resp {
    let read = if req.method() == http::Method::POST {
        ReadBody::Json { limit: 16384 }
    } else {
        ReadBody::No
    };
    let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "logins", 0, read).await {
        FirewallRequest::Accepted { parts, body, .. } => (parts, body),
        FirewallRequest::Refused { .. } => {
            return send_json(
                401,
                &json!({"error": "Login changes must come from the org firewall"}),
                &[],
            );
        }
    };
    if parts.method != http::Method::POST {
        return send_json(405, &json!({"error": "Method not allowed"}), &[]);
    }
    let mut raw = match body {
        FirewallBody::Json(b) => Some(b),
        _ => None,
    };
    // Never echo what the browser said: only that it did not work.
    let unavailable = || send_json(503, &json!({"error": "The agent's browser did not answer."}), &[]);
    let raw_ref = raw.as_ref();
    match cc_http::pathname(&parts.uri.to_string()).as_str() {
        "/logins/open-tab" => {
            let Some(url) = parse_open_tab(raw_ref) else {
                return send_json(400, &json!({"error": "Invalid site"}), &[]);
            };
            match browser.open_tab(&url).await {
                Ok(()) => send_json(200, &json!({"ok": true}), &[]),
                Err(_) => unavailable(),
            }
        }
        "/logins/answered" => {
            let Some(input) = parse_answered(raw_ref) else {
                return send_json(400, &json!({"error": "Invalid request"}), &[]);
            };
            let Some(wake) = wake else {
                return send_json(503, &json!({"error": "The agent is not running."}), &[]);
            };
            match wake
                .submit(
                    &answered_message(&input),
                    "Website logins",
                    &format!("login-{}", input.request_id),
                )
                .await
            {
                Ok((ok, _)) => send_json(if ok { 200 } else { 502 }, &json!({"ok": ok}), &[]),
                Err(_) => unavailable(),
            }
        }
        "/logins/type" => {
            let input = parse_type(raw_ref);
            // The request body's copy of the password is wiped as soon as it is parsed.
            if let Some(p) = raw.as_mut().and_then(|b| b.get_mut("password")) {
                wipe(p);
            }
            let Some((password, sites)) = input else {
                return send_json(400, &json!({"error": "Invalid request"}), &[]);
            };
            match browser.type_password(&password, &sites).await {
                Ok(Typed::Ok) => send_json(200, &json!({"ok": true}), &[]),
                Ok(Typed::Not(reason)) => send_json(200, &json!({"ok": false, "reason": reason}), &[]),
                Err(_) => unavailable(),
            }
        }
        "/logins/clear-cookies" => {
            let Some(sites) = parse_clear_cookies(raw_ref) else {
                return send_json(400, &json!({"error": "Invalid sites"}), &[]);
            };
            match browser.clear_cookies(&sites).await {
                Ok(n) => send_json(200, &json!({"ok": true, "removed": n}), &[]),
                Err(_) => unavailable(),
            }
        }
        _ => send_json(404, &json!({"error": "Not found"}), &[]),
    }
}

#[cfg(test)]
mod tests;
