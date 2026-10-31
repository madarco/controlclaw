//! Joining Meet signed in to the agent's Google account (`meeting-signin.ts`,
//! docs/plans/meetsignin.md).
//!
//! The owner signs in once, by hand, in a Chrome window on this box that has no debugger attached
//! (Google refuses sign-in in a browser started with remote-debugging flags). The session stays in
//! a profile used only for meetings, outside the agent's home so it is in no backup. After that the
//! meeting browser starts on that profile and Meet sees the account.
//!
//! This is the one Google credential that lives on the agent box: a web session, not an API token.
//! It is offered only for the account the organization granted this agent, only from the owner's
//! enrolled Meetings page, and it is removed when that grant goes.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use cc_http::BoxFuture;
use serde_json::{Value, json};

use super::archive::atomic_json;
use super::cdp::{Cdp, debugger_client};
use super::js::{head16, len16};
use crate::boxside::shell::encode_uri_component;
use crate::platform::time::now_iso;

const LIST_ACCOUNTS: &str = "https://accounts.google.com/ListAccounts?gpsia=1&source=ChromiumBrowser&json=standard";

fn same(a: &str, b: &str) -> bool {
    super::js::js_trim(a).to_lowercase() == super::js::js_trim(b).to_lowercase()
}

/// `signinUrl`: Google's account chooser with the address filled in, then Meet.
pub fn signin_url(account: &str) -> String {
    format!(
        "https://accounts.google.com/AccountChooser?Email={}&continue={}",
        encode_uri_component(account),
        encode_uri_component("https://meet.google.com/")
    )
}

/// `parseListAccounts`: the signed-in addresses in Google's answer to ListAccounts, the request
/// Chrome itself uses. `None` for anything that is not that answer: not knowing who is signed in
/// is different from nobody being signed in.
pub fn parse_list_accounts(text: &str) -> Option<Vec<String>> {
    let parsed: Value = serde_json::from_str(text).ok()?;
    let a = parsed.as_array()?;
    if a.first() != Some(&json!("gaia.l.a.r")) {
        return None;
    }
    let rows = a.get(1)?.as_array()?;
    Some(
        rows.iter()
            .filter_map(Value::as_array)
            .filter(|e| e.get(14) != Some(&json!(1)))
            .filter_map(|e| e.get(3).and_then(Value::as_str))
            .filter(|email| email_shape(email))
            .map(String::from)
            .collect(),
    )
}

/// `/^[^\s@]{1,64}@[^\s@]{1,255}$/` (UTF-16 units, no `u` flag).
fn email_shape(email: &str) -> bool {
    let Some((name, domain)) = email.split_once('@') else {
        return false;
    };
    let plain = |s: &str| !s.chars().any(|c| c == '@' || super::js::js_space(c));
    (1..=64).contains(&len16(name)) && (1..=255).contains(&len16(domain)) && plain(name) && plain(domain)
}

/// `signedInAccounts`: who is signed in to the meeting browser, asked through its loopback
/// debugger in a tab on accounts.google.com, which then sends ListAccounts with its cookies.
pub async fn signed_in_accounts(cdp: &str) -> Result<Vec<String>, String> {
    let client = debugger_client().ok_or("Meeting browser debugger not found")?;
    let target: Value = client
        .put(format!("{cdp}/json/new?{}", encode_uri_component(LIST_ACCOUNTS)))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?
        .json()
        .await
        .map_err(|e| e.without_url().to_string())?;
    static PAGE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^ws://127\.0\.0\.1:\d+/devtools/page/").expect("regex"));
    static ID: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^[A-Za-z0-9-]{1,100}$").expect("regex"));
    let (Some(id), Some(ws)) = (
        target.get("id").and_then(Value::as_str).filter(|i| ID.is_match(i)),
        target
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .filter(|u| PAGE.is_match(u)),
    ) else {
        return Err("Meeting browser debugger not found".into());
    };
    let outcome = async {
        let (page, _events) = Cdp::connect(ws).await.map_err(|e| {
            if e == "timed out" {
                "Meeting browser debugger timed out".to_string()
            } else {
                "Meeting browser debugger failed".to_string()
            }
        })?;
        // Google answers only a POST from its own page. Until the tab has loaded there, and when
        // Google refuses or the network fails, the answer is "not yet", never "signed out".
        let expression = format!(
            "document.readyState !== 'complete' || location.origin !== 'https://accounts.google.com' ? null :\n          fetch({}, {{ method: 'POST', credentials: 'include' }}).then((r) => r.ok ? r.text() : null, () => null)",
            json!(LIST_ACCOUNTS)
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            let answer = page
                .answer(
                    "Runtime.evaluate",
                    json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
                    None,
                    Some(Duration::from_secs(5)),
                )
                .await;
            let text = answer
                .as_ref()
                .and_then(|a| a.pointer("/result/result/value"))
                .and_then(Value::as_str)
                .map(String::from);
            if let Some(accounts) = text.as_deref().and_then(parse_list_accounts) {
                return Ok(accounts);
            }
            let wait = if text.is_none() { 300 } else { 1500 };
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
        Err("Google did not answer who is signed in".to_string())
    }
    .await;
    let _ = client
        .get(format!("{cdp}/json/close/{id}"))
        .timeout(Duration::from_secs(3))
        .send()
        .await;
    outcome
}

type Fut<T> = BoxFuture<T>;
type WindowFn = Arc<dyn Fn(bool, Option<String>) -> Fut<Result<(), String>> + Send + Sync>;

#[derive(Clone)]
pub struct SigninDeps {
    pub state_path: PathBuf,
    /// The Chrome profile that holds the session. Removed whole on sign-out.
    pub profile_dir: PathBuf,
    /// The Google account this agent is granted, or `None`.
    pub account: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// Whether the firewall's Google connection works right now (shown on the card).
    pub connected: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Opens or closes the sign-in window (`cc-meeting-signin.service`) on the given page.
    pub window: WindowFn,
    /// Starts or stops the meeting browser on the signed-in profile.
    pub browser: Arc<dyn Fn(bool) -> Fut<Result<(), String>> + Send + Sync>,
    /// Blocks the agent's own browser automation while the owner types.
    pub reserve: Arc<dyn Fn(bool) + Send + Sync>,
    /// A meeting is running or starting.
    pub busy: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Addresses signed in to the meeting browser, first account first.
    pub accounts: Arc<dyn Fn() -> Fut<Result<Vec<String>, String>> + Send + Sync>,
    /// An unfinished sign-in is closed after this long.
    pub timeout: Duration,
}

/// `{status, email?, signedInAt?}` in `state/meeting-signin.json`.
#[derive(Debug, Clone, Default, PartialEq)]
struct Saved {
    status: &'static str,
    email: Option<String>,
    signed_in_at: Option<String>,
}

impl Saved {
    fn none() -> Self {
        Self {
            status: "none",
            ..Default::default()
        }
    }
    fn json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("status".into(), json!(self.status));
        if let Some(e) = &self.email {
            m.insert("email".into(), json!(e));
        }
        if let Some(t) = &self.signed_in_at {
            m.insert("signedInAt".into(), json!(t));
        }
        Value::Object(m)
    }
}

pub struct MeetingSignin {
    deps: SigninDeps,
    saved: Mutex<Saved>,
    timer: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// One step at a time: Done pressed twice, or Sign out during Done, must not interleave.
    chain: Arc<tokio::sync::Mutex<()>>,
    /// A sign-out is already queued for a grant that went away: polls do not queue more.
    clearing: std::sync::atomic::AtomicBool,
    me: Weak<MeetingSignin>,
}

impl MeetingSignin {
    pub fn new(deps: SigninDeps) -> Arc<Self> {
        let s = Arc::new_cyclic(|me| Self {
            deps,
            saved: Mutex::new(Saved::none()),
            timer: Mutex::new(None),
            chain: Arc::new(tokio::sync::Mutex::new(())),
            clearing: std::sync::atomic::AtomicBool::new(false),
            me: me.clone(),
        });
        let raw = std::fs::read(&s.deps.state_path)
            .ok()
            .and_then(|r| serde_json::from_slice::<Value>(&r).ok());
        if let Some(raw) = raw {
            let status = raw.get("status").and_then(Value::as_str);
            match (status, raw.get("email").and_then(Value::as_str)) {
                (Some(st @ ("ready" | "expired")), Some(email)) => {
                    *s.saved() = Saved {
                        status: if st == "ready" { "ready" } else { "expired" },
                        email: Some(email.to_string()),
                        signed_in_at: raw.get("signedInAt").and_then(Value::as_str).map(String::from),
                    };
                }
                // A sign-in cut short by a restart: nobody confirmed whose session is in the profile.
                (Some("pending"), _) => {
                    let _ = s.wipe();
                }
                _ => {}
            }
        }
        if s.saved().status == "none"
            && s.deps.profile_dir.exists()
            && let Err(e) = s.wipe()
        {
            tracing::error!(
                "[meetings] a leftover meeting profile could not be removed: {}",
                head16(&e, 200)
            );
        }
        // A window left by the previous process is closed before any step: the queue is held
        // until it is.
        if tokio::runtime::Handle::try_current().is_ok()
            && let Ok(turn) = s.chain.clone().try_lock_owned()
        {
            let window = s.deps.window.clone();
            tokio::spawn(async move {
                let _ = window(false, None).await;
                drop(turn);
            });
        }
        s
    }

    fn saved(&self) -> MutexGuard<'_, Saved> {
        self.saved.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, saved: &Saved) -> Result<(), String> {
        atomic_json(&self.deps.state_path, &saved.json()).map_err(|e| e.to_string())
    }

    /// The profile and the state go; the state is `none` even when it cannot be written.
    fn wipe(&self) -> Result<(), String> {
        match std::fs::remove_dir_all(&self.deps.profile_dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
        let none = Saved::none();
        *self.saved() = none.clone();
        self.save(&none)
    }

    fn stop_timer(&self) {
        if let Some(t) = self.timer.lock().unwrap_or_else(|e| e.into_inner()).take() {
            t.abort();
        }
    }

    /// Drops the session when the account it belongs to is no longer granted to this agent.
    pub fn sync(&self) {
        let saved = self.saved().clone();
        if saved.status == "none" || (self.deps.busy)() {
            return;
        }
        let account = (self.deps.account)();
        if saved.status == "pending" {
            if account.is_none()
                && let Some(me) = self.me.upgrade()
                && tokio::runtime::Handle::try_current().is_ok()
                && !self.clearing.swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                tokio::spawn(async move {
                    let _ = me.clear().await;
                    me.clearing.store(false, std::sync::atomic::Ordering::SeqCst);
                });
            }
            return;
        }
        if account.is_none_or(|a| !same(&a, saved.email.as_deref().unwrap_or_default())) {
            // Called from reads and from the Google apply: a profile that cannot be removed is
            // logged and tried again on the next call, never thrown into them.
            match self.wipe() {
                Ok(()) => tracing::info!(
                    "[meetings] the Google account is no longer granted to this agent: its meeting sign-in was removed"
                ),
                Err(e) => tracing::error!(
                    "[meetings] the meeting sign-in could not be removed: {}",
                    head16(&e, 200)
                ),
            }
        }
    }

    /// What the Meetings page shows; `null` when this agent has no Google account granted.
    pub fn summary(&self) -> Value {
        self.sync();
        let Some(account) = (self.deps.account)() else {
            return Value::Null;
        };
        let saved = self.saved().clone();
        json!({"account": account, "status": saved.status, "signedInAt": saved.signed_in_at, "connected": (self.deps.connected)()})
    }

    pub fn pending(&self) -> bool {
        self.saved().status == "pending"
    }

    /// Whether the next join should start on the signed-in profile.
    pub fn ready(&self) -> bool {
        self.sync();
        self.saved().status == "ready"
    }

    /// At join, with the meeting browser running on the profile: is Google still signed in as the
    /// account? A session Google ended is marked, and the caller joins as a guest instead.
    pub async fn verify(&self) -> bool {
        let account = (self.deps.account)();
        let Some(account) = account.filter(|_| self.saved().status == "ready") else {
            return false;
        };
        let first = match (self.deps.accounts)().await {
            Ok(list) => list.into_iter().next(),
            Err(e) => {
                // Not knowing is not "signed out": join as a guest this once and keep the session.
                tracing::warn!("[meetings] could not check the Google sign-in: {e}");
                return false;
            }
        };
        if first.as_deref().is_some_and(|f| same(f, &account)) {
            return true;
        }
        // Only the session this check was for: a sign-out or a sync meanwhile stays as it is.
        let expired = {
            let mut saved = self.saved();
            if saved.status != "ready" || !saved.email.as_deref().is_some_and(|e| same(e, &account)) {
                return false;
            }
            saved.status = "expired";
            saved.clone()
        };
        if let Err(e) = self.save(&expired) {
            tracing::error!(
                "[meetings] the ended Google sign-in could not be recorded: {}",
                head16(&e, 200)
            );
        }
        tracing::info!("[meetings] Google sign-in has ended: joining as a guest");
        false
    }

    /// Opens the sign-in window, with the agent's own browser automation blocked.
    pub async fn start(&self) -> Result<Value, String> {
        let _turn = self.chain.lock().await;
        let Some(account) = (self.deps.account)() else {
            return Err("Connect a Google account for this agent first".into());
        };
        if (self.deps.busy)() {
            return Err("Stop the current meeting first".into());
        }
        if self.pending() {
            return Ok(self.summary());
        }
        // Pending from here on, before anything is awaited: a join that arrives while the window
        // is opening is refused, so it cannot start the meeting browser under the sign-in.
        let before = std::mem::replace(
            &mut *self.saved(),
            Saved {
                status: "pending",
                ..Default::default()
            },
        );
        (self.deps.reserve)(true);
        let opened: Result<(), String> = async {
            self.save(&self.saved().clone())?;
            (self.deps.browser)(false).await?;
            (self.deps.window)(true, Some(signin_url(&account))).await
        }
        .await;
        if let Err(e) = opened {
            let _ = (self.deps.window)(false, None).await;
            (self.deps.reserve)(false);
            *self.saved() = before.clone();
            // The next start or restart writes it.
            let _ = self.save(&before);
            return Err(e);
        }
        if let Some(me) = self.me.upgrade() {
            let wait = self.deps.timeout;
            let timer = tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                // A task of its own, so that `finish` stopping this timer does not stop itself.
                tokio::spawn(async move {
                    let _ = me.finish(true).await;
                });
            });
            if let Some(old) = self.timer.lock().unwrap_or_else(|e| e.into_inner()).replace(timer) {
                old.abort();
            }
        }
        Ok(self.summary())
    }

    /// The owner pressed Done: keep the session only if it is the account's. A check that could
    /// not be made leaves the sign-in open, so Done can be pressed again; `last` is the window
    /// timing out, which ends it either way. `{signin, error?}`.
    pub async fn finish(&self, last: bool) -> Result<Value, String> {
        let _turn = self.chain.lock().await;
        if !self.pending() {
            return Ok(json!({"signin": self.summary()}));
        }
        let account = (self.deps.account)();
        let checked: Result<Option<String>, String> = async {
            (self.deps.window)(false, None).await?;
            if account.is_none() {
                return Ok(None);
            }
            (self.deps.browser)(true).await?;
            Ok((self.deps.accounts)().await?.into_iter().next())
        }
        .await;
        let _ = (self.deps.browser)(false).await;
        let (first, unknown) = match checked {
            Ok(f) => (f, false),
            Err(e) => {
                tracing::warn!("[meetings] could not read the Google sign-in: {e}");
                (None, true)
            }
        };
        if unknown && !last {
            return Ok(
                json!({"signin": self.summary(), "error": "The sign-in could not be checked just now. Press Done again."}),
            );
        }
        self.stop_timer();
        (self.deps.reserve)(false);
        if let (false, Some(a), Some(f)) = (unknown, account.as_deref(), first.as_deref())
            && same(f, a)
        {
            let ready = Saved {
                status: "ready",
                email: Some(a.to_string()),
                signed_in_at: Some(now_iso()),
            };
            *self.saved() = ready.clone();
            self.save(&ready)?;
            return Ok(json!({"signin": self.summary()}));
        }
        if let Err(e) = self.wipe() {
            tracing::error!(
                "[meetings] the meeting sign-in could not be removed: {}",
                head16(&e, 200)
            );
            return Err("The Google sign-in could not be removed from this agent. Try again.".into());
        }
        let error = if unknown {
            "The sign-in could not be checked. Sign in again.".to_string()
        } else if let Some(f) = first {
            format!(
                "That was {f}. Sign in as {}.",
                account.as_deref().unwrap_or("the agent's Google account")
            )
        } else {
            "No Google sign-in was found. Try again and finish signing in before pressing Done.".to_string()
        };
        Ok(json!({"signin": self.summary(), "error": error}))
    }

    /// Sign out: close anything open and remove the profile. Google's own session list is not touched.
    pub async fn clear(&self) -> Result<Value, String> {
        let _turn = self.chain.lock().await;
        if (self.deps.busy)() {
            return Err("Stop the current meeting first".into());
        }
        self.stop_timer();
        if self.pending() {
            let _ = (self.deps.window)(false, None).await;
            (self.deps.reserve)(false);
        }
        let _ = (self.deps.browser)(false).await;
        if let Err(e) = self.wipe() {
            tracing::error!(
                "[meetings] the meeting sign-in could not be removed: {}",
                head16(&e, 200)
            );
            return Err("The Google sign-in could not be removed from this agent. Try again.".into());
        }
        Ok(self.summary())
    }
}

impl super::service::Signin for MeetingSignin {
    fn pending(&self) -> bool {
        MeetingSignin::pending(self)
    }
    fn ready(&self) -> bool {
        MeetingSignin::ready(self)
    }
    fn verify(&self) -> BoxFuture<bool> {
        let me = self.me.upgrade();
        Box::pin(async move {
            match me {
                Some(m) => m.verify().await,
                None => false,
            }
        })
    }
    fn summary(&self) -> Value {
        MeetingSignin::summary(self)
    }
    fn sync(&self) {
        MeetingSignin::sync(self)
    }
}

#[cfg(test)]
mod tests;
