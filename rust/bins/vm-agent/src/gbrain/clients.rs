//! Outside AI apps on the brain (T-219): Claude, ChatGPT, Cursor, Claude Code, Codex.
//!
//! The brain's public name serves one MCP address, `https://<brain>/mcp`, with an OAuth server of
//! our own in front of it (`oauth.rs`). This is its record: the apps that registered (dynamic client
//! registration), the sign-ins waiting for a person, and the clients the org firewall approved after
//! an owner or admin typed its code.
//!
//! An approved client gets a GBrain token of its own, minted by the same root helper as an agent's
//! (`cc-gbrain-token create client-<id>`, so GBrain names it `cc-client-<id>`), and kept here. It
//! never leaves this box. What the app holds is our access and refresh tokens, stored only as
//! sha256 hashes; GBrain has never heard of them. At the gate each request's `Authorization` is
//! replaced with the client's GBrain token, as for agents, so a token or client made on GBrain's
//! admin page reaches nothing here.
//!
//! Only the firewall adds a client or widens one (`POST /gbrain/clients/connect`, firewall-signed,
//! after the code). Removing one, the end date and the emergency stop are checked on every call.
//!
//! Registrations and approved clients are kept in `gbrain-clients.json` (0600, in the state
//! directory on the encrypted disk). Sign-ins waiting for approval are kept in memory only: a
//! restart drops them, and the app starts its sign-in again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine;
use cc_proc::Runner;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::activity::parse_iso;
use super::run_helper;

const HELPER: &str = "/usr/local/bin/cc-gbrain-token";
const HELPER_TIMEOUT: Duration = Duration::from_secs(25);
static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,48}$").expect("regex"));
static GBRAIN_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{32,}$").expect("regex"));

/// How long an app's sign-in may wait for the person and the code.
pub const PENDING_MS: i64 = 30 * 60_000;
/// How long the one-time code handed back to the app is good for.
pub const CODE_MS: i64 = 5 * 60_000;
pub const ACCESS_MS: i64 = 60 * 60_000;
pub const REFRESH_MS: i64 = 30 * 24 * 60 * 60_000;
/// At most this many registrations; the oldest one no approved client uses goes first.
const MAX_REGISTRATIONS: usize = 200;
/// A registration nobody approved within a week is dropped.
const REGISTRATION_IDLE_MS: i64 = 7 * 24 * 60 * 60_000;
const MAX_PENDING: usize = 200;
/// Sign-ins waiting per registration: a new one replaces that app's oldest, so one app cannot fill
/// the list for everyone.
const MAX_PENDING_PER_APP: usize = 3;
/// Tokens kept per client (access and refresh together); the oldest go first.
const MAX_TOKENS: usize = 40;
pub const MAX_NAME: usize = 60;
const MAX_REDIRECTS: usize = 5;
const MAX_REDIRECT_LEN: usize = 512;

/// Calls per client: a bucket of this many, refilled at this many a second (120 a minute).
const CLIENT_BURST: f64 = 120.0;
const CLIENT_PER_SEC: f64 = 2.0;
/// Sign-ins started per registered app.
const AUTHORIZE_BURST: f64 = 10.0;
const AUTHORIZE_PER_SEC: f64 = 0.2;
/// Token calls per app that showed a live refresh token or an approved code.
const TOKEN_BURST: f64 = 30.0;
const TOKEN_PER_SEC: f64 = 0.5;
/// Past this many buckets the idle ones go.
const MAX_BUCKETS: usize = 2000;

/// The calls anyone can make with nothing to show. The proxy box hides who is asking (no PROXY
/// protocol), so these share one bucket per endpoint. A sign-in is charged to its app's own bucket,
/// and a token call that shows a live refresh token or an approved code to its app's: junk cannot
/// starve those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicCall {
    Register,
    Token,
}

impl PublicCall {
    /// (burst, per second).
    fn rate(self) -> (f64, f64) {
        match self {
            PublicCall::Register => (20.0, 0.2),
            PublicCall::Token => (120.0, 2.0),
        }
    }
}

/// What `/oauth/authorize/done` gives the browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finish {
    /// The app's redirect with a new one-time code.
    Code(String),
    /// Not approved yet, or the approval is not this browser's to finish.
    Waiting,
    /// The sign-in ran out: the app's redirect with `access_denied`.
    Denied(String),
    /// No such sign-in, or this browser did not start it.
    NotHere,
}

/// A started sign-in: its id, which goes to the console, and the browser's secret, which goes only
/// into a cookie on the brain's own name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    pub req: String,
    pub browser: String,
}

/// The cookie that ties `/oauth/authorize/done` to the browser that started the sign-in.
pub fn browser_cookie(req: &str) -> String {
    format!("__Host-cc_signin_{}", &hash(req)[..16])
}

fn is_sha256_hex(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn random_token(prefix: &str) -> String {
    let b: [u8; 32] = rand::random();
    format!("{prefix}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// PKCE S256: `BASE64URL(SHA256(verifier)) == challenge`.
pub fn pkce_matches(verifier: &str, challenge: &str) -> bool {
    let ok_chars = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
    };
    if !(43..=128).contains(&verifier.len()) || !ok_chars(verifier) {
        return false;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == challenge
}

/// A redirect URI an app may register: https, http on loopback only (RFC 8252 §7.3), or an app's
/// own scheme with a host part (`cursor://anysphere.cursor-mcp/...`, RFC 8252 §7.1; Cursor's has no
/// dot, so the RFC's reverse-domain advice is not required). No fragment, no userinfo.
pub fn redirect_allowed(uri: &str) -> bool {
    if uri.len() > MAX_REDIRECT_LEN || uri.contains('#') {
        return false;
    }
    let Ok(u) = url::Url::parse(uri) else { return false };
    if !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match u.scheme() {
        "https" => u.host_str().is_some_and(|h| !h.is_empty()),
        "http" => matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        s => {
            u.host_str().is_some_and(|h| !h.is_empty())
                && !matches!(
                    s,
                    "javascript" | "data" | "file" | "blob" | "vbscript" | "about" | "ftp" | "ws" | "wss" | "mailto"
                )
        }
    }
}

/// Whether `asked` is one of the registered URIs. A loopback URI may differ in its port only
/// (RFC 8252 §7.3: native apps pick a free port each time).
pub fn redirect_matches(registered: &[String], asked: &str) -> bool {
    let Ok(a) = url::Url::parse(asked) else { return false };
    registered.iter().any(|r| {
        if r == asked {
            return true;
        }
        let Ok(r) = url::Url::parse(r) else { return false };
        r.scheme() == "http"
            && a.scheme() == "http"
            && matches!(r.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
            && r.host_str() == a.host_str()
            && r.path() == a.path()
            && r.query() == a.query()
    })
}

/// What a person sees as the app's site: the redirect URI's host, or its scheme for a native app.
pub fn site_of(uri: &str) -> String {
    match url::Url::parse(uri) {
        Ok(u) => match u.host_str() {
            Some(h) if u.scheme() == "https" || u.scheme() == "http" => h.to_string(),
            _ => format!("{}://", u.scheme()),
        },
        Err(_) => String::new(),
    }
}

/// An app's name, as it gave it, made safe to show and to send: printable, at most 60 characters.
pub fn clean_name(raw: &str) -> String {
    let s: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let s: String = s.chars().take(MAX_NAME).collect();
    if s.is_empty() { "MCP client".into() } else { s }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    #[serde(rename = "clientId")]
    pub client_id: String,
    pub name: String,
    #[serde(rename = "redirectUris")]
    pub redirect_uris: Vec<String>,
    /// sha256 of the secret, for an app that asked to be a confidential client.
    #[serde(rename = "secretHash", default, skip_serializing_if = "Option::is_none")]
    pub secret_hash: Option<String>,
    #[serde(rename = "createdMs")]
    pub created_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    pub hash: String,
    /// `access` or `refresh`.
    pub kind: String,
    #[serde(rename = "expiresMs")]
    pub expires_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Client {
    /// The console's id for it (`brain_client.id`).
    pub id: String,
    #[serde(rename = "oauthClientId")]
    pub oauth_client_id: String,
    pub name: String,
    pub scope: String,
    #[serde(rename = "expiresMs", default, skip_serializing_if = "Option::is_none")]
    pub expires_ms: Option<i64>,
    /// The client's GBrain token. Never sent anywhere.
    pub token: String,
    pub at: String,
    #[serde(default)]
    pub issued: Vec<Issued>,
}

#[derive(Debug, Clone)]
pub struct Pending {
    pub client_id: String,
    pub redirect_uri: String,
    pub challenge: String,
    pub state: Option<String>,
    pub created_ms: i64,
    /// sha256 of the secret in the starting browser's cookie.
    pub browser: String,
    /// The console read it for the Connect page: a person is looking at it, so a new sign-in never
    /// pushes it out.
    pub opened: bool,
    /// Set once the firewall approved it: the console's client id and the code's hash.
    pub approved: Option<(String, String)>,
    /// sha256 of the approval secret, which only the Connect page that asked holds.
    pub approval: Option<String>,
    /// The one-time code, in memory only, so a second load of the return page hands back the same
    /// one instead of spending the first.
    pub code: Option<String>,
    pub code_expires_ms: i64,
    pub code_used: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    #[serde(default)]
    version: u8,
    #[serde(default)]
    registrations: Vec<Registration>,
    #[serde(default)]
    clients: Vec<Client>,
}

struct Bucket {
    tokens: f64,
    at_ms: i64,
}

impl Bucket {
    fn full(burst: f64, now: i64) -> Self {
        Self {
            tokens: burst,
            at_ms: now,
        }
    }
    /// Take one; `Err(seconds to wait)` when empty.
    fn take(&mut self, burst: f64, per_sec: f64, now: i64) -> Result<(), u64> {
        let elapsed = (now - self.at_ms).max(0) as f64 / 1000.0;
        self.tokens = (self.tokens + elapsed * per_sec).min(burst);
        self.at_ms = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            Err(((1.0 - self.tokens) / per_sec).ceil().max(1.0) as u64)
        }
    }
}

struct State {
    registrations: Vec<Registration>,
    clients: Vec<Client>,
    pending: HashMap<String, Pending>,
    buckets: HashMap<String, Bucket>,
    public: HashMap<PublicCall, Bucket>,
}

/// Why `/mcp` turns a caller away, or what it forwards with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAdmission {
    /// The client's console id and its GBrain token.
    Token {
        id: String,
        token: String,
    },
    Unknown,
    Expired,
    Stopped,
    Limited(u64),
}

/// What `/oauth/token` hands back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub access: String,
    pub refresh: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectInput {
    pub id: String,
    /// The sign-in this approves. None: change the scope or end date of a client already here.
    pub req: Option<String>,
    /// With `req`: sha256 (hex) of the secret the Connect page that asked holds. The browser shows
    /// it at `/oauth/authorize/done`, so the sign-in's id alone gets no code.
    pub approval: Option<String>,
    pub scope: String,
    pub expires_ms: Option<i64>,
}

pub fn parse_connect(body: Option<&Map<String, Value>>, now: i64) -> Result<ConnectInput, &'static str> {
    let Some(b) = body else {
        return Err("a JSON body is required");
    };
    let id = b.get("id").and_then(Value::as_str).filter(|v| ID.is_match(v));
    let Some(id) = id else { return Err("id is required") };
    let scope = b
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| *s == "read" || *s == "read_write");
    let Some(scope) = scope else {
        return Err("scope must be read or read_write");
    };
    let req = match b.get("req") {
        None | Some(Value::Null) => None,
        Some(Value::String(r)) if r.len() <= 64 && !r.is_empty() => Some(r.clone()),
        _ => return Err("req must be a sign-in id"),
    };
    let approval = match (&req, b.get("approval")) {
        (None, _) => None,
        (Some(_), Some(Value::String(a))) if is_sha256_hex(a) => Some(a.clone()),
        (Some(_), _) => return Err("approval is required with req"),
    };
    let expires_ms = match b.get("expiresAt") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => match parse_iso(s) {
            Some(ms) if (ms as i64) > now => Some(ms as i64),
            Some(_) => return Err("expiresAt is in the past"),
            None => return Err("expiresAt must be an ISO time"),
        },
        _ => return Err("expiresAt must be an ISO time"),
    };
    Ok(ConnectInput {
        id: id.into(),
        req,
        approval,
        scope: scope.into(),
        expires_ms,
    })
}

pub fn parse_id(body: Option<&Map<String, Value>>, field: &str) -> Result<String, &'static str> {
    body.and_then(|b| b.get(field))
        .and_then(Value::as_str)
        .filter(|v| v.len() <= 64 && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
        .map(String::from)
        .ok_or("an id is required")
}

pub struct BrainClients {
    path: PathBuf,
    runner: Arc<dyn Runner>,
    state: Mutex<State>,
    /// One connect, disconnect or reissue at a time, helper call included (as the gate's `ops`).
    ops: tokio::sync::Mutex<()>,
}

pub fn iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    // Civil from days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60,
        ms.rem_euclid(1000)
    )
}

impl BrainClients {
    pub fn new(path: &Path, runner: Arc<dyn Runner>) -> Self {
        let saved = Self::load(path);
        Self {
            path: path.to_path_buf(),
            runner,
            state: Mutex::new(State {
                registrations: saved.registrations,
                clients: saved
                    .clients
                    .into_iter()
                    .filter(|c| GBRAIN_TOKEN.is_match(&c.token) && ID.is_match(&c.id))
                    .collect(),
                pending: HashMap::new(),
                buckets: HashMap::new(),
                public: HashMap::new(),
            }),
            ops: tokio::sync::Mutex::new(()),
        }
    }

    /// Unreadable means no client gets in until it is connected again: fail closed.
    fn load(path: &Path) -> Saved {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|e| {
                tracing::error!("[gbrain-clients] could not read {}: {e}", path.display());
                Saved::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Saved::default(),
            Err(e) => {
                tracing::error!("[gbrain-clients] could not read {}: {e}", path.display());
                Saved::default()
            }
        }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, st: &State) -> Result<(), String> {
        let data = serde_json::to_vec(&json!({
            "version": 1,
            "registrations": st.registrations,
            "clients": st.clients,
        }))
        .map_err(|e| e.to_string())?;
        cc_store::write_atomic(&self.path, &data, 0o600, cc_store::TmpName::Suffix).map_err(|e| e.to_string())
    }

    /// One call from anyone to the registration, sign-in or token endpoint.
    pub fn take_public(&self, kind: PublicCall, now: i64) -> Result<(), u64> {
        let (burst, per_sec) = kind.rate();
        self.st()
            .public
            .entry(kind)
            .or_insert_with(|| Bucket::full(burst, now))
            .take(burst, per_sec, now)
    }

    /// One call charged to an app's own bucket (`kind:<client id>`).
    fn take_own(st: &mut State, key: String, burst: f64, per_sec: f64, now: i64) -> Result<(), u64> {
        if st.buckets.len() >= MAX_BUCKETS {
            // A bucket that has refilled is the same as none.
            st.buckets.retain(|_, b| now - b.at_ms < 10 * 60_000);
        }
        st.buckets
            .entry(key)
            .or_insert_with(|| Bucket::full(burst, now))
            .take(burst, per_sec, now)
    }

    /// A sign-in started for a registered app: its own bucket.
    pub fn take_authorize(&self, client_id: &str, now: i64) -> Result<(), u64> {
        Self::take_own(
            &mut self.st(),
            format!("authorize:{client_id}"),
            AUTHORIZE_BURST,
            AUTHORIZE_PER_SEC,
            now,
        )
    }

    /// A token call. One that shows its app's live refresh token or approved code is charged to
    /// that app's bucket; anything else to the shared one.
    pub fn take_token(&self, client_id: &str, refresh: Option<&str>, code: Option<&str>, now: i64) -> Result<(), u64> {
        let mut st = self.st();
        let known = refresh.map(hash).is_some_and(|h| {
            st.clients.iter().any(|c| {
                c.oauth_client_id == client_id
                    && c.issued
                        .iter()
                        .any(|t| t.kind == "refresh" && t.hash == h && t.expires_ms > now)
            })
        }) || code.map(hash).is_some_and(|h| {
            st.pending.values().any(|p| {
                p.client_id == client_id
                    && !p.code_used
                    && now < p.code_expires_ms
                    && p.approved.as_ref().is_some_and(|(_, ch)| *ch == h)
            })
        });
        if known {
            return Self::take_own(&mut st, format!("token:{client_id}"), TOKEN_BURST, TOKEN_PER_SEC, now);
        }
        let (burst, per_sec) = PublicCall::Token.rate();
        st.public
            .entry(PublicCall::Token)
            .or_insert_with(|| Bucket::full(burst, now))
            .take(burst, per_sec, now)
    }

    // ---- registration and sign-in (the public side) ----

    /// Dynamic client registration (RFC 7591). The app gets an id, and a secret when it asked to be
    /// confidential. Registering grants nothing.
    pub fn register(
        &self,
        name: &str,
        redirect_uris: Vec<String>,
        confidential: bool,
        now: i64,
    ) -> Result<(Registration, Option<String>), &'static str> {
        if redirect_uris.is_empty() || redirect_uris.len() > MAX_REDIRECTS {
            return Err("redirect_uris must list one to five URIs");
        }
        if !redirect_uris.iter().all(|u| redirect_allowed(u)) {
            return Err("a redirect URI must be https, http on loopback, or an app's own scheme");
        }
        let secret = confidential.then(|| random_token("ccbs_"));
        let reg = Registration {
            client_id: random_token("ccbc_"),
            name: clean_name(name),
            redirect_uris,
            secret_hash: secret.as_deref().map(hash),
            created_ms: now,
        };
        let mut st = self.st();
        st.pending.retain(|_, p| now - p.created_ms < PENDING_MS);
        // In use: an approved client's, or one whose sign-in is waiting for a person.
        let used: Vec<String> = st
            .clients
            .iter()
            .map(|c| c.oauth_client_id.clone())
            .chain(st.pending.values().map(|p| p.client_id.clone()))
            .collect();
        st.registrations
            .retain(|r| used.contains(&r.client_id) || now - r.created_ms < REGISTRATION_IDLE_MS);
        while st.registrations.len() >= MAX_REGISTRATIONS {
            let Some(i) = st.registrations.iter().position(|r| !used.contains(&r.client_id)) else {
                return Err("too many apps are registered with this brain");
            };
            st.registrations.remove(i);
        }
        st.registrations.push(reg.clone());
        self.save(&st).map_err(|_| "could not save the registration")?;
        Ok((reg, secret))
    }

    pub fn registration(&self, client_id: &str) -> Option<Registration> {
        self.st()
            .registrations
            .iter()
            .find(|r| r.client_id == client_id)
            .cloned()
    }

    /// An app's sign-in, waiting for a person. A new one pushes out the oldest unapproved one of the
    /// same app past `MAX_PENDING_PER_APP`, and the oldest nobody opened when the list is full.
    pub fn begin(
        &self,
        client_id: &str,
        redirect_uri: &str,
        challenge: &str,
        state: Option<String>,
        now: i64,
    ) -> Result<Started, &'static str> {
        if !(43..=128).contains(&challenge.len()) {
            return Err("code_challenge must be an S256 challenge");
        }
        let mut st = self.st();
        st.pending.retain(|_, p| now - p.created_ms < PENDING_MS);
        let oldest = |st: &State, f: &dyn Fn(&Pending) -> bool| {
            st.pending
                .iter()
                .filter(|(_, p)| p.approved.is_none() && f(p))
                .min_by_key(|(_, p)| p.created_ms)
                .map(|(k, _)| k.clone())
        };
        while st.pending.values().filter(|p| p.client_id == client_id).count() >= MAX_PENDING_PER_APP {
            let Some(k) = oldest(&st, &|p| p.client_id == client_id && !p.opened) else {
                return Err("too many sign-ins are waiting; try again later");
            };
            st.pending.remove(&k);
        }
        // Full: the app with the most sign-ins nobody opened gives up its oldest, so a flood pushes
        // out its own before a person's that is on its way to the Connect page. Between apps with as
        // many, the most recently registered goes first (a flood's registrations are new).
        while st.pending.len() >= MAX_PENDING {
            let mut waiting: HashMap<&str, usize> = HashMap::new();
            for p in st.pending.values().filter(|p| p.approved.is_none() && !p.opened) {
                *waiting.entry(p.client_id.as_str()).or_default() += 1;
            }
            let registered = |id: &str| {
                st.registrations
                    .iter()
                    .find(|r| r.client_id == id)
                    .map_or(i64::MAX, |r| r.created_ms)
            };
            let Some(app) = waiting
                .into_iter()
                .max_by_key(|(a, n)| (*n, registered(a), *a))
                .map(|(a, _)| a.to_string())
            else {
                return Err("too many sign-ins are waiting; try again later");
            };
            let Some(k) = oldest(&st, &|p| p.client_id == app && !p.opened) else {
                return Err("too many sign-ins are waiting; try again later");
            };
            st.pending.remove(&k);
        }
        let req = random_token("");
        let browser = random_token("");
        st.pending.insert(
            req.clone(),
            Pending {
                client_id: client_id.into(),
                redirect_uri: redirect_uri.into(),
                challenge: challenge.into(),
                state,
                created_ms: now,
                browser: hash(&browser),
                opened: false,
                approved: None,
                approval: None,
                code: None,
                code_expires_ms: 0,
                code_used: false,
            },
        );
        Ok(Started { req, browser })
    }

    /// What the console (the Connect page) and the firewall (the code message) read: the app's name
    /// and site, from here. Once read, the sign-in is never pushed out by newer ones.
    pub fn request_info(&self, req: &str, now: i64) -> Option<Value> {
        let mut st = self.st();
        let p = st.pending.get(req).filter(|p| now - p.created_ms < PENDING_MS)?;
        let (client_id, site, approved) = (p.client_id.clone(), site_of(&p.redirect_uri), p.approved.is_some());
        let name = st
            .registrations
            .iter()
            .find(|r| r.client_id == client_id)
            .map(|r| r.name.clone())?;
        if let Some(p) = st.pending.get_mut(req) {
            p.opened = true;
        }
        Some(json!({"name": name, "site": site, "approved": approved}))
    }

    /// Where the browser goes back to once the sign-in is approved (`/oauth/authorize/done`). It must
    /// show both secrets: `browser`, from the cookie the brain gave the browser that started the
    /// sign-in, and `approval`, which only the Connect page that asked for it holds. The sign-in's
    /// id alone (it is in the console link anyone may be sent) gets nothing.
    pub fn finish(&self, req: &str, browser: Option<&str>, approval: Option<&str>, issuer: &str, now: i64) -> Finish {
        let mut st = self.st();
        let Some(p) = st.pending.get_mut(req) else {
            return Finish::NotHere;
        };
        if browser.map(hash).as_deref() != Some(p.browser.as_str()) {
            return Finish::NotHere;
        }
        let deny = |p: &Pending| {
            let mut u = url::Url::parse(&p.redirect_uri).ok()?;
            {
                let mut q = u.query_pairs_mut();
                q.append_pair("error", "access_denied");
                if let Some(s) = &p.state {
                    q.append_pair("state", s);
                }
                q.append_pair("iss", issuer);
            }
            Some(u.to_string())
        };
        if now - p.created_ms >= PENDING_MS {
            let out = deny(p);
            st.pending.remove(req);
            return out.map_or(Finish::NotHere, Finish::Denied);
        }
        let Some((id, _)) = p.approved.clone() else {
            return Finish::Waiting;
        };
        if p.approval.is_none() || approval.map(hash) != p.approval {
            return Finish::Waiting;
        }
        let code = match &p.code {
            Some(c) if !p.code_used && now < p.code_expires_ms => c.clone(),
            _ => {
                let c = random_token("ccba_");
                p.approved = Some((id, hash(&c)));
                p.code = Some(c.clone());
                p.code_expires_ms = now + CODE_MS;
                p.code_used = false;
                c
            }
        };
        let Ok(mut u) = url::Url::parse(&p.redirect_uri) else {
            return Finish::NotHere;
        };
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("code", &code);
            if let Some(s) = &p.state {
                q.append_pair("state", s);
            }
            q.append_pair("iss", issuer);
        }
        Finish::Code(u.to_string())
    }

    /// Check a registered app's secret, when it has one. Public clients pass with none.
    fn secret_ok(reg: &Registration, secret: Option<&str>) -> bool {
        match (&reg.secret_hash, secret) {
            (None, _) => true,
            (Some(h), Some(s)) => &hash(s) == h,
            (Some(_), None) => false,
        }
    }

    fn issue(c: &mut Client, now: i64) -> Grant {
        let end = c.expires_ms.unwrap_or(i64::MAX);
        let access = random_token("ccbt_");
        let refresh = random_token("ccbr_");
        let access_exp = (now + ACCESS_MS).min(end);
        c.issued.retain(|t| t.expires_ms > now);
        c.issued.push(Issued {
            hash: hash(&access),
            kind: "access".into(),
            expires_ms: access_exp,
        });
        c.issued.push(Issued {
            hash: hash(&refresh),
            kind: "refresh".into(),
            expires_ms: (now + REFRESH_MS).min(end),
        });
        while c.issued.len() > MAX_TOKENS {
            c.issued.remove(0);
        }
        Grant {
            access,
            refresh,
            expires_in: ((access_exp - now) / 1000).max(1),
            scope: if c.scope == "read_write" {
                "read write".into()
            } else {
                "read".into()
            },
        }
    }

    /// `grant_type=authorization_code`, PKCE checked. A code is good once.
    pub fn exchange_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: Option<&str>,
        verifier: &str,
        secret: Option<&str>,
        now: i64,
    ) -> Result<Grant, &'static str> {
        let h = hash(code);
        let mut st = self.st();
        let Some((req, p)) = st
            .pending
            .iter()
            .find(|(_, p)| p.approved.as_ref().is_some_and(|(_, ch)| *ch == h))
            .map(|(k, p)| (k.clone(), p.clone()))
        else {
            return Err("invalid_grant");
        };
        // One try: whatever happens next, this code is spent.
        st.pending.remove(&req);
        if p.code_used || now > p.code_expires_ms || p.client_id != client_id {
            return Err("invalid_grant");
        }
        if redirect_uri.is_some_and(|r| r != p.redirect_uri) || !pkce_matches(verifier, &p.challenge) {
            return Err("invalid_grant");
        }
        let Some(reg) = st.registrations.iter().find(|r| r.client_id == client_id).cloned() else {
            return Err("invalid_client");
        };
        if !Self::secret_ok(&reg, secret) {
            return Err("invalid_client");
        }
        let id = p.approved.map(|(id, _)| id).unwrap_or_default();
        let Some(c) = st.clients.iter_mut().find(|c| c.id == id) else {
            return Err("invalid_grant");
        };
        if c.expires_ms.is_some_and(|e| e <= now) {
            return Err("invalid_grant");
        }
        let g = Self::issue(c, now);
        self.save(&st).map_err(|_| "server_error")?;
        Ok(g)
    }

    /// `grant_type=refresh_token`: the refresh token is swapped for a new pair.
    pub fn refresh(
        &self,
        refresh: &str,
        client_id: &str,
        secret: Option<&str>,
        now: i64,
    ) -> Result<Grant, &'static str> {
        let h = hash(refresh);
        let mut st = self.st();
        let Some(reg) = st.registrations.iter().find(|r| r.client_id == client_id).cloned() else {
            return Err("invalid_client");
        };
        if !Self::secret_ok(&reg, secret) {
            return Err("invalid_client");
        }
        let Some(c) = st.clients.iter_mut().find(|c| {
            c.oauth_client_id == client_id
                && c.issued
                    .iter()
                    .any(|t| t.kind == "refresh" && t.hash == h && t.expires_ms > now)
        }) else {
            return Err("invalid_grant");
        };
        if c.expires_ms.is_some_and(|e| e <= now) {
            return Err("invalid_grant");
        }
        c.issued.retain(|t| t.hash != h);
        let g = Self::issue(c, now);
        self.save(&st).map_err(|_| "server_error")?;
        Ok(g)
    }

    /// One `/mcp` call: whose bearer it is, and whether it may go through now.
    pub fn admit(&self, bearer: &str, stopped: bool, now: i64) -> ClientAdmission {
        let h = hash(bearer);
        let mut st = self.st();
        let Some(c) = st
            .clients
            .iter()
            .find(|c| c.issued.iter().any(|t| t.kind == "access" && t.hash == h))
        else {
            return ClientAdmission::Unknown;
        };
        let live = c
            .issued
            .iter()
            .any(|t| t.kind == "access" && t.hash == h && t.expires_ms > now);
        if c.expires_ms.is_some_and(|e| e <= now) {
            return ClientAdmission::Expired;
        }
        if !live {
            return ClientAdmission::Unknown;
        }
        if stopped {
            return ClientAdmission::Stopped;
        }
        let (id, token) = (c.id.clone(), c.token.clone());
        let bucket = st
            .buckets
            .entry(id.clone())
            .or_insert_with(|| Bucket::full(CLIENT_BURST, now));
        if let Err(wait) = bucket.take(CLIENT_BURST, CLIENT_PER_SEC, now) {
            return ClientAdmission::Limited(wait);
        }
        ClientAdmission::Token { id, token }
    }

    // ---- the firewall's side ----

    /// What the firewall reads to reconcile. No tokens.
    pub fn list(&self) -> Vec<Value> {
        self.st()
            .clients
            .iter()
            .map(|c| {
                json!({
                    "id": c.id,
                    "name": c.name,
                    "scope": c.scope,
                    "expiresAt": c.expires_ms.map(iso),
                    "at": c.at,
                })
            })
            .collect()
    }

    async fn helper(&self, args: &[&str]) -> Result<String, String> {
        let cmd = super::helper(HELPER).args(args.iter().copied()).timeout(HELPER_TIMEOUT);
        run_helper(self.runner.as_ref(), cmd).await
    }

    async fn mint(&self, id: &str, scope: &str) -> Result<String, String> {
        let token = self
            .helper(&["create", &format!("client-{id}"), scope])
            .await
            .map_err(|e| format!("could not create the app's brain token: {e}"))?
            .trim()
            .to_string();
        if !GBRAIN_TOKEN.is_match(&token) {
            return Err("GBrain returned no usable token".into());
        }
        Ok(token)
    }

    /// Approve a sign-in (with `req`), or change an approved client's scope or end date. Only
    /// after the firewall checked the code, or for a change that takes access away.
    pub async fn connect(&self, input: &ConnectInput, now: i64) -> Result<(), String> {
        let _op = self.ops.lock().await;
        let existing = self.st().clients.iter().find(|c| c.id == input.id).cloned();
        match (&input.req, existing) {
            (Some(req), existing) => {
                let (oauth_client_id, name) = {
                    let st = self.st();
                    let p = st
                        .pending
                        .get(req)
                        .filter(|p| now - p.created_ms < PENDING_MS)
                        .ok_or("That sign-in has expired. Start again in the app.")?;
                    if p.approved.as_ref().is_some_and(|(id, _)| *id != input.id) {
                        return Err("That sign-in was approved for another client.".into());
                    }
                    let reg = st
                        .registrations
                        .iter()
                        .find(|r| r.client_id == p.client_id)
                        .ok_or("The app's registration is gone. Start again in the app.")?;
                    (reg.client_id.clone(), reg.name.clone())
                };
                if existing.as_ref().is_some_and(|c| c.oauth_client_id != oauth_client_id) {
                    return Err("That client is already connected as another app.".into());
                }
                let minted = !matches!(&existing, Some(c) if c.scope == input.scope);
                let token = match &existing {
                    Some(c) if !minted => c.token.clone(),
                    _ => self.mint(&input.id, &input.scope).await?,
                };
                // The sign-in may have run out while the token was made: then nothing is saved.
                let still = {
                    let st = self.st();
                    st.pending.get(req).is_some_and(|p| {
                        now - p.created_ms < PENDING_MS && p.approved.as_ref().is_none_or(|(id, _)| *id == input.id)
                    })
                };
                if !still {
                    if minted && existing.is_none() {
                        let _ = self.helper(&["revoke", &format!("client-{}", input.id)]).await;
                    }
                    return Err("That sign-in has expired. Start again in the app.".into());
                }
                let mut st = self.st();
                let mut issued = existing.map(|c| c.issued).unwrap_or_default();
                // Nothing outlives the end date.
                if let Some(end) = input.expires_ms {
                    for t in &mut issued {
                        t.expires_ms = t.expires_ms.min(end);
                    }
                }
                st.clients.retain(|c| c.id != input.id);
                st.clients.push(Client {
                    id: input.id.clone(),
                    oauth_client_id,
                    name: name.clone(),
                    scope: input.scope.clone(),
                    expires_ms: input.expires_ms,
                    token,
                    at: iso(now),
                    issued,
                });
                // The code itself is made when the browser comes back (`finish`).
                if let Some(p) = st.pending.get_mut(req) {
                    p.approved = Some((input.id.clone(), String::new()));
                    p.approval = input.approval.clone();
                }
                self.save(&st)?;
                tracing::info!(
                    "[gbrain-clients] {name} ({}) may use the brain ({})",
                    input.id,
                    input.scope
                );
            }
            (None, Some(c)) => {
                let token = if c.scope == input.scope {
                    c.token.clone()
                } else {
                    self.mint(&input.id, &input.scope).await?
                };
                let mut st = self.st();
                if let Some(x) = st.clients.iter_mut().find(|x| x.id == input.id) {
                    x.scope = input.scope.clone();
                    x.expires_ms = input.expires_ms;
                    x.token = token;
                    // Nothing outlives the end date.
                    if let Some(end) = x.expires_ms {
                        for t in &mut x.issued {
                            t.expires_ms = t.expires_ms.min(end);
                        }
                    }
                }
                self.save(&st)?;
                tracing::info!("[gbrain-clients] {} ({}) changed to {}", c.name, c.id, input.scope);
            }
            (None, None) => return Err("That app is not connected to the brain.".into()),
        }
        Ok(())
    }

    /// Take a client off: out of the store first (that alone stops it), then its GBrain token.
    pub async fn disconnect(&self, id: &str) -> Result<bool, String> {
        let _op = self.ops.lock().await;
        let had = {
            let mut st = self.st();
            let had = st.clients.iter().any(|c| c.id == id);
            st.clients.retain(|c| c.id != id);
            st.pending
                .retain(|_, p| p.approved.as_ref().is_none_or(|(cid, _)| cid != id));
            st.buckets.remove(id);
            self.save(&st)?;
            had
        };
        self.helper(&["revoke", &format!("client-{id}")])
            .await
            .map_err(|e| format!("could not revoke the app's brain token: {e}"))?;
        tracing::info!("[gbrain-clients] {id} disconnected from the brain");
        Ok(had)
    }

    /// After a restore the database's token table is the backup's: mint every client a new GBrain
    /// token. Same clients, same scopes; the apps' own tokens are untouched.
    pub async fn reissue_all(&self) -> (usize, Vec<String>) {
        let _op = self.ops.lock().await;
        let clients: Vec<(String, String)> = self
            .st()
            .clients
            .iter()
            .map(|c| (c.id.clone(), c.scope.clone()))
            .collect();
        let (mut done, mut failed) = (0, Vec::new());
        for (id, scope) in clients {
            match self.mint(&id, &scope).await {
                Ok(token) => {
                    let mut st = self.st();
                    if let Some(c) = st.clients.iter_mut().find(|c| c.id == id) {
                        c.token = token;
                    }
                    if self.save(&st).is_ok() {
                        done += 1;
                    } else {
                        failed.push(id);
                    }
                }
                Err(e) => {
                    tracing::error!("[gbrain-clients] could not reissue {id}'s token: {e}");
                    failed.push(id);
                }
            }
        }
        (done, failed)
    }
}

#[cfg(test)]
mod tests;
