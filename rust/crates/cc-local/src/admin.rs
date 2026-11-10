//! The admin login and the local API a standalone firewall serves on its panel listener.
//!
//! - **Setup.** At the first start there is no admin. The firewall makes a one-time setup token,
//!   keeps only its hash, and logs the token once. `POST /api/setup {token, password}` creates the
//!   admin and spends the token.
//! - **Login.** `POST /api/login {password}` checks the password (argon2id) and sets a session
//!   cookie: HttpOnly, SameSite=Strict, 12 hours, and Secure when the panel is served over HTTPS.
//!   Only the cookie's hash is stored. The answer carries the session's CSRF token, which every
//!   write sends back as `x-csrf-token`.
//! - **Password.** `POST /api/admin/password` changes it and ends the other sessions; `reset` is for
//!   a forgotten one (`password.rs`).
//! - **The API** is the route table in [`crate::api`] (docs/standalone/panel-api.md). Every route
//!   there runs after the checks here: the Host, the session, and on a write the CSRF token.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use http::Method;
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api;
use crate::db::{Db, now_s};
use crate::plane::{BoxFuture, LocalControlPlane};

pub const COOKIE: &str = "cc_local_session";
const SESSION_S: i64 = 12 * 3600;
const PASSWORD_MIN: usize = 12;
const BODY_MAX: usize = 256 * 1024;
/// Login and setup tries allowed per minute from one client address, and from all together.
const FAILURES_PER_MINUTE: usize = 10;
const FAILURES_PER_MINUTE_ALL: usize = 30;
/// argon2 checks at once: each takes 19 MiB, so a burst of logins cannot take the box's memory.
const ARGON_PERMITS: usize = 2;
const SETUP_HASH: &str = "setup_token_sha256";

/// Runs a command handler: `None` when no handler has the action.
pub type CommandHook = Arc<dyn Fn(String, Map<String, Value>) -> BoxFuture<'static, Option<Value>> + Send + Sync>;
/// Makes a link that opens one of the firewall's own pages.
pub type OpenLinkHook = Arc<dyn Fn(&str) -> Result<String, String> + Send + Sync>;

/// What the firewall says about itself: its beat fields (`Commands::beat_fields`).
pub type StatusHook = Arc<dyn Fn() -> Map<String, Value> + Send + Sync>;
/// Tell the firewall its rules or AI settings changed, so it reads them now.
pub type NotifyHook = Arc<dyn Fn() + Send + Sync>;

/// What the API needs from the firewall around it.
#[derive(Clone)]
pub struct Hooks {
    /// Run a command handler as the signed-in admin: `None` when no handler has the action.
    pub command: CommandHook,
    /// A link that opens one of the firewall's own pages (`mitm-agent open`).
    pub open_link: OpenLinkHook,
    /// The beat fields: the stop's and the exit's state (`kill`, `residential`).
    pub status: StatusHook,
    pub rules_changed: NotifyHook,
}

impl Default for Hooks {
    /// Nothing behind it: no command runs, no page opens.
    fn default() -> Self {
        Self {
            command: Arc::new(|_, _| Box::pin(async { None })),
            open_link: Arc::new(|_| Err("no pages here".into())),
            status: Arc::new(Map::new),
            rules_changed: Arc::new(|| {}),
        }
    }
}

/// How the API is reached.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// `Secure` on the session cookie: the browser reaches the API on `localhost` or over HTTPS.
    pub secure: bool,
    /// The names a request's `Host` may carry, without a port: loopback, the bind address and the
    /// names it is served under (Caddy, Tailscale Serve). Anything else is refused, so a web page
    /// whose name resolves to 127.0.0.1 (DNS rebinding) cannot reach the API through a tunnel.
    pub hosts: Vec<String>,
}

impl AdminConfig {
    /// Loopback names plus `more`.
    pub fn with_hosts(secure: bool, more: impl IntoIterator<Item = String>) -> Self {
        let mut hosts: Vec<String> = ["localhost", "127.0.0.1", "::1"]
            .iter()
            .map(|h| h.to_string())
            .collect();
        hosts.extend(
            more.into_iter()
                .map(|h| h.trim().trim_matches(['[', ']']).to_lowercase())
                .filter(|h| !h.is_empty()),
        );
        Self { secure, hosts }
    }
}

pub struct Admin {
    db: Arc<Db>,
    plane: Arc<LocalControlPlane>,
    hooks: Hooks,
    config: AdminConfig,
    /// Login and setup tries in the last minute, by client address; cleared on success.
    failures: Mutex<HashMap<IpAddr, VecDeque<i64>>>,
    argon: tokio::sync::Semaphore,
    routes: Vec<api::Route>,
}

fn token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// Equal in time, whatever the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

struct Session {
    user_id: i64,
    csrf: String,
    token_hash: String,
}

impl Admin {
    pub fn new(db: Arc<Db>, plane: Arc<LocalControlPlane>, hooks: Hooks, config: AdminConfig) -> Arc<Self> {
        Arc::new(Self {
            db,
            plane,
            hooks,
            config,
            failures: Mutex::new(HashMap::new()),
            argon: tokio::sync::Semaphore::new(ARGON_PERMITS),
            routes: api::routes(),
        })
    }

    /// Read the firewall's bots, inboxes and Google grants for their rules (`api::managed`): one set
    /// up before the rules existed, or changed while nobody read them, gets its rule without anyone
    /// opening its page. Retried until the firewall's modules answer; after that, every change made
    /// here reads them again.
    pub async fn read_managed(&self) {
        let c = api::Ctx {
            db: self.db.clone(),
            plane: self.plane.clone(),
            hooks: self.hooks.clone(),
            params: HashMap::new(),
            query: String::new(),
        };
        let mut wait = std::time::Duration::from_secs(5);
        loop {
            tokio::time::sleep(wait).await;
            match api::managed::refresh_all(&c).await {
                Ok(()) => return,
                Err(e) => tracing::warn!(
                    "[cc-local] the bots' and accounts' rules (again in a while): {}",
                    e.body
                ),
            }
            wait = (wait * 2).min(std::time::Duration::from_secs(300));
        }
    }

    /// The request's `Host` names this API (`AdminConfig::hosts`).
    pub(crate) fn host_ok(&self, host: Option<&str>) -> bool {
        let Some(h) = host.map(str::trim).filter(|h| !h.is_empty()) else {
            return false;
        };
        let name = if let Some(rest) = h.strip_prefix('[') {
            rest.split(']').next().unwrap_or_default()
        } else {
            h.rsplit_once(':').map_or(
                h,
                |(n, port)| if port.chars().all(|c| c.is_ascii_digit()) { n } else { h },
            )
        };
        let name = name.to_lowercase();
        self.config.hosts.contains(&name)
    }

    /// argon2, off the async threads and at most `ARGON_PERMITS` at once.
    async fn argon<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let _permit = self.argon.acquire().await.ok()?;
        tokio::task::spawn_blocking(f).await.ok()
    }

    fn has_admin(&self) -> bool {
        self.db
            .lock()
            .query_row("SELECT 1 FROM admin_users LIMIT 1", [], |_| Ok(()))
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// At start: with no admin yet, a fresh setup token (its hash kept) for the log. A token from
    /// an earlier start is replaced, so only the newest log line works.
    pub fn setup_token(&self) -> Option<String> {
        if self.has_admin() {
            return None;
        }
        let t = token();
        self.db.set_setting(SETUP_HASH, &sha(&t)).ok()?;
        Some(t)
    }

    fn hash_password(pw: &str) -> Result<String, String> {
        Argon2::default()
            .hash_password(pw.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|h| h.to_string())
            .map_err(|e| e.to_string())
    }

    fn check_password(pw: &str, hash: &str) -> bool {
        PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
    }

    /// Count a try from `ip`, unless there were too many from it, or from everyone, in the last
    /// minute: then `false`. The check and the count are one step under the lock, so parallel tries
    /// cannot all pass. Behind a reverse proxy or a tunnel every client has the same address and
    /// shares one budget; the shared cap means a flood of bad tries also holds the admin off for
    /// the rest of that minute.
    fn try_begin(&self, ip: IpAddr) -> bool {
        let mut all = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_s();
        all.retain(|_, f| {
            while f.front().is_some_and(|t| *t < now - 60) {
                f.pop_front();
            }
            !f.is_empty()
        });
        if all.get(&ip).is_some_and(|f| f.len() >= FAILURES_PER_MINUTE)
            || all.values().map(VecDeque::len).sum::<usize>() >= FAILURES_PER_MINUTE_ALL
        {
            return false;
        }
        all.entry(ip).or_default().push_back(now);
        true
    }

    /// A try that succeeded no longer counts. Only that one: other tries from the same address
    /// (every client, behind a proxy) still do.
    fn succeeded(&self, ip: IpAddr) {
        if let Some(f) = self.failures.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&ip) {
            f.pop_back();
        }
    }

    fn start_session(&self, user_id: i64) -> Result<(String, String), String> {
        let (cookie, csrf) = (token(), token());
        let now = now_s();
        self.db
            .lock()
            .execute(
                "INSERT INTO sessions (token_hash, user_id, csrf, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sha(&cookie), user_id, csrf, now, now + SESSION_S],
            )
            .map_err(|e| e.to_string())?;
        Ok((cookie, csrf))
    }

    fn session(&self, cookie_header: Option<&str>) -> Option<Session> {
        let value = cookie_header?
            .split(';')
            .filter_map(|c| c.trim().split_once('='))
            .find(|(k, _)| *k == COOKIE)?
            .1;
        let token_hash = sha(value);
        self.db
            .lock()
            .query_row(
                "SELECT user_id, csrf FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, now_s()],
                |r| {
                    Ok(Session {
                        user_id: r.get(0)?,
                        csrf: r.get(1)?,
                        token_hash: token_hash.clone(),
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
    }

    fn set_cookie(&self, value: &str, max_age: i64) -> String {
        format!(
            "{COOKIE}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
            if self.config.secure { "; Secure" } else { "" }
        )
    }

    /// The panel API, under `/api/`.
    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["api"]);
        let me = self.clone();
        r.prefix("api", "/api/", move |req, ctx| {
            let me = me.clone();
            async move { me.handle(req, ctx.remote.ip()).await }
        });
        r.fallback(cc_http::not_found);
        r
    }

    async fn handle(&self, req: cc_http::Req, ip: IpAddr) -> cc_http::Resp {
        let (parts, body) = req.into_parts();
        if !self.host_ok(cc_http::header(&parts, "host")) {
            return reply(
                421,
                json!({"error": "This firewall's API is not served under that name"}),
            );
        }
        let path = cc_http::pathname(parts.uri.path());
        let query = parts.uri.query().unwrap_or_default().to_string();
        let method = parts.method.clone();
        let body: Value = if method == Method::GET {
            Value::Null
        } else {
            match cc_http::read_body(body, BODY_MAX).await {
                Some(b) if b.is_empty() => Value::Null,
                Some(b) => match serde_json::from_slice(&b) {
                    Ok(v) => v,
                    Err(_) => return reply(400, json!({"error": "Invalid JSON"})),
                },
                None => return reply(413, json!({"error": "Body too large or too slow"})),
            }
        };
        let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        match (method.as_str(), path.as_str()) {
            ("POST", "/api/setup") => return self.setup(ip, &s("token"), &s("password")).await,
            ("POST", "/api/login") => return self.login(ip, &s("password")).await,
            ("GET", "/api/session") => {
                let sess = self.session(cc_http::header(&parts, "cookie"));
                return reply(
                    200,
                    json!({"admin": sess.is_some(), "setup": !self.has_admin(), "csrf": sess.map(|x| x.csrf)}),
                );
            }
            _ => {}
        }
        let Some(sess) = self.session(cc_http::header(&parts, "cookie")) else {
            return reply(401, json!({"error": "Sign in first"}));
        };
        // Every write carries the session's CSRF token; a GET changes nothing.
        if method != Method::GET && !same(cc_http::header(&parts, "x-csrf-token").unwrap_or_default(), &sess.csrf) {
            return reply(403, json!({"error": "Missing or wrong CSRF token"}));
        }
        if (method.as_str(), path.as_str()) == ("POST", "/api/admin/password") {
            return self.change_password(ip, &sess, &s("current"), &s("new")).await;
        }
        if (method.as_str(), path.as_str()) == ("POST", "/api/logout") {
            let _ = self
                .db
                .lock()
                .execute("DELETE FROM sessions WHERE user_id = ?1", [sess.user_id]);
            let mut r = reply(200, json!({"ok": true}));
            cookie(&mut r, &self.set_cookie("", 0));
            return r;
        }
        let (route, params) = match api::find(&self.routes, &method, &path) {
            api::Found::Route(r, p) => (r, p),
            api::Found::Method => return reply(405, json!({"error": "Method not allowed"})),
            api::Found::None => return cc_http::not_found(),
        };
        let ctx = api::Ctx {
            db: self.db.clone(),
            plane: self.plane.clone(),
            hooks: self.hooks.clone(),
            params,
            query,
        };
        let r = api::call(route, ctx, body).await;
        reply(r.status, r.body)
    }

    async fn setup(&self, ip: IpAddr, token: &str, password: &str) -> cc_http::Resp {
        if self.has_admin() {
            return reply(409, json!({"error": "This firewall has an admin already. Sign in."}));
        }
        if !self.try_begin(ip) {
            return reply(429, json!({"error": "Too many tries. Wait a minute."}));
        }
        let Some(hash) = self.db.setting(SETUP_HASH) else {
            return reply(
                409,
                json!({"error": "No setup token. Restart the firewall for a new one."}),
            );
        };
        if !same(&sha(token), &hash) {
            return reply(401, json!({"error": "Wrong setup token"}));
        }
        if password.chars().count() < PASSWORD_MIN {
            return reply(
                400,
                json!({"error": format!("The password needs at least {PASSWORD_MIN} characters")}),
            );
        }
        let pw = password.to_string();
        let hashed = self
            .argon(move || Self::hash_password(&pw))
            .await
            .unwrap_or_else(|| Err("argon2 did not run".into()));
        let created = hashed.and_then(|h| {
            let c = self.db.lock();
            c.execute(
                "INSERT INTO admin_users (username, password_hash, created_at) VALUES ('admin', ?1, ?2)",
                params![h, now_s()],
            )
            .map_err(|e| e.to_string())?;
            c.execute("DELETE FROM settings WHERE key = ?1", [SETUP_HASH])
                .map_err(|e| e.to_string())?;
            Ok(c.last_insert_rowid())
        });
        match created.and_then(|id| self.start_session(id)) {
            Ok((cookie_value, csrf)) => {
                self.succeeded(ip);
                tracing::info!("[cc-local] the admin was set up; the setup token is spent");
                let mut r = reply(200, json!({"ok": true, "csrf": csrf}));
                cookie(&mut r, &self.set_cookie(&cookie_value, SESSION_S));
                r
            }
            Err(e) => {
                tracing::error!("[cc-local] setup: {e}");
                reply(500, json!({"error": "Failed"}))
            }
        }
    }

    async fn login(&self, ip: IpAddr, password: &str) -> cc_http::Resp {
        if !self.try_begin(ip) {
            return reply(429, json!({"error": "Too many tries. Wait a minute."}));
        }
        let row: Option<(i64, String)> = self
            .db
            .lock()
            .query_row(
                "SELECT id, password_hash FROM admin_users WHERE username = 'admin'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        let checked = match row {
            Some((id, hash)) => {
                let pw = password.to_string();
                self.argon(move || Self::check_password(&pw, &hash))
                    .await
                    .unwrap_or(false)
                    .then_some(id)
            }
            None => None,
        };
        let Some(id) = checked else {
            return reply(401, json!({"error": "Wrong password"}));
        };
        match self.start_session(id) {
            Ok((cookie_value, csrf)) => {
                self.succeeded(ip);
                let mut r = reply(200, json!({"ok": true, "csrf": csrf}));
                cookie(&mut r, &self.set_cookie(&cookie_value, SESSION_S));
                r
            }
            Err(e) => {
                tracing::error!("[cc-local] login: {e}");
                reply(500, json!({"error": "Failed"}))
            }
        }
    }
}

pub use crate::api::panel::replace_rules;

fn reply(status: u16, body: Value) -> cc_http::Resp {
    let mut r = cc_http::json(status, &body);
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", http::HeaderValue::from_static("nosniff"));
    r
}

fn cookie(r: &mut cc_http::Resp, value: &str) {
    if let Ok(v) = http::HeaderValue::from_str(value) {
        r.headers_mut().append(http::header::SET_COOKIE, v);
    }
}

mod password;
pub use password::reset;

#[cfg(test)]
mod tests;
