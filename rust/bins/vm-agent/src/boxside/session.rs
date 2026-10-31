//! Browser sessions on this box (`session.ts`). A firewall ticket checked at `/__cc/session` buys an
//! HS256 cookie signed with a random per-box secret that never leaves the box (`KEYS_DIR/
//! session_secret`, hex). Three cookies, never interchangeable: the OpenClaw session
//! (`__Host-cc_session`, no `aud`), the live-browser view (`__Secure-cc_view`, `aud: "view"`) and the
//! widget sandbox host's (`__Host-cc_sandbox`, `aud: "sandbox"`), bought with a one-time ticket
//! (`aud: "sandbox-ticket"`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use cc_auth::jwt::{self, Claims, SignKey, VerifyKey, VerifyOptions};
use serde_json::{Map, Value};

use super::access_state::{AccessState, now_ms};

pub const SESSION_COOKIE: &str = "__Host-cc_session";
const SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;
pub const VIEW_COOKIE: &str = "__Secure-cc_view";
const VIEW_COOKIE_PATH: &str = "/__cc/novnc";
const VIEW_AUDIENCE: &str = "view";
pub const SANDBOX_COOKIE: &str = "__Host-cc_sandbox";
const SANDBOX_AUDIENCE: &str = "sandbox";
const SANDBOX_TICKET_AUDIENCE: &str = "sandbox-ticket";
pub const SANDBOX_TICKET_TTL_SECONDS: i64 = 60;
/// The sandbox cookie lasts an hour at most, and never past the dashboard session.
const SANDBOX_TTL_SECONDS: i64 = 60 * 60;

/// What the OpenClaw session says about the person holding it (`SessionClaims`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionClaims {
    /// Owner or admin. Read as `=== true` only: absent is read-only.
    pub can_write: bool,
    /// The firewall's name for the browser, when the session came from a firewall ticket.
    pub device_id: Option<String>,
}

pub struct Sessions {
    keys_dir: PathBuf,
    secret: RwLock<Option<Vec<u8>>>,
    access: Arc<AccessState>,
    /// Login and sandbox ticket ids spent, with their expiry (s) (`seenJti`).
    seen_jti: Mutex<HashMap<String, i64>>,
}

fn now_s() -> i64 {
    jwt::now_s()
}

/// jose's audience check: a string equal to it, or an array that holds it.
fn has_audience(claims: &Claims, aud: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(s)) => s == aud,
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(aud)),
        _ => false,
    }
}

/// `readUniqueCookie`, with the TS's log line when a name came twice (cookie tossing).
pub fn unique_cookie(header: Option<&str>, name: &str) -> Option<String> {
    let reading = cc_origin::read_unique_cookie(header, name);
    if reading.duplicated {
        tracing::warn!("[session] {name} arrived more than once — ignoring it (cookie tossing)");
    }
    reading.value
}

impl Sessions {
    /// Reads the secret `main` made at start (`ensureSessionSecret`); without one every session
    /// is refused, as the TS refuses before `ensureSessionSecret` ran.
    pub fn new(keys_dir: PathBuf, access: Arc<AccessState>) -> Self {
        let secret = read_secret(&keys_dir);
        Self {
            keys_dir,
            secret: RwLock::new(secret),
            access,
            seen_jti: Mutex::new(HashMap::new()),
        }
    }

    fn secret(&self) -> Option<Vec<u8>> {
        self.secret.read().ok().and_then(|s| s.clone())
    }

    /// "Sign out all browsers": a new secret, so every cookie this box issued stops verifying, and
    /// the revoked list is cleared with it (`rotateSessionSecret`).
    pub fn rotate_secret(&self) -> std::io::Result<()> {
        let mut b = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        let path = self.keys_dir.join("session_secret");
        // Whole or not at all: a half-written secret would be a short key.
        cc_store::write_atomic(&path, hex::encode(b).as_bytes(), 0o600, cc_store::TmpName::Suffix)?;
        if let Ok(mut s) = self.secret.write() {
            *s = Some(b.to_vec());
        }
        self.access.clear_revoked()?;
        tracing::info!("[session] rotated the session secret: every browser is signed out");
        Ok(())
    }

    fn sign(&self, claims: Map<String, Value>, lifetime_s: i64, now: Option<i64>) -> Option<String> {
        let secret = self.secret()?;
        jwt::sign(claims, &SignKey::Hs256(secret), Some(lifetime_s), now).ok()
    }

    fn verify(&self, token: &str) -> Option<Claims> {
        let secret = self.secret()?;
        jwt::verify(token, &VerifyKey::Hs256(secret), VerifyOptions::default()).ok()
    }

    /// `typeof dev === "string" && isRevoked(dev)`, the check on the view and sandbox cookies.
    fn revoked(&self, claims: &Claims) -> bool {
        matches!(claims.get("dev"), Some(Value::String(d)) if self.access.is_revoked(d, now_ms()))
    }

    /// The token's device (`deviceId ? … : {}`: an empty one is none), or `Err` when it is revoked.
    fn device(&self, claims: &Claims) -> Result<Option<String>, ()> {
        let device_id = claims
            .get("dev")
            .and_then(Value::as_str)
            .filter(|d| !d.is_empty())
            .map(str::to_string);
        if device_id
            .as_deref()
            .is_some_and(|d| self.access.is_revoked(d, now_ms()))
        {
            return Err(());
        }
        Ok(device_id)
    }

    pub fn issue_session(&self, vm_id: &str, claims: &SessionClaims) -> Option<String> {
        let mut c = Map::new();
        c.insert("sub".into(), Value::String(vm_id.into()));
        if claims.can_write {
            c.insert("canWrite".into(), Value::Bool(true));
        }
        if let Some(d) = claims.device_id.as_ref().filter(|d| !d.is_empty()) {
            c.insert("dev".into(), Value::String(d.clone()));
        }
        self.sign(c, SESSION_TTL_SECONDS, None)
    }

    /// The claims of a valid session for this box and its expiry (s), or `None`
    /// (`readSessionWithExpiry`). Only a token with no audience is an OpenClaw session.
    pub fn read_session_with_expiry(&self, cookie_header: Option<&str>, vm_id: &str) -> Option<(SessionClaims, f64)> {
        self.secret()?;
        let header = cookie_header.filter(|h| !h.is_empty())?;
        let token = unique_cookie(Some(header), SESSION_COOKIE)?;
        if token.is_empty() {
            return None;
        }
        let p = self.verify(&token)?;
        if p.get("sub").and_then(Value::as_str) != Some(vm_id) || p.contains_key("aud") {
            return None;
        }
        let exp = p.get("exp").and_then(Value::as_f64)?;
        let device_id = self.device(&p).ok()?;
        Some((
            SessionClaims {
                can_write: p.get("canWrite") == Some(&Value::Bool(true)),
                device_id,
            },
            exp,
        ))
    }

    pub fn read_session(&self, cookie_header: Option<&str>, vm_id: &str) -> Option<SessionClaims> {
        self.read_session_with_expiry(cookie_header, vm_id).map(|(c, _)| c)
    }

    pub fn verify_session(&self, cookie_header: Option<&str>, vm_id: &str) -> bool {
        self.read_session(cookie_header, vm_id).is_some()
    }

    pub fn issue_view_session(&self, vm_id: &str, device_id: Option<&str>) -> Option<String> {
        let mut c = Map::new();
        c.insert("sub".into(), Value::String(vm_id.into()));
        if let Some(d) = device_id.filter(|d| !d.is_empty()) {
            c.insert("dev".into(), Value::String(d.into()));
        }
        c.insert("aud".into(), Value::String(VIEW_AUDIENCE.into()));
        self.sign(c, SESSION_TTL_SECONDS, None)
    }

    pub fn verify_view_session(&self, cookie_header: Option<&str>, vm_id: &str) -> bool {
        self.verify_aud_cookie(cookie_header, vm_id, VIEW_COOKIE, VIEW_AUDIENCE)
    }

    fn verify_aud_cookie(&self, cookie_header: Option<&str>, vm_id: &str, name: &str, aud: &str) -> bool {
        if self.secret().is_none() {
            return false;
        }
        let Some(header) = cookie_header.filter(|h| !h.is_empty()) else {
            return false;
        };
        let Some(token) = unique_cookie(Some(header), name).filter(|t| !t.is_empty()) else {
            return false;
        };
        let Some(p) = self.verify(&token) else { return false };
        if !has_audience(&p, aud) || self.revoked(&p) {
            return false;
        }
        p.get("sub").and_then(Value::as_str) == Some(vm_id)
    }

    /// Each login or sandbox ticket id is accepted once; entries go with the token (`consumeJti`).
    /// The check and the insert are one step under the lock.
    pub fn consume_jti(&self, jti: &str, exp_seconds: f64) -> bool {
        let now = now_s();
        let mut seen = self.seen_jti.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(jti) {
            return false;
        }
        // An `exp` is a JSON number; jose takes fractions, so keep it whole seconds, rounded up.
        seen.insert(jti.to_string(), exp_seconds.ceil() as i64);
        true
    }

    /// A ticket for the sandbox host, minted for whoever holds a valid OpenClaw session.
    pub fn issue_sandbox_ticket(&self, cookie_header: Option<&str>, vm_id: &str) -> Option<String> {
        self.secret()?;
        let (claims, exp) = self.read_session_with_expiry(cookie_header, vm_id)?;
        let mut c = Map::new();
        c.insert("sub".into(), Value::String(vm_id.into()));
        c.insert("sexp".into(), number(exp));
        if let Some(d) = claims.device_id {
            c.insert("dev".into(), Value::String(d));
        }
        c.insert("aud".into(), Value::String(SANDBOX_TICKET_AUDIENCE.into()));
        c.insert("jti".into(), Value::String(uuid::Uuid::new_v4().to_string()));
        self.sign(c, SANDBOX_TICKET_TTL_SECONDS, None)
    }

    /// Spend a ticket (once, within its minute) for the sandbox host's own cookie and its max-age.
    pub fn redeem_sandbox_ticket(&self, ticket: &str, vm_id: &str) -> Option<(String, i64)> {
        self.secret()?;
        if ticket.is_empty() {
            return None;
        }
        let p = self.verify(ticket)?;
        if !has_audience(&p, SANDBOX_TICKET_AUDIENCE) || p.get("sub").and_then(Value::as_str) != Some(vm_id) {
            return None;
        }
        let jti = p.get("jti").and_then(Value::as_str)?;
        let exp = p.get("exp").and_then(Value::as_f64)?;
        let sexp = p.get("sexp").and_then(Value::as_f64)?;
        let device_id = self.device(&p).ok()?;
        if !self.consume_jti(&format!("sandbox:{jti}"), exp) {
            return None;
        }
        let now = now_s();
        let exp = sexp.min((now + SANDBOX_TTL_SECONDS) as f64);
        if exp <= now as f64 {
            return None;
        }
        // jose's `setExpirationTime(number)` takes the number as it is.
        let exp = exp.floor() as i64;
        let mut c = Map::new();
        c.insert("sub".into(), Value::String(vm_id.into()));
        if let Some(d) = device_id {
            c.insert("dev".into(), Value::String(d));
        }
        c.insert("aud".into(), Value::String(SANDBOX_AUDIENCE.into()));
        let token = self.sign(c, exp - now, Some(now))?;
        Some((token, exp - now))
    }

    pub fn verify_sandbox_session(&self, cookie_header: Option<&str>, vm_id: &str) -> bool {
        self.verify_aud_cookie(cookie_header, vm_id, SANDBOX_COOKIE, SANDBOX_AUDIENCE)
    }
}

fn number(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9e15 {
        Value::from(f as i64)
    } else {
        serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null)
    }
}

/// The HS256 key, or `None` unless the file holds exactly 32 bytes of hex. Without a key every
/// session is refused: a short or empty one would let anyone sign a session, and the TS (jose)
/// refuses a zero-length key too. `main` remakes a bad file at start (`keys::ensure_session_secret`).
fn read_secret(keys_dir: &std::path::Path) -> Option<Vec<u8>> {
    let raw = std::fs::read_to_string(keys_dir.join("session_secret")).ok()?;
    hex::decode(raw.trim())
        .ok()
        .filter(|k| k.len() == crate::keys::SESSION_SECRET_BYTES)
}

pub fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax")
}

pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

pub fn view_session_cookie(token: &str) -> String {
    format!(
        "{VIEW_COOKIE}={token}; Path={VIEW_COOKIE_PATH}; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=None"
    )
}

pub fn clear_view_session_cookie() -> String {
    format!("{VIEW_COOKIE}=; Path={VIEW_COOKIE_PATH}; Max-Age=0; HttpOnly; Secure; SameSite=None")
}

pub fn sandbox_cookie(token: &str, max_age: i64) -> String {
    format!("{SANDBOX_COOKIE}={token}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax")
}

/// The `Sessions` contract W8's pages use.
pub struct SessionsContract {
    pub sessions: Arc<Sessions>,
    pub keys: cc_auth::keys::KeysDir,
}

impl crate::contracts::Sessions for SessionsContract {
    fn session(&self, parts: &http::request::Parts) -> Option<crate::contracts::Session> {
        let vm_id = self.keys.vm_id()?;
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        self.sessions
            .read_session(cookie.as_deref(), &vm_id)
            .map(|c| crate::contracts::Session {
                can_write: c.can_write,
                device_id: c.device_id,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VM: &str = "vm_test_1";
    const OTHER: &str = "vm_test_2";

    fn sessions() -> (tempfile::TempDir, Sessions) {
        let dir = tempfile::tempdir().expect("dir");
        std::fs::write(dir.path().join("session_secret"), hex::encode([9u8; 32])).expect("secret");
        let access = Arc::new(AccessState::new(dir.path()));
        let s = Sessions::new(dir.path().to_path_buf(), access);
        (dir, s)
    }

    fn cookie(set: &str) -> String {
        set.split(';').next().unwrap_or_default().to_string()
    }

    #[test]
    fn each_cookie_verifies_for_its_own_box() {
        let (_d, s) = sessions();
        let c = |t: Option<String>| cookie(&session_cookie(&t.expect("token")));
        let v = |t: Option<String>| cookie(&view_session_cookie(&t.expect("token")));
        let none = SessionClaims::default();
        assert!(s.verify_session(Some(&c(s.issue_session(VM, &none))), VM));
        assert!(s.verify_view_session(Some(&v(s.issue_view_session(VM, None))), VM));
        assert!(!s.verify_session(Some(&c(s.issue_session(OTHER, &none))), VM));
        assert!(!s.verify_view_session(Some(&v(s.issue_view_session(OTHER, None))), VM));
    }

    #[test]
    fn a_view_token_replayed_as_the_openclaw_cookie_is_refused_and_the_reverse() {
        let (_d, s) = sessions();
        let view = s.issue_view_session(VM, None).expect("view");
        assert!(!s.verify_session(Some(&format!("{SESSION_COOKIE}={view}")), VM));
        let session = s.issue_session(VM, &SessionClaims::default()).expect("session");
        assert!(!s.verify_view_session(Some(&format!("{VIEW_COOKIE}={session}")), VM));
    }

    #[test]
    fn the_view_cookie_is_scoped_to_the_novnc_route_and_can_cross_sites() {
        let set = view_session_cookie("t");
        assert!(set.starts_with("__Secure-cc_view="));
        for part in ["Path=/__cc/novnc", "SameSite=None", "Secure", "HttpOnly"] {
            assert!(set.contains(part), "{set}");
        }
        assert!(!set.contains("Partitioned"));
    }

    #[test]
    fn the_session_carries_what_the_ticket_said_the_holder_may_do() {
        let (_d, s) = sessions();
        let owner = cookie(&session_cookie(
            &s.issue_session(
                VM,
                &SessionClaims {
                    can_write: true,
                    device_id: None,
                },
            )
            .expect("t"),
        ));
        let reader = cookie(&session_cookie(
            &s.issue_session(VM, &SessionClaims::default()).expect("t"),
        ));
        assert_eq!(
            s.read_session(Some(&owner), VM),
            Some(SessionClaims {
                can_write: true,
                device_id: None
            })
        );
        assert_eq!(s.read_session(Some(&reader), VM), Some(SessionClaims::default()));
        assert!(s.verify_session(Some(&reader), VM));
    }

    #[test]
    fn a_claim_cannot_be_smuggled_past_the_box_signature() {
        let (_d, s) = sessions();
        let token = s.issue_session(VM, &SessionClaims::default()).expect("t");
        let parts: Vec<&str> = token.split('.').collect();
        use base64::Engine;
        let body =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"{VM}","canWrite":true}}"#));
        assert_eq!(
            s.read_session(Some(&format!("{SESSION_COOKIE}={}.{body}.{}", parts[0], parts[2])), VM),
            None
        );
    }

    #[test]
    fn garbage_and_missing_cookies_are_false() {
        let (_d, s) = sessions();
        assert!(!s.verify_session(None, VM));
        assert!(!s.verify_view_session(None, VM));
        assert!(!s.verify_view_session(Some(&format!("{VIEW_COOKIE}=not-a-jwt")), VM));
        assert!(!s.verify_session(Some("unrelated=1"), VM));
    }

    #[test]
    fn a_tossed_duplicate_is_read_as_none() {
        let (_d, s) = sessions();
        let t = s.issue_session(VM, &SessionClaims::default()).expect("t");
        assert!(!s.verify_session(Some(&format!("{SESSION_COOKIE}={t}; {SESSION_COOKIE}={t}")), VM));
    }

    #[test]
    fn a_revoked_device_and_a_rotated_secret_end_sessions() {
        let (_d, s) = sessions();
        let claims = |d: &str| SessionClaims {
            can_write: false,
            device_id: Some(d.into()),
        };
        let a = cookie(&session_cookie(&s.issue_session(VM, &claims("dev_a")).expect("t")));
        let b = cookie(&session_cookie(&s.issue_session(VM, &claims("dev_b")).expect("t")));
        s.access.revoke_devices(&["dev_a".into()], now_ms()).expect("save");
        assert!(!s.verify_session(Some(&a), VM));
        assert!(s.verify_session(Some(&b), VM));
        s.rotate_secret().expect("rotate");
        assert!(!s.verify_session(Some(&b), VM));
        // The revoked list went with the old secret.
        assert!(!s.access.is_revoked("dev_a", now_ms()));
    }

    #[test]
    fn an_empty_or_short_secret_signs_nobody_in() {
        for bad in ["", "\n", "abcd", "not hex at all"] {
            let dir = tempfile::tempdir().expect("dir");
            std::fs::write(dir.path().join("session_secret"), bad).expect("secret");
            let s = Sessions::new(dir.path().to_path_buf(), Arc::new(AccessState::new(dir.path())));
            // A session an attacker signs with the key the file would give.
            let key = hex::decode(bad.trim()).unwrap_or_default();
            let mut c = Map::new();
            c.insert("sub".into(), Value::String(VM.into()));
            c.insert("canWrite".into(), Value::Bool(true));
            let forged = jwt::sign(c, &SignKey::Hs256(key), Some(3600), None).expect("sign");
            assert_eq!(
                s.read_session(Some(&format!("{SESSION_COOKIE}={forged}")), VM),
                None,
                "{bad:?}"
            );
            assert_eq!(s.issue_session(VM, &SessionClaims::default()), None);
            assert!(s.issue_sandbox_ticket(Some("x=y"), VM).is_none());
        }
    }

    #[test]
    fn jti_once() {
        let (_d, s) = sessions();
        let exp = (now_s() + 60) as f64;
        assert!(s.consume_jti("a", exp));
        assert!(!s.consume_jti("a", exp));
        assert!(s.consume_jti("b", exp));
        // An expired entry is forgotten.
        assert!(s.consume_jti("c", (now_s() - 1) as f64));
        assert!(s.consume_jti("c", exp));
    }

    #[test]
    fn sandbox_ticket_once_for_a_session_never_past_it() {
        let (_d, s) = sessions();
        let session = cookie(&session_cookie(
            &s.issue_session(
                VM,
                &SessionClaims {
                    can_write: true,
                    device_id: Some("d".into()),
                },
            )
            .expect("t"),
        ));
        assert_eq!(s.issue_sandbox_ticket(None, VM), None);
        let t = s.issue_sandbox_ticket(Some(&session), VM).expect("ticket");
        let (token, max_age) = s.redeem_sandbox_ticket(&t, VM).expect("redeem");
        assert!((SANDBOX_TTL_SECONDS - 1..=SANDBOX_TTL_SECONDS).contains(&max_age));
        assert_eq!(s.redeem_sandbox_ticket(&t, VM), None, "spent once");
        let c = cookie(&sandbox_cookie(&token, max_age));
        assert!(s.verify_sandbox_session(Some(&c), VM));
        assert!(!s.verify_sandbox_session(Some(&c), OTHER));
        // A sandbox cookie is not a session, nor a ticket.
        assert!(!s.verify_session(Some(&format!("{SESSION_COOKIE}={token}")), VM));
        assert_eq!(s.redeem_sandbox_ticket(&token, VM), None);
        s.access.revoke_devices(&["d".into()], now_ms()).expect("save");
        assert!(!s.verify_sandbox_session(Some(&c), VM));
    }
}
