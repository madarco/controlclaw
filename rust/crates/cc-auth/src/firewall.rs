//! Tokens the organization's firewall signs for an agent box (`packages/vm-agent/src/auth.ts`,
//! `verifyMitmRequest` and `bindingProblem`).
//!
//! A token names the route's `purpose` and this box's `vmId`, and is bound to one request: method
//! `m`, path `p` (no query), host `h`, body hash `b`, and an id `jti` taken once. Until this box
//! has seen one bound token from its firewall it also takes unbound ones (an older firewall), except
//! for the purposes that never existed without the binding. Seeing one is kept on disk (the latch),
//! as is the time of the newest token taken, so that after a restart, when the taken ids are gone,
//! nothing as old is taken again.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use indexmap::IndexMap;
use serde_json::Value;

use crate::jwt::{self, Claims, VerifyKey, VerifyOptions};
use crate::request_path;

/// How long a taken id is kept after its token ends: the phone stream allows two minutes of clock
/// difference, so an id must outlive that.
const TAKEN_KEPT_MS: i64 = 150_000;
/// Past this many ids a new token is refused rather than an id forgotten early.
const TAKEN_MAX: usize = 20_000;
/// How far ahead of this box's clock a token's `iat` may be.
const AHEAD_MS: i64 = 150_000;
/// Expired ids looked at per call.
const TAKEN_SWEEP: usize = 64;

/// Purposes that never existed without the binding.
const ALWAYS_BOUND: &[&str] = &[
    "apply-read",
    "apply-ticket",
    "template-check",
    "template-repair",
    "template-capture",
    "disk",
    "mcp-servers",
];

/// Why a token was refused, as the fixed words the TS puts on `req.ccRefused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Unbound,
    Method,
    Path,
    Host,
    Body,
    Time,
    Ahead,
    BeforeRestart,
    Replay,
    Busy,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Unbound => "unbound",
            Refusal::Method => "method",
            Refusal::Path => "path",
            Refusal::Host => "host",
            Refusal::Body => "body",
            Refusal::Time => "time",
            Refusal::Ahead => "ahead",
            Refusal::BeforeRestart => "before-restart",
            Refusal::Replay => "replay",
            Refusal::Busy => "busy",
        }
    }
}

/// The parts of a request the check needs.
pub struct RequestParts<'a> {
    pub method: &'a str,
    /// The request target as received (path and query, or absolute form).
    pub url: &'a str,
    pub authorization: Option<&'a str>,
    /// The id of the token this same request was already accepted with, if a handler checks
    /// twice (`req.ccTokenId`): that is not a replay.
    pub accepted_token_id: Option<&'a str>,
}

/// A token that was taken.
#[derive(Debug, Clone)]
pub struct Accepted {
    pub vm_id: String,
    pub iss: String,
    pub claims: Claims,
    /// The token was bound to this request (`req.ccBound`): a body read must then match `body_sha256`.
    pub bound: bool,
    /// The `b` claim, hex SHA-256 of the body the firewall signed. `None` on a bound token means no
    /// body is acceptable (`readJsonBody` compares against undefined).
    pub body_sha256: Option<String>,
    pub token_id: Option<String>,
}

/// What a check came to. `Refused` carries the reason; `Invalid` is everything jose or the claim
/// checks threw on, which the TS returns as a plain `null` without a reason.
#[derive(Debug)]
pub enum Outcome {
    Accepted(Accepted),
    Refused(Refusal),
    Invalid,
}

type KeyLoader = Box<dyn Fn() -> Option<String> + Send + Sync>;
type HostLoader = Box<dyn Fn() -> Vec<String> + Send + Sync>;

struct State {
    /// The pinned key once it has loaded and parsed; never re-read until restart, as in the TS.
    key: Option<VerifyKey>,
    bound_seen: bool,
    bound_written: bool,
    floor_iat: i64,
    newest_iat: i64,
    taken: IndexMap<String, i64>,
    refusal_said: Vec<(Refusal, Instant)>,
    host_unknown_said: Option<Instant>,
    wrong_name_said: Option<Instant>,
}

pub struct FirewallAuth {
    key_loader: KeyLoader,
    own_vm_id: Option<String>,
    hostnames: HostLoader,
    latch_path: Option<PathBuf>,
    /// Log, every 10 minutes, that a token's host cannot be checked. Off where the agent said so
    /// once itself (the vm-agent's unmanaged mode).
    warn_unknown_host: bool,
    state: Mutex<State>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn said_recently(at: Option<Instant>, every: Duration) -> bool {
    at.is_some_and(|t| t.elapsed() <= every)
}

impl FirewallAuth {
    /// No log line per token when this box has no host names: the caller said so once already.
    pub fn quiet_unknown_host(mut self) -> Self {
        self.warn_unknown_host = false;
        self
    }

    /// `latch_path` is `<STATE_DIR>/firewall-tokens-bound`; the newest-iat file sits next to it.
    pub fn new(
        key_loader: impl Fn() -> Option<String> + Send + Sync + 'static,
        own_vm_id: Option<String>,
        hostnames: impl Fn() -> Vec<String> + Send + Sync + 'static,
        latch_path: Option<PathBuf>,
    ) -> Self {
        let bound_seen = latch_path.as_deref().is_some_and(Path::exists);
        let mut floor = 0;
        if let Some(p) = &latch_path
            && let Ok(raw) = std::fs::read_to_string(newest_path(p))
            && let Ok(kept) = raw.trim().parse::<f64>()
            && kept.fract() == 0.0
            && kept > 0.0
            && kept <= 9_007_199_254_740_991.0
        {
            // Never further ahead of this box's clock than a token may be.
            floor = (kept as i64).min((now_ms() + AHEAD_MS) / 1000);
        }
        Self {
            key_loader: Box::new(key_loader),
            own_vm_id,
            hostnames: Box::new(hostnames),
            latch_path,
            warn_unknown_host: true,
            state: Mutex::new(State {
                key: None,
                bound_seen,
                bound_written: bound_seen,
                floor_iat: floor,
                newest_iat: floor,
                taken: IndexMap::new(),
                refusal_said: Vec::new(),
                host_unknown_said: None,
                wrong_name_said: None,
            }),
        }
    }

    /// Whether this box takes only bound tokens now (`firewallTokensBound`, reported as `fw_tokens_bound`).
    pub fn tokens_bound(&self) -> bool {
        self.state.lock().map(|s| s.bound_seen).unwrap_or(false)
    }

    /// The pinned key, loading it if it has not loaded yet (the org's first box pins it late).
    pub fn pinned_key(&self) -> Option<VerifyKey> {
        let mut s = self.state.lock().ok()?;
        if s.key.is_none() {
            // The TS keeps the first PEM that loads, even one that will not import; this keeps the
            // first that parses, which differs only for a corrupt pin file (every token fails then).
            s.key = (self.key_loader)().and_then(|pem| VerifyKey::ed25519_spki_pem(&pem).ok());
        }
        s.key.clone()
    }

    pub fn verify(&self, req: &RequestParts<'_>, purpose: &str, clock_tolerance_s: i64) -> Outcome {
        self.verify_at(req, purpose, clock_tolerance_s, now_ms())
    }

    pub fn verify_at(&self, req: &RequestParts<'_>, purpose: &str, clock_tolerance_s: i64, now: i64) -> Outcome {
        let Some(token) = req.authorization.and_then(|a| a.strip_prefix("Bearer ")) else {
            return Outcome::Invalid;
        };
        let Some(key) = self.pinned_key() else {
            return Outcome::Invalid;
        };
        let opts = VerifyOptions {
            clock_tolerance_s,
            now: Some(now.div_euclid(1000)),
        };
        let Ok(claims) = jwt::verify(token, &key, opts) else {
            return Outcome::Invalid;
        };
        if claims.get("purpose") != Some(&Value::String(purpose.to_string())) {
            return Outcome::Invalid;
        }
        let Some(Value::String(vm_id)) = claims.get("vmId") else {
            return Outcome::Invalid;
        };
        if let Some(own) = &self.own_vm_id
            && vm_id != own
        {
            return Outcome::Invalid;
        }
        let vm_id = vm_id.clone();
        match self.binding(req, &claims, now) {
            Ok(binding) => Outcome::Accepted(Accepted {
                vm_id,
                iss: claims
                    .get("iss")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                bound: binding.is_some(),
                body_sha256: binding.as_ref().and_then(|b| b.body.clone()),
                token_id: binding.map(|b| b.jti),
                claims,
            }),
            Err(problem) => {
                if let Ok(mut s) = self.state.lock() {
                    let said = s.refusal_said.iter().position(|(r, _)| *r == problem);
                    let recent = said.is_some_and(|i| s.refusal_said[i].1.elapsed() <= Duration::from_secs(60));
                    if !recent {
                        if let Some(i) = said {
                            s.refusal_said.remove(i);
                        }
                        s.refusal_said.push((problem, Instant::now()));
                        let path = request_path(req.url).unwrap_or_default();
                        tracing::error!(
                            "[auth] refused a firewall token ({}) for {} {}",
                            problem.as_str(),
                            req.method,
                            path
                        );
                    }
                }
                Outcome::Refused(problem)
            }
        }
    }

    /// `bindingProblem`: `Ok(None)` for an unbound token that is still taken, `Ok(Some)` for a bound
    /// one, `Err` with the reason otherwise. Same order of checks as the TS.
    fn binding(&self, req: &RequestParts<'_>, claims: &Claims, now: i64) -> Result<Option<Binding>, Refusal> {
        let mut s = self.state.lock().map_err(|_| Refusal::Busy)?;
        let always = claims
            .get("purpose")
            .and_then(Value::as_str)
            .is_some_and(|p| ALWAYS_BOUND.contains(&p));
        let (Some(Value::String(m)), Some(Value::String(p)), Some(Value::String(jti))) =
            (claims.get("m"), claims.get("p"), claims.get("jti"))
        else {
            return if s.bound_seen || always {
                Err(Refusal::Unbound)
            } else {
                Ok(None)
            };
        };
        if m != req.method {
            return Err(Refusal::Method);
        }
        if Some(p.as_str()) != request_path(req.url).as_deref() {
            return Err(Refusal::Path);
        }
        let mut wrong_name = false;
        match claims.get("h") {
            Some(Value::String(h)) => {
                let mine: Vec<String> = (self.hostnames)()
                    .into_iter()
                    .filter(|n| !n.is_empty())
                    .map(|n| n.to_lowercase())
                    .collect();
                if !mine.is_empty() && !mine.iter().any(|n| n == h) {
                    let shown: String = h.chars().take(80).collect();
                    if s.bound_seen || always {
                        tracing::error!(
                            "[auth] refused a firewall token signed for {shown}: this box answers as {}",
                            mine.join(", ")
                        );
                        return Err(Refusal::Host);
                    }
                    wrong_name = true;
                    if !said_recently(s.wrong_name_said, Duration::from_secs(600)) {
                        s.wrong_name_said = Some(Instant::now());
                        tracing::error!(
                            "[auth] a firewall token was signed for {shown}, and this box answers as {}: taken for now, and this box goes on taking its firewall's older tokens until the names agree",
                            mine.join(", ")
                        );
                    }
                }
                if mine.is_empty()
                    && self.warn_unknown_host
                    && !said_recently(s.host_unknown_said, Duration::from_secs(600))
                {
                    s.host_unknown_said = Some(Instant::now());
                    tracing::error!(
                        "[auth] this box has no vm_hostname or access_hostname in its keys folder, so it cannot check which host a firewall token was signed for"
                    );
                }
            }
            other => {
                if other.is_some() || s.bound_seen || always {
                    return Err(Refusal::Host);
                }
            }
        }
        let body = match claims.get("b") {
            None => None,
            Some(Value::String(b)) => Some(b.clone()),
            Some(_) => return Err(Refusal::Body),
        };
        // `Number.isSafeInteger(iat)`: an integer-valued number within ±2^53-1.
        let iat = match claims.get("iat").and_then(Value::as_f64) {
            Some(v) if v.fract() == 0.0 && v.abs() <= 9_007_199_254_740_991.0 => v as i64,
            _ => return Err(Refusal::Time),
        };
        if iat * 1000 > now + AHEAD_MS {
            return Err(Refusal::Ahead);
        }
        if iat <= s.floor_iat {
            return Err(Refusal::BeforeRestart);
        }
        if req.accepted_token_id == Some(jti.as_str()) {
            return Ok(Some(Binding { jti: jti.clone(), body }));
        }
        let mut looked = 0;
        while let Some((_, until)) = s.taken.first() {
            looked += 1;
            if *until >= now || looked > TAKEN_SWEEP {
                break;
            }
            s.taken.shift_remove_index(0);
        }
        if s.taken.contains_key(jti) {
            return Err(Refusal::Replay);
        }
        if s.taken.len() >= TAKEN_MAX {
            return Err(Refusal::Busy);
        }
        let exp_ms = match claims.get("exp").and_then(Value::as_f64) {
            Some(e) => (e * 1000.0) as i64,
            None => now + 30_000,
        };
        s.taken.insert(jti.clone(), exp_ms + TAKEN_KEPT_MS);
        if !wrong_name {
            s.bound_seen = true;
        }
        if s.bound_seen
            && !s.bound_written
            && let Some(path) = &self.latch_path
            && cc_store::write_file(path, chrono_like_iso(now).as_bytes(), 0o600).is_ok()
        {
            s.bound_written = true;
        }
        if iat > s.newest_iat {
            s.newest_iat = iat;
            if let Some(path) = &self.latch_path {
                // Written whole or not at all: a file cut short by a crash would read as an older time.
                let _ = cc_store::write_atomic(
                    &newest_path(path),
                    iat.to_string().as_bytes(),
                    0o600,
                    cc_store::TmpName::Suffix,
                );
            }
        }
        Ok(Some(Binding { jti: jti.clone(), body }))
    }

    /// Tests only: fill the taken ids without signing thousands of tokens.
    #[doc(hidden)]
    pub fn take_ids_for_test(&self, ids: impl IntoIterator<Item = (String, i64)>) {
        if let Ok(mut s) = self.state.lock() {
            s.taken.extend(ids);
        }
    }
}

struct Binding {
    jti: String,
    body: Option<String>,
}

fn newest_path(latch: &Path) -> PathBuf {
    PathBuf::from(format!("{}.newest", latch.display()))
}

/// `new Date(ms).toISOString()`: `YYYY-MM-DDTHH:MM:SS.mmmZ`, UTC.
pub fn chrono_like_iso(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{SignKey, sign};
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use serde_json::json;

    /// Whole seconds of the real clock: the restored floor is capped against it.
    /// Read once per test: a token made from one reading and checked against a later one is off by
    /// a second whenever the clock turns over in between (the `ahead` check missed by exactly that).
    fn base() -> i64 {
        now_ms() / 1000 * 1000
    }

    fn pair() -> (SignKey, String) {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pem = sk.to_pkcs8_pem(Default::default()).expect("pem").to_string();
        let pubpem = sk.verifying_key().to_public_key_pem(Default::default()).expect("pem");
        (SignKey::ed25519_pkcs8_pem(&pem).expect("key"), pubpem)
    }

    fn auth(dir: &Path, pubpem: String) -> FirewallAuth {
        FirewallAuth::new(
            move || Some(pubpem.clone()),
            Some("vm_1".into()),
            || vec!["box.example".into()],
            Some(dir.join("firewall-tokens-bound")),
        )
    }

    fn token(sk: &SignKey, extra: Value, iat_s: i64) -> String {
        let mut c = json!({"vmId": "vm_1", "purpose": "channels", "iss": "fw_1"})
            .as_object()
            .cloned()
            .unwrap_or_default();
        if let Value::Object(e) = extra {
            c.extend(e);
        }
        sign(c, sk, Some(30), Some(iat_s)).expect("sign")
    }

    fn req<'a>(method: &'a str, url: &'a str, auth: &'a str) -> RequestParts<'a> {
        RequestParts {
            method,
            url,
            authorization: Some(auth),
            accepted_token_id: None,
        }
    }

    #[test]
    fn unbound_until_latched_then_refused() {
        let now = base();
        let dir = tempfile::tempdir().expect("dir");
        let (sk, pubpem) = pair();
        let a = auth(dir.path(), pubpem);
        let t = format!("Bearer {}", token(&sk, json!({}), now / 1000));
        assert!(
            matches!(a.verify_at(&req("POST", "/channels/apply", &t), "channels", 0, now), Outcome::Accepted(ref x) if !x.bound)
        );
        let b = format!(
            "Bearer {}",
            token(
                &sk,
                json!({"m":"POST","p":"/channels/apply","h":"box.example","jti":"j1","b":"ab"}),
                now / 1000
            )
        );
        match a.verify_at(&req("POST", "/channels/apply?x=1", &b), "channels", 0, now) {
            Outcome::Accepted(x) => {
                assert!(x.bound);
                assert_eq!(x.body_sha256.as_deref(), Some("ab"));
            }
            o => panic!("{o:?}"),
        }
        assert!(dir.path().join("firewall-tokens-bound").exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("firewall-tokens-bound.newest")).expect("newest"),
            (now / 1000).to_string()
        );
        assert!(matches!(
            a.verify_at(&req("POST", "/channels/apply", &t), "channels", 0, now),
            Outcome::Refused(Refusal::Unbound)
        ));
        assert!(matches!(
            a.verify_at(&req("POST", "/channels/apply", &b), "channels", 0, now),
            Outcome::Refused(Refusal::Replay)
        ));
    }

    #[test]
    fn binding_checks_in_order() {
        let now = base();
        let dir = tempfile::tempdir().expect("dir");
        let (sk, pubpem) = pair();
        let a = auth(dir.path(), pubpem);
        let iat = now / 1000;
        let t = |e: Value| format!("Bearer {}", token(&sk, e, iat));
        let check = |tok: &str, m: &str, u: &str| a.verify_at(&req(m, u, tok), "channels", 0, now);
        assert!(matches!(
            check(&t(json!({"m":"GET","p":"/x","jti":"1"})), "POST", "/x"),
            Outcome::Refused(Refusal::Method)
        ));
        assert!(matches!(
            check(&t(json!({"m":"POST","p":"/y","jti":"1"})), "POST", "/x"),
            Outcome::Refused(Refusal::Path)
        ));
        assert!(matches!(
            check(&t(json!({"m":"POST","p":"/x","jti":"1","h":5})), "POST", "/x"),
            Outcome::Refused(Refusal::Host)
        ));
        assert!(matches!(
            check(&t(json!({"m":"POST","p":"/x","jti":"1","b":1})), "POST", "/x"),
            Outcome::Refused(Refusal::Body)
        ));
        // A wrong name before the latch is taken, and does not latch.
        assert!(matches!(
            check(&t(json!({"m":"POST","p":"/x","jti":"2","h":"other"})), "POST", "/x"),
            Outcome::Accepted(_)
        ));
        assert!(!a.tokens_bound());
        let ahead = format!(
            "Bearer {}",
            token(&sk, json!({"m":"POST","p":"/x","jti":"3"}), iat + 151)
        );
        assert!(matches!(
            a.verify_at(&req("POST", "/x", &ahead), "channels", 200, now),
            Outcome::Refused(Refusal::Ahead)
        ));
        // Purpose and vmId mismatches are plain invalid, with no reason.
        assert!(matches!(
            a.verify_at(&req("POST", "/x", &t(json!({}))), "llm", 0, now),
            Outcome::Invalid
        ));
    }

    #[test]
    fn always_bound_purposes_and_restart_floor() {
        let now = base();
        let dir = tempfile::tempdir().expect("dir");
        let (sk, pubpem) = pair();
        let a = auth(dir.path(), pubpem.clone());
        let mut c = json!({"vmId":"vm_1","purpose":"disk"})
            .as_object()
            .cloned()
            .unwrap_or_default();
        let unbound = format!(
            "Bearer {}",
            sign(c.clone(), &sk, Some(30), Some(now / 1000)).expect("sign")
        );
        assert!(matches!(
            a.verify_at(&req("POST", "/disk/reseal", &unbound), "disk", 0, now),
            Outcome::Refused(Refusal::Unbound)
        ));
        c.extend(
            json!({"m":"POST","p":"/disk/reseal","h":"box.example","jti":"d1"})
                .as_object()
                .cloned()
                .unwrap_or_default(),
        );
        let bound = format!("Bearer {}", sign(c, &sk, Some(30), Some(now / 1000)).expect("sign"));
        assert!(matches!(
            a.verify_at(&req("POST", "/disk/reseal", &bound), "disk", 0, now),
            Outcome::Accepted(_)
        ));
        // After a restart the same second is refused, and only newer tokens are taken.
        let again = auth(dir.path(), pubpem);
        let same = format!(
            "Bearer {}",
            token(
                &sk,
                json!({"m":"GET","p":"/a","h":"box.example","jti":"n1"}),
                now / 1000
            )
        );
        assert!(matches!(
            again.verify_at(&req("GET", "/a", &same), "channels", 0, now),
            Outcome::Refused(Refusal::BeforeRestart)
        ));
        let newer = format!(
            "Bearer {}",
            token(
                &sk,
                json!({"m":"GET","p":"/a","h":"box.example","jti":"n2"}),
                now / 1000 + 1
            )
        );
        assert!(matches!(
            again.verify_at(&req("GET", "/a", &newer), "channels", 0, now + 1000),
            Outcome::Accepted(_)
        ));
    }

    #[test]
    fn busy_past_the_cap() {
        let now = base();
        let dir = tempfile::tempdir().expect("dir");
        let (sk, pubpem) = pair();
        let a = auth(dir.path(), pubpem);
        a.take_ids_for_test((0..TAKEN_MAX).map(|i| (format!("id{i}"), now + 1_000_000)));
        let t = format!(
            "Bearer {}",
            token(&sk, json!({"m":"GET","p":"/a","jti":"x"}), now / 1000)
        );
        assert!(matches!(
            a.verify_at(&req("GET", "/a", &t), "channels", 0, now),
            Outcome::Refused(Refusal::Busy)
        ));
    }

    #[test]
    fn iso_time() {
        assert_eq!(chrono_like_iso(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(chrono_like_iso(1_800_000_000_123), "2027-01-15T08:00:00.123Z");
    }
}
