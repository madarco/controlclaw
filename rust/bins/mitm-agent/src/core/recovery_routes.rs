//! The recovery routes (`recovery.ts`): `npx @controlclaw/recover` talking to this firewall over
//! TLS on port 3100, signed with the owner's recovery key, with the control plane out of the path.
//!
//! Every request carries an Ed25519 signature over its method, path, timestamp and whole body. The
//! routes act only on a firewall nothing is bound to yet. Ten verified requests a minute; five
//! unverified ones close the routes to unverified callers for fifteen minutes, and never to the
//! owner. One plain route serves a streamed archive to an agent box once, by a 32-byte token.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use cc_crypto::envelope::unwrap_data_key;
use cc_crypto::recovery::{
    NOT_A_RECOVERY_REQUEST, RECOVERY_REPLAY_WINDOW_MS, RecoveryBodyHasher, RecoveryRequest, RecoveryVerdict,
    decode_recovery_body, recovery_key_fingerprint, verify_recovery_request,
};
use cc_http::{Body, Req, Resp, json};
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use rand::RngCore;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::agent_client::{AgentClient, AgentTarget};
use super::backup::{Backup, RecoveryKeys};
use super::identities::Agents;
use super::kit::text;
use super::now_ms;
use super::self_restore::{SelfRestore, SelfRestoreInput};

pub const RECOVERY_RATE_PER_MINUTE: usize = 10;
pub const RECOVERY_BAD_SIGNATURES: u32 = 5;
pub const RECOVERY_LOCKOUT_MS: u64 = 15 * 60_000;
const MAX_FIREWALL_ARCHIVE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_AGENT_ARCHIVE_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const STAGED_TTL_MS: u64 = 60 * 60_000;
/// A body in memory (the firewall's own archive, the small requests) gets this long in all.
const MEMORY_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
/// An archive to disk gets this long plus a second for every [`SPILL_MIN_RATE`] bytes it has sent:
/// one that trickles loses the single archive slot instead of holding it.
const SPILL_GRACE: std::time::Duration = std::time::Duration::from_secs(120);
const SPILL_MIN_RATE: u64 = 256 * 1024;
/// Bodies read into memory at once (each up to [`MAX_FIREWALL_ARCHIVE_BYTES`]).
const MEMORY_READS: usize = 4;
const STAGED_PREFIX: &str = "/recovery/staged/";

/// `eligibility`: `Err(reason)` when a restore may not run.
pub type Eligibility = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;

struct Staged {
    path: PathBuf,
    bytes: u64,
    at: u64,
}

#[derive(Default)]
struct St {
    /// Times of the VERIFIED requests in the last minute.
    recent: VecDeque<u64>,
    bad: u32,
    locked_until: u64,
    staged: HashMap<String, Staged>,
}

struct Read {
    head: Map<String, Value>,
    tail: Option<Vec<u8>>,
    tail_path: Option<PathBuf>,
    digest: String,
}

pub struct RecoveryRoutes {
    org_id: String,
    box_id: String,
    backup: Arc<Backup>,
    eligibility: Eligibility,
    self_restore: Option<Arc<SelfRestore>>,
    agent: AgentClient,
    agents: Arc<Agents>,
    staging_dir: PathBuf,
    base_url: Option<String>,
    cert_fingerprint: Option<String>,
    st: Mutex<St>,
    /// One archive streaming to disk at a time.
    spill: tokio::sync::Mutex<()>,
    /// At most [`MEMORY_READS`] bodies in memory at a time.
    memory: tokio::sync::Semaphore,
}

fn reply(status: u16, body: Value) -> Resp {
    json(status, &body)
}

fn err(status: u16, message: impl Into<String>) -> Resp {
    reply(status, json!({"error": message.into()}))
}

fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

impl RecoveryRoutes {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: &str,
        box_id: &str,
        backup: Arc<Backup>,
        eligibility: Eligibility,
        self_restore: Option<Arc<SelfRestore>>,
        agent: AgentClient,
        agents: Arc<Agents>,
        staging_dir: PathBuf,
        base_url: Option<String>,
        cert_fingerprint: Option<String>,
    ) -> Self {
        Self {
            org_id: org_id.into(),
            box_id: box_id.into(),
            backup,
            eligibility,
            self_restore,
            agent,
            agents,
            staging_dir,
            base_url,
            cert_fingerprint,
            st: Mutex::new(St::default()),
            spill: tokio::sync::Mutex::new(()),
            memory: tokio::sync::Semaphore::new(MEMORY_READS),
        }
    }

    fn st(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---- the plain half: a staged archive, to an agent box ----

    /// `serveStaged`: `GET /recovery/staged/<token>`, once.
    pub async fn serve_staged(&self, path: &str) -> Resp {
        let token = &path[STAGED_PREFIX.len()..];
        // Swept first: a lookup before expiring would serve the entry meant to retire.
        self.sweep_staged();
        let entry = {
            let mut st = self.st();
            match st.staged.get(token) {
                Some(e) if e.path.exists() => st.staged.remove(token),
                _ => None,
            }
        };
        let Some(entry) = entry else {
            return err(404, "Not found");
        };
        let Ok(file) = tokio::fs::File::open(&entry.path).await else {
            return err(404, "Not found");
        };
        let stream = futures_util::stream::unfold((Some(file), entry.path), |(file, path)| async move {
            let mut file = file?;
            let mut buf = vec![0u8; 64 * 1024];
            match file.read(&mut buf).await {
                Ok(0) => {
                    remove(&path);
                    None
                }
                Ok(n) => {
                    buf.truncate(n);
                    Some((Ok(Frame::data(Bytes::from(buf))), (Some(file), path)))
                }
                Err(e) => {
                    remove(&path);
                    Some((Err(e), (None, path)))
                }
            }
        });
        let body: Body = StreamBody::new(stream).boxed();
        let mut r = Resp::new(body);
        r.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/octet-stream"),
        );
        if let Ok(v) = http::HeaderValue::from_str(&entry.bytes.to_string()) {
            r.headers_mut().insert(http::header::CONTENT_LENGTH, v);
        }
        r
    }

    fn sweep_staged(&self) {
        let cutoff = now_ms().saturating_sub(STAGED_TTL_MS);
        let mut st = self.st();
        st.staged.retain(|_, e| {
            if e.at >= cutoff {
                return true;
            }
            remove(&e.path);
            false
        });
    }

    // ---- the TLS half: the signed routes ----

    pub async fn handle(&self, req: Req, path: &str) -> Resp {
        if req.method() != hyper::Method::POST {
            return err(405, "Use POST.");
        }
        let keys = self.backup.recovery_keys();
        let header = |name: &str| {
            req.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let signature = header("x-cc-recovery-signature").filter(|s| !s.is_empty());
        // `Number(header ?? NaN)`.
        let timestamp = header("x-cc-recovery-timestamp").map_or(f64::NAN, |t| js_number(&t));
        let locked = self.st().locked_until.saturating_sub(now_ms());
        let (Some(signature), true) = (signature, timestamp.is_finite()) else {
            // Nothing to check, so nothing is read.
            self.count_bad();
            return err(401, "This request is not signed.");
        };
        // A body is read before its signature can be checked (it covers the whole body). So before
        // anything is read: a signature that cannot be one is refused as a bad one, one archive is
        // taken in at a time, a few bodies are held in memory at a time, and every read has a time
        // limit. (The TS reads any signed-looking request, with none of these limits.)
        let spilling = path == "/recovery/agent-restore";
        if cc_crypto::b64::decode(&signature).map_or(true, |b| b.len() != 64) {
            self.count_bad();
            if locked > 0 {
                return err(
                    429,
                    format!(
                        "Too many unsigned or badly signed requests. The recovery routes are closed to them for another {} minute(s).",
                        locked.div_ceil(60_000)
                    ),
                );
            }
            return err(
                401,
                "This request is not signed by the recovery key this firewall was given.",
            );
        }
        let _one = match spilling.then(|| self.spill.try_lock()) {
            Some(Err(_)) => {
                return err(
                    429,
                    "Another archive is being received. Wait for it to finish and try again.",
                );
            }
            Some(Ok(g)) => Some(g),
            None => None,
        };
        let _held = match (!spilling).then(|| self.memory.try_acquire()) {
            Some(Err(_)) => {
                return err(429, "Too many requests are being received. Try again in a moment.");
            }
            Some(Ok(p)) => Some(p),
            None => None,
        };
        let spill = spilling.then(|| self.new_spill_path());
        let body = match self.read(req.into_body(), spill.clone()).await {
            Ok(b) => b,
            Err(e) => {
                if let Some(p) = &spill {
                    remove(p);
                }
                // A body that never arrived proves nothing: it counts toward the lockout.
                self.count_bad();
                return err(400, e);
            }
        };
        let resp = self.answer(&keys, &signature, timestamp, path, &body, locked).await;
        // Anything that did not become a staged archive goes now.
        if let Some(p) = &body.tail_path
            && !self.st().staged.values().any(|s| &s.path == p)
        {
            remove(p);
        }
        resp
    }

    async fn answer(
        &self,
        keys: &Option<RecoveryKeys>,
        signature: &str,
        timestamp: f64,
        path: &str,
        body: &Read,
        locked: u64,
    ) -> Resp {
        // Checked before the key is known to exist: no key answers as a wrong key does.
        let verdict = match keys.as_ref().and_then(|k| k.signing_public_key.as_deref()) {
            Some(pk) => verify_recovery_request(
                pk,
                signature,
                RecoveryRequest {
                    method: "POST",
                    path,
                    timestamp,
                    digest: &body.digest,
                },
                now_ms() as f64,
                RECOVERY_REPLAY_WINDOW_MS,
            ),
            None => RecoveryVerdict::BadSignature(
                "This firewall has not been given a recovery key to check signatures against.".into(),
            ),
        };
        let message = match verdict {
            RecoveryVerdict::Ok => None,
            RecoveryVerdict::Stale(m) => Some(m),
            RecoveryVerdict::BadSignature(m) => {
                self.count_bad();
                Some(m)
            }
        };
        if let Some(m) = message {
            if locked > 0 {
                return err(
                    429,
                    format!(
                        "Too many unsigned or badly signed requests. The recovery routes are closed to them for another {} minute(s).",
                        locked.div_ceil(60_000)
                    ),
                );
            }
            return err(401, m);
        }
        {
            // A good signature clears the run and the lockout.
            let mut st = self.st();
            st.bad = 0;
            st.locked_until = 0;
        }
        if !self.allow_rate() {
            return err(
                429,
                format!(
                    "The recovery routes take {RECOVERY_RATE_PER_MINUTE} signed requests a minute. Wait a moment and try again."
                ),
            );
        }
        let Some(keys) = keys else {
            return err(400, "no recovery key");
        };
        if path == "/recovery/hello" {
            return reply(200, self.hello(keys));
        }
        if let Err(reason) = (self.eligibility)() {
            return err(409, reason);
        }
        let r = match path {
            "/recovery/firewall-restore" => self.firewall_restore(body).await,
            "/recovery/agent-restore" => self.agent_restore(body).await,
            _ => return err(404, "Not found"),
        };
        match r {
            Ok(v) => reply(200, v),
            Err(e) => {
                tracing::info!("[recovery] {path} failed: {e}");
                err(400, e)
            }
        }
    }

    fn allow_rate(&self) -> bool {
        let now = now_ms();
        let mut st = self.st();
        while st.recent.front().is_some_and(|t| *t + 60_000 <= now) {
            st.recent.pop_front();
        }
        if st.recent.len() >= RECOVERY_RATE_PER_MINUTE {
            return false;
        }
        st.recent.push_back(now);
        true
    }

    fn count_bad(&self) {
        let mut st = self.st();
        st.bad += 1;
        if st.bad < RECOVERY_BAD_SIGNATURES {
            return;
        }
        st.locked_until = now_ms() + RECOVERY_LOCKOUT_MS;
        st.bad = 0;
        tracing::info!(
            "[recovery] {RECOVERY_BAD_SIGNATURES} unsigned or badly signed requests; the routes are closed to them for {} minutes",
            RECOVERY_LOCKOUT_MS / 60_000
        );
    }

    /// Where an agent archive lands while it streams in; also sweeps what a killed process left.
    fn new_spill_path(&self) -> PathBuf {
        let _ = std::fs::create_dir_all(&self.staging_dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.staging_dir, std::fs::Permissions::from_mode(0o700));
        }
        self.sweep_staged();
        let cutoff = std::time::SystemTime::now() - std::time::Duration::from_millis(STAGED_TTL_MS);
        if let Ok(dir) = std::fs::read_dir(&self.staging_dir) {
            for e in dir.flatten() {
                if e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < cutoff) {
                    remove(&e.path());
                }
            }
        }
        let mut b = [0u8; 6];
        rand::thread_rng().fill_bytes(&mut b);
        self.staging_dir
            .join(format!("cc-recovery-{}-{}", now_ms(), hex::encode(b)))
    }

    /// The whole body, hashed as it arrives; after the head, to the spill file or memory.
    async fn read(&self, mut body: hyper::body::Incoming, spill: Option<PathBuf>) -> Result<Read, String> {
        let max = if spill.is_some() {
            MAX_AGENT_ARCHIVE_BYTES
        } else {
            MAX_FIREWALL_ARCHIVE_BYTES
        };
        let mut sink = match &spill {
            Some(p) => {
                let mut o = tokio::fs::OpenOptions::new();
                o.write(true).create(true).truncate(true);
                #[cfg(unix)]
                o.mode(0o600);
                Some(o.open(p).await.map_err(|e| e.to_string())?)
            }
            None => None,
        };
        let mut hasher = RecoveryBodyHasher::default();
        let mut framed: Vec<u8> = Vec::new();
        let mut head: Option<Map<String, Value>> = None;
        let mut tail: Vec<u8> = Vec::new();
        let mut total: u64 = 0;
        let start = tokio::time::Instant::now();
        let spilling = spill.is_some();
        let r = async {
            loop {
                let deadline = if spilling {
                    start + SPILL_GRACE + std::time::Duration::from_secs(total / SPILL_MIN_RATE)
                } else {
                    start + MEMORY_READ_TIMEOUT
                };
                let Ok(next) = tokio::time::timeout_at(deadline, body.frame()).await else {
                    return Err("That request took too long to arrive.".to_string());
                };
                let Some(frame) = next else { break };
                let frame = frame.map_err(|e| e.to_string())?;
                let Ok(buf) = frame.into_data() else { continue };
                total += buf.len() as u64;
                if total > max {
                    return Err("That archive is larger than this firewall will take.".to_string());
                }
                hasher.update(&buf);
                let rest: Vec<u8> = if head.is_none() {
                    framed.extend_from_slice(&buf);
                    match decode_recovery_body(&framed) {
                        Ok((h, at)) => {
                            head = Some(h);
                            framed[at..].to_vec()
                        }
                        Err(e) => {
                            if e.0 == NOT_A_RECOVERY_REQUEST || framed.len() > 128 * 1024 {
                                return Err(e.0);
                            }
                            continue;
                        }
                    }
                } else {
                    buf.to_vec()
                };
                if rest.is_empty() {
                    continue;
                }
                match sink.as_mut() {
                    Some(f) => f.write_all(&rest).await.map_err(|e| e.to_string())?,
                    None => tail.extend_from_slice(&rest),
                }
            }
            Ok(())
        }
        .await;
        if let Some(f) = sink.as_mut() {
            let _ = f.flush().await;
        }
        r?;
        let Some(head) = head else {
            return Err("This request's head never arrived in full.".into());
        };
        Ok(Read {
            head,
            tail: spill.is_none().then_some(tail),
            tail_path: spill,
            digest: hasher.digest(),
        })
    }

    // ---- the routes ----

    fn hello(&self, keys: &RecoveryKeys) -> Value {
        let backup = self.backup.own_keypair();
        let eligible = (self.eligibility)();
        let agents: Vec<Value> = self
            .agents
            .agents()
            .iter()
            .map(|i| {
                let vm = i.get("vm_id").cloned().unwrap_or(Value::Null);
                let name = i
                    .get("name")
                    .filter(|n| !n.is_null())
                    .cloned()
                    .unwrap_or_else(|| vm.clone());
                json!({"name": name, "vmId": vm})
            })
            .collect();
        json!({
            "ok": true,
            "orgId": self.org_id,
            "boxId": self.box_id,
            "backupPublicKey": backup.as_ref().map(|b| b.public_key.clone()),
            "backupFingerprint": backup.as_ref().map(|b| b.fingerprint.clone()),
            "recoveryFingerprint": keys.fingerprint,
            "recoveryKeyFingerprint": keys.signing_public_key.as_deref().map(|s| recovery_key_fingerprint(&keys.public_key, s)),
            "certFingerprint": self.cert_fingerprint,
            "canRestore": eligible.is_ok(),
            "reason": eligible.err(),
            "agents": agents,
        })
    }

    async fn firewall_restore(&self, body: &Read) -> Result<Value, String> {
        let Some(service) = &self.self_restore else {
            return Err("This firewall cannot put itself back.".into());
        };
        // A restore already swapped the files: until the restart, another one would start from the
        // old process's state.
        if self.backup.restoring() {
            return Err("This firewall was just put back and is restarting. Try again in a minute.".into());
        }
        let h = &body.head;
        let (Some(backup_id), Some(source_box_id), Some(header), Some(manifest_hash), Some(sealed)) = (
            text(h, "backupId"),
            text(h, "sourceBoxId"),
            text(h, "header"),
            text(h, "manifestHash"),
            text(h, "dataKeySealedToFirewall"),
        ) else {
            return Err("This request does not name a backup to put back.".into());
        };
        let data_key = self.open_data_key(&sealed)?;
        let (archive, download_url) = match text(h, "archiveUrl") {
            Some(u) => (None, Some(checked_url(&u)?)),
            None => match &body.tail {
                Some(t) if !t.is_empty() => (Some(t.clone()), None),
                _ => return Err("No archive arrived, and no address was given for one.".into()),
            },
        };
        let r = service
            .run(SelfRestoreInput {
                backup_id: backup_id.clone(),
                source_box_id,
                download_url,
                archive,
                header,
                manifest_hash,
                data_key,
                taken_at: text(h, "takenAt"),
            })
            .await?;
        // Frozen until the restart, as the console path is: the in-memory store is the old box's.
        self.backup.mark_restoring();
        tracing::info!(
            "[recovery] this firewall was put back from {backup_id} ({} file(s), backup key {})",
            r.entries,
            r.fingerprint.as_deref().unwrap_or("unknown")
        );
        Ok(
            json!({"ok": true, "entries": r.entries, "takenAt": r.taken_at, "fingerprint": r.fingerprint, "quarantined": r.quarantined}),
        )
    }

    async fn agent_restore(&self, body: &Read) -> Result<Value, String> {
        let h = &body.head;
        let (Some(backup_id), Some(header), Some(manifest_hash), Some(sealed), Some(agent_name)) = (
            text(h, "backupId"),
            text(h, "header"),
            text(h, "manifestHash"),
            text(h, "dataKeySealedToFirewall"),
            text(h, "agent"),
        ) else {
            return Err("This request does not name a backup to restore.".into());
        };
        let kind = text(h, "kind");
        if kind.as_deref() != Some("workspace") && kind.as_deref() != Some("state") {
            return Err(format!(
                "A {} archive is not something an agent can be restored from.",
                kind.as_deref().unwrap_or("missing")
            ));
        }
        let kind = kind.unwrap_or_default();
        let target = self.resolve_agent(&agent_name)?;
        let data_key = self.open_data_key(&sealed)?;
        let (url, token) = self.staged_url(h, body.tail_path.as_deref())?;
        let r = self
            .agent
            .post(
                &target,
                "/backup/restore",
                &json!({
                    "orgId": self.org_id, "vmId": target.vm_id, "backupId": backup_id, "kind": kind,
                    "dataKey": data_key, "header": header, "manifestHash": manifest_hash, "downloadUrl": url,
                }),
            )
            .await;
        // Whatever happened, the archive is not waiting for anyone any more.
        self.drop_staged(token.as_deref());
        let r = r.map_err(|e| e.to_string())?;
        tracing::info!("[recovery] restored {kind} onto {agent_name}");
        let mut out = json!({"ok": true, "vmId": target.vm_id, "kind": kind});
        for k in ["entries", "restarted"] {
            if let Some(v) = r.get(k) {
                out[k] = v.clone();
            }
        }
        Ok(out)
    }

    fn resolve_agent(&self, name: &str) -> Result<AgentTarget, String> {
        let wanted = name.to_lowercase();
        let all = self.agents.agents();
        let name_of = |i: &Map<String, Value>| i.get("name").and_then(Value::as_str).map(str::to_string);
        let m = all.iter().find(|i| {
            name_of(i).unwrap_or_default().to_lowercase() == wanted
                || i.get("vm_id").and_then(Value::as_str) == Some(name)
        });
        let host = m.and_then(|i| text(i, "hostname"));
        let (Some(m), Some(host)) = (m, host) else {
            let known: Vec<String> = all
                .iter()
                .map(|i| name_of(i).unwrap_or_else(|| super::activity_sanitize::js_string(i.get("vm_id"))))
                .collect();
            let known = known.join(", ");
            return Err(format!(
                "This firewall does not know an agent called {name}.{}",
                if known.is_empty() {
                    " It knows none yet.".to_string()
                } else {
                    format!(" It knows: {known}.")
                }
            ));
        };
        Ok(AgentTarget::new(
            super::activity_sanitize::js_string(m.get("vm_id")),
            &host,
        ))
    }

    fn open_data_key(&self, sealed: &str) -> Result<String, String> {
        let Some(b) = self.backup.own_keypair() else {
            return Err("This firewall has no backup key yet, so nothing can be sealed to it.".into());
        };
        unwrap_data_key(sealed, &b.secret_key).map_err(|_| {
            format!(
                "That key was not sealed to this firewall. Its backup key is {}.",
                b.fingerprint
            )
        })
    }

    /// Where the agent box reads the archive: the given address, or a one-time one on this box.
    fn staged_url(
        &self,
        head: &Map<String, Value>,
        tail_path: Option<&Path>,
    ) -> Result<(String, Option<String>), String> {
        if let Some(u) = text(head, "archiveUrl") {
            return Ok((checked_url(&u)?, None));
        }
        let none = || "No archive arrived, and no address was given for one.".to_string();
        let path = tail_path.ok_or_else(none)?;
        let size = std::fs::metadata(path).map(|m| m.len()).map_err(|_| none())?;
        if size == 0 {
            return Err(none());
        }
        let Some(base) = &self.base_url else {
            return Err("This firewall has no private address to serve the archive from, so pass --archive-url with somewhere the agent box can fetch it.".into());
        };
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        let token = hex::encode(b);
        self.st().staged.insert(
            token.clone(),
            Staged {
                path: path.to_path_buf(),
                bytes: size,
                at: now_ms(),
            },
        );
        Ok((format!("{base}{STAGED_PREFIX}{token}"), Some(token)))
    }

    fn drop_staged(&self, token: Option<&str>) {
        let Some(token) = token else { return };
        if let Some(e) = self.st().staged.remove(token) {
            remove(&e.path);
        }
    }
}

fn checked_url(given: &str) -> Result<String, String> {
    let u = url::Url::parse(given).map_err(|_| "That archive address is not a URL.".to_string())?;
    if u.scheme() != "https" {
        return Err("An archive address has to be https.".into());
    }
    Ok(given.to_string())
}

/// `Number(s)` for a header: trimmed, empty is 0, anything else not a number is NaN.
fn js_number(s: &str) -> f64 {
    let t = s.trim();
    if t.is_empty() {
        return 0.0;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_and_urls() {
        assert_eq!(js_number(" 1700000000000 "), 1_700_000_000_000.0);
        assert!(js_number("abc").is_nan());
        assert_eq!(js_number(""), 0.0);
        assert_eq!(
            checked_url("http://x").expect_err("http"),
            "An archive address has to be https."
        );
        assert_eq!(
            checked_url("nope").expect_err("url"),
            "That archive address is not a URL."
        );
    }
}
