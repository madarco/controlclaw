//! Rescue shell access, box side (`ssh.ts`, `routes/ssh.ts`, `ssh-logins.ts`). The box mints the
//! key (`ssh-keygen`), hands the public half to root (`cc-ssh-open <seconds>`, key on stdin) and the
//! private half back once, in the reply; it is never written to this box's disk past the call and
//! never logged. `cc-ssh-open` arms the timer that closes the window, so nothing the console does
//! keeps it open. Opening and closing come only from the org firewall (`ssh`). Every login is
//! reported from sshd's own journal.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use cc_http::{FirewallBody, Req, Resp};
use cc_proc::Runner;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::exec::exec;
use super::web::{self, send_json};

pub const MIN_SECONDS: i64 = 5 * 60;
pub const MAX_SECONDS: i64 = 72 * 60 * 60;
const KEYGEN_TIMEOUT: Duration = Duration::from_secs(20);
const SUDO_TIMEOUT: Duration = Duration::from_secs(30);
/// The account a rescue session lands in; `cc-ssh-open` hardcodes the same name.
pub const SUPPORT_USER: &str = "ccsupport";
/// What `cc-ssh-open` prints when it installed the key (T-70); an older script does not.
const OPEN_OK: &str = "key=installed";
const MARK: &str = "controlclaw-rescue";

/// `SHA256:…`, as `ssh-keygen -l` and sshd's log write it.
pub fn fingerprint_of(public_key: &str) -> String {
    let blob = public_key.split_whitespace().nth(1).unwrap_or_default();
    // `Buffer.from(blob, "base64")` skips what is not base64 rather than failing.
    let clean: String = blob
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/')
        .collect();
    // Lenient like Buffer: padding or not, trailing bits allowed.
    let lenient = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent)
            .with_decode_allow_trailing_bits(true),
    );
    let raw = lenient.decode(&clean).unwrap_or_default();
    let digest = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&raw));
    format!("SHA256:{}", digest.trim_end_matches('='))
}

pub fn marker_for(grant_id: &str) -> String {
    format!("{MARK}-{grant_id}")
}

fn is_grant_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(Clone)]
pub struct SshAccess {
    runner: Arc<dyn Runner>,
    state_path: PathBuf,
    work_dir: PathBuf,
    user: String,
}

impl SshAccess {
    pub fn new(runner: Arc<dyn Runner>, state_path: PathBuf) -> Self {
        Self {
            runner,
            state_path,
            work_dir: std::env::temp_dir(),
            user: SUPPORT_USER.into(),
        }
    }

    #[cfg(test)]
    pub fn with_work_dir(mut self, d: PathBuf) -> Self {
        self.work_dir = d;
        self
    }

    fn read_state(&self) -> Option<Map<String, Value>> {
        let v: Value = serde_json::from_slice(&std::fs::read(&self.state_path).ok()?).ok()?;
        let m = v.as_object()?.clone();
        (m.get("grantId")?.is_string() && m.get("endsAt")?.is_string()).then_some(m)
    }

    /// `status()`: past the deadline the answer is closed, whatever the file says.
    pub fn status(&self) -> Value {
        match self.read_state() {
            None => json!({"open": false, "user": self.user, "grantId": null, "fingerprint": null, "endsAt": null}),
            Some(s) => {
                let ends = s["endsAt"].as_str().unwrap_or_default();
                let open = web::date_parse(ends).is_some_and(|t| t > web::time_ms(std::time::SystemTime::now()));
                let fp = s.get("fingerprint").and_then(Value::as_str).unwrap_or("");
                json!({"open": open, "user": self.user, "grantId": s["grantId"], "fingerprint": fp, "endsAt": ends})
            }
        }
    }

    /// Mint a key, install its public half, open the port and arm the timer.
    pub async fn open(&self, grant_id: &str, seconds: f64) -> Result<Value, String> {
        let secs = seconds.round();
        if !secs.is_finite() || secs < MIN_SECONDS as f64 || secs > MAX_SECONDS as f64 {
            return Err(format!(
                "a shell access window must be between {MIN_SECONDS} and {MAX_SECONDS} seconds"
            ));
        }
        let secs = secs as i64;
        if !is_grant_id(grant_id) {
            return Err("malformed grant id".into());
        }
        let (public_key, private_key) = self.mint(grant_id).await?;
        let now = web::time_ms(std::time::SystemTime::now());
        let ends_at = web::iso(now + secs * 1000);
        let opened = exec(
            self.runner.as_ref(),
            "sudo",
            &["/usr/local/bin/cc-ssh-open", &secs.to_string()],
            SUDO_TIMEOUT,
            Some(&format!("{public_key}\n")),
        )
        .await
        .map_err(|e| e.message)?;
        if !opened.stdout.contains(OPEN_OK) {
            // An old script has already opened 22: take it down before saying so.
            let _ = exec(
                self.runner.as_ref(),
                "sudo",
                &["/usr/local/bin/cc-ssh-close"],
                SUDO_TIMEOUT,
                None,
            )
            .await;
            return Err(
                "this box is running a cc-ssh-open that predates root support access; re-provision it and try again"
                    .into(),
            );
        }
        let fingerprint = fingerprint_of(&public_key);
        let state =
            json!({"grantId": grant_id, "fingerprint": fingerprint, "endsAt": ends_at, "openedAt": web::iso(now)});
        if let Some(dir) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        cc_store::write_file(&self.state_path, state.to_string().as_bytes(), 0o600).map_err(|e| e.to_string())?;
        // The fingerprint, never the key.
        tracing::info!("[ssh] opened for {} until {ends_at} ({fingerprint})", self.user);
        Ok(
            json!({"user": self.user, "fingerprint": fingerprint, "publicKey": public_key, "privateKey": private_key, "endsAt": ends_at, "sudo": true}),
        )
    }

    /// Take root away, take the key out, shut the port. Safe when nothing is open.
    pub async fn close(&self) -> Result<Value, String> {
        let was = self.read_state();
        exec(
            self.runner.as_ref(),
            "sudo",
            &["/usr/local/bin/cc-ssh-close"],
            SUDO_TIMEOUT,
            None,
        )
        .await
        .map_err(|e| e.message)?;
        let _ = std::fs::remove_file(&self.state_path);
        if let Some(w) = &was {
            let fp = w.get("fingerprint").and_then(Value::as_str).unwrap_or("");
            tracing::info!("[ssh] closed for {} (was {fp})", self.user);
        }
        Ok(json!({"user": self.user, "closed": was.is_some()}))
    }

    /// `ssh-keygen` into a folder of its own, removed before the reply.
    async fn mint(&self, grant_id: &str) -> Result<(String, String), String> {
        // 0700 from the start, with a full random name, and removed when this returns or is dropped.
        let dir = KeyDir::create(&self.work_dir)?;
        let key = dir.path().join("key");
        let key_s = key.to_string_lossy().into_owned();
        let marker = marker_for(grant_id);
        let result = async {
            exec(
                self.runner.as_ref(),
                "ssh-keygen",
                &["-q", "-t", "ed25519", "-N", "", "-C", &marker, "-f", &key_s],
                KEYGEN_TIMEOUT,
                None,
            )
            .await
            .map_err(|e| e.message)?;
            let public = std::fs::read_to_string(format!("{key_s}.pub")).map_err(|e| e.to_string())?;
            let private = std::fs::read_to_string(&key).map_err(|e| e.to_string())?;
            Ok::<_, String>((public.trim().to_string(), private))
        }
        .await;
        // Before the reply: the private half must not outlive this call on this disk.
        drop(dir);
        result
    }
}

/// `mkdtemp` for the key pair: made 0700 in one step, removed on drop.
struct KeyDir(PathBuf);

impl KeyDir {
    fn create(parent: &Path) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = parent.join(format!("cc-ssh-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| e.to_string())?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for KeyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Opening and closing run to the end in a task of their own, so a request the firewall drops
/// half way cannot leave port 22 open with no `ssh.json` saying so (or the reverse), as Node
/// finishes a handler whose client went away.
async fn finish(f: impl std::future::Future<Output = Result<Value, String>> + Send + 'static) -> Result<Value, String> {
    tokio::spawn(f)
        .await
        .unwrap_or_else(|_| Err("shell access could not be changed".into()))
}

/// `handleSsh`: open and close from the firewall only (`ssh`); the status with either token.
pub async fn handle(app: &crate::app::App, ssh: &SshAccess, req: Req) -> Resp {
    let (parts, body) =
        match web::firewall_or_console(app, req, "ssh", "shell access must come from the org firewall").await {
            Ok(r) => r,
            Err(r) => return *r,
        };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    let ok = |v: Result<Value, String>| match v {
        Ok(Value::Object(m)) => {
            let mut out = Map::new();
            out.insert("ok".into(), json!(true));
            out.extend(m);
            send_json(200, &Value::Object(out), &[])
        }
        Ok(_) => send_json(200, &json!({"ok": true}), &[]),
        Err(e) => send_json(500, &json!({"ok": false, "error": e}), &[]),
    };
    match (parts.method.as_str(), pathname.as_str()) {
        ("GET", "/ssh/status") => ok(Ok(ssh.status())),
        ("POST", "/ssh/open") => {
            let b = match &body {
                FirewallBody::Json(b) => Some(b),
                _ => None,
            };
            let grant = b.and_then(|b| b.get("grantId")).and_then(Value::as_str);
            let seconds = b.and_then(|b| b.get("seconds")).and_then(Value::as_f64);
            match (grant, seconds) {
                (Some(g), Some(s)) => {
                    let (me, g) = (ssh.clone(), g.to_string());
                    ok(finish(async move { me.open(&g, s).await }).await)
                }
                _ => send_json(400, &json!({"ok": false, "error": "grantId and seconds required"}), &[]),
            }
        }
        ("POST", "/ssh/close") => {
            let me = ssh.clone();
            ok(finish(async move { me.close().await }).await)
        }
        _ => send_json(404, &json!({"error": "Not found"}), &[]),
    }
}

// ---- reporting logins (`ssh-logins.ts`) ----

const MAX_PER_TICK: usize = 50;
const MAX_BUFFERED: usize = 500;
const POLL_TIMEOUT: Duration = Duration::from_secs(15);

/// `parseSshdLine`: an accepted public-key login, with journalctl's own time when the line has one.
pub fn parse_sshd_line(line: &str) -> Option<(String, String, String, Option<i64>)> {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"Accepted publickey for (\S+) from (\S+) port \d+ ssh2:\s+\S+\s+(SHA256:\S+)")
            .expect("regex")
    });
    static STAMP: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:?\d{2}|Z)?)").expect("regex")
    });
    let m = RE.captures(line)?;
    let at = STAMP.captures(line).and_then(|s| {
        let raw = s[1].to_string();
        // `+0000` → `+00:00`.
        let fixed = match raw.len() {
            n if n >= 5
                && (raw.as_bytes()[n - 5] == b'+' || raw.as_bytes()[n - 5] == b'-')
                && !raw[n - 4..].contains(':') =>
            {
                format!("{}:{}", &raw[..n - 2], &raw[n - 2..])
            }
            _ => raw,
        };
        web::date_parse(&fixed)
    });
    Some((m[1].to_string(), m[3].to_string(), m[2].to_string(), at))
}

/// Ships every SSH login to the console's Activity page (`SshLoginWatcher`). Records stay buffered
/// until the console took them: the journal cursor has moved past them by then.
pub struct SshLoginWatcher {
    runner: Arc<dyn Runner>,
    cursor_path: PathBuf,
    pending: tokio::sync::Mutex<Vec<Value>>,
}

impl SshLoginWatcher {
    pub fn new(runner: Arc<dyn Runner>, cursor_path: PathBuf) -> Self {
        Self {
            runner,
            cursor_path,
            pending: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    async fn journal(&self) -> Vec<String> {
        let cursor = format!("--cursor-file={}", self.cursor_path.display());
        let args = [
            "-u",
            "ssh",
            "-u",
            "sshd",
            "--no-pager",
            "-q",
            "-o",
            "short-iso",
            cursor.as_str(),
        ];
        match exec(self.runner.as_ref(), "journalctl", &args, POLL_TIMEOUT, None).await {
            Ok(o) => o
                .stdout
                .split('\n')
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            // A box with no journal, or none of those units, is not an error worth a line.
            Err(e) if e.stdout.is_empty() => Vec::new(),
            Err(e) => e
                .stdout
                .split('\n')
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    /// One pass; how many logins it reported.
    pub async fn tick(&self, ship: impl AsyncFnOnce(Value) -> Result<u16, String>) -> Result<usize, String> {
        let lines = self.journal().await;
        let mut pending = self.pending.lock().await;
        let tick_ts = (web::time_ms(std::time::SystemTime::now()) as f64 / 1000.0).round() as i64;
        for line in lines {
            let Some((user, fingerprint, from_ip, at)) = parse_sshd_line(&line) else {
                continue;
            };
            pending.push(json!({
                "source": "ssh_login",
                "login_id": &hex::encode(Sha256::digest(line.as_bytes()))[..32],
                "ts": at.map(|ms| (ms as f64 / 1000.0).round() as i64).unwrap_or(tick_ts),
                "user": user,
                "fingerprint": fingerprint,
                "from_ip": from_ip,
            }));
        }
        let over = pending.len().saturating_sub(MAX_BUFFERED);
        pending.drain(..over);
        if pending.is_empty() {
            return Ok(0);
        }
        let records: Vec<Value> = pending.iter().take(MAX_PER_TICK).cloned().collect();
        let n = records.len();
        let status = ship(json!({"records": records})).await?;
        if !(200..300).contains(&status) {
            tracing::info!("[ssh] could not report {n} login(s): HTTP {status}; keeping them for the next pass");
            return Ok(0);
        }
        pending.drain(..n);
        tracing::info!("[ssh] reported {n} login(s)");
        Ok(n)
    }
}

#[cfg(test)]
mod tests;
