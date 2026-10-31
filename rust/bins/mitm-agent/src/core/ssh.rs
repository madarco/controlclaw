//! Letting ControlClaw support into a box (`ssh.ts`, `ssh-local.ts`, `ssh-logins.ts`): a code, and
//! never first use (an org that cannot be asked cannot say yes). The key is minted on the box being
//! opened; on this firewall that is here, through `cc-ssh-open` on stdin. Closing needs no code.
//! Every SSH login on this box is shipped to Activity from sshd's journal.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use base64::Engine;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::agent_client::{AgentClient, AgentTarget};
use super::code_message::CodeParts;
use super::consent::{iso, no_recipients};
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, null_or, obj, ok, run_ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE_PREFIX: &str = "ssh:";
const SELF: &str = "self";
pub const MIN_SECONDS: f64 = 5.0 * 60.0;
pub const MAX_SECONDS: f64 = 72.0 * 60.0 * 60.0;
const SUPPORT_USER: &str = "ccsupport";
const MARK: &str = "controlclaw-rescue";
const OPEN_OK: &str = "key=installed";
static GRANT_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("re"));

/// `fingerprintOf`: `SHA256:` and the unpadded base64 of the key blob's hash.
pub fn fingerprint_of(public_key: &str) -> String {
    let blob = public_key.split_whitespace().nth(1).unwrap_or("");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .unwrap_or_default();
    let b64 = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(raw));
    format!("SHA256:{}", b64.trim_end_matches('='))
}

/// `SshLocal`: a rescue session on this firewall, root for the window, as `ccsupport`.
pub struct SshLocal {
    state_path: PathBuf,
    runner: Arc<dyn cc_proc::Runner>,
}

impl SshLocal {
    pub fn new(state_path: PathBuf, runner: Arc<dyn cc_proc::Runner>) -> Self {
        Self { state_path, runner }
    }

    fn read_state(&self) -> Option<Map<String, Value>> {
        let o: Map<String, Value> = serde_json::from_str(&std::fs::read_to_string(&self.state_path).ok()?).ok()?;
        let grant = o.get("grantId")?.as_str()?.to_string();
        let ends = o.get("endsAt")?.as_str()?.to_string();
        let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        Some(obj(&[
            ("grantId", json!(grant)),
            ("fingerprint", json!(s("fingerprint").unwrap_or_default())),
            ("endsAt", json!(ends.clone())),
            ("openedAt", json!(s("openedAt").unwrap_or(ends))),
        ]))
    }

    /// `status`: what `/ready` reports (T-63).
    pub fn status(&self) -> Map<String, Value> {
        match self.read_state() {
            None => obj(&[
                ("open", json!(false)),
                ("user", json!(SUPPORT_USER)),
                ("grantId", Value::Null),
                ("fingerprint", Value::Null),
                ("endsAt", Value::Null),
            ]),
            Some(st) => {
                let ends = st["endsAt"].as_str().unwrap_or_default();
                let open = parse_iso_ms(ends).is_some_and(|e| e > now_ms() as f64);
                obj(&[
                    ("open", json!(open)),
                    ("user", json!(SUPPORT_USER)),
                    ("grantId", st["grantId"].clone()),
                    ("fingerprint", st["fingerprint"].clone()),
                    ("endsAt", st["endsAt"].clone()),
                ])
            }
        }
    }

    pub async fn open(&self, grant_id: &str, seconds: f64) -> Result<Map<String, Value>, String> {
        let seconds = seconds.round();
        if !seconds.is_finite() || !(MIN_SECONDS..=MAX_SECONDS).contains(&seconds) {
            return Err(format!(
                "a shell access window must be between {MIN_SECONDS} and {MAX_SECONDS} seconds"
            ));
        }
        if !GRANT_ID.is_match(grant_id) {
            return Err("malformed grant id".into());
        }
        let dir = std::env::temp_dir().join(format!("cc-ssh-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        let path = dir.join("key");
        let made = async {
            let keygen = cc_proc::Cmd::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-C"])
                .arg(format!("{MARK}-{grant_id}"))
                .arg("-f")
                .arg(path.display().to_string())
                .timeout(Duration::from_secs(20));
            run_ok(self.runner.as_ref(), keygen).await?;
            let public = std::fs::read_to_string(dir.join("key.pub")).map_err(|e| e.to_string())?;
            let private = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            Ok::<_, String>((public.trim().to_string(), private))
        }
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        let (public, private) = made?;
        let ends_at = iso(now_ms() + (seconds as u64) * 1000);
        // The root grant, the key, the port and the timer, in one all-or-nothing call.
        let open = cc_proc::Cmd::new("sudo")
            .args(["/usr/local/bin/cc-ssh-open".to_string(), format!("{seconds}")])
            .stdin(format!("{public}\n").into_bytes())
            .timeout(Duration::from_secs(30));
        let opened = run_ok(self.runner.as_ref(), open).await?;
        if !opened.contains(OPEN_OK) {
            let close = cc_proc::Cmd::new("sudo")
                .arg("/usr/local/bin/cc-ssh-close")
                .timeout(Duration::from_secs(30));
            let _ = run_ok(self.runner.as_ref(), close).await;
            return Err("this firewall is running a cc-ssh-open that predates root support access; re-provision it and try again".into());
        }
        let fingerprint = fingerprint_of(&public);
        let state =
            json!({"grantId": grant_id, "fingerprint": fingerprint, "endsAt": ends_at, "openedAt": iso(now_ms())});
        cc_store::write_file(&self.state_path, state.to_string().as_bytes(), 0o600).map_err(|e| e.to_string())?;
        tracing::info!("[ssh] opened on this firewall for {SUPPORT_USER} until {ends_at} ({fingerprint})");
        Ok(obj(&[
            ("user", json!(SUPPORT_USER)),
            ("fingerprint", json!(fingerprint)),
            ("publicKey", json!(public)),
            ("privateKey", json!(private)),
            ("endsAt", json!(ends_at)),
            ("sudo", json!(true)),
        ]))
    }

    pub async fn close(&self) -> Result<Map<String, Value>, String> {
        let was = self.read_state();
        let close = cc_proc::Cmd::new("sudo")
            .arg("/usr/local/bin/cc-ssh-close")
            .timeout(Duration::from_secs(30));
        run_ok(self.runner.as_ref(), close).await?;
        let _ = std::fs::remove_file(&self.state_path);
        if let Some(w) = &was {
            tracing::info!(
                "[ssh] closed on this firewall (was {})",
                w["fingerprint"].as_str().unwrap_or_default()
            );
        }
        Ok(obj(&[("user", json!(SUPPORT_USER)), ("closed", json!(was.is_some()))]))
    }
}

/// `Date.parse` of an ISO time with milliseconds and `Z` (what this box writes).
pub(crate) fn parse_iso_ms(s: &str) -> Option<f64> {
    static ISO: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|[+-]\d{2}:?\d{2})?$")
            .expect("a valid regex")
    });
    let c = ISO.captures(s)?;
    let n = |i: usize| c.get(i).and_then(|m| m.as_str().parse::<i64>().ok());
    let (y, mo, d) = (n(1)?, n(2)?, n(3)?);
    // Days from the civil date (Howard Hinnant's algorithm).
    let (y2, m2) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * m2 + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let mut secs = days * 86_400 + n(4)? * 3600 + n(5)? * 60 + n(6)?;
    if let Some(z) = c.get(8).map(|m| m.as_str()).filter(|z| *z != "Z") {
        let sign = if z.starts_with('-') { -1 } else { 1 };
        let digits: String = z[1..].chars().filter(char::is_ascii_digit).collect();
        let (hh, mm) = (digits[..2].parse::<i64>().ok()?, digits[2..].parse::<i64>().ok()?);
        secs -= sign * (hh * 3600 + mm * 60);
    }
    let ms = c
        .get(7)
        .map(|m| format!("{:0<3}", m.as_str()).parse::<i64>().unwrap_or(0))
        .unwrap_or(0);
    Some((secs * 1000 + ms) as f64)
}

fn hours(seconds: f64) -> String {
    let h = (seconds / 3600.0).round() as i64;
    if h >= 24 && h % 24 == 0 {
        let d = h / 24;
        return format!("{d} day{}", if h == 24 { "" } else { "s" });
    }
    format!("{h} hour{}", if h == 1 { "" } else { "s" })
}

#[derive(Debug, Clone, PartialEq)]
struct Proposal {
    change_id: String,
    seconds: f64,
    /// `None` for this firewall.
    agent: Option<(String, String, String)>,
}

fn parse(p: &Map<String, Value>) -> Result<Proposal, String> {
    let bad = || "malformed ssh.propose payload".to_string();
    let change_id = text(p, "changeId").ok_or_else(bad)?;
    let seconds = p.get("seconds").and_then(Value::as_f64).map(f64::round).unwrap_or(0.0);
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(bad());
    }
    let agent = match p.get("agent") {
        None | Some(Value::Null) => None,
        Some(raw) => {
            let empty = Map::new();
            let a = raw.as_object().unwrap_or(&empty);
            let (Some(vm), Some(host)) = (text(a, "vmId"), text(a, "hostname")) else {
                return Err(bad());
            };
            Some((vm.clone(), text(a, "name").unwrap_or(vm), host))
        }
    };
    Ok(Proposal {
        change_id,
        seconds,
        agent,
    })
}

impl Proposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id, "seconds": super::ingress::num(self.seconds),
            "agent": self.agent.as_ref().map(|(vm, name, host)| json!({"vmId": vm, "name": name, "hostname": host})),
        })
    }

    fn vm(&self) -> Option<&str> {
        self.agent.as_ref().map(|(v, _, _)| v.as_str())
    }
}

/// `summarize`: which box and for how long, written here.
fn summarize(p: &Proposal, box_name: &str) -> String {
    let name = p.agent.as_ref().map(|(_, n, _)| n.as_str()).unwrap_or(box_name);
    format!(
        "Let ControlClaw support open a shell on {name} for {}",
        hours(p.seconds)
    )
}

pub struct Ssh {
    agent: AgentClient,
    pub local: Arc<SshLocal>,
    kit: Kit,
    agents: Arc<super::identities::Agents>,
    box_name: String,
}

impl Ssh {
    pub fn new(agent: AgentClient, local: Arc<SshLocal>, kit: Kit, agents: Arc<super::identities::Agents>) -> Self {
        Self {
            agent,
            local,
            kit,
            agents,
            box_name: "your firewall".into(),
        }
    }

    fn scope(vm: Option<&str>) -> String {
        format!("{SCOPE_PREFIX}{}", vm.unwrap_or(SELF))
    }

    async fn open_on(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let Some((vm, _, host)) = &p.agent else {
            return self.local.open(&p.change_id, p.seconds).await;
        };
        let r = self
            .agent
            .post(
                &AgentTarget::new(vm, host),
                "/ssh/open",
                &json!({"grantId": p.change_id, "seconds": super::ingress::num(p.seconds)}),
            )
            .await
            .map_err(|e| e.to_string())?;
        if !r.get("privateKey").is_some_and(Value::is_string) || !r.get("fingerprint").is_some_and(Value::is_string) {
            return Err("The box did not hand back a key. Nothing was opened.".into());
        }
        Ok(r)
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize(&p, &self.box_name);
        let data = obj(&[("changeId", json!(p.change_id)), ("summary", json!(summary))]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        let scope = Self::scope(p.vm());
        if routes.is_empty() {
            // Never first use: an org that cannot be asked cannot say yes.
            self.kit.consent.forget(&scope);
            let (message, extra) = no_recipients(self.kit.agent_allowed());
            let mut d = data;
            d.extend(extra);
            return fail(
                "failed",
                format!("{message} Letting support in has no first-use shortcut."),
                d,
            );
        }
        // The first part names the box as this firewall has it on record.
        let known = match p.vm() {
            Some(vm) => self.agents.record_name(vm).map(|n| format!("the agent {n}")),
            None => Some("your firewall".to_string()),
        };
        let parts = known.map(|k| CodeParts {
            ask: format!("Let ControlClaw support open a shell on {k} for {}", hours(p.seconds)),
            ..Default::default()
        });
        let agent_name = p
            .agent
            .as_ref()
            .map(|(_, n, _)| n.clone())
            .unwrap_or_else(|| self.box_name.clone());
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope,
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name,
                summary,
                routes,
                parts,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!(
                "[ssh] code sent for {} via {sent_via}",
                p.agent.as_ref().map(|(_, n, _)| n.as_str()).unwrap_or("this firewall")
            );
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed ssh.confirm payload");
        };
        let vm = text(&payload, "vmId");
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(&Self::scope(vm.as_deref()), &change_id, &code) {
            CodeCheck::Expired => fail(
                "expired",
                "No shell access is waiting for a code, or the code expired.",
                data,
            ),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                match self.open_on(&p).await {
                    // The private key rides in the result; the console takes it out before
                    // anything is written down. It is not logged here.
                    Ok(opened) => {
                        let mut d = data;
                        d.extend(opened);
                        d.insert("summary".into(), json!(summarize(&p, &self.box_name)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("vmId".into(), null_or(p.vm().map(str::to_string)));
                        ok("opened", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        let vm = text(&payload, "vmId");
        self.kit
            .consent
            .cancel(&Self::scope(vm.as_deref()), change_id.as_deref());
        ok("cancelled", obj(&[("changeId", null_or(change_id))]))
    }

    /// `ssh.close`: no code; revoking is never the dangerous direction.
    pub async fn close(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        let agent = payload
            .get("agent")
            .and_then(Value::as_object)
            .and_then(|a| Some((text(a, "vmId")?, text(a, "hostname")?)));
        self.kit
            .consent
            .forget(&Self::scope(agent.as_ref().map(|(v, _)| v.as_str())));
        let closed = match &agent {
            None => self.local.close().await,
            Some((vm, host)) => self
                .agent
                .post(&AgentTarget::new(vm, host), "/ssh/close", &json!({}))
                .await
                .map_err(|e| e.to_string()),
        };
        let closed = match closed {
            Ok(c) => c,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        tracing::info!(
            "[ssh] closed on {}",
            agent.as_ref().map(|(v, _)| v.as_str()).unwrap_or("this firewall")
        );
        let mut d = obj(&[("changeId", null_or(change_id))]);
        d.extend(closed);
        d.insert("vmId".into(), null_or(agent.map(|(v, _)| v)));
        ok("closed", d)
    }
}

static ACCEPTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Accepted publickey for (\S+) from (\S+) port [0-9]+ ssh2:\s+\S+\s+(SHA256:\S+)").expect("re")
});
static STAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:[+-][0-9]{2}:?[0-9]{2}|Z)?)").expect("re")
});

/// `parseSshdLine`: `(user, fingerprint, from, at ms)` of an accepted login.
pub fn parse_sshd_line(line: &str) -> Option<(String, String, String, Option<f64>)> {
    let m = ACCEPTED.captures(line)?;
    let at = STAMP.captures(line).and_then(|s| parse_iso_ms(&s[1]));
    Some((m[1].to_string(), m[3].to_string(), m[2].to_string(), at))
}

const MAX_PER_TICK: usize = 50;
const MAX_BUFFERED: usize = 500;

/// `SshLoginWatcher`: every SSH login on this box, from sshd's journal, to Activity.
pub struct SshLogins {
    runner: Arc<dyn cc_proc::Runner>,
    cursor_path: PathBuf,
    url: String,
    client: super::store_client::StoreClient,
    pending: Mutex<Vec<Value>>,
}

impl SshLogins {
    pub fn new(
        runner: Arc<dyn cc_proc::Runner>,
        cursor_path: PathBuf,
        url: &str,
        client: super::store_client::StoreClient,
    ) -> Self {
        Self {
            runner,
            cursor_path,
            url: url.into(),
            client,
            pending: Mutex::new(Vec::new()),
        }
    }

    async fn journal(&self) -> Vec<String> {
        let cmd = cc_proc::Cmd::new("journalctl")
            .args(["-u", "ssh", "-u", "sshd", "--no-pager", "-q", "-o", "short-iso"])
            .arg(format!("--cursor-file={}", self.cursor_path.display()))
            .timeout(Duration::from_secs(15));
        match self.runner.run(cmd).await {
            Ok(out) => out
                .stdout_str()
                .split('\n')
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    pub async fn tick(&self) -> usize {
        let lines = self.journal().await;
        let tick_ts = (now_ms() as f64 / 1000.0).round() as i64;
        let records = {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            for line in &lines {
                let Some((user, fp, from, at)) = parse_sshd_line(line) else {
                    continue;
                };
                pending.push(json!({
                    "source": "ssh_login",
                    "login_id": &hex::encode(Sha256::digest(line.as_bytes()))[..32],
                    "ts": at.map(|a| (a / 1000.0).round() as i64).unwrap_or(tick_ts),
                    "user": user, "fingerprint": fp, "from_ip": from,
                }));
            }
            let n = pending.len();
            if n > MAX_BUFFERED {
                pending.drain(..n - MAX_BUFFERED);
            }
            if pending.is_empty() {
                return 0;
            }
            pending.iter().take(MAX_PER_TICK).cloned().collect::<Vec<_>>()
        };
        let n = records.len();
        match self.client.post_text(&self.url, &json!({"records": records})).await {
            Ok((s, _)) if (200..300).contains(&s) => {
                let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                let take = n.min(pending.len());
                pending.drain(..take);
                tracing::info!("[ssh] reported {n} login(s)");
                n
            }
            Ok((s, _)) => {
                tracing::info!("[ssh] could not report {n} login(s): HTTP {s}; keeping them for the next pass");
                0
            }
            Err(e) => {
                tracing::error!("[ssh] login watch: {e}");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_summaries_and_times() {
        let line = "2026-09-22T14:02:11+0000 box sshd[2211]: Accepted publickey for controlclaw from 203.0.113.9 port 54321 ssh2: ED25519 SHA256:abcd";
        let (user, fp, from, at) = parse_sshd_line(line).expect("parsed");
        assert_eq!(
            (user.as_str(), fp.as_str(), from.as_str()),
            ("controlclaw", "SHA256:abcd", "203.0.113.9")
        );
        assert_eq!(at, Some(1_790_085_731_000.0));
        assert!(parse_sshd_line("Failed password for x").is_none());
        assert_eq!(hours(3600.0), "1 hour");
        assert_eq!(hours(86400.0 * 3.0), "3 days");
        assert_eq!(hours(86400.0), "1 day");
        assert_eq!(hours(7200.0), "2 hours");
        let p = parse(json!({"changeId": "g1", "seconds": 7200}).as_object().expect("obj")).expect("ok");
        assert_eq!(
            summarize(&p, "your firewall"),
            "Let ControlClaw support open a shell on your firewall for 2 hours"
        );
        assert!(parse(json!({"changeId": "g1", "seconds": 0}).as_object().expect("obj")).is_err());
        assert!(
            parse(
                json!({"changeId": "g1", "seconds": 60, "agent": {"vmId": "v"}})
                    .as_object()
                    .expect("obj")
            )
            .is_err()
        );
        assert_eq!(parse_iso_ms("2026-10-28T10:00:00.500Z"), Some(1_793_181_600_500.0));
        assert_eq!(
            fingerprint_of("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA== x"),
            fingerprint_of(" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==")
        );
    }
}
