//! Backups on the firewall (`backup.ts`, `backup-store.ts`). This box holds the org's backup
//! keypair, mints a data key per backup and wraps it for each recipient, unwraps one for a restore,
//! and asks a person before the recipients change. Taking a backup needs no code; a restore and a
//! new recovery key do (the first recovery key is first use).
//!
//! Sealing takes minutes, so `backup.run`, `backup.firewall-run` and an applied restore answer
//! "running" or "applied" at once and report the outcome on a later beat, under a command id the
//! console recognises (`backup.done:`, `backup.restored:`, `backup.firewall-restored:`).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use cc_crypto::envelope::{fingerprint, generate_recipient_keypair, random_data_key, unwrap_data_key, wrap_data_key};
use cc_crypto::recovery::recovery_key_fingerprint;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentTarget};
use super::consent::iso;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use super::self_backup::{SelfBackup, SelfBackupInput};
use super::self_restore::{SelfRestore, SelfRestoreInput};
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeAsk, CodeCheck};

pub const RUN_REPORT_PREFIX: &str = "backup.done:";
pub const RESTORE_REPORT_PREFIX: &str = "backup.restored:";
pub const SELF_RESTORE_REPORT_PREFIX: &str = "backup.firewall-restored:";

const RESTORE_PREFIX: &str = "backup-restore:";
const RECOVERY_SCOPE: &str = "backup-recovery:org";
const SELF_RESTORE_SCOPE: &str = "backup-firewall-restore:self";
/// An agent's two archives, and the brain's one.
const KINDS: &[&str] = &["workspace", "state", "gbrain"];

const NOT_A_RECOVERY_KEY: &str = "That is not a recovery key this firewall can use.";
const NEEDS_RECOVERY_KEY: &str = "This firewall cannot open that backup. It was taken before the firewall was rebuilt, so it needs your recovery key.";
const SELF_NEEDS_RECOVERY_KEY: &str = "This firewall cannot open that backup. Paste your recovery key and try again.";
const FROZEN: &str =
    "This firewall has been put back from its backup and is restarting onto it. Try again in a minute.";

/// The disk seals that follow the recovery key (`disk-reseal.ts`, C6).
pub trait Reseal: Send + Sync {
    /// How many boxes a replacement would seal again, for the code message.
    fn count(&self) -> usize;
    /// Start moving the seals to a key a code just confirmed.
    fn replaced(&self, public_key: &str);
}

/// 32 bytes of public key in base64: 43 characters and `=`.
fn is_public_key(v: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{43}=$").expect("re"));
    v.len() == 44 && RE.is_match(v)
}

/// `httpsUrl`.
fn https_url(v: Option<&Value>) -> Option<String> {
    let s = v
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.encode_utf16().count() <= 4096)?;
    (url::Url::parse(s).ok()?.scheme() == "https").then(|| s.to_string())
}

/// `takenAt.slice(0, 16).replace("T", " ")`, by UTF-16 units as JS slices.
fn when(taken_at: Option<&str>) -> String {
    match taken_at {
        Some(t) => {
            let short = String::from_utf16_lossy(&t.encode_utf16().take(16).collect::<Vec<u16>>());
            format!(" from {} UTC", short.replacen('T', " ", 1))
        }
        None => String::new(),
    }
}

#[derive(Debug, Clone)]
struct Agent {
    vm_id: String,
    name: String,
    hostname: String,
}

impl Agent {
    fn target(&self) -> AgentTarget {
        AgentTarget::new(&self.vm_id, &self.hostname)
    }
}

/// `parseAgent`: the proposal names the box; this firewall keeps no registry to check it against.
fn parse_agent(payload: &Map<String, Value>) -> Result<Agent, String> {
    let empty = Map::new();
    let a = payload.get("agent").and_then(Value::as_object).unwrap_or(&empty);
    let (Some(vm_id), Some(hostname)) = (text(a, "vmId"), text(a, "hostname")) else {
        return Err("malformed backup payload: the agent is not named".into());
    };
    Ok(Agent {
        name: text(a, "name").unwrap_or_else(|| vm_id.clone()),
        vm_id,
        hostname,
    })
}

#[derive(Debug, Clone)]
struct Restore {
    change_id: String,
    backup_id: String,
    agent: Agent,
    kind: String,
    header: String,
    manifest_hash: String,
    download_url: String,
    wrapped: String,
    taken_at: Option<String>,
    source_vm_id: Option<String>,
}

impl Restore {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id, "backupId": self.backup_id,
            "agent": {"vmId": self.agent.vm_id, "name": self.agent.name, "hostname": self.agent.hostname},
            "kind": self.kind, "header": self.header, "manifestHash": self.manifest_hash,
            "downloadUrl": self.download_url, "wrapped": self.wrapped, "takenAt": self.taken_at,
            "sourceVmId": self.source_vm_id,
        })
    }
}

/// `parseRestore` (also reads a proposal back after its code).
fn parse_restore(p: &Map<String, Value>) -> Result<Restore, String> {
    static VM: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("re"));
    let kind = text(p, "kind").filter(|k| KINDS.contains(&k.as_str()));
    let (
        Some(change_id),
        Some(backup_id),
        Some(kind),
        Some(header),
        Some(manifest_hash),
        Some(download_url),
        Some(wrapped),
    ) = (
        text(p, "changeId"),
        text(p, "backupId"),
        kind,
        text(p, "header"),
        text(p, "manifestHash"),
        https_url(p.get("downloadUrl")),
        text(p, "wrapped"),
    )
    else {
        return Err("malformed backup.restore.propose payload".into());
    };
    Ok(Restore {
        change_id,
        backup_id,
        agent: parse_agent(p)?,
        kind,
        header,
        manifest_hash,
        download_url,
        wrapped,
        taken_at: text(p, "takenAt"),
        source_vm_id: text(p, "sourceVmId").filter(|v| VM.is_match(v)),
    })
}

/// `summarizeRestore`: names what is about to be lost.
fn summarize_restore(p: &Restore) -> String {
    let w = when(p.taken_at.as_deref());
    if p.kind == "gbrain" {
        return format!("Replace everything in your organization's brain with a backup{w}");
    }
    let what = if p.kind == "workspace" { "files" } else { "settings" };
    format!("Replace {}'s {what} with a backup{w}", p.agent.name)
}

#[derive(Debug, Clone)]
struct RecoveryProposal {
    public_key: String,
    signing_public_key: Option<String>,
    fingerprint: String,
    replaces: Option<String>,
}

/// `summarizeRecovery`: carries this firewall's own fingerprint, which the console shows too.
fn summarize_recovery(p: &RecoveryProposal, own: &str, boxes: usize) -> String {
    let disks = match boxes {
        0 => String::new(),
        1 => " and seal the disk of 1 box to it".to_string(),
        n => format!(" and seal the disks of {n} boxes to it"),
    };
    match &p.replaces {
        Some(r) if *r == p.fingerprint => {
            format!(
                "Confirm your backup recovery key {}{disks}; this firewall's key is {own}",
                p.fingerprint
            )
        }
        Some(r) => format!(
            "Replace your backup recovery key (new {}, old {r}){disks}; this firewall's key is {own}",
            p.fingerprint
        ),
        None => format!(
            "Set your backup recovery key to {}; this firewall's key is {own}",
            p.fingerprint
        ),
    }
}

#[derive(Debug, Clone)]
struct SelfRestoreProposal {
    change_id: String,
    backup_id: String,
    source_box_id: String,
    header: String,
    manifest_hash: String,
    download_url: String,
    wrapped: String,
    taken_at: Option<String>,
}

impl SelfRestoreProposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id, "backupId": self.backup_id, "sourceBoxId": self.source_box_id,
            "header": self.header, "manifestHash": self.manifest_hash, "downloadUrl": self.download_url,
            "wrappedKey": self.wrapped, "takenAt": self.taken_at,
        })
    }
}

fn parse_self_restore(p: &Map<String, Value>) -> Result<SelfRestoreProposal, String> {
    let (
        Some(change_id),
        Some(backup_id),
        Some(source_box_id),
        Some(header),
        Some(manifest_hash),
        Some(download_url),
        Some(wrapped),
    ) = (
        text(p, "changeId"),
        text(p, "backupId"),
        text(p, "sourceBoxId"),
        text(p, "header"),
        text(p, "manifestHash"),
        https_url(p.get("downloadUrl")),
        text(p, "wrappedKey"),
    )
    else {
        return Err("malformed backup.firewall-restore payload".into());
    };
    Ok(SelfRestoreProposal {
        change_id,
        backup_id,
        source_box_id,
        header,
        manifest_hash,
        download_url,
        wrapped,
        taken_at: text(p, "takenAt"),
    })
}

fn summarize_self_restore(p: &SelfRestoreProposal, own: &str) -> String {
    format!(
        "Replace this firewall's keys, certificate authority and rules with its backup{}; the key being replaced is {own}",
        when(p.taken_at.as_deref())
    )
}

/// This firewall's own recipient keypair.
#[derive(Debug, Clone)]
pub struct Keypair {
    pub public_key: String,
    pub secret_key: String,
    pub fingerprint: String,
}

/// The recovery key this firewall was given: the two public halves.
#[derive(Debug, Clone)]
pub struct RecoveryKeys {
    pub public_key: String,
    /// Null on a key set before the recovery CLI existed: the routes stay off.
    pub signing_public_key: Option<String>,
    pub fingerprint: String,
}

struct St {
    /// `{version: 1, keypair, recovery}`.
    store: Map<String, Value>,
    reports: Vec<CommandResult>,
    running: HashSet<String>,
    /// Set once a self-restore landed: nothing in memory describes the box on disk any more.
    restoring: bool,
}

fn empty_store() -> Map<String, Value> {
    obj(&[
        ("version", json!(1)),
        ("keypair", Value::Null),
        ("recovery", Value::Null),
    ])
}

pub struct Backup {
    path: PathBuf,
    box_key: String,
    aad: String,
    org_id: String,
    st: Mutex<St>,
    agent: AgentClient,
    kit: Kit,
    self_backup: Option<SelfBackup>,
    self_restore: Option<Arc<SelfRestore>>,
    pub reseal: OnceLock<Arc<dyn Reseal>>,
}

impl Backup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        self_backup: Option<SelfBackup>,
        self_restore: Option<Arc<SelfRestore>>,
    ) -> Self {
        let aad = format!("{org}:{box_id}:backup");
        let log = |l: &str| tracing::error!("{l}");
        // A store that will not open starts empty and is reported (T-53); `keypair` refuses to mint
        // over it.
        let store = match cc_crypto::enc_file::load_store_or_empty("backup", &path, box_key, &aad, &log) {
            Some(Value::Object(l)) => {
                let recovery = match l.get("recovery") {
                    Some(Value::Object(r)) => {
                        let mut r = r.clone();
                        if r.get("signingPublicKey").is_none_or(Value::is_null) {
                            r.insert("signingPublicKey".into(), Value::Null);
                        }
                        Value::Object(r)
                    }
                    // Anything else is no recovery key: kept, it would read as none to `rebind`
                    // and be overwritten without a code, where the TS refuses.
                    _ => Value::Null,
                };
                let keypair = l
                    .get("keypair")
                    .filter(|k| !k.is_null())
                    .cloned()
                    .unwrap_or(Value::Null);
                obj(&[("version", json!(1)), ("keypair", keypair), ("recovery", recovery)])
            }
            _ => empty_store(),
        };
        Self {
            path,
            box_key: box_key.into(),
            aad,
            org_id: org.into(),
            st: Mutex::new(St {
                store,
                reports: Vec::new(),
                running: HashSet::new(),
                restoring: false,
            }),
            agent,
            kit,
            self_backup,
            self_restore,
            reseal: OnceLock::new(),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s);
    }

    fn st(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, st: &St) {
        if st.restoring {
            tracing::info!(
                "[backup] not writing the store: this firewall has been put back from its backup and is restarting onto it"
            );
            return;
        }
        if let Err(e) = cc_crypto::enc_file::save_store(
            "backup",
            &self.path,
            &Value::Object(st.store.clone()),
            &self.box_key,
            &self.aad,
        ) {
            tracing::error!("[backup] could not save the store: {e}");
        }
    }

    /// Drained onto every beat.
    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut self.st().reports)
    }

    /// A restore swapped this box's files from elsewhere (the recovery route): from now until the
    /// restart, nothing here may write the store over the restored one.
    pub fn mark_restoring(&self) {
        self.set_restoring(true);
    }

    /// The self-restore's freeze: on before the swap, off again only when the swap was undone.
    pub fn set_restoring(&self, on: bool) {
        self.st().restoring = on;
    }

    pub fn restoring(&self) -> bool {
        self.st().restoring
    }

    /// `ownKeypair`: null before first use.
    pub fn own_keypair(&self) -> Option<Keypair> {
        let st = self.st();
        let k = st.store.get("keypair")?.as_object()?;
        Some(Keypair {
            public_key: text(k, "publicKey")?,
            secret_key: text(k, "secretKey")?,
            fingerprint: k
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }

    fn recovery(&self) -> Option<Map<String, Value>> {
        self.st().store.get("recovery").and_then(Value::as_object).cloned()
    }

    /// `recoveryKeys`: the two public halves, or `None`.
    pub fn recovery_keys(&self) -> Option<RecoveryKeys> {
        let r = self.recovery()?;
        let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        Some(RecoveryKeys {
            public_key: s("publicKey"),
            signing_public_key: text(&r, "signingPublicKey"),
            fingerprint: s("fingerprint"),
        })
    }

    fn control_fingerprint(&self) -> Option<String> {
        let k = self.recovery_keys()?;
        Some(recovery_key_fingerprint(
            &k.public_key,
            k.signing_public_key.as_deref()?,
        ))
    }

    /// `status`: public by construction, on every beat.
    pub fn status(&self) -> Option<Value> {
        let kp = self.st().store.get("keypair").and_then(Value::as_object).cloned()?;
        let recovery = self.recovery().map(|r| {
            json!({
                "fingerprint": r.get("fingerprint"),
                "tofu": r.get("tofu"),
                "setAt": r.get("setAt"),
                "control": self.control_fingerprint(),
            })
        });
        Some(json!({"publicKey": kp.get("publicKey"), "fingerprint": kp.get("fingerprint"), "recovery": recovery}))
    }

    /// `keypair` / `ensureKeypair`: made at start-up, never over a store this box cannot read.
    pub fn keypair(&self) -> Result<Keypair, String> {
        if let Some(k) = self.own_keypair() {
            return Ok(k);
        }
        if cc_crypto::store_health::is_store_unreadable("backup") {
            return Err(
                "this firewall cannot read its backup store, so it will not mint a replacement key over it".into(),
            );
        }
        let mut st = self.st();
        // Checked again under the lock: two callers must not mint two keys.
        if let Some(k) = st.store.get("keypair").and_then(Value::as_object)
            && let (Some(public_key), Some(secret_key)) = (text(k, "publicKey"), text(k, "secretKey"))
        {
            let fingerprint = k
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            return Ok(Keypair {
                public_key,
                secret_key,
                fingerprint,
            });
        }
        let kp = generate_recipient_keypair();
        st.store.insert(
            "keypair".into(),
            json!({"publicKey": kp.public_key, "secretKey": kp.secret_key, "fingerprint": kp.fingerprint}),
        );
        self.save(&st);
        tracing::info!("[backup] generated this firewall's backup key ({})", kp.fingerprint);
        Ok(Keypair {
            public_key: kp.public_key,
            secret_key: kp.secret_key,
            fingerprint: kp.fingerprint,
        })
    }

    /// `announceRecovery`: the two lines the owner compares with what the recover CLI prints.
    pub fn announce_recovery(&self) {
        let Some(r) = self.recovery_keys() else { return };
        tracing::info!("[mitm-agent] recovery key fingerprint: {}", r.fingerprint);
        match self.control_fingerprint() {
            Some(c) => tracing::info!(
                "[mitm-agent] recovery command key: {c} — npx @controlclaw/recover must print this exact line"
            ),
            None => tracing::info!(
                "[mitm-agent] recovery command key: none (this key predates the recovery CLI; replace it in Settings → Backups to use one)"
            ),
        }
    }

    /// The handlers' guard: refused while the box restarts onto a restored state.
    pub fn frozen(&self) -> Option<CommandOutcome> {
        self.restoring().then(|| fail("retry", FROZEN, Map::new()))
    }

    /// `later`: run detached and report under `command_id`; nothing here throws.
    fn later<F>(self: &Arc<Self>, command_id: String, label: String, work: F)
    where
        F: std::future::Future<Output = Result<Map<String, Value>, String>> + Send + 'static,
    {
        if !self.st().running.insert(command_id.clone()) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let r = work.await;
            let mut st = me.st();
            st.running.remove(&command_id);
            let report = match r {
                Ok(data) => CommandResult {
                    command_id,
                    ok: true,
                    status: "done".into(),
                    message: String::new(),
                    data: Some(data),
                },
                Err(e) => {
                    let message: String = if e.is_empty() {
                        "the backup failed".to_string()
                    } else {
                        e
                    };
                    let message = String::from_utf16_lossy(&message.encode_utf16().take(500).collect::<Vec<u16>>());
                    tracing::info!("[backup] {label} failed: {message}");
                    CommandResult {
                        command_id,
                        ok: false,
                        status: "failed".into(),
                        message,
                        data: Some(Map::new()),
                    }
                }
            };
            st.reports.push(report);
        });
    }

    // ---- taking one ----

    pub async fn run(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let Some(backup_id) = text(&payload, "backupId") else {
            return CommandOutcome::failed("failed", "malformed backup.run payload: no backupId");
        };
        let agent = match parse_agent(&payload) {
            Ok(a) => a,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let empty = Map::new();
        let uploads = payload.get("uploads").and_then(Value::as_object).unwrap_or(&empty);
        let kinds: Vec<String> = payload
            .get("kinds")
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(Value::as_str)
                    .filter(|k| KINDS.contains(k))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if kinds.is_empty() {
            return CommandOutcome::failed("failed", "malformed backup.run payload: no archives asked for");
        }
        let mut urls = Vec::new();
        for kind in &kinds {
            let Some(u) = https_url(uploads.get(kind)) else {
                return fail(
                    "failed",
                    format!("No upload address for the {kind} archive."),
                    obj(&[("backupId", json!(backup_id))]),
                );
            };
            urls.push((kind.clone(), u));
        }
        let kp = match self.keypair() {
            Ok(k) => k,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let data_key = random_data_key();
        let recovery = self.recovery();
        let own_wrap = match wrap_data_key(&data_key, &kp.public_key) {
            Ok(w) => w,
            Err(e) => return CommandOutcome::failed("failed", e.0),
        };
        let mut wraps = vec![json!({"recipient": "firewall", "fingerprint": kp.fingerprint, "wrapped": own_wrap})];
        if let Some(r) = &recovery {
            let pk = r.get("publicKey").and_then(Value::as_str).unwrap_or_default();
            match wrap_data_key(&data_key, pk) {
                Ok(w) => {
                    wraps.push(json!({"recipient": "recovery", "fingerprint": r.get("fingerprint"), "wrapped": w}))
                }
                Err(e) => return CommandOutcome::failed("failed", e.0),
            }
        }
        let has_recovery = recovery.is_some();
        let (me, org, id, w2) = (self.clone(), self.org_id.clone(), backup_id.clone(), wraps.clone());
        self.later(format!("{RUN_REPORT_PREFIX}{backup_id}"), format!("backup of {}", agent.name), async move {
            let mut archives = Vec::new();
            for (kind, upload_url) in urls {
                let body = json!({"orgId": org, "vmId": agent.vm_id, "backupId": id, "kind": kind, "dataKey": data_key, "uploadUrl": upload_url});
                let r = me.agent.post(&agent.target(), "/backup/run", &body).await.map_err(|e| e.to_string())?;
                let mut a = obj(&[("kind", json!(kind))]);
                for k in ["header", "manifestHash", "plainBytes", "cipherBytes", "entries", "excludedBytes", "takenAt"] {
                    if let Some(v) = r.get(k) {
                        a.insert(k.into(), v.clone());
                    }
                }
                archives.push(Value::Object(a));
            }
            tracing::info!(
                "[backup] sealed {} archive(s) of {} for {} recipient(s)",
                archives.len(),
                agent.name,
                w2.len()
            );
            // `this.store.recovery !== null` when the work finishes.
            let recovery_now = me.recovery().is_some();
            Ok(obj(&[
                ("backupId", json!(id)),
                ("archives", Value::Array(archives)),
                ("wraps", Value::Array(w2)),
                ("recovery", json!(recovery_now)),
            ]))
        });
        ok(
            "running",
            obj(&[
                ("backupId", json!(backup_id)),
                ("wraps", Value::Array(wraps)),
                ("recovery", json!(has_recovery)),
            ]),
        )
    }

    /// `backup.firewall-run`: wrapped to the recovery key only (this box's own key is in it).
    pub async fn run_self(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(backup_id), Some(upload_url)) = (text(&payload, "backupId"), https_url(payload.get("uploadUrl")))
        else {
            return CommandOutcome::failed("failed", "malformed backup.firewall-run payload");
        };
        let data = obj(&[("backupId", json!(backup_id))]);
        let Some(self_backup) = self.self_backup.clone() else {
            return fail("unavailable", "This firewall cannot back itself up.", data);
        };
        let Some(recovery) = self.recovery_keys() else {
            return fail(
                "no_recovery_key",
                "A firewall backup can only be sealed to your recovery key, and this organisation has not set one yet.",
                data,
            );
        };
        let data_key = random_data_key();
        let own = match self.keypair() {
            Ok(k) => k,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let id = backup_id.clone();
        self.later(
            format!("{RUN_REPORT_PREFIX}{backup_id}"),
            "backup of this firewall".into(),
            async move {
                let r = self_backup
                    .run(SelfBackupInput {
                        backup_id: id.clone(),
                        upload_url,
                        data_key,
                        recovery_public_key: recovery.public_key,
                        recovery_fingerprint: recovery.fingerprint,
                    })
                    .await?;
                Ok(obj(&[
                    ("backupId", json!(id)),
                    (
                        "archives",
                        json!([{
                            "kind": "firewall", "header": r.header, "manifestHash": r.manifest_hash,
                            "plainBytes": r.plain_bytes, "cipherBytes": r.cipher_bytes, "entries": r.entries,
                            "takenAt": r.taken_at, "firewallFingerprint": own.fingerprint,
                        }]),
                    ),
                    (
                        "wraps",
                        json!([{"recipient": "recovery", "fingerprint": r.recovery_fingerprint, "wrapped": r.wrapped}]),
                    ),
                ]))
            },
        );
        ok("running", data)
    }

    // ---- putting one back ----

    fn unwrap_with_own(&self, wrapped: &str) -> Option<String> {
        let kp = self.own_keypair()?;
        unwrap_data_key(wrapped, &kp.secret_key).ok()
    }

    /// `applyRestore`: the data key is unwrapped here, before the command settles.
    fn apply_restore(self: &Arc<Self>, p: &Restore) -> Result<Map<String, Value>, String> {
        let Some(kp) = self.own_keypair() else {
            return Err("This firewall has no backup key, so it cannot open a backup.".into());
        };
        let data_key = unwrap_data_key(&p.wrapped, &kp.secret_key).map_err(|_| NEEDS_RECOVERY_KEY.to_string())?;
        let (me, org, p2) = (self.clone(), self.org_id.clone(), p.clone());
        self.later(
            format!("{RESTORE_REPORT_PREFIX}{}", p.change_id),
            format!("restore of {} onto {}", p.kind, p.agent.name),
            async move {
                let mut body = obj(&[
                    ("orgId", json!(org)),
                    ("vmId", json!(p2.agent.vm_id)),
                    ("backupId", json!(p2.backup_id)),
                    ("kind", json!(p2.kind)),
                    ("dataKey", json!(data_key)),
                    ("header", json!(p2.header)),
                    ("manifestHash", json!(p2.manifest_hash)),
                    ("downloadUrl", json!(p2.download_url)),
                ]);
                if let Some(s) = p2.source_vm_id.as_ref().filter(|s| **s != p2.agent.vm_id) {
                    body.insert("sourceVmId".into(), json!(s));
                }
                let r = me
                    .agent
                    .post(&p2.agent.target(), "/backup/restore", &Value::Object(body))
                    .await
                    .map_err(|e| e.to_string())?;
                tracing::info!("[backup] restored {} onto {}", p2.kind, p2.agent.name);
                let mut d = obj(&[
                    ("changeId", json!(p2.change_id)),
                    ("vmId", json!(p2.agent.vm_id)),
                    ("kind", json!(p2.kind)),
                ]);
                for k in ["entries", "restarted"] {
                    if let Some(v) = r.get(k) {
                        d.insert(k.into(), v.clone());
                    }
                }
                Ok(d)
            },
        );
        Ok(obj(&[
            ("vmId", json!(p.agent.vm_id)),
            ("kind", json!(p.kind)),
            ("backupId", json!(p.backup_id)),
        ]))
    }

    pub async fn propose_restore(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse_restore(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize_restore(&p);
        let data = obj(&[
            ("changeId", json!(p.change_id)),
            ("backupId", json!(p.backup_id)),
            ("summary", json!(summary)),
        ]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        let scope = format!("{RESTORE_PREFIX}{}", p.agent.vm_id);
        if routes.is_empty() {
            self.kit.consent.forget(&scope);
            return match self.apply_restore(&p) {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        // Refused before a code goes out when this key will not open it.
        if self.own_keypair().is_some() && self.unwrap_with_own(&p.wrapped).is_none() {
            return fail("needs_recovery_key", NEEDS_RECOVERY_KEY, data);
        }
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope,
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: p.agent.name.clone(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[backup] restore code sent for {} via {sent_via}", p.agent.name);
        }
        awaiting(sent, data)
    }

    pub async fn confirm_restore(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(vm_id)) = (text(&payload, "changeId"), text(&payload, "vmId")) else {
            return CommandOutcome::failed("failed", "malformed backup.restore.confirm payload");
        };
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self
            .kit
            .consent
            .verify(&format!("{RESTORE_PREFIX}{vm_id}"), &change_id, &code)
        {
            CodeCheck::Expired => fail(
                "expired",
                "No restore is waiting for a code, or the code expired.",
                data,
            ),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse_restore(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                match self.apply_restore(&p) {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize_restore(&p)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel_restore(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        if let Some(vm) = text(&payload, "vmId") {
            self.kit
                .consent
                .cancel(&format!("{RESTORE_PREFIX}{vm}"), change_id.as_deref());
        }
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }

    // ---- the recovery key ----

    fn set_recovery(&self, p: &RecoveryProposal, tofu: bool) {
        {
            let mut st = self.st();
            st.store.insert(
                "recovery".into(),
                json!({
                    "publicKey": p.public_key, "signingPublicKey": p.signing_public_key,
                    "fingerprint": p.fingerprint, "tofu": tofu, "setAt": iso(now_ms()),
                }),
            );
            self.save(&st);
        }
        self.announce_recovery();
        tracing::info!(
            "[backup] recovery key {}: {}{}",
            if p.replaces.is_some() { "replaced" } else { "set" },
            p.fingerprint,
            if tofu { " (first use, no code)" } else { "" }
        );
    }

    fn reseal_count(&self) -> usize {
        self.reseal.get().map_or(0, |r| r.count())
    }

    pub async fn propose_recovery(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(public_key)) = (text(&payload, "changeId"), text(&payload, "publicKey")) else {
            return CommandOutcome::failed("failed", "malformed backup.recovery.propose payload");
        };
        let refuse = || fail("failed", NOT_A_RECOVERY_KEY, obj(&[("changeId", json!(change_id))]));
        if !is_public_key(&public_key) {
            return refuse();
        }
        let signing_public_key = text(&payload, "signingPublicKey");
        if signing_public_key.as_deref().is_some_and(|s| !is_public_key(s)) {
            return refuse();
        }
        let own = match self.keypair() {
            Ok(k) => k,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let p = RecoveryProposal {
            fingerprint: fingerprint(&public_key).unwrap_or_default(),
            public_key,
            signing_public_key,
            replaces: self
                .recovery()
                .and_then(|r| r.get("fingerprint").and_then(Value::as_str).map(str::to_string)),
        };
        let summary = summarize_recovery(&p, &own.fingerprint, self.reseal_count());
        let data = obj(&[
            ("changeId", json!(change_id)),
            ("summary", json!(summary)),
            ("fingerprint", json!(p.fingerprint)),
            ("firewallFingerprint", json!(own.fingerprint)),
            ("firewallPublicKey", json!(own.public_key)),
        ]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(RECOVERY_SCOPE);
            self.set_recovery(&p, true);
            let mut d = data;
            d.insert("tofu".into(), json!(true));
            return ok("applied", d);
        }
        let proposal = json!({
            "changeId": change_id, "publicKey": p.public_key, "signingPublicKey": p.signing_public_key,
            "fingerprint": p.fingerprint, "replaces": p.replaces,
        });
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: RECOVERY_SCOPE.into(),
                change_id,
                proposal,
                agent_name: "your organization's backups".into(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[backup] recovery key code sent via {sent_via}");
        }
        awaiting(sent, data)
    }

    /// `backup.recovery.rebind`: a rebuilt firewall gets the org's pair back, only when it holds none.
    pub async fn rebind_recovery(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(public_key), Some(signing_public_key)) = (
            text(&payload, "publicKey").filter(|k| is_public_key(k)),
            text(&payload, "signingPublicKey").filter(|k| is_public_key(k)),
        ) else {
            return fail("failed", NOT_A_RECOVERY_KEY, Map::new());
        };
        if let Some(fp) = self
            .recovery()
            .map(|r| r.get("fingerprint").cloned().unwrap_or(Value::Null))
        {
            let shown = fp.as_str().map(str::to_string).unwrap_or_else(|| fp.to_string());
            return fail(
                "already_set",
                format!(
                    "This firewall already holds a recovery key ({shown}), so it will not take another without a confirmation."
                ),
                obj(&[("fingerprint", fp)]),
            );
        }
        let own = match self.keypair() {
            Ok(k) => k,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let fp = fingerprint(&public_key).unwrap_or_default();
        let control = recovery_key_fingerprint(&public_key, &signing_public_key);
        self.set_recovery(
            &RecoveryProposal {
                public_key,
                signing_public_key: Some(signing_public_key),
                fingerprint: fp.clone(),
                replaces: None,
            },
            true,
        );
        ok(
            "applied",
            obj(&[
                ("fingerprint", json!(fp)),
                ("control", json!(control)),
                ("firewallFingerprint", json!(own.fingerprint)),
                ("firewallPublicKey", json!(own.public_key)),
            ]),
        )
    }

    pub async fn confirm_recovery(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed backup.recovery.confirm payload");
        };
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self.kit.consent.verify(RECOVERY_SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail(
                "expired",
                "No recovery key is waiting for a code, or the code expired.",
                data,
            ),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let o = proposal.as_object().cloned().unwrap_or_default();
                let p = RecoveryProposal {
                    public_key: text(&o, "publicKey").unwrap_or_default(),
                    signing_public_key: text(&o, "signingPublicKey"),
                    fingerprint: text(&o, "fingerprint").unwrap_or_default(),
                    replaces: text(&o, "replaces"),
                };
                let own = match self.keypair() {
                    Ok(k) => k,
                    Err(e) => return CommandOutcome::failed("failed", e),
                };
                let boxes = self.reseal_count();
                self.set_recovery(&p, false);
                // Only here: a key taken without a code moves no disk.
                if let Some(r) = self.reseal.get() {
                    r.replaced(&p.public_key);
                }
                let mut d = data;
                d.insert("summary".into(), json!(summarize_recovery(&p, &own.fingerprint, boxes)));
                d.insert("fingerprint".into(), json!(p.fingerprint));
                d.insert("firewallFingerprint".into(), json!(own.fingerprint));
                d.insert("firewallPublicKey".into(), json!(own.public_key));
                d.insert("sentVia".into(), json!(sent_via));
                d.insert("tofu".into(), json!(false));
                ok("applied", d)
            }
        }
    }

    pub fn cancel_recovery(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        self.kit.consent.cancel(RECOVERY_SCOPE, change_id.as_deref());
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }

    // ---- putting this firewall back from its own backup ----

    fn apply_self_restore(self: &Arc<Self>, p: &SelfRestoreProposal) -> Result<Map<String, Value>, String> {
        let Some(service) = self.self_restore.clone() else {
            return Err("This firewall cannot put itself back.".into());
        };
        let Some(kp) = self.own_keypair() else {
            return Err("This firewall has no backup key, so it cannot open a backup.".into());
        };
        let data_key = unwrap_data_key(&p.wrapped, &kp.secret_key).map_err(|_| SELF_NEEDS_RECOVERY_KEY.to_string())?;
        let (me, p2) = (self.clone(), p.clone());
        self.later(
            format!("{SELF_RESTORE_REPORT_PREFIX}{}", p.change_id),
            "restore of this firewall".into(),
            async move {
                let r = service
                    .run(SelfRestoreInput {
                        backup_id: p2.backup_id.clone(),
                        source_box_id: p2.source_box_id.clone(),
                        download_url: Some(p2.download_url.clone()),
                        archive: None,
                        header: p2.header.clone(),
                        manifest_hash: p2.manifest_hash.clone(),
                        data_key,
                        taken_at: p2.taken_at.clone(),
                    })
                    .await?;
                me.st().restoring = true;
                Ok(obj(&[
                    ("changeId", json!(p2.change_id)),
                    ("backupId", json!(p2.backup_id)),
                    ("entries", json!(r.entries)),
                    ("takenAt", json!(r.taken_at)),
                    ("fingerprint", json!(r.fingerprint)),
                    ("quarantined", json!(r.quarantined)),
                ]))
            },
        );
        Ok(obj(&[
            ("backupId", json!(p.backup_id)),
            ("replaces", json!(kp.fingerprint)),
        ]))
    }

    pub async fn propose_self_restore(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse_self_restore(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let own = match self.keypair() {
            Ok(k) => k,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize_self_restore(&p, &own.fingerprint);
        let data = obj(&[
            ("changeId", json!(p.change_id)),
            ("backupId", json!(p.backup_id)),
            ("summary", json!(summary)),
            ("firewallFingerprint", json!(own.fingerprint)),
        ]);
        if self.self_restore.is_none() {
            return fail("unavailable", "This firewall cannot put itself back.", data);
        }
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if unwrap_data_key(&p.wrapped, &own.secret_key).is_err() {
            return fail("needs_recovery_key", SELF_NEEDS_RECOVERY_KEY, data);
        }
        if routes.is_empty() {
            self.kit.consent.forget(SELF_RESTORE_SCOPE);
            return match self.apply_self_restore(&p) {
                Ok(applied) => {
                    let mut d = data;
                    d.extend(applied);
                    d.insert("tofu".into(), json!(true));
                    ok("applied", d)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: SELF_RESTORE_SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: "your firewall".into(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[backup] firewall restore code sent via {sent_via}");
        }
        awaiting(sent, data)
    }

    pub async fn confirm_self_restore(self: &Arc<Self>, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed backup.firewall-restore.confirm payload");
        };
        let data = obj(&[("changeId", json!(change_id))]);
        let code = text(&payload, "code").unwrap_or_default();
        match self.kit.consent.verify(SELF_RESTORE_SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail(
                "expired",
                "No firewall restore is waiting for a code, or the code expired.",
                data,
            ),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse_self_restore(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                let own = match self.keypair() {
                    Ok(k) => k,
                    Err(e) => return CommandOutcome::failed("failed", e),
                };
                match self.apply_self_restore(&p) {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize_self_restore(&p, &own.fingerprint)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel_self_restore(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        self.kit.consent.cancel(SELF_RESTORE_SCOPE, change_id.as_deref());
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries() {
        let r = RecoveryProposal {
            public_key: String::new(),
            signing_public_key: None,
            fingerprint: "aaaa".into(),
            replaces: None,
        };
        assert_eq!(
            summarize_recovery(&r, "ffff", 3),
            "Set your backup recovery key to aaaa; this firewall's key is ffff"
        );
        let r2 = RecoveryProposal {
            replaces: Some("bbbb".into()),
            ..r.clone()
        };
        assert_eq!(
            summarize_recovery(&r2, "ffff", 1),
            "Replace your backup recovery key (new aaaa, old bbbb) and seal the disk of 1 box to it; this firewall's key is ffff"
        );
        let r3 = RecoveryProposal {
            replaces: Some("aaaa".into()),
            ..r
        };
        assert_eq!(
            summarize_recovery(&r3, "ffff", 2),
            "Confirm your backup recovery key aaaa and seal the disks of 2 boxes to it; this firewall's key is ffff"
        );
        assert_eq!(when(Some("2026-10-01T12:34:56.000Z")), " from 2026-10-01 12:34 UTC");
        assert!(is_public_key("E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20="));
        assert!(!is_public_key("E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20"));
        assert_eq!(https_url(Some(&json!("http://x"))), None);
        assert_eq!(https_url(Some(&json!("https://x/y"))), Some("https://x/y".into()));
    }
}
