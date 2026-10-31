//! Sealing every box's disk passphrase to the recovery key after it was replaced with a code
//! (`disk-reseal.ts`). A loop, not a command: it seals this firewall's own disk, asks each agent to
//! seal its own, and keeps asking until each answers with the key's name. The record of every
//! agent this firewall has pinned or been told of is never shrunk on the console's word, and the
//! closing message says "you no longer need the previous key" only when every agent in it named
//! the new key itself in this round.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::agent_client::{AgentClient, AgentError, AgentTarget};
use super::kit::Kit;
use super::now_ms;
use super::own_messages::remember_own;
use crate::contracts::CodeSender;

pub const RESEAL_RETRY_MS: u64 = 5 * 60_000;
/// A box that is done is asked again this often: one restored from an older image is behind.
pub const RESEAL_RECHECK_MS: u64 = 6 * 60 * 60_000;
const MESSAGE_TTL_MS: u64 = 30 * 24 * 60 * 60_000;
/// How long an agent the list no longer has is waited for when it has not answered as itself.
pub const RESEAL_ABSENT_MS: u64 = 7 * 24 * 60 * 60_000;

static TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^sha256:[0-9a-f]{16}$").expect("re"));
static VM_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$").expect("re"));
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x00-\x1f\x7f]+").expect("re"));
static NOT_OPEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)disk is not open").expect("re"));
static NO_DISK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)no container at|no \S+luks\.key").expect("re"));
static NO_HELPER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)a password is required|a terminal is required|command not found|No such file|usage: cc-secure \{")
        .expect("re")
});
static MISSING: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)No such file|command not found").expect("re"));
static BUSY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)sealing its disk passphrase already").expect("re"));

pub use cc_crypto::recovery::recovery_key_tag;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResealBox {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub at: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moved: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub absent_since: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped: Option<String>,
}

impl ResealBox {
    fn new(state: &str, at: u64) -> Self {
        Self {
            state: state.into(),
            at: at as f64,
            ..Default::default()
        }
    }
    fn moved(&self) -> bool {
        self.moved == Some(true)
    }
    /// `extras`: message, moved and dropped, when set.
    fn extras(&self, out: &mut Map<String, Value>) {
        if let Some(m) = self.message.as_ref().filter(|m| !m.is_empty()) {
            out.insert("message".into(), json!(m));
        }
        if self.moved() {
            out.insert("moved".into(), json!(true));
        }
        if let Some(d) = &self.dropped {
            out.insert("dropped".into(), json!(d));
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Dropped {
    why: String,
    at: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct Known {
    name: String,
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sealed_at: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dropped: Option<Dropped>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Message {
    text: String,
    at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Store {
    version: u32,
    known: BTreeMap<String, Known>,
    target: Option<String>,
    previous: Option<String>,
    started_at: f64,
    origin: String,
    lost: bool,
    #[serde(rename = "self")]
    self_box: Option<ResealBox>,
    agents: BTreeMap<String, ResealBox>,
    said_started: bool,
    said_done: bool,
    outbox: Vec<Message>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            version: 1,
            known: BTreeMap::new(),
            target: None,
            previous: None,
            started_at: 0.0,
            origin: "found".into(),
            lost: false,
            self_box: None,
            agents: BTreeMap::new(),
            said_started: false,
            said_done: false,
            outbox: Vec::new(),
            extra: Map::new(),
        }
    }
}

/// Only ids of the expected shape become keys.
fn dict<T>(m: BTreeMap<String, T>) -> BTreeMap<String, T> {
    m.into_iter().filter(|(k, _)| VM_ID.is_match(k)).collect()
}

/// A store whose whole shape did not parse: each field and each entry on its own. An entry left
/// out marks the record lost, so no round says every box is sealed after it.
fn lenient(o: Map<String, Value>) -> Store {
    let mut lost = false;
    let field = |k: &str| o.get(k).cloned().unwrap_or(Value::Null);
    fn map_of<T: serde::de::DeserializeOwned>(v: Value, lost: &mut bool) -> BTreeMap<String, T> {
        let mut out = BTreeMap::new();
        for (k, x) in v.as_object().cloned().unwrap_or_default() {
            match serde_json::from_value(x) {
                Ok(t) => {
                    out.insert(k, t);
                }
                Err(_) => *lost = true,
            }
        }
        dict(out)
    }
    let known = map_of(field("known"), &mut lost);
    let agents = map_of(field("agents"), &mut lost);
    let outbox: Vec<Message> = field("outbox")
        .as_array()
        .map(|l| {
            l.iter()
                .filter_map(|m| serde_json::from_value(m.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    let text = |v: Value| v.as_str().map(str::to_string);
    let flag = |v: Value| v.as_bool().unwrap_or(false);
    let d = Store::default();
    Store {
        known,
        agents,
        target: text(field("target")),
        previous: text(field("previous")),
        started_at: field("startedAt").as_f64().unwrap_or(0.0),
        origin: text(field("origin")).unwrap_or(d.origin),
        lost: lost || flag(field("lost")),
        self_box: serde_json::from_value(field("self")).ok().flatten(),
        said_started: flag(field("saidStarted")),
        said_done: flag(field("saidDone")),
        outbox,
        ..Store::default()
    }
}

/// One line a box wrote about itself, cut to 200 characters.
fn brief(text: &str) -> String {
    let clean = CONTROL.replace_all(text, " ").trim().to_string();
    let units: Vec<u16> = clean.encode_utf16().collect();
    if units.len() > 200 {
        format!("{}…", String::from_utf16_lossy(&units[..200]).trim_end())
    } else {
        clean
    }
}

/// `readAnswer`: `{"to", "changed"}` from what `cc-secure reseal` printed or an agent answered.
fn read_answer(v: &Value) -> Option<(String, bool)> {
    let o = match v {
        Value::String(s) => {
            let line = s.split('\n').map(str::trim).rfind(|l| l.starts_with('{'))?;
            serde_json::from_str::<Value>(line).ok()?
        }
        other => other.clone(),
    };
    let to = o.get("to")?.as_str().filter(|t| TAG.is_match(t))?;
    Some((to.to_string(), o.get("changed")?.as_bool()?))
}

fn boxes(n: usize) -> String {
    if n == 1 { "1 box".into() } else { format!("{n} boxes") }
}

/// "14 October", in UTC.
fn day(ms: f64) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let iso = super::consent::iso(ms as u64);
    let month: usize = iso.get(5..7).and_then(|m| m.parse().ok()).unwrap_or(1);
    let d: u32 = iso.get(8..10).and_then(|d| d.parse().ok()).unwrap_or(1);
    format!("{d} {}", MONTHS[month.clamp(1, 12) - 1])
}

fn list(names: &[String]) -> String {
    match names {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn dropped_words(why: &str) -> &'static str {
    match why {
        "deleted" => "deleted",
        "silent" => "not reached for a week",
        _ => "refusing for a week",
    }
}

/// The recovery key this firewall holds.
#[derive(Debug, Clone)]
pub struct Target {
    pub public_key: String,
    pub fingerprint: String,
    /// Taken without a code: moves no disk.
    pub tofu: bool,
}

#[derive(Debug, Clone)]
pub struct Listed {
    pub vm_id: String,
    pub hostname: String,
    pub name: String,
}

pub type TargetFn = Arc<dyn Fn() -> Option<Target> + Send + Sync>;
pub type ListedFn = Arc<dyn Fn() -> Vec<Listed> + Send + Sync>;
/// `(vmId, hostname)` of every pin; `None` when the pins could not be read.
pub type PinnedFn = Arc<dyn Fn() -> Option<Vec<(String, String)>> + Send + Sync>;
pub type SyncedFn = Arc<dyn Fn() -> bool + Send + Sync>;

struct Inner {
    path: PathBuf,
    box_key: String,
    aad: String,
    store: Mutex<Store>,
    agent: AgentClient,
    kit: Kit,
    runner: Arc<dyn Runner>,
    target: TargetFn,
    listed: ListedFn,
    pinned: PinnedFn,
    synced: SyncedFn,
    running: tokio::sync::Mutex<()>,
    again: AtomicBool,
}

#[derive(Clone)]
pub struct DiskReseal(Arc<Inner>);

impl DiskReseal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        path: PathBuf,
        box_key: &str,
        org: &str,
        box_id: &str,
        agent: AgentClient,
        kit: Kit,
        runner: Arc<dyn Runner>,
        target: TargetFn,
        listed: ListedFn,
        pinned: PinnedFn,
        synced: SyncedFn,
    ) -> Self {
        let aad = format!("{org}:{box_id}:disk-reseal");
        let log = |l: &str| tracing::info!("{l}");
        let loaded = cc_crypto::enc_file::load_store_or_empty("disk-reseal", &path, box_key, &aad, &log);
        let store = match loaded {
            Some(v)
                if v.get("version").and_then(Value::as_f64) == Some(1.0)
                    && v.get("known").is_some_and(Value::is_object) =>
            {
                // `{...empty(), ...loaded}`: what is missing takes the empty value.
                let mut base = serde_json::to_value(Store::default()).expect("a store serializes");
                if let (Some(b), Some(l)) = (base.as_object_mut(), v.as_object()) {
                    for (k, x) in l {
                        b.insert(k.clone(), x.clone());
                    }
                }
                match serde_json::from_value::<Store>(base.clone()) {
                    Ok(mut s) => {
                        s.known = dict(std::mem::take(&mut s.known));
                        s.agents = dict(std::mem::take(&mut s.agents));
                        s
                    }
                    // Field by field, as the TS takes the object as it is: one entry this build
                    // cannot read is left out, never the whole record.
                    Err(_) => lenient(base.as_object().cloned().unwrap_or_default()),
                }
            }
            _ => Store::default(),
        };
        let me = Self(Arc::new(Inner {
            path,
            box_key: box_key.into(),
            aad,
            store: Mutex::new(store),
            agent,
            kit,
            runner,
            target,
            listed,
            pinned,
            synced,
            running: tokio::sync::Mutex::new(()),
            again: AtomicBool::new(false),
        }));
        if cc_crypto::store_health::is_store_unreadable("disk-reseal") {
            me.note_lost("its record of agents could not be read");
        }
        me
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let s = self.st();
        self.save(&s);
    }

    fn st(&self) -> std::sync::MutexGuard<'_, Store> {
        self.0.store.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, s: &Store) {
        let v = serde_json::to_value(s).unwrap_or(Value::Null);
        if let Err(e) = cc_crypto::enc_file::save_store("disk-reseal", &self.0.path, &v, &self.0.box_key, &self.0.aad) {
            tracing::error!("[disk-reseal] could not save the store: {e}");
        }
    }

    fn listed(&self) -> Vec<Listed> {
        (self.0.listed)()
            .into_iter()
            .filter(|a| VM_ID.is_match(&a.vm_id))
            .collect()
    }

    fn pins(&self) -> Option<Vec<(String, String)>> {
        match (self.0.pinned)() {
            None => {
                self.note_lost("its pinned agents could not be read");
                None
            }
            Some(p) => Some(p.into_iter().filter(|(v, _)| VM_ID.is_match(v)).collect()),
        }
    }

    fn note_lost(&self, why: &str) {
        let mut s = self.st();
        if s.lost {
            return;
        }
        s.lost = true;
        self.save(&s);
        tracing::info!("[disk-reseal] {why}; from now on no round says every box is sealed");
    }

    fn begin(&self, tag: &str, origin: &str) {
        let pins = self.pins();
        let mut s = self.st();
        let previous = s.target.clone().or(s.previous.clone());
        let keep_self = s.self_box.clone().filter(|b| b.state == "none");
        *s = Store {
            known: std::mem::take(&mut s.known),
            lost: s.lost,
            target: Some(tag.into()),
            previous: if previous.as_deref() != Some(tag) {
                previous
            } else {
                s.previous.clone()
            },
            started_at: now_ms() as f64,
            origin: origin.into(),
            outbox: std::mem::take(&mut s.outbox),
            self_box: keep_self,
            extra: std::mem::take(&mut s.extra),
            ..Store::default()
        };
        Self::learn_pins(&mut s, pins.as_deref());
        let ids: Vec<String> = s.known.keys().cloned().collect();
        for vm in ids {
            s.agents.insert(vm, ResealBox::new("off", 0));
        }
        self.save(&s);
        tracing::info!(
            "[disk-reseal] moving every box's disk seal to the recovery key {tag}: {} agent(s) on the roster{}",
            s.agents.len(),
            if origin == "found" {
                " (found boxes that may be behind)"
            } else {
                ""
            }
        );
    }

    fn learn_pins(s: &mut Store, pins: Option<&[(String, String)]>) {
        for (vm, host) in pins.unwrap_or_default() {
            let first = host
                .split('.')
                .next()
                .filter(|l| !l.is_empty())
                .unwrap_or(vm)
                .to_string();
            Self::know(s, vm, host, &first);
        }
    }

    /// Add an agent to the record, and to the round when one is open. Never removes one.
    fn know(s: &mut Store, vm: &str, hostname: &str, name: &str) {
        if !s.known.contains_key(vm) {
            s.known.insert(
                vm.into(),
                Known {
                    name: name.into(),
                    host: hostname.to_lowercase(),
                    ..Default::default()
                },
            );
            tracing::info!("[disk-reseal] {name} ({vm}) is on the record of agents");
        }
        if s.target.is_some() && !s.agents.contains_key(vm) {
            s.agents.insert(vm.into(), ResealBox::new("off", 0));
        }
    }

    fn enroll(s: &mut Store, listed: &[Listed], pins: Option<&[(String, String)]>) {
        for a in listed {
            let pin = pins
                .and_then(|p| p.iter().find(|(v, _)| *v == a.vm_id))
                .map(|(_, h)| h.clone());
            Self::know(s, &a.vm_id, &pin.unwrap_or_else(|| a.hostname.clone()), &a.name);
            if let Some(k) = s.known.get_mut(&a.vm_id) {
                k.name = a.name.clone();
                k.dropped = None;
            }
            if s.agents.get(&a.vm_id).is_some_and(|b| b.dropped.is_some()) {
                s.agents.insert(a.vm_id.clone(), ResealBox::new("off", 0));
            }
        }
    }

    /// How many boxes a replacement would seal again, for the code message.
    pub fn count(&self) -> usize {
        let listed = self.listed();
        let pins = self.pins().unwrap_or_default();
        let s = self.st();
        let mut ids: Vec<String> = listed.into_iter().map(|a| a.vm_id).collect();
        for (vm, k) in &s.known {
            if k.dropped.is_none() {
                ids.push(vm.clone());
            }
        }
        for (vm, _) in pins {
            if s.known.get(&vm).is_none_or(|k| k.dropped.is_none()) {
                ids.push(vm);
            }
        }
        ids.sort();
        ids.dedup();
        ids.len()
            + if s.self_box.as_ref().is_some_and(|b| b.state == "none") {
                0
            } else {
                1
            }
    }

    /// `report`: names of keys and states of boxes, on every beat.
    pub fn report(&self) -> Value {
        let t = (self.0.target)();
        let confirmed = t.as_ref().is_some_and(|t| !t.tofu);
        let s = self.st();
        let live = confirmed && s.target.as_deref() == t.as_ref().map(|t| recovery_key_tag(&t.public_key)).as_deref();
        let self_report = s.self_box.as_ref().filter(|_| live).map(|b| {
            let mut m = Map::new();
            m.insert("state".into(), json!(b.state));
            b.extras(&mut m);
            Value::Object(m)
        });
        let agents: Vec<Value> = if live {
            s.agents
                .iter()
                .map(|(vm, b)| {
                    let mut m = Map::new();
                    m.insert("vmId".into(), json!(vm));
                    m.insert("state".into(), json!(b.state));
                    b.extras(&mut m);
                    m.insert("at".into(), super::ingress::num(b.at));
                    Value::Object(m)
                })
                .collect()
        } else {
            Vec::new()
        };
        json!({
            "confirmed": confirmed,
            "target": if live { s.target.clone() } else { None },
            "fingerprint": t.map(|t| t.fingerprint),
            "self": self_report,
            "agents": agents,
        })
    }

    /// One pass over every box; a call while one runs makes it run once more, and waits for it.
    pub async fn tick(&self) {
        self.0.again.store(true, Ordering::SeqCst);
        // A caller that finds a pass running waits for it, then runs what it asked for itself
        // when that pass had already finished its last check of `again`.
        let _one = match self.0.running.try_lock() {
            Ok(g) => g,
            Err(_) => self.0.running.lock().await,
        };
        while self.0.again.swap(false, Ordering::SeqCst) {
            if let Err(e) = self.run().await {
                tracing::info!("[disk-reseal] pass failed: {e}");
            }
        }
    }

    fn target_is(&self, tag: &str) -> bool {
        self.st().target.as_deref() == Some(tag)
    }

    async fn run(&self) -> Result<(), String> {
        let Some(t) = (self.0.target)().filter(|t| !t.tofu) else {
            // Not confirmed with a code: no disk moves, and an earlier round stops.
            {
                let mut s = self.st();
                if s.target.is_some() {
                    let keep_self = s.self_box.clone().filter(|b| b.state == "none");
                    *s = Store {
                        known: std::mem::take(&mut s.known),
                        lost: s.lost,
                        previous: s.target.take(),
                        outbox: std::mem::take(&mut s.outbox),
                        self_box: keep_self,
                        extra: std::mem::take(&mut s.extra),
                        ..Store::default()
                    };
                    self.save(&s);
                }
            }
            self.pins();
            self.flush().await;
            return Ok(());
        };
        let tag = recovery_key_tag(&t.public_key);
        if !self.target_is(&tag) {
            self.begin(&tag, "found");
        }
        self.seal_self(&t.public_key, &tag).await;
        if !self.target_is(&tag) {
            return Ok(());
        }
        let pins = self.pins();
        let listed = self.listed();
        let roster: Vec<(String, ResealBox)> = {
            let mut s = self.st();
            Self::learn_pins(&mut s, pins.as_deref());
            Self::enroll(&mut s, &listed, pins.as_deref());
            self.save(&s);
            s.agents.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        for (vm, b) in roster {
            if !self.target_is(&tag) {
                return Ok(());
            }
            if b.dropped.is_some() {
                continue;
            }
            let (host, name) = {
                let s = self.st();
                let k = s.known.get(&vm);
                (
                    k.map(|k| k.host.clone()).unwrap_or_default(),
                    k.map(|k| k.name.clone()).unwrap_or_else(|| vm.clone()),
                )
            };
            self.seal_agent(&vm, &host, &name, &t.public_key, &tag).await;
        }
        if !self.target_is(&tag) {
            return Ok(());
        }
        // Before the list was read since start it is empty, not short.
        if (self.0.synced)() {
            self.end_waits(&listed);
            self.announce(&t.fingerprint);
        }
        self.flush().await;
        Ok(())
    }

    fn due(b: Option<&ResealBox>) -> bool {
        match b {
            None => true,
            Some(b) if b.state == "none" => false,
            Some(b) => b.state != "done" || now_ms() as f64 - b.at >= RESEAL_RECHECK_MS as f64,
        }
    }

    async fn seal_self(&self, public_key: &str, tag: &str) {
        let before = self.st().self_box.clone();
        if !Self::due(before.as_ref()) {
            return;
        }
        let moved = before.as_ref().is_some_and(ResealBox::moved);
        let now = now_ms();
        let cmd = Cmd::new("sudo")
            .args(["-n", "/usr/local/bin/cc-secure", "reseal", public_key])
            .timeout(Duration::from_secs(150));
        let mut next = match self.0.runner.run(cmd).await {
            Ok(o) if o.success() => match read_answer(&Value::String(o.stdout_str())) {
                Some((to, changed)) if to == tag => {
                    if changed {
                        tracing::info!("[disk-reseal] this firewall's disk is sealed to {tag}");
                    }
                    ResealBox {
                        moved: Some(moved || changed),
                        ..ResealBox::new("done", now)
                    }
                }
                _ => ResealBox {
                    message: Some("This firewall did not say which recovery key its disk is sealed to now.".into()),
                    moved: Some(moved),
                    ..ResealBox::new("failed", now)
                },
            },
            // The helper or sudo is not there: a firewall with no encrypted disk.
            Err(_) => ResealBox::new("none", now),
            Ok(o) => {
                let stderr = o.stderr_str();
                let text = format!("{stderr}\nCommand failed: sudo -n /usr/local/bin/cc-secure reseal {public_key}");
                let said = stderr
                    .split('\n')
                    .map(str::trim)
                    .rfind(|l| l.starts_with("cc-secure: "))
                    .map(str::to_string);
                if NOT_OPEN.is_match(&text) {
                    ResealBox {
                        moved: Some(moved),
                        ..ResealBox::new("locked", now)
                    }
                } else if NO_DISK.is_match(&text) {
                    ResealBox::new("none", now)
                } else if NO_HELPER.is_match(&text) {
                    if MISSING.is_match(&text) {
                        ResealBox::new("none", now)
                    } else {
                        ResealBox {
                            moved: Some(moved),
                            ..ResealBox::new("update", now)
                        }
                    }
                } else {
                    let m = said
                        .map(|s| s["cc-secure: ".len()..].to_string())
                        .unwrap_or_else(|| "The seal could not be written.".into());
                    ResealBox {
                        message: Some(brief(&m)),
                        moved: Some(moved),
                        ..ResealBox::new("failed", now)
                    }
                }
            }
        };
        if next.moved == Some(false) {
            next.moved = None;
        }
        if before.as_ref().map(|b| &b.state) != Some(&next.state) && next.state != "done" {
            tracing::info!(
                "[disk-reseal] this firewall's disk: {}{}",
                next.state,
                next.message.as_ref().map(|m| format!(" ({m})")).unwrap_or_default()
            );
        }
        let mut s = self.st();
        // A second replacement confirmed meanwhile: this answer is about the old key.
        if s.target.as_deref() != Some(tag) {
            return;
        }
        s.self_box = Some(next);
        self.save(&s);
    }

    async fn seal_agent(&self, vm: &str, host: &str, name: &str, public_key: &str, tag: &str) {
        let before = self.st().agents.get(vm).cloned();
        if !Self::due(before.as_ref()) {
            return;
        }
        let moved = before.as_ref().is_some_and(ResealBox::moved);
        let now = now_ms();
        let target = AgentTarget::new(vm, host);
        let mut answer = None;
        let mut next = match self
            .0
            .agent
            .post(&target, "/disk/reseal", &json!({"publicKey": public_key}))
            .await
        {
            Ok(r) => {
                answer = read_answer(&Value::Object(r));
                match &answer {
                    Some((to, changed)) if to == tag => {
                        if *changed {
                            tracing::info!("[disk-reseal] {name}: sealed to {tag}");
                        }
                        ResealBox {
                            moved: Some(moved || *changed),
                            ..ResealBox::new("done", now)
                        }
                    }
                    _ => ResealBox {
                        message: Some("The box did not say which recovery key its disk is sealed to now.".into()),
                        moved: Some(moved),
                        ..ResealBox::new("failed", now)
                    },
                }
            }
            Err(e) => {
                let (state, message) = refusal(&e);
                let b = ResealBox {
                    message,
                    moved: Some(moved),
                    ..ResealBox::new(&state, now)
                };
                if before.as_ref().map(|x| &x.state) != Some(&b.state) {
                    tracing::info!(
                        "[disk-reseal] {name}: {}{}",
                        b.state,
                        b.message.as_ref().map(|m| format!(" ({m})")).unwrap_or_default()
                    );
                }
                b
            }
        };
        if next.moved == Some(false) {
            next.moved = None;
        }
        let mut s = self.st();
        if s.target.as_deref() != Some(tag) {
            return;
        }
        // How long the list has been without it is not an answer's to reset.
        next.absent_since = before.and_then(|b| b.absent_since);
        s.agents.insert(vm.into(), next);
        if let (Some((to, _)), Some(k)) = (answer, s.known.get_mut(vm)) {
            k.sealed_to = Some(to);
            k.sealed_at = Some(now as f64);
        }
        self.save(&s);
    }

    /// `endWaits`: only an agent the list no longer has, and only one that has not answered as itself.
    fn end_waits(&self, listed: &[Listed]) {
        let now = now_ms() as f64;
        let mut s = self.st();
        let mut changed = false;
        let ids: Vec<String> = s.agents.keys().cloned().collect();
        for vm in ids {
            let Some(mut b) = s.agents.get(&vm).cloned() else {
                continue;
            };
            if b.dropped.is_some() {
                continue;
            }
            if listed.iter().any(|a| a.vm_id == vm) {
                if b.absent_since.take().is_some() {
                    s.agents.insert(vm, b);
                    changed = true;
                }
                continue;
            }
            if b.absent_since.is_none() {
                b.absent_since = Some(now);
                changed = true;
            }
            let since = b.absent_since.unwrap_or(now);
            if b.state != "off" && b.state != "update" {
                s.agents.insert(vm, b);
                continue;
            }
            let k = s.known.get(&vm).cloned();
            // The list's address owner: the last entry with that host wins, as `new Map` keeps it.
            let host = k.as_ref().map(|k| k.host.clone()).unwrap_or_default();
            let taken = listed
                .iter()
                .rev()
                .find(|a| a.hostname.to_lowercase() == host)
                .map(|a| a.vm_id.clone());
            let why = if taken.as_ref().is_some_and(|t| *t != vm) {
                "deleted".to_string()
            } else if let Some(d) = k.as_ref().and_then(|k| k.dropped.clone()) {
                d.why
            } else if now - since >= RESEAL_ABSENT_MS as f64 {
                if b.state == "off" {
                    "silent".into()
                } else {
                    "refused".into()
                }
            } else {
                s.agents.insert(vm, b);
                continue;
            };
            b.dropped = Some(why.clone());
            s.agents.insert(vm.clone(), b);
            if let Some(k) = s.known.get_mut(&vm)
                && k.dropped.as_ref().map(|d| &d.why) != Some(&why)
            {
                k.dropped = Some(Dropped {
                    why: why.clone(),
                    at: now,
                });
            }
            changed = true;
            let name = k.map(|k| k.name).unwrap_or_else(|| vm.clone());
            tracing::info!(
                "[disk-reseal] {name} ({vm}) is not sealed and is not waited for any more: {}",
                dropped_words(&why)
            );
        }
        if changed {
            self.save(&s);
        }
    }

    fn confirmed(s: &Store, vm: &str) -> bool {
        s.known.get(vm).is_some_and(|k| {
            k.sealed_to.is_some() && k.sealed_to == s.target && k.sealed_at.unwrap_or(0.0) >= s.started_at
        })
    }

    fn describe(s: &Store, vm: &str) -> String {
        let k = s.known.get(vm);
        let when = match k.and_then(|k| k.dropped.as_ref()) {
            Some(d) => format!("dropped as {} on {}", dropped_words(&d.why), day(d.at)),
            None => "not sealed".into(),
        };
        let seal = match k.and_then(|k| k.sealed_to.as_ref()) {
            None => "its seal was never confirmed",
            Some(t) if Some(t) == s.previous.as_ref() => "last sealed to the previous key",
            Some(_) => "last sealed to an older key",
        };
        format!(
            "{} ({when}; {seal})",
            k.map(|k| k.name.clone()).unwrap_or_else(|| vm.to_string())
        )
    }

    /// `announce`: computed from the record against the round's key, nothing else.
    fn announce(&self, fingerprint: &str) {
        let mut s = self.st();
        let selfs: Vec<ResealBox> = s.self_box.clone().filter(|b| b.state != "none").into_iter().collect();
        let agents: Vec<String> = s.agents.keys().cloned().collect();
        let not_sealed: Vec<String> = agents.iter().filter(|v| !Self::confirmed(&s, v)).cloned().collect();
        let sealed = selfs.iter().filter(|b| b.state == "done").count() + (agents.len() - not_sealed.len());
        let total = selfs.len() + agents.len();
        let moved = selfs
            .iter()
            .chain(agents.iter().filter_map(|v| s.agents.get(v)))
            .filter(|b| b.moved())
            .count();
        if moved == 0 && s.origin == "found" {
            return;
        }
        let closed = selfs.iter().all(|b| b.state == "done")
            && not_sealed
                .iter()
                .all(|v| s.agents.get(v).is_some_and(|b| b.dropped.is_some()));
        let now = now_ms() as f64;
        if closed && !s.said_done {
            let unknown = s.lost;
            let text = if not_sealed.is_empty() && !unknown {
                if moved == 0 {
                    return;
                }
                if s.origin == "found" && !s.said_started {
                    format!(
                        "ControlClaw: your firewall sealed the disks of {} to your current recovery key ({fingerprint}). They were still sealed to an earlier key. Your current key now opens all {total} of your boxes.",
                        boxes(moved)
                    )
                } else {
                    format!(
                        "ControlClaw: the {} now sealed to your recovery key ({fingerprint}). You no longer need the previous key to open them.",
                        if total == 1 {
                            "disk of your 1 box is".to_string()
                        } else {
                            format!("disks of all {total} of your boxes are")
                        }
                    )
                }
            } else if not_sealed.is_empty() {
                format!(
                    "ControlClaw: the disks of all {} this firewall knows of are sealed to your recovery key ({fingerprint}). It could not read its own record of agents at some point, so there may be others. Keep your previous key if you may still need one of them.",
                    boxes(total)
                )
            } else {
                let on_previous = not_sealed
                    .iter()
                    .all(|v| s.known.get(v).and_then(|k| k.sealed_to.clone()) == s.previous);
                let deleted: Vec<String> = not_sealed
                    .iter()
                    .filter(|v| s.agents.get(*v).and_then(|b| b.dropped.as_deref()) == Some("deleted"))
                    .cloned()
                    .collect();
                let mut parts = vec![
                    format!("ControlClaw: {sealed} of {total} boxes are sealed to your recovery key ({fingerprint})."),
                    format!(
                        "Not sealed: {}.",
                        not_sealed
                            .iter()
                            .map(|v| Self::describe(&s, v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    format!(
                        "Keep your {} if you may still need {}.",
                        if on_previous { "previous key" } else { "earlier keys" },
                        if not_sealed.len() == 1 {
                            "that box"
                        } else {
                            "those boxes"
                        }
                    ),
                ];
                if deleted.len() == not_sealed.len() {
                    parts.push(format!(
                        "If {} really deleted, you no longer need {}.",
                        if deleted.len() == 1 {
                            "this box is"
                        } else {
                            "these boxes are"
                        },
                        if on_previous {
                            "the previous key".to_string()
                        } else {
                            format!("an earlier key for {}", if deleted.len() == 1 { "it" } else { "them" })
                        }
                    ));
                } else if !deleted.is_empty() {
                    let names: Vec<String> = deleted
                        .iter()
                        .map(|v| s.known.get(v).map(|k| k.name.clone()).unwrap_or_else(|| v.clone()))
                        .collect();
                    parts.push(format!(
                        "The console says {} {} deleted.",
                        list(&names),
                        if deleted.len() == 1 { "was" } else { "were" }
                    ));
                }
                if unknown {
                    parts.push("This firewall could not read its own record of agents at some point, so there may be others too.".into());
                }
                parts.join(" ")
            };
            s.outbox.push(Message { text, at: now });
            s.said_done = true;
            s.said_started = true;
            self.save(&s);
            return;
        }
        if !closed && s.origin == "found" && !s.said_started {
            let waiting = total - sealed;
            let text = format!(
                "ControlClaw: your firewall is sealing the disks of your boxes to your current recovery key ({fingerprint}). Some were still sealed to an earlier key. {} not done yet; keep the earlier key until your console shows every box on the current one.",
                if waiting == 1 {
                    "1 box is".to_string()
                } else {
                    format!("{waiting} boxes are")
                }
            );
            s.outbox.push(Message { text, at: now });
            s.said_started = true;
            self.save(&s);
        }
    }

    async fn flush(&self) {
        let waiting = self.st().outbox.clone();
        if waiting.is_empty() {
            return;
        }
        let cutoff = now_ms().saturating_sub(MESSAGE_TTL_MS) as f64;
        let mut gone = Vec::new();
        for m in waiting {
            if m.at < cutoff || self.deliver(&m.text).await {
                gone.push(m);
            }
        }
        if !gone.is_empty() {
            let mut s = self.st();
            s.outbox.retain(|m| !gone.contains(m));
            self.save(&s);
        }
    }

    async fn deliver(&self, text: &str) -> bool {
        for route in self.0.kit.routes().unwrap_or_default() {
            for sender in &route.senders {
                let CodeSender::Person { kind, id, .. } = sender else {
                    continue;
                };
                remember_own(text);
                let body = json!({"type": kind, "to": id, "text": text});
                if self
                    .0
                    .agent
                    .post(
                        &AgentTarget::new(&route.vm_id, &route.hostname),
                        "/channels/send",
                        &body,
                    )
                    .await
                    .is_ok()
                {
                    return true;
                }
            }
        }
        false
    }
}

/// What an agent's "no" means. Anything that is not an answer from its vm-agent is `off`.
fn refusal(e: &AgentError) -> (String, Option<String>) {
    let AgentError::Status { status, message } = e else {
        return ("off".into(), None);
    };
    let said = message.strip_prefix(&format!("agent {status}: ")).map(str::to_string);
    let Some(said) = said else { return ("off".into(), None) };
    if *status == 409 && NOT_OPEN.is_match(&said) {
        return ("locked".into(), None);
    }
    if *status == 409 && BUSY.is_match(&said) {
        return ("failed".into(), Some("The box was busy. It is asked again.".into()));
    }
    if [409, 404, 401, 403].contains(status) {
        return ("update".into(), None);
    }
    if *status >= 502 {
        return ("off".into(), None);
    }
    ("failed".into(), Some(brief(&said)))
}

impl super::backup::Reseal for DiskReseal {
    fn count(&self) -> usize {
        DiskReseal::count(self)
    }

    /// Written at once, before any box is called.
    fn replaced(&self, public_key: &str) {
        self.begin(&recovery_key_tag(public_key), "replacement");
        let me = self.clone();
        tokio::spawn(async move { me.tick().await });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_parts() {
        assert_eq!(
            recovery_key_tag("E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20=").len(),
            "sha256:".len() + 16
        );
        assert_eq!(
            read_answer(&json!("noise\n{\"to\":\"sha256:0123456789abcdef\",\"changed\":true}\n")),
            Some(("sha256:0123456789abcdef".into(), true))
        );
        assert_eq!(read_answer(&json!({"to": "x", "changed": true})), None);
        assert_eq!(day(1_792_000_000_000.0), "14 October");
        assert_eq!(list(&["a".into(), "b".into(), "c".into()]), "a, b and c");
        assert_eq!(brief("a\u{1}\u{2}b"), "a b");
        let e = AgentError::Status {
            status: 409,
            message: "agent 409: The disk is not open".into(),
        };
        assert_eq!(refusal(&e).0, "locked");
        assert_eq!(
            refusal(&AgentError::Status {
                status: 404,
                message: "agent 404: Not found".into()
            })
            .0,
            "update"
        );
        assert_eq!(
            refusal(&AgentError::Status {
                status: 503,
                message: "agent 503: x".into()
            })
            .0,
            "off"
        );
        assert_eq!(refusal(&AgentError::Timeout).0, "off");
    }

    #[test]
    fn one_odd_entry_leaves_the_rest() {
        let v = json!({"version": 1, "known": {"cm1": {"name": "a", "host": "a.example"}, "cm2": {"host": "x"}}, "agents": {"cm1": {"state": "done", "at": 1.0}}, "target": "sha256:0006bb1c1b76749b", "previous": null, "startedAt": 5.0, "origin": "replacement", "lost": false, "self": null, "saidStarted": true, "saidDone": false, "outbox": [{"text": "hi", "at": 1.0}, {"bad": 1}]});
        let s = lenient(v.as_object().cloned().expect("o"));
        assert_eq!(s.known.keys().collect::<Vec<_>>(), vec!["cm1"]);
        assert!(s.lost, "an entry left out marks the record lost");
        assert_eq!(s.target.as_deref(), Some("sha256:0006bb1c1b76749b"));
        assert_eq!(s.outbox.len(), 1);
        assert!(s.said_started);
    }

    #[test]
    fn store_round_trips_in_the_ts_shape() {
        let mut s = Store::default();
        s.known.insert(
            "vm_1".into(),
            Known {
                name: "atlas".into(),
                host: "atlas.example".into(),
                ..Default::default()
            },
        );
        s.agents.insert("vm_1".into(), ResealBox::new("off", 0));
        let v = serde_json::to_value(&s).expect("json");
        assert_eq!(v["agents"]["vm_1"], json!({"state": "off", "at": 0.0}));
        assert!(v.get("self").is_some() && v.get("startedAt").is_some() && v.get("saidDone").is_some());
        let back: Store = serde_json::from_value(v).expect("back");
        assert_eq!(back.known.len(), 1);
    }
}
