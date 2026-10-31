//! Updating every box on one code (`update-all.ts`, `update-all-store.ts`, T-100). The summary
//! names every box, the set is frozen when the code goes out, and each box keeps its own rule (no
//! first use for the firewall). A confirmed batch writes a grant on disk, because the firewall's
//! own update restarts this process: the listed boxes, once each, for two and a half hours.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::{Map, Value, json};

use super::agent_client::AgentTarget;
use super::code_message::{CodeParts, Details};
use super::consent::{iso, no_recipients};
use super::firewall_update::FirewallUpdate;
use super::identities::Agents;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use super::update::{RunOptions, Updates};
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE: &str = "update-all:org";
/// How long a confirmed batch stays spendable: longer than one box's hour, because the console
/// runs the agents in waves and calls a batch abandoned only after 105 minutes.
pub const BATCH_GRANT_MS: u64 = 150 * 60_000;

// ---- the grant (`update-all-store.ts`) ----

#[derive(Debug, Clone, PartialEq)]
struct Grant {
    auto: bool,
    change_id: String,
    /// Epoch ms; past it the grant authorises nothing.
    until: f64,
    pending: Vec<String>,
    used: Vec<String>,
    at: String,
}

impl Grant {
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        if self.auto {
            m.insert("mode".into(), json!("auto"));
        }
        m.insert("changeId".into(), json!(self.change_id));
        m.insert("until".into(), super::ingress::num(self.until));
        m.insert("pending".into(), json!(self.pending));
        m.insert("used".into(), json!(self.used));
        m.insert("at".into(), json!(self.at));
        Value::Object(m)
    }
    fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let list = |k: &str| -> Vec<String> {
            o.get(k)
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default()
        };
        Some(Self {
            auto: o.get("mode").and_then(Value::as_str) == Some("auto"),
            change_id: o.get("changeId")?.as_str()?.to_string(),
            until: o.get("until")?.as_f64()?,
            pending: list("pending"),
            used: list("used"),
            at: o.get("at").and_then(Value::as_str).unwrap_or_default().to_string(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefusal {
    NoGrant,
    WrongBatch,
    NotListed,
    AlreadyUsed,
}

impl ClaimRefusal {
    fn message(self) -> &'static str {
        match self {
            Self::NoGrant => "Your firewall no longer has a confirmed batch. Start the update again.",
            Self::WrongBatch => "That code confirmed a different batch. Start the update again.",
            Self::NotListed => "That box was not in the batch you confirmed.",
            Self::AlreadyUsed => "That box has already been started by this batch.",
        }
    }
}

/// `UpdateAllStoreFile`: fails closed, an unreadable store is no grant.
pub struct GrantStore {
    path: PathBuf,
    box_key: String,
    aad: String,
    grant: Mutex<Option<Grant>>,
}

impl GrantStore {
    pub fn new(path: PathBuf, box_key: &str, org: &str, box_id: &str) -> Self {
        let aad = format!("{org}:{box_id}:update-all");
        let log = |l: &str| tracing::error!("{l}");
        let grant = match cc_crypto::enc_file::load_store_or_empty("update-all", &path, box_key, &aad, &log) {
            // A store from a newer build is not something to guess at.
            Some(v) if v.get("version").and_then(Value::as_f64) == Some(1.0) => {
                v.get("grant").and_then(Grant::from_json)
            }
            _ => None,
        };
        Self {
            path,
            box_key: box_key.into(),
            aad,
            grant: Mutex::new(grant),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let g = self.g();
        self.save(&g).expect("save");
    }

    fn g(&self) -> std::sync::MutexGuard<'_, Option<Grant>> {
        self.grant.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A write that fails fails the command, as `saveStore` throwing does.
    fn save(&self, g: &Option<Grant>) -> Result<(), String> {
        let v = json!({"version": 1, "grant": g.as_ref().map(Grant::to_json)});
        cc_crypto::enc_file::save_store("update-all", &self.path, &v, &self.box_key, &self.aad).map_err(|e| e.0)
    }

    fn live(g: &Option<Grant>, now: u64) -> Option<&Grant> {
        g.as_ref().filter(|g| g.until > now as f64)
    }

    fn grant(&self, now: u64) -> Option<Grant> {
        Self::live(&self.g(), now).cloned()
    }

    fn put(&self, grant: Grant) -> Result<(), String> {
        let mut g = self.g();
        *g = Some(grant);
        self.save(&g)
    }

    /// Take one box out of the grant, written before the caller starts anything.
    /// `Err(message)`: a refusal, or a write that failed after the box was taken out.
    pub fn claim(&self, change_id: &str, vm_id: &str, now: u64) -> Result<(), String> {
        let mut g = self.g();
        let Some(live) = Self::live(&g, now) else {
            return Err(ClaimRefusal::NoGrant.message().into());
        };
        let refusal = if live.change_id != change_id {
            Some(ClaimRefusal::WrongBatch)
        } else if live.used.iter().any(|v| v == vm_id) {
            Some(ClaimRefusal::AlreadyUsed)
        } else if !live.pending.iter().any(|v| v == vm_id) {
            Some(ClaimRefusal::NotListed)
        } else {
            None
        };
        if let Some(r) = refusal {
            return Err(r.message().into());
        }
        if let Some(x) = g.as_mut() {
            x.pending.retain(|v| v != vm_id);
            x.used.push(vm_id.to_string());
        }
        self.save(&g)
    }

    /// Give a claimed box back, for a start that failed before the box did anything.
    pub fn unclaim(&self, change_id: &str, vm_id: &str) {
        let mut g = self.g();
        let Some(x) = g.as_mut().filter(|x| x.change_id == change_id) else {
            return;
        };
        x.used.retain(|v| v != vm_id);
        if !x.pending.iter().any(|v| v == vm_id) {
            x.pending.push(vm_id.to_string());
        }
        if let Err(e) = self.save(&g) {
            tracing::error!("[update-all] could not give {vm_id} back to the batch: {e}");
        }
    }

    pub fn drop_grant(&self, change_id: Option<&str>) -> Result<(), String> {
        let mut g = self.g();
        let Some(x) = g.as_ref() else { return Ok(()) };
        if change_id.is_some_and(|c| c != x.change_id) {
            return Ok(());
        }
        *g = None;
        self.save(&g)
    }

    /// `grant(now)?.mode === "auto"`.
    pub fn auto_grant_live(&self, now: u64) -> bool {
        self.grant(now).is_some_and(|g| g.auto)
    }
}

// ---- the batch ----

#[derive(Debug, Clone)]
struct BatchBox {
    vm_id: String,
    name: String,
    hostname: String,
    role: String,
}

#[derive(Debug, Clone)]
struct Batch {
    change_id: String,
    boxes: Vec<BatchBox>,
}

impl Batch {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id,
            "boxes": self.boxes.iter().map(|b| json!({"vmId": b.vm_id, "name": b.name, "hostname": b.hostname, "role": b.role})).collect::<Vec<_>>(),
        })
    }
    fn vm_ids(&self) -> Vec<String> {
        self.boxes.iter().map(|b| b.vm_id.clone()).collect()
    }
}

fn role_of(v: Option<&Value>) -> &'static str {
    match v.and_then(Value::as_str) {
        Some("mitm") => "mitm",
        Some("gbrain") => "gbrain",
        _ => "openclaw",
    }
}

/// `parseProposal`: a malformed entry fails the whole batch, so the summary describes all of it.
fn parse(p: &Map<String, Value>) -> Result<Batch, String> {
    let bad = || "malformed update-all.propose payload".to_string();
    let change_id = text(p, "changeId");
    let raw = p.get("boxes").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut boxes = Vec::new();
    for entry in &raw {
        let empty = Map::new();
        let b = entry.as_object().unwrap_or(&empty);
        let role = role_of(b.get("role"));
        let hostname = text(b, "hostname").unwrap_or_default();
        let Some(vm_id) = text(b, "vmId") else {
            return Err(bad());
        };
        if role != "mitm" && hostname.is_empty() {
            return Err(bad());
        }
        boxes.push(BatchBox {
            name: text(b, "name").unwrap_or_else(|| vm_id.clone()),
            vm_id,
            hostname,
            role: role.into(),
        });
    }
    let Some(change_id) = change_id.filter(|_| !boxes.is_empty()) else {
        return Err(bad());
    };
    let mut ids = boxes.iter().map(|b| &b.vm_id).collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    if ids.len() != boxes.len() {
        return Err(bad());
    }
    Ok(Batch { change_id, boxes })
}

/// `summarize`: names every box, in the order they run.
pub fn summarize_names(names: &[String]) -> String {
    match names {
        [] => "Update the software on nothing".into(),
        [one] => format!("Update the software on {one}"),
        [rest @ .., last] => format!("Update the software on {} and {last}", rest.join(", ")),
    }
}

fn summarize(p: &Batch) -> String {
    summarize_names(&p.boxes.iter().map(|b| b.name.clone()).collect::<Vec<_>>())
}

pub type AutoGrant = Arc<dyn Fn() -> Option<String> + Send + Sync>;

pub struct UpdateAll {
    kit: Kit,
    agents: Arc<Agents>,
    updates: Arc<Updates>,
    this_box: Arc<FirewallUpdate>,
    pub store: Arc<GrantStore>,
    auto_grant: AutoGrant,
    box_name: String,
}

impl UpdateAll {
    pub fn new(
        kit: Kit,
        agents: Arc<Agents>,
        updates: Arc<Updates>,
        this_box: Arc<FirewallUpdate>,
        store: Arc<GrantStore>,
        auto_grant: AutoGrant,
    ) -> Self {
        Self {
            kit,
            agents,
            updates,
            this_box,
            store,
            auto_grant,
            box_name: "your organization".into(),
        }
    }

    fn grant_for(&self, p: &Batch) -> Result<(), String> {
        let now = now_ms();
        self.store.put(Grant {
            auto: false,
            change_id: p.change_id.clone(),
            until: (now + BATCH_GRANT_MS) as f64,
            pending: p.vm_ids(),
            used: Vec::new(),
            at: iso(now),
        })
    }

    /// `update-all.auto`: a nightly batch under the standing auto-update grant.
    pub fn automatic(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let data = obj(&[("changeId", json!(p.change_id)), ("summary", json!(summarize(&p)))]);
        if (self.auto_grant)().is_none() {
            return fail("failed", "Automatic updates are off.", data);
        }
        let now = now_ms();
        let until = payload
            .get("windowEndsAt")
            .and_then(Value::as_str)
            .and_then(super::ssh::parse_iso_ms);
        let Some(until) = until.filter(|u| *u > now as f64 && *u <= (now + 24 * 60 * 60_000) as f64) else {
            return fail("failed", "The automatic update window has closed or is invalid.", data);
        };
        // A replay cannot refill slots this batch already spent.
        let existing = self.store.grant(now);
        if existing.as_ref().is_some_and(|g| g.change_id != p.change_id) {
            return fail("failed", "Another update batch is active.", data);
        }
        if existing.is_none()
            && let Err(e) = self.store.put(Grant {
                auto: true,
                change_id: p.change_id.clone(),
                until,
                pending: p.vm_ids(),
                used: Vec::new(),
                at: iso(now),
            })
        {
            return CommandOutcome::failed("failed", e);
        }
        ok("applied", data)
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let summary = summarize(&p);
        let includes_self = p.boxes.iter().any(|b| b.role == "mitm");
        let data = obj(&[
            ("changeId", json!(p.change_id)),
            ("summary", json!(summary)),
            ("boxes", json!(p.vm_ids())),
        ]);
        if includes_self && !self.this_box.supported() {
            return fail(
                "failed",
                "This firewall was created before in-place updates; it has to be rebuilt instead. Leave it out of the batch.",
                data,
            );
        }
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            // The firewall has no first use; a batch with it is refused.
            if includes_self {
                let (message, extra) = no_recipients(self.kit.agent_allowed());
                let mut d = data;
                d.extend(extra);
                return fail(
                    "failed",
                    format!("{message} Your firewall cannot be updated until then."),
                    d,
                );
            }
            self.kit.consent.forget(SCOPE);
            if let Err(e) = self.grant_for(&p) {
                return CommandOutcome::failed("failed", e);
            }
            tracing::info!(
                "[update-all] no code recipient: {} agent(s) applied on first use",
                p.boxes.len()
            );
            let mut d = data;
            d.insert("tofu".into(), json!(true));
            return ok("applied", d);
        }
        // Part one lists the boxes by this firewall's own record, all of them or none.
        let names: Vec<Option<String>> = p
            .boxes
            .iter()
            .map(|b| {
                if b.role == "mitm" {
                    Some("your firewall".to_string())
                } else {
                    self.agents.record_name(&b.vm_id)
                }
            })
            .collect();
        let all: Vec<String> = names.iter().flatten().cloned().collect();
        let joined = all.join(", ");
        let parts = (all.len() == names.len() && joined.encode_utf16().count() <= 1200).then(|| CodeParts {
            ask: format!(
                "Update the software on {} {}",
                all.len(),
                if all.len() == 1 { "box" } else { "boxes" }
            ),
            details: Some(Details::Text(format!(
                "{}: {joined}",
                if all.len() == 1 { "It is" } else { "They are" }
            ))),
            ..Default::default()
        });
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: SCOPE.into(),
                change_id: p.change_id.clone(),
                proposal: p.to_json(),
                agent_name: self.box_name.clone(),
                summary,
                routes,
                parts,
                recovery: true,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[update-all] code sent for {} box(es) via {sent_via}", p.boxes.len());
        }
        awaiting(sent, data)
    }

    /// Checks the code and writes the grant; starts nothing.
    pub fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed update-all.confirm payload");
        };
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail("expired", "No update is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().and_then(|o| parse(o).ok()) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                if let Err(e) = self.grant_for(&p) {
                    return CommandOutcome::failed("failed", e);
                }
                tracing::info!("[update-all] confirmed for {} box(es)", p.boxes.len());
                let mut d = data;
                d.insert("summary".into(), json!(summarize(&p)));
                d.insert("sentVia".into(), json!(sent_via));
                d.insert("tofu".into(), json!(false));
                d.insert("boxes".into(), json!(p.vm_ids()));
                ok("applied", d)
            }
        }
    }

    /// `update-all.apply`: one box out of a confirmed batch. The consent check is `claim`.
    pub async fn apply_one(&self, payload: Map<String, Value>) -> CommandOutcome {
        let (Some(change_id), Some(vm_id)) = (text(&payload, "changeId"), text(&payload, "vmId")) else {
            return CommandOutcome::failed("failed", "malformed update-all.apply payload");
        };
        let role = role_of(payload.get("role"));
        let data = obj(&[("changeId", json!(change_id)), ("vmId", json!(vm_id))]);
        let now = now_ms();
        let grant = self.store.grant(now);
        if grant.as_ref().is_some_and(|g| g.auto) && (self.auto_grant)().is_none() {
            return fail("failed", "Automatic updates are off.", data);
        }
        let options = match &grant {
            Some(g) if g.auto => RunOptions {
                auto: true,
                deadline: Some((g.until / 1000.0).floor() as u64),
            },
            _ => RunOptions::default(),
        };
        if let Err(m) = self.store.claim(&change_id, &vm_id, now) {
            return fail("failed", m, data);
        }
        let r: Result<Map<String, Value>, String> = async {
            if role == "mitm" {
                if !self.this_box.supported() {
                    return Err("This firewall has nothing pinned to update from.".to_string());
                }
                let applied = self
                    .this_box
                    .apply_for_batch(options.auto, options.deadline.map(|d| d as f64))?;
                tracing::info!("[update-all] started on this box");
                return Ok(applied);
            }
            let Some(hostname) = text(&payload, "hostname") else {
                return Err("malformed update-all.apply payload".to_string());
            };
            let name = text(&payload, "name").unwrap_or_else(|| vm_id.clone());
            self.updates
                .apply_to_target(&AgentTarget::new(&vm_id, &hostname), &name, &options)
                .await
        }
        .await;
        match r {
            Ok(applied) => {
                let mut d = data;
                d.extend(applied);
                ok("applied", d)
            }
            Err(e) => {
                // Nothing started: the slot goes back for a retry under the same code.
                self.store.unclaim(&change_id, &vm_id);
                fail(
                    "failed",
                    if e.is_empty() {
                        "The box did not start the run.".to_string()
                    } else {
                        e
                    },
                    data,
                )
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        self.kit.consent.cancel(SCOPE, change_id.as_deref());
        if let Err(e) = self.store.drop_grant(change_id.as_deref()) {
            return CommandOutcome::failed("failed", e);
        }
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_parse() {
        assert_eq!(
            summarize_names(&["fw".into(), "a".into(), "b".into()]),
            "Update the software on fw, a and b"
        );
        assert_eq!(summarize_names(&["fw".into()]), "Update the software on fw");
        let p = |v: Value| parse(v.as_object().expect("o"));
        assert!(p(json!({"changeId": "c", "boxes": [{"vmId": "a"}]})).is_err());
        assert!(
            p(json!({"changeId": "c", "boxes": [{"vmId": "a", "role": "mitm"}, {"vmId": "a", "role": "mitm"}]}))
                .is_err()
        );
        assert_eq!(
            p(json!({"changeId": "c", "boxes": [{"vmId": "fw", "role": "mitm"}]}))
                .expect("ok")
                .boxes[0]
                .name,
            "fw"
        );
    }

    #[test]
    fn grants_are_used_once() {
        let dir = tempfile::tempdir().expect("dir");
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let s = GrantStore::new(dir.path().join("u.enc"), key, "o", "b");
        assert_eq!(s.claim("c", "a", 1), Err(ClaimRefusal::NoGrant.message().into()));
        s.put(Grant {
            auto: false,
            change_id: "c".into(),
            until: 1000.0,
            pending: vec!["a".into()],
            used: vec![],
            at: String::new(),
        })
        .expect("put");
        assert_eq!(s.claim("d", "a", 1), Err(ClaimRefusal::WrongBatch.message().into()));
        assert_eq!(s.claim("c", "z", 1), Err(ClaimRefusal::NotListed.message().into()));
        assert_eq!(s.claim("c", "a", 1), Ok(()));
        assert_eq!(s.claim("c", "a", 1), Err(ClaimRefusal::AlreadyUsed.message().into()));
        s.unclaim("c", "a");
        // Read back from disk.
        let again = GrantStore::new(dir.path().join("u.enc"), key, "o", "b");
        assert_eq!(again.claim("c", "a", 1), Ok(()));
        assert_eq!(again.claim("c", "a", 2000), Err(ClaimRefusal::NoGrant.message().into()));
    }
}
