//! The brain on a standalone firewall (docs/standalone/brain.md, docs/plans/standalone-brain.md B):
//! which agents use it and how, the admin's lock, its model, what it did, and a sign-in link to its
//! own pages. The firewall's brain module does the work (`gbrain.*`); a change from the signed-in
//! admin applies with no code, as the other standalone settings.
//!
//! `GET /api/brain` and `GET /api/brain/overview` answer in the shapes the panel's Brain page reads
//! (`PanelBrainView` in `apps/firewall-panel/src/api/brain.ts`, `BrainOverviewView` in
//! `packages/console-ui/src/lib/brain-stats.ts`): change them together.
//!
//! The counts come from the firewall's own record of each agent's call (the tools gate's
//! `/brain/mcp` rows, with the tool's name) and from the brain's `brain_stats` readings when the
//! brain sends them. "Save what it learns automatically" is not here: it needs the
//! `cc-instructions` plugin, which `controlclaw connect` does not install.

use std::collections::{BTreeMap, HashMap};

use http::Method;
use rusqlite::OptionalExtension;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{CommandAnswer, Ctx, Reply, Result, Route, checked, new_id};
use crate::db::{Db, now_s};

const TAG: &str = "brain";
const MODEL_SETTING: &str = "brain_model";
/// The models a brain set up by ControlClaw takes (`MODELS` in `rust/bins/vm-agent/src/gbrain/model.rs`,
/// the brain checks again): id, name, one line.
const MODELS: &[(&str, &str, &str)] = &[
    ("gpt-5.6-luna", "GPT-5.6 Luna", "Enough for most brains."),
    (
        "gpt-5.6-terra",
        "GPT-5.6 Terra",
        "Reads long pages better, about ten times the cost.",
    ),
];
/// The model keys the brain's calls can go out on.
const BRAIN_KEY_PROVIDERS: &[&str] = &["openai", "vercel_gateway"];
const NO_AUTO_SAVE: &str = "Not available on a standalone firewall: it needs the cc-instructions plugin on the agent, which controlclaw connect does not install.";
/// The tools gate's record of an agent's brain call (`integrations/tools_gate.rs`: host
/// `controlplane-mcp`, path `/brain/mcp`), as activity files it.
const BRAIN_CALL_SUMMARY: &str = "%controlplane-mcp/brain/mcp";

/// GBrain's searches and saves. Twin: `SEARCH_OPS` and `SAVE_OPS` in
/// `packages/console-ui/src/lib/brain-stats.ts`; change both together.
pub const SEARCH_OPS: &[&str] = &[
    "search",
    "query",
    "search_by_image",
    "recall",
    "context_pack",
    "find_experts",
    "takes_search",
    "search_exact",
    "find_pages",
    "memory_recall",
    "assemble_evidence",
];
pub const SAVE_OPS: &[&str] = &[
    "put_page",
    "capture",
    "remember",
    "add_link",
    "add_tag",
    "add_timeline_entry",
    "put_raw_data",
    "takes_add",
    "takes_update",
    "takes_supersede",
    "file_upload",
    "append_page",
    "edit_page",
    "put_pages",
    "memory_write",
    "commit_page_upload",
    "memory_propose",
    "confirm_memory",
    "promote_guest_note",
    "ontology_propose",
    "log_ingest",
    "revert_version",
    "takes_resolve",
];

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<(), PanelBrain, _, _>(
            "/api/brain",
            TAG,
            "The brain, whether it answers, its model, the agents that may use it and how, and the locks",
            |c| async move { view(&c).await },
        ),
        Route::get::<(), BrainOverview, _, _>(
            "/api/brain/overview",
            TAG,
            "Searches and saves today and over 30 days, per agent and per hour, the brain's page counts",
            |c| async move { Ok(Reply::ok(&overview(&c.db, now_s())?)) },
        ),
        Route::write::<BrainAgentScope, CommandAnswer, _, _>(
            Method::PUT,
            "/api/brain/agents/:vmId",
            TAG,
            "Switch an agent on the brain, or change what it may do: read, or read and write",
            |c, b| async move { connect(&c, b).await },
        ),
        Route::write::<super::NoBody, CommandAnswer, _, _>(
            Method::DELETE,
            "/api/brain/agents/:vmId",
            TAG,
            "Switch an agent off the brain; its OpenClaw config is left as it was",
            |c, _| async move {
                let vm = c.param("vmId").to_string();
                let p = checked("gbrain.disconnect", json!({"agentVmId": vm}))?;
                Ok(c.command("gbrain.disconnect", Value::Object(p)).await?.reply())
            },
        ),
        Route::write::<BrainLockBody, CommandAnswer, _, _>(
            Method::PUT,
            "/api/brain/lock",
            TAG,
            "Lock every agent out of the brain, or let them back; connections are kept",
            |c, b| async move {
                let p = checked("gbrain.lock", json!({"locked": b.locked}))?;
                Ok(c.command("gbrain.lock", Value::Object(p)).await?.reply())
            },
        ),
        Route::get::<(), CommandAnswer, _, _>(
            "/api/brain/status",
            TAG,
            "Whether the brain answers: GBrain and its database",
            |c| async move { Ok(c.command("gbrain.status", json!({})).await?.reply()) },
        ),
        Route::get::<(), BrainModelView, _, _>(
            "/api/brain/model",
            TAG,
            "The brain's model, and the ones it takes",
            |c| async move { Ok(Reply::ok(&model_view(&c.db)?)) },
        ),
        Route::write::<BrainModelBody, BrainModelView, _, _>(
            Method::PUT,
            "/api/brain/model",
            TAG,
            "Set the brain's model for its own work (the nightly run, rewording searches); it restarts once",
            |c, b| async move { set_model(&c, b).await },
        ),
        Route::write::<BrainPagesBody, BrainPagesView, _, _>(
            Method::PUT,
            "/api/brain/pages",
            TAG,
            "The name the browser reaches the brain's pages at (HTTPS in front of BRAIN_PAGES_BIND); set once",
            |c, b| async move { set_pages(&c, b) },
        ),
        Route::write::<BrainOpenBody, super::panel::OpenLink, _, _>(
            Method::POST,
            "/api/brain/open",
            TAG,
            "A one-time link (60 s) that signs this browser in to the brain's pages, or GBrain's admin page",
            |c, b| async move {
                let page = if b.page == BrainPage::Admin {
                    "brain-admin"
                } else {
                    "brain"
                };
                if brain_row(&c.db)?.and_then(|b| b.hostname).is_none() {
                    return Err(Reply::error(
                        409,
                        "The brain's pages have no name yet: set it with PUT /api/brain/pages.",
                    ));
                }
                (c.hooks.open_link)(page)
                    .map(|url| Reply::ok(&super::panel::OpenLink { url }))
                    .map_err(|e| Reply::error(409, e))
            },
        ),
    ]
}

// ---- the view ----

#[derive(Debug, Serialize, JsonSchema)]
pub struct ServiceState {
    pub active: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainModelChoice {
    pub id: String,
    pub label: String,
    pub blurb: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainConnection {
    /// `read` or `read_write`.
    pub scope: String,
    /// When it was switched on (ISO).
    pub since: String,
    /// Always false here: "Save what it learns automatically" is not on a standalone firewall.
    pub auto_capture: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainAgent {
    pub vm_id: String,
    pub name: String,
    pub running: bool,
    /// The firewall can reach its vm-agent, so it can be switched on.
    pub secured: bool,
    /// Null while it is off the brain.
    pub connection: Option<BrainConnection>,
    /// Under the emergency stop, on its own or with everyone.
    pub stopped: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainDetail {
    pub vm_id: String,
    pub name: String,
    /// Where the firewall reaches its vm-agent.
    pub address: Option<String>,
    /// `install` or `connect`, when the brain's pairing said; null otherwise.
    pub origin: Option<String>,
    /// The brain's vm-agent answered.
    pub reachable: bool,
    /// GBrain's own service, when the vm-agent answered.
    pub service: Option<ServiceState>,
    /// No agent can search or save: the emergency stop for everyone, or the admin's lock.
    pub locked: bool,
    /// The admin's lock (`PUT /api/brain/lock`).
    pub locked_by_admin: bool,
    /// The emergency stop for everyone.
    pub stopped_all: bool,
    /// Its pages have a name, so they can be opened (`POST /api/brain/open`).
    pub pages: bool,
    /// `https://<name>` of its pages, when set.
    pub pages_url: Option<String>,
    pub hostname: Option<String>,
    /// GBrain's version, when the brain reported it.
    pub version: Option<String>,
    /// The model set from here; null until one was.
    pub model: Option<String>,
    pub models: Vec<BrainModelChoice>,
    /// No OpenAI or Vercel AI Gateway key on this firewall for the brain's calls.
    pub needs_key: bool,
    pub agents: Vec<BrainAgent>,
    /// Always null here: a change applies at once.
    pub change: Option<Value>,
    /// What agents are given as their `gbrain` MCP entry; null when the tools gate is off.
    pub gate_url: Option<String>,
    /// Why the brain could not be read, when it could not.
    pub brain_error: Option<String>,
    pub auto_save: BrainAutoSave,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PanelBrain {
    /// The brain paired with this firewall (role `gbrain`); null when there is none.
    pub brain: Option<BrainDetail>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainAutoSave {
    pub available: bool,
    pub reason: String,
}

struct BrainRow {
    vm_id: String,
    name: String,
    private_ip: Option<String>,
    agent_addr: Option<String>,
    hostname: Option<String>,
}

fn brain_row(db: &Db) -> rusqlite::Result<Option<BrainRow>> {
    db.lock()
        .query_row(
            "SELECT vm_id, name, private_ip, agent_addr, hostname FROM agents WHERE role = 'gbrain' ORDER BY created_at, vm_id LIMIT 1",
            [],
            |r| {
                Ok(BrainRow {
                    vm_id: r.get(0)?,
                    name: r.get(1)?,
                    private_ip: r.get(2)?,
                    agent_addr: r.get(3)?,
                    hostname: r.get::<_, Option<String>>(4)?.filter(|h| !h.is_empty()),
                })
            },
        )
        .optional()
}

struct AgentRow {
    vm_id: String,
    name: String,
    running: bool,
    reachable: bool,
}

fn openclaw_agents(db: &Db) -> rusqlite::Result<Vec<AgentRow>> {
    let c = db.lock();
    let mut q = c.prepare(
        "SELECT vm_id, name, status, agent_addr IS NOT NULL OR wg_public_key IS NOT NULL FROM agents WHERE role = 'openclaw' ORDER BY created_at, vm_id",
    )?;
    q.query_map([], |r| {
        Ok(AgentRow {
            vm_id: r.get(0)?,
            name: r.get(1)?,
            running: r.get::<_, String>(2)? == "running",
            reachable: r.get(3)?,
        })
    })?
    .collect()
}

fn has_brain_key(db: &Db) -> rusqlite::Result<bool> {
    let c = db.lock();
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM llm_keys WHERE provider IN ('openai', 'vercel_gateway') AND state = 'active'",
        [],
        |r| r.get(0),
    )?;
    debug_assert_eq!(BRAIN_KEY_PROVIDERS.len(), 2);
    Ok(n > 0)
}

/// The newest `brain_stats` reading's GBrain version, when it has one.
fn brain_version(db: &Db) -> Option<String> {
    let rec: String = db
        .lock()
        .query_row(
            "SELECT record FROM activity_raw WHERE source = 'brain_stats' ORDER BY occurred_at DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok()?;
    let v: Value = serde_json::from_str(&rec).ok()?;
    v["version"].as_str().map(str::to_string)
}

async fn view(c: &Ctx) -> Result {
    let Some(brain) = brain_row(&c.db)? else {
        return Ok(Reply::ok(&PanelBrain { brain: None }));
    };
    // The brain's gate and its health, at once: each waits for the brain when it is down.
    let (read, health) = tokio::join!(
        c.command("gbrain.read", json!({})),
        c.command("gbrain.status", json!({}))
    );
    let read = read?;
    let data = read.data.clone().unwrap_or(Value::Null);
    let conns = data["connections"].as_object().cloned().unwrap_or_default();
    let stop_ids: Vec<String> = data["stopped"]["vmIds"]
        .as_array()
        .map(|l| l.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let stopped_all = data["stopped"]["all"] == true;
    let locked_by_admin = data["locked"] == true;
    let health = health.ok().filter(|h| h.ok).and_then(|h| h.data);
    let brain_error = data["gateError"]
        .as_str()
        .map(str::to_string)
        .or_else(|| (!read.ok).then(|| read.message.clone().unwrap_or_default()));
    let agents = openclaw_agents(&c.db)?
        .into_iter()
        .map(|a| {
            let conn = conns.get(&a.vm_id);
            BrainAgent {
                connection: conn.map(|x| BrainConnection {
                    scope: x["scope"].as_str().unwrap_or("read").to_string(),
                    since: x["at"].as_str().unwrap_or_default().to_string(),
                    auto_capture: false,
                }),
                stopped: stopped_all || stop_ids.contains(&a.vm_id),
                running: a.running,
                secured: a.reachable,
                vm_id: a.vm_id,
                name: a.name,
            }
        })
        .collect();
    let needs_key = !has_brain_key(&c.db)?;
    let model = model_view(&c.db)?;
    Ok(Reply::ok(&PanelBrain {
        brain: Some(BrainDetail {
            address: brain.agent_addr.clone().or(brain.private_ip.clone()),
            origin: None,
            // The brain's own gate answered: not only the absence of an error (no call was made
            // while the firewall did not know the brain yet).
            reachable: brain_error.is_none() && data["gate"].is_object(),
            service: health.as_ref().map(|h| ServiceState {
                // The brain's `/health` says `running` (`service_status`).
                active: h["health"]["services"]["gbrain"] == "running",
            }),
            locked: stopped_all || locked_by_admin,
            locked_by_admin,
            stopped_all,
            pages: brain.hostname.is_some(),
            pages_url: brain.hostname.as_ref().map(|h| format!("https://{h}")),
            hostname: brain.hostname,
            version: brain_version(&c.db),
            model: model.model,
            models: if needs_key { Vec::new() } else { model.models },
            needs_key,
            agents,
            change: None,
            gate_url: data["gateUrl"].as_str().map(str::to_string),
            brain_error,
            auto_save: BrainAutoSave {
                available: false,
                reason: NO_AUTO_SAVE.into(),
            },
            vm_id: brain.vm_id,
            name: brain.name,
        }),
    }))
}

// ---- switching agents on and off ----

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrainScope {
    Read,
    ReadWrite,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrainAgentScope {
    pub scope: BrainScope,
}

async fn connect(c: &Ctx, b: BrainAgentScope) -> Result {
    let vm = c.param("vmId").to_string();
    let Some(brain) = brain_row(&c.db)? else {
        return Err(Reply::error(409, "There is no brain paired with this firewall."));
    };
    if !openclaw_agents(&c.db)?.iter().any(|a| a.vm_id == vm) {
        return Err(Reply::not_found("Agent"));
    }
    let scope = match b.scope {
        BrainScope::Read => "read",
        BrainScope::ReadWrite => "read_write",
    };
    let p = checked(
        "gbrain.propose",
        json!({"changeId": new_id("chg"), "agentVmId": vm, "brainVmId": brain.vm_id, "scope": scope}),
    )?;
    let mut with = Map::new();
    with.insert("agentVmId".into(), json!(vm));
    Ok(c.apply_as("gbrain.propose", "gbrain.confirm", p, with).await?.reply())
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrainLockBody {
    pub locked: bool,
}

// ---- the model ----

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainModelView {
    /// The model last set from here; null until one was (the brain's own default then).
    pub model: Option<String>,
    pub models: Vec<BrainModelChoice>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrainModelBody {
    pub model: String,
}

fn model_view(db: &Db) -> rusqlite::Result<BrainModelView> {
    Ok(BrainModelView {
        model: db.setting(MODEL_SETTING),
        models: MODELS
            .iter()
            .map(|(id, label, blurb)| BrainModelChoice {
                id: id.to_string(),
                label: label.to_string(),
                blurb: blurb.to_string(),
            })
            .collect(),
    })
}

async fn set_model(c: &Ctx, b: BrainModelBody) -> Result {
    if !MODELS.iter().any(|(id, _, _)| *id == b.model) {
        let ids: Vec<&str> = MODELS.iter().map(|m| m.0).collect();
        return Err(Reply::bad(format!("model: one of {}", ids.join(", "))));
    }
    let p = checked("gbrain.model", json!({"model": b.model}))?;
    let answer = c.command("gbrain.model", Value::Object(p)).await?;
    if !answer.ok {
        return Err(answer.reply());
    }
    c.db.set_setting(MODEL_SETTING, &b.model)?;
    Ok(Reply::ok(&model_view(&c.db)?))
}

// ---- the pages' name ----

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrainPagesBody {
    /// A name with a dot and no port (`brain.example.com`), served on 443 by HTTPS in front of
    /// `BRAIN_PAGES_BIND`; the brain's own `vm_hostname` must be the same.
    pub hostname: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainPagesView {
    pub hostname: String,
    pub url: String,
}

/// A DNS name with a dot, no port, no scheme.
pub fn plausible_hostname(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && h.parse::<std::net::Ipv4Addr>().is_err()
}

/// Set once: the firewall pins a box to its first name (the access module), so a later name would
/// be shown here and never opened. Pairing the brain again gives it a new one.
fn set_pages(c: &Ctx, b: BrainPagesBody) -> Result {
    let h = b.hostname.trim().to_lowercase();
    if !plausible_hostname(&h) {
        return Err(Reply::bad(
            "hostname: a name with a dot and no port, such as brain.example.com",
        ));
    }
    let Some(brain) = brain_row(&c.db)? else {
        return Err(Reply::error(409, "There is no brain paired with this firewall."));
    };
    if let Some(old) = &brain.hostname {
        if *old == h {
            return Ok(Reply::ok(&BrainPagesView {
                url: format!("https://{h}"),
                hostname: h,
            }));
        }
        return Err(Reply::error(
            409,
            format!(
                "The brain's pages are already at {old}, and the firewall keeps a machine's first name. To use another, pair the brain again."
            ),
        ));
    }
    let taken: Option<String> =
        c.db.lock()
            .query_row(
                "SELECT vm_id FROM agents WHERE lower(hostname) = ?1 AND vm_id <> ?2",
                [&h, &brain.vm_id],
                |r| r.get(0),
            )
            .optional()?;
    if taken.is_some() {
        return Err(Reply::error(409, "Another machine has that name."));
    }
    c.db.lock()
        .execute("UPDATE agents SET hostname = ?1 WHERE vm_id = ?2", [&h, &brain.vm_id])?;
    (c.hooks.rules_changed)();
    Ok(Reply::ok(&BrainPagesView {
        url: format!("https://{h}"),
        hostname: h,
    }))
}

/// Pages, Lately, Ask, Import and Export each open on the brain's Pages, where the others are a
/// click away; `admin` is GBrain's own admin page.
#[derive(Debug, Deserialize, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BrainPage {
    Pages,
    Lately,
    Ask,
    Import,
    Export,
    Admin,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrainOpenBody {
    pub page: BrainPage,
}

// ---- the Overview ----

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct BrainCount {
    pub today: u64,
    /// Yesterday up to the same time of day.
    pub yesterday: u64,
    /// The last 24 hours, oldest first, as `hours`.
    pub hourly: Vec<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainAnswerMs {
    pub today: Option<i64>,
    pub hourly: Vec<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainReading {
    pub at: String,
    pub page_count: u64,
    pub chunk_count: u64,
    pub by_type: BTreeMap<String, u64>,
    pub disk_used_bytes: Option<u64>,
    pub disk_free_bytes: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainTypeChange {
    pub key: String,
    /// The key: the panel names it.
    pub label: String,
    pub delta: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BrainFeedItem {
    #[serde(rename_all = "camelCase")]
    Saves {
        id: String,
        at: String,
        agent_vm_id: Option<String>,
        agent_name: Option<String>,
        count: u64,
    },
    Changes {
        id: String,
        at: String,
        changes: Vec<BrainTypeChange>,
    },
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct BrainGrowthDay {
    /// `YYYY-MM-DD`, UTC.
    pub day: String,
    /// Pages at the day's last reading; null before the first one.
    pub pages: Option<u64>,
    pub saves: u64,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainAgentUsage {
    pub vm_id: String,
    pub searches: u64,
    pub saves: u64,
    pub last_at: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BrainOverview {
    /// ISO hour starts of the 24 points.
    pub hours: Vec<String>,
    pub searches: BrainCount,
    /// Saves that went through.
    pub saves: BrainCount,
    pub answer_ms: BrainAnswerMs,
    pub last_saved_at: Option<String>,
    /// The newest reading of the brain's counts; null until the brain sends one.
    pub latest: Option<BrainReading>,
    /// Newest first: an agent's saves per quarter hour, and how the counts per kind moved.
    pub feed: Vec<BrainFeedItem>,
    /// 30 days, oldest first, ending today.
    pub growth: Vec<BrainGrowthDay>,
    /// Searches and saves per agent over 30 days, busiest first.
    pub agents: Vec<BrainAgentUsage>,
}

pub fn iso(at: i64) -> String {
    let secs = at.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}.000Z",
        day_of(at),
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn day_of(at: i64) -> String {
    let days = at.div_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

fn median(v: &mut [i64]) -> Option<i64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    })
}

/// One call the tools gate relayed: when, which agent, the tool, the answer's status and time.
struct Call {
    at: i64,
    vm: String,
    search: bool,
    save: bool,
    ms: Option<i64>,
}

/// The Overview, from the firewall's record of each brain call and the brain's own readings.
pub fn overview(db: &Db, now: i64) -> rusqlite::Result<BrainOverview> {
    const HOUR: i64 = 3600;
    const DAY: i64 = 86_400;
    let since = now - 30 * DAY;
    let calls: Vec<Call> = {
        let c = db.lock();
        let mut q = c.prepare(
            "SELECT occurred_at, record FROM activity_raw WHERE source = 'egress' AND occurred_at >= ?1 AND summary LIKE ?2 ORDER BY occurred_at",
        )?;
        q.query_map(rusqlite::params![since, BRAIN_CALL_SUMMARY], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|(at, rec)| {
            let r: Value = serde_json::from_str(&rec).ok()?;
            let tool = r["tool"].as_str()?;
            // GBrain refuses a read-only agent's save inside a 200: the scope the gate wrote says so.
            let ok = r["status"].as_u64().is_some_and(|s| (200..300).contains(&s)) && r["scope"] != "read";
            Some(Call {
                at,
                vm: r["vm_id"].as_str().unwrap_or_default().to_string(),
                search: SEARCH_OPS.contains(&tool),
                save: SAVE_OPS.contains(&tool) && ok,
                ms: r["duration_ms"].as_i64(),
            })
        })
        .filter(|c| c.search || c.save)
        .collect()
    };
    let readings: Vec<(i64, Value)> = {
        let c = db.lock();
        let mut q = c.prepare(
            "SELECT occurred_at, record FROM activity_raw WHERE source = 'brain_stats' AND occurred_at >= ?1 ORDER BY occurred_at",
        )?;
        q.query_map([since], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(at, rec)| serde_json::from_str(&rec).ok().map(|v| (at, v)))
            .collect()
    };
    let names: HashMap<String, String> = {
        let c = db.lock();
        let mut q = c.prepare("SELECT vm_id, name FROM agents")?;
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };

    let first_hour = now.div_euclid(HOUR) * HOUR - 23 * HOUR;
    let today = now.div_euclid(DAY) * DAY;
    let (yesterday, yesterday_to) = (today - DAY, now - DAY);
    let mut searches = BrainCount {
        hourly: vec![0; 24],
        ..Default::default()
    };
    let mut saves = BrainCount {
        hourly: vec![0; 24],
        ..Default::default()
    };
    let mut today_ms = Vec::new();
    let mut hour_ms: Vec<Vec<i64>> = vec![Vec::new(); 24];
    let mut usage: Vec<BrainAgentUsage> = Vec::new();
    let mut groups: BTreeMap<(i64, String), (i64, u64)> = BTreeMap::new();
    let mut saves_by_day: HashMap<String, u64> = HashMap::new();
    let mut last_saved = None;
    for c in &calls {
        let count = if c.search { &mut searches } else { &mut saves };
        if c.at >= today {
            count.today += 1;
        } else if c.at >= yesterday && c.at <= yesterday_to {
            count.yesterday += 1;
        }
        if c.at >= first_hour {
            let i = ((c.at - first_hour) / HOUR).min(23) as usize;
            count.hourly[i] += 1;
            if c.search
                && let Some(ms) = c.ms
            {
                hour_ms[i].push(ms);
            }
        }
        if c.search
            && c.at >= today
            && let Some(ms) = c.ms
        {
            today_ms.push(ms);
        }
        if c.save {
            last_saved = Some(c.at);
            *saves_by_day.entry(day_of(c.at)).or_default() += 1;
            if c.at >= now - 7 * DAY {
                let g = groups.entry((c.at.div_euclid(900), c.vm.clone())).or_default();
                g.0 = g.0.max(c.at);
                g.1 += 1;
            }
        }
        if !c.vm.is_empty() {
            let i = match usage.iter().position(|u| u.vm_id == c.vm) {
                Some(i) => i,
                None => {
                    usage.push(BrainAgentUsage {
                        vm_id: c.vm.clone(),
                        ..Default::default()
                    });
                    usage.len() - 1
                }
            };
            let u = &mut usage[i];
            if c.search {
                u.searches += 1;
            } else {
                u.saves += 1;
            }
            u.last_at = Some(iso(c.at));
        }
    }
    usage.sort_by_key(|u| std::cmp::Reverse(u.searches + u.saves));

    let mut feed: Vec<(i64, BrainFeedItem)> = groups
        .into_iter()
        .map(|((q, vm), (at, count))| {
            (
                at,
                BrainFeedItem::Saves {
                    id: format!("s:{vm}:{q}"),
                    at: iso(at),
                    agent_name: names.get(&vm).cloned(),
                    agent_vm_id: (!vm.is_empty()).then_some(vm),
                    count,
                },
            )
        })
        .collect();
    let by_type = |v: &Value| -> BTreeMap<String, u64> {
        v["pages_by_type"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, n)| n.as_u64().map(|n| (k.clone(), n)))
                    .collect()
            })
            .unwrap_or_default()
    };
    for w in readings.windows(2) {
        let (at, after) = (&w[1].0, &w[1].1);
        if *at < now - 7 * DAY {
            continue;
        }
        let (before, after) = (by_type(&w[0].1), by_type(after));
        let mut changes: Vec<BrainTypeChange> = before
            .keys()
            .chain(after.keys())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .filter_map(|k| {
                let delta = *after.get(k).unwrap_or(&0) as i64 - *before.get(k).unwrap_or(&0) as i64;
                (delta != 0).then(|| BrainTypeChange {
                    key: k.clone(),
                    label: k.clone(),
                    delta,
                })
            })
            .collect();
        if changes.is_empty() {
            continue;
        }
        changes.sort_by(|a, b| b.delta.abs().cmp(&a.delta.abs()).then(a.key.cmp(&b.key)));
        feed.push((
            *at,
            BrainFeedItem::Changes {
                id: format!("c:{at}"),
                at: iso(*at),
                changes,
            },
        ));
    }
    feed.sort_by_key(|f| std::cmp::Reverse(f.0));
    feed.truncate(30);

    let mut pages_by_day: HashMap<String, u64> = HashMap::new();
    for (at, v) in &readings {
        if let Some(n) = v["page_count"].as_u64() {
            pages_by_day.insert(day_of(*at), n);
        }
    }
    let first_reading = readings.first().map(|r| day_of(r.0));
    let mut growth = Vec::with_capacity(30);
    let mut last_pages = None;
    for i in (0..30).rev() {
        let day = day_of(now - i * DAY);
        if let Some(n) = pages_by_day.get(&day) {
            last_pages = Some(*n);
        }
        let before_first = first_reading.as_ref().is_none_or(|f| day < *f);
        growth.push(BrainGrowthDay {
            pages: if before_first { None } else { last_pages },
            saves: saves_by_day.get(&day).copied().unwrap_or(0),
            day,
        });
    }
    let latest = readings.last().map(|(at, v)| BrainReading {
        at: iso(*at),
        page_count: v["page_count"].as_u64().unwrap_or(0),
        chunk_count: v["chunk_count"].as_u64().unwrap_or(0),
        by_type: by_type(v),
        disk_used_bytes: v["disk_used_bytes"].as_u64(),
        disk_free_bytes: v["disk_free_bytes"].as_u64(),
    });

    Ok(BrainOverview {
        hours: (0..24).map(|i| iso(first_hour + i * HOUR)).collect(),
        searches,
        saves,
        answer_ms: BrainAnswerMs {
            today: median(&mut today_ms),
            hourly: hour_ms.iter_mut().map(|v| median(v).unwrap_or(0)).collect(),
        },
        last_saved_at: last_saved.map(iso),
        latest,
        feed: feed.into_iter().map(|(_, f)| f).collect(),
        growth,
        agents: usage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_are_utc_dates() {
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(1_795_000_000), "2026-11-18");
        assert_eq!(day_of(951_782_400), "2000-02-29");
        assert_eq!(iso(1_795_000_000), "2026-11-18T11:06:40.000Z");
    }

    #[test]
    fn names_for_the_pages() {
        assert!(plausible_hostname("brain.example.com"));
        for h in [
            "localhost",
            "brain.example.com:8443",
            "10.0.0.2",
            "-a.example",
            "a..b",
            "a b.c",
            "",
        ] {
            assert!(!plausible_hostname(h), "{h}");
        }
    }
}
