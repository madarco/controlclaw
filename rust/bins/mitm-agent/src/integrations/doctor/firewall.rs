//! Doctor on the firewall (`doctor.ts`): a coding agent (Claude Code, Codex or Pi) given root on
//! one agent over SSH, or this firewall's repair commands, for a window, after a code a person
//! typed. Its turns run in a unit of their own (`cc-doctor-run`), its transcript is sealed here,
//! and the console learns its state only, never its content.
//!
//!   doctor.propose  { sessionId, vmId, cli, credentialId, model, kind?, step?, preset? }
//!   doctor.confirm  { sessionId, code }
//!   doctor.stop     { sessionId }

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::capture::{self, CAPTURE_WINDOW_MS, CaptureRecord};
use super::credentials::{self, DoctorCredentials};
use super::gateway::{AI_GATEWAY, ANTHROPIC, DoctorGateway, GatewayCredential, Upstream};
use super::repair::{self, REPAIR_STEP, REPAIR_WINDOW_MS, RepairFacts, RepairRecord};
use super::runner::{DoctorRunner, RunInput, Sockets};
use super::store::{DoctorStore, Transcript};
use super::stream::{self, CHECK_TOOLS_OK, CHECK_WRONG_TOOLS, Cli, DoctorStream, Event, Init, Parsed};
use super::{Clock, Target};
use crate::app::App;
use crate::commands::CommandOutcome;
use crate::integrations::codes::{Codes, Verified};
use crate::integrations::{as_map, js, outcome};

pub const DOCTOR_WINDOW_MS: i64 = 2 * 60 * 60_000;
pub const DOCTOR_IDLE_MS: i64 = 15 * 60_000;
/// How long the agent may take to check its steps again and read its repair folder.
const REPAIR_DONE_TIMEOUT: Duration = Duration::from_secs(12 * 60);
/// How much of the end of a check's last message is kept for its report.
const CHECK_REPORT_TAIL: usize = 100_000;
pub const CHECK_TOOL: &str = "mcp__tplcheck__run";
const CHECK_MCP: &str = "tplcheck";
const CHECK_BUILTIN_AGENTS: &[&str] = &["claude", "Explore", "general-purpose", "Plan", "statusline-setup"];
pub const CHECK_MAX_MODEL_REQUESTS: u32 = 80;
pub const CHECK_SOCKETS_DIR: &str = "/run/ccdoctor-sock";
pub const CHECK_MODEL_URL: &str = "http://127.0.0.1:7802";
pub const CHECK_PREEMPTED: &str = "A repair was started, so this test gave way. It will run again.";
pub const SECRETS_FORGOTTEN: &str = "The firewall restarted since this session, so it can no longer check these files against the keys the session used. They are not read and cannot be sent. Start a new session.";
const FAILED: &str =
    "The doctor request could not be completed. Check the selected model, credentials and firewall software.";
const KINDS: &[&str] = &[
    "repair-agent",
    "repair-firewall",
    "template-capture",
    "template-repair",
    "template-check",
];

/// Problems a Firewall Doctor start from the console may name: fixed text, so nothing free-form
/// passes through the console.
pub const FIREWALL_PRESETS: &[(&str, &str)] = &[
    (
        "pages",
        "The firewall's own pages (Doctor chat, Logs, sign-in to agents) do not load. Check Caddy first.",
    ),
    (
        "egress",
        "The agents have no internet through the firewall. Check the proxy and its logs.",
    ),
    (
        "dns",
        "Names do not resolve for the agents. Check dnsmasq and its configuration.",
    ),
    (
        "update",
        "The last firewall update failed. Read the update log, find the cause and repair it.",
    ),
    (
        "disk",
        "The firewall's disk is full or nearly full. Find what filled it and free space safely.",
    ),
    (
        "unlock",
        "Agents cannot unlock their encrypted disks, or the firewall's own encrypted state is not mounted. Check Tang and disk encryption.",
    ),
];

static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,80}$").expect("pattern"));

fn repair_kind(on_firewall: bool) -> &'static str {
    if on_firewall { "repair-firewall" } else { "repair-agent" }
}

/// `string(value, max)`: a string no longer than `max`, trimmed; else empty.
fn string(v: Option<&Value>, max: usize) -> String {
    v.and_then(Value::as_str)
        .filter(|s| s.encode_utf16().count() <= max)
        .map(|s| js::trim(s).to_string())
        .unwrap_or_default()
}

/// `agentAnswered`: the agent's own service answered, even with a refusal (a 4xx).
pub fn agent_answered(e: &crate::contracts::AgentError) -> bool {
    let m = e.message.strip_prefix("agent ").unwrap_or("");
    m.get(..3)
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|_| m.get(3..4) == Some(":"))
        .is_some_and(|s| (400..500).contains(&s))
}

/// The listener a tool-only session reaches its tool through (`loopback-tools.ts`, I7).
pub trait SessionTools: Send + Sync {
    fn token(&self) -> String;
    /// Its URL, or with a path, that unix socket.
    fn start(&self, socket: Option<String>) -> cc_http::BoxFuture<Result<String, String>>;
    fn close(&self) -> cc_http::BoxFuture<()>;
}

pub type MakeTools = Arc<dyn Fn(Arc<dyn Fn() -> bool + Send + Sync>) -> Arc<dyn SessionTools> + Send + Sync>;

#[derive(Clone)]
struct ToolSpec {
    make: MakeTools,
    url_env: &'static str,
    token_env: &'static str,
    /// `firewall` or `check`.
    target: &'static str,
}

/// Firewall Doctor: this firewall as a repair target, present only where its helper is installed.
#[derive(Clone)]
pub struct FirewallTarget {
    pub vm_id: String,
    pub name: String,
    pub tools: MakeTools,
    pub reserve: Option<Arc<super::reserve::Reserve>>,
}

#[derive(Clone)]
struct Proposal {
    target: Target,
    cli: Cli,
    credential_id: String,
    model: String,
    summary: String,
    preset: Option<&'static str>,
    repair: Option<(RepairFacts, String)>,
    capture: Option<String>,
}

struct Session {
    id: String,
    vm_id: String,
    kind: String,
    state: &'static str,
    expires_at: i64,
    mode: &'static str,
    proposal: Proposal,
    codes: Arc<Codes>,
    touched_at: i64,
    busy: bool,
    generation: u64,
    resume_id: Option<String>,
    seq: u64,
    end_reason: Option<String>,
    dirty: bool,
    uploading: bool,
    sent_via: Option<String>,
    storage_failed: bool,
    secrets: HashSet<String>,
    gateway: Option<Arc<DoctorGateway>>,
    tools: Option<Arc<dyn SessionTools>>,
    tools_url: Option<String>,
    tool_spec: Option<ToolSpec>,
    last_text: Option<String>,
    tools_checked: bool,
    preempted: bool,
    ending: bool,
    started_by: Option<String>,
    created: bool,
}

type S = Arc<Mutex<Session>>;

/// What the console learns about a session: its state, and for one started here the row it needs.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Upload {
    pub session_id: String,
    pub kind: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<Value>,
}

/// A send to the console refused with its own words; `replace`: a draft is waiting there.
#[derive(Debug, Clone, PartialEq)]
pub enum SendError {
    Refused {
        message: String,
        replace: bool,
    },
    /// The console would not record a repair started here: it has to end now.
    RefusedRepair,
    Failed,
}

pub type UploadFn = Arc<dyn Fn(Upload) -> cc_http::BoxFuture<Result<(), SendError>> + Send + Sync>;
pub type SendFn = Arc<dyn Fn(Value) -> cc_http::BoxFuture<Result<(), SendError>> + Send + Sync>;

pub struct Options {
    pub store: DoctorStore,
    pub runner: Arc<dyn DoctorRunner>,
    pub agents: Arc<dyn Fn() -> Vec<Target> + Send + Sync>,
    pub private_key: Arc<dyn Fn() -> String + Send + Sync>,
    pub firewall: Option<FirewallTarget>,
    pub upload: UploadFn,
    pub propose: Option<SendFn>,
    pub send_draft: Option<SendFn>,
    pub now: Clock,
    pub window_ms: Option<i64>,
    pub idle_ms: Option<i64>,
    pub check_sockets_dir: String,
    /// Where gateway requests go (the tests' fake provider).
    pub gateway_base: Option<String>,
}

/// A Final check: one headless turn about an agent, with read-only tools the caller serves.
pub struct CheckInput {
    pub session_id: String,
    pub target: Target,
    pub cli: Cli,
    pub credential_id: String,
    pub model: String,
    pub prompt: String,
    pub seconds: i64,
    pub tools: MakeTools,
}

/// `done`, `busy`, `preempted`, `stopped` or `failed`, and the report.
pub struct CheckResult {
    pub outcome: &'static str,
    pub text: String,
}

pub struct DoctorFirewall {
    app: Arc<App>,
    o: Options,
    sessions: Mutex<Vec<(String, S)>>,
    /// The TS's `commandTail`: commands one at a time.
    commands: tokio::sync::Mutex<()>,
    /// The secrets of sessions that ended (repairs and captures), the newest fifty.
    ended_secrets: Mutex<Vec<(String, HashSet<String>)>>,
    reading: Mutex<HashSet<String>>,
    sending: tokio::sync::Mutex<()>,
    next_prune: AtomicI64,
}

fn data(id: &str) -> Map<String, Value> {
    as_map(json!({"sessionId": id}))
}

fn with(mut base: Map<String, Value>, extra: Value) -> Option<Map<String, Value>> {
    base.extend(as_map(extra));
    Some(base)
}

impl DoctorFirewall {
    pub fn new(app: &Arc<App>, o: Options) -> Arc<Self> {
        Arc::new(Self {
            app: app.clone(),
            o,
            sessions: Mutex::new(Vec::new()),
            commands: tokio::sync::Mutex::new(()),
            ended_secrets: Mutex::new(Vec::new()),
            reading: Mutex::new(HashSet::new()),
            sending: tokio::sync::Mutex::new(()),
            next_prune: AtomicI64::new(0),
        })
    }

    fn now(&self) -> i64 {
        (self.o.now)()
    }

    fn idle(&self) -> i64 {
        self.o.idle_ms.unwrap_or(DOCTOR_IDLE_MS)
    }

    /// `allSecrets`: W3's `firewallSecrets()`, which holds the stores' remembered secrets too.
    fn all_secrets(&self) -> Vec<String> {
        self.app
            .contracts
            .firewall_secrets
            .get()
            .map(|s| s.values())
            .unwrap_or_default()
    }

    fn get(&self, id: &str) -> Option<S> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, s)| s.clone())
    }

    fn all(&self) -> Vec<S> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(_, s)| s.clone())
            .collect()
    }

    fn forget(&self, id: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(k, _)| k != id);
    }

    pub fn session(&self, id: &str) -> Option<Value> {
        let s = self.get(id)?;
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        Some(
            json!({"sessionId": id, "vmId": s.vm_id, "kind": s.kind, "state": s.state, "expiresAt": s.expires_at, "mode": s.mode}),
        )
    }

    /// The session's state, expiry and mode, for the terminal.
    pub fn active(&self, id: &str) -> Option<(String, i64, &'static str)> {
        let s = self.get(id)?;
        let s = s.lock().unwrap_or_else(|e| e.into_inner());
        (s.state == "running").then(|| (s.vm_id.clone(), s.expires_at, s.mode))
    }

    pub fn touch(&self, id: &str) -> bool {
        let Some(s) = self.get(id) else { return false };
        let mut s = s.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.now();
        if s.state != "running" || now >= s.expires_at || now - s.touched_at >= self.idle() {
            return false;
        }
        s.touched_at = now;
        true
    }

    // ---- commands ----

    pub async fn handle(self: &Arc<Self>, action: &str, p: Map<String, Value>) -> CommandOutcome {
        let _one = self.commands.lock().await;
        let id = string(p.get("sessionId"), 100);
        let failed = || outcome(false, "failed", Some(FAILED.into()), Some(data(&id)));
        match action {
            "propose" => self.propose(&p, None).await.unwrap_or_else(|_| failed()),
            "confirm" | "stop" if !ID.is_match(&id) => {
                outcome(false, "failed", Some("Invalid doctor session.".into()), None)
            }
            "confirm" => self
                .confirm(&id, &string(p.get("code"), 100))
                .await
                .unwrap_or_else(|_| failed()),
            "stop" => {
                self.stop(&id).await;
                let busy = self
                    .get(&id)
                    .is_some_and(|s| s.lock().unwrap_or_else(|e| e.into_inner()).busy);
                outcome(
                    !busy,
                    if busy { "busy" } else { "ended" },
                    busy.then(|| "The firewall is retrying stopping the doctor unit.".to_string()),
                    Some(data(&id)),
                )
            }
            _ => crate::integrations::failed(&format!("unknown command doctor.{action}")),
        }
    }

    /// A repair started on the firewall's own page: the same proposal, the same code.
    pub async fn start_local(self: &Arc<Self>, p: Map<String, Value>, started_by: &str) -> CommandOutcome {
        let _one = self.commands.lock().await;
        let id = string(p.get("sessionId"), 100);
        match self.propose(&p, Some(started_by)).await {
            Ok(o) => o,
            Err(()) => outcome(false, "failed", Some(FAILED.into()), Some(data(&id))),
        }
    }

    /// The code for a session started on this page. A session started from the console is confirmed there.
    pub async fn confirm_local(self: &Arc<Self>, id: &str, code: &str, started_by: &str) -> CommandOutcome {
        let _one = self.commands.lock().await;
        let mine = self
            .get(id)
            .is_some_and(|s| s.lock().unwrap_or_else(|e| e.into_inner()).started_by.as_deref() == Some(started_by));
        if !mine {
            return outcome(
                false,
                "expired",
                Some("No doctor session is waiting for this code.".into()),
                Some(data(id)),
            );
        }
        let code: String = code.chars().take(100).collect();
        self.confirm(id, &code).await.unwrap_or_else(|_| {
            outcome(
                false,
                "failed",
                Some("The doctor request could not be completed.".into()),
                Some(data(id)),
            )
        })
    }

    fn target_of(&self, vm_id: &str) -> Option<Target> {
        (self.o.agents)().into_iter().find(|a| a.vm_id == vm_id)
    }

    async fn credential(&self, cli: Cli, id: &str, model: &str) -> Result<DoctorCredentials, String> {
        let c = match self.app.contracts.doctor_credential.get() {
            Some(src) => src.credential(id).await,
            None => None,
        };
        credentials::resolve(cli, c.as_ref(), model, self.now())
    }

    /// Err: malformed (the command layer's fixed failure).
    async fn propose(self: &Arc<Self>, p: &Map<String, Value>, started_by: Option<&str>) -> Result<CommandOutcome, ()> {
        let id = string(p.get("sessionId"), 100);
        let vm_id = string(p.get("vmId"), 100);
        let cli = p.get("cli").and_then(Value::as_str).and_then(Cli::parse);
        let credential_id = string(p.get("credentialId"), 100);
        let model = string(p.get("model"), 200);
        let d = data(&id);
        let (true, Some(cli), false) = (ID.is_match(&id), cli, credential_id.is_empty()) else {
            return Err(());
        };
        let fw = self.o.firewall.as_ref();
        let on_firewall = fw.is_some_and(|f| f.vm_id == vm_id);
        let preset = p
            .get("preset")
            .and_then(Value::as_str)
            .and_then(|k| FIREWALL_PRESETS.iter().find(|(n, _)| *n == k))
            .map(|(n, _)| *n);
        if preset.is_some() && !on_firewall {
            return Err(());
        }
        // A console older than the field names no kind: the target says which repair it is.
        let kind = match p.get("kind") {
            None => repair_kind(on_firewall).to_string(),
            Some(Value::String(k)) if KINDS.contains(&k.as_str()) => k.clone(),
            Some(_) => return Err(()),
        };
        let template_repair = kind == "template-repair";
        let template_capture = kind == "template-capture";
        if kind != repair_kind(on_firewall) && !((template_repair || template_capture) && !on_firewall) {
            if kind.starts_with("repair-") || template_repair || template_capture {
                return Err(());
            }
            return Ok(outcome(
                false,
                "failed",
                Some("This firewall's software cannot run that kind of Doctor session. Update the firewall.".into()),
                Some(d),
            ));
        }
        let step = if template_repair {
            string(p.get("step"), 130)
        } else {
            String::new()
        };
        if template_repair && step.is_empty() {
            return Err(());
        }
        let target = match fw.filter(|_| on_firewall) {
            Some(f) => Some(Target {
                vm_id: f.vm_id.clone(),
                name: f.name.clone(),
                hostname: String::new(),
                private_ip: String::new(),
                ssh_host_key: String::new(),
                key_ready: true,
                kind: Some("firewall".into()),
            }),
            None => self.target_of(&vm_id),
        };
        let ok_target = target.as_ref().is_some_and(|t| {
            on_firewall
                || (t.key_ready && t.private_ip.parse::<std::net::IpAddr>().is_ok() && !t.ssh_host_key.is_empty())
        });
        let Some(target) = target.filter(|_| ok_target) else {
            return Ok(outcome(
                false,
                "failed",
                Some("This agent has not installed the doctor SSH key yet. Update it before using Doctor.".into()),
                Some(d),
            ));
        };
        // A Final check is not in the way of a repair: it gives way, once this proposal is good.
        let others: Vec<S> = self
            .all()
            .into_iter()
            .filter(|s| s.lock().unwrap_or_else(|e| e.into_inner()).kind != "template-check")
            .collect();
        let live = |s: &Session| matches!(s.state, "proposed" | "running") || s.busy;
        if self.get(&id).is_some()
            || others.iter().any(|s| {
                let s = s.lock().unwrap_or_else(|e| e.into_inner());
                s.vm_id == vm_id && live(&s)
            })
        {
            return Ok(outcome(
                false,
                "failed",
                Some("A doctor session is already pending or running for this agent.".into()),
                Some(d),
            ));
        }
        // Every session runs as the same ccdoctor account, so a firewall repair and an agent repair never overlap.
        if others.iter().any(|s| {
            let s = s.lock().unwrap_or_else(|e| e.into_inner());
            (s.proposal.target.kind.as_deref() == Some("firewall")) != on_firewall && live(&s)
        }) {
            let m = if on_firewall {
                "An agent repair is pending or running. Stop it before repairing the firewall."
            } else {
                "A firewall repair is pending or running. Stop it before repairing an agent."
            };
            return Ok(outcome(false, "failed", Some(m.into()), Some(d)));
        }
        // No code routes or consent codes on this build, or the channel list unread: refused.
        let codes = Arc::new(Codes::for_module(&self.app, "doctor", &format!("doctor:{id}")));
        let routes = match codes.routes() {
            Ok(r) => r,
            Err(_) => {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("The firewall cannot read its confirmation channels.".into()),
                    Some(d),
                ));
            }
        };
        if !self.app.contracts.code_routes.get().is_some_and(|r| r.ready()) {
            return Ok(outcome(
                false,
                "failed",
                Some("The firewall cannot read its confirmation channels.".into()),
                Some(d),
            ));
        }
        // Nothing of a session is shown before the firewall's secrets can be masked out of it.
        if self.app.contracts.firewall_secrets.get().is_none() {
            return Ok(outcome(
                false,
                "failed",
                Some("This firewall cannot run Doctor yet. Update the firewall.".into()),
                Some(d),
            ));
        }
        let credential = self.credential(cli, &credential_id, &model).await.map_err(|_| ())?;
        let mut repair_: Option<(RepairFacts, String)> = None;
        if template_repair {
            // The template, its files and the failed step as the AGENT has them.
            let Some(client) = self.app.contracts.agents.get() else {
                return Ok(outcome(false, "failed", Some("The agent did not answer, so the firewall could not read which step failed. Repair the agent itself with Doctor.".into()), Some(d)));
            };
            let raw = match tokio::time::timeout(
                Duration::from_secs(20),
                client.get(&target.vm_id, "/templates/repair/facts"),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) if agent_answered(&e) => {
                    return Ok(outcome(false, "failed", Some("This agent's software cannot have a template step repaired, or it has no template. Update the agent.".into()), Some(d)));
                }
                _ => {
                    return Ok(outcome(false, "failed", Some("The agent did not answer, so the firewall could not read which step failed. Repair the agent itself with Doctor.".into()), Some(d)));
                }
            };
            let Some(facts) = repair::read_repair_facts(&raw) else {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("The agent's answer about its template could not be read. Update the agent.".into()),
                    Some(d),
                ));
            };
            if facts.failed_steps.is_empty() {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("No step of the template is failed on this agent now.".into()),
                    with(d, json!({"noFailedStep": true})),
                ));
            }
            if !facts.failed_steps.contains(&step) {
                let first = facts.failed_steps[0].clone();
                let m = format!(
                    "The step \"{step}\" is not failed on this agent. The agent reports \"{first}\" as failed. Open the agent's page again and start from there."
                );
                return Ok(outcome(false, "failed", Some(m), with(d, json!({"failedStep": first}))));
            }
            if !REPAIR_STEP.is_match(&step) {
                return Ok(outcome(false, "failed", Some("This step is part of a shared set of steps, and Doctor cannot repair it as a step of the template. Repair the agent itself with Doctor.".into()), Some(d)));
            }
            repair_ = Some((facts, step.clone()));
        }
        let mut capture_: Option<String> = None;
        if template_capture {
            let Some(client) = self.app.contracts.agents.get() else {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("The agent did not answer, so a capture session cannot read it.".into()),
                    Some(d),
                ));
            };
            let raw = match tokio::time::timeout(
                Duration::from_secs(20),
                client.get(&target.vm_id, "/templates/capture/facts"),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) if agent_answered(&e) => {
                    return Ok(outcome(
                        false,
                        "failed",
                        Some("This agent's software cannot be read by a capture session yet. Update the agent.".into()),
                        Some(d),
                    ));
                }
                _ => {
                    return Ok(outcome(
                        false,
                        "failed",
                        Some("The agent did not answer, so a capture session cannot read it.".into()),
                        Some(d),
                    ));
                }
            };
            let Some(base) = capture::read_capture_facts(&raw) else {
                return Ok(outcome(
                    false,
                    "failed",
                    Some("The agent's answer could not be read. Update the agent.".into()),
                    Some(d),
                ));
            };
            capture_ = Some(base);
        }
        let window = if template_repair || template_capture {
            "1 hour"
        } else {
            "2 hours"
        };
        let cli_name = cli.name();
        // The agent is named as this firewall has it on record, never as the console wrote it.
        // How the session is paid for is a label that came from the control plane: it goes to the
        // code message's part for such text.
        let agent = crate::integrations::codes::record_name(Some(&target.name), &target.vm_id);
        let who = if on_firewall {
            "the firewall with its repair commands (restart services, free disk space, rerun the update)".to_string()
        } else {
            format!("the agent {agent} with root access")
        };
        let parts = crate::core::code_message::CodeParts {
            ask: if capture_.is_some() {
                format!("Let {cli_name} read {who} to write a template from it, for up to {window}")
            } else if let Some((f, st)) = &repair_ {
                format!(
                    "Let {cli_name} repair {} on {who} for up to {window}",
                    repair::repair_subject(f, st)
                )
            } else {
                format!("Let {cli_name} repair {who} for up to 2 hours")
            },
            typed: vec![crate::core::code_message::TypedLine {
                label: "Paid with".into(),
                text: credential.label.to_string(),
                more: None,
            }],
            ..Default::default()
        };
        let summary = if capture_.is_some() {
            format!(
                "Let {cli_name} read {agent} with root access to write a template from it, using {}, for up to {window}",
                credential.label
            )
        } else if let Some((f, st)) = &repair_ {
            format!(
                "Let {cli_name} repair {} on {agent} with root access, using {}, for up to {window}",
                repair::repair_subject(f, st),
                credential.label
            )
        } else if on_firewall {
            format!(
                "Let {cli_name} repair the firewall with its repair commands (restart services, free disk space, rerun the update) using {} for up to 2 hours",
                credential.label
            )
        } else {
            format!(
                "Let {cli_name} repair {agent} with root access using {} for up to 2 hours",
                credential.label
            )
        };
        // Real recipients only, even on a development box. Root access has no first-use shortcut.
        let routes: Vec<Value> = routes
            .into_iter()
            .filter_map(|mut r| {
                let senders: Vec<Value> = r
                    .get("senders")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|x| x.get("type") != Some(&json!("dev")))
                    .cloned()
                    .collect();
                if senders.is_empty() {
                    return None;
                }
                r["senders"] = Value::Array(senders);
                Some(r)
            })
            .collect();
        // The recovery key's sealed challenge is W3's (`RecoveryConfirm`), not in the contract yet:
        // with nobody to send to, the proposal is refused.
        if routes.is_empty() {
            let m = if template_repair || template_capture {
                "Nobody is approved on a channel of this organization, so there is nobody to send the code to. Approve someone on a channel first.".to_string()
            } else {
                "Nobody is set to get confirmation codes. Add somebody on the Firewall page. Doctor has no first-use shortcut.".to_string()
            };
            return Ok(outcome(
                false,
                "failed",
                Some(m),
                with(d, json!({"noRecipients": true})),
            ));
        }
        let proposal = Proposal {
            target: target.clone(),
            cli,
            credential_id: credential_id.clone(),
            model: model.clone(),
            summary: summary.clone(),
            preset,
            repair: repair_.clone(),
            capture: capture_.clone(),
        };
        let tool_spec = fw.filter(|_| on_firewall).map(|f| ToolSpec {
            make: f.tools.clone(),
            url_env: "CC_FWDOCTOR_URL",
            token_env: "CC_FWDOCTOR_TOKEN",
            target: "firewall",
        });
        let now = self.now();
        let s = Session {
            id: id.clone(),
            vm_id: vm_id.clone(),
            kind: kind.clone(),
            state: "proposed",
            expires_at: now + 10 * 60_000,
            mode: "chat",
            proposal: proposal.clone(),
            codes: codes.clone(),
            touched_at: now,
            busy: false,
            generation: 0,
            resume_id: None,
            seq: 0,
            end_reason: None,
            dirty: false,
            uploading: false,
            sent_via: None,
            storage_failed: false,
            secrets: HashSet::new(),
            gateway: None,
            tools: None,
            tools_url: None,
            tool_spec,
            last_text: None,
            tools_checked: false,
            preempted: false,
            ending: false,
            started_by: started_by.map(String::from),
            created: false,
        };
        // A full disk is one of the things a firewall repair fixes: free the reserve first.
        if on_firewall && let Some(r) = fw.and_then(|f| f.reserve.as_ref()) {
            r.release();
        }
        // Reserved before the code goes out, so two proposals cannot both be granted.
        let record = repair_.as_ref().map(|(f, st)| RepairRecord {
            template: f.template.clone(),
            hash: f.hash.clone(),
            step: st.clone(),
            ..Default::default()
        });
        if self.o.store.create(&id, &vm_id, &kind, record).is_err() {
            if on_firewall && let Some(r) = fw.and_then(|f| f.reserve.as_ref()) {
                r.restore();
            }
            return Err(());
        }
        let s: S = Arc::new(Mutex::new(s));
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((id.clone(), s.clone()));
        let change = json!({"changeId": id, "kind": kind, "vmId": vm_id, "cli": cli.as_str(), "credentialId": credential_id, "model": model, "summary": summary});
        let subject = if on_firewall {
            target.name.clone()
        } else {
            agent.clone()
        };
        match codes
            .send_parts(&id, change, &subject, &summary, routes, Some(parts))
            .await
        {
            Ok(sent) => Ok(outcome(
                true,
                "awaiting_code",
                None,
                with(
                    d,
                    json!({"summary": summary, "sentVia": sent.sent_via, "expiresAt": sent.expires_at, "attemptsLeft": sent.attempts_left}),
                ),
            )),
            Err(_) => {
                self.drop_session(&s);
                let m = if template_repair || template_capture {
                    "No approved channel could deliver the code. Check the organization's channels and try again."
                } else if on_firewall {
                    "No approved channel could deliver the doctor code, and the organization has no recovery key."
                } else {
                    "No approved channel could deliver the doctor code. Recovery-key confirmation is available only when the agent is not responding and the organization has a recovery key."
                };
                Ok(outcome(false, "failed", Some(m.into()), Some(d)))
            }
        }
    }

    async fn confirm(self: &Arc<Self>, id: &str, code: &str) -> Result<CommandOutcome, ()> {
        let d = data(id);
        let Some(s) = self
            .get(id)
            .filter(|s| s.lock().unwrap_or_else(|e| e.into_inner()).state == "proposed")
        else {
            return Ok(outcome(
                false,
                "expired",
                Some("No doctor session is waiting for this code.".into()),
                Some(d),
            ));
        };
        let codes = s.lock().unwrap_or_else(|e| e.into_inner()).codes.clone();
        let sent_via = match codes.verify(id, code) {
            Verified::Expired => {
                self.drop_session(&s);
                return Ok(outcome(false, "expired", None, Some(d)));
            }
            Verified::Invalid { attempts_left } => {
                if attempts_left == 0 {
                    self.drop_session(&s);
                }
                return Ok(outcome(
                    false,
                    "invalid_code",
                    None,
                    with(d, json!({"attemptsLeft": attempts_left})),
                ));
            }
            Verified::Ok { sent_via, .. } => sent_via,
        };
        // A person's repair comes before a Final check: a running check gives way now.
        for c in self.all() {
            let running = {
                let c = c.lock().unwrap_or_else(|e| e.into_inner());
                c.kind == "template-check" && (c.state == "running" || c.busy)
            };
            if running {
                c.lock().unwrap_or_else(|e| e.into_inner()).preempted = true;
                self.end(&c, "ended", CHECK_PREEMPTED).await;
            }
        }
        let (cli, cred_id, model) = {
            let now = self.now();
            let window = self.o.window_ms.unwrap_or(DOCTOR_WINDOW_MS);
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.state = "running";
            g.sent_via = Some(sent_via.clone());
            let cap = if g.proposal.repair.is_some() {
                REPAIR_WINDOW_MS
            } else if g.proposal.capture.is_some() {
                CAPTURE_WINDOW_MS
            } else {
                DOCTOR_WINDOW_MS
            };
            g.expires_at = now + window.min(cap);
            g.touched_at = now;
            (
                g.proposal.cli,
                g.proposal.credential_id.clone(),
                g.proposal.model.clone(),
            )
        };
        let creds = match self.credential(cli, &cred_id, &model).await {
            Ok(c) => c,
            Err(_) => {
                self.end(&s, "failed", "The selected credential is unavailable or expired.")
                    .await;
                return Ok(outcome(false, "failed", None, Some(d)));
            }
        };
        if !self.touch(id) {
            return Ok(outcome(false, "expired", None, Some(d)));
        }
        let (first, expires, summary) = {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(e) = creds.expires_at {
                g.expires_at = g.expires_at.min(e - 30_000);
            }
            let first = if let Some(p) = g.proposal.preset {
                FIREWALL_PRESETS
                    .iter()
                    .find(|(n, _)| *n == p)
                    .map(|(_, t)| t.to_string())
            } else if let Some(base) = &g.proposal.capture {
                Some(capture::capture_prompt(base, id))
            } else {
                g.proposal
                    .repair
                    .as_ref()
                    .map(|(f, st)| repair::repair_prompt(f, st, id))
            };
            (first, g.expires_at, g.proposal.summary.clone())
        };
        self.emit(&s, "status", "Doctor session started.");
        // A preset, a capture or a repair starts with the firewall's own first message.
        if let Some(text) = first {
            self.emit(&s, "user", &text);
            let me = self.clone();
            let s2 = s.clone();
            tokio::spawn(async move { me.launch(s2, text, None).await });
        }
        Ok(outcome(
            true,
            "running",
            None,
            with(
                d,
                json!({"expiresAt": js::iso(expires), "sentVia": sent_via, "summary": summary}),
            ),
        ))
    }

    /// A person's message in the chat.
    pub async fn reply(self: &Arc<Self>, id: &str, text: &str) -> CommandOutcome {
        let _one = self.commands.lock().await;
        let text = string(Some(&Value::String(text.into())), 8000);
        self.message(id, &text).await
    }

    async fn message(self: &Arc<Self>, id: &str, text: &str) -> CommandOutcome {
        let d = data(id);
        let Some(s) = self.get(id).filter(|_| self.touch(id)) else {
            return outcome(false, "expired", None, Some(d));
        };
        // A Final check is one turn the firewall wrote: nobody talks to it.
        if s.lock().unwrap_or_else(|e| e.into_inner()).kind == "template-check" {
            return outcome(
                false,
                "failed",
                Some("A test takes no messages. Start Doctor to talk to a coding agent.".into()),
                Some(d),
            );
        }
        if text.is_empty() {
            return outcome(false, "failed", Some("Write a message first.".into()), Some(d));
        }
        let terminal = s.lock().unwrap_or_else(|e| e.into_inner()).mode == "terminal";
        if terminal {
            s.lock().unwrap_or_else(|e| e.into_inner()).generation += 1;
            let _ = self.o.runner.stop(id, true).await;
            if !self.touch(id) {
                return outcome(false, "expired", None, Some(d));
            }
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.busy = false;
            g.mode = "chat";
        }
        if s.lock().unwrap_or_else(|e| e.into_inner()).busy {
            return outcome(
                false,
                "busy",
                Some("Wait for the current doctor turn to finish.".into()),
                Some(d),
            );
        }
        self.emit(&s, "user", text);
        let (me, s2, t) = (self.clone(), s.clone(), text.to_string());
        tokio::spawn(async move { me.launch(s2, t, None).await });
        outcome(true, "running", None, Some(d))
    }

    /// The transcript as the chat shows it: masked with everything this firewall keeps secret now.
    #[cfg(test)]
    pub fn transcript(&self, id: &str) -> Option<Value> {
        self.transcript_after(id, 0, usize::MAX)
    }

    /// The transcript with only the events after `cursor`, at most `limit`: the chat's stream asks
    /// every second, and only what it sends is masked.
    pub fn transcript_after(&self, id: &str, cursor: u64, limit: usize) -> Option<Value> {
        let record = self.o.store.get(id).ok().flatten()?;
        let s = self.get(id);
        let mut secrets: Vec<String> = self.all_secrets();
        let (state, busy) = match &s {
            Some(s) => {
                let g = s.lock().unwrap_or_else(|e| e.into_inner());
                secrets.extend(g.secrets.iter().cloned());
                (g.state.to_string(), g.busy)
            }
            None => (
                if matches!(record.state.as_str(), "running" | "proposed") {
                    "ended".into()
                } else {
                    record.state.clone()
                },
                false,
            ),
        };
        let kind = record
            .kind
            .clone()
            .unwrap_or_else(|| repair_kind(self.o.firewall.as_ref().is_some_and(|f| f.vm_id == record.vm_id)).into());
        let events: Vec<Event> = record
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .take(limit)
            .map(|e| Event {
                text: stream::redact_text(&e.text, secrets.iter()),
                ..e.clone()
            })
            .collect();
        let mut v = as_map(serde_json::to_value(&record).unwrap_or(Value::Null));
        v.insert("kind".into(), json!(kind));
        v.insert("state".into(), json!(state));
        v.insert("busy".into(), json!(busy));
        v.insert("events".into(), serde_json::to_value(events).unwrap_or(Value::Null));
        Some(Value::Object(v))
    }

    pub fn record(&self, id: &str) -> Option<Transcript> {
        self.o.store.get(id).ok().flatten()
    }

    pub async fn delete_transcript(self: &Arc<Self>, id: &str) -> Result<(), String> {
        let _one = self.commands.lock().await;
        self.stop(id).await;
        if self
            .get(id)
            .is_some_and(|s| s.lock().unwrap_or_else(|e| e.into_inner()).busy)
        {
            return Err("Doctor is still stopping. Try again.".into());
        }
        self.o.store.delete(id)
    }

    fn active_fn(&self, s: &S) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let (s, now, idle) = (s.clone(), self.o.now.clone(), self.idle());
        Arc::new(move || {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            let n = now();
            g.state == "running" && n < g.expires_at && n - g.touched_at < idle
        })
    }

    /// Whether the session `s` still runs turn `generation`.
    fn current(&self, s: &S, generation: u64) -> bool {
        let id = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            if g.generation != generation || g.state != "running" {
                return false;
            }
            g.id.clone()
        };
        self.touch(&id)
    }

    async fn launch(self: Arc<Self>, s: S, problem: String, prepared: Option<DoctorCredentials>) {
        let id = s.lock().unwrap_or_else(|e| e.into_inner()).id.clone();
        if !self.touch(&id) {
            return;
        }
        let generation = {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.busy = true;
            g.generation += 1;
            g.generation
        };
        let result = self.clone().turn(&s, problem, prepared, generation).await;
        if result.is_err() {
            let (still, near) = {
                let g = s.lock().unwrap_or_else(|e| e.into_inner());
                (
                    g.generation == generation && g.state == "running",
                    self.now() >= g.expires_at - 1_000,
                )
            };
            if still {
                // RuntimeMaxSec receives whole seconds, rounded down to keep the hard deadline.
                if near {
                    self.end(&s, "ended", "Doctor session window expired.").await;
                } else {
                    self.end(&s, "failed", "The doctor turn failed.").await;
                }
            }
        }
    }

    async fn turn(
        self: Arc<Self>,
        s: &S,
        problem: String,
        prepared: Option<DoctorCredentials>,
        generation: u64,
    ) -> Result<(), ()> {
        let (cli, cred_id, model, spec, mode, kind, target, resume, id) = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            (
                g.proposal.cli,
                g.proposal.credential_id.clone(),
                g.proposal.model.clone(),
                g.tool_spec.clone(),
                g.mode,
                g.kind.clone(),
                g.proposal.target.clone(),
                g.resume_id.clone(),
                g.id.clone(),
            )
        };
        let creds = match prepared {
            Some(c) => c,
            None => self.credential(cli, &cred_id, &model).await.map_err(|_| ())?,
        };
        if !self.current(s, generation) {
            return Ok(());
        }
        // The agents' SSH key never enters a tool-only session.
        let key = if spec.is_some() {
            String::new()
        } else {
            (self.o.private_key)()
        };
        let check = spec.as_ref().is_some_and(|t| t.target == "check");
        {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            for v in self.all_secrets() {
                g.secrets.insert(v);
            }
            for v in creds.env.values().flat_map(|v| stream::secret_lines(v)) {
                g.secrets.insert(v);
            }
            if !key.is_empty() {
                for v in stream::secret_lines(&key) {
                    g.secrets.insert(v);
                }
            }
        }
        // A Final check gets no part of the credential: not the key, not the provider's address.
        let mut env: BTreeMap<String, String> = if check { BTreeMap::new() } else { creds.env.clone() };
        let previous = s.lock().unwrap_or_else(|e| e.into_inner()).gateway.take();
        if let Some(gw) = previous {
            gw.close();
        }
        if !self.current(s, generation) {
            return Ok(());
        }
        let active = self.active_fn(s);
        // Its unit has no network: the tool and the model are two unix sockets in a folder of its own.
        let sockets = if check {
            Some(self.check_sockets(&id).map_err(|_| ())?)
        } else {
            None
        };
        if let Some(spec) = &spec {
            let have = s.lock().unwrap_or_else(|e| e.into_inner()).tools.clone();
            let tools = match have {
                Some(t) => t,
                None => {
                    let t = (spec.make)(active.clone());
                    // On the session before it listens, as the TS sets `s.tools` first: an end during
                    // the start finds it and closes it.
                    s.lock().unwrap_or_else(|e| e.into_inner()).tools = Some(t.clone());
                    let url = t
                        .start(sockets.as_ref().map(|x| x.tools.clone()))
                        .await
                        .map_err(|_| ())?;
                    if !self.current(s, generation) {
                        t.close().await;
                        return Ok(());
                    }
                    s.lock().unwrap_or_else(|e| e.into_inner()).tools_url = Some(url);
                    t
                }
            };
            let url = s
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .tools_url
                .clone()
                .unwrap_or_default();
            if !check {
                env.insert(spec.url_env.into(), url);
            }
            env.insert(spec.token_env.into(), tools.token());
            s.lock()
                .unwrap_or_else(|e| e.into_inner())
                .secrets
                .insert(tools.token());
            if !self.current(s, generation) {
                return Ok(());
            }
        }
        if creds.included_models.is_some() || check {
            let upstream: Option<Upstream> = match creds.provider {
                "anthropic" => Some(ANTHROPIC),
                "gateway" => Some(AI_GATEWAY),
                _ => None,
            };
            if check && upstream.is_none() {
                return Err(());
            }
            let (me, model2, cid) = (self.clone(), model.clone(), cred_id.clone());
            let gateway = DoctorGateway::new(super::gateway::Options {
                active: active.clone(),
                upstream: if check { upstream } else { None },
                strict: check.then_some(CHECK_MAX_MODEL_REQUESTS),
                base_override: self.o.gateway_base.clone(),
                credential: Arc::new(move || {
                    let (me, model, cid) = (me.clone(), model2.clone(), cid.clone());
                    Box::pin(async move {
                        let current = me.credential(cli, &cid, &model).await.ok()?;
                        let key = current
                            .env
                            .get("OPENAI_API_KEY")
                            .or(current.env.get("ANTHROPIC_AUTH_TOKEN"))
                            .or(current.env.get("ANTHROPIC_API_KEY"))
                            .cloned()
                            .unwrap_or_default();
                        // A check uses the one model that was chosen, also where the plan includes more.
                        match current.included_models.filter(|m| !m.is_empty()) {
                            Some(m) => Some(GatewayCredential {
                                key,
                                allowed_models: if check {
                                    m.into_iter().filter(|x| *x == model).collect()
                                } else {
                                    m
                                },
                            }),
                            None if check && !key.is_empty() => Some(GatewayCredential {
                                key,
                                allowed_models: vec![model],
                            }),
                            None => None,
                        }
                    })
                }),
            });
            s.lock().unwrap_or_else(|e| e.into_inner()).gateway = Some(gateway.clone());
            let base = gateway
                .start(sockets.as_ref().map(|x| std::path::Path::new(&x.model)))
                .await
                .map_err(|_| ())?;
            if !self.current(s, generation) {
                gateway.close();
                return Ok(());
            }
            // Inside a check's own network namespace the bridge answers at a fixed loopback address.
            if cli == Cli::Claude {
                env.insert(
                    "ANTHROPIC_BASE_URL".into(),
                    if check { CHECK_MODEL_URL.into() } else { base },
                );
                env.insert("ANTHROPIC_AUTH_TOKEN".into(), gateway.token.clone());
            } else {
                env.insert("OPENAI_BASE_URL".into(), format!("{base}/v1"));
                env.insert("OPENAI_API_KEY".into(), gateway.token.clone());
            }
            s.lock()
                .unwrap_or_else(|e| e.into_inner())
                .secrets
                .insert(gateway.token.clone());
        }
        let parser = Arc::new(Mutex::new(DoctorStream::new(cli)));
        let (me, s2, p2) = (self.clone(), s.clone(), parser.clone());
        let output: super::runner::Output = Box::new(move |chunk: &str| {
            let out = p2.lock().unwrap_or_else(|e| e.into_inner()).write(chunk);
            me.take(&s2, generation, out, check);
        });
        let seconds = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            let until = creds
                .expires_at
                .map(|e| g.expires_at.min(e - 30_000))
                .unwrap_or(g.expires_at);
            ((until - self.now()) / 1000).max(1)
        };
        let mut agent = serde_json::to_value(&target).unwrap_or(Value::Null);
        if let Some(o) = agent.as_object_mut()
            && target.kind.is_none()
        {
            o.remove("kind");
        }
        let input = RunInput {
            session_id: id.clone(),
            cli: cli.as_str().into(),
            mode: mode.into(),
            ssh_private_key: key,
            env,
            model: model.clone(),
            provider: creds.provider.into(),
            problem,
            agent,
            target: spec.as_ref().map(|t| t.target.to_string()),
            sockets,
            resume_id: resume,
            seconds,
        };
        // The unit starts under the session's lock and only while this turn is the session's: a stop
        // on another thread lands wholly before (and nothing starts) or wholly after (and stops it).
        let s3 = s.clone();
        let admit: super::runner::Admit = Box::new(move |spawn: &mut dyn FnMut() -> bool| {
            let g = s3.lock().unwrap_or_else(|e| e.into_inner());
            g.generation == generation && g.state == "running" && spawn()
        });
        let ran = self.o.runner.run(input, output, admit).await;
        let out = parser.lock().unwrap_or_else(|e| e.into_inner()).end();
        self.take(s, generation, out, check);
        let failed = parser.lock().unwrap_or_else(|e| e.into_inner()).failed;
        if ran.is_err() || failed {
            return Err(());
        }
        let (still, checked, mode) = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            (
                g.generation == generation && g.state == "running",
                g.tools_checked,
                g.mode,
            )
        };
        // A turn that never said what it started with is not one whose report is taken.
        if check && still && !checked {
            self.end(s, "failed", CHECK_WRONG_TOOLS).await;
            return Ok(());
        }
        if still {
            s.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
            if kind != "template-check" {
                let text = if mode == "chat" {
                    "Doctor is ready for your next message."
                } else {
                    "Live terminal opened."
                };
                self.emit(s, "status", text);
            }
        }
        Ok(())
    }

    /// What a chunk of output gave: events kept, the id to resume with, and a check's tool list.
    fn take(self: &Arc<Self>, s: &S, generation: u64, out: stream::Out, check: bool) {
        for item in out.items {
            if s.lock().unwrap_or_else(|e| e.into_inner()).generation != generation {
                return;
            }
            match item {
                stream::Item::Resume(id) => s.lock().unwrap_or_else(|e| e.into_inner()).resume_id = Some(id),
                stream::Item::Event(e) => {
                    {
                        let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
                        g.touched_at = self.now();
                        if e.kind == "text" {
                            let tail = tail_utf16(&e.text, CHECK_REPORT_TAIL);
                            g.last_text = Some(stream::redact_secrets(&tail, g.secrets.iter()));
                        }
                    }
                    self.emit_parsed(s, &e);
                }
                stream::Item::Init(init) if check => {
                    if tools_ok(&init) {
                        s.lock().unwrap_or_else(|e| e.into_inner()).tools_checked = true;
                        self.emit(s, "status", CHECK_TOOLS_OK);
                    } else {
                        // Stopped now, as the TS's `end` takes effect before its first await: the
                        // turn's own result is not the check's, and the check waits for this stop.
                        {
                            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
                            g.ending = true;
                            g.generation += 1;
                        }
                        let (me, s2) = (self.clone(), s.clone());
                        tokio::spawn(async move { me.end(&s2, "failed", CHECK_WRONG_TOOLS).await });
                    }
                }
                stream::Item::Init(_) => {}
            }
        }
    }

    // Used by the Final check (tplcheck, I7).
    /// One Final check: a session of kind `template-check` that needs no code here (its caller holds
    /// the organization's consent), has no SSH key, and runs one turn.
    pub async fn check(self: &Arc<Self>, input: CheckInput) -> CheckResult {
        let failed = CheckResult {
            outcome: "failed",
            text: String::new(),
        };
        let s = {
            let _one = self.commands.lock().await;
            // Nothing of a check is kept before the firewall's secrets can be masked out of it.
            if !ID.is_match(&input.session_id)
                || self.get(&input.session_id).is_some()
                || input.cli != Cli::Claude
                || self.app.contracts.firewall_secrets.get().is_none()
            {
                return failed;
            }
            let busy = self.all().iter().any(|s| {
                let g = s.lock().unwrap_or_else(|e| e.into_inner());
                matches!(g.state, "proposed" | "running") || g.busy
            });
            if busy {
                return CheckResult {
                    outcome: "busy",
                    text: String::new(),
                };
            }
            let Ok(creds) = self.credential(input.cli, &input.credential_id, &input.model).await else {
                return failed;
            };
            if !matches!(creds.provider, "anthropic" | "gateway") {
                return failed;
            }
            let now = self.now();
            let mut target = input.target.clone();
            target.kind = Some("agent".into());
            let s = Session {
                id: input.session_id.clone(),
                vm_id: input.target.vm_id.clone(),
                kind: "template-check".into(),
                state: "running",
                expires_at: now + (input.seconds.max(1) * 1000).min(DOCTOR_WINDOW_MS),
                mode: "chat",
                proposal: Proposal {
                    target,
                    cli: input.cli,
                    credential_id: input.credential_id.clone(),
                    model: input.model.clone(),
                    summary: String::new(),
                    preset: None,
                    repair: None,
                    capture: None,
                },
                codes: Arc::new(Codes::for_module(
                    &self.app,
                    "doctor",
                    &format!("doctor:{}", input.session_id),
                )),
                touched_at: now,
                busy: false,
                generation: 0,
                resume_id: None,
                seq: 0,
                end_reason: None,
                dirty: false,
                uploading: false,
                sent_via: None,
                storage_failed: false,
                secrets: HashSet::new(),
                gateway: None,
                tools: None,
                tools_url: None,
                tool_spec: Some(ToolSpec {
                    make: input.tools.clone(),
                    url_env: "",
                    token_env: "CC_TPLCHECK_TOKEN",
                    target: "check",
                }),
                last_text: None,
                tools_checked: false,
                preempted: false,
                ending: false,
                started_by: None,
                created: false,
            };
            if self
                .o
                .store
                .create(&input.session_id, &input.target.vm_id, "template-check", None)
                .is_err()
            {
                return failed;
            }
            let s: S = Arc::new(Mutex::new(s));
            self.sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((input.session_id.clone(), s.clone()));
            self.emit(&s, "status", "Test started.");
            self.emit(&s, "user", &input.prompt);
            s
        };
        self.clone().launch(s.clone(), input.prompt.clone(), None).await;
        // A stop started for what the check started with is waited for before its result is given.
        while s.lock().unwrap_or_else(|e| e.into_inner()).ending {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let finished = s.lock().unwrap_or_else(|e| e.into_inner()).state == "running";
        if finished {
            self.end(&s, "ended", "Test finished.").await;
        }
        let g = s.lock().unwrap_or_else(|e| e.into_inner());
        let outcome = if finished {
            "done"
        } else if g.preempted {
            "preempted"
        } else if g.state == "failed" {
            "failed"
        } else {
            "stopped"
        };
        CheckResult {
            outcome,
            text: if finished {
                g.last_text.clone().unwrap_or_default()
            } else {
                String::new()
            },
        }
    }

    // Used by the Final check (tplcheck, I7).
    /// A line this firewall adds to a kept transcript, such as a Final check's report as it was read.
    pub fn annotate(&self, id: &str, text: &str) {
        let Ok(Some(record)) = self.o.store.get(id) else { return };
        let seq = record.events.last().map(|e| e.seq).unwrap_or(0) + 1;
        if let Some(s) = self.get(id) {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.seq = g.seq.max(seq);
        }
        let secrets = self.all_secrets();
        let _ = self.o.store.append(
            id,
            Event {
                seq,
                kind: "status".into(),
                text: stream::redact_text(text, secrets.iter()),
                title: None,
            },
            &record.state,
        );
    }

    /// Open the live terminal: the chat turn stops and the session runs as a terminal.
    pub async fn terminal(self: &Arc<Self>, id: &str) -> Result<(), String> {
        let _one = self.commands.lock().await;
        let s = self
            .get(id)
            .filter(|_| self.touch(id))
            .ok_or("Doctor session expired.")?;
        let (kind, mode, cli, resume) = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            (g.kind.clone(), g.mode, g.proposal.cli, g.resume_id.clone())
        };
        if kind == "template-check" {
            return Err("A test has no terminal.".into());
        }
        if mode != "terminal" {
            if cli != Cli::Pi && resume.is_none() {
                return Err("Wait for the first doctor turn to initialize before opening the terminal.".into());
            }
            s.lock().unwrap_or_else(|e| e.into_inner()).generation += 1;
            let _ = self.o.runner.stop(id, true).await;
            if !self.touch(id) {
                return Err("Doctor session expired.".into());
            }
            {
                let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
                g.busy = false;
                g.mode = "terminal";
            }
            // `cc-doctor-run` in terminal mode returns once the unit is up: waited for, as the TS does.
            self.clone().launch(s.clone(), String::new(), None).await;
            if s.lock().unwrap_or_else(|e| e.into_inner()).state != "running" {
                return Err("Doctor terminal could not start.".into());
            }
        }
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>, id: &str) {
        match self.get(id) {
            Some(s) => {
                let live = {
                    let g = s.lock().unwrap_or_else(|e| e.into_inner());
                    g.busy || !matches!(g.state, "ended" | "failed")
                };
                if live {
                    self.end(&s, "ended", "Stopped by the owner.").await;
                } else {
                    let _ = self.o.runner.stop(id, false).await;
                }
            }
            None => {
                let _ = self.o.runner.stop(id, false).await;
            }
        }
    }

    fn secrets_of(&self, id: &str) -> HashSet<String> {
        if let Some(s) = self.get(id) {
            return s.lock().unwrap_or_else(|e| e.into_inner()).secrets.clone();
        }
        self.ended_secrets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(k, _)| k == id)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// Whether this process still holds the keys a session used. Not after a restart.
    fn knows_secrets(&self, id: &str) -> bool {
        self.get(id).is_some()
            || self
                .ended_secrets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .any(|(k, _)| k == id)
    }

    async fn end(self: &Arc<Self>, s: &S, state: &'static str, reason: &str) {
        let (id, gateway, tools, kind, firewall, repair, capture) = {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.ending = true;
            if g.proposal.repair.is_some() || g.proposal.capture.is_some() {
                let mut ended = self.ended_secrets.lock().unwrap_or_else(|e| e.into_inner());
                ended.retain(|(k, _)| *k != g.id);
                ended.push((g.id.clone(), g.secrets.clone()));
                let n = ended.len();
                if n > 50 {
                    ended.drain(..n - 50);
                }
            }
            g.codes.forget();
            g.generation += 1;
            g.state = state;
            g.busy = false;
            g.end_reason = Some(reason.into());
            g.dirty = true;
            g.tools_url = None;
            (
                g.id.clone(),
                g.gateway.take(),
                g.tools.take(),
                g.kind.clone(),
                g.proposal.target.kind.as_deref() == Some("firewall"),
                g.proposal.repair.is_some(),
                g.proposal.capture.is_some(),
            )
        };
        if let Some(gw) = gateway {
            gw.close();
        }
        if let Some(t) = tools {
            t.close().await;
        }
        if kind == "template-check" {
            let _ = std::fs::remove_dir_all(std::path::Path::new(&self.o.check_sockets_dir).join(&id));
        }
        if firewall && let Some(r) = self.o.firewall.as_ref().and_then(|f| f.reserve.as_ref()) {
            r.restore();
        }
        // A stop failure stays visible and is retried by tick. Never claim the unit ended before it did.
        if self.o.runner.stop(&id, false).await.is_err() {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.state = "failed";
            g.end_reason = Some("The firewall is retrying stopping the doctor unit.".into());
            g.busy = true;
        }
        let (text, confirmed, busy) = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            (g.end_reason.clone().unwrap_or_default(), g.sent_via.is_some(), g.busy)
        };
        self.emit(s, "status", &text);
        s.lock().unwrap_or_else(|e| e.into_inner()).ending = false;
        // What a repair or capture wrote is read once its unit is gone. Not awaited.
        if confirmed && !busy && (repair || capture) {
            let (me, id2) = (self.clone(), id.clone());
            tokio::spawn(async move {
                if repair {
                    me.read_repair(&id2).await;
                } else {
                    me.read_capture(&id2).await;
                }
            });
        }
    }

    /// The template a capture session wrote, asked of the agent and checked here. Kept with the
    /// transcript; nothing leaves this firewall here.
    pub async fn read_capture(&self, id: &str) -> Option<CaptureRecord> {
        if !self
            .reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(format!("c:{id}"))
        {
            return None;
        }
        let out = self.read_capture_now(id).await;
        self.reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&format!("c:{id}"));
        out
    }

    async fn read_capture_now(&self, id: &str) -> Option<CaptureRecord> {
        let record = self.o.store.get(id).ok().flatten()?;
        let kept = record.capture.clone()?;
        let mut secrets: Vec<String> = self.all_secrets();
        secrets.extend(self.secrets_of(id));
        let mut next = CaptureRecord {
            checked_at: Some(self.now()),
            sent_at: kept.sent_at,
            sent_hash: kept.sent_hash.clone(),
            ..Default::default()
        };
        if kept.sent_at.is_none() {
            next.sent_hash = None;
        }
        if !self.knows_secrets(id) {
            next.problems = Some(vec![SECRETS_FORGOTTEN.into()]);
            let _ = self.o.store.set_capture(id, next.clone());
            return Some(next);
        }
        let asked = match (self.target_of(&record.vm_id), self.app.contracts.agents.get()) {
            (Some(t), Some(c)) => tokio::time::timeout(
                REPAIR_DONE_TIMEOUT,
                c.post(&t.vm_id, "/templates/capture/done", json!({"sessionId": id})),
            )
            .await
            .ok()
            .and_then(Result::ok),
            _ => None,
        };
        match asked {
            None => {
                next.problems = Some(vec![
                "The agent did not answer, so the firewall could not read the template the session wrote. Try again."
                    .into(),
            ])
            }
            Some(raw) if raw.get("ok") == Some(&Value::Bool(false)) => {
                next.problems = Some(repair::read_repair_problems(raw.get("problems"), &secrets))
            }
            Some(raw) => {
                if let Some(pack) = raw.get("pack").filter(|p| !p.is_null()) {
                    match capture::read_capture_pack(pack, &secrets) {
                        Ok(p) => next.pack = Some(p),
                        Err(p) => next.problems = Some(p),
                    }
                }
            }
        }
        self.o.store.get(id).ok().flatten()?;
        let _ = self.o.store.set_capture(id, next.clone());
        Some(next)
    }

    /// Sends the kept draft to ControlClaw, as it is kept. Only from a person's press on this
    /// firewall's page; one send at a time.
    pub async fn send_capture(&self, id: &str, sent_by: &str, replace: bool) -> Value {
        let _one = self.sending.lock().await;
        let r = |ok: bool, m: Option<&str>, replace: bool| {
            let mut v = as_map(json!({"ok": ok}));
            if let Some(m) = m {
                v.insert("message".into(), json!(m));
            }
            if replace {
                v.insert("replace".into(), json!(true));
            }
            Value::Object(v)
        };
        let record = self.o.store.get(id).ok().flatten();
        let Some((record, pack, mut kept)) = record.and_then(|rec| {
            let c = rec.capture.clone()?;
            let p = c.pack.clone()?;
            Some((rec, p, c))
        }) else {
            return r(false, Some("There is nothing to send."), false);
        };
        let Some(send) = &self.o.send_draft else {
            return r(false, Some("There is nothing to send."), false);
        };
        if self.get(id).is_some_and(|s| {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.state == "running" || g.busy
        }) {
            return r(
                false,
                Some("Stop the session first. The draft is read again when it ends."),
                false,
            );
        }
        if !self.knows_secrets(id) {
            return r(false, Some(SECRETS_FORGOTTEN), false);
        }
        let mut secrets = self.all_secrets();
        secrets.extend(self.secrets_of(id));
        // Checked again now, against what this firewall keeps secret now.
        if let Err(problems) = capture::read_capture_pack(&serde_json::to_value(&pack).unwrap_or(Value::Null), &secrets)
        {
            kept.pack = None;
            kept.checked_at = Some(self.now());
            kept.problems = Some(problems);
            let _ = self.o.store.set_capture(id, kept);
            return r(
                false,
                Some("The draft holds a value this firewall keeps secret now, so it was not sent."),
                false,
            );
        }
        let mut body = as_map(json!({"sessionId": id, "vmId": record.vm_id, "sentBy": sent_by, "pack": pack}));
        if replace {
            body.insert("replace".into(), json!(true));
        }
        match send(Value::Object(body)).await {
            Err(SendError::Refused { message, replace }) => return r(false, Some(&message), replace),
            Err(_) => return r(false, Some("ControlClaw did not take the draft. Try again."), false),
            Ok(()) => {}
        }
        if let Ok(Some(now)) = self.o.store.get(id)
            && let Some(mut c) = now.capture
        {
            c.sent_at = Some(self.now());
            c.sent_hash = Some(capture::capture_hash(&pack));
            let _ = self.o.store.set_capture(id, c);
        }
        r(true, None, false)
    }

    /// What a repair changed in the template's files, asked of the agent and checked here.
    pub async fn read_repair(&self, id: &str) -> Option<RepairRecord> {
        if !self
            .reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(format!("r:{id}"))
        {
            return None;
        }
        let out = self.read_repair_now(id).await;
        self.reading
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&format!("r:{id}"));
        out
    }

    async fn read_repair_now(&self, id: &str) -> Option<RepairRecord> {
        let record = self.o.store.get(id).ok().flatten()?;
        let kept = record.repair.clone()?;
        let mut secrets = self.all_secrets();
        secrets.extend(self.secrets_of(id));
        let mut next = RepairRecord {
            template: kept.template.clone(),
            hash: kept.hash.clone(),
            step: kept.step.clone(),
            checked_at: Some(self.now()),
            sent_at: kept.sent_at,
            sent_hash: kept.sent_at.and(kept.sent_hash.clone()),
            ..Default::default()
        };
        if !self.knows_secrets(id) {
            next.problems = Some(vec![SECRETS_FORGOTTEN.into()]);
            let _ = self.o.store.set_repair(id, next.clone());
            return Some(next);
        }
        let asked = match (self.target_of(&record.vm_id), self.app.contracts.agents.get()) {
            (Some(t), Some(c)) => tokio::time::timeout(
                REPAIR_DONE_TIMEOUT,
                c.post(&t.vm_id, "/templates/repair/done", json!({"sessionId": id})),
            )
            .await
            .ok()
            .and_then(Result::ok),
            _ => None,
        };
        match asked {
            None => {
                next.problems = Some(vec![
                    "The agent did not answer, so the firewall could not read what the repair changed. Try again."
                        .into(),
                ])
            }
            Some(raw) if raw.get("ok") == Some(&Value::Bool(false)) => {
                next.problems = Some(repair::read_repair_problems(raw.get("problems"), &secrets))
            }
            Some(raw) => {
                if let Some(pack) = raw.get("pack").filter(|p| !p.is_null()) {
                    match repair::read_repair_pack(pack, &kept.hash, &secrets) {
                        Ok(p) => next.pack = Some(p),
                        Err(p) => next.problems = Some(p),
                    }
                }
            }
        }
        // Deleted while the agent was asked: nothing is written back.
        self.o.store.get(id).ok().flatten()?;
        let _ = self.o.store.set_repair(id, next.clone());
        Some(next)
    }

    /// Sends the kept pack to ControlClaw. Only from a person's press on this firewall's page.
    pub async fn send_repair(&self, id: &str, sent_by: &str) -> Value {
        let _one = self.sending.lock().await;
        let r = |ok: bool, m: Option<&str>| match m {
            Some(m) => json!({"ok": ok, "message": m}),
            None => json!({"ok": ok}),
        };
        let record = self.o.store.get(id).ok().flatten();
        let Some((record, pack, mut kept)) = record.and_then(|rec| {
            let k = rec.repair.clone()?;
            let p = k.pack.clone()?;
            Some((rec, p, k))
        }) else {
            return r(false, Some("There is nothing to send."));
        };
        let Some(send) = &self.o.propose else {
            return r(false, Some("There is nothing to send."));
        };
        if self.get(id).is_some_and(|s| {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            g.state == "running" || g.busy
        }) {
            return r(
                false,
                Some("Stop the repair first. The changes are read again when it ends."),
            );
        }
        if !self.knows_secrets(id) {
            return r(false, Some(SECRETS_FORGOTTEN));
        }
        let mut secrets = self.all_secrets();
        secrets.extend(self.secrets_of(id));
        if let Err(problems) = repair::read_repair_pack(
            &serde_json::to_value(&pack).unwrap_or(Value::Null),
            &kept.hash,
            &secrets,
        ) {
            kept.pack = None;
            kept.checked_at = Some(self.now());
            kept.problems = Some(problems);
            let _ = self.o.store.set_repair(id, kept);
            return r(
                false,
                Some("The changes hold a value this firewall keeps secret now, so they were not sent."),
            );
        }
        let body = json!({"sessionId": id, "vmId": record.vm_id, "template": kept.template, "step": kept.step, "sentBy": sent_by, "pack": pack});
        match send(body).await {
            Err(SendError::Refused { message, .. }) => return r(false, Some(&message)),
            Err(_) => return r(false, Some("ControlClaw did not take the proposal. Try again.")),
            Ok(()) => {}
        }
        if let Ok(Some(now)) = self.o.store.get(id)
            && let Some(mut k) = now.repair
        {
            k.sent_at = Some(self.now());
            k.sent_hash = Some(repair::pack_hash(&pack));
            let _ = self.o.store.set_repair(id, k);
        }
        r(true, None)
    }

    /// A Final check's own folder with its two sockets.
    fn check_sockets(&self, id: &str) -> Result<Sockets, String> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::path::Path::new(&self.o.check_sockets_dir).join(id);
        std::fs::DirBuilder::new()
            .mode(0o750)
            .create(&dir)
            .map_err(|_| "no socket folder".to_string())?;
        Ok(Sockets {
            tools: dir.join("tools.sock").display().to_string(),
            model: dir.join("model.sock").display().to_string(),
        })
    }

    fn emit(self: &Arc<Self>, s: &S, kind: &'static str, text: &str) {
        self.emit_parsed(
            s,
            &Parsed {
                kind,
                text: text.into(),
            },
        );
    }

    fn emit_parsed(self: &Arc<Self>, s: &S, e: &Parsed) {
        let secrets = self.all_secrets();
        let (id, seq, state, text) = {
            let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
            for v in secrets {
                g.secrets.insert(v);
            }
            if g.storage_failed {
                return;
            }
            g.seq += 1;
            let text = stream::redact_text(&e.text, g.secrets.iter());
            (g.id.clone(), g.seq, g.state, text)
        };
        if !matches!(self.o.store.get(&id), Ok(Some(_))) {
            return;
        }
        match self.o.store.append(
            &id,
            Event {
                seq,
                kind: e.kind.into(),
                text,
                title: None,
            },
            state,
        ) {
            Ok(()) => s.lock().unwrap_or_else(|e| e.into_inner()).dirty = true,
            Err(_) => {
                s.lock().unwrap_or_else(|e| e.into_inner()).storage_failed = true;
                let (me, s2) = (self.clone(), s.clone());
                tokio::spawn(async move {
                    me.end(&s2, "failed", "The firewall could not save the Doctor transcript.")
                        .await
                });
            }
        }
    }

    /// A proposal that will never run: forgotten, and a firewall repair's disk reserve given back.
    fn drop_session(self: &Arc<Self>, s: &S) {
        let (id, fw) = {
            let g = s.lock().unwrap_or_else(|e| e.into_inner());
            (g.id.clone(), g.proposal.target.kind.as_deref() == Some("firewall"))
        };
        self.forget(&id);
        if fw && let Some(r) = self.o.firewall.as_ref().and_then(|f| f.reserve.as_ref()) {
            r.restore();
        }
    }

    pub async fn tick(self: &Arc<Self>) {
        let now = self.now();
        if now >= self.next_prune.load(Ordering::SeqCst) {
            self.o.store.prune();
            self.next_prune.store(now + 60_000, Ordering::SeqCst);
        }
        for s in self.all() {
            let (state, expires, touched, busy) = {
                let g = s.lock().unwrap_or_else(|e| e.into_inner());
                (g.state, g.expires_at, g.touched_at, g.busy)
            };
            if state == "proposed" && now >= expires {
                s.lock().unwrap_or_else(|e| e.into_inner()).codes.forget();
                self.drop_session(&s);
            } else if state == "running" && (now >= expires || now - touched >= self.idle()) {
                let why = if now >= expires {
                    "Doctor session window expired."
                } else {
                    "Doctor session idle timeout."
                };
                self.end(&s, "ended", why).await;
            } else if state == "failed" && busy {
                self.end(&s, "failed", "Doctor session stopped after a runner error.")
                    .await;
            }
        }
    }

    /// The sessions' metadata to the console. Never content.
    pub async fn flush(self: &Arc<Self>) {
        for s in self.all() {
            let (id, kind, state, dirty, uploading, busy, ending, seq, end_reason, created) = {
                let g = s.lock().unwrap_or_else(|e| e.into_inner());
                let created = match (&g.started_by, g.created) {
                    (Some(by), false) => Some(json!({
                        "vmId": g.vm_id, "cli": g.proposal.cli.as_str(), "credentialId": g.proposal.credential_id, "model": g.proposal.model,
                        "summary": g.proposal.summary, "sentVia": g.sent_via.clone().unwrap_or_default(), "startedBy": by, "endsAt": js::iso(g.expires_at),
                    })),
                    _ => None,
                };
                (
                    g.id.clone(),
                    g.kind.clone(),
                    g.state,
                    g.dirty,
                    g.uploading,
                    g.busy,
                    g.ending,
                    g.seq,
                    g.end_reason.clone(),
                    created,
                )
            };
            // A Final check has no row in the console's Doctor table: its result goes with the beat.
            if kind == "template-check" {
                if !busy && !ending && matches!(state, "ended" | "failed") {
                    self.forget(&id);
                }
                continue;
            }
            if state == "proposed" || (state == "failed" && busy) || !dirty || uploading {
                continue;
            }
            s.lock().unwrap_or_else(|e| e.into_inner()).uploading = true;
            let sent_created = created.is_some();
            let up = (self.o.upload)(Upload {
                session_id: id.clone(),
                kind,
                state: state.into(),
                end_reason,
                created,
            })
            .await;
            match up {
                Ok(()) => {
                    let gone = {
                        let mut g = s.lock().unwrap_or_else(|e| e.into_inner());
                        if sent_created {
                            g.created = true;
                        }
                        g.dirty = g.seq != seq || g.state != state;
                        !g.dirty && !g.busy && matches!(g.state, "ended" | "failed")
                    };
                    if gone {
                        self.forget(&id);
                    }
                }
                // A repair started here that the console refused: end it at once and stop sending.
                Err(SendError::RefusedRepair) => {
                    self.end(&s, "failed", "ControlClaw refused this repair: whoever started it can no longer manage Doctor, or the agent is gone.").await;
                    self.forget(&id);
                }
                // Otherwise retry metadata only. Content stays in the encrypted store.
                Err(_) => {}
            }
            s.lock().unwrap_or_else(|e| e.into_inner()).uploading = false;
        }
    }
}

/// The last `n` UTF-16 units of `s` (`slice(-n)`).
fn tail_utf16(s: &str, n: usize) -> String {
    let units: Vec<u16> = s.encode_utf16().collect();
    if units.len() <= n {
        return s.to_string();
    }
    String::from_utf16_lossy(&units[units.len() - n..])
}

/// Claude Code's own account of what the model is offered: the one tool, and nothing else.
fn tools_ok(init: &Init) -> bool {
    let (Some(slash), Some(skills), Some(agents)) = (&init.slash, &init.skills, &init.agents) else {
        return false;
    };
    let extras = slash.len()
        + skills.len()
        + agents
            .iter()
            .filter(|a| !CHECK_BUILTIN_AGENTS.contains(&a.as_str()))
            .count();
    init.tools == [CHECK_TOOL] && init.mcp == [CHECK_MCP] && extras == 0
}

#[cfg(test)]
pub(crate) mod tests;
