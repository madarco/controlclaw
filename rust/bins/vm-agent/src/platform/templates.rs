//! The template chosen when this agent was created, and the templates, skills and notes an owner
//! asks for later (`templates.ts`). A port of the TS `TemplateService`, step for step: the agent asks
//! the console what it was given, runs `cc-runbook` (which stays TS) and reports ids, kinds and
//! statuses. On an agent with a firewall, an apply or an install the console asks for runs only with
//! the firewall's ticket, once, for exactly the files and values the code message showed.
//!
//! Every state file keeps the TS name and shape (`state/templates/…`), so a rollback finds them.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, send_json};
use hyper::Method;

use super::common::js_slice;
use super::common::{Deps, Flag};
use super::skill_files::{notes_locked, notes_place, notes_set_hash, read_notes_record, read_skill_record};
use super::skills::SkillsError;
use super::time::{iso_ms, now_ms, parse_iso_z};
use crate::app::App;
use crate::stages;

pub const TEMPLATE_POLL: Duration = Duration::from_secs(2 * 60);
pub const TEMPLATE_IDLE_POLL_MS: i64 = 15 * 60_000;
pub const TEMPLATE_VERIFY: Duration = Duration::from_secs(6 * 60 * 60);
const RUN_TIMEOUT: Duration = Duration::from_secs(45 * 60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CALL: Duration = Duration::from_secs(20);
const BUNDLE_MAX_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const UNPACK_TIMEOUT: Duration = Duration::from_secs(60);
const SKILL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_START_SKILLS: usize = 30;
const START_SKILLS_TRIES: u64 = 4;
const UNSURE_ROUNDS: u32 = 5;
pub const TEMPLATE_REVIEW_MS: i64 = 45 * 60_000;
pub const TEMPLATE_TICKET_MS: i64 = 30 * 60_000;
pub const AGENT_NAME_MAX: usize = 200;
pub const PENDING_NOTE_MAX: usize = 400;
const CHECKED_WHEN_APPLIED: &str = "checked when applied";
const MAX_BESIDE: usize = 20;
/// `SKILL_PAYLOAD_MAX_BYTES`: a skill at its limit as base64, with room for the JSON.
const SKILL_PAYLOAD_MAX_BYTES: usize = 1_333_334 + 256 * 1024;
/// `NOTES_PAYLOAD_MAX_BYTES`.
const NOTES_PAYLOAD_MAX_BYTES: usize = 2_000_000 * 2 + 512 * 1024;
const APPLIED_VARS: &str = "vars.json";
const PREVIEW_VARS: &str = "preview-vars.json";
const PROBE_VARS: &str = "probe-vars.json";
const BESIDE_VARS: &str = "beside-vars.json";

fn re(p: &str) -> Regex {
    Regex::new(p).expect("regex")
}

static TEMPLATE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,62}$"));
static REQUEST_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{8,64}$"));
static STEP_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)?$"));
static BUNDLE_HASH: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-f0-9]{64}$"));
static SKILL_NAME_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,63}$"));
static TIME_ZONE: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_+\-/]{1,64}$"));
static MCP_SERVER_NAME: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,39}$"));
static STAMP: LazyLock<Regex> = LazyLock::new(|| re(r"^[0-9TZ:.-]{1,48}$"));
static ORG_TEMPLATE_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^org-[a-z0-9]{8,40}$"));
static SKILL_PAYLOAD_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^sks-[a-z0-9]{8,40}$"));
static NOTES_PAYLOAD_ID: LazyLock<Regex> = LazyLock::new(|| re(r"^snt-[a-z0-9]{8,40}$"));
static NEWLINES: LazyLock<Regex> = LazyLock::new(|| re("[\r\n\u{2028}\u{2029}]+"));

pub fn is_org_template(id: &str) -> bool {
    ORG_TEMPLATE_ID.is_match(id)
}
pub fn is_skill_payload(id: &str) -> bool {
    SKILL_PAYLOAD_ID.is_match(id)
}
pub fn is_notes_payload(id: &str) -> bool {
    NOTES_PAYLOAD_ID.is_match(id)
}

fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// `overwriteTicket`: what a ticket names for an install over a copy changed on this agent.
pub fn overwrite_ticket(hash: &str) -> String {
    hex::encode(Sha256::digest(format!("{hash}\0overwrite").as_bytes()))
}

/// What a template's steps are filled with.
#[derive(Debug, Clone, PartialEq)]
pub struct Vars {
    pub note: String,
    pub name: String,
    pub time_zone: String,
}

impl Vars {
    fn json(&self) -> Value {
        json!({ "note": self.note, "name": self.name, "timeZone": self.time_zone })
    }
    fn of(v: Option<&Value>) -> Option<Self> {
        let v = v?;
        Some(Self {
            note: s(v, "note")?.into(),
            name: s(v, "name")?.into(),
            time_zone: s(v, "timeZone")?.into(),
        })
    }
}

/// `payloadHash`: one hash for the files and what their steps are filled with.
pub fn payload_hash(files: &str, vars: &Vars, beside: bool) -> String {
    let tag = if beside {
        "template-apply-v1-beside"
    } else {
        "template-apply-v1"
    };
    let what = json!([tag, files, vars.note, vars.name, vars.time_zone]);
    hex::encode(Sha256::digest(what.to_string().as_bytes()))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: String,
    pub kind: String,
    pub template: String,
    pub preview: Option<String>,
    pub steps: Vec<String>,
    pub run_id: Option<String>,
    pub bundle: Option<String>,
    pub look: bool,
    pub beside: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rerun {
    pub run_id: Option<String>,
    pub steps: Vec<String>,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartItem {
    pub payload: String,
    pub hash: String,
    pub run_id: Option<String>,
}

impl StartItem {
    fn json(&self) -> Value {
        json!({ "payload": self.payload, "hash": self.hash, "runId": self.run_id })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartSkills {
    pub id: String,
    pub items: Vec<StartItem>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Install {
    pub id: String,
    pub payload: String,
    pub hash: String,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Assignment {
    pub template: Option<String>,
    pub vars: Vars,
    pub run_id: Option<String>,
    pub rerun: Option<Rerun>,
    pub request: Option<Request>,
    pub bundle: Option<String>,
    pub capture: Option<String>,
    pub skill_capture: Option<(String, String)>,
    /// Some(x) when the console said `review` at all.
    pub review: Option<Option<String>>,
    pub skills: Option<StartSkills>,
    pub install: Option<Install>,
}

fn request_id(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|i| REQUEST_ID.is_match(i))
        .map(str::to_string)
}

fn bundle_hash(v: Option<&Value>) -> Option<String> {
    v.and_then(|b| b.get("hash"))
        .and_then(Value::as_str)
        .filter(|h| BUNDLE_HASH.is_match(h))
        .map(str::to_string)
}

fn step_ids(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().filter(|i| STEP_ID.is_match(i)).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `startSkillsOf`.
fn start_skills_of(v: Option<&Value>) -> Option<StartSkills> {
    let v = v?;
    let id = request_id(v.get("id"))?;
    let items: Vec<StartItem> = v
        .get("items")?
        .as_array()?
        .iter()
        .take(MAX_START_SKILLS)
        .filter_map(|e| {
            let payload = s(e, "payload").filter(|p| is_skill_payload(p) || is_notes_payload(p))?;
            let hash = s(e, "hash").filter(|h| BUNDLE_HASH.is_match(h))?;
            Some(StartItem {
                payload: payload.into(),
                hash: hash.into(),
                run_id: request_id(e.get("runId")),
            })
        })
        .collect();
    (!items.is_empty()).then_some(StartSkills { id, items })
}

/// `skillInstallOf`.
fn install_of(v: Option<&Value>) -> Option<Install> {
    let v = v?;
    Some(Install {
        id: request_id(v.get("id"))?,
        payload: s(v, "payload")
            .filter(|p| is_skill_payload(p) || is_notes_payload(p))?
            .into(),
        hash: s(v, "hash").filter(|h| BUNDLE_HASH.is_match(h))?.into(),
        run_id: request_id(v.get("runId")),
    })
}

/// `assignment()` reading of the console's answer.
pub fn parse_assignment(raw: &Value) -> Option<Assignment> {
    let raw = raw.as_object().map(|_| raw)?;
    let template = s(raw, "template")
        .filter(|t| TEMPLATE_ID.is_match(t))
        .map(str::to_string);
    let steps = step_ids(raw.get("rerun").and_then(|r| r.get("steps")));
    let request = raw.get("request").and_then(|a| {
        let id = request_id(a.get("id"))?;
        let kind = s(a, "kind").filter(|k| *k == "preview" || *k == "apply")?;
        let template = s(a, "template").filter(|t| TEMPLATE_ID.is_match(t))?;
        Some(Request {
            id,
            kind: kind.into(),
            template: template.into(),
            preview: request_id(a.get("preview")),
            steps: step_ids(a.get("steps")),
            run_id: s(a, "runId").map(str::to_string),
            bundle: bundle_hash(a.get("bundle")),
            look: kind == "preview" && a.get("look") == Some(&json!(true)),
            beside: a.get("beside") == Some(&json!(true)),
        })
    });
    let name = s(raw, "name")
        .map(|n| js_slice(&NEWLINES.replace_all(n, " "), AGENT_NAME_MAX))
        .unwrap_or_default();
    Some(Assignment {
        vars: Vars {
            note: s(raw, "note").unwrap_or_default().into(),
            name,
            time_zone: s(raw, "timeZone")
                .filter(|z| TIME_ZONE.is_match(z))
                .unwrap_or("UTC")
                .into(),
        },
        run_id: s(raw, "runId").map(str::to_string),
        rerun: (template.is_some() && !steps.is_empty()).then(|| {
            let r = &raw["rerun"];
            Rerun {
                run_id: s(r, "runId").map(str::to_string),
                steps,
                at: s(r, "at").map(|a| js_slice(a, 40)).unwrap_or_default(),
            }
        }),
        request,
        bundle: template.as_ref().and_then(|_| bundle_hash(raw.get("bundle"))),
        capture: raw.get("capture").and_then(|c| request_id(c.get("id"))),
        skill_capture: raw.get("skillCapture").and_then(|c| {
            Some((
                request_id(c.get("id"))?,
                s(c, "name").filter(|n| SKILL_NAME_RE.is_match(n))?.to_string(),
            ))
        }),
        review: raw
            .as_object()
            .and_then(|o| o.get("review"))
            .map(|r| r.as_str().filter(|t| TEMPLATE_ID.is_match(t)).map(str::to_string)),
        skills: start_skills_of(raw.get("skills")),
        install: install_of(raw.get("install")),
        template,
    })
}

/// A file a previewed template would keep, with the template's text for it (`cc-runbook review`).
fn review_files_of(raw: Option<&Value>) -> Vec<Value> {
    raw.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|f| {
            let step = s(f, "step").filter(|i| STEP_ID.is_match(i))?;
            let path = s(f, "path")?;
            let text = s(f, "text")?;
            if path.is_empty() || path.starts_with('/') || path.split('/').any(|p| p == "..") {
                return None;
            }
            Some(json!({
                "step": step,
                "title": s(f, "title").map(|t| js_slice(t, 120)).unwrap_or_else(|| step.to_string()),
                "path": path,
                "text": text,
                "exists": f.get("exists") == Some(&json!(true)),
                "stamp": s(f, "stamp").filter(|t| STAMP.is_match(t)),
            }))
        })
        .collect()
}

/// `readTemplateReview`: what the last preview left for the Files page, while it is recent. W7's
/// `GET /files/template-review` reads it through the `template_review` contract.
pub fn read_template_review(state_dir: &Path) -> Option<Value> {
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(state_dir.join("review.json")).ok()?).ok()?;
    let template = s(&raw, "template").filter(|t| TEMPLATE_ID.is_match(t))?;
    let at = s(&raw, "at")?;
    let age = now_ms() - js_date(at)?;
    if !(0..TEMPLATE_REVIEW_MS).contains(&age) {
        return None;
    }
    let files: Vec<Value> = review_files_of(raw.get("files"))
        .into_iter()
        .map(|mut f| {
            if let Some(o) = f.as_object_mut() {
                o.remove("stamp");
            }
            f
        })
        .collect();
    (!files.is_empty()).then(|| json!({ "template": template, "at": at, "files": files }))
}

/// W7's `template_review` contract: the review under this box's `state/templates`.
pub struct ReviewSlot {
    pub state_dir: PathBuf,
}

impl ReviewSlot {
    /// The template service's own state folder.
    pub fn of(app_state_dir: &Path) -> Self {
        Self {
            state_dir: app_state_dir.join("templates"),
        }
    }
}

impl crate::contracts::TemplateReview for ReviewSlot {
    fn template_review(&self) -> Option<Value> {
        read_template_review(&self.state_dir)
    }
}

/// `new Date(s).getTime()` for the times the agent itself wrote (ISO, `Z`).
fn js_date(s: &str) -> Option<i64> {
    parse_iso_z(s)
}

/// Where the template comes from: a folder, or why there is none.
#[derive(Debug, Clone, PartialEq)]
enum Folder {
    Dir(PathBuf),
    Missing,
    Broken,
    Unsure,
}

impl Folder {
    fn dir(&self) -> Option<&PathBuf> {
        match self {
            Folder::Dir(d) => Some(d),
            _ => None,
        }
    }
}

/// `cc-runbook facts`.
#[derive(Debug, Clone, PartialEq)]
struct Facts {
    name: String,
    hash: String,
    steps: Vec<(String, String)>,
    mcp: Vec<String>,
}

/// A console call that failed: its HTTP status when it answered.
#[derive(Debug, Clone, PartialEq)]
pub struct CallError {
    pub status: Option<u16>,
    pub message: String,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// What the runner printed and how it exited.
struct Ran {
    code: Option<i32>,
    stdout: String,
    ok: bool,
}

/// How this service talks to the console: `GET`/`POST /api/vm-agent/template<path>`, with the
/// box's token. A trait so tests can stand in for the console.
pub trait Console: Send + Sync {
    fn call(
        &self,
        method: &str,
        body: Option<Value>,
        path: String,
        max_bytes: usize,
    ) -> cc_http::BoxFuture<Result<Value, CallError>>;
}

/// The real console: `<base>/api/vm-agent/template…` over the box's HTTP client.
pub struct HttpConsole {
    pub base: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub token: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub http: cc_client::HttpClient,
}

impl Console for HttpConsole {
    fn call(
        &self,
        method: &str,
        body: Option<Value>,
        path: String,
        max_bytes: usize,
    ) -> cc_http::BoxFuture<Result<Value, CallError>> {
        let base = (self.base)();
        let token = (self.token)();
        let http = self.http.get();
        let method = method.to_string();
        Box::pin(async move {
            let base = base.ok_or_else(|| CallError {
                status: None,
                message: "no control plane address".into(),
            })?;
            let token = token.ok_or_else(|| CallError {
                status: None,
                message: "missing vm_id / vm_private_key.pem in KEYS_DIR".into(),
            })?;
            let url = format!("{base}/api/vm-agent/template{path}");
            let mut req = if method == "GET" {
                http.get(&url)
            } else {
                http.post(&url)
            }
            .bearer_auth(token)
            .timeout(CALL);
            if let Some(b) = &body {
                req = req.header("content-type", "application/json").body(b.to_string());
            }
            // Without the URL: it names this box's console.
            let res = req.send().await.map_err(|e| CallError {
                status: None,
                message: e.without_url().to_string(),
            })?;
            let status = res.status().as_u16();
            if !res.status().is_success() {
                return Err(CallError {
                    status: Some(status),
                    message: format!("control plane answered {status}"),
                });
            }
            let streamed = path.starts_with('/');
            let mut bytes = Vec::new();
            let mut res = res;
            // Read up to the limit and no further: the size is not taken on the sender's word.
            while let Some(chunk) = res.chunk().await.map_err(|e| CallError {
                status: None,
                message: e.without_url().to_string(),
            })? {
                bytes.extend_from_slice(&chunk);
                if streamed && bytes.len() > max_bytes {
                    return Err(CallError {
                        status: Some(413),
                        message: "the template is too large".into(),
                    });
                }
            }
            if streamed {
                return Ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()));
            }
            serde_json::from_slice(&bytes).map_err(|e| CallError {
                status: None,
                message: e.to_string(),
            })
        })
    }
}

pub struct TemplateOptions {
    pub console: Arc<dyn Console>,
    pub deps: Deps,
    /// `node` and the bundled runner.
    pub node: String,
    pub runbook: String,
    pub templates_dir: PathBuf,
    pub state_dir: PathBuf,
    pub home: PathBuf,
    /// Whether this agent holds its firewall's key (`mitm_pinned_pubkey.pem`).
    pub firewall: Arc<dyn Fn() -> bool + Send + Sync>,
    /// Whether this box is a new agent (the born stamp), asked on every attempt.
    pub is_new: Arc<dyn Fn() -> bool + Send + Sync>,
    pub verify_after: Duration,
    pub runbook_state_dir: PathBuf,
    pub notes_helper_there: Arc<dyn Fn() -> bool + Send + Sync>,
}

pub struct TemplateService {
    o: TemplateOptions,
    unsent: std::sync::Mutex<Option<Value>>,
    settled: AtomicBool,
    asked_at: AtomicU64,
    poked: AtomicBool,
    again: AtomicBool,
    running: AtomicBool,
    verifying: AtomicBool,
    unsure: AtomicU32,
    round: tokio::sync::Mutex<()>,
    /// The periodic check and a round never run at once (they share the unpack folder).
    exclusive: tokio::sync::Mutex<()>,
    /// The pending and ticket files: the firewall's routes run beside a round (the TS had one thread).
    files: std::sync::Mutex<()>,
}

/// A round or a check holds the template's unpack folder just now.
#[derive(Debug)]
pub struct Busy;

pub const BUSY: &str = "The agent is applying or checking its template just now. Ask again in a minute.";

fn lock<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn rm(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Reads a ticket and removes it, under the files lock: used up by reading it, whatever it says.
fn take_locked(files: &std::sync::Mutex<()>, path: &Path) -> Option<Value> {
    let _f = lock(files);
    let v = read_json(path);
    rm(path);
    v
}

fn rm_all(path: &Path) {
    let _ = std::fs::remove_dir_all(path);
    let _ = std::fs::remove_file(path);
}

impl TemplateService {
    pub fn new(o: TemplateOptions) -> Arc<Self> {
        let unsent = read_json(&o.state_dir.join("unsent.json")).filter(Value::is_object);
        Arc::new(Self {
            o,
            unsent: std::sync::Mutex::new(unsent),
            settled: AtomicBool::new(false),
            asked_at: AtomicU64::new(0),
            poked: AtomicBool::new(false),
            again: AtomicBool::new(false),
            running: AtomicBool::new(false),
            verifying: AtomicBool::new(false),
            unsure: AtomicU32::new(0),
            round: tokio::sync::Mutex::new(()),
            exclusive: tokio::sync::Mutex::new(()),
            files: std::sync::Mutex::new(()),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.o.state_dir.join(name)
    }

    fn log(&self, line: &str) {
        self.o.deps.log(&format!("[templates] {line}"));
    }

    /// `write`: tmp and rename, 0600, the folder 0700.
    fn write(&self, path: &Path, value: &Value) {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
            let _ = std::fs::set_permissions(d, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        }
        let _ = cc_store::write_atomic(path, value.to_string().as_bytes(), 0o600, cc_store::TmpName::Suffix);
    }

    fn coded(&self) -> bool {
        (self.o.firewall)()
    }

    fn fresh(at: Option<&str>, ms: i64) -> bool {
        let Some(t) = at.and_then(js_date) else { return false };
        let age = now_ms() - t;
        (0..ms).contains(&age)
    }

    /// The console's poke, remembered until a round asks.
    pub fn poke(&self) {
        self.poked.store(true, Ordering::SeqCst);
    }

    /// Whether to ask the console on this round.
    pub fn asks(&self) -> bool {
        if !self.settled.load(Ordering::SeqCst)
            || lock(&self.unsent).is_some()
            || self.poked.load(Ordering::SeqCst)
            || self.start_open()
        {
            return true;
        }
        now_ms() - self.asked_at.load(Ordering::SeqCst) as i64 >= TEMPLATE_IDLE_POLL_MS
    }

    fn keep(&self, result: Value) {
        *lock(&self.unsent) = Some(result.clone());
        self.write(&self.path("unsent.json"), &result);
    }

    async fn call(&self, method: &str, body: Option<Value>, path: &str, max: usize) -> Result<Value, CallError> {
        let path = if path.is_empty() && method == "GET" {
            let mut can =
                "templates_org,templates_steps2,templates_bundles,skills_start,skills_capture,notes_start".to_string();
            if self.coded() {
                can.push_str(",skills_apply");
                if (self.o.notes_helper_there)() {
                    can.push_str(",notes_apply");
                }
            }
            format!("?can={can}")
        } else {
            path.to_string()
        };
        self.o.console.call(method, body, path, max).await
    }

    /// The runner, its output held to `maxBuffer` (1 MB for `facts`, else 4 MB): more is a failure.
    async fn run(&self, args: Vec<String>, timeout: Duration) -> Ran {
        let max = if args.get(1).map(String::as_str) == Some("facts") {
            1024 * 1024
        } else {
            MAX_OUTPUT
        };
        let cmd = cc_proc::Cmd::new(&self.o.node)
            .args(args)
            .timeout(timeout)
            .env("HOME", self.o.home.to_string_lossy().to_string())
            .stdin(Vec::new());
        match self.o.deps.runner.run(cmd).await {
            Ok(out) if out.stdout.len() > max || out.stderr.len() > max => Ran {
                code: None,
                ok: false,
                stdout: String::new(),
            },
            Ok(out) => Ran {
                code: out.code,
                ok: out.success(),
                stdout: out.stdout_str(),
            },
            Err(_) => Ran {
                code: None,
                ok: false,
                stdout: String::new(),
            },
        }
    }

    fn marker(&self) -> Option<Value> {
        let raw = read_json(&self.path("applied.json"))?;
        let template = s(&raw, "template")?;
        let at = s(&raw, "at")?;
        let mut m = Map::new();
        m.insert("template".into(), json!(template));
        m.insert("at".into(), json!(at));
        if raw.get("missing").is_some_and(super::llm::truthy) {
            m.insert("missing".into(), json!(true));
        }
        for k in ["rerun", "request"] {
            if let Some(v) = s(&raw, k) {
                m.insert(k.into(), json!(v));
            }
        }
        if let Some(h) = s(&raw, "hash").filter(|h| BUNDLE_HASH.is_match(h)) {
            m.insert("hash".into(), json!(h));
        }
        if let Some(v) = Vars::of(raw.get("vars")) {
            m.insert("vars".into(), v.json());
        }
        Some(Value::Object(m))
    }

    /// The bundles applied beside the agent's template, oldest first.
    fn beside(&self) -> Vec<(String, Value)> {
        let Some(Value::Object(raw)) = read_json(&self.path("beside.json")) else {
            return Vec::new();
        };
        raw.into_iter()
            .filter_map(|(id, b)| {
                if !TEMPLATE_ID.is_match(&id) {
                    return None;
                }
                let vars = Vars::of(b.get("vars"))?;
                let at = s(&b, "at")?;
                let request = s(&b, "request")?;
                Some((
                    id,
                    json!({
                        "at": at,
                        "request": request,
                        "hash": s(&b, "hash").filter(|h| BUNDLE_HASH.is_match(h)),
                        "vars": vars.json(),
                        "name": s(&b, "name").filter(|n| TEMPLATE_ID.is_match(n)),
                    }),
                ))
            })
            .collect()
    }

    /// The folder a template runs from (see the TS `folder`). Err only when the console cannot be reached.
    async fn folder(&self, template: &str, hash: Option<&str>) -> Result<Folder, CallError> {
        if !is_org_template(template) {
            let dir = self.o.templates_dir.join(template);
            return Ok(if dir.join("template.yaml").exists() {
                Folder::Dir(dir)
            } else {
                Folder::Missing
            });
        }
        let Some(hash) = hash else { return Ok(Folder::Broken) };
        let org = self.path("org");
        let kept = org.join(format!("{template}.json"));
        let dir = org.join(template);
        let unpack = |again: bool| {
            let (kept, dir) = (kept.clone(), dir.clone());
            async move {
                let mut again = again;
                loop {
                    rm_all(&dir);
                    let r = self
                        .run(
                            vec![
                                self.o.runbook.clone(),
                                "unpack".into(),
                                kept.to_string_lossy().into(),
                                dir.to_string_lossy().into(),
                                "--hash".into(),
                                hash.into(),
                            ],
                            UNPACK_TIMEOUT,
                        )
                        .await;
                    if r.ok {
                        return (true, false);
                    }
                    rm_all(&dir);
                    // The runner's own answers: not the named files (3), not a valid template (64).
                    let certain = matches!(r.code, Some(3) | Some(64));
                    if certain || again {
                        return (false, certain);
                    }
                    again = true;
                }
            }
        };
        if kept.exists() {
            // A copy kept from before that does not unpack is fetched again.
            let (ok, _) = unpack(false).await;
            if ok {
                return Ok(Folder::Dir(dir));
            }
        }
        let text = match self
            .call("GET", None, &format!("/bundle?template={template}"), BUNDLE_MAX_BYTES)
            .await
        {
            Ok(v) => v.as_str().unwrap_or_default().to_string(),
            Err(e) if e.status == Some(404) => return Ok(Folder::Missing),
            Err(e) => return Err(e),
        };
        let _ = std::fs::create_dir_all(&org);
        let _ = std::fs::set_permissions(&org, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        if let Err(e) = cc_store::write_atomic(&kept, text.as_bytes(), 0o600, cc_store::TmpName::Suffix) {
            self.log(&format!(
                "{template}: its files could not be kept on this agent ({})",
                errno(&e)
            ));
            return Ok(Folder::Unsure);
        }
        let (ok, certain) = unpack(false).await;
        if ok {
            return Ok(Folder::Dir(dir));
        }
        if !certain {
            self.log(&format!("{template}: its files could not be unpacked just now"));
            return Ok(Folder::Unsure);
        }
        self.log(&format!(
            "{template}: the files are not the ones the console named, or do not pass the check"
        ));
        rm(&kept);
        Ok(Folder::Broken)
    }

    /// The runner, and what it printed for the console whatever its exit code.
    #[allow(clippy::too_many_arguments)]
    async fn runbook(
        &self,
        command: &str,
        template: &str,
        dir: &Path,
        vars: &Vars,
        run_id: Option<&str>,
        only: Option<&[String]>,
        no_scripts: bool,
        beside: bool,
    ) -> Option<Value> {
        let file = self.path(if command == "check" {
            PREVIEW_VARS
        } else if beside {
            BESIDE_VARS
        } else {
            APPLIED_VARS
        });
        self.write(&file, &vars.json());
        let mut args: Vec<String> = vec![
            self.o.runbook.clone(),
            if command == "check" {
                "run".into()
            } else {
                command.into()
            },
            dir.to_string_lossy().into(),
            "--vars".into(),
            file.to_string_lossy().into(),
            "--json".into(),
            "--public".into(),
        ];
        if is_org_template(template) {
            args.extend(["--as".into(), template.into()]);
        }
        if command == "check" {
            args.push("--check".into());
            if no_scripts {
                args.push("--no-scripts".into());
            }
            if let Some(o) = only {
                args.extend(["--only".into(), o.join(",")]);
            }
        }
        if beside && command != "verify" {
            for other in self.beside_folders(template, dir).await {
                args.extend(["--beside".into(), other.to_string_lossy().into()]);
            }
        }
        if command == "run" {
            args.push("--skip-unconfirmed".into());
            if let Some(r) = run_id.filter(|r| !r.is_empty()) {
                args.extend(["--run-id".into(), r.into()]);
            }
            if let Some(o) = only {
                args.extend(["--only".into(), o.join(",")]);
            }
        }
        if command != "check" {
            args.push("--repairs".into());
        }
        let r = self
            .run(args, if command == "run" { RUN_TIMEOUT } else { VERIFY_TIMEOUT })
            .await;
        let report: Value = serde_json::from_str(&r.stdout).ok()?;
        report.get("steps").is_some_and(Value::is_array).then_some(report)
    }

    async fn beside_folders(&self, template: &str, dir: &Path) -> Vec<PathBuf> {
        let at = |id: &str| {
            if is_org_template(id) {
                self.path("org").join(id)
            } else {
                self.o.templates_dir.join(id)
            }
        };
        let name = self.facts(dir).await.map(|f| f.name);
        let marker = self.marker();
        let mut ids: Vec<String> = Vec::new();
        if let Some(m) = &marker
            && m.get("missing").is_none()
        {
            ids.push(s(m, "template").unwrap_or_default().into());
        }
        for (id, b) in self.beside() {
            if id != template && name.as_deref().is_none_or(|n| s(&b, "name") != Some(n)) {
                ids.push(id);
            }
        }
        ids.into_iter()
            .filter(|id| id != template)
            .map(|id| at(&id))
            .filter(|f| f.join("template.yaml").exists())
            .collect()
    }

    async fn send(&self) -> Result<(), CallError> {
        let Some(body) = lock(&self.unsent).clone() else {
            return Ok(());
        };
        if let Err(e) = self.call("POST", Some(body), "", 0).await {
            // Refused for what it is: sending it again changes nothing.
            if !matches!(e.status, Some(400) | Some(413)) {
                return Err(e);
            }
            self.log(&format!(
                "the control plane refused the result ({}); not sent again",
                e.status.unwrap_or_default()
            ));
        }
        *lock(&self.unsent) = None;
        rm(&self.path("unsent.json"));
        Ok(())
    }

    async fn assignment(&self) -> Result<Option<Assignment>, CallError> {
        let raw = self.call("GET", None, "", 0).await?;
        Ok(parse_assignment(&raw))
    }

    /// One round: apply what is to apply, send what the console has not had. One at a time; a
    /// caller during a round waits for it. A poke during a round gets a round of its own.
    pub fn tick(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            let Ok(_round) = me.round.try_lock() else {
                let _wait = me.round.lock().await;
                return;
            };
            let _x = me.exclusive.lock().await;
            let running = Flag::on(&me.running);
            if let Err(e) = me.once().await {
                me.log(&format!("could not finish: {e}"));
            }
            drop(running);
            drop(_x);
            drop(_round);
            if me.poked.load(Ordering::SeqCst) && !me.again.swap(true, Ordering::SeqCst) {
                let again = me.clone();
                tokio::spawn(async move {
                    again.tick().await;
                    again.again.store(false, Ordering::SeqCst);
                });
            }
        })
    }

    async fn once(self: &Arc<Self>) -> Result<(), CallError> {
        if lock(&self.unsent).is_some() {
            self.send().await?;
        }
        self.poked.store(false, Ordering::SeqCst);
        let assignment = self.assignment().await?;
        self.asked_at.store(now_ms() as u64, Ordering::SeqCst);
        let Some(a) = assignment else { return Ok(()) };
        if let Some(marker) = self.marker() {
            self.settled.store(true, Ordering::SeqCst);
            if marker.get("missing").is_none() {
                self.rerun(&marker, &a).await?;
            }
        } else if let Some(t) = a.template.clone().filter(|_| self.coded() && !(self.o.is_new)()) {
            if !self.settled.load(Ordering::SeqCst) {
                self.log(&format!(
                    "{t} is named for this agent, which is no longer new: not applied without a confirmation code"
                ));
                self.keep(json!({ "kind": "run", "template": t, "unconfirmed": true }));
                self.send().await?;
            }
            self.settled.store(true, Ordering::SeqCst);
        } else if let Some(t) = a.template.clone() {
            self.apply(&t, &a.vars, a.run_id.as_deref(), None, a.bundle.as_deref(), None, false)
                .await?;
        } else {
            self.settled.store(true, Ordering::SeqCst);
        }
        let wanted = match &a.review {
            None => None,
            Some(Some(t)) => Some(Some(t.clone())),
            Some(None) => Some(
                a.request
                    .as_ref()
                    .filter(|r| r.kind == "preview")
                    .map(|r| r.template.clone()),
            ),
        };
        self.drop_review(wanted);
        if let Some(r) = &a.request {
            self.asked(r, &a).await?;
        }
        self.start_skills(a.skills.as_ref()).await?;
        self.install(a.install.as_ref()).await?;
        if let Some(c) = &a.capture {
            self.capture(c).await;
        }
        if let Some((id, name)) = &a.skill_capture {
            self.capture_skill(id, name).await;
        }
        let mut wanted: Vec<String> = Vec::new();
        wanted.extend(a.template.clone());
        wanted.extend(a.request.as_ref().map(|r| r.template.clone()));
        wanted.extend(self.marker().and_then(|m| s(&m, "template").map(str::to_string)));
        wanted.extend(self.beside().into_iter().map(|(id, _)| id));
        self.tidy(&wanted);
        Ok(())
    }

    /// Removes the copies of the organization's templates no longer had or asked about.
    fn tidy(&self, wanted: &[String]) {
        let Ok(rd) = std::fs::read_dir(self.path("org")) else {
            return;
        };
        for e in rd.filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            let base = name.trim_end_matches(".tmp").trim_end_matches(".json").to_string();
            if !wanted.contains(&base) {
                rm_all(&e.path());
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply(
        self: &Arc<Self>,
        template: &str,
        vars: &Vars,
        run_id: Option<&str>,
        request_id: Option<&str>,
        hash: Option<&str>,
        found: Option<Folder>,
        beside: bool,
    ) -> Result<(), CallError> {
        let folder = match found {
            Some(f) => f,
            None => self.folder(template, hash).await?,
        };
        if folder.dir().is_some() {
            self.drop_repair(template);
        }
        let now = iso_ms(now_ms());
        let mut from = Map::new();
        if let Some(r) = request_id {
            from.insert("request".into(), json!(r));
        }
        if let Some(h) = hash {
            from.insert("hash".into(), json!(h));
        }
        if folder == Folder::Unsure && request_id.is_none() && self.unsure.load(Ordering::SeqCst) < UNSURE_ROUNDS {
            let n = self.unsure.fetch_add(1, Ordering::SeqCst) + 1;
            self.log(&format!(
                "{template} could not be unpacked just now; trying again on the next round ({n} of {UNSURE_ROUNDS})"
            ));
            return Ok(());
        }
        let Some(dir) = folder.dir().cloned() else {
            self.log(&format!("{template} is not on this agent"));
            let mut result = json!({ "kind": "run", "template": template });
            result[if folder == Folder::Missing { "missing" } else { "broken" }] = json!(true);
            if let Some(r) = request_id {
                result["requestId"] = json!(r);
            }
            self.keep(result);
            if request_id.is_none() {
                let mut m = json!({ "template": template, "at": now, "missing": true });
                for (k, v) in from {
                    m[k] = v;
                }
                self.write(&self.path("applied.json"), &m);
            }
            self.settled.store(true, Ordering::SeqCst);
            return self.send().await;
        };
        if beside && let Some(request_id) = request_id {
            self.log(&format!("applying the bundle {template}"));
            let report = self
                .runbook("run", template, &dir, vars, run_id, None, false, true)
                .await;
            let mut result = json!({ "kind": "run", "template": template, "requestId": request_id });
            match &report {
                Some(r) => result["report"] = r.clone(),
                None => result["broken"] = json!(true),
            }
            self.keep(result);
            let Some(report) = report else {
                self.log(&format!("{template}: the runner gave no report"));
                return self.send().await;
            };
            let name = self.facts(&dir).await.map(|f| f.name);
            let others: Vec<(String, Value)> = self
                .beside()
                .into_iter()
                .filter(|(id, b)| id != template && name.as_deref().is_none_or(|n| s(b, "name") != Some(n)))
                .collect();
            let skip = others.len().saturating_sub(MAX_BESIDE - 1);
            let mut kept: Map<String, Value> = others.into_iter().skip(skip).collect();
            kept.insert(
                template.into(),
                json!({ "at": now, "request": request_id, "hash": hash, "name": name, "vars": vars.json() }),
            );
            self.write(&self.path("beside.json"), &Value::Object(kept));
            self.log(&format!(
                "applied the bundle {template}: {}",
                report
                    .get("result")
                    .map(js_string)
                    .unwrap_or_else(|| "undefined".into())
            ));
            self.verify_later();
            return self.send().await;
        }
        self.log(&format!("applying {template}"));
        let report = self
            .runbook("run", template, &dir, vars, run_id, None, false, false)
            .await;
        let mut result = json!({ "kind": "run", "template": template });
        match &report {
            Some(r) => result["report"] = r.clone(),
            None => result["broken"] = json!(true),
        }
        if let Some(r) = request_id {
            result["requestId"] = json!(r);
        }
        self.keep(result);
        let mut m = json!({ "template": template, "at": now });
        for (k, v) in from {
            m[k] = v;
        }
        m["vars"] = vars.json();
        self.write(&self.path("applied.json"), &m);
        // A bundle this template carries is the template's from now on.
        let carried: Vec<String> = std::fs::read_dir(dir.join("bundles"))
            .map(|rd| {
                rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let recorded = self.beside();
        if !carried.is_empty()
            && recorded
                .iter()
                .any(|(_, b)| s(b, "name").is_some_and(|n| carried.iter().any(|c| c == n)))
        {
            let kept: Map<String, Value> = recorded
                .into_iter()
                .filter(|(_, b)| s(b, "name").is_none_or(|n| !carried.iter().any(|c| c == n)))
                .collect();
            self.write(&self.path("beside.json"), &Value::Object(kept));
        }
        self.settled.store(true, Ordering::SeqCst);
        match &report {
            Some(r) => self.log(&format!(
                "applied {template}: {}",
                r.get("result").map(js_string).unwrap_or_else(|| "undefined".into())
            )),
            None => self.log(&format!("{template}: the runner gave no report")),
        }
        self.verify_later();
        self.send().await
    }

    fn verify_later(self: &Arc<Self>) {
        let me = self.clone();
        let after = self.o.verify_after;
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            me.verify().await;
        });
    }

    async fn capture_skill(&self, id: &str, name: &str) {
        let done = self.path("skill-capture.json");
        if read_json(&done)
            .and_then(|v| s(&v, "id").map(str::to_string))
            .as_deref()
            == Some(id)
        {
            return;
        }
        self.log(&format!(
            "reading the skill {name} of this agent's own, to be saved in the organization's skills"
        ));
        let mut body = json!({ "id": id, "skill": name, "failed": true });
        let r = self
            .run(
                vec![self.o.runbook.clone(), "capture".into(), "--skill".into(), name.into()],
                VERIFY_TIMEOUT,
            )
            .await;
        match serde_json::from_str::<Value>(&r.stdout) {
            Ok(read) if r.ok => {
                if let (Some(files), Some(left)) = (
                    read.get("files").filter(|f| f.is_array()),
                    read.get("leftOut").filter(|l| l.is_array()),
                ) {
                    body = if read.get("found") == Some(&json!(true)) {
                        json!({ "id": id, "skill": name, "observed": { "files": files, "leftOut": left } })
                    } else {
                        json!({ "id": id, "skill": name, "failed": true, "notFound": true, "leftOut": left })
                    };
                }
            }
            _ => self.log("could not read the skill: the runner failed"),
        }
        if let Err(e) = self.call("POST", Some(body), "/capture", BUNDLE_MAX_BYTES).await {
            self.log(&format!("the console did not take the skill that was read: {e}"));
            if e.status.is_none_or(|s| s >= 500) {
                return;
            }
        }
        self.write(&done, &json!({ "id": id }));
    }

    async fn capture(&self, id: &str) {
        let done = self.path("capture.json");
        if read_json(&done)
            .and_then(|v| s(&v, "id").map(str::to_string))
            .as_deref()
            == Some(id)
        {
            return;
        }
        self.log("reading this agent's setup for Save as template");
        let mut body = json!({ "id": id, "failed": true });
        let r = self
            .run(vec![self.o.runbook.clone(), "capture".into()], VERIFY_TIMEOUT)
            .await;
        match serde_json::from_str::<Value>(&r.stdout) {
            Ok(o)
                if r.ok
                    && ["files", "plugins", "config"]
                        .iter()
                        .all(|k| o.get(*k).is_some_and(Value::is_array)) =>
            {
                body = json!({ "id": id, "observed": o });
            }
            _ => self.log("could not read the setup: the runner failed"),
        }
        self.write(&done, &json!({ "id": id }));
        if let Err(e) = self.call("POST", Some(body), "/capture", BUNDLE_MAX_BYTES).await {
            self.log(&format!("the console did not take what was read: {e}"));
        }
    }

    /// `startLatch`: None when nothing was taken yet; a record that cannot be read is a closed one.
    fn start_latch(&self) -> Option<Latch> {
        let closed = Some(Latch {
            done: true,
            ..Latch::default()
        });
        let text = match std::fs::read_to_string(self.path("start-skills.json")) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => return closed,
        };
        let Ok(raw) = serde_json::from_str::<Value>(&text) else {
            return closed;
        };
        let parsed = start_skills_of(Some(&json!({ "id": raw.get("id"), "items": raw.get("items") })));
        let Some(p) = parsed else {
            return Some(Latch {
                id: s(&raw, "id").unwrap_or_default().into(),
                done: true,
                ..Latch::default()
            });
        };
        Some(Latch {
            id: p.id,
            at: s(&raw, "at").unwrap_or_default().into(),
            items: p.items,
            tries: raw.get("tries").and_then(Value::as_u64).unwrap_or(0),
            done: raw.get("done") == Some(&json!(true)),
        })
    }

    fn start_open(&self) -> bool {
        self.start_latch().is_some_and(|l| !l.done)
    }

    fn latch_json(id: &str, at: &str, items: &[StartItem], tries: u64, done: bool) -> Value {
        json!({ "id": id, "at": at, "items": items.iter().map(StartItem::json).collect::<Vec<_>>(), "tries": tries, "done": done })
    }

    /// The skills a new agent starts with: only while new, once, only what was named first.
    async fn start_skills(&self, named: Option<&StartSkills>) -> Result<(), CallError> {
        let latch = self.start_latch();
        if latch.as_ref().is_some_and(|l| l.done) {
            return Ok(());
        }
        let path = self.path("start-skills.json");
        if !(self.o.is_new)() {
            if let Some(l) = &latch {
                self.write(&path, &Self::latch_json(&l.id, &l.at, &l.items, l.tries, true));
            } else if let Some(n) = named {
                self.write(&path, &Self::latch_json(&n.id, &iso_ms(now_ms()), &n.items, 0, true));
                if let Err(e) = self
                    .call(
                        "POST",
                        Some(json!({ "kind": "skills", "requestId": n.id, "notNew": true, "skills": [] })),
                        "",
                        0,
                    )
                    .await
                {
                    self.log(&format!("the console was not told that this agent is not new: {e}"));
                }
            }
            return Ok(());
        }
        let (id, at, items, tries) = match latch {
            Some(l) => (l.id, l.at, l.items, l.tries),
            None => {
                let Some(n) = named else { return Ok(()) };
                let at = iso_ms(now_ms());
                self.write(&path, &Self::latch_json(&n.id, &at, &n.items, 0, false));
                (n.id.clone(), at, n.items.clone(), 0)
            }
        };
        self.log(&format!(
            "installing what this agent starts with: {} skill(s) or set(s) of notes",
            items.len()
        ));
        let mut results = Vec::new();
        for item in &items {
            let mut r = json!({ "payload": item.payload });
            for (k, v) in self
                .install_skill(item, "", None, Over::default())
                .await?
                .as_object()
                .cloned()
                .unwrap_or_default()
            {
                r[k] = v;
            }
            results.push(r);
        }
        let tries = tries + 1;
        let mut over = false;
        if let Err(e) = self
            .call(
                "POST",
                Some(json!({ "kind": "skills", "requestId": id, "skills": results })),
                "",
                0,
            )
            .await
        {
            if !matches!(e.status, Some(400) | Some(413)) {
                self.write(
                    &path,
                    &Self::latch_json(&id, &at, &items, tries, tries >= START_SKILLS_TRIES),
                );
                return Err(e);
            }
            self.log(&format!(
                "the control plane refused the skills result ({}); not sent again",
                e.status.unwrap_or_default()
            ));
            over = true;
        }
        let all_in = results.iter().all(|r| {
            r.pointer("/report/steps")
                .and_then(Value::as_array)
                .is_some_and(|steps| {
                    steps.iter().any(|s| {
                        matches!(
                            s.get("kind").and_then(Value::as_str),
                            Some("openclaw.skill" | "openclaw.notes")
                        ) && matches!(s.get("status").and_then(Value::as_str), Some("ok" | "changed"))
                    })
                })
        });
        self.write(
            &path,
            &Self::latch_json(&id, &at, &items, tries, over || all_in || tries >= START_SKILLS_TRIES),
        );
        Ok(())
    }

    /// One skill or set: fetched, checked and installed by the runner. Err only when the console
    /// cannot be reached. The answer is `{report}`, `{missing: true}` or `{broken: true}`.
    async fn install_skill(
        &self,
        item: &StartItem,
        run: &str,
        confirmed_name: Option<&str>,
        over: Over,
    ) -> Result<Value, CallError> {
        let notes = is_notes_payload(&item.payload);
        let max = if notes {
            NOTES_PAYLOAD_MAX_BYTES
        } else {
            SKILL_PAYLOAD_MAX_BYTES
        };
        let text = match self
            .call("GET", None, &format!("/bundle?template={}", item.payload), max)
            .await
        {
            Ok(v) => v.as_str().unwrap_or_default().to_string(),
            Err(e) if e.status == Some(404) => return Ok(json!({ "missing": true })),
            Err(e) if e.status == Some(413) => return Ok(json!({ "broken": true })),
            Err(e) => return Err(e),
        };
        if let Some(confirmed) = confirmed_name {
            let named = serde_json::from_str::<Value>(&text).ok().and_then(|raw| {
                raw.get(if notes { "set" } else { "skill" })
                    .and_then(|x| s(x, "name").map(str::to_string))
            });
            if named.as_deref() != Some(confirmed) {
                self.log(&format!(
                    "{}: the console handed out another name than the one that was confirmed ({confirmed}); nothing was installed",
                    item.payload
                ));
                return Ok(json!({ "broken": true }));
            }
        }
        let file = self.path("skills").join(format!("{}{run}.json", item.payload));
        let _ = std::fs::create_dir_all(self.path("skills"));
        let _ = std::fs::set_permissions(self.path("skills"), std::os::unix::fs::PermissionsExt::from_mode(0o700));
        let written = cc_store::write_file(&file, text.as_bytes(), 0o600);
        let answer = match written {
            Err(e) => {
                self.log(&format!(
                    "{}: the skill could not be kept on this agent ({})",
                    item.payload,
                    errno(&e)
                ));
                json!({ "broken": true })
            }
            Ok(()) => {
                let mut args: Vec<String> = vec![self.o.runbook.clone()];
                let f = file.to_string_lossy().to_string();
                if notes {
                    args.extend([
                        "notes".into(),
                        f,
                        "--hash".into(),
                        item.hash.clone(),
                        "--as".into(),
                        item.payload.clone(),
                        "--public".into(),
                    ]);
                    if let Some(n) = confirmed_name {
                        args.extend(["--name".into(), n.into()]);
                    }
                } else {
                    args.extend([
                        "skill".into(),
                        f,
                        "--hash".into(),
                        item.hash.clone(),
                        "--as".into(),
                        item.payload.clone(),
                        "--skip-unconfirmed".into(),
                        "--json".into(),
                        "--public".into(),
                    ]);
                    if let Some(r) = &item.run_id {
                        args.extend(["--run-id".into(), r.clone()]);
                    }
                    if let Some(n) = confirmed_name {
                        args.extend(["--name".into(), n.into()]);
                    }
                    if over.replace_changed {
                        args.push("--replace-changed".into());
                    }
                    if over.keep_switch {
                        args.push("--keep-switch".into());
                    }
                    if let Some(h) = &over.only_over_record {
                        args.extend(["--only-over-record".into(), h.clone()]);
                    }
                }
                let r = self.run(args, SKILL_TIMEOUT).await;
                match serde_json::from_str::<Value>(&r.stdout) {
                    Ok(report) if report.get("steps").is_some_and(Value::is_array) => json!({ "report": report }),
                    _ => {
                        self.log(&format!(
                            "{}: the skill was not installed (not the files the console named, or not a valid skill)",
                            item.payload
                        ));
                        json!({ "broken": true })
                    }
                }
            }
        };
        rm(&file);
        Ok(answer)
    }

    fn skill_dir(&self, name: &str) -> PathBuf {
        self.o.home.join(".openclaw").join("skills").join(name)
    }

    /// The skill this agent prepared and waits for a ticket for, while recent.
    fn skill_pending(&self) -> Option<Value> {
        let r = read_json(&self.path("skill-pending.json"))?;
        let kind = s(&r, "kind").filter(|k| *k == "skill" || *k == "notes")?;
        let ref_ = s(&r, "ref").filter(|x| REQUEST_ID.is_match(x))?;
        if !Self::fresh(s(&r, "at"), TEMPLATE_REVIEW_MS) {
            return None;
        }
        let name = s(&r, "name").filter(|n| SKILL_NAME_RE.is_match(n))?;
        let hash = s(&r, "hash").filter(|h| BUNDLE_HASH.is_match(h))?;
        let files = r.get("files").filter(|f| f.is_number())?;
        let changed = r.get("changed") == Some(&json!(true));
        let item = s(&r, "item")?;
        let mut p = json!({
            "kind": kind, "ref": ref_, "name": name, "hash": hash,
            "payload": if changed { overwrite_ticket(hash) } else { hash.to_string() },
            "files": files,
        });
        if kind == "notes" {
            if !is_notes_payload(item) {
                return None;
            }
            p["always"] = json!(r.get("always") == Some(&json!(true)));
            p["bytes"] = r.get("bytes").filter(|b| b.is_number()).cloned().unwrap_or(json!(0));
        } else {
            if !is_skill_payload(item) || !r.get("runnable").is_some_and(Value::is_number) {
                return None;
            }
            if r.get("settings").is_some_and(|x| !x.is_number()) {
                return None;
            }
            p["runnable"] = r["runnable"].clone();
            p["settings"] = r.get("settings").cloned().unwrap_or(json!(0));
        }
        p["replaces"] = json!(r.get("replaces") == Some(&json!(true)));
        p["changed"] = json!(changed);
        p["at"] = r["at"].clone();
        // Kept, not handed to the firewall.
        p["item"] = json!(item);
        p["runId"] = json!(request_id(r.get("runId")));
        p["said"] = json!(r.get("said") == Some(&json!(true)));
        p["confirmedAt"] = json!(s(&r, "confirmedAt"));
        p["result"] = r
            .get("result")
            .filter(|x| x.is_object())
            .cloned()
            .unwrap_or(Value::Null);
        Some(p)
    }

    /// A skill or set for an agent that already runs: prepared, then installed with a ticket.
    async fn install(&self, req: Option<&Install>) -> Result<(), CallError> {
        if !self.coded() {
            return Ok(());
        }
        let (pending_path, ticket_path, done_path) = (
            self.path("skill-pending.json"),
            self.path("skill-ticket.json"),
            self.path("skill-done.json"),
        );
        let Some(req) = req else {
            let _f = lock(&self.files);
            rm(&pending_path);
            rm(&ticket_path);
            return Ok(());
        };
        if read_json(&done_path)
            .and_then(|v| s(&v, "id").map(str::to_string))
            .as_deref()
            == Some(req.id.as_str())
        {
            return Ok(());
        }
        let finish = || {
            self.write(&done_path, &json!({ "id": req.id }));
            let _f = lock(&self.files);
            rm(&pending_path);
            rm(&ticket_path);
        };
        let report = |body: Value| {
            let mut b = json!({ "kind": "skills", "requestId": req.id });
            for (k, v) in body.as_object().cloned().unwrap_or_default() {
                b[k] = v;
            }
            self.call("POST", Some(b), "", 0)
        };
        let kept = read_json(&pending_path);
        if kept.as_ref().and_then(|k| s(k, "ref")) != Some(req.id.as_str()) {
            {
                let _f = lock(&self.files);
                rm(&pending_path);
                rm(&ticket_path);
            }
            let facts = self.check_skill(req).await?;
            if facts.get("missing").is_some() || facts.get("broken").is_some() {
                let mut entry = json!({ "payload": req.payload });
                for (k, v) in facts.as_object().cloned().unwrap_or_default() {
                    entry[k] = v;
                }
                report(json!({ "skills": [entry] })).await?;
                finish();
                return Ok(());
            }
            let mut record = json!({ "ref": req.id, "name": facts["name"], "hash": req.hash, "item": req.payload });
            for (k, v) in facts.as_object().cloned().unwrap_or_default() {
                if k != "name" {
                    record[k] = v;
                }
            }
            record["runId"] = json!(req.run_id);
            record["at"] = json!(iso_ms(now_ms()));
            self.write(&pending_path, &record);
            self.log(&format!(
                "prepared the {} {} for a confirmation code",
                what(s(&facts, "kind").unwrap_or("skill")),
                s(&facts, "name").unwrap_or_default()
            ));
            let mut said = json!({ "prepared": true, "skills": [] });
            if facts.get("changed") == Some(&json!(true)) {
                said["changed"] = json!(true);
            }
            report(said).await?;
            record["said"] = json!(true);
            self.write(&pending_path, &record);
            return Ok(());
        }
        let Some(mut pending) = self.skill_pending() else {
            finish();
            return Ok(());
        };
        let keep = |p: &Value| {
            let mut record = p.clone();
            if let Some(o) = record.as_object_mut() {
                o.remove("payload");
            }
            self.write(&pending_path, &record);
        };
        let item = s(&pending, "item").unwrap_or_default().to_string();
        if pending.get("result").is_some_and(Value::is_object) {
            let mut entry = json!({ "payload": item });
            for (k, v) in pending["result"].as_object().cloned().unwrap_or_default() {
                entry[k] = v;
            }
            report(json!({ "skills": [entry] })).await?;
            finish();
            return Ok(());
        }
        let hash = s(&pending, "hash").unwrap_or_default().to_string();
        if pending["confirmedAt"].is_null() {
            if pending.get("said") != Some(&json!(true)) {
                let mut said = json!({ "prepared": true, "skills": [] });
                if pending.get("changed") == Some(&json!(true)) {
                    said["changed"] = json!(true);
                }
                report(said).await?;
                pending["said"] = json!(true);
                keep(&pending);
            }
            let Some(ticket) = take_locked(&self.files, &ticket_path) else {
                return Ok(());
            };
            if s(&ticket, "ref") != Some(req.id.as_str())
                || s(&ticket, "hash") != Some(hash.as_str())
                || hash != req.hash
                || item != req.payload
                || !Self::fresh(s(&ticket, "at"), TEMPLATE_TICKET_MS)
            {
                return Ok(());
            }
            pending["confirmedAt"] = json!(s(&ticket, "at").map(str::to_string).unwrap_or_else(|| iso_ms(now_ms())));
            keep(&pending);
        }
        if !Self::fresh(s(&pending, "confirmedAt"), TEMPLATE_TICKET_MS) || hash != req.hash || item != req.payload {
            finish();
            return Ok(());
        }
        let kind = s(&pending, "kind").unwrap_or("skill").to_string();
        let name = s(&pending, "name").unwrap_or_default().to_string();
        self.log(&format!("installing the {} {name}", what(&kind)));
        let over = if kind == "skill" {
            Over {
                replace_changed: pending.get("changed") == Some(&json!(true)),
                keep_switch: pending.get("replaces") == Some(&json!(true)),
                only_over_record: None,
            }
        } else {
            Over::default()
        };
        let result = self
            .install_skill(
                &StartItem {
                    payload: item.clone(),
                    hash: hash.clone(),
                    run_id: s(&pending, "runId").map(str::to_string),
                },
                "",
                Some(&name),
                over,
            )
            .await?;
        pending["result"] = result.clone();
        keep(&pending);
        let mut entry = json!({ "payload": item });
        for (k, v) in result.as_object().cloned().unwrap_or_default() {
            entry[k] = v;
        }
        report(json!({ "skills": [entry] })).await?;
        finish();
        Ok(())
    }

    /// What a payload is, without installing it: fetched and checked by the runner.
    async fn check_skill(&self, item: &Install) -> Result<Value, CallError> {
        let notes = is_notes_payload(&item.payload);
        if notes && notes_locked(&notes_place()) {
            return Ok(json!({ "broken": true, "locked": true }));
        }
        let max = if notes {
            NOTES_PAYLOAD_MAX_BYTES
        } else {
            SKILL_PAYLOAD_MAX_BYTES
        };
        let text = match self
            .call("GET", None, &format!("/bundle?template={}", item.payload), max)
            .await
        {
            Ok(v) => v.as_str().unwrap_or_default().to_string(),
            Err(e) if e.status == Some(404) => return Ok(json!({ "missing": true })),
            Err(e) if e.status == Some(413) => return Ok(json!({ "broken": true })),
            Err(e) => return Err(e),
        };
        let file = self.path("skills").join(format!("{}.check.json", item.payload));
        let _ = std::fs::create_dir_all(self.path("skills"));
        let answer = (|| async {
            cc_store::write_file(&file, text.as_bytes(), 0o600).ok()?;
            let args = vec![
                self.o.runbook.clone(),
                if notes { "notes".into() } else { "skill".into() },
                file.to_string_lossy().into(),
                "--hash".into(),
                item.hash.clone(),
                "--as".into(),
                item.payload.clone(),
                "--check".into(),
                "--json".into(),
                "--public".into(),
            ];
            let r = self.run(args, SKILL_TIMEOUT).await;
            let steps = serde_json::from_str::<Value>(&r.stdout).ok()?.get("steps")?.as_array()?.clone();
            let raw: Value = serde_json::from_str(&text).ok()?;
            if notes {
                let name = raw.get("set").and_then(|x| s(x, "name")).filter(|n| SKILL_NAME_RE.is_match(n))?;
                let files = raw.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
                if files.is_empty() || files.len() > 1000 || !steps.iter().any(|s| s.get("kind") == Some(&json!("openclaw.notes"))) {
                    return None;
                }
                let bytes: usize = files.iter().filter_map(|f| s(f, "content")).map(str::len).sum();
                let given = read_notes_record(&self.o.home, name);
                let replaces = given.is_some() || notes_place().root.join(name).is_dir();
                let now = given
                    .as_ref()
                    .filter(|g| g.source == "organization")
                    .and_then(|g| notes_set_hash(&notes_place().root, name, g.always.as_deref()));
                let changed = now.is_some_and(|n| Some(n) != given.as_ref().map(|g| g.hash.clone()));
                let always = raw.get("set").and_then(|x| s(x, "always")).is_some_and(|a| !a.is_empty());
                return Some(json!({ "kind": "notes", "name": name, "files": files.len(), "always": always, "bytes": bytes, "replaces": replaces, "changed": changed }));
            }
            let name = raw.get("skill").and_then(|x| s(x, "name")).filter(|n| SKILL_NAME_RE.is_match(n))?;
            let files = raw.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
            if files.len() > 1000 {
                return None;
            }
            let shebang = |f: &Value| {
                let Some(c) = s(f, "content") else { return false };
                if s(f, "encoding") == Some("base64") {
                    node_base64(&js_slice(c, 4)).starts_with(b"#!")
                } else {
                    c.starts_with("#!")
                }
            };
            let runnable = files.iter().filter(|f| f.get("executable") == Some(&json!(true)) || shebang(f)).count();
            let settings = steps.iter().filter(|s| s.get("kind") == Some(&json!("controlclaw.setting"))).count();
            let (replaces, changed) = self.skill_on_agent(name);
            Some(json!({ "kind": "skill", "name": name, "replaces": replaces, "changed": changed, "files": files.len(), "runnable": runnable, "settings": settings }))
        })()
        .await;
        rm(&file);
        Ok(answer.unwrap_or_else(|| json!({ "broken": true })))
    }

    fn skill_on_agent(&self, name: &str) -> (bool, bool) {
        let dir = self.skill_dir(name);
        let record = if dir.join("SKILL.md").exists() {
            read_skill_record(&dir)
        } else {
            None
        };
        match record {
            Some(r) if r.source == "organization" => {
                let now = super::skill_files::SkillHashes::default().of(&dir);
                (true, now.as_deref() != Some(r.installed_hash.as_str()))
            }
            _ => (false, false),
        }
    }

    /// Puts a skill back as the organization installed it here (`restoreSkill`).
    pub async fn restore_skill(
        &self,
        name: Option<&Value>,
        expected: Option<&Value>,
        payload: Option<&Value>,
    ) -> Result<Value, SkillsError> {
        let e = |status: u16, m: &str| SkillsError {
            status,
            message: m.into(),
        };
        let (Some(name), Some(expected), Some(payload)) = (
            name.and_then(Value::as_str).filter(|n| SKILL_NAME_RE.is_match(n)),
            expected.and_then(Value::as_str).filter(|h| BUNDLE_HASH.is_match(h)),
            payload.and_then(Value::as_str).filter(|p| is_skill_payload(p)),
        ) else {
            return Err(e(400, "Name the skill, its hash and its version."));
        };
        let dir = self.skill_dir(name);
        let record = if dir.join("SKILL.md").exists() {
            read_skill_record(&dir)
        } else {
            None
        };
        let Some(record) = record.filter(|r| r.source == "organization") else {
            return Err(e(
                409,
                "This agent has no record of being given that skill by your organization, so it is not put back from here.",
            ));
        };
        if record.installed_hash != expected {
            return Err(e(
                409,
                "The skill this agent was given is not that version, so it is not put back from here.",
            ));
        }
        if self.skill_pending().is_some()
            && let Ok(asked) = self.call("GET", None, "", 0).await
            && install_of(asked.get("install")).is_none()
        {
            rm(&self.path("skill-pending.json"));
            rm(&self.path("skill-ticket.json"));
        }
        if self.skill_pending().is_some() {
            return Err(e(
                409,
                "An install is waiting on this agent. Finish or cancel it first.",
            ));
        }
        let over = Over {
            replace_changed: true,
            keep_switch: true,
            only_over_record: Some(record.installed_hash.clone()),
        };
        let item = StartItem {
            payload: payload.into(),
            hash: record.installed_hash.clone(),
            run_id: None,
        };
        let result = self
            .install_skill(&item, ".restore", Some(name), over)
            .await
            .map_err(|err| {
                e(
                    502,
                    &js_slice(&format!("The console could not be reached for the skill: {err}"), 200),
                )
            })?;
        if result.get("missing").is_some() {
            return Err(e(409, "The console no longer hands that version out."));
        }
        let step = step_of(&result, "openclaw.skill");
        let status = step.as_ref().and_then(|s| s.get("status")).and_then(Value::as_str);
        if !matches!(status, Some("ok" | "changed")) {
            return Err(e(502, "The skill could not be put back."));
        }
        if step.as_ref().and_then(|s| s.get("message")) == Some(&json!("kept as it is")) {
            return Err(e(
                409,
                "Another version of the skill was installed on this agent in the meantime, so it was not put back.",
            ));
        }
        self.log(&format!("skill {name}: put back as it was given"));
        Ok(json!({ "ok": true, "restored": status == Some("changed") }))
    }

    /// Puts a set of notes back as this agent was given it (`restoreNotes`).
    pub async fn restore_notes(&self, name: Option<&Value>, expected: Option<&Value>) -> Result<Value, SkillsError> {
        let e = |status: u16, m: &str| SkillsError {
            status,
            message: m.into(),
        };
        let (Some(name), Some(expected)) = (name.and_then(Value::as_str), expected.and_then(Value::as_str)) else {
            return Err(e(400, "Name the set and its hash."));
        };
        if notes_locked(&notes_place()) {
            return Err(e(
                423,
                "This agent's disk is locked, and its notes are in the locked part. Open the disk first.",
            ));
        }
        let record = read_notes_record(&self.o.home, name)
            .filter(|r| r.source == "organization" && r.payload.as_deref().is_some_and(is_notes_payload));
        let Some(record) = record else {
            return Err(e(
                409,
                "This agent has no record of being given that set, so it is not put back from here.",
            ));
        };
        if record.hash != expected {
            return Err(e(
                409,
                "The set this agent was given is not that version, so it is not put back from here.",
            ));
        }
        let item = StartItem {
            payload: record.payload.clone().unwrap_or_default(),
            hash: record.hash.clone(),
            run_id: None,
        };
        let result = self
            .install_skill(&item, ".restore", None, Over::default())
            .await
            .map_err(|err| {
                e(
                    502,
                    &js_slice(&format!("The console could not be reached for the notes: {err}"), 200),
                )
            })?;
        if result.get("missing").is_some() {
            return Err(e(409, "The console no longer hands that version out."));
        }
        let status = step_of(&result, "openclaw.notes")
            .and_then(|s| s.get("status").and_then(Value::as_str).map(str::to_string));
        if !matches!(status.as_deref(), Some("ok" | "changed")) {
            return Err(e(502, "The notes could not be put back."));
        }
        self.log(&format!("notes {name}: put back as they were given"));
        Ok(json!({ "ok": true, "restored": status.as_deref() == Some("changed") }))
    }

    /// `cc-runbook facts`: what a template is from its own files.
    async fn facts(&self, dir: &Path) -> Option<Facts> {
        let r = self
            .run(
                vec![self.o.runbook.clone(), "facts".into(), dir.to_string_lossy().into()],
                UNPACK_TIMEOUT,
            )
            .await;
        if !r.ok {
            return None;
        }
        let raw: Value = serde_json::from_str(&r.stdout).ok()?;
        let name = s(&raw, "name").filter(|n| TEMPLATE_ID.is_match(n))?;
        let hash = s(&raw, "hash").filter(|h| BUNDLE_HASH.is_match(h))?;
        let all = raw.get("steps")?.as_array()?;
        let steps: Vec<(String, String)> = all
            .iter()
            .filter_map(|st| {
                Some((
                    s(st, "id").filter(|i| STEP_ID.is_match(i))?.to_string(),
                    s(st, "kind")?.to_string(),
                ))
            })
            .collect();
        if steps.len() != all.len() {
            return None;
        }
        let mcp = raw
            .get("mcp")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|n| n.as_str().filter(|n| MCP_SERVER_NAME.is_match(n)).map(str::to_string))
                    .take(20)
                    .collect()
            })
            .unwrap_or_default();
        Some(Facts {
            name: name.into(),
            hash: hash.into(),
            steps,
            mcp,
        })
    }

    /// For the firewall: what the preview (or the prepared install) with this id found, while recent.
    pub fn pending(&self, ref_: &str) -> Option<Value> {
        let _f = lock(&self.files);
        self.pending_locked(ref_).map(|(p, _)| p)
    }

    /// `pending`, with the values of a template preview from the same read. The caller holds `files`.
    fn pending_locked(&self, ref_: &str) -> Option<(Value, Option<Vars>)> {
        if let Some(skill) = self.skill_pending()
            && s(&skill, "ref") == Some(ref_)
            && skill["confirmedAt"].is_null()
        {
            let mut facts = skill;
            if let Some(o) = facts.as_object_mut() {
                for k in ["item", "runId", "said", "confirmedAt", "result"] {
                    o.remove(k);
                }
            }
            return Some((facts, None));
        }
        let raw = read_json(&self.path("pending.json"))?;
        if s(&raw, "kind") != Some("template")
            || s(&raw, "ref") != Some(ref_)
            || !Self::fresh(s(&raw, "at"), TEMPLATE_REVIEW_MS)
        {
            return None;
        }
        let template = s(&raw, "template")?;
        let name = s(&raw, "name")?;
        let hash = s(&raw, "hash").filter(|h| BUNDLE_HASH.is_match(h))?;
        let (steps, change, scripts) = (
            raw.get("steps")?.as_f64()?,
            raw.get("change")?.as_f64()?,
            raw.get("scripts")?.as_f64()?,
        );
        let vars = Vars::of(raw.get("vars"))?;
        let beside = raw.get("beside") == Some(&json!(true));
        let num = super::common::js_number;
        let mut p = json!({
            "kind": "template", "ref": ref_, "template": template, "name": name, "hash": hash,
            "org": raw.get("org") == Some(&json!(true)),
            "steps": num(steps), "change": num(change), "scripts": num(scripts),
            "at": raw["at"],
            "filledName": js_slice(&vars.name, AGENT_NAME_MAX),
            "note": js_slice(&vars.note, PENDING_NOTE_MAX),
            "noteCut": js_len(&vars.note) > PENDING_NOTE_MAX,
            "payload": payload_hash(hash, &vars, beside),
        });
        if beside {
            p["beside"] = json!(true);
        }
        if let Some(mcp) = raw.get("mcp").and_then(Value::as_array).filter(|a| !a.is_empty()) {
            let names: Vec<Value> = mcp
                .iter()
                .filter(|n| n.as_str().is_some_and(|n| MCP_SERVER_NAME.is_match(n)))
                .take(20)
                .cloned()
                .collect();
            p["mcp"] = json!(names);
        }
        Some((p, Some(vars)))
    }

    /// From the firewall, after the right code: this preview (or prepared install) may go ahead, once.
    pub fn ticket(&self, ref_: &str, payload: &str) -> bool {
        let _f = lock(&self.files);
        let Some((pending, vars)) = self.pending_locked(ref_) else {
            return false;
        };
        let kind = s(&pending, "kind").unwrap_or_default();
        if kind == "skill" || kind == "notes" {
            if !cc_crypto::ct_eq(
                s(&pending, "payload").unwrap_or_default().as_bytes(),
                payload.as_bytes(),
            ) {
                return false;
            }
            self.write(
                &self.path("skill-ticket.json"),
                &json!({ "ref": ref_, "hash": pending["hash"], "at": iso_ms(now_ms()) }),
            );
            self.log(&format!(
                "a confirmation code was given to install the {} {}",
                what(kind),
                s(&pending, "name").unwrap_or_default()
            ));
            return true;
        }
        if !cc_crypto::ct_eq(
            s(&pending, "payload").unwrap_or_default().as_bytes(),
            payload.as_bytes(),
        ) {
            return false;
        }
        let Some(vars) = vars else { return false };
        self.write(
            &self.path("ticket.json"),
            &json!({ "ref": ref_, "template": pending["template"], "hash": pending["hash"], "at": iso_ms(now_ms()), "vars": vars.json(), "beside": pending.get("beside") == Some(&json!(true)) }),
        );
        self.log(&format!(
            "a confirmation code was given for {}",
            s(&pending, "template").unwrap_or_default()
        ));
        true
    }

    /// Whether the firewall's ticket covers this apply. Used up by asking.
    async fn ticketed(&self, request: &Request, dir: &Path) -> Option<Vars> {
        let ticket = take_locked(&self.files, &self.path("ticket.json"))?;
        let vars = Vars::of(ticket.get("vars"))?;
        let preview = request.preview.as_deref()?;
        if s(&ticket, "ref") != Some(preview)
            || s(&ticket, "template") != Some(request.template.as_str())
            || !Self::fresh(s(&ticket, "at"), TEMPLATE_TICKET_MS)
        {
            return None;
        }
        let beside = ticket.get("beside") == Some(&json!(true));
        if beside != request.beside {
            self.log(&format!(
                "{}: the apply is not what was confirmed ({})",
                request.template,
                if beside {
                    "a bundle beside the template"
                } else {
                    "the agent's template"
                }
            ));
            return None;
        }
        let hash = if is_org_template(&request.template) {
            request.bundle.clone()
        } else {
            self.facts(dir).await.map(|f| f.hash)
        };
        if hash.as_deref().is_none_or(|h| Some(h) != s(&ticket, "hash")) {
            return None;
        }
        let _f = lock(&self.files);
        rm(&self.path("pending.json"));
        Some(vars)
    }

    /// A preview or an apply asked for in the console. Each request once.
    async fn asked(self: &Arc<Self>, request: &Request, a: &Assignment) -> Result<(), CallError> {
        let handled = read_json(&self.path("request.json")).and_then(|v| s(&v, "id").map(str::to_string));
        if handled.as_deref() == Some(request.id.as_str())
            || self
                .marker()
                .is_some_and(|m| s(&m, "request") == Some(request.id.as_str()))
            || self
                .beside()
                .iter()
                .any(|(_, b)| s(b, "request") == Some(request.id.as_str()))
        {
            return Ok(());
        }
        if request.kind == "apply" {
            let mut found = None;
            let mut vars = a.vars.clone();
            if self.coded() {
                let f = self.folder(&request.template, request.bundle.as_deref()).await?;
                let confirmed = match f.dir() {
                    Some(d) => self.ticketed(request, d).await,
                    None => None,
                };
                if f.dir().is_some() && confirmed.is_none() {
                    self.log(&format!(
                        "{} was not applied: no confirmation code was given for it",
                        request.template
                    ));
                    self.write(&self.path("request.json"), &json!({ "id": request.id }));
                    self.keep(json!({ "kind": "run", "template": request.template, "requestId": request.id, "unconfirmed": true }));
                    return self.send().await;
                }
                if let Some(c) = confirmed {
                    vars = c;
                }
                found = Some(f);
            }
            let beside = request.beside && is_org_template(&request.template);
            self.apply(
                &request.template,
                &vars,
                request.run_id.as_deref(),
                Some(&request.id),
                request.bundle.as_deref(),
                found,
                beside,
            )
            .await?;
            self.write(&self.path("request.json"), &json!({ "id": request.id }));
            return Ok(());
        }
        let folder = self.folder(&request.template, request.bundle.as_deref()).await?;
        if request.look {
            let kept = match folder.dir() {
                Some(d) => self.review(request, d, &a.vars).await,
                None => Map::new(),
            };
            self.write(&self.path("request.json"), &json!({ "id": request.id }));
            if let Err(e) = self
                .call("POST", Some(json!({ "kind": "preview", "template": request.template, "requestId": request.id, "kept": kept })), "", 0)
                .await
            {
                self.log(&format!("the second look was not taken: {e}"));
            }
            return Ok(());
        }
        self.log(&format!("previewing {}", request.template));
        let facts = match (self.coded(), folder.dir()) {
            (true, Some(d)) => self.facts(d).await,
            _ => None,
        };
        let own: Vec<String> = match &facts {
            Some(f) => f
                .steps
                .iter()
                .filter(|(_, k)| k != "controlclaw.setting")
                .map(|(i, _)| i.clone())
                .collect(),
            None => request.steps.clone(),
        };
        let no_scripts = self.coded() && is_org_template(&request.template);
        let beside = request.beside && is_org_template(&request.template);
        let report = match folder.dir() {
            Some(d) if !own.is_empty() => {
                self.runbook(
                    "check",
                    &request.template,
                    d,
                    &a.vars,
                    None,
                    Some(&own),
                    no_scripts,
                    beside,
                )
                .await
            }
            _ => None,
        };
        self.write(&self.path("request.json"), &json!({ "id": request.id }));
        // A ticket can only be for the preview now written, not for one it replaced.
        let files = lock(&self.files);
        rm(&self.path("pending.json"));
        rm(&self.path("ticket.json"));
        let hash = if is_org_template(&request.template) {
            request.bundle.clone()
        } else {
            facts.as_ref().map(|f| f.hash.clone())
        };
        if let (Some(f), Some(hash)) = (&facts, &hash)
            && (report.is_some() || own.is_empty())
        {
            let said: Vec<&Value> = report
                .as_ref()
                .and_then(|r| r.get("steps"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|st| s(st, "id").is_some_and(|i| own.iter().any(|o| o == i)))
                .collect();
            let mut p = json!({
                "kind": "template",
                "ref": request.id,
                "template": request.template,
                "name": f.name,
                "hash": hash,
                "org": is_org_template(&request.template),
                "steps": own.len(),
                "change": said.iter().filter(|st| s(st, "status") == Some("would-change") && s(st, "message") != Some(CHECKED_WHEN_APPLIED)).count(),
                "scripts": f.steps.iter().filter(|(_, k)| k == "run").count(),
            });
            if !f.mcp.is_empty() {
                p["mcp"] = json!(f.mcp);
            }
            p["at"] = json!(iso_ms(now_ms()));
            if beside {
                p["beside"] = json!(true);
            }
            p["vars"] = a.vars.json();
            self.write(&self.path("pending.json"), &p);
        }
        drop(files);
        let mut result = json!({ "kind": "preview", "template": request.template, "requestId": request.id });
        match (&folder, &report) {
            (Folder::Missing, _) => result["missing"] = json!(true),
            (Folder::Broken | Folder::Unsure, _) => result["broken"] = json!(true),
            (_, Some(r)) => result["report"] = r.clone(),
            (_, None) if !request.steps.is_empty() => result["broken"] = json!(true),
            _ => {}
        }
        self.keep(result);
        self.send().await?;
        let Some(d) = folder.dir() else { return Ok(()) };
        let kept = self.review(request, d, &a.vars).await;
        if !kept.is_empty()
            && let Err(e) = self
                .call("POST", Some(json!({ "kind": "preview", "template": request.template, "requestId": request.id, "kept": kept })), "", 0)
                .await
        {
            self.log(&format!("when the kept files were written was not taken: {e}"));
        }
        Ok(())
    }

    /// Keeps, for the Files page, the files the previewed template would not overwrite.
    async fn review(&self, request: &Request, dir: &Path, vars: &Vars) -> Map<String, Value> {
        let path = self.path("review.json");
        let out: Option<Map<String, Value>> = async {
            let file = self.path(PREVIEW_VARS);
            self.write(&file, &vars.json());
            let mut args = vec![self.o.runbook.clone(), "review".into(), dir.to_string_lossy().into(), "--vars".into(), file.to_string_lossy().into()];
            if is_org_template(&request.template) {
                args.extend(["--as".into(), request.template.clone()]);
            }
            let r = self.run(args, VERIFY_TIMEOUT).await;
            if !r.ok {
                return None;
            }
            let files = review_files_of(serde_json::from_str::<Value>(&r.stdout).ok()?.get("files"));
            if files.is_empty() {
                return None;
            }
            self.write(&path, &json!({ "template": request.template, "requestId": request.id, "at": iso_ms(now_ms()), "files": files }));
            Some(
                files
                    .iter()
                    .filter(|f| f.get("exists") == Some(&json!(true)))
                    .filter_map(|f| Some((s(f, "step")?.to_string(), json!(s(f, "stamp")?))))
                    .collect(),
            )
        }
        .await;
        match out {
            Some(m) => m,
            None => {
                if read_template_review(&self.o.state_dir)
                    .and_then(|r| s(&r, "template").map(str::to_string))
                    .as_deref()
                    != Some(request.template.as_str())
                {
                    rm(&path);
                }
                Map::new()
            }
        }
    }

    /// Drops what was kept for the Files page once the console no longer shows that preview.
    fn drop_review(&self, wanted: Option<Option<String>>) {
        let Some(wanted) = wanted else { return };
        let path = self.path("review.json");
        let kept = read_json(&path).and_then(|v| s(&v, "template").map(str::to_string));
        if kept.is_none() || kept != wanted {
            rm(&path);
        }
    }

    /// Steps asked for again in the console, run from the files that were applied.
    async fn rerun(self: &Arc<Self>, marker: &Value, a: &Assignment) -> Result<(), CallError> {
        let template = s(marker, "template").unwrap_or_default().to_string();
        let Some(rerun) = a
            .rerun
            .as_ref()
            .filter(|_| a.template.as_deref() == Some(template.as_str()))
        else {
            return Ok(());
        };
        let request = format!(
            "{}:{}:{}",
            rerun.run_id.as_deref().unwrap_or_default(),
            rerun.at,
            rerun.steps.join(",")
        );
        if s(marker, "rerun") == Some(request.as_str()) {
            return Ok(());
        }
        let hash = if self.coded() { None } else { a.bundle.clone() }.or_else(|| s(marker, "hash").map(str::to_string));
        let found = self.folder(&template, hash.as_deref()).await?;
        if found == Folder::Unsure {
            return Ok(());
        }
        let Some(dir) = found.dir().cloned() else {
            self.log(&format!(
                "{template}: steps were not run again, the files that were applied could not be had"
            ));
            let mut m = marker.clone();
            m["rerun"] = json!(request);
            self.write(&self.path("applied.json"), &m);
            self.keep(json!({ "kind": "rerun", "template": template, "missing": true }));
            return self.send().await;
        };
        self.log(&format!("running {} step(s) of {template} again", rerun.steps.len()));
        let vars = self.applied_vars(marker, &a.vars);
        let report = self
            .runbook(
                "run",
                &template,
                &dir,
                &vars,
                rerun.run_id.as_deref(),
                Some(&rerun.steps),
                false,
                false,
            )
            .await;
        let mut m = self.marker().unwrap_or_else(|| marker.clone());
        m["rerun"] = json!(request);
        self.write(&self.path("applied.json"), &m);
        let Some(mut report) = report else { return Ok(()) };
        let ran: Vec<Value> = report["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|st| s(st, "id").is_some_and(|i| rerun.steps.iter().any(|x| x == i)))
            .cloned()
            .collect();
        report["steps"] = json!(ran);
        self.keep(json!({ "kind": "rerun", "template": template, "report": report }));
        self.send().await
    }

    /// The values to run steps again and to check them with: the applied ones on an agent with a firewall.
    fn applied_vars(&self, marker: &Value, assignment: &Vars) -> Vars {
        if !self.coded() {
            return assignment.clone();
        }
        if let Some(v) = Vars::of(marker.get("vars")) {
            return v;
        }
        let vars = read_json(&self.path(APPLIED_VARS))
            .and_then(|v| Vars::of(Some(&v)))
            .unwrap_or_else(|| Vars {
                note: String::new(),
                name: assignment.name.clone(),
                time_zone: "UTC".into(),
            });
        let mut m = marker.clone();
        m["vars"] = vars.json();
        self.write(&self.path("applied.json"), &m);
        vars
    }

    fn drop_repair(&self, template: &str) {
        let dir = self.o.runbook_state_dir.join("repair").join(template);
        rm(&PathBuf::from(format!("{}.json", dir.display())));
        if std::fs::remove_dir_all(&dir).is_err() && dir.exists() {
            self.log(&format!(
                "{template}: the repair folder could not be removed; it is put out of use"
            ));
            if std::fs::remove_file(dir.join("template.yaml")).is_err() && dir.join("template.yaml").exists() {
                self.log(&format!(
                    "{template}: the repair folder is still in use. Remove {} by hand",
                    dir.display()
                ));
            }
        }
    }

    /// For the firewall before a Doctor repair of a step.
    pub async fn repair_facts(&self) -> Result<Option<Value>, Busy> {
        // The folder is unpacked again here: not under a round that runs from it.
        let Ok(_x) = self.exclusive.try_lock() else {
            return Err(Busy);
        };
        Ok(self.repair_facts_held().await)
    }

    async fn repair_facts_held(&self) -> Option<Value> {
        let marker = self.marker().filter(|m| m.get("missing").is_none())?;
        let template = s(&marker, "template")?.to_string();
        let dir = self.folder(&template, s(&marker, "hash")).await.ok()?.dir()?.clone();
        let facts = self.facts(&dir).await?;
        let mut failed_steps: Vec<String> = Vec::new();
        if let Some(state) = read_json(&self.o.runbook_state_dir.join(format!("{template}.json"))) {
            let failed: Vec<&Value> = state["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|st| {
                    s(st, "status") == Some("failed")
                        && s(st, "id").is_some_and(|i| facts.steps.iter().any(|(fi, _)| fi == i))
                })
                .collect();
            for optional in [false, true] {
                for st in &failed {
                    if (st.get("optional") == Some(&json!(true))) == optional {
                        failed_steps.push(s(st, "id").unwrap_or_default().into());
                    }
                }
            }
        }
        let vars = self.path(APPLIED_VARS);
        Some(json!({
            "template": template, "name": facts.name, "hash": facts.hash, "org": is_org_template(&template),
            "failedSteps": failed_steps, "dir": dir, "repairDir": self.o.runbook_state_dir.join("repair").join(&template),
            "vars": vars.exists().then(|| vars.to_string_lossy().to_string()),
        }))
    }

    /// After a Doctor repair: the steps checked again, and the repair's changes packed for the firewall.
    pub async fn repair_done(self: &Arc<Self>, session: &str) -> Value {
        let Some(marker) = self.marker().filter(|m| m.get("missing").is_none()) else {
            return json!({ "ok": true, "pack": null });
        };
        let template = s(&marker, "template").unwrap_or_default().to_string();
        let busy = || json!({ "ok": false, "problems": ["The agent is applying or checking its template just now. Read the changes again in a minute."] });
        if self.running.load(Ordering::SeqCst) || self.verifying.load(Ordering::SeqCst) {
            return busy();
        }
        let Ok(_x) = self.exclusive.try_lock() else {
            return busy();
        };
        let Some(dir) = self
            .folder(&template, s(&marker, "hash"))
            .await
            .ok()
            .and_then(|f| f.dir().cloned())
        else {
            return json!({ "ok": true, "pack": null });
        };
        let vars = Vars::of(marker.get("vars"))
            .or_else(|| read_json(&self.path(APPLIED_VARS)).and_then(|v| Vars::of(Some(&v))));
        if let Some(vars) = vars {
            let _checking = Flag::on(&self.verifying);
            if let Some(report) = self
                .runbook("verify", &template, &dir, &vars, None, None, false, false)
                .await
            {
                self.keep(json!({ "kind": "repair", "template": template, "session": session, "report": report }));
                let _ = self.send().await;
            }
        }
        let mut args = vec![
            self.o.runbook.clone(),
            "pack".into(),
            dir.to_string_lossy().into(),
            "--session".into(),
            session.into(),
        ];
        if is_org_template(&template) {
            args.extend(["--as".into(), template.clone()]);
        }
        let r = self.run(args, UNPACK_TIMEOUT).await;
        pack_answer(&r.stdout, "The repair's changes could not be read on the agent.", true)
    }

    /// For the firewall before a capture session: where the session writes.
    pub fn capture_session_facts(&self) -> Value {
        json!({ "base": self.o.home.join(".controlclaw").join("capture") })
    }

    /// After a capture session: the template it wrote, checked and packed.
    pub async fn capture_session_done(&self, session: &str) -> Value {
        let r = self
            .run(
                vec![
                    self.o.runbook.clone(),
                    "capture-pack".into(),
                    "--session".into(),
                    session.into(),
                ],
                UNPACK_TIMEOUT,
            )
            .await;
        pack_answer(
            &r.stdout,
            "The session's template could not be read on the agent.",
            false,
        )
    }

    /// For the firewall before a Final check.
    pub async fn check_facts(&self) -> Result<Option<Value>, Busy> {
        let Ok(_x) = self.exclusive.try_lock() else {
            return Err(Busy);
        };
        Ok(self.check_facts_held().await)
    }

    async fn check_facts_held(&self) -> Option<Value> {
        let marker = self.marker().filter(|m| m.get("missing").is_none())?;
        let template = s(&marker, "template")?.to_string();
        let dir = self.folder(&template, s(&marker, "hash")).await.ok()?.dir()?.clone();
        let facts = self.facts(&dir).await?;
        Some(json!({
            "template": template, "name": facts.name, "hash": facts.hash, "org": is_org_template(&template),
            "steps": facts.steps.iter().map(|(i, _)| i.clone()).collect::<Vec<_>>(), "appliedAt": marker["at"],
        }))
    }

    /// One read for a Final check (`cc-runbook probe`).
    pub async fn probe(self: &Arc<Self>, verb: &str, arg: Option<&str>) -> Value {
        let Some(marker) = self.marker().filter(|m| m.get("missing").is_none()) else {
            return json!({ "ok": false, "text": "This agent has no template." });
        };
        let busy = || json!({ "ok": false, "text": BUSY });
        if verb == "verify" && (self.running.load(Ordering::SeqCst) || self.verifying.load(Ordering::SeqCst)) {
            return busy();
        }
        // Every probe unpacks the folder again: never under a round or a check that runs from it.
        let Ok(_x) = self.exclusive.try_lock() else {
            return busy();
        };
        let _checking = (verb == "verify").then(|| Flag::on(&self.verifying));
        let template = s(&marker, "template").unwrap_or_default().to_string();
        async {
            let Some(dir) = self
                .folder(&template, s(&marker, "hash"))
                .await
                .ok()
                .and_then(|f| f.dir().cloned())
            else {
                return json!({ "ok": false, "text": "The template's files could not be read on this agent." });
            };
            let mut args = vec![
                self.o.runbook.clone(),
                "probe".into(),
                dir.to_string_lossy().into(),
                verb.into(),
            ];
            if let Some(a) = arg {
                args.push(a.into());
            }
            if is_org_template(&template) {
                args.extend(["--as".into(), template.clone()]);
            }
            if let Some(v) = Vars::of(marker.get("vars")) {
                let file = self.path(PROBE_VARS);
                self.write(&file, &v.json());
                args.extend(["--vars".into(), file.to_string_lossy().into()]);
            }
            let r = self.run(args, VERIFY_TIMEOUT).await;
            if r.ok {
                return json!({ "ok": true, "text": r.stdout.trim_end() });
            }
            if r.code == Some(1) && !r.stdout.trim().is_empty() {
                return json!({ "ok": false, "text": r.stdout.trim_end() });
            }
            json!({ "ok": false, "text": "That could not be read on this agent." })
        }
        .await
    }

    /// Checks the applied template and its bundles, and tells the console. Never fails.
    pub fn verify(self: &Arc<Self>) -> cc_http::BoxFuture<()> {
        let me = self.clone();
        Box::pin(async move {
            let own = me.marker().filter(|m| m.get("missing").is_none());
            let beside = me.beside();
            if (own.is_none() && beside.is_empty())
                || me.running.load(Ordering::SeqCst)
                || me.verifying.load(Ordering::SeqCst)
            {
                return;
            }
            let Ok(_x) = me.exclusive.try_lock() else { return };
            let _checking = Flag::on(&me.verifying);
            if let Some(marker) = own {
                me.check(&marker).await;
            }
            for (id, b) in beside {
                let Some(vars) = Vars::of(b.get("vars")) else { continue };
                match me.folder(&id, s(&b, "hash")).await {
                    Ok(Folder::Dir(dir)) => {
                        if let Some(report) = me.runbook("verify", &id, &dir, &vars, None, None, false, true).await
                            && let Err(e) = me
                                .call(
                                    "POST",
                                    Some(json!({ "kind": "verify", "template": id, "report": report })),
                                    "",
                                    0,
                                )
                                .await
                        {
                            me.log(&format!("could not check the bundle {id}: {e}"));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => me.log(&format!("could not check the bundle {id}: {e}")),
                }
            }
        })
    }

    async fn check(&self, marker: &Value) {
        let template = s(marker, "template").unwrap_or_default().to_string();
        let result: Result<(), CallError> = async {
            let a = self.assignment().await?;
            let (vars, run_id) = match &a {
                Some(a) => (a.vars.clone(), a.run_id.clone()),
                None => (
                    Vars {
                        note: String::new(),
                        name: String::new(),
                        time_zone: "UTC".into(),
                    },
                    None,
                ),
            };
            let Some(dir) = self.folder(&template, s(marker, "hash")).await?.dir().cloned() else {
                return Ok(());
            };
            let vars = self.applied_vars(marker, &vars);
            if let Some(report) = self
                .runbook("verify", &template, &dir, &vars, run_id.as_deref(), None, false, false)
                .await
            {
                self.call(
                    "POST",
                    Some(json!({ "kind": "verify", "template": template, "report": report })),
                    "",
                    0,
                )
                .await?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = result {
            self.log(&format!("could not check {template}: {e}"));
        }
    }
}

/// `start-skills.json`: the skills a new agent starts with, taken once.
#[derive(Debug, Clone, Default)]
struct Latch {
    id: String,
    at: String,
    items: Vec<StartItem>,
    tries: u64,
    done: bool,
}

#[derive(Debug, Clone, Default)]
struct Over {
    replace_changed: bool,
    keep_switch: bool,
    only_over_record: Option<String>,
}

fn what(kind: &str) -> &'static str {
    if kind == "notes" { "shared notes" } else { "skill" }
}

fn step_of(result: &Value, kind: &str) -> Option<Value> {
    result
        .pointer("/report/steps")
        .and_then(Value::as_array)?
        .iter()
        .find(|s| s.get("kind") == Some(&json!(kind)))
        .cloned()
}

/// `Buffer.from(s, "base64")`: lenient as Node is. URL-safe letters count, anything else is
/// skipped, and the first `=` ends it.
pub fn node_base64(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// `String(x)` for a report's `result`.
fn js_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".into(),
        other => other.to_string(),
    }
}

fn errno(e: &std::io::Error) -> &'static str {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => "EACCES",
        std::io::ErrorKind::NotFound => "ENOENT",
        std::io::ErrorKind::StorageFull => "ENOSPC",
        _ => "error",
    }
}

/// The runner's `pack` / `capture-pack` answer.
fn pack_answer(stdout: &str, fallback: &str, empty_is_none: bool) -> Value {
    if let Ok(raw) = serde_json::from_str::<Value>(stdout) {
        if raw.get("none") == Some(&json!(true)) {
            return json!({ "ok": true, "pack": null });
        }
        if let Some(p) = raw.get("problems").and_then(Value::as_array) {
            let problems: Vec<String> = p
                .iter()
                .filter_map(|x| x.as_str())
                .take(20)
                .map(|x| js_slice(x, 400))
                .collect();
            return json!({ "ok": false, "problems": problems });
        }
        if let Some(files) = raw.get("files").and_then(Value::as_array) {
            if empty_is_none && files.is_empty() {
                return json!({ "ok": true, "pack": null });
            }
            return json!({ "ok": true, "pack": raw });
        }
    }
    json!({ "ok": false, "problems": [fallback] })
}

/// Where the TS runner sits on an agent box (the Ansible role puts it in the vm-agent bundle).
const RUNBOOK_JS: &str = "/opt/controlclaw/agent/dist/cc-runbook.js";
const TEMPLATES_DIR: &str = "/opt/controlclaw/agent/templates";
const NODE: &str = "/usr/bin/node";

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn connected(app: &App) -> bool {
    app.contracts.openclaw.get().is_some_and(|o| o.client.connected())
}

/// The template service of an agent box (index.ts, the `listen` callback): applied once OpenClaw
/// answers, then only checked. A box still in the pool has no organization, so no template yet.
pub fn start(app: &Arc<App>) {
    let Some(p) = app.contracts.platform.get() else { return };
    if app.config.pool_marker.exists() {
        return;
    }
    let weak = Arc::downgrade(app);
    let keys = app.keys.clone();
    let keys_dir = app.config.keys_dir.clone();
    let console = HttpConsole {
        base: Arc::new(move || super::gateway::saas_base_url(&*weak.upgrade()?)),
        token: Arc::new(move || cc_auth::sign::box_token(&keys).ok()),
        http: app.http.clone(),
    };
    let home = app.config.home.clone();
    let templates = TemplateService::new(TemplateOptions {
        console: Arc::new(console),
        deps: Deps::of(app),
        node: env_or("CC_NODE", NODE),
        runbook: env_or("CC_RUNBOOK_JS", RUNBOOK_JS),
        templates_dir: env_or("CC_TEMPLATES_DIR", TEMPLATES_DIR).into(),
        state_dir: ReviewSlot::of(&app.config.state_dir).state_dir,
        runbook_state_dir: std::env::var("CC_RUNBOOK_STATE")
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".controlclaw").join("runbook")),
        home,
        // The firewall's key, held since this agent joined its organization: with it the firewall
        // can hand over a ticket, so an apply needs one.
        firewall: Arc::new(move || keys_dir.join("mitm_pinned_pubkey.pem").exists()),
        is_new: Arc::new(|| super::born::is_new(1.0)),
        verify_after: Duration::from_secs(3 * 60),
        // `notesHelperThere`: the root helper that writes shared notes is installed.
        notes_helper_there: Arc::new(|| Path::new(&env_or("CC_NOTES_HELPER", "/usr/local/sbin/cc-notes")).exists()),
    });
    let _ = p.templates.set(templates.clone());
    let t = templates.clone();
    let _ = p.restore.set(Arc::new(move |path: String, body: Map<String, Value>| {
        let t = t.clone();
        Box::pin(async move {
            if path == "/skills/restore" {
                t.restore_skill(body.get("name"), body.get("expectedHash"), body.get("payload"))
                    .await
            } else {
                t.restore_notes(body.get("name"), body.get("expectedHash")).await
            }
        })
    }));
    let (t, weak) = (templates.clone(), Arc::downgrade(app));
    let _ = p.templates_poke.set(Arc::new(move || {
        // Remembered when it cannot be acted on now: the next round, or the next connect, asks.
        t.poke();
        if weak.upgrade().is_some_and(|a| connected(&a)) {
            tokio::spawn(t.tick());
        }
    }));
    let t = templates.clone();
    super::on_connected(app, move || {
        let t = t.clone();
        Box::pin(async move {
            if t.asks() {
                tokio::spawn(t.tick());
            }
        })
    });
    let (t, weak) = (templates.clone(), Arc::downgrade(app));
    tokio::spawn(async move {
        let mut every = tokio::time::interval(TEMPLATE_POLL);
        every.tick().await;
        loop {
            every.tick().await;
            if t.asks() && weak.upgrade().is_some_and(|a| connected(&a)) {
                tokio::spawn(t.tick());
            }
        }
    });
    // After every start of this service, which is after every Update, and every few hours.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3 * 60)).await;
        let mut every = tokio::time::interval(TEMPLATE_VERIFY);
        loop {
            every.tick().await;
            templates.verify().await;
        }
    });
}

const LIMIT_WINDOW_MS: i64 = 10 * 60_000;

/// At most `max` asks in ten minutes, per route kind (`admit` in the TS routes).
fn admit(asked: &std::sync::Mutex<Vec<i64>>, max: usize) -> bool {
    let now = now_ms();
    let mut a = lock(asked);
    a.retain(|t| now - t < LIMIT_WINDOW_MS);
    if a.len() >= max {
        return false;
    }
    a.push(now);
    true
}

static REPAIR_ASKED: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
static CAPTURE_ASKED: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
static FACTS_ASKED: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
static PROBE_ASKED: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
static REF: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{8,64}$"));
static SESSION: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_-]{8,80}$"));
static VERB: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z]{2,20}$"));
/// A config path, a workspace path or a command's name: never something the runner could read as an option.
static ARG: LazyLock<Regex> = LazyLock::new(|| re(r"^[A-Za-z0-9_][A-Za-z0-9_.@/:+-]{0,199}$"));

const NOT_FIREWALL: &str = "this must come from the org firewall";

/// What a health or model probe answers (G6's health summary); the check route asks it.
pub type HealthProbe = Arc<dyn Fn(&'static str) -> cc_http::BoxFuture<Value> + Send + Sync>;

fn merged(head: Value, rest: Value) -> Value {
    let mut out = head;
    if let (Some(o), Value::Object(r)) = (out.as_object_mut(), rest) {
        o.extend(r);
    }
    out
}

/// The firewall's routes into the template service, each with its own token purpose and nothing
/// else, before the console's gate: the control plane must not be able to hand itself a ticket.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let a = app.clone();
    router.route(
        stages::PREFIXED,
        |_, p| p == "/apply/pending" || p == "/apply/ticket",
        move |req, _| {
            let app = a.clone();
            async move {
                let path = cc_http::pathname(&req.uri().to_string());
                let ticket = path == "/apply/ticket";
                let (purpose, read) = if ticket {
                    ("apply-ticket", ReadBody::Json { limit: 16_384 })
                } else {
                    ("apply-read", ReadBody::No)
                };
                let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, purpose, 0, read).await {
                    FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                    FirewallRequest::Refused { .. } => return send_json(401, &json!({ "error": NOT_FIREWALL })),
                };
                if parts.method != if ticket { Method::POST } else { Method::GET } {
                    return send_json(404, &json!({ "error": "Not found" }));
                }
                let Some(t) = app.contracts.platform.get().and_then(|p| p.templates.get().cloned()) else {
                    return send_json(503, &json!({ "ok": false, "error": "This agent takes no templates" }));
                };
                if !ticket {
                    let query = parts.uri.query().unwrap_or_default();
                    let r = url::form_urlencoded::parse(query.as_bytes())
                        .find(|(k, _)| k == "ref")
                        .map(|(_, v)| v.into_owned())
                        .unwrap_or_default();
                    return match REF.is_match(&r).then(|| t.pending(&r)).flatten() {
                        Some(p) => send_json(200, &merged(json!({ "ok": true }), p)),
                        None => send_json(404, &json!({ "ok": false, "error": "no such preview" })),
                    };
                }
                let b = match body {
                    FirewallBody::Json(b) => b,
                    _ => Map::new(),
                };
                let r = b.get("ref").and_then(Value::as_str).filter(|r| REF.is_match(r));
                let h = b
                    .get("hash")
                    .and_then(Value::as_str)
                    .filter(|h| BUNDLE_HASH.is_match(h));
                let (Some(r), Some(h)) = (r, h) else {
                    return send_json(400, &json!({ "ok": false, "error": "ref and hash are needed" }));
                };
                if t.ticket(r, h) {
                    send_json(200, &json!({ "ok": true }))
                } else {
                    send_json(409, &json!({ "ok": false, "error": "no such preview" }))
                }
            }
        },
    );
    for (prefix, purpose) in [
        ("/templates/capture/", "template-capture"),
        ("/templates/repair/", "template-repair"),
        ("/templates/check/", "template-check"),
    ] {
        let a = app.clone();
        router.prefix(stages::PREFIXED, prefix, move |req, _| {
            let app = a.clone();
            async move {
                let read = if req.method() == Method::POST {
                    ReadBody::Json { limit: 16_384 }
                } else {
                    ReadBody::No
                };
                let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, purpose, 0, read).await {
                    FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                    FirewallRequest::Refused { .. } => return send_json(401, &json!({ "error": NOT_FIREWALL })),
                };
                let Some(t) = app.contracts.platform.get().and_then(|p| p.templates.get().cloned()) else {
                    return send_json(503, &json!({ "ok": false, "error": "This agent takes no templates" }));
                };
                let path = cc_http::pathname(&parts.uri.to_string());
                let b = match body {
                    FirewallBody::Json(b) => Some(b),
                    _ => None,
                };
                let too_often = || send_json(429, &json!({ "ok": false, "error": "asked too often" }));
                let session = || {
                    b.as_ref()
                        .and_then(|b| b.get("sessionId"))
                        .and_then(Value::as_str)
                        .filter(|s| SESSION.is_match(s))
                        .map(str::to_string)
                };
                let no_session = || send_json(400, &json!({ "ok": false, "error": "a session id is needed" }));
                let not_found = || send_json(404, &json!({ "error": "Not found" }));
                match purpose {
                    "template-capture" | "template-repair" => {
                        let capture = purpose == "template-capture";
                        if !admit(if capture { &CAPTURE_ASKED } else { &REPAIR_ASKED }, 20) {
                            return too_often();
                        }
                        let base = if capture { "/templates/capture" } else { "/templates/repair" };
                        if path == format!("{base}/facts") && parts.method == Method::GET {
                            if capture {
                                return send_json(200, &merged(json!({ "ok": true }), t.capture_session_facts()));
                            }
                            return match t.repair_facts().await {
                                Ok(Some(f)) => send_json(200, &merged(json!({ "ok": true }), f)),
                                Ok(None) => send_json(404, &json!({ "ok": false, "error": "no template" })),
                                Err(Busy) => send_json(409, &json!({ "ok": false, "error": BUSY })),
                            };
                        }
                        if path != format!("{base}/done") || parts.method != Method::POST {
                            return not_found();
                        }
                        let Some(s) = session() else { return no_session() };
                        let answer = if capture {
                            t.capture_session_done(&s).await
                        } else {
                            t.repair_done(&s).await
                        };
                        send_json(200, &answer)
                    }
                    _ => {
                        if path == "/templates/check/facts" && parts.method == Method::GET {
                            if !admit(&FACTS_ASKED, 20) {
                                return too_often();
                            }
                            return match t.check_facts().await {
                                Ok(Some(f)) => send_json(200, &merged(json!({ "ok": true }), f)),
                                Ok(None) => send_json(404, &json!({ "ok": false, "error": "no template" })),
                                Err(Busy) => send_json(409, &json!({ "ok": false, "error": BUSY })),
                            };
                        }
                        if path != "/templates/check/probe" || parts.method != Method::POST {
                            return not_found();
                        }
                        if !admit(&PROBE_ASKED, 120) {
                            return send_json(
                                429,
                                &json!({ "ok": false, "text": "This agent has answered many questions in the last minutes. Ask again later." }),
                            );
                        }
                        let verb = b.as_ref().and_then(|b| b.get("verb")).and_then(Value::as_str).filter(|v| VERB.is_match(v));
                        // Left out is fine; anything else must be a plain argument.
                        let arg = match b.as_ref().and_then(|b| b.get("arg")) {
                            None => Ok(None),
                            Some(Value::String(a)) if ARG.is_match(a) => Ok(Some(a.as_str())),
                            Some(_) => Err(()),
                        };
                        let (Some(verb), Ok(arg)) = (verb, arg) else {
                            return send_json(
                                200,
                                &json!({ "ok": false, "text": "That command or its argument is not one this agent answers." }),
                            );
                        };
                        if verb == "health" || verb == "model" {
                            if arg.is_some() {
                                return send_json(200, &json!({ "ok": false, "text": format!("{verb} takes no argument.") }));
                            }
                            let probe = app.contracts.platform.get().and_then(|p| p.health_probe.get().cloned());
                            let Some(probe) = probe else {
                                return send_json(200, &json!({ "ok": false, "text": "That could not be read on this agent." }));
                            };
                            let answer = probe(if verb == "health" { "health" } else { "model" }).await;
                            let text = serde_json::to_string_pretty(&answer).unwrap_or_default();
                            return send_json(200, &json!({ "ok": true, "text": text }));
                        }
                        send_json(200, &t.probe(verb, arg).await)
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proc::{Output, RecordingRunner};

    type Answer = Box<dyn Fn(&str, &str, Option<&Value>) -> Result<Value, CallError> + Send + Sync>;

    struct FakeConsole {
        calls: std::sync::Mutex<Vec<(String, String, Option<Value>)>>,
        answer: std::sync::Mutex<Answer>,
    }

    impl Console for FakeConsole {
        fn call(
            &self,
            method: &str,
            body: Option<Value>,
            path: String,
            _max: usize,
        ) -> cc_http::BoxFuture<Result<Value, CallError>> {
            let r = (lock(&self.answer))(method, &path, body.as_ref());
            lock(&self.calls).push((method.into(), path, body));
            Box::pin(async move { r })
        }
    }

    impl FakeConsole {
        fn assign(&self, a: Value) {
            *lock(&self.answer) =
                Box::new(move |m, _, _| Ok(if m == "GET" { a.clone() } else { json!({ "ok": true }) }));
        }
        fn posts(&self) -> Vec<Value> {
            lock(&self.calls)
                .iter()
                .filter(|c| c.0 == "POST")
                .filter_map(|c| c.2.clone())
                .collect()
        }
    }

    const H: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    struct Rig {
        svc: Arc<TemplateService>,
        console: Arc<FakeConsole>,
        runner: RecordingRunner,
        dir: tempfile::TempDir,
    }

    fn rig(firewall: bool, new: bool) -> Rig {
        let dir = tempfile::tempdir().expect("dir");
        let templates = dir.path().join("templates");
        std::fs::create_dir_all(templates.join("basic")).expect("mk");
        std::fs::write(templates.join("basic/template.yaml"), "name: basic\n").expect("w");
        let runner = RecordingRunner::new();
        runner.answer_with(|c| {
            let out = |v: Value| Some(cc_proc::ok(&v.to_string()));
            match c.args.get(1).map(String::as_str) {
                Some("facts") => out(json!({ "name": "basic", "hash": H, "steps": [{ "id": "a", "kind": "file" }, { "id": "b", "kind": "run" }], "mcp": [] })),
                Some("run") if c.args.iter().any(|a| a == "--check") => {
                    out(json!({ "result": "would-change", "steps": [{ "id": "a", "status": "would-change" }, { "id": "b", "status": "ok" }] }))
                }
                Some("run") => out(json!({ "result": "ok", "steps": [{ "id": "a", "status": "changed" }] })),
                _ => Some(Output {
                    code: Some(1),
                    ..Default::default()
                }),
            }
        });
        let console = Arc::new(FakeConsole {
            calls: std::sync::Mutex::new(Vec::new()),
            answer: std::sync::Mutex::new(Box::new(|_, _, _| Ok(json!({})))),
        });
        let r = runner.clone();
        let deps = Deps {
            writer: Arc::new(|| None),
            runner: Arc::new(r),
            home: dir.path().to_path_buf(),
            restart: Arc::new(|| Box::pin(async { Ok(()) })),
            log: Arc::new(|_| {}),
            bin: crate::platform::common::OPENCLAW_BIN.to_string(),
            unit_down: None,
            offline: crate::platform::common::no_offline(),
        };
        let svc = TemplateService::new(TemplateOptions {
            console: console.clone(),
            deps,
            node: "node".into(),
            runbook: "/rb.js".into(),
            templates_dir: templates,
            state_dir: dir.path().join("state"),
            home: dir.path().to_path_buf(),
            firewall: Arc::new(move || firewall),
            is_new: Arc::new(move || new),
            verify_after: Duration::from_secs(3600),
            runbook_state_dir: dir.path().join("runbook"),
            notes_helper_there: Arc::new(|| false),
        });
        Rig {
            svc,
            console,
            runner,
            dir,
        }
    }

    impl Rig {
        fn applies(&self) -> usize {
            self.runner
                .calls()
                .iter()
                .filter(|c| c.args.get(1).map(String::as_str) == Some("run") && !c.args.iter().any(|a| a == "--check"))
                .count()
        }
        fn state(&self, name: &str) -> Option<Value> {
            read_json(&self.dir.path().join("state").join(name))
        }
    }

    fn vars(note: &str) -> Vars {
        Vars {
            note: note.into(),
            name: "Ada".into(),
            time_zone: "UTC".into(),
        }
    }

    #[test]
    fn base64_is_read_as_node_reads_it() {
        assert_eq!(node_base64("IyEv"), b"#!/");
        assert_eq!(node_base64("IyE"), b"#!");
        assert_eq!(node_base64("I-E_"), node_base64("I+E/"));
        assert_eq!(node_base64("Iy=E"), b"#");
    }

    #[test]
    fn hashes_match_the_ts() {
        let v = Vars {
            note: "Hi \u{2028} \"q\" \u{e9}".into(),
            name: "Ada".into(),
            time_zone: "Europe/Rome".into(),
        };
        let a = "a".repeat(64);
        assert_eq!(
            payload_hash(&a, &v, false),
            "a7293ba75ecc0c39a516d06a0c33828cb0572f53686b331b0a16f6569f88fe3a"
        );
        assert_eq!(
            payload_hash(&a, &v, true),
            "410220e45e2da9b7e60fcf19be2f2e433eae04a811ec818fc0bed9f80374460f"
        );
        assert_eq!(
            overwrite_ticket(&"b".repeat(64)),
            "bc064f186872a72ad782696cef69eb3885678b3fefb75ebb4933d589479595a2"
        );
    }

    #[test]
    fn reads_the_console_answer_strictly() {
        let a = parse_assignment(&json!({
            "template": "basic", "name": "Ada\nLovelace", "timeZone": "bad zone!",
            "request": { "id": "short", "kind": "apply", "template": "basic" },
            "rerun": { "steps": ["a", "../x"], "at": "t" },
            "skills": { "id": "req-skills1", "items": [{ "payload": "sks-abcdefgh", "hash": H }, { "payload": "nope", "hash": H }] },
        }))
        .expect("parsed");
        assert_eq!(a.vars.name, "Ada Lovelace");
        assert_eq!(a.vars.time_zone, "UTC");
        assert!(a.request.is_none(), "a request id that is too short is no request");
        assert_eq!(a.rerun.expect("rerun").steps, vec!["a".to_string()]);
        assert_eq!(a.skills.expect("skills").items.len(), 1);
        assert!(parse_assignment(&json!("x")).is_none());
    }

    #[tokio::test]
    async fn an_apply_runs_once_with_the_values_the_code_confirmed() {
        let r = rig(true, false);
        r.console.assign(json!({
            "note": "first note", "name": "Ada", "timeZone": "UTC",
            "request": { "id": "preview-0001", "kind": "preview", "template": "basic" },
        }));
        r.svc.tick().await;
        let pending = r.svc.pending("preview-0001").expect("pending");
        assert_eq!(pending["change"], json!(1));
        assert_eq!(pending["scripts"], json!(1));
        assert_eq!(pending["steps"], json!(2));
        let payload = payload_hash(H, &vars("first note"), false);
        assert_eq!(pending["payload"], json!(payload));
        assert!(!r.svc.ticket("preview-0001", &payload_hash(H, &vars("other"), false)));
        assert!(r.svc.ticket("preview-0001", &payload));
        assert_eq!(r.applies(), 0);
        // The console now asks for the apply, with another note than the one confirmed.
        r.console.assign(json!({
            "note": "changed note", "name": "Ada", "timeZone": "UTC",
            "request": { "id": "apply-00001", "kind": "apply", "template": "basic", "preview": "preview-0001" },
        }));
        r.svc.tick().await;
        assert_eq!(r.applies(), 1);
        let applied = r.state("applied.json").expect("marker");
        assert_eq!(applied["vars"]["note"], json!("first note"));
        assert_eq!(applied["request"], json!("apply-00001"));
        assert!(r.state("ticket.json").is_none(), "the ticket is used up");
        // The same request again does nothing.
        r.svc.tick().await;
        assert_eq!(r.applies(), 1);
    }

    #[tokio::test]
    async fn an_apply_without_a_ticket_is_not_run() {
        let r = rig(true, false);
        r.console.assign(json!({
            "note": "", "name": "Ada", "timeZone": "UTC",
            "request": { "id": "apply-00001", "kind": "apply", "template": "basic", "preview": "preview-0001" },
        }));
        r.svc.tick().await;
        assert_eq!(r.applies(), 0);
        assert!(
            r.console
                .posts()
                .iter()
                .any(|p| p["unconfirmed"] == json!(true) && p["requestId"] == json!("apply-00001"))
        );
        assert!(r.state("applied.json").is_none());
    }

    #[tokio::test]
    async fn a_template_named_for_an_agent_no_longer_new_needs_a_code() {
        let r = rig(true, false);
        r.console
            .assign(json!({ "template": "basic", "note": "", "name": "Ada", "timeZone": "UTC" }));
        r.svc.tick().await;
        assert_eq!(r.applies(), 0);
        assert!(
            r.console
                .posts()
                .iter()
                .any(|p| p["unconfirmed"] == json!(true) && p["template"] == json!("basic"))
        );
    }

    #[tokio::test]
    async fn a_new_agent_applies_its_template_once() {
        let r = rig(true, true);
        r.console
            .assign(json!({ "template": "basic", "note": "n", "name": "Ada", "timeZone": "UTC" }));
        r.svc.tick().await;
        r.svc.tick().await;
        assert_eq!(r.applies(), 1);
        assert!(
            r.console
                .posts()
                .iter()
                .any(|p| p["kind"] == json!("run") && p["report"]["result"] == json!("ok"))
        );
    }

    #[tokio::test]
    async fn a_ticket_for_a_preview_never_made_is_refused() {
        let r = rig(true, false);
        assert!(!r.svc.ticket("preview-0001", H));
        assert!(r.svc.pending("preview-0001").is_none());
    }

    #[test]
    fn the_review_is_read_only_while_recent() {
        let d = tempfile::tempdir().expect("dir");
        let f =
            json!({ "step": "a", "path": "notes/a.md", "text": "x", "exists": true, "stamp": "2026-10-01T00:00:00Z" });
        let write = |at: String| {
            std::fs::write(d.path().join("review.json"), json!({ "template": "basic", "at": at, "files": [f.clone(), { "step": "b", "path": "../x", "text": "y" }] }).to_string()).expect("w")
        };
        write(iso_ms(now_ms()));
        let r = read_template_review(d.path()).expect("recent");
        assert_eq!(r["files"].as_array().map(Vec::len), Some(1));
        assert!(r["files"][0].get("stamp").is_none());
        write(iso_ms(now_ms() - TEMPLATE_REVIEW_MS - 1));
        assert!(read_template_review(d.path()).is_none());
    }

    #[tokio::test]
    async fn a_new_preview_voids_the_ticket_of_the_last_one() {
        let r = rig(true, false);
        let preview = |id: &str, note: &str| json!({ "note": note, "name": "Ada", "timeZone": "UTC", "request": { "id": id, "kind": "preview", "template": "basic" } });
        r.console.assign(preview("preview-0001", "a"));
        r.svc.tick().await;
        assert!(r.svc.ticket("preview-0001", &payload_hash(H, &vars("a"), false)));
        r.console.assign(preview("preview-0002", "b"));
        r.svc.tick().await;
        assert!(r.state("ticket.json").is_none());
        assert!(r.svc.pending("preview-0001").is_none());
        r.console.assign(json!({
            "note": "a", "name": "Ada", "timeZone": "UTC",
            "request": { "id": "apply-00001", "kind": "apply", "template": "basic", "preview": "preview-0001" },
        }));
        r.svc.tick().await;
        assert_eq!(r.applies(), 0);
    }

    #[tokio::test]
    async fn the_firewalls_reads_do_not_wait_on_a_round() {
        let r = rig(true, true);
        r.console
            .assign(json!({ "template": "basic", "note": "n", "name": "Ada", "timeZone": "UTC" }));
        r.svc.tick().await;
        let held = r.svc.exclusive.lock().await;
        assert!(r.svc.check_facts().await.is_err());
        assert!(r.svc.repair_facts().await.is_err());
        assert_eq!(r.svc.probe("verify", None).await["text"], json!(BUSY));
        assert_eq!(r.svc.probe("config", Some("a.b")).await["text"], json!(BUSY));
        drop(held);
        assert!(r.svc.check_facts().await.expect("free").is_some());
        assert!(!r.svc.verifying.load(Ordering::SeqCst));
    }

    #[test]
    fn a_flag_is_cleared_when_dropped() {
        let f = AtomicBool::new(false);
        {
            let _on = Flag::on(&f);
            assert!(f.load(Ordering::SeqCst));
        }
        assert!(!f.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn output_past_the_limit_is_a_failure() {
        let r = rig(true, true);
        r.runner.answer_with(|_| None);
        let big = "x".repeat(MAX_OUTPUT + 1);
        let runner = RecordingRunner::new();
        runner.answer_with(move |_| Some(cc_proc::ok(&big)));
        let mut deps = r.svc.o.deps.clone();
        deps.runner = Arc::new(runner);
        let svc = TemplateService::new(TemplateOptions {
            console: r.console.clone(),
            deps,
            node: "node".into(),
            runbook: "/rb.js".into(),
            templates_dir: r.dir.path().join("templates"),
            state_dir: r.dir.path().join("state2"),
            home: r.dir.path().to_path_buf(),
            firewall: Arc::new(|| true),
            is_new: Arc::new(|| true),
            verify_after: Duration::from_secs(3600),
            runbook_state_dir: r.dir.path().join("runbook"),
            notes_helper_there: Arc::new(|| false),
        });
        let ran = svc
            .run(vec!["/rb.js".into(), "review".into()], Duration::from_secs(1))
            .await;
        assert!(!ran.ok && ran.stdout.is_empty());
    }
}
