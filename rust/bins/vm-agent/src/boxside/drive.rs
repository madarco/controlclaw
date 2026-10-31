//! Google Drive folders on the agent box (`drive.ts`, `routes/drive.ts`). The org firewall sends
//! the whole desired mount set in one `POST /drive/apply` (purpose `drive`); it is written to
//! `state/drive.json` and `sudo systemd-run --unit=cc-drive-apply --collect cc-drive-apply` is
//! launched detached. The root script takes no arguments: it reads the file. The unit name is also
//! the mutex, so a second launch while one runs is "already reconciling", not an error. Health comes
//! back from `state/drive-mounts.json` (written by the script) and each mount's rclone on loopback.

use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use cc_http::{FirewallBody, Req, Resp};
use cc_proc::Runner;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::exec::{exec, failure_line};
use super::web::{self, send_json};

/// Launching the detached unit, not running the reconcile.
const LAUNCH_TIMEOUT: Duration = Duration::from_secs(20);
const RC_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_MOUNTS: usize = 8;
const APPLY_UNIT: &str = "cc-drive-apply";
pub const APPLY_SCRIPT: &str = "/usr/local/bin/cc-drive-apply";

static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,39}$").expect("regex"));
static FOLDER_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{10,200}$").expect("regex"));
static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CC-DRIVE-[0-9a-f]{8,64}$").expect("regex"));
static SETTING_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9,.]{1,64}$").expect("regex"));
static ALREADY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)already loaded|already exists|already running").expect("regex"));

const DRIVE_SCOPES: [&str; 3] = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/drive.metadata.readonly",
];

fn valid_name(n: &str) -> bool {
    NAME_RE.is_match(n) && !n.ends_with(' ')
}

pub use crate::phone::model::truthy;

/// Why a body was not taken: the route's 400, or (as in TS, where `null.name` throws out of
/// `parseApply` into the route's catch) its 500.
#[derive(Debug, PartialEq)]
pub enum Refused {
    Bad(String),
    Threw(String),
}

/// `parseApply`, in the TS's order and words. The result is the desired file as written.
pub fn parse_apply(body: &Map<String, Value>) -> Result<Value, Refused> {
    let bad = |m: String| Err(Refused::Bad(m));
    let placeholder = body.get("placeholder").and_then(Value::as_str).unwrap_or("");
    if !PLACEHOLDER_RE.is_match(placeholder) {
        return bad("placeholder is not the shape the firewall generates".into());
    }
    let scope = body.get("scope").and_then(Value::as_str).unwrap_or("");
    if !DRIVE_SCOPES.contains(&scope) {
        return bad("scope is not a Google Drive scope".into());
    }
    let empty = Map::new();
    let d = body.get("defaults").and_then(Value::as_object).unwrap_or(&empty);
    let text = |k: &str, default: &str| d.get(k).and_then(Value::as_str).unwrap_or(default).to_string();
    let defaults = [
        ("exportFormats", text("exportFormats", "docx,xlsx,pdf")),
        ("vfsCacheMaxSize", text("vfsCacheMaxSize", "2G")),
        ("vfsCacheMinFreeSpace", text("vfsCacheMinFreeSpace", "4G")),
    ];
    for (key, value) in &defaults {
        if !SETTING_RE.is_match(value) {
            return bad(format!(
                "defaults.{key} has characters that cannot go on a command line"
            ));
        }
    }
    // Required: a missing set read as empty would unmount everything.
    let Some(Value::Array(raw)) = body.get("mounts") else {
        return bad("mounts must be an array".into());
    };
    if raw.len() > MAX_MOUNTS {
        return bad(format!("at most {MAX_MOUNTS} Drive folders"));
    }
    let mut mounts = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for m in raw {
        if m.is_null() {
            return Err(Refused::Threw("Cannot read properties of null (reading 'name')".into()));
        }
        let name = m.get("name").and_then(Value::as_str).unwrap_or("");
        let folder_id = m.get("folderId").and_then(Value::as_str).unwrap_or("");
        if !valid_name(name) {
            return bad(format!(
                "mounts[].name {} cannot be a directory name",
                web::json_stringify(&json!(name))
            ));
        }
        if !FOLDER_ID_RE.is_match(folder_id) {
            return bad(format!(
                "mounts[].folderId {} is invalid",
                web::json_stringify(&json!(folder_id))
            ));
        }
        let mode = match m.get("mode").and_then(Value::as_str) {
            Some(x @ ("ro" | "rw")) => x,
            _ => return bad("mounts[].mode must be ro or rw".into()),
        };
        let lower = name.to_lowercase();
        if seen.contains(&lower) {
            return bad(format!(
                "two folders are both named {}",
                web::json_stringify(&json!(name))
            ));
        }
        seen.push(lower);
        mounts.push(json!({"name": name, "folderId": folder_id, "mode": mode}));
    }
    Ok(json!({
        "placeholder": placeholder,
        "scope": scope,
        "connected": body.get("connected") == Some(&Value::Bool(true)),
        "defaults": {
            "exportFormats": defaults[0].1,
            // Default true: a Google-native file reads as 0 bytes through the mount.
            "skipGdocs": d.get("skipGdocs") != Some(&Value::Bool(false)),
            "vfsCacheMaxSize": defaults[1].1,
            "vfsCacheMinFreeSpace": defaults[2].1,
        },
        "mounts": mounts,
    }))
}

/// The reconcile's own report, its shape checked rather than trusted.
struct ApplyState {
    status: String,
    detail: String,
    connected: bool,
    unsaved: Vec<Value>,
    mounts: Vec<Map<String, Value>>,
    at: String,
}

/// One mount's rclone `vfs/stats`.
struct Stats {
    bytes_used: Value,
    uploads_queued: f64,
    uploads_queued_v: Value,
    errored_files: Value,
    out_of_space: bool,
}

/// `DriveService`.
pub struct Drive {
    desired_path: PathBuf,
    state_path: PathBuf,
    apply_script: PathBuf,
    runner: Arc<dyn Runner>,
    http: reqwest::Client,
    /// One write of the desired file at a time (one `<path>.tmp`).
    writing: std::sync::Mutex<()>,
}

impl Drive {
    pub fn new(runner: Arc<dyn Runner>, desired_path: PathBuf, state_path: PathBuf) -> Self {
        Self {
            desired_path,
            state_path,
            apply_script: APPLY_SCRIPT.into(),
            runner,
            // Loopback only, never through a proxy.
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            writing: std::sync::Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn with_script(mut self, p: PathBuf) -> Self {
        self.apply_script = p;
        self
    }

    /// Whether this box has Drive support installed at all.
    pub fn supported(&self) -> bool {
        self.apply_script.exists()
    }

    /// The modes of the set last asked for, read fresh from the desired file.
    fn modes(&self) -> Map<String, Value> {
        let mut out = Map::new();
        let Some(desired) = std::fs::read_to_string(&self.desired_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        else {
            return out;
        };
        for m in desired.get("mounts").and_then(Value::as_array).into_iter().flatten() {
            if let Some(name) = m.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) {
                out.insert(name.into(), m.get("mode").cloned().unwrap_or(Value::Null));
            }
        }
        out
    }

    fn read_state(&self) -> Option<ApplyState> {
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.state_path).ok()?).ok()?;
        let o = raw.as_object()?;
        let mounts = o.get("mounts")?.as_array()?;
        let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        Some(ApplyState {
            status: s("status").unwrap_or_else(|| "unknown".into()),
            detail: s("detail").unwrap_or_default(),
            connected: o.get("connected") == Some(&Value::Bool(true)),
            unsaved: o
                .get("unsaved")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|u| u.get("name").is_some_and(Value::is_string))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            mounts: mounts
                .iter()
                .filter_map(Value::as_object)
                .filter(|m| {
                    m.get("name").is_some_and(Value::is_string) && m.get("rcPort").is_some_and(Value::is_number)
                })
                .cloned()
                .collect(),
            at: s("at").unwrap_or_default(),
        })
    }

    /// Write the set and launch the reconcile; `reconciling: false` means one was already running.
    pub async fn apply(&self, input: &Value) -> Result<Value, String> {
        let previous = std::fs::read_to_string(&self.desired_path).ok();
        let body = serde_json::to_string_pretty(input).unwrap_or_default();
        {
            let _one = self.writing.lock().unwrap_or_else(|e| e.into_inner());
            web::write_atomic(&self.desired_path, body.as_bytes(), 0o640)?;
        }
        let folders: Vec<Value> = input["mounts"]
            .as_array()
            .map(|a| a.iter().map(|m| m["name"].clone()).collect())
            .unwrap_or_default();
        let script = self.apply_script.to_string_lossy().into_owned();
        let unit = format!("--unit={APPLY_UNIT}");
        let launched = exec(
            self.runner.as_ref(),
            "sudo",
            &["/usr/bin/systemd-run", &unit, "--collect", &script],
            LAUNCH_TIMEOUT,
            None,
        )
        .await;
        if let Err(e) = launched {
            let line = failure_line(&e);
            if ALREADY_RE.is_match(&line) {
                tracing::info!("[drive] a reconcile is already running; the new set is on disk and will be applied");
                return Ok(json!({"ok": true, "reconciling": false, "folders": folders}));
            }
            // Put the previous set back, so an unattended run does not apply a refused set.
            if let Some(p) = previous {
                let _one = self.writing.lock().unwrap_or_else(|e| e.into_inner());
                let _ = web::write_atomic(&self.desired_path, p.as_bytes(), 0o640);
            }
            tracing::info!("[drive] could not launch the reconcile: {line}");
            return Err(line);
        }
        let n = folders.len();
        let connected = input["connected"] == Value::Bool(true);
        tracing::info!(
            "[drive] reconciling {n} folder(s){}",
            if connected {
                ""
            } else {
                " (no Google connection, they stay unmounted)"
            }
        );
        Ok(json!({"ok": true, "reconciling": true, "folders": folders}))
    }

    async fn rc(&self, port: &Value, path: &str) -> Option<Value> {
        let port = web::js_string(port);
        let res = self
            .http
            .post(format!("http://127.0.0.1:{port}{path}"))
            .timeout(RC_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !res.status().is_success() {
            return None;
        }
        res.json::<Value>().await.ok()
    }

    async fn stats(&self, port: &Value) -> Option<Stats> {
        let body = self.rc(port, "/vfs/stats").await?;
        let c = body.get("diskCache").filter(|c| truthy(Some(c)))?;
        let num = |k: &str| match c.get(k) {
            Some(v @ Value::Number(_)) => v.clone(),
            _ => json!(0),
        };
        let queued = num("uploadsQueued");
        Some(Stats {
            bytes_used: num("bytesUsed"),
            uploads_queued: queued.as_f64().unwrap_or(0.0),
            uploads_queued_v: queued,
            errored_files: num("erroredFiles"),
            out_of_space: c.get("outOfSpace") == Some(&Value::Bool(true)),
        })
    }

    /// Queued writes already tried and not being tried now: refused, waiting to try again.
    async fn failing(&self, port: &Value) -> Option<usize> {
        let body = self.rc(port, "/vfs/queue").await?;
        let q = body.get("queue")?.as_array()?;
        Some(
            q.iter()
                .filter(|i| {
                    i.get("tries").and_then(Value::as_f64).is_some_and(|t| t >= 1.0)
                        && i.get("uploading") != Some(&Value::Bool(true))
                })
                .count(),
        )
    }

    /// Every mount is reported, even one whose rclone is not answering.
    pub async fn status(&self) -> Value {
        let Some(state) = self.read_state() else {
            return json!({"connected": false, "applyStatus": "none", "applyDetail": "", "unsaved": [], "mounts": [], "at": null});
        };
        let modes = self.modes();
        let rows = futures_util::future::join_all(state.mounts.iter().map(|m| {
            let modes = &modes;
            let connected = state.connected;
            async move {
                let mounted = truthy(m.get("mounted"));
                let port = m.get("rcPort").cloned().unwrap_or(Value::Null);
                let stats = if mounted { self.stats(&port).await } else { None };
                let failing = match &stats {
                    Some(s) if mounted && s.uploads_queued > 0.0 => {
                        self.failing(&port).await.map(|n| json!(n)).unwrap_or(Value::Null)
                    }
                    Some(_) => json!(0),
                    None => Value::Null,
                };
                let name = m.get("name").cloned().unwrap_or(Value::Null);
                let active = m.get("active").cloned().unwrap_or(Value::Null);
                let last_error = if mounted || !connected {
                    Value::Null
                } else {
                    json!(format!("the mount is {}", js_template(m.get("active"))))
                };
                // Built field by field: a field the report lacks is left out, as `JSON.stringify` drops
                // `undefined`.
                let mut row = Map::new();
                row.insert("name".into(), name.clone());
                row.insert(
                    "mode".into(),
                    name.as_str().and_then(|n| modes.get(n)).cloned().unwrap_or(Value::Null),
                );
                if let Some(v) = m.get("mounted") {
                    row.insert("mounted".into(), v.clone());
                }
                if m.contains_key("active") {
                    row.insert("active".into(), active);
                }
                row.insert(
                    "cacheBytes".into(),
                    stats.as_ref().map(|s| s.bytes_used.clone()).unwrap_or(Value::Null),
                );
                row.insert(
                    "queuedUploads".into(),
                    stats
                        .as_ref()
                        .map(|s| s.uploads_queued_v.clone())
                        .unwrap_or(Value::Null),
                );
                row.insert("failingUploads".into(), failing);
                row.insert(
                    "erroredFiles".into(),
                    stats.as_ref().map(|s| s.errored_files.clone()).unwrap_or(Value::Null),
                );
                row.insert(
                    "outOfSpace".into(),
                    stats.as_ref().map(|s| json!(s.out_of_space)).unwrap_or(Value::Null),
                );
                row.insert("lastError".into(), last_error);
                Value::Object(row)
            }
        }))
        .await;
        json!({
            "connected": state.connected,
            "applyStatus": state.status,
            "applyDetail": state.detail,
            "unsaved": state.unsaved,
            "mounts": rows,
            "at": state.at,
        })
    }

    /// `summary()` for `/status`: a file read, no rclone call.
    pub fn summary(&self) -> Option<Value> {
        let state = self.read_state()?;
        let mounted = state.mounts.iter().filter(|m| truthy(m.get("mounted"))).count();
        Some(json!({"folders": state.mounts.len(), "mounted": mounted, "connected": state.connected}))
    }
}

/// `${v}` in a template literal, for a field that may be missing.
fn js_template(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(other) => web::js_string(other),
    }
}

/// `handleDrive`: the apply from the firewall only (`drive`), the status with either token.
pub async fn handle(app: &crate::app::App, drive: Option<&Drive>, req: Req) -> Resp {
    let (parts, body) = match web::firewall_or_console(
        app,
        req,
        "drive",
        "Drive folder changes must come from the org firewall",
    )
    .await
    {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let Some(service) = drive else {
        return send_json(
            501,
            &json!({"error": "This agent's software does not support Drive folders yet. Update it."}),
            &[],
        );
    };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    if pathname == "/drive/apply" && parts.method == http::Method::POST {
        let FirewallBody::Json(b) = &body else {
            return send_json(400, &json!({"error": "invalid JSON body"}), &[]);
        };
        let input = match parse_apply(b) {
            Ok(i) => i,
            Err(Refused::Bad(e)) => return send_json(400, &json!({"error": e}), &[]),
            Err(Refused::Threw(e)) => return send_json(500, &json!({"error": e}), &[]),
        };
        return match service.apply(&input).await {
            // 202: accepted, and the reconcile is running.
            Ok(v) => send_json(202, &v, &[]),
            Err(e) => send_json(500, &json!({"error": e}), &[]),
        };
    }
    if pathname == "/drive/status" && parts.method == http::Method::GET {
        return send_json(200, &service.status().await, &[]);
    }
    send_json(404, &json!({"error": "Not found"}), &[])
}

#[cfg(test)]
mod tests;
