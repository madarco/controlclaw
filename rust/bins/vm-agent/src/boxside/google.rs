//! The organization's Google account on the agent box (`google.ts`, `routes/google.ts`). The org
//! firewall sends the whole desired state in one `POST /google/apply` (purpose `google`): the
//! placeholder this box puts in `Authorization`, whether the organization is connected, the
//! services granted and the Cloud project to bill. It becomes one environment file that the `gog`
//! wrapper sources on every command. No Google credential passes through here: the placeholder is
//! swapped for a real token by the firewall's proxy, for this box only.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_http::{FirewallBody, Req, Resp};
use cc_proc::Runner;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::exec::{exec, failure_line};
use super::web::{self, send_json};

/// `GOOGLE_VERSION_MS`; the console's status timeout stays above it.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
pub const GOG_BIN: &str = "/usr/local/bin/gog";

static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CC-GOOG-[0-9a-f]{8,64}$").expect("regex"));
static PROJECT_ID_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$").expect("regex"));
static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([0-9]+\.[0-9]+\.[0-9]+)").expect("regex"));

/// The services the firewall may name: an allowlist, as this list is written into a file agents read.
pub const SERVICES: [&str; 6] = ["gmail", "calendar", "drive", "contacts", "sheets", "docs"];

/// `LABEL_RE` (`/^[^\s<>"'\\]{3,254}$/`), its length counted in UTF-16 units as JavaScript does.
fn valid_label(s: &str) -> bool {
    let n = s.encode_utf16().count();
    (3..=254).contains(&n)
        && !s
            .chars()
            .any(|c| c.is_whitespace() || "<>\"'\\".contains(c) || c == '\u{feff}')
}

/// What the firewall asked for, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct GoogleApply {
    pub placeholder: Option<String>,
    pub connected: bool,
    pub project_id: Option<String>,
    pub services: Vec<String>,
    pub account_label: Option<String>,
    /// Whether this agent is ticked for the account, whatever state the connection is in.
    pub ticked: bool,
}

/// A string field that may also be null or absent; anything else is the message.
fn opt_str(body: &Map<String, Value>, key: &str, msg: &str) -> Result<Option<String>, String> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        // `raw ? String(raw) : null`: an empty string is none.
        Some(Value::String(s)) => Ok((!s.is_empty()).then(|| s.clone())),
        Some(_) => Err(msg.into()),
    }
}

/// `parseApply`: the values become environment variables and header values, so they are checked
/// here too, however trusted the sender.
pub fn parse_apply(body: &Map<String, Value>) -> Result<GoogleApply, String> {
    let placeholder = match body.get("placeholder") {
        Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => return Err("placeholder must be a string or null".into()),
    };
    if placeholder.as_deref().is_some_and(|p| !PLACEHOLDER_RE.is_match(p)) {
        return Err("placeholder is not the shape the firewall generates".into());
    }
    let project_id = opt_str(body, "projectId", "projectId must be a string or null")?;
    if project_id.as_deref().is_some_and(|p| !PROJECT_ID_RE.is_match(p)) {
        return Err("projectId is not a Google Cloud project id".into());
    }
    // Required, not defaulted: a missing list read as empty would tell every agent it has nothing.
    let Some(Value::Array(raw)) = body.get("services") else {
        return Err("services must be an array".into());
    };
    let mut services: Vec<String> = Vec::new();
    for s in raw {
        match s.as_str().filter(|s| SERVICES.contains(s)) {
            Some(s) => {
                if !services.iter().any(|x| x == s) {
                    services.push(s.to_string());
                }
            }
            None => return Err(format!("services[] {} is not a Google service", web::json_stringify(s))),
        }
    }
    let account_label = opt_str(body, "accountLabel", "accountLabel must be a string or null")?;
    if account_label.as_deref().is_some_and(|l| !valid_label(l)) {
        return Err("accountLabel is not an address".into());
    }
    let granted = match body.get("granted") {
        None => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => return Err("granted must be a boolean".into()),
    };
    let connected = body.get("connected") == Some(&Value::Bool(true));
    let ticked = granted.unwrap_or(connected && placeholder.is_some());
    Ok(GoogleApply {
        placeholder,
        connected,
        project_id,
        services,
        account_label,
        ticked,
    })
}

/// A value safe on the right of an environment-file assignment: single-quoted, the second gate
/// after the patterns above.
fn env_value(v: &str) -> String {
    format!("'{}'", v.replace('\'', "'\\''"))
}

/// What `state/google.json` says, read loosely.
struct Applied {
    connected: bool,
    project_id: Option<String>,
    services: Vec<String>,
    account_label: Option<String>,
    ticked: bool,
    at: String,
}

pub type Listener = Arc<dyn Fn() + Send + Sync>;

/// `GoogleService`. In the `google` contract slot for W8's meeting sign-in; empty without `gog`.
pub struct Google {
    env_path: PathBuf,
    state_path: PathBuf,
    gog_bin: PathBuf,
    runner: Arc<dyn Runner>,
    listeners: Mutex<Vec<Listener>>,
    /// One apply at a time: both files go through one `<path>.tmp` each.
    applying: Mutex<()>,
}

impl Google {
    pub fn new(runner: Arc<dyn Runner>, env_path: PathBuf, state_path: PathBuf) -> Self {
        Self {
            env_path,
            state_path,
            gog_bin: GOG_BIN.into(),
            runner,
            listeners: Mutex::new(Vec::new()),
            applying: Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn with_gog(mut self, p: PathBuf) -> Self {
        self.gog_bin = p;
        self
    }

    /// Whether this box has `gog` at all.
    pub fn supported(&self) -> bool {
        self.gog_bin.exists()
    }

    /// `onApplied`: called after each apply, in a task of its own so it never holds up the answer.
    pub fn on_applied(&self, f: Listener) {
        if let Ok(mut l) = self.listeners.lock() {
            l.push(f);
        }
    }

    /// One atomic write, or one removal. A box with no grant has no file at all.
    pub fn apply(&self, input: &GoogleApply) -> Result<bool, String> {
        let granted = input.connected && input.placeholder.is_some();
        let _one = self.applying.lock().unwrap_or_else(|e| e.into_inner());
        let write = || -> Result<(), String> {
            if let (true, Some(p)) = (granted, &input.placeholder) {
                let mut lines = vec![
                    "# Written by the ControlClaw agent from what the org firewall pushed. Do not edit:".to_string(),
                    "# the next push overwrites it. Nothing here is a secret.".into(),
                    "#".into(),
                    "# GOG_ACCESS_TOKEN is a PLACEHOLDER, not a token. The org firewall's proxy swaps it for a".into(),
                    "# real Google access token on *.googleapis.com, for this box only. It does not expire, so".into(),
                    "# ignore gog's note about a direct token expiring in about an hour (it prints that for any".into(),
                    "# --access-token and cannot tell ours from a real one).".into(),
                    format!("GOG_ACCESS_TOKEN={}", env_value(p)),
                    "GOG_HOME=/opt/controlclaw/gog".into(),
                    format!("CC_GOOGLE_SERVICES={}", env_value(&input.services.join(","))),
                ];
                if let Some(l) = &input.account_label {
                    lines.push(format!("CC_GOOGLE_ACCOUNT={}", env_value(l)));
                }
                if let Some(p) = &input.project_id {
                    lines.push(format!("GOG_QUOTA_PROJECT={}", env_value(p)));
                }
                lines.push(String::new());
                web::write_atomic(&self.env_path, lines.join("\n").as_bytes(), 0o600)?;
            } else {
                match std::fs::remove_file(&self.env_path) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        return Err(web::node_io(&e, "rm", &self.env_path.display().to_string(), None));
                    }
                    _ => {}
                }
            }
            let state = json!({
                "placeholder": if granted { json!("set") } else { Value::Null },
                "connected": input.connected,
                "projectId": input.project_id,
                "services": input.services,
                "accountLabel": input.account_label,
                "ticked": input.ticked,
                "at": web::iso(web::time_ms(std::time::SystemTime::now())),
            });
            let body = serde_json::to_string_pretty(&state).unwrap_or_default();
            web::write_atomic(&self.state_path, body.as_bytes(), 0o600)
        };
        write().map_err(|e| format!("Could not write this box's Google settings: {}", e))?;
        let listeners: Vec<Listener> = self.listeners.lock().map(|l| l.clone()).unwrap_or_default();
        if !listeners.is_empty() {
            // The grant is written; a listener must not fail the apply, nor (W8 asked) hold up its
            // answer. Outside a runtime they run here.
            let run = move || {
                for l in listeners {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| l()));
                }
            };
            match tokio::runtime::Handle::try_current() {
                Ok(h) => {
                    h.spawn_blocking(run);
                }
                Err(_) => run(),
            }
        }
        if granted {
            let services = if input.services.is_empty() {
                "no services".to_string()
            } else {
                input.services.join(", ")
            };
            tracing::info!(
                "[google] {} is available to gog ({services})",
                input.account_label.as_deref().unwrap_or("an account")
            );
        } else {
            tracing::info!("[google] no grant on this box; gog has nothing to send");
        }
        Ok(granted)
    }

    /// The account this agent is ticked for, or None. Still named while the connection fails.
    pub fn account(&self) -> Option<String> {
        self.read_state().filter(|a| a.ticked).and_then(|a| a.account_label)
    }

    /// Whether the firewall reported a working connection in its last apply.
    pub fn connected(&self) -> bool {
        self.read_state().is_some_and(|a| a.connected)
    }

    /// What the box has now; never the placeholder.
    pub async fn status(&self) -> Value {
        let applied = self.read_state();
        let version = self.version().await;
        json!({
            "gogVersion": version,
            // The file, not the remembered state.
            "hasPlaceholder": self.env_path.exists(),
            "connected": applied.as_ref().is_some_and(|a| a.connected),
            "services": applied.as_ref().map(|a| a.services.clone()).unwrap_or_default(),
            "projectId": applied.as_ref().and_then(|a| a.project_id.clone()),
            "accountLabel": applied.as_ref().and_then(|a| a.account_label.clone()),
            "at": applied.as_ref().map(|a| a.at.clone()),
        })
    }

    fn read_state(&self) -> Option<Applied> {
        let raw: Value = serde_json::from_str(&std::fs::read_to_string(&self.state_path).ok()?).ok()?;
        let o = raw.as_object()?;
        let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
        let connected = o.get("connected") == Some(&Value::Bool(true));
        Some(Applied {
            connected,
            project_id: s("projectId"),
            services: o
                .get("services")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .filter(|x| SERVICES.contains(x))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            account_label: s("accountLabel"),
            // Written before the field existed: a state with a placeholder was a grant.
            ticked: match o.get("ticked") {
                Some(Value::Bool(b)) => *b,
                _ => connected && o.get("placeholder").and_then(Value::as_str) == Some("set"),
            },
            at: s("at").unwrap_or_default(),
        })
    }

    /// `gog --version`, best effort: the first thing shaped like a version, else the first line.
    async fn version(&self) -> Option<String> {
        let bin = self.gog_bin.to_string_lossy();
        match exec(self.runner.as_ref(), &bin, &["--version"], VERSION_TIMEOUT, None).await {
            Ok(out) => VERSION_RE.captures(&out.stdout).map(|c| c[1].to_string()).or_else(|| {
                out.stdout
                    .trim()
                    .split('\n')
                    .next()
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
            }),
            Err(e) => {
                tracing::info!("[google] could not read the gog version: {}", failure_line(&e));
                None
            }
        }
    }
}

/// `handleGoogle`: the apply from the firewall only (`google`), the status with either token.
pub async fn handle(app: &crate::app::App, google: Option<&Google>, req: Req) -> Resp {
    let (parts, body) = match web::firewall_or_console(
        app,
        req,
        "google",
        "Google account changes must come from the org firewall",
    )
    .await
    {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let Some(service) = google else {
        return send_json(
            501,
            &json!({"error": "This agent does not have gog yet, so it cannot use your Google account. Update it."}),
            &[],
        );
    };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    let write = parts.method == http::Method::POST;
    if pathname == "/google/apply" && write {
        let FirewallBody::Json(b) = &body else {
            return send_json(400, &json!({"error": "invalid JSON body"}), &[]);
        };
        let input = match parse_apply(b) {
            Ok(i) => i,
            Err(e) => return send_json(400, &json!({"error": e}), &[]),
        };
        return match service.apply(&input) {
            Ok(granted) => send_json(200, &json!({"ok": true, "granted": granted}), &[]),
            Err(e) => send_json(500, &json!({"error": e}), &[]),
        };
    }
    if pathname == "/google/status" && parts.method == http::Method::GET {
        return send_json(200, &service.status().await, &[]);
    }
    send_json(404, &json!({"error": "Not found"}), &[])
}

/// Where the `gog` wrapper reads the grant: `state/gog.env`.
pub fn env_path(state_dir: &Path) -> PathBuf {
    state_dir.join("gog.env")
}

#[cfg(test)]
mod tests;
