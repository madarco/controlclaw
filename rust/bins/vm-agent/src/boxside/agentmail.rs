//! The agent's AgentMail inbox (`agentmail.ts`, `routes/agentmail.ts`). The org firewall sends the
//! placeholder, the inbox and who may write to it (purpose `agentmail`); the placeholder goes in
//! `~/.openclaw/.env` as `AGENTMAIL_API_KEY`, the plugin and channel into OpenClaw's config, and
//! OpenClaw is restarted and watched until the settings are live. The answer comes at once
//! (`status: pending`); `GET /agentmail/status` says how it ended.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Req, Resp};
use regex::Regex;
use serde_json::{Map, Value, json};

use super::web::send_json;
use crate::platform::common::{CONFIG_PATCH_RESTART, GATEWAY_READ};

/// `GATEWAY_START_LIMIT_MS`: as long as the watchdog gives OpenClaw to start.
const GATEWAY_START_LIMIT: Duration = Duration::from_secs(15 * 60);

/// zod's `z.email()` pattern.
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[A-Za-z0-9_'+\-]+\.)*[A-Za-z0-9_'+\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$",
    )
    .expect("regex")
});

fn email(v: &Value) -> Option<String> {
    v.as_str()
        .filter(|s| s.encode_utf16().count() <= 254 && EMAIL.is_match(s))
        .map(str::to_string)
}

/// `AgentMailApply`. All three None is "forget the inbox".
#[derive(Debug, Clone, PartialEq)]
pub struct AgentMailApply {
    pub placeholder: Option<String>,
    pub inbox_id: Option<String>,
    pub human_email: Option<String>,
    pub allowed_senders: Option<Vec<String>>,
}

impl AgentMailApply {
    /// `allowedSenders ?? [humanEmail]`, what the channel's `allowFrom` is set to.
    fn allow_from(&self) -> Value {
        match &self.allowed_senders {
            Some(a) => json!(a),
            None => json!([self.human_email]),
        }
    }

    /// `open` only with the firewall's wildcard.
    fn dm_policy(&self) -> &'static str {
        match self.allowed_senders.as_deref() {
            Some([one]) if one == "*" => "open",
            _ => "allowlist",
        }
    }
}

/// `parseAgentMailApply`: None is the route's 400.
pub fn parse_apply(raw: &Map<String, Value>) -> Option<AgentMailApply> {
    static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CC-AMAIL-[0-9a-f]{32}$").expect("regex"));
    static INBOX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9._+-]+@agentmail\.to$").expect("regex"));
    if raw.get("placeholder") == Some(&Value::Null) && raw.get("inboxId") == Some(&Value::Null) {
        return Some(AgentMailApply {
            placeholder: None,
            inbox_id: None,
            human_email: None,
            allowed_senders: None,
        });
    }
    let placeholder = raw.get("placeholder")?.as_str().filter(|p| PLACEHOLDER.is_match(p))?;
    let inbox_id = raw.get("inboxId")?.as_str().filter(|i| INBOX.is_match(i))?;
    let human = raw.get("humanEmail").unwrap_or(&Value::Null);
    let human_email = email(human)?;
    let allowed = match raw.get("allowedSenders") {
        None => json!([human]),
        Some(v) => v.clone(),
    };
    let list: Vec<String> = match allowed.as_array() {
        Some(a) if a.len() == 1 && a[0] == json!("*") => vec!["*".into()],
        Some(a) if a.len() <= 50 => a.iter().map(email).collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    let mut seen: Vec<String> = Vec::new();
    for s in list {
        if !seen.contains(&s) {
            seen.push(s);
        }
    }
    Some(AgentMailApply {
        placeholder: Some(placeholder.into()),
        inbox_id: Some(inbox_id.into()),
        human_email: Some(human_email),
        allowed_senders: Some(seen),
    })
}

#[derive(Debug, Clone)]
struct Record {
    id: u64,
    inbox_id: Option<String>,
    placeholder: Option<String>,
    allowed_senders: Vec<String>,
    status: &'static str,
}

impl Record {
    fn to_json(&self) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("inboxId".into(), json!(self.inbox_id));
        m.insert("placeholder".into(), json!(self.placeholder));
        m.insert("allowedSenders".into(), json!(self.allowed_senders));
        m.insert("status".into(), json!(self.status));
        m
    }
}

/// `AgentMailService`. In the `agentmail` slot, for W8's invite reader (`status().inboxId`).
pub struct AgentMail {
    /// Weak: the app holds this service in its contracts.
    app: std::sync::Weak<crate::app::App>,
    env_path: PathBuf,
    last: Mutex<Option<Record>>,
    ids: AtomicU64,
    serial: tokio::sync::Mutex<()>,
    /// Between tries while waiting for OpenClaw; a test makes them short.
    pace: Duration,
}

impl AgentMail {
    pub fn new(app: &Arc<crate::app::App>, env_path: PathBuf) -> Self {
        Self {
            app: Arc::downgrade(app),
            env_path,
            last: Mutex::new(None),
            ids: AtomicU64::new(0),
            serial: tokio::sync::Mutex::new(()),
            pace: Duration::from_secs(2),
        }
    }

    #[cfg(test)]
    pub fn with_pace(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
    }

    /// The last apply: `{inboxId, placeholder, allowedSenders, status}`, or None.
    pub fn status(&self) -> Option<Value> {
        self.last.lock().ok()?.as_ref().map(|r| Value::Object(r.to_json()))
    }

    /// Start an apply and answer at once. The same apply while one is pending is that one.
    pub fn start(self: &Arc<Self>, input: AgentMailApply) -> Map<String, Value> {
        let allowed = input
            .allowed_senders
            .clone()
            .unwrap_or_else(|| input.human_email.iter().cloned().collect());
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = last.as_ref()
            && r.status == "pending"
            && r.inbox_id == input.inbox_id
            && r.placeholder == input.placeholder
            && r.allowed_senders == allowed
        {
            return r.to_json();
        }
        let id = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        let record = Record {
            id,
            inbox_id: input.inbox_id.clone(),
            placeholder: input.placeholder.clone(),
            allowed_senders: allowed,
            status: "pending",
        };
        *last = Some(record.clone());
        drop(last);
        let me = self.clone();
        tokio::spawn(async move {
            let status = if me.apply(&input).await.is_ok() {
                "active"
            } else {
                "failed"
            };
            // Only the record this apply made: a newer one has its own outcome coming.
            if let Ok(mut l) = me.last.lock()
                && let Some(r) = l.as_mut().filter(|r| r.id == id)
            {
                r.status = status;
            }
        });
        record.to_json()
    }

    /// One at a time.
    pub async fn apply(&self, input: &AgentMailApply) -> Result<(), String> {
        let _one = self.serial.lock().await;
        self.write(input).await
    }

    fn write_env(&self, placeholder: Option<&str>) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        static STALE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^\s*(?:export\s+)?AGENTMAIL_(?:API_KEY|WEBHOOK_SECRET)\s*=").expect("regex"));
        // `existsSync ? readFileSync(…, "utf8") : ""`: a file that is there but cannot be read
        // fails the apply rather than being written over as if empty.
        let shown = self.env_path.display().to_string();
        let current = match std::fs::read(&self.env_path) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(super::web::node_io(&e, "open", &shown, None)),
        };
        // Other integrations kept; stale webhook credentials removed so ingress uses the socket.
        let mut lines: Vec<String> = current
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
            .filter(|l| !STALE.is_match(l))
            .collect();
        if let Some(p) = placeholder {
            lines.push(format!("AGENTMAIL_API_KEY={p}"));
        }
        if let Some(dir) = self.env_path.parent() {
            std::fs::create_dir_all(dir)
                .map_err(|e| super::web::node_io(&e, "mkdir", &dir.display().to_string(), None))?;
        }
        let tmp = PathBuf::from(format!("{}.agentmail.tmp", self.env_path.display()));
        let tmp_shown = tmp.display().to_string();
        let body: Vec<String> = lines.into_iter().filter(|l| !l.is_empty()).collect();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| super::web::node_io(&e, "open", &tmp_shown, None))?;
        f.write_all(format!("{}\n", body.join("\n")).as_bytes())
            .map_err(|e| super::web::node_io(&e, "write", &tmp_shown, None))?;
        drop(f);
        std::fs::rename(&tmp, &self.env_path).map_err(|e| super::web::node_io(&e, "rename", &tmp_shown, Some(&shown)))
    }

    async fn write(&self, input: &AgentMailApply) -> Result<(), String> {
        let Some(app) = self.app.upgrade() else {
            return Err("OpenClaw is not running".into());
        };
        let oc = app.contracts.openclaw.get().filter(|o| o.client.connected());
        let Some(oc) = oc else {
            return Err("OpenClaw is not running".into());
        };
        let client = oc.client.clone();
        let snapshot = client
            .call("config.get", json!({}), GATEWAY_READ)
            .await
            .map_err(|e| e.to_string())?;
        let Some(hash) = snapshot.get("hash").and_then(Value::as_str).filter(|h| !h.is_empty()) else {
            return Err("OpenClaw returned no config hash".into());
        };
        let placeholder = input.placeholder.as_deref();
        self.write_env(placeholder)?;
        let key_ref = json!({"source": "env", "provider": "default", "id": "AGENTMAIL_API_KEY"});
        let mut patch = Map::new();
        patch.insert(
            "plugins".into(),
            json!({"entries": {"agentmail": {
                "enabled": placeholder.is_some(),
                "config": if placeholder.is_some() { json!({"apiKey": key_ref}) } else { json!({"apiKey": null}) },
            }}}),
        );
        patch.insert(
            "channels".into(),
            json!({"agentmail": if placeholder.is_some() {
                json!({
                    "apiKey": key_ref,
                    "inboxId": input.inbox_id,
                    "dmPolicy": input.dm_policy(),
                    "allowFrom": input.allow_from(),
                    "webhookSecret": null,
                })
            } else {
                Value::Null
            }}),
        );
        let mut opts = cc_openclaw::PatchOptions::new(CONFIG_PATCH_RESTART);
        opts.base_hash = Some(hash.to_string());
        opts.snapshot = Some(snapshot.clone());
        opts.read_timeout = Some(GATEWAY_READ);
        // Sender edits and forgetting the inbox remove list entries.
        opts.replace_paths = vec!["channels.agentmail.allowFrom".into()];
        // A timed-out patch may already be saved: restart and check the live config either way.
        let _patched = oc.config.patch(&patch, opts).await;
        let disconnected = Arc::new(AtomicBool::new(false));
        let watcher = {
            let mut rx = client.connection_state();
            let flag = disconnected.clone();
            // Subscribed while connected, so any change at all went through a disconnect, even
            // when the watch folded it into the reconnect that followed.
            rx.mark_unchanged();
            tokio::spawn(async move {
                if rx.changed().await.is_ok() {
                    flag.store(true, Ordering::SeqCst);
                }
            })
        };
        let restarted = super::exec::restart_service(app.runner.as_ref(), &app.config.service)
            .await
            .is_ok();
        let result = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let until = tokio::time::Instant::now() + GATEWAY_START_LIMIT;
            while tokio::time::Instant::now() < until {
                if client.when_connected(Duration::from_secs(5)).await
                    && let Ok(live) = client.call("config.get", json!({}), GATEWAY_READ).await
                    && (restarted || disconnected.load(Ordering::SeqCst))
                    && cc_openclaw::config_queue::config_active(&live) == Some(true)
                    && self.is_live(input, &live)
                {
                    return Ok(());
                }
                tokio::time::sleep(self.pace).await;
            }
            Err("AgentMail settings were saved but OpenClaw did not activate them".to_string())
        }
        .await;
        watcher.abort();
        result
    }

    /// The live config holds what was asked for.
    fn is_live(&self, input: &AgentMailApply, live: &Value) -> bool {
        let channel = &live["config"]["channels"]["agentmail"];
        let enabled = &live["config"]["plugins"]["entries"]["agentmail"]["enabled"];
        if input.placeholder.is_some() {
            channel["inboxId"] == json!(input.inbox_id)
                && *enabled == Value::Bool(true)
                && channel["dmPolicy"] == json!(input.dm_policy())
                && channel["allowFrom"] == input.allow_from()
        } else {
            !crate::phone::model::truthy(Some(channel)) && *enabled == Value::Bool(false)
        }
    }
}

/// `handleAgentMail`: firewall-signed (`agentmail`), reads included.
pub async fn handle(app: &crate::app::App, service: &Arc<AgentMail>, req: Req) -> Resp {
    let read = if req.method() == http::Method::POST {
        ReadBody::Json { limit: 16384 }
    } else {
        ReadBody::No
    };
    let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "agentmail", 0, read).await {
        FirewallRequest::Accepted { parts, body, .. } => (parts, body),
        FirewallRequest::Refused { .. } => {
            return send_json(
                401,
                &json!({"error": "AgentMail changes must come from the org firewall"}),
                &[],
            );
        }
    };
    let pathname = cc_http::pathname(&parts.uri.to_string());
    if parts.method == http::Method::GET && pathname == "/agentmail/status" {
        let apply = service.status().unwrap_or(Value::Null);
        return send_json(200, &json!({"apply": apply}), &[]);
    }
    if parts.method != http::Method::POST || pathname != "/agentmail/apply" {
        return send_json(404, &json!({"error": "Not found"}), &[]);
    }
    // The TS's 503 "OpenClaw is not available" was for the moment before `start` made the
    // service; here it exists from registration, so there is no such moment.
    let input = match &body {
        FirewallBody::Json(b) => parse_apply(b),
        _ => None,
    };
    let Some(input) = input else {
        return send_json(400, &json!({"error": "Invalid AgentMail configuration"}), &[]);
    };
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.extend(service.start(input));
    send_json(200, &Value::Object(out), &[])
}

#[cfg(test)]
mod tests;
