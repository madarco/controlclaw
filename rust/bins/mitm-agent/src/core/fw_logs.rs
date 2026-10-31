//! The firewall's own Logs page (`fw-logs.ts`, `fw-logs-types.ts`, `fw-page-door.ts`,
//! `fw-logs-page.ts`, apps/saas/docs/features/firewall-logs.md): each service's journal and the
//! last update run, read through the root helper `cc-fw-logs`, every line masked with the secrets
//! this firewall holds, for an owner in an enrolled browser. The door is an open intent for this
//! firewall, posted from its own origin, which buys a two-hour cookie scoped to the page's path.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use futures_util::FutureExt;
use futures_util::future::{BoxFuture as FBox, Shared};
use rand::RngCore;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::access::AccessFirewall;
use super::fw_shell::{FwPage, fw_notice, fw_shell_page};

pub const FW_LOGS_HELPER: &str = "/usr/local/bin/cc-fw-logs";
const UPDATE_STATE: &str = "/opt/controlclaw/state/update.json";
const MAX_LINES: usize = 3000;
const MAX_MESSAGE: usize = 4000;

/// The ranges the page offers, in seconds.
pub fn range_seconds(range: &str) -> Option<u64> {
    match range {
        "15m" => Some(15 * 60),
        "1h" => Some(60 * 60),
        "24h" => Some(24 * 60 * 60),
        _ => None,
    }
}

struct Service {
    id: &'static str,
    label: &'static str,
    about: &'static str,
    status: Option<&'static str>,
    units: &'static str,
    optional: bool,
}

/// The catalog. The ids are the contract with the helper; `status` is what `systemctl show` reads.
const SERVICES: &[Service] = &[
    Service {
        id: "mitm-agent",
        label: "Firewall agent",
        about: "Rules, sync with the console, this page",
        status: Some("controlclaw-mitm-agent.service"),
        units: r"^controlclaw-mitm-agent\.service$",
        optional: false,
    },
    Service {
        id: "proxy",
        label: "Proxy",
        about: "Every request your agents make",
        status: Some("controlclaw-mitmproxy.service"),
        units: r"^controlclaw-mitmproxy\.service$",
        optional: false,
    },
    Service {
        id: "caddy",
        label: "Caddy",
        about: "HTTPS for this firewall and your agents' addresses",
        status: Some("caddy.service"),
        units: r"^caddy\.service$",
        optional: false,
    },
    Service {
        id: "dnsmasq",
        label: "DNS",
        about: "Name lookups for your agents (dnsmasq)",
        status: Some("dnsmasq.service"),
        units: r"^dnsmasq\.service$",
        optional: false,
    },
    Service {
        id: "tang",
        label: "Tang",
        about: "Unlocks your agents' encrypted disks",
        status: Some("tangd.socket"),
        units: r"^tangd(\.socket|@.*\.service)$",
        optional: false,
    },
    Service {
        id: "disk",
        label: "Disk encryption",
        about: "This firewall's own encrypted disk",
        status: Some("cc-secure.service"),
        units: r"^cc-secure\.service$",
        optional: false,
    },
    Service {
        id: "team-chat",
        label: "Team chat",
        about: "ClickClack, when Team chat is on",
        status: Some("clickclack.service"),
        units: r"^clickclack\.service$",
        optional: true,
    },
    Service {
        id: "chrony",
        label: "Clock",
        about: "Time for this firewall and your agents (chrony)",
        status: Some("chrony.service"),
        units: r"^chrony\.service$",
        optional: false,
    },
    Service {
        id: "tailscale",
        label: "Tailscale",
        about: "Owner access over Tailscale, when it is on",
        status: Some("tailscaled.service"),
        units: r"^tailscaled\.service$",
        optional: true,
    },
    Service {
        id: "update",
        label: "Updates",
        about: "Update progress messages",
        status: None,
        units: r"^cc-reprovision\.service$",
        optional: false,
    },
];

static UNIT_RES: LazyLock<Vec<Regex>> =
    LazyLock::new(|| SERVICES.iter().map(|s| Regex::new(s.units).expect("regex")).collect());
static LEVEL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#""level"\s*:\s*"(\w+)""#).expect("regex"));
static TANG_CLEAN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(Started tangd@|tangd@\S+: Deactivated successfully\.)").expect("regex"));
static TRAILING_WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+$").expect("regex"));
static TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^@([0-9]+)$").expect("regex"));

pub fn is_fw_service(v: &str) -> bool {
    SERVICES.iter().any(|s| s.id == v)
}

fn service_for(unit: &str) -> Option<&'static str> {
    SERVICES
        .iter()
        .zip(UNIT_RES.iter())
        .find(|(_, re)| re.is_match(unit))
        .map(|(s, _)| s.id)
}

/// A journald field as text: a string, or the bytes it hands for one that is not valid UTF-8.
fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) if a.iter().all(Value::is_number) => {
            let bytes: Vec<u8> = a.iter().map(|b| b.as_u64().unwrap_or(0) as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

fn level(priority: &str, message: &str) -> &'static str {
    // Caddy and others write JSON lines with their own level, all filed at 6.
    if message.starts_with('{')
        && let Some(m) = LEVEL.captures(message)
    {
        return match m[1].to_lowercase().as_str() {
            "error" | "fatal" | "panic" => "error",
            "warn" | "warning" => "warn",
            "debug" => "debug",
            _ => "info",
        };
    }
    match priority {
        "0" | "1" | "2" | "3" => "error",
        "4" => "warn",
        "7" => "debug",
        _ => "info",
    }
}

/// This page's own sudo reads, and Tang's clean per-connection units.
fn noise(service: &str, ident: &str, from_systemd: bool, unit: &str, message: &str) -> bool {
    (service == "mitm-agent"
        && ident == "sudo"
        && (message.contains(FW_LOGS_HELPER) || message.starts_with("pam_unix(sudo:session)")))
        || (service == "tang" && from_systemd && unit.starts_with("tangd@") && TANG_CLEAN.is_match(message))
}

fn utf16_cut(s: &str, n: usize) -> Option<String> {
    let units: Vec<u16> = s.encode_utf16().collect();
    (units.len() > n).then(|| format!("{} …", String::from_utf16_lossy(&units[..n])))
}

/// `parseJournal`: `journalctl -o json` lines, newest first; units outside the catalog dropped.
pub fn parse_journal(stdout: &str, redact: &dyn Fn(&str) -> String) -> Vec<Value> {
    let mut out: Vec<(String, Value)> = Vec::new();
    for raw in stdout.split('\n') {
        if raw.trim().is_empty() {
            continue;
        }
        let Ok(Value::Object(e)) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        let from_systemd = e.get("_PID") == Some(&json!("1")) || e.get("SYSLOG_IDENTIFIER") == Some(&json!("systemd"));
        let pick = |a: &str, b: &str| e.get(a).filter(|v| !v.is_null()).or_else(|| e.get(b));
        let unit = text(if from_systemd {
            pick("UNIT", "_SYSTEMD_UNIT")
        } else {
            pick("_SYSTEMD_UNIT", "UNIT")
        });
        let Some(service) = service_for(&unit) else { continue };
        let us = match e.get("__REALTIME_TIMESTAMP") {
            Some(Value::String(s)) => s.trim().parse::<f64>().ok(),
            Some(Value::Number(n)) => n.as_f64(),
            _ => None,
        };
        let Some(us) = us.filter(|u| u.is_finite()) else {
            continue;
        };
        let message = TRAILING_WS.replace(&text(e.get("MESSAGE")), "").into_owned();
        if noise(
            service,
            &text(e.get("SYSLOG_IDENTIFIER")),
            from_systemd,
            &unit,
            &message,
        ) {
            continue;
        }
        // Mask first: a secret cut in half by the cap would no longer match.
        let masked = redact(&message);
        let message = utf16_cut(&masked, MAX_MESSAGE).unwrap_or(masked);
        let time = cc_crypto::store_health::iso_from_millis((us / 1000.0).floor() as i64);
        let lvl = if from_systemd {
            "unit"
        } else {
            level(&text(e.get("PRIORITY")), &message)
        };
        out.push((
            time.clone(),
            json!({"time": time, "service": service, "level": lvl, "message": message}),
        ));
    }
    out.sort_by(|a, b| b.0.cmp(&a.0));
    out.into_iter().map(|(_, v)| v).collect()
}

/// `systemctl show` of several units: blocks of key=value, in argument order.
pub fn parse_show(stdout: &str) -> Vec<HashMap<String, String>> {
    static BLANK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n\s*\n").expect("regex"));
    BLANK
        .split(stdout)
        .filter(|b| !b.trim().is_empty())
        .map(|block| {
            block
                .split('\n')
                .filter_map(|line| {
                    let i = line.find('=').filter(|i| *i > 0)?;
                    Some((line[..i].to_string(), line[i + 1..].trim().to_string()))
                })
                .collect()
        })
        .collect()
}

fn timestamp(v: Option<&String>) -> Option<String> {
    let m = TIMESTAMP.captures(v?)?;
    let secs: i64 = m[1].parse().ok()?;
    (secs != 0).then(|| cc_crypto::store_health::iso_from_millis(secs * 1000))
}

pub fn service_states(show: &[HashMap<String, String>]) -> Vec<Value> {
    let by_id: HashMap<&str, &HashMap<String, String>> = show
        .iter()
        .map(|kv| (kv.get("Id").map(String::as_str).unwrap_or(""), kv))
        .collect();
    let mut out = Vec::new();
    for s in SERVICES {
        let Some(status) = s.status else { continue };
        let Some(kv) = by_id.get(status) else { continue };
        if kv.get("LoadState").map(String::as_str) == Some("not-found") {
            continue;
        }
        let active = kv.get("ActiveState").cloned().unwrap_or_else(|| "unknown".into());
        let since = timestamp(if active == "active" {
            kv.get("ActiveEnterTimestamp")
        } else {
            kv.get("InactiveEnterTimestamp")
        })
        .or_else(|| timestamp(kv.get("ActiveEnterTimestamp")));
        let exit = kv
            .get("ExecMainStatus")
            .filter(|v| !v.is_empty())
            .and_then(|v| v.parse::<f64>().ok());
        let restarts = kv
            .get("NRestarts")
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| *v != 0.0 && v.is_finite());
        out.push(json!({
            "id": s.id,
            "label": s.label,
            "about": s.about,
            "active": active,
            "sub": kv.get("SubState").cloned().unwrap_or_default(),
            "result": kv.get("Result").cloned().unwrap_or_default(),
            "since": since,
            "restarts": restarts.map(|r| json!(r as i64)).unwrap_or(json!(0)),
            "exitStatus": exit.map(|e| json!(e as i64)),
            "optional": s.optional,
        }));
    }
    out
}

fn update_state() -> Value {
    let Some(s) = std::fs::read_to_string(UPDATE_STATE)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return Value::Null;
    };
    let Some(phase) = s.get("phase").and_then(Value::as_str) else {
        return Value::Null;
    };
    let field = |k: &str| match s.get(k) {
        None | Some(Value::Null) => String::new(),
        v => super::activity_sanitize::js_string(v),
    };
    json!({"phase": phase, "detail": field("detail"), "ref": field("ref"), "at": field("at")})
}

/// Runs a command and hands back its stdout, or fails on a non-zero exit.
pub type Run = Arc<dyn Fn(&str, Vec<String>) -> cc_http::BoxFuture<Result<String, String>> + Send + Sync>;

/// `makeFwLogs`.
pub struct FwLogsReader {
    pub secrets: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
    pub hostname: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    pub run: Run,
    pub helper_present: Arc<dyn Fn() -> bool + Send + Sync>,
    pub update: Arc<dyn Fn() -> Value + Send + Sync>,
}

impl FwLogsReader {
    /// The real one: commands through `runner`, the helper and `update.json` on this box.
    pub fn new(
        runner: Arc<dyn cc_proc::Runner>,
        secrets: Arc<dyn Fn() -> Vec<String> + Send + Sync>,
        hostname: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> Self {
        let run: Run = Arc::new(move |cmd: &str, args: Vec<String>| {
            let runner = runner.clone();
            let c = cc_proc::Cmd::new(cmd)
                .args(args)
                .timeout(std::time::Duration::from_secs(15));
            Box::pin(async move {
                let out = runner.run(c).await.map_err(|e| e.to_string())?;
                if out.success() {
                    Ok(out.stdout_str())
                } else {
                    Err(format!("exit {:?}", out.code))
                }
            })
        });
        Self {
            secrets,
            hostname,
            run,
            helper_present: Arc::new(|| std::path::Path::new(FW_LOGS_HELPER).exists()),
            update: Arc::new(update_state),
        }
    }

    pub async fn read(&self, range: &str, service: &str) -> Value {
        let redactor = cc_redact::Redactor::new((self.secrets)());
        let redact = |s: &str| redactor.redact(s);
        let mut base = Map::new();
        base.insert("firewall".into(), json!((self.hostname)()));
        base.insert("range".into(), json!(range));
        base.insert("service".into(), json!(service));
        base.insert("update".into(), (self.update)());
        base.insert("lines".into(), json!([]));
        base.insert("truncated".into(), json!(false));
        let units: Vec<String> = SERVICES.iter().filter_map(|s| s.status.map(str::to_string)).collect();
        let mut args = vec![
            "show".to_string(),
            "--timestamp=unix".into(),
            "-p".into(),
            "Id,LoadState,ActiveState,SubState,Result,NRestarts,ExecMainStatus,ActiveEnterTimestamp,InactiveEnterTimestamp".into(),
        ];
        args.extend(units);
        let services = match (self.run)("systemctl", args).await {
            Ok(out) => service_states(&parse_show(&out)),
            Err(_) => Vec::new(),
        };
        base.insert("services".into(), json!(services));
        if !(self.helper_present)() {
            base.insert(
                "warning".into(),
                json!("This firewall is on a build that cannot read its logs yet. Press Update on the Firewall page."),
            );
            return Value::Object(base);
        }
        let failed = |mut base: Map<String, Value>| {
            base.insert(
                "warning".into(),
                json!("The firewall could not read its logs. Try again in a moment."),
            );
            Value::Object(base)
        };
        if service == "run" {
            let Ok(out) = (self.run)("sudo", vec!["-n".into(), FW_LOGS_HELPER.into(), "run".into()]).await else {
                return failed(base);
            };
            let mut lines: Vec<String> = out
                .split('\n')
                .map(|l| {
                    let m = redact(l);
                    utf16_cut(&m, MAX_MESSAGE).unwrap_or(m)
                })
                .collect();
            while lines.last().is_some_and(|l| l.trim().is_empty()) {
                lines.pop();
            }
            base.insert("run".into(), json!(lines));
            return Value::Object(base);
        }
        let secs = range_seconds(range).unwrap_or(3600);
        let args = vec![
            "-n".into(),
            FW_LOGS_HELPER.into(),
            "journal".into(),
            secs.to_string(),
            MAX_LINES.to_string(),
            service.to_string(),
        ];
        let Ok(out) = (self.run)("sudo", args).await else {
            return failed(base);
        };
        let lines: Vec<Value> = parse_journal(&out, &redact)
            .into_iter()
            .filter(|l| service == "all" || l["service"] == service)
            .collect();
        base.insert("lines".into(), json!(lines));
        base.insert(
            "truncated".into(),
            json!(out.split('\n').filter(|l| !l.trim().is_empty()).count() >= MAX_LINES),
        );
        Value::Object(base)
    }
}

// ---- the door ----

const GRANT_MS: u64 = 2 * 60 * 60_000;
const GRANTS_MAX: usize = 1000;

#[derive(Clone)]
struct Grant {
    user_id: String,
    device_id: String,
    expires_at: u64,
}

/// What a page answers: status, extra headers, content type, body.
pub struct PageReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub content_type: Option<String>,
    pub body: String,
}

/// `FwPageDoor`.
pub struct FwPageDoor {
    pub access: Arc<AccessFirewall>,
    pub root: &'static str,
    pub cookie: &'static str,
    pub next: &'static str,
    pub title: &'static str,
    pub opening: &'static str,
    pub refused: &'static str,
    pub csp: &'static str,
    pub now: Arc<dyn Fn() -> u64 + Send + Sync>,
    grants: Mutex<HashMap<String, Grant>>,
}

/// What a page request carries that the door reads.
pub struct PageRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub origin: Option<String>,
    pub cookie: Option<String>,
    pub content_type: String,
    pub body: Option<Vec<u8>>,
}

impl FwPageDoor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        access: Arc<AccessFirewall>,
        root: &'static str,
        cookie: &'static str,
        next: &'static str,
        title: &'static str,
        opening: &'static str,
        refused: &'static str,
        csp: &'static str,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            access,
            root,
            cookie,
            next,
            title,
            opening,
            refused,
            csp,
            now,
            grants: Mutex::new(HashMap::new()),
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        vec![
            ("cache-control".into(), "no-store".into()),
            ("referrer-policy".into(), "same-origin".into()),
            ("x-content-type-options".into(), "nosniff".into()),
            ("content-security-policy".into(), self.csp.into()),
        ]
    }

    pub fn send(&self, status: u16, text: &str, ty: &str) -> PageReply {
        PageReply {
            status,
            headers: self.headers(),
            content_type: Some(format!("{ty}; charset=utf-8")),
            body: text.to_string(),
        }
    }

    fn refused_page(&self) -> String {
        fw_notice(
            self.title,
            Some(&format!("{} unavailable", self.title)),
            self.refused,
            None,
            None,
        )
    }

    fn grant(&self, cookie: Option<&str>) -> Option<Grant> {
        let name = format!("{}=", self.cookie);
        let matches: Vec<&str> = cookie
            .unwrap_or("")
            .split(';')
            .map(str::trim)
            .filter(|s| s.starts_with(&name))
            .collect();
        if matches.len() != 1 {
            return None;
        }
        let token = &matches[0][name.len()..];
        if !(token.len() == 43
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        {
            return None;
        }
        let key = hex::encode(Sha256::digest(token.as_bytes()));
        let grant = self.grants.lock().ok()?.get(&key).cloned()?;
        if grant.expires_at <= (self.now)()
            || !self
                .access
                .firewall_device_active(cookie, &grant.user_id, &grant.device_id)
        {
            return None;
        }
        Some(grant)
    }

    /// The open flow, the grant check, the method and the bare root. `None` for a granted GET of
    /// one of the page's own paths, which the page answers.
    pub async fn handle(&self, req: &PageRequest) -> Option<PageReply> {
        let root = self.root;
        if req.path == format!("{root}/open.js") && req.method == "GET" {
            return Some(self.send(200, &self.open_js(), "text/javascript"));
        }
        if req.path == format!("{root}/open") && req.method == "GET" {
            let notice = fw_notice(
                self.title,
                None,
                self.opening,
                Some("status"),
                Some(&format!("{root}/open.js")),
            );
            return Some(self.send(200, &notice, "text/html"));
        }
        if req.path == format!("{root}/open") && req.method == "POST" {
            if req.origin != self.access.origin() || req.origin.is_none() {
                return Some(self.send(403, "", "text/plain"));
            }
            if !req.content_type.starts_with("application/x-www-form-urlencoded") {
                return Some(self.send(415, "", "text/plain"));
            }
            // A body over the cap fails the read, which the ingress answers with a bare 500.
            let Some(body) = req.body.clone() else {
                return Some(PageReply {
                    status: 500,
                    headers: vec![("content-length".into(), "0".into())],
                    content_type: None,
                    body: String::new(),
                });
            };
            let intent = url::form_urlencoded::parse(&body)
                .find(|(k, _)| k == "intent")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            let Some(identity) = self
                .access
                .authorize_firewall(req.origin.as_deref(), req.cookie.as_deref(), &intent, self.next)
                .await
            else {
                return Some(self.send(403, &self.refused_page(), "text/html"));
            };
            let now = (self.now)();
            let mut grants = self.grants.lock().unwrap_or_else(|e| e.into_inner());
            grants.retain(|_, g| g.expires_at > now);
            if grants.len() >= GRANTS_MAX {
                return Some(self.send(429, "", "text/plain"));
            }
            let mut b = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            let token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b);
            grants.insert(
                hex::encode(Sha256::digest(token.as_bytes())),
                Grant {
                    user_id: identity.user_id,
                    device_id: identity.device_id,
                    expires_at: now + GRANT_MS,
                },
            );
            let mut headers = self.headers();
            headers.push(("location".into(), format!("{root}/")));
            headers.push((
                "set-cookie".into(),
                format!(
                    "{}={token}; Path={root}; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
                    self.cookie,
                    GRANT_MS / 1000
                ),
            ));
            return Some(PageReply {
                status: 303,
                headers,
                content_type: None,
                body: String::new(),
            });
        }
        if self.grant(req.cookie.as_deref()).is_none() {
            return Some(self.send(403, &self.refused_page(), "text/html"));
        }
        if req.method != "GET" {
            return Some(self.send(405, "", "text/plain"));
        }
        if req.path == root {
            let mut headers = self.headers();
            headers.push(("location".into(), format!("{root}/")));
            return Some(PageReply {
                status: 308,
                headers,
                content_type: None,
                body: String::new(),
            });
        }
        None
    }

    /// Posts the intent in the address's fragment to `open`; the fragment never reaches a server.
    fn open_js(&self) -> String {
        let missing = serde_json::to_string(&format!("Open the {} from the console.", self.title.to_lowercase()))
            .unwrap_or_default();
        format!(
            r#"const p=new URLSearchParams(location.hash.slice(1)),intent=p.get("i");history.replaceState(null,"",location.pathname);if(!intent){{document.getElementById("status").textContent={missing}}}else{{const form=document.createElement("form");form.method="POST";form.action="{}/open";const input=document.createElement("input");input.type="hidden";input.name="intent";input.value=intent;form.append(input);document.body.append(form);form.submit()}}"#,
            self.root
        )
    }
}

// ---- the page ----

pub const FW_LOGS_ROOT: &str = "/__cc/doctor/logs";
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src data:; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub fn owns_fw_logs_path(path: &str) -> bool {
    path == FW_LOGS_ROOT || path.starts_with(&format!("{FW_LOGS_ROOT}/"))
}

type Read = Shared<FBox<'static, Value>>;

pub struct FwLogsPage {
    pub door: FwPageDoor,
    reader: Arc<FwLogsReader>,
    console_url: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    js: String,
    /// Reads still running, by range and service: the same question waits for the same answer.
    reads: Arc<Mutex<HashMap<String, Read>>>,
}

impl FwLogsPage {
    pub fn new(
        access: Arc<AccessFirewall>,
        reader: Arc<FwLogsReader>,
        console_url: Arc<dyn Fn() -> Option<String> + Send + Sync>,
        js: String,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            door: FwPageDoor::new(
                access,
                FW_LOGS_ROOT,
                "__Secure-cc_fw_logs",
                "firewall-logs",
                "Firewall logs",
                "Opening the firewall logs...",
                "Open the firewall logs from the console (Firewall, then Logs) in an enrolled browser. Open a working agent first to enroll this browser.",
                CSP,
                now,
            ),
            reader,
            console_url,
            js,
            reads: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn handle(&self, req: &PageRequest) -> PageReply {
        let root = FW_LOGS_ROOT;
        if let Some(r) = self.door.handle(req).await {
            return r;
        }
        if req.path == format!("{root}/") {
            let html = fw_shell_page(
                "Firewall logs",
                Some(FwPage::Logs),
                r#"<div id="root"></div>"#,
                Some((self.console_url)()),
                r#"<script type="module" src="app.js"></script>"#,
                None,
            );
            return self.door.send(200, &html, "text/html");
        }
        if req.path == format!("{root}/app.js") {
            return self.door.send(200, &self.js, "text/javascript");
        }
        if req.path == format!("{root}/data") {
            let first = |k: &str| {
                url::form_urlencoded::parse(req.query.as_bytes())
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.into_owned())
            };
            let range = first("range").unwrap_or_else(|| "1h".into());
            let service = first("service").unwrap_or_else(|| "all".into());
            if range_seconds(&range).is_none() || !(service == "all" || service == "run" || is_fw_service(&service)) {
                return self.door.send(400, "", "text/plain");
            }
            let key = format!("{range}:{service}");
            let read = {
                let mut reads = self.reads.lock().unwrap_or_else(|e| e.into_inner());
                reads
                    .entry(key.clone())
                    .or_insert_with(|| {
                        let (reader, reads, key) = (self.reader.clone(), self.reads.clone(), key.clone());
                        let fut: FBox<'static, Value> = Box::pin(async move {
                            let v = reader.read(&range, &service).await;
                            if let Ok(mut r) = reads.lock() {
                                r.remove(&key);
                            }
                            v
                        });
                        fut.shared()
                    })
                    .clone()
            };
            let body = read.await;
            return self.door.send(200, &body.to_string(), "application/json");
        }
        self.door.send(404, "", "text/plain")
    }
}

/// A page reply as hyper's.
pub fn page_response(r: PageReply) -> cc_http::Resp {
    let mut resp = cc_http::full(
        http::StatusCode::from_u16(r.status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR),
        r.content_type.as_deref().unwrap_or(""),
        r.body,
    );
    let h = resp.headers_mut();
    for (k, v) in r.headers {
        if let (Ok(k), Ok(v)) = (
            http::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(&v),
        ) {
            h.append(k, v);
        }
    }
    resp
}

/// The page request of a hyper request; a POST's body read up to 8 KiB.
pub async fn page_request(req: cc_http::Req) -> PageRequest {
    use http_body_util::BodyExt;
    let (parts, body) = req.into_parts();
    let h = |n: &str| cc_http::header(&parts, n).map(str::to_string);
    let body = if parts.method == http::Method::POST {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            http_body_util::Limited::new(body, 8192).collect(),
        )
        .await
        {
            Ok(Ok(b)) => Some(b.to_bytes().to_vec()),
            _ => None,
        }
    } else {
        Some(Vec::new())
    };
    PageRequest {
        method: parts.method.to_string(),
        path: cc_http::pathname(parts.uri.path()),
        query: parts.uri.query().unwrap_or("").to_string(),
        origin: h("origin"),
        cookie: h("cookie"),
        content_type: h("content-type").unwrap_or_default(),
        body,
    }
}

#[cfg(test)]
mod tests;
