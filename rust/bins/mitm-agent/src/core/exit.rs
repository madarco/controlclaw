//! The residential exit on the firewall (`exit.ts`, `exit-store.ts`): the org's upstream proxy
//! account (the password never leaves this box), the sticky salt made here, and this month's
//! bytes, which the cap is enforced against. Adding, replacing, removing and settings changes all
//! take a code; `exit.check` runs the reachability check now.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};

use rand::RngCore;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::consent::iso;
use super::exit_check::{CHECK_SESSION, CheckResult, Upstream, check_exit};
use super::ingress::num;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, null_or, obj, ok, text};
use super::now_ms;
use crate::commands::{CommandOutcome, CommandResult};
use crate::contracts::{CodeAsk, CodeCheck};

const SCOPE: &str = "exit:org";
const CHECK_INTERVAL_MS: u64 = 15 * 60_000;
/// Default monthly ceiling: generous, on, and editable.
pub const DEFAULT_CAP_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const COUNTED_IDS_KEPT: usize = 20_000;

pub type OnChanged = Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>;

/// `normalizeCountry`: ISO 3166-1 alpha-2, uppercase, or nothing.
pub fn normalize_country(v: Option<&Value>) -> Option<String> {
    let clean = v
        .and_then(Value::as_str)
        .map(|s| s.trim().to_uppercase())
        .unwrap_or_default();
    (clean.len() == 2 && clean.chars().all(|c| c.is_ascii_uppercase())).then_some(clean)
}

#[derive(Debug, Clone, Default)]
pub struct TemplateValues {
    pub username: Option<String>,
    pub password: Option<String>,
    pub session: Option<String>,
    pub country: Option<String>,
}

static SEGMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[([^\[\]]*)\]").expect("re"));
static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{(username|password|session|country|country_lc)\}").expect("re"));

fn placeholder(name: &str, v: &TemplateValues) -> String {
    let s = |x: &Option<String>| x.clone().unwrap_or_default();
    match name {
        "username" => s(&v.username),
        "password" => s(&v.password),
        "session" => s(&v.session),
        "country" => s(&v.country).to_uppercase(),
        "country_lc" => s(&v.country).to_lowercase(),
        _ => String::new(),
    }
}

/// `renderTemplate`, which must agree with the proxy's: a `[...]` stays only when every
/// placeholder in it has a value (one with none follows the session).
pub fn render_template(template: &str, v: &TemplateValues) -> String {
    let kept = SEGMENT.replace_all(template, |c: &regex::Captures| {
        let inner = &c[1];
        let names: Vec<String> = PLACEHOLDER.captures_iter(inner).map(|m| m[1].to_string()).collect();
        if names.is_empty() {
            return if v.session.as_deref().is_some_and(|s| !s.is_empty()) {
                inner.to_string()
            } else {
                String::new()
            };
        }
        if names.iter().all(|n| !placeholder(n, v).is_empty()) {
            inner.to_string()
        } else {
            String::new()
        }
    });
    PLACEHOLDER
        .replace_all(&kept, |c: &regex::Captures| placeholder(&c[1], v))
        .into_owned()
}

/// `sessionFor`: the per-agent session the proxy derives (for its tests and the e2e harness).
#[cfg(test)]
pub fn session_for(salt: &str, vm_id: &str) -> String {
    use hmac::Mac;
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(salt.as_bytes()).expect("any key");
    m.update(vm_id.as_bytes());
    hex::encode(m.finalize().into_bytes())[..12].to_string()
}

/// A change (`ExitProposal`), as JSON so it rides the consent code as the TS keeps it.
#[derive(Debug, Clone, PartialEq)]
struct Proposal(Map<String, Value>);

impl Proposal {
    fn kind(&self) -> &str {
        self.0.get("kind").and_then(Value::as_str).unwrap_or("")
    }
    fn s(&self, k: &str) -> Option<String> {
        self.0.get(k).and_then(Value::as_str).map(str::to_string)
    }
    fn sticky(&self) -> bool {
        self.0.get("sticky") == Some(&Value::Bool(true))
    }
    /// The tri-state fields: absent says nothing, `null` clears.
    fn tri(&self, k: &str) -> Option<&Value> {
        self.0.get(k)
    }
}

/// `parseProposal`.
fn parse(p: &Map<String, Value>) -> Result<Proposal, String> {
    let bad = || "malformed exit.propose payload".to_string();
    let change_id = text(p, "changeId").ok_or_else(bad)?;
    let kind = p
        .get("kind")
        .and_then(Value::as_str)
        .filter(|k| ["add", "replace", "remove", "settings"].contains(k))
        .ok_or_else(bad)?;
    let port = p
        .get("port")
        .filter(|v| v.as_f64().is_some_and(f64::is_finite))
        .cloned();
    let scheme = p
        .get("scheme")
        .and_then(Value::as_str)
        .filter(|s| ["http", "https", "socks5"].contains(s));
    if (kind == "add" || kind == "replace")
        && (text(p, "host").is_none() || !port.as_ref().is_some_and(super::sync::js_truthy) || scheme.is_none())
    {
        return Err(bad());
    }
    let provider = text(p, "provider").unwrap_or_else(|| "custom".into());
    let mut m = obj(&[
        ("changeId", json!(change_id)),
        ("kind", json!(kind)),
        ("provider", json!(provider)),
        (
            "providerName",
            json!(text(p, "providerName").unwrap_or_else(|| provider.clone())),
        ),
        ("scheme", json!(scheme.unwrap_or("http"))),
        ("host", json!(text(p, "host").unwrap_or_default())),
        ("port", port.filter(super::sync::js_truthy).unwrap_or(json!(0))),
        (
            "usernameTemplate",
            json!(text(p, "usernameTemplate").unwrap_or_else(|| "{username}".into())),
        ),
        (
            "passwordTemplate",
            json!(text(p, "passwordTemplate").unwrap_or_else(|| "{password}".into())),
        ),
        ("usernameHint", null_or(text(p, "usernameHint"))),
        ("sticky", json!(p.get("sticky") == Some(&Value::Bool(true)))),
    ]);
    if p.contains_key("capBytes") {
        let cap = p
            .get("capBytes")
            .filter(|v| v.as_f64().is_some_and(f64::is_finite))
            .cloned()
            .unwrap_or(Value::Null);
        m.insert("capBytes".into(), cap);
    }
    if p.contains_key("country") {
        m.insert("country".into(), null_or(normalize_country(p.get("country"))));
    }
    if let Some(t) = p.get("templates").and_then(Value::as_object)
        && let (Some(u), Some(pw)) = (text(t, "usernameTemplate"), text(t, "passwordTemplate"))
    {
        m.insert(
            "templates".into(),
            json!({"usernameTemplate": u, "passwordTemplate": pw}),
        );
    }
    for k in ["username", "password"] {
        if let Some(v) = text(p, k) {
            m.insert(k.into(), json!(v));
        }
    }
    Ok(Proposal(m))
}

/// `summarize`; a settings change says which of its two things moved against `current_country`.
fn summarize(p: &Proposal, current_country: Option<&str>) -> String {
    let who = p.s("usernameHint").map(|h| format!(" ({h})")).unwrap_or_default();
    let name = p.s("providerName").unwrap_or_default();
    match p.kind() {
        "add" => format!("Send some sites out through {name}{who} instead of your firewall"),
        "replace" => format!("Replace the {name} credential{who}"),
        "remove" => "Stop sending any traffic out through a residential exit".into(),
        _ => {
            if let Some(c) = p.tri("country")
                && c.as_str() != current_country
            {
                return match c.as_str() {
                    Some(code) => format!("Have your residential traffic come out in {code}"),
                    None => "Stop asking for a particular country on your residential traffic".into(),
                };
            }
            if p.sticky() {
                "Give each agent its own residential IP".into()
            } else {
                "Stop giving each agent its own residential IP".into()
            }
        }
    }
}

fn month_key(ms: u64) -> String {
    iso(ms)[..7].to_string()
}

fn empty_store() -> Map<String, Value> {
    obj(&[
        ("version", json!(1)),
        ("upstream", Value::Null),
        ("sticky", json!(false)),
        ("stickySalt", json!("")),
        ("capBytes", Value::Null),
        ("country", Value::Null),
        (
            "usage",
            json!({"month": month_key(now_ms()), "bytesIn": 0, "bytesOut": 0}),
        ),
        ("lastCheck", Value::Null),
        ("updatedAt", json!(iso(now_ms()))),
    ])
}

struct State {
    store: Map<String, Value>,
    reports: Vec<CommandResult>,
    checking: bool,
    last_check_started: u64,
    counted: HashSet<String>,
    counted_order: VecDeque<String>,
}

pub struct Exit {
    path: PathBuf,
    box_key: String,
    aad: String,
    state: Mutex<State>,
    kit: Kit,
    on_changed: OnChanged,
    /// One change at a time: they read and write the store around the check.
    running: tokio::sync::Mutex<()>,
}

fn f(v: Option<&Value>) -> f64 {
    v.and_then(Value::as_f64).unwrap_or(0.0)
}

impl Exit {
    pub fn new(path: PathBuf, box_key: &str, org: &str, box_id: &str, kit: Kit, on_changed: OnChanged) -> Self {
        let aad = format!("{org}:{box_id}:exit");
        let log = |l: &str| tracing::error!("{l}");
        let mut store = empty_store();
        if let Some(Value::Object(o)) = cc_crypto::enc_file::load_store_or_empty("exit", &path, box_key, &aad, &log)
            && o.get("version").and_then(Value::as_f64) == Some(1.0)
        {
            store.extend(o);
        }
        Self {
            path,
            box_key: box_key.into(),
            aad,
            state: Mutex::new(State {
                store,
                reports: Vec::new(),
                checking: false,
                last_check_started: 0,
                counted: HashSet::new(),
                counted_order: VecDeque::new(),
            }),
            kit,
            on_changed,
            running: tokio::sync::Mutex::new(()),
        }
    }

    /// Save what was loaded, unchanged (the TS ↔ Rust store round trip).
    #[cfg(test)]
    pub fn resave(&self) {
        let mut s = self.st();
        self.save(&mut s).expect("save");
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A store that cannot be written fails the command (the TS throws).
    fn save(&self, s: &mut State) -> Result<(), String> {
        s.store.insert("updatedAt".into(), json!(iso(now_ms())));
        cc_crypto::enc_file::save_store(
            "exit",
            &self.path,
            &Value::Object(s.store.clone()),
            &self.box_key,
            &self.aad,
        )
        .map_err(|e| format!("The residential exit could not be saved on your firewall: {e}"))
    }

    /// The same, from a timer or the traffic count, where there is nobody to tell.
    fn save_logged(&self, s: &mut State) {
        if let Err(e) = self.save(s) {
            tracing::error!("[exit] {e}");
        }
    }

    fn roll_month(&self, s: &mut State) {
        let month = month_key(now_ms());
        if s.store
            .get("usage")
            .and_then(|u| u.get("month"))
            .and_then(Value::as_str)
            != Some(month.as_str())
        {
            s.store
                .insert("usage".into(), json!({"month": month, "bytesIn": 0, "bytesOut": 0}));
            self.save_logged(s);
        }
    }

    fn used(&self, s: &mut State) -> f64 {
        self.roll_month(s);
        let u = s.store.get("usage").cloned().unwrap_or_default();
        f(u.get("bytesIn")) + f(u.get("bytesOut"))
    }

    /// `exitConfig`: what the proxy reads (`exit.json`), password included.
    pub fn exit_config(&self) -> Value {
        let mut s = self.st();
        let Some(u) = s.store.get("upstream").and_then(Value::as_object).cloned() else {
            return json!({"enabled": false});
        };
        let used = self.used(&mut s);
        json!({
            "enabled": true,
            "upstream": {
                "scheme": u.get("scheme"), "host": u.get("host"), "port": u.get("port"),
                "username": u.get("username"), "password": u.get("password"),
                "username_template": u.get("usernameTemplate"), "password_template": u.get("passwordTemplate"),
            },
            "sticky": s.store.get("sticky"),
            "sticky_salt": s.store.get("stickySalt"),
            "cap_bytes": s.store.get("capBytes"),
            "used_bytes": num(used),
            "country": s.store.get("country"),
        })
    }

    /// `status`: what rides the beat (`residential`); no secret.
    pub fn status(&self) -> Value {
        let mut s = self.st();
        self.roll_month(&mut s);
        let st = &s.store;
        let u = st.get("upstream").and_then(Value::as_object);
        let last = st.get("lastCheck").and_then(Value::as_object).map(|c| {
            json!({
                "at": num((f(c.get("at")) / 1000.0).round()), "ok": c.get("ok"),
                "exit_ip": c.get("exitIp"), "exit_country": c.get("exitCountry"), "error": c.get("error"),
            })
        });
        let usage = st.get("usage").cloned().unwrap_or_default();
        json!({
            "configured": u.is_some(),
            "provider": u.and_then(|u| u.get("provider")).cloned().unwrap_or(Value::Null),
            "sticky": st.get("sticky"),
            "hint": u.and_then(|u| u.get("usernameHint")).cloned().unwrap_or(Value::Null),
            "cap_bytes": st.get("capBytes"),
            "country": st.get("country"),
            "last_check": last,
            "usage": {"month": usage.get("month"), "bytes_in": usage.get("bytesIn"), "bytes_out": usage.get("bytesOut")},
        })
    }

    /// Reports made with no command behind them, drained on each beat.
    pub fn drain_reports(&self) -> Vec<CommandResult> {
        std::mem::take(&mut self.st().reports)
    }

    /// `noteTraffic`: this month's residential bytes, each flow counted once.
    pub fn note_traffic(&self, records: &[Value]) {
        let mut s = self.st();
        if s.store.get("upstream").is_none_or(Value::is_null) {
            return;
        }
        let (mut bytes_in, mut bytes_out) = (0.0, 0.0);
        for r in records {
            if r.get("effect").and_then(Value::as_str) != Some("residential") {
                continue;
            }
            if let Some(id) = r.get("flow_id").and_then(Value::as_str) {
                if !s.counted.insert(id.to_string()) {
                    continue;
                }
                s.counted_order.push_back(id.to_string());
                while s.counted_order.len() > COUNTED_IDS_KEPT {
                    if let Some(old) = s.counted_order.pop_front() {
                        s.counted.remove(&old);
                    }
                }
            }
            bytes_in += r.get("bytes_in").and_then(Value::as_f64).unwrap_or(0.0).max(0.0);
            bytes_out += r.get("bytes_out").and_then(Value::as_f64).unwrap_or(0.0).max(0.0);
        }
        if bytes_in == 0.0 && bytes_out == 0.0 {
            return;
        }
        self.roll_month(&mut s);
        let usage = s.store.get("usage").cloned().unwrap_or_default();
        let (bi, bo) = (f(usage.get("bytesIn")) + bytes_in, f(usage.get("bytesOut")) + bytes_out);
        s.store.insert(
            "usage".into(),
            json!({"month": usage.get("month"), "bytesIn": num(bi), "bytesOut": num(bo)}),
        );
        self.save_logged(&mut s);
    }

    /// On a timer: the check when it is due and there is an exit.
    pub async fn tick(&self) {
        {
            let s = self.st();
            if s.store.get("upstream").is_none_or(Value::is_null) || s.checking {
                return;
            }
            if now_ms().saturating_sub(s.last_check_started) < CHECK_INTERVAL_MS {
                return;
            }
        }
        self.run_check().await;
    }

    async fn run_check(&self) -> Option<CheckResult> {
        let up = {
            let mut s = self.st();
            let u = s.store.get("upstream").and_then(Value::as_object).cloned()?;
            if s.checking {
                return None;
            }
            s.checking = true;
            s.last_check_started = now_ms();
            // Sticky off: the proxy sends no session, so neither does the check.
            let session = (s.store.get("sticky") == Some(&Value::Bool(true))).then(|| CHECK_SESSION.to_string());
            let country = s.store.get("country").and_then(Value::as_str).map(str::to_string);
            let st = |k: &str| u.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
            let values = TemplateValues {
                username: Some(st("username")),
                password: None,
                session: session.clone(),
                country: country.clone(),
            };
            let pw = TemplateValues {
                username: None,
                password: Some(st("password")),
                session,
                country,
            };
            Upstream {
                scheme: st("scheme"),
                host: st("host"),
                // Out of range or not whole: port 0, which fails to connect (Node refuses it
                // too), never a wrapped port somewhere else.
                port: u
                    .get("port")
                    .and_then(Value::as_f64)
                    .filter(|p| p.fract() == 0.0 && (0.0..65536.0).contains(p))
                    .map_or(0, |p| p as u16),
                user: render_template(&st("usernameTemplate"), &values),
                password: render_template(&st("passwordTemplate"), &pw),
            }
        };
        let r = check_exit(&up, None).await;
        let mut s = self.st();
        s.checking = false;
        let before = s.store.get("lastCheck").cloned().unwrap_or(Value::Null);
        s.store.insert(
            "lastCheck".into(),
            json!({"at": now_ms(), "ok": r.ok, "exitIp": r.exit_ip, "exitCountry": r.exit_country, "error": r.error}),
        );
        self.save_logged(&mut s);
        let moved = before.is_null()
            || before.get("ok") != Some(&json!(r.ok))
            || before.get("exitIp") != Some(&json!(r.exit_ip))
            || before.get("exitCountry") != Some(&json!(r.exit_country));
        if moved {
            let where_ = format!(
                "{}{}",
                r.exit_ip.as_deref().unwrap_or("an unknown address"),
                r.exit_country
                    .as_deref()
                    .map(|c| format!(" in {c}"))
                    .unwrap_or_default()
            );
            if r.ok {
                tracing::info!("[exit] reachable, exiting from {where_}");
            } else {
                tracing::info!("[exit] unreachable: {}", r.error.as_deref().unwrap_or_default());
            }
        }
        Some(r)
    }

    async fn force_check(&self) -> Option<CheckResult> {
        self.st().last_check_started = 0;
        self.run_check().await
    }

    pub async fn check_command(&self) -> CommandOutcome {
        if self.st().store.get("upstream").is_none_or(Value::is_null) {
            return CommandOutcome::failed("failed", "No residential exit is set up.");
        }
        let Some(r) = self.force_check().await else {
            return CommandOutcome::failed("failed", "The check could not run.");
        };
        CommandOutcome {
            ok: r.ok,
            status: if r.ok { "applied" } else { "failed" }.into(),
            message: Some(r.error.unwrap_or_default()),
            data: Some(obj(&[
                ("exitIp", null_or(r.exit_ip)),
                ("exitCountry", null_or(r.exit_country)),
                ("latencyMs", json!(r.latency_ms)),
            ])),
        }
    }

    async fn apply(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        match p.kind() {
            "remove" => {
                {
                    let mut s = self.st();
                    s.store.insert("upstream".into(), Value::Null);
                    s.store.insert("stickySalt".into(), json!(""));
                    s.store.insert("lastCheck".into(), Value::Null);
                    self.save(&mut s)?;
                }
                (self.on_changed)().await?;
                tracing::info!("[exit] residential exit removed");
                Ok(obj(&[("configured", json!(false))]))
            }
            "settings" => {
                let (country_moved, templates_moved, country, configured) = {
                    let mut s = self.st();
                    s.store.insert("sticky".into(), json!(p.sticky()));
                    if let Some(c) = p.tri("capBytes") {
                        s.store.insert("capBytes".into(), c.clone());
                    }
                    let mut country_moved = false;
                    if let Some(c) = p.tri("country") {
                        country_moved = s.store.get("country") != Some(c);
                        s.store.insert("country".into(), c.clone());
                    }
                    let mut templates_moved = false;
                    if let Some(t) = p.tri("templates").and_then(Value::as_object)
                        && let Some(u) = s.store.get_mut("upstream").and_then(Value::as_object_mut)
                    {
                        templates_moved = u.get("usernameTemplate") != t.get("usernameTemplate")
                            || u.get("passwordTemplate") != t.get("passwordTemplate");
                        if templates_moved {
                            u.insert("usernameTemplate".into(), t["usernameTemplate"].clone());
                            u.insert("passwordTemplate".into(), t["passwordTemplate"].clone());
                        }
                    }
                    self.save(&mut s)?;
                    let country = s.store.get("country").cloned().unwrap_or(Value::Null);
                    let configured = s.store.get("upstream").is_some_and(|u| !u.is_null());
                    (country_moved, templates_moved, country, configured)
                };
                (self.on_changed)().await?;
                tracing::info!(
                    "[exit] sticky {}, cap {}, country {}{}",
                    if p.sticky() { "on" } else { "off" },
                    p.tri("capBytes")
                        .filter(|c| !c.is_null())
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "none".into()),
                    country.as_str().unwrap_or("any"),
                    if templates_moved {
                        ", credential shape updated"
                    } else {
                        ""
                    }
                );
                let mut out = obj(&[
                    ("configured", json!(configured)),
                    ("sticky", json!(p.sticky())),
                    ("country", country),
                ]);
                if (country_moved || templates_moved)
                    && let Some(r) = self.force_check().await
                {
                    out.insert("reachable".into(), json!(r.ok));
                    out.insert("exitIp".into(), null_or(r.exit_ip));
                    out.insert("exitCountry".into(), null_or(r.exit_country));
                    if !r.ok {
                        out.insert("checkError".into(), null_or(r.error));
                    }
                }
                Ok(out)
            }
            _ => {
                let country = {
                    let mut s = self.st();
                    let prev = s.store.get("upstream").and_then(Value::as_object).cloned();
                    let pv = |k: &str| {
                        prev.as_ref()
                            .and_then(|u| u.get(k))
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    };
                    let username = p.s("username").or_else(|| pv("username")).unwrap_or_default();
                    let password = p.s("password").or_else(|| pv("password")).unwrap_or_default();
                    if password.is_empty() {
                        return Err("This change carries no credential.".into());
                    }
                    let hint = p
                        .tri("usernameHint")
                        .filter(|h| !h.is_null())
                        .cloned()
                        .or_else(|| pv("usernameHint").map(Value::String))
                        .unwrap_or(Value::Null);
                    s.store.insert(
                        "upstream".into(),
                        json!({
                            "provider": p.s("provider"), "scheme": p.s("scheme"), "host": p.s("host"), "port": p.0.get("port"),
                            "username": username, "password": password,
                            "usernameTemplate": p.s("usernameTemplate"), "passwordTemplate": p.s("passwordTemplate"),
                            "usernameHint": hint,
                        }),
                    );
                    s.store.insert("sticky".into(), json!(p.sticky()));
                    if let Some(c) = p.tri("country") {
                        s.store.insert("country".into(), c.clone());
                    }
                    if let Some(c) = p.tri("capBytes") {
                        s.store.insert("capBytes".into(), c.clone());
                    } else if prev.is_none() {
                        s.store.insert("capBytes".into(), json!(DEFAULT_CAP_BYTES));
                    }
                    // A new credential gets a new salt.
                    let mut salt = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut salt);
                    s.store.insert("stickySalt".into(), json!(hex::encode(salt)));
                    s.store.insert("lastCheck".into(), Value::Null);
                    self.save(&mut s)?;
                    s.store.get("country").cloned().unwrap_or(Value::Null)
                };
                (self.on_changed)().await?;
                tracing::info!(
                    "[exit] {} {} ({}://{}:{}, sticky {}, country {})",
                    if p.kind() == "add" { "connected" } else { "replaced" },
                    p.s("providerName").unwrap_or_default(),
                    p.s("scheme").unwrap_or_default(),
                    p.s("host").unwrap_or_default(),
                    p.0.get("port").map(|v| v.to_string()).unwrap_or_default(),
                    if p.sticky() { "on" } else { "off" },
                    country.as_str().unwrap_or("any")
                );
                let r = self.run_check().await;
                let mut out = obj(&[
                    ("configured", json!(true)),
                    ("sticky", json!(p.sticky())),
                    ("country", country),
                    ("reachable", json!(r.as_ref().is_some_and(|r| r.ok))),
                    ("exitIp", null_or(r.as_ref().and_then(|r| r.exit_ip.clone()))),
                    ("exitCountry", null_or(r.as_ref().and_then(|r| r.exit_country.clone()))),
                ]);
                if let Some(r) = r.filter(|r| !r.ok) {
                    out.insert("checkError".into(), null_or(r.error));
                }
                Ok(out)
            }
        }
    }

    fn country(&self) -> Option<String> {
        self.st()
            .store
            .get("country")
            .and_then(Value::as_str)
            .map(str::to_string)
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let p = match parse(&payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed("failed", e),
        };
        let _one = self.running.lock().await;
        let summary = summarize(&p, self.country().as_deref());
        let data = obj(&[("changeId", p.0["changeId"].clone()), ("summary", json!(summary))]);
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        if routes.is_empty() {
            self.kit.consent.forget(SCOPE);
            return match self.apply(&p).await {
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
                scope: SCOPE.into(),
                change_id: p.s("changeId").unwrap_or_default(),
                proposal: Value::Object(p.0.clone()),
                agent_name: "your organization's exit".into(),
                summary,
                routes,
                ..Default::default()
            })
            .await;
        if let crate::contracts::CodeSent::Sent { sent_via, .. } = &sent {
            tracing::info!("[exit] code sent for {} via {sent_via}", p.kind());
        }
        awaiting(sent, data)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed exit.confirm payload");
        };
        let _one = self.running.lock().await;
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(SCOPE, &change_id, &code) {
            CodeCheck::Expired => fail("expired", "No change is waiting for a code, or the code expired.", data),
            CodeCheck::Wrong { tries_left } => {
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                let Some(p) = proposal.as_object().cloned().map(Proposal) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                // Against what the box held before, as the person was shown.
                let summary = summarize(&p, self.country().as_deref());
                match self.apply(&p).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summary));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        // The pending proposal holds the password in memory; cancelling drops it with the code.
        self.kit.consent.cancel(SCOPE, change_id.as_deref());
        ok("cancelled", obj(&[("changeId", null_or(change_id))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_render_as_the_proxy_does() {
        let v = |session: Option<&str>, country: Option<&str>| TemplateValues {
            username: Some("bob".into()),
            password: Some("pw".into()),
            session: session.map(str::to_string),
            country: country.map(str::to_string),
        };
        let t = "customer-{username}[-cc-{country}][-sessid-{session}]";
        assert_eq!(render_template(t, &v(None, None)), "customer-bob");
        assert_eq!(
            render_template(t, &v(Some("s1"), Some("de"))),
            "customer-bob-cc-DE-sessid-s1"
        );
        assert_eq!(
            render_template("{username}[-sticky]", &v(Some("s"), None)),
            "bob-sticky"
        );
        assert_eq!(render_template("{username}[-sticky]", &v(None, None)), "bob");
        assert_eq!(render_template("x-{country_lc}", &v(None, Some("FR"))), "x-fr");
        assert_eq!(session_for("salt", "vm_1").len(), 12);
    }

    #[test]
    fn proposals_and_summaries() {
        let p = |v: Value| parse(v.as_object().expect("obj"));
        assert_eq!(
            p(json!({"changeId": "c", "kind": "add"})).expect_err("x"),
            "malformed exit.propose payload"
        );
        let a = p(json!({"changeId": "c", "kind": "add", "providerName": "Oxylabs", "usernameHint": "bo…", "scheme": "http", "host": "pr.oxylabs.io", "port": 7777, "username": "bob", "password": "pw"})).expect("ok");
        assert_eq!(
            summarize(&a, None),
            "Send some sites out through Oxylabs (bo…) instead of your firewall"
        );
        assert!(!a.0.contains_key("capBytes") && !a.0.contains_key("country"));
        let s = p(json!({"changeId": "c", "kind": "settings", "country": "de", "sticky": true})).expect("ok");
        assert_eq!(summarize(&s, None), "Have your residential traffic come out in DE");
        assert_eq!(summarize(&s, Some("DE")), "Give each agent its own residential IP");
        let s = p(json!({"changeId": "c", "kind": "settings", "country": "xx1"})).expect("ok");
        assert_eq!(
            summarize(&s, Some("DE")),
            "Stop asking for a particular country on your residential traffic"
        );
        assert_eq!(normalize_country(Some(&json!(" it "))), Some("IT".into()));
    }
}
