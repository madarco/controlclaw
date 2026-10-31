//! OpenClaw's log for the console and for the box's own log page (`routes/logs.ts`,
//! `routes/logs-page.ts`, `redact.ts`).
//!
//!   GET /logs?lines=N   the last N lines of OpenClaw's file log (or `openclaw logs --json` when the
//!                       file cannot be read), the unit's lifecycle and crash lines from its journal,
//!                       the vm-agent's own phone lines, and the unit's state
//!   GET /logs/stream    the same as server-sent events, for at most LOGS_STREAM_MAX_MS
//!
//! Only `time`, `level`, `subsystem` and `message` leave the box, and every message goes through
//! the redactor: the values only this box knows, and anything that looks like a credential.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use cc_http::Resp;
use cc_proc::{Cmd, Runner};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt};

use super::web::{self, date_parse, js_string};

const OPENCLAW_BIN: &str = "/usr/bin/openclaw";
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(15);
const CLI_TIMEOUT_MS: u64 = 10_000;
const MAX_BYTES: &str = "250000";
const DEFAULT_LINES: usize = 200;
const MAX_LINES: usize = 1000;
const PING: Duration = Duration::from_secs(20);
const SERVICE_POLL: Duration = Duration::from_secs(5);
pub const LOGS_STREAM_MAX: Duration = Duration::from_secs(280);
const JOURNAL_LINES: usize = 200;
const TAIL_BYTES: u64 = 512 * 1024;
const FOLLOW_POLL: Duration = Duration::from_millis(700);
const FOLLOW_BACKLOG_LINES: usize = 50;
const AGENT_UNIT: &str = "controlclaw-agent";
/// The key-dir values masked in every line (`SECRET_FILES`).
const SECRET_FILES: &[&str] = &["openclaw_gateway_token", "session_secret", "bootstrap_token"];

/// The redactor, with the box's own secrets (`loadRedactionSecrets`). Loaded again after a value
/// changes (the session secret on "sign out all browsers").
pub struct Redaction {
    keys_dir: PathBuf,
    redactor: RwLock<cc_redact::Redactor>,
    /// Every value ever masked: a rotated secret can still be in lines written before it changed.
    seen: std::sync::Mutex<Vec<String>>,
}

impl Redaction {
    pub fn load(keys_dir: &Path) -> Self {
        let r = Self {
            keys_dir: keys_dir.to_path_buf(),
            redactor: RwLock::new(cc_redact::Redactor::new(Vec::<String>::new())),
            seen: std::sync::Mutex::new(Vec::new()),
        };
        let n = r.reload();
        tracing::info!("Loaded {n} secret(s) for log redaction");
        r
    }

    /// Missing or short files are skipped. Values read before stay masked. Returns how many of the
    /// files' values are masked now (`loadRedactionSecrets`'s count).
    pub fn reload(&self) -> usize {
        let found: Vec<String> = SECRET_FILES
            .iter()
            .filter_map(|n| std::fs::read_to_string(self.keys_dir.join(n)).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| v.encode_utf16().count() >= cc_redact::MIN_SECRET_LENGTH)
            .collect();
        let n = found.len();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        for v in found {
            if !seen.contains(&v) {
                seen.push(v);
            }
        }
        if let Ok(mut r) = self.redactor.write() {
            *r = cc_redact::Redactor::new(seen.clone());
        }
        n
    }

    pub fn redact(&self, text: &str) -> String {
        self.redactor.read().map(|r| r.redact(text)).unwrap_or_default()
    }
}

/// One line as the console shows it (`LogLine`), in that key order.
fn line(time: String, level: String, subsystem: String, message: String) -> Value {
    json!({"time": time, "level": level, "subsystem": subsystem, "message": message})
}

fn object(raw: &str) -> Option<Map<String, Value>> {
    match serde_json::from_str::<Value>(raw) {
        Ok(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// `String(x ?? default)`.
fn string_or(m: &Map<String, Value>, k: &str, default: &str) -> String {
    match m.get(k) {
        None | Some(Value::Null) => default.to_string(),
        Some(v) => js_string(v),
    }
}

fn now_iso() -> String {
    web::iso(web::time_ms(std::time::SystemTime::now()))
}

/// `mapCliRecord`: one `openclaw logs --json` record, or `None` for meta records.
pub fn map_cli_record(r: &Redaction, raw: &str) -> Option<Value> {
    let rec = object(raw)?;
    match rec.get("type").and_then(Value::as_str) {
        Some("log") => Some(line(
            string_or(&rec, "time", ""),
            string_or(&rec, "level", "info").to_lowercase(),
            string_or(&rec, "subsystem", "openclaw"),
            r.redact(&string_or(&rec, "message", "")),
        )),
        Some("notice") => Some(line(
            now_iso(),
            "notice".into(),
            "openclaw".into(),
            r.redact(&string_or(&rec, "message", "")),
        )),
        _ => None,
    }
}

/// `mapFileRecord`: one tslog record from OpenClaw's file log, in the CLI's shape.
pub fn map_file_record(r: &Redaction, raw: &str) -> Option<Value> {
    let rec = object(raw)?;
    let meta = rec.get("_meta").and_then(Value::as_object).cloned().unwrap_or_default();
    let (Some(Value::String(message)), Some(Value::String(time))) = (rec.get("message"), rec.get("time")) else {
        return None;
    };
    let mut subsystem = "openclaw".to_string();
    let name = meta.get("name").and_then(Value::as_str).unwrap_or_default();
    if name.starts_with('{') {
        if let Some(ctx) = object(name) {
            let s = match ctx.get("subsystem") {
                None | Some(Value::Null) => ctx.get("module"),
                some => some,
            };
            if let Some(Value::String(s)) = s
                && !s.is_empty()
            {
                subsystem = s.clone();
            }
        }
    } else if !name.is_empty() {
        subsystem = name.to_string();
    }
    Some(line(
        time.clone(),
        string_or(&meta, "logLevelName", "info").to_lowercase(),
        subsystem,
        r.redact(message),
    ))
}

/// `Number(x)` for a journal field, which is a string of digits.
fn js_number(v: Option<&Value>) -> Option<f64> {
    match v {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() { Some(0.0) } else { t.parse::<f64>().ok() }
        }
        Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        Some(Value::Null) => Some(0.0),
        _ => None,
    }
    .filter(|f| f.is_finite())
}

fn journal_time(rec: &Map<String, Value>) -> String {
    match js_number(rec.get("__REALTIME_TIMESTAMP")) {
        Some(us) => web::iso((us / 1000.0).trunc() as i64),
        None => now_iso(),
    }
}

/// `CRASH_RE`: `^(\s+at |\w*Error\b|node:|FATAL|Unhandled|ELIFECYCLE|Segmentation fault)`.
fn looks_like_crash(m: &str) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(?:\s+at |\w*Error\b|node:|FATAL|Unhandled|ELIFECYCLE|Segmentation fault)").expect("regex")
    });
    RE.is_match(m)
}

/// `mapJournalRecord`: the unit's lifecycle lines and crash-looking output only.
pub fn map_journal_record(r: &Redaction, raw: &str) -> Option<Value> {
    let rec = object(raw)?;
    let message = rec.get("MESSAGE").and_then(Value::as_str).filter(|m| !m.is_empty())?;
    let time = journal_time(&rec);
    if rec.get("SYSLOG_IDENTIFIER").and_then(Value::as_str) == Some("systemd") {
        return Some(line(time, "unit".into(), "systemd".into(), r.redact(message)));
    }
    if looks_like_crash(message) {
        return Some(line(time, "error".into(), "stderr".into(), r.redact(message)));
    }
    None
}

/// `mapAgentPhoneRecord`: the vm-agent's own `[phone] …` and `[phone-stream] …` lines.
pub fn map_agent_phone_record(r: &Redaction, raw: &str) -> Option<Value> {
    let rec = object(raw)?;
    let message = rec.get("MESSAGE").and_then(Value::as_str)?;
    if !(message.starts_with("[phone] ") || message.starts_with("[phone-stream] ")) {
        return None;
    }
    let time = journal_time(&rec);
    let lower = message.to_lowercase();
    let level = if ["fail", "refus", "error", "unavailable", "timeout"]
        .iter()
        .any(|w| lower.contains(w))
    {
        "warn"
    } else {
        "info"
    };
    Some(line(time, level.into(), "vm-agent/phone".into(), r.redact(message)))
}

/// `parseServiceShow`: the unit's state, in the TS key order.
pub fn parse_service_show(stdout: &str) -> Value {
    let mut kv: Vec<(String, String)> = Vec::new();
    for l in stdout.split('\n') {
        if let Some(i) = l.find('=')
            && i > 0
        {
            let (k, v) = (l[..i].to_string(), l[i + 1..].trim().to_string());
            match kv.iter_mut().find(|(x, _)| *x == k) {
                Some(e) => e.1 = v,
                None => kv.push((k, v)),
            }
        }
    }
    let get = |k: &str| kv.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
    let since = get("ExecMainStartTimestamp")
        .filter(|s| !s.is_empty())
        .and_then(|s| date_parse(&s))
        .map(web::iso);
    let exit = get("ExecMainStatus").map(|v| js_number(Some(&Value::String(v))));
    json!({
        "active": get("ActiveState").unwrap_or_else(|| "unknown".into()),
        "subState": get("SubState").unwrap_or_else(|| "unknown".into()),
        "result": get("Result").unwrap_or_else(|| "unknown".into()),
        "exitStatus": exit.flatten().map(|f| json!(f as i64)).unwrap_or(Value::Null),
        "since": since,
        "restarts": get("NRestarts").and_then(|v| js_number(Some(&Value::String(v)))).map(|f| f as i64).unwrap_or(0),
    })
}

/// `?lines=N`: 200 by default, at most 1000.
pub fn parse_lines(query_lines: Option<&str>) -> usize {
    match query_lines.and_then(web::parse_int) {
        Some(n) if n >= 1 => (n as usize).min(MAX_LINES),
        _ => DEFAULT_LINES,
    }
}

pub struct Logs {
    runner: Arc<dyn Runner>,
    pub redaction: Arc<Redaction>,
    /// `CC_SERVICE`: whose unit and journal (`openclaw`, or `gbrain` on a brain box).
    service: String,
    /// OpenClaw's file log folder (`OPENCLAW_LOG_DIR`, `/tmp/openclaw`).
    log_dir: PathBuf,
}

/// What a run gave (`run` in logs.ts): stdout whatever the exit, and the first stderr line as the
/// error when it failed.
async fn run(runner: &dyn Runner, cmd: Cmd) -> (String, Option<String>) {
    let program = cmd.program.clone();
    let line = std::iter::once(cmd.program.clone())
        .chain(cmd.args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    match runner.run(cmd).await {
        Ok(out) if out.success() => (out.stdout_str(), None),
        Ok(out) => {
            let first = out
                .stderr_str()
                .trim()
                .split('\n')
                .next()
                .unwrap_or_default()
                .to_string();
            // `stderr's first line || err.message`; execFile's message is the whole command line.
            let err = if !first.is_empty() {
                first
            } else {
                format!("Command failed: {line}")
            };
            (out.stdout_str(), Some(err))
        }
        Err(cc_proc::RunError::Spawn(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            (String::new(), Some(format!("spawn {program} ENOENT")))
        }
        Err(e) => (String::new(), Some(e.to_string())),
    }
}

fn home_env(cmd: Cmd) -> Cmd {
    cmd.env(
        "HOME",
        std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()),
    )
}

/// The newest `openclaw*.log` in the log folder, by mtime.
async fn newest_log_file(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(PathBuf, std::time::SystemTime)> = None;
    // In name order, as Node's `readdirSync` (libuv's scandir) gives them: the first wins a tie.
    let mut names: Vec<String> = Vec::new();
    let mut rd = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(e)) = rd.next_entry().await {
        names.push(e.file_name().to_string_lossy().into_owned());
    }
    names.sort();
    for name in names {
        if !(name.starts_with("openclaw") && name.ends_with(".log")) {
            continue;
        }
        let path = dir.join(&name);
        let mtime = tokio::fs::metadata(&path).await.ok()?.modified().ok()?;
        if best.as_ref().is_none_or(|(_, m)| mtime > *m) {
            best = Some((path, mtime));
        }
    }
    best.map(|b| b.0)
}

struct FileTail {
    path: PathBuf,
    size: u64,
    lines: Vec<Value>,
}

impl Logs {
    pub fn new(runner: Arc<dyn Runner>, redaction: Arc<Redaction>, service: String) -> Self {
        Self {
            runner,
            redaction,
            service,
            log_dir: std::env::var("OPENCLAW_LOG_DIR")
                .unwrap_or_else(|_| "/tmp/openclaw".into())
                .into(),
        }
    }

    /// The last `lines` records of the newest log file, or `None` when there is none readable.
    async fn read_file_tail(&self, lines: usize) -> Option<FileTail> {
        let path = newest_log_file(&self.log_dir).await?;
        let mut f = tokio::fs::File::open(&path).await.ok()?;
        let size = f.metadata().await.ok()?.len();
        let start = size.saturating_sub(TAIL_BYTES);
        f.seek(std::io::SeekFrom::Start(start)).await.ok()?;
        let mut buf = Vec::with_capacity((size - start) as usize);
        (&mut f).take(size - start).read_to_end(&mut buf).await.ok()?;
        let mut text = String::from_utf8_lossy(&buf).into_owned();
        if start > 0 {
            // `text.slice(text.indexOf("\n") + 1)`: without a newline that is the whole text.
            text = match text.find('\n') {
                Some(i) => text[i + 1..].to_string(),
                None => text,
            };
        }
        let mut out: Vec<Value> = text
            .split('\n')
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| map_file_record(&self.redaction, l))
            .collect();
        let skip = out.len().saturating_sub(lines);
        out.drain(..skip);
        Some(FileTail { path, size, lines: out })
    }

    async fn read_cli_snapshot(&self, lines: usize) -> (Vec<Value>, Option<String>) {
        let cmd = home_env(Cmd::new(OPENCLAW_BIN).args([
            "logs".to_string(),
            "--json".into(),
            "--limit".into(),
            lines.to_string(),
            "--max-bytes".into(),
            MAX_BYTES.into(),
            "--timeout".into(),
            CLI_TIMEOUT_MS.to_string(),
        ]))
        .timeout(SNAPSHOT_TIMEOUT);
        let (stdout, error) = run(self.runner.as_ref(), cmd).await;
        let out: Vec<Value> = stdout
            .split('\n')
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| map_cli_record(&self.redaction, l))
            .collect();
        let warning = match error {
            Some(e) if out.is_empty() => Some(self.redaction.redact(&format!("openclaw logs: {e}"))),
            _ => None,
        };
        (out, warning)
    }

    async fn read_journal(&self) -> Vec<Value> {
        let cmd = Cmd::new("sudo")
            .args([
                "journalctl".to_string(),
                "-u".into(),
                self.service.clone(),
                "-n".into(),
                JOURNAL_LINES.to_string(),
                "-o".into(),
                "json".into(),
                "--no-pager".into(),
            ])
            .timeout(SNAPSHOT_TIMEOUT);
        let (stdout, _) = run(self.runner.as_ref(), home_env(cmd)).await;
        stdout
            .split('\n')
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| map_journal_record(&self.redaction, l))
            .collect()
    }

    async fn read_agent_phone_journal(&self) -> Vec<Value> {
        // A brain has no phone.
        if self.service != "openclaw" {
            return Vec::new();
        }
        let cmd = Cmd::sudo("journalctl")
            .args([
                "-u".to_string(),
                AGENT_UNIT.into(),
                "-n".into(),
                (JOURNAL_LINES * 4).to_string(),
                "-o".into(),
                "json".into(),
                "--no-pager".into(),
            ])
            .timeout(SNAPSHOT_TIMEOUT);
        let (stdout, _) = run(self.runner.as_ref(), home_env(cmd)).await;
        stdout
            .split('\n')
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| map_agent_phone_record(&self.redaction, l))
            .collect()
    }

    async fn read_service_state(&self) -> Value {
        let cmd = Cmd::new("systemctl")
            .args([
                "show",
                &self.service,
                "-p",
                "ActiveState,SubState,Result,ExecMainStatus,ExecMainStartTimestamp,NRestarts",
            ])
            .timeout(Duration::from_secs(5));
        let (stdout, _) = run(self.runner.as_ref(), home_env(cmd)).await;
        parse_service_show(&stdout)
    }

    /// `handleLogs`: the snapshot.
    pub async fn snapshot(&self, lines: usize) -> Resp {
        let from_file = self.read_file_tail(lines).await;
        let gateway = async {
            match &from_file {
                Some(t) => (t.lines.clone(), None),
                None => self.read_cli_snapshot(lines).await,
            }
        };
        let ((gw_lines, warning), journal, service, phone) = tokio::join!(
            gateway,
            self.read_journal(),
            self.read_service_state(),
            self.read_agent_phone_journal()
        );
        let mut merged: Vec<Value> = gw_lines.into_iter().chain(journal).chain(phone).collect();
        merged.sort_by_key(sort_time);
        let skip = merged.len().saturating_sub(lines);
        merged.drain(..skip);
        let mut body = Map::new();
        body.insert("service".into(), service);
        body.insert("lines".into(), Value::Array(merged));
        if let Some(w) = warning {
            body.insert("warning".into(), json!(w));
        }
        web::send_json(200, &Value::Object(body), &[])
    }

    /// `handleUnitLogs`: a box with no OpenClaw log (the brain): the unit's journal and state.
    pub async fn unit_snapshot(&self, lines: usize) -> Resp {
        let (journal, service) = tokio::join!(self.read_journal(), self.read_service_state());
        let skip = journal.len().saturating_sub(lines);
        let journal: Vec<Value> = journal.into_iter().skip(skip).collect();
        web::send_json(200, &json!({"service": service, "lines": journal}), &[])
    }

    /// `handleLogStream`: the live tail as server-sent events.
    pub fn stream(self: &Arc<Self>) -> Resp {
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(256);
        let me = self.clone();
        tokio::spawn(async move { me.run_stream(tx).await });
        web::streamed(
            200,
            rx,
            &[
                ("content-type", "text/event-stream; charset=utf-8".into()),
                ("cache-control", "no-cache, no-transform".into()),
                ("connection", "keep-alive".into()),
                ("x-accel-buffering", "no".into()),
            ],
        )
    }

    async fn run_stream(self: Arc<Self>, tx: tokio::sync::mpsc::Sender<Bytes>) {
        let event = |name: Option<&str>, data: &Value| {
            let head = name.map(|n| format!("event: {n}\n")).unwrap_or_default();
            Bytes::from(format!(
                "{head}data: {}\n\n",
                serde_json::to_string(data).unwrap_or_default()
            ))
        };
        // Lines from the followers come through here, so one task writes the response.
        let (lines_tx, mut lines_rx) = tokio::sync::mpsc::channel::<Value>(256);
        let mut children: Vec<tokio::process::Child> = Vec::new();
        if let Some(c) = self.follow_agent_phone_journal(lines_tx.clone()) {
            children.push(c);
        }
        let (cli_exit_tx, mut cli_exit_rx) = tokio::sync::mpsc::channel::<()>(1);
        let tail = self.read_file_tail(FOLLOW_BACKLOG_LINES).await;
        let mut follower = None;
        let mut gone = false;
        match tail {
            Some(t) => {
                for l in &t.lines {
                    if tx.send(event(None, l)).await.is_err() {
                        gone = true;
                        break;
                    }
                }
                let me = self.clone();
                let ltx = lines_tx.clone();
                follower = Some(tokio::spawn(async move { me.follow_file(t.path, t.size, ltx).await }));
            }
            None => {
                if let Some(c) = self.follow_cli(lines_tx.clone(), cli_exit_tx) {
                    children.push(c);
                }
            }
        }
        drop(lines_tx);
        // The unit's state on connect, then whenever it changes, polled in a task of its own so a
        // slow `systemctl` never holds up the tail (the TS does not await it either).
        let (service_tx, mut service_rx) = tokio::sync::mpsc::channel::<Value>(4);
        let me = self.clone();
        let poller = tokio::spawn(async move {
            let mut poll = tokio::time::interval(SERVICE_POLL);
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last = String::new();
            loop {
                poll.tick().await;
                let s = me.read_service_state().await;
                let key = s.to_string();
                if key != last {
                    last = key;
                    if service_tx.send(s).await.is_err() {
                        return;
                    }
                }
            }
        });
        let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING, PING);
        let stop = tokio::time::sleep(LOGS_STREAM_MAX);
        tokio::pin!(stop);
        // `gone`: the browser left while the backlog went out.
        if !gone {
            loop {
                let out = tokio::select! {
                    _ = &mut stop => {
                        let _ = tx.send(event(Some("end"), &json!({"reason": "max-duration"}))).await;
                        break;
                    }
                    _ = ping.tick() => Some(Bytes::from_static(b": ping\n\n")),
                    // A stopped gateway explains a quiet tail.
                    Some(s) = service_rx.recv() => Some(event(Some("service"), &s)),
                    Some(l) = lines_rx.recv() => Some(event(None, &l)),
                    Some(()) = cli_exit_rx.recv() => {
                        // The CLI exits when it cannot reach the gateway; the browser reconnects.
                        let _ = tx.send(event(Some("end"), &json!({"reason": "cli-exit"}))).await;
                        break;
                    }
                    _ = tx.closed() => break,
                };
                if let Some(b) = out
                    && tx.send(b).await.is_err()
                {
                    break;
                }
            }
        }
        poller.abort();
        if let Some(f) = follower {
            f.abort();
        }
        for c in children {
            tokio::spawn(kill_group(c));
        }
    }

    /// Follow the file log from `size` of `path`: what was appended, in whole lines. A newer dated
    /// file is switched to; a file that shrank is read from 0.
    async fn follow_file(self: Arc<Self>, mut path: PathBuf, mut offset: u64, out: tokio::sync::mpsc::Sender<Value>) {
        let mut partial: Vec<u8> = Vec::new();
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + FOLLOW_POLL, FOLLOW_POLL);
        loop {
            tick.tick().await;
            if let Some(newest) = newest_log_file(&self.log_dir).await
                && newest != path
            {
                path = newest;
                offset = 0;
                partial.clear();
            }
            let Ok(meta) = tokio::fs::metadata(&path).await else {
                continue;
            };
            let size = meta.len();
            if size < offset {
                offset = 0;
                partial.clear();
            }
            if size == offset {
                continue;
            }
            let Ok(mut f) = tokio::fs::File::open(&path).await else {
                continue;
            };
            if f.seek(std::io::SeekFrom::Start(offset)).await.is_err() {
                continue;
            }
            let want = (size - offset).min(TAIL_BYTES);
            let mut buf = Vec::with_capacity(want as usize);
            let Ok(n) = (&mut f).take(want).read_to_end(&mut buf).await else {
                continue;
            };
            offset += n as u64;
            partial.extend_from_slice(&buf);
            while let Some(i) = partial.iter().position(|b| *b == b'\n') {
                let raw: Vec<u8> = partial.drain(..=i).collect();
                let l = String::from_utf8_lossy(&raw[..raw.len() - 1]).into_owned();
                if l.trim().is_empty() {
                    continue;
                }
                if let Some(v) = map_file_record(&self.redaction, &l)
                    && out.send(v).await.is_err()
                {
                    return;
                }
            }
        }
    }

    /// Live phone lines from the vm-agent's journal (`sudo -n journalctl -u controlclaw-agent -f`).
    fn follow_agent_phone_journal(&self, out: tokio::sync::mpsc::Sender<Value>) -> Option<tokio::process::Child> {
        if self.service != "openclaw" {
            return None;
        }
        let args = [
            "-n",
            "journalctl",
            "-u",
            AGENT_UNIT,
            "-f",
            "-n",
            "0",
            "-o",
            "json",
            "--no-pager",
        ];
        let redaction = self.redaction.clone();
        spawn_lines("sudo", &args, move |l| map_agent_phone_record(&redaction, l), out, None)
    }

    /// The fallback tail when the file log is not readable: `openclaw logs --json --follow`.
    fn follow_cli(
        &self,
        out: tokio::sync::mpsc::Sender<Value>,
        exit: tokio::sync::mpsc::Sender<()>,
    ) -> Option<tokio::process::Child> {
        let backlog = FOLLOW_BACKLOG_LINES.to_string();
        let args = [
            "logs",
            "--json",
            "--follow",
            "--limit",
            &backlog,
            "--max-bytes",
            MAX_BYTES,
        ];
        let redaction = self.redaction.clone();
        let child = spawn_lines(
            OPENCLAW_BIN,
            &args,
            move |l| map_cli_record(&redaction, l),
            out,
            Some(exit.clone()),
        );
        if child.is_none() {
            // Node reports the spawn failure as the child's exit.
            let _ = exit.try_send(());
        }
        child
    }
}

/// Merge order: `Date.parse(time) || 0`; a stable sort keeps lines with one time in order.
fn sort_time(l: &Value) -> i64 {
    l.get("time").and_then(Value::as_str).and_then(date_parse).unwrap_or(0)
}

/// A follower: the command in its own process group, stdout read line by line. Long-running and
/// streamed, which the `cc_proc` runner does not do yet (noted for W0), so it is spawned here.
fn spawn_lines(
    program: &str,
    args: &[&str],
    map: impl Fn(&str) -> Option<Value> + Send + 'static,
    out: tokio::sync::mpsc::Sender<Value>,
    exit: Option<tokio::sync::mpsc::Sender<()>>,
) -> Option<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env(
            "HOME",
            std::env::var("HOME").unwrap_or_else(|_| "/home/controlclaw".into()),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = cmd.spawn().ok()?;
    let stdout = child.stdout.take()?;
    tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stdout).split(b'\n');
        loop {
            // Also when nothing it reads is wanted: a follower whose stream is gone stops here.
            let raw = tokio::select! {
                r = reader.next_segment() => match r {
                    Ok(Some(raw)) => raw,
                    _ => break,
                },
                _ = out.closed() => return,
            };
            let l = String::from_utf8_lossy(&raw).into_owned();
            if l.trim().is_empty() {
                continue;
            }
            if let Some(v) = map(&l)
                && out.send(v).await.is_err()
            {
                return;
            }
        }
        if let Some(e) = exit {
            let _ = e.send(()).await;
        }
    });
    Some(child)
}

/// SIGTERM to the follower's whole group, so the launcher and its node child both go; sudo passes
/// it on to the command. Only if that is ignored for two seconds, a SIGKILL.
async fn kill_group(mut child: tokio::process::Child) {
    if let Ok(Some(_)) = child.try_wait() {
        return;
    }
    if let Some(pid) = child.id() {
        let _ = tokio::process::Command::new("kill")
            .args(["-TERM", "--", &format!("-{pid}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
    if tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .is_err()
    {
        let _ = child.start_kill();
    }
}

/// The log page and its two reads (`routes/logs-page.ts`).
pub mod page {
    use super::*;
    use crate::boxside::access::Access;

    const PAGE_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

    fn page_headers() -> Vec<(&'static str, String)> {
        vec![
            ("cache-control", "no-store".into()),
            ("x-frame-options", "DENY".into()),
            ("content-security-policy", PAGE_CSP.into()),
        ]
    }

    pub fn serve_page(access: &Access, parts: &http::request::Parts, vm_id: &str) -> Resp {
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        let html = |code: u16, body: String| {
            web::with_headers(
                cc_http::full(
                    http::StatusCode::from_u16(code).unwrap_or(http::StatusCode::OK),
                    "text/html; charset=utf-8",
                    body,
                ),
                &page_headers(),
            )
        };
        if access.sessions.read_session(cookie.as_deref(), vm_id).is_none() {
            return html(401, access.denied_logs_page());
        }
        let ctx = access.shell_context();
        let agent_name = crate::boxside::shell::agent_name_of(ctx.hostname.as_deref());
        html(
            200,
            crate::boxside::shell::shell_page(
                &ctx,
                &format!("{agent_name} · logs"),
                Some("logs"),
                &format!(
                    r#"<div id="root"></div><script id="cc-logs" type="application/json">{}</script><script type="module" src="/__cc/files-ui/logs.js"></script>"#,
                    crate::boxside::shell::inline_json(&json!({"agentName": agent_name}))
                ),
                "",
                access.nav(),
            ),
        )
    }

    /// `serveLogsData`: same origin only, then the session, then the snapshot or the stream.
    pub async fn serve_data(
        access: &Access,
        logs: &Arc<Logs>,
        parts: &http::request::Parts,
        pathname: &str,
        vm_id: &str,
    ) -> Resp {
        let policy = cc_origin::OriginPolicy {
            allowed: vec![access.allowed_origins().0],
            allow_top_level_navigation: false,
            uncredentialed: cc_origin::Uncredentialed::Allow,
        };
        let facts = cc_origin::agent_request_facts(parts.method.as_str(), &parts.headers, None);
        if let cc_origin::OriginVerdict::Denied { reason, origin } = cc_origin::check_origin(&facts, &policy) {
            tracing::warn!("[logs] {}", cc_origin::denial_message(reason, origin.as_deref()));
            return cc_http::json(403, &json!({"error": "Not from this agent's own page."}));
        }
        let cookie = cc_origin::node_header(&parts.headers, "cookie");
        if access.sessions.read_session(cookie.as_deref(), vm_id).is_none() {
            return cc_http::json(401, &json!({"error": "Your session on this agent has expired."}));
        }
        if pathname == "/__cc/logs/snapshot" {
            return logs.snapshot(parse_lines(query_lines(parts).as_deref())).await;
        }
        logs.stream()
    }
}

/// `?lines=` of the request.
pub fn query_lines(parts: &http::request::Parts) -> Option<String> {
    web::query(parts, "lines")
}

#[cfg(test)]
mod tests;
