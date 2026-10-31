//! The brain's Activity (`gbrain-activity.ts`, docs/plans/gbrain.md §10): what reaches the
//! console's Brain view.
//!
//! **Agents' calls.** GBrain streams one event per MCP call on its admin feed (`GET /admin/events`,
//! server-sent events), already redacted: the token's name, the operation, how long it took and
//! whether it worked. The gate names each agent's token `cc-<vmId>`. The feed wants GBrain's admin
//! cookie, which this reader gets from a single-use login link followed over loopback; when the
//! cookie stops working it gets another. Events missed while the feed is down are not replayed.
//!
//! **The nightly run.** `cc-gbrain-dream` leaves a summary of the night's run; it is shipped once,
//! keyed by when it finished.
//!
//! **The counts.** Every 15 minutes, the page count and pages per type (`stats.rs`).
//!
//! All three go to `POST /api/vm-agent/activity` with the box's own token.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::now_ms;
use super::stats::{Disk, STATS_EVERY, map_brain_stats};

static AGENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^cc-([A-Za-z0-9_-]{1,64})$").expect("regex"));
static COOKIE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"gbrain_admin=([^;,\s]+)").expect("regex"));
const QUEUE_MAX: usize = 2000;
const BATCH: usize = 200;
/// No call may hold up its loop for good: Node's timers kept firing while one hung.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The admin feed: how long its answer may take, and how long it may stay silent before it is
/// opened again, so a feed that hangs cannot stop Activity for good. A quiet brain reopens it every
/// few minutes; calls made in the seconds it is closed are not seen, as after any reconnect.
const FEED_ANSWER_TIMEOUT: Duration = Duration::from_secs(60);
const FEED_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// The first `n` UTF-16 units of `s` (`s.slice(0, n)`), never splitting a character.
fn slice16(s: &str, n: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in s.chars() {
        units += c.len_utf16();
        if units > n {
            break;
        }
        out.push(c);
    }
    out
}

/// `Date.parse` of the ISO times GBrain and the nightly run write (`2026-09-30T14:45:11.051Z`,
/// or with a `+hh:mm` offset): milliseconds, or `None`.
pub fn parse_iso(s: &str) -> Option<f64> {
    static ISO: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::([0-9]{2})(?:\.([0-9]{1,9}))?)?(Z|[+-][0-9]{2}:[0-9]{2})$")
            .expect("regex")
    });
    let c = ISO.captures(s)?;
    let n = |i: usize| c.get(i).map_or(0, |m| m.as_str().parse::<i64>().unwrap_or(0));
    let (y, mo, d, h, mi, sec) = (n(1), n(2), n(3), n(4), n(5), n(6));
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 24 || mi > 59 || sec > 59 {
        return None;
    }
    let ms = c.get(7).map_or(0, |m| {
        let f = format!("{:0<3}", m.as_str());
        f[..3].parse::<i64>().unwrap_or(0)
    });
    // Days from the civil date (Howard Hinnant's algorithm).
    let (yy, mm) = if mo <= 2 { (y - 1, mo + 9) } else { (y, mo - 3) };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * mm + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let offset = match c.get(8).map(|m| m.as_str()) {
        Some("Z") | None => 0,
        Some(o) => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (o[1..3].parse::<i64>().unwrap_or(0) * 60 + o[4..6].parse::<i64>().unwrap_or(0))
        }
    };
    let secs = days * 86_400 + h * 3600 + mi * 60 + sec - offset * 60;
    Some((secs * 1000 + ms) as f64)
}

/// A number the way JSON gives it: an integer when it is one, so the record reads as the TS one.
fn num(n: f64) -> Value {
    if n.fract() == 0.0 && n.abs() < 9.007e15 {
        json!(n as i64)
    } else {
        json!(n)
    }
}

/// One `data:` line of GBrain's admin feed, as a record. `None` for anything that is not an
/// agent's call.
pub fn map_brain_event(data: &str) -> Option<Value> {
    let ev: Value = serde_json::from_str(data).ok()?;
    let agent_raw = ev.get("agent").and_then(Value::as_str);
    let agent = agent_raw
        .and_then(|a| AGENT.captures(a))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string());
    let operation = ev
        .get("operation")
        .and_then(Value::as_str)
        .map(|o| slice16(o, 80))
        .unwrap_or_default();
    let ts_raw = ev.get("timestamp").and_then(Value::as_str);
    let at = ts_raw.and_then(parse_iso);
    // Only calls through the gate; MCP's own protocol methods (`tools/list`) are not something the
    // agent did.
    let (Some(agent), Some(at)) = (agent, at) else {
        return None;
    };
    if operation.is_empty() || operation.contains('/') {
        return None;
    }
    let status = ev.get("status").and_then(Value::as_str).map(|s| slice16(s, 32));
    let latency = ev
        .get("latency_ms")
        .and_then(Value::as_f64)
        .filter(|f| f.is_finite())
        .map(|f| f.round() as i64);
    let id_src = format!(
        "{}|{}|{operation}|{}",
        agent_raw.unwrap_or_default(),
        ts_raw.unwrap_or_default(),
        latency.map(|l| l.to_string()).unwrap_or_default()
    );
    let call_id = hex::encode(Sha256::digest(id_src.as_bytes()))[..40].to_string();
    Some(json!({
        "source": "brain_call",
        "call_id": call_id,
        "ts": num(at / 1000.0),
        "agent_vm_id": agent,
        "operation": operation,
        "ok": status.as_deref() == Some("success"),
        "status": status,
        "duration_ms": latency,
    }))
}

/// The nightly summary file, as a record. `None` when it cannot be read.
pub fn read_cycle_report(raw: &str) -> Option<Value> {
    let d: Value = serde_json::from_str(raw).ok()?;
    let finished = d.get("finished_at").and_then(Value::as_str)?;
    let at = parse_iso(finished)?;
    let n = |k: &str| d.get(k).and_then(Value::as_f64).filter(|f| f.is_finite());
    let mut totals = Map::new();
    if let Some(Value::Object(t)) = d.get("totals") {
        for (k, v) in t.iter().take(40) {
            if let Some(f) = v.as_f64().filter(|f| f.is_finite()) {
                totals.insert(slice16(k, 64), num(f));
            }
        }
    }
    Some(json!({
        "source": "brain_cycle",
        "cycle_id": slice16(finished, 64),
        "ts": num(at / 1000.0),
        "status": d.get("status").and_then(Value::as_str).map(|s| slice16(s, 32)).unwrap_or_else(|| "unknown".into()),
        "exit_code": n("exit_code").map(num),
        "duration_ms": n("duration_ms").map(|f| json!(f.round() as i64)),
        "cost_usd": n("cost_usd").map(|c| num(c.max(0.0))),
        "model_calls": n("model_calls").map(|f| json!(f.round() as i64)),
        "totals": totals,
    }))
}

/// Pulls the `data:` payloads out of a chunk of SSE text; returns them and what is left over.
pub fn split_sse(buffer: &str) -> (Vec<String>, String) {
    static BLANK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\r?\n\r?\n").expect("regex"));
    let mut blocks: Vec<&str> = BLANK.split(buffer).collect();
    let rest = blocks.pop().unwrap_or_default().to_string();
    let events = blocks
        .iter()
        .filter_map(|block| {
            let data = block
                .split('\n')
                .map(|l| l.strip_suffix('\r').unwrap_or(l))
                .filter(|l| l.starts_with("data:"))
                .map(|l| l[5..].trim_start())
                .collect::<Vec<_>>()
                .join("\n");
            (!data.is_empty()).then_some(data)
        })
        .collect();
    (events, rest)
}

pub type LoginFn = Arc<dyn Fn() -> futures_util::future::BoxFuture<'static, Result<String, String>> + Send + Sync>;
pub type TokenFn = Arc<dyn Fn() -> Result<String, String> + Send + Sync>;
pub type DiskFn = Arc<dyn Fn() -> Option<Disk> + Send + Sync>;
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

pub type ClientFn = Arc<dyn Fn() -> reqwest::Client + Send + Sync>;

pub struct Options {
    /// The client for the console: it trusts the firewall's CA once it is installed
    /// (`cc_client::HttpClient`), since the brain's egress goes through the firewall.
    pub console_http: ClientFn,
    /// GBrain on loopback, e.g. `http://127.0.0.1:3130`.
    pub gbrain_url: String,
    /// A single-use `/admin/auth/<token>` path (`login.rs`).
    pub login_path: LoginFn,
    pub activity_url: String,
    pub token: TokenFn,
    pub report_path: PathBuf,
    pub cursor_path: PathBuf,
    pub disk: Option<DiskFn>,
    pub log: LogFn,
}

pub struct BrainActivity {
    opts: Options,
    /// No redirects: GBrain's login link answers with one, and so does a stale cookie.
    http: reqwest::Client,
    /// Records with a sequence number, so a flush removes what it sent even when older records were
    /// dropped meanwhile.
    queue: Mutex<(VecDeque<(u64, Value)>, u64)>,
    cookie: Mutex<Option<String>>,
}

/// A request error without its URL: the login link's path is a one-use admin token, and none of
/// these may reach the journal with what they asked for.
fn plain(e: reqwest::Error) -> String {
    e.without_url().to_string()
}

fn refused(status: u16) -> bool {
    status == 401 || status == 403 || (300..400).contains(&status)
}

impl BrainActivity {
    pub fn new(opts: Options) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Arc::new(Self {
            opts,
            http,
            queue: Mutex::new((VecDeque::new(), 0)),
            cookie: Mutex::new(None),
        })
    }

    fn log(&self, line: &str) {
        (self.opts.log)(line);
    }

    pub fn start(self: &Arc<Self>) {
        let a = self.clone();
        tokio::spawn(async move { a.follow_loop().await });
        let a = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(10));
            t.tick().await;
            loop {
                t.tick().await;
                if let Err(e) = a.flush().await {
                    a.log(&format!("ship failed: {e}"));
                }
            }
        });
        let a = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(60));
            loop {
                t.tick().await;
                if let Err(e) = a.check_cycle().await {
                    a.log(&format!("nightly report: {e}"));
                }
            }
        });
        let a = self.clone();
        tokio::spawn(async move {
            // The first read waits a minute, so a brain that has just started is not counted
            // mid-start.
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut t = tokio::time::interval(STATS_EVERY);
            loop {
                t.tick().await;
                if let Err(e) = a.read_stats().await {
                    a.log(&format!("counts: {e}"));
                }
            }
        });
    }

    #[cfg(test)]
    pub fn pending(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).0.len()
    }

    pub fn enqueue(&self, r: Value) {
        let mut guard = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        let (q, next) = &mut *guard;
        *next += 1;
        q.push_back((*next, r));
        // A console that is down for a long time costs the oldest calls, not the box's memory.
        while q.len() > QUEUE_MAX {
            q.pop_front();
        }
    }

    /// GBrain's admin cookie, from a fresh single-use link followed over loopback.
    pub async fn admin_cookie(&self) -> Result<String, String> {
        let path = (self.opts.login_path)().await?;
        let res = self
            .http
            .get(format!("{}{path}", self.opts.gbrain_url))
            .timeout(CALL_TIMEOUT)
            .send()
            .await
            .map_err(plain)?;
        let set_cookie = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(", ");
        COOKIE
            .captures(&set_cookie)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| format!("GBrain set no admin cookie (HTTP {})", res.status().as_u16()))
    }

    async fn cookie(&self) -> Result<String, String> {
        if let Some(c) = self.cookie.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Ok(c);
        }
        let c = self.admin_cookie().await?;
        *self.cookie.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.clone());
        Ok(c)
    }

    fn drop_cookie(&self) {
        *self.cookie.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The brain's counts, queued for the next flush. A refused cookie is replaced once.
    pub async fn read_stats(&self) -> Result<(), String> {
        for _ in 0..2 {
            let cookie = self.cookie().await?;
            let res = self
                .http
                .get(format!("{}/admin/api/full-stats", self.opts.gbrain_url))
                .header("cookie", format!("gbrain_admin={cookie}"))
                .timeout(CALL_TIMEOUT)
                .send()
                .await
                .map_err(plain)?;
            let status = res.status().as_u16();
            // A redirect is GBrain sending a stale cookie to its login page.
            if refused(status) {
                self.drop_cookie();
                continue;
            }
            if !res.status().is_success() {
                return Err(format!("GBrain's stats answered HTTP {status}"));
            }
            let body: Value = res.json().await.map_err(plain)?;
            let disk = self.opts.disk.as_ref().and_then(|d| d());
            let r = map_brain_stats(&body, now_ms(), disk).ok_or("GBrain's stats had no page count")?;
            self.enqueue(r);
            return Ok(());
        }
        Err("GBrain refused the admin cookie for its stats".into())
    }

    async fn follow_loop(&self) {
        let mut backoff = Duration::from_secs(5);
        loop {
            match self.follow_once(&mut backoff).await {
                Ok(()) => self.log("admin feed ended; reconnecting"),
                Err(e) => self.log(&format!("{e}; retrying in {} s", backoff.as_secs())),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    async fn follow_once(&self, backoff: &mut Duration) -> Result<(), String> {
        let cookie = self.cookie().await?;
        let res = self
            .http
            .get(format!("{}/admin/events", self.opts.gbrain_url))
            .header("cookie", format!("gbrain_admin={cookie}"))
            .header("accept", "text/event-stream")
            .send();
        let res = tokio::time::timeout(FEED_ANSWER_TIMEOUT, res)
            .await
            .map_err(|_| "admin feed did not answer".to_string())?
            .map_err(plain)?;
        let status = res.status().as_u16();
        if refused(status) {
            self.drop_cookie();
            return Err(format!("admin feed refused the cookie (HTTP {status})"));
        }
        if !res.status().is_success() {
            return Err(format!("admin feed answered HTTP {status}"));
        }
        *backoff = Duration::from_secs(5);
        let mut body = res.bytes_stream();
        let mut pending: Vec<u8> = Vec::new();
        let mut buffer = String::new();
        loop {
            let chunk = match tokio::time::timeout(FEED_IDLE_TIMEOUT, body.next()).await {
                Err(_) => return Err("admin feed was silent too long".into()),
                Ok(None) => break,
                Ok(Some(chunk)) => chunk.map_err(plain)?,
            };
            // `TextDecoder` with `stream: true`: a character split across chunks waits.
            pending.extend_from_slice(&chunk);
            let valid = match std::str::from_utf8(&pending) {
                Ok(s) => s.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => pending.len(),
            };
            buffer.push_str(&String::from_utf8_lossy(&pending[..valid]));
            pending.drain(..valid);
            let (events, rest) = split_sse(&buffer);
            buffer = if rest.len() > 1_000_000 { String::new() } else { rest };
            for e in events {
                if let Some(r) = map_brain_event(&e) {
                    self.enqueue(r);
                }
            }
        }
        Ok(())
    }

    /// The nightly summary, shipped once: the cursor is when the last shipped run finished.
    pub async fn check_cycle(&self) -> Result<(), String> {
        let Ok(raw) = std::fs::read_to_string(&self.opts.report_path) else {
            return Ok(());
        };
        let Some(r) = read_cycle_report(&raw) else {
            return Ok(());
        };
        let id = r["cycle_id"].as_str().unwrap_or_default().to_string();
        let last = std::fs::read_to_string(&self.opts.cursor_path).unwrap_or_default();
        if last.trim() == id {
            return Ok(());
        }
        if self.post(std::slice::from_ref(&r)).await? {
            cc_store::write_atomic(&self.opts.cursor_path, id.as_bytes(), 0o644, cc_store::TmpName::Suffix)
                .map_err(|e| e.to_string())?;
            self.log(&format!("shipped the nightly run of {id}"));
        }
        Ok(())
    }

    pub async fn flush(&self) -> Result<(), String> {
        loop {
            let (batch, last): (Vec<Value>, u64) = {
                let q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
                let batch: Vec<&(u64, Value)> = q.0.iter().take(BATCH).collect();
                (
                    batch.iter().map(|(_, v)| v.clone()).collect(),
                    batch.last().map_or(0, |(n, _)| *n),
                )
            };
            if batch.is_empty() || !self.post(&batch).await? {
                return Ok(());
            }
            let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
            while q.0.front().is_some_and(|(n, _)| *n <= last) {
                q.0.pop_front();
            }
        }
    }

    async fn post(&self, records: &[Value]) -> Result<bool, String> {
        let token = (self.opts.token)()?;
        let res = (self.opts.console_http)()
            .post(&self.opts.activity_url)
            .timeout(CALL_TIMEOUT)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&json!({"records": records})).unwrap_or_default())
            .send()
            .await
            .map_err(plain)?;
        let status = res.status().as_u16();
        if status == 400 || status == 413 {
            self.log(&format!(
                "batch of {} rejected with HTTP {status}; dropped",
                records.len()
            ));
            return Ok(true);
        }
        if !res.status().is_success() {
            self.log(&format!("ship failed: HTTP {status}"));
            return Ok(false);
        }
        Ok(true)
    }
}
