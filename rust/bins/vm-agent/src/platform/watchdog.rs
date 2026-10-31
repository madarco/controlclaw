//! Notices an agent that has stopped working while everything about it looks up, and puts back the
//! part that is stuck (`watchdog.ts`, T-browserhang).
//!
//! - **OpenClaw's gateway**: its `/healthz` is asked every tick; after `GATEWAY_FAILS` misses in a row
//!   OpenClaw is restarted. One that has not answered since its unit started is still starting and is
//!   left alone until `START_LIMIT_MS`.
//! - **The way out**: a TLS handshake with the control plane is tried every tick, the ordinary way.
//!   When it fails while the same handshake through a tunnel opened straight on the firewall's proxy
//!   completes, the redirector is stuck, and after `JAM_FAILS` in a row it is restarted.
//!
//! - **OpenClaw stopped by something else** (#601). A unit that is down is normally left down: the
//!   console's Stop, the emergency stop and the vm-agent's own short stops (a restore, a meeting) are
//!   noted as on purpose (`stop_mark.rs`). A unit that went down any other way (an Update that failed
//!   after stopping it, OpenClaw's own `doctor` that could not start a system unit again, a person on
//!   the box) and has stayed down for `DOWN_LIMIT_MS` is started (T-openclaw-autopatch: agents stopped
//!   by the nightly Update on 2026-10-27 stayed down for days).
//!
//! None of these is made during an Update, and the start is never made on a box that has not
//! finished its first provisioning (a unit not enabled yet). OpenClaw is left alone while a Doctor
//! session is on the box, and the redirector while a meeting or a phone call is running, unless the
//! jam has lasted `JAM_IN_CALL_MS`. Every restart and start is rate-limited.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::common::lock;
use super::health_summary::WatchStatus;

pub const TICK: Duration = Duration::from_secs(30);
/// Misses in a row before OpenClaw is restarted: two minutes.
pub const GATEWAY_FAILS: u32 = 4;
/// Misses in a row before the redirector is restarted: a minute and a half.
pub const JAM_FAILS: u32 = 3;
/// OpenClaw is not judged this soon after its unit became active.
pub const START_GRACE_MS: f64 = 3.0 * 60_000.0;
/// `GATEWAY_START_LIMIT_MS` (budgets.ts): a start that has not answered by now will not.
pub const START_LIMIT_MS: f64 = 15.0 * 60_000.0;
/// Two reads of the unit's start that differ by more than this are two starts.
const SAME_START_MS: f64 = 5_000.0;
/// With a meeting or a call running, the redirector is restarted only after a jam this long.
pub const JAM_IN_CALL_MS: f64 = 5.0 * 60_000.0;
/// OpenClaw down this long, and not on purpose, is started. A failed Update takes seconds to give up.
pub const DOWN_LIMIT_MS: f64 = 5.0 * 60_000.0;
pub const RESTART_QUIET_MS: f64 = 10.0 * 60_000.0;
pub const MAX_RESTARTS: usize = 3;
pub const RESTART_WINDOW_MS: f64 = 60.0 * 60_000.0;

/// One line for the owner's Activity page, and whether the restart worked.
pub type Report = Box<dyn Fn(&str, bool) + Send + Sync>;

/// What the watchdog asks and does; closures so tests can stand in for the box.
pub struct WatchdogDeps {
    /// How long OpenClaw's unit has been `active`, in ms; None when it is anything else.
    pub unit_active_for: Box<dyn Fn() -> cc_http::BoxFuture<Option<f64>> + Send + Sync>,
    pub gateway_answers: Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>,
    /// What the console's Restart does first: ends a meeting in progress.
    pub before_restart: Box<dyn Fn() -> cc_http::BoxFuture<()> + Send + Sync>,
    pub restart_openclaw: Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>,
    /// How long OpenClaw's unit has been `inactive` or `failed`, in ms; None when it is anything else
    /// (running, starting, stopping, or waiting for systemd to start it again after a crash).
    pub unit_down_for: Box<dyn Fn() -> cc_http::BoxFuture<Option<f64>> + Send + Sync>,
    /// The last action the vm-agent took on the unit was a stop: the console's, the kill switch's or its own.
    pub stopped_on_purpose: Box<dyn Fn() -> bool + Send + Sync>,
    /// The unit has been running this long, whoever started it: a stop noted before that no longer counts.
    pub forget_stop: Box<dyn Fn(f64) + Send + Sync>,
    pub start_openclaw: Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>,
    /// A TLS handshake with the control plane the ordinary way; None when not tested.
    pub outbound: Box<dyn Fn() -> cc_http::BoxFuture<Option<bool>> + Send + Sync>,
    /// The same handshake through a tunnel opened on the firewall's proxy directly.
    pub proxy_direct: Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>,
    /// `ok`, `failed`, or `refused` when this agent's role has no sudoers line for it.
    pub restart_redirector: Box<dyn Fn() -> cc_http::BoxFuture<&'static str> + Send + Sync>,
    /// An Update (`update`) or a Doctor session (`doctor`) is running.
    pub hold: Box<dyn Fn() -> cc_http::BoxFuture<Option<&'static str>> + Send + Sync>,
    /// A meeting or a phone call is running.
    pub in_call: Box<dyn Fn() -> cc_http::BoxFuture<bool> + Send + Sync>,
    /// One line for the owner's Activity page.
    pub report: Report,
    /// A monotonic clock in ms, the one systemd counts the unit's start on.
    pub now: Box<dyn Fn() -> f64 + Send + Sync>,
    pub log: Box<dyn Fn(&str) + Send + Sync>,
}

#[derive(Default)]
struct Limiter {
    at: Vec<f64>,
}

impl Limiter {
    fn allow(&mut self, now: f64) -> bool {
        self.at.retain(|t| now - t < RESTART_WINDOW_MS);
        if self.at.len() >= MAX_RESTARTS {
            return false;
        }
        if self.at.last().is_some_and(|l| now - l < RESTART_QUIET_MS) {
            return false;
        }
        self.at.push(now);
        true
    }
}

#[derive(Default)]
struct Gateway {
    fails: u32,
    started_at: Option<f64>,
    answered: bool,
    limit: Limiter,
    start_limit: Limiter,
}

#[derive(Default)]
struct Jam {
    fails: u32,
    since: Option<f64>,
    refused: bool,
    limit: Limiter,
}

pub struct Watchdog {
    d: WatchdogDeps,
    gw: tokio::sync::Mutex<Gateway>,
    jam: tokio::sync::Mutex<Jam>,
    state: Mutex<WatchStatus>,
    busy: AtomicBool,
}

impl Watchdog {
    pub fn new(d: WatchdogDeps) -> Self {
        Self {
            d,
            gw: tokio::sync::Mutex::new(Gateway::default()),
            jam: tokio::sync::Mutex::new(Jam::default()),
            state: Mutex::new(WatchStatus {
                gateway_answers: None,
                outbound: None,
                jammed: false,
            }),
            busy: AtomicBool::new(false),
        }
    }

    pub fn status(&self) -> WatchStatus {
        *lock(&self.state)
    }

    fn log(&self, line: &str) {
        (self.d.log)(&format!("[watchdog] {line}"));
    }

    pub async fn tick(&self) {
        if self.busy.swap(true, Ordering::SeqCst) {
            return;
        }
        tokio::join!(self.check_gateway(), self.check_outbound());
        self.busy.store(false, Ordering::SeqCst);
    }

    /// How long the unit has been active when it is the start being judged.
    async fn same_start(&self, started_at: Option<f64>) -> Option<f64> {
        let active_for = (self.d.unit_active_for)().await?;
        let s = started_at?;
        ((self.d.now)() - active_for - s)
            .abs()
            .le(&SAME_START_MS)
            .then_some(active_for)
    }

    async fn check_gateway(&self) {
        let mut g = self.gw.lock().await;
        let Some(active_for) = (self.d.unit_active_for)().await else {
            // Stopped, or between two starts: nothing to judge.
            g.started_at = None;
            g.answered = false;
            g.fails = 0;
            lock(&self.state).gateway_answers = None;
            self.check_down(&mut g).await;
            return;
        };
        (self.d.forget_stop)(active_for);
        let started_at = (self.d.now)() - active_for;
        if g.started_at.is_none_or(|s| (started_at - s).abs() > SAME_START_MS) {
            g.started_at = Some(started_at);
            g.answered = false;
            g.fails = 0;
        }
        // Asked during the grace too: an answer there is what later tells a hang from a slow start.
        if (self.d.gateway_answers)().await {
            g.answered = true;
            g.fails = 0;
            lock(&self.state).gateway_answers = (active_for >= START_GRACE_MS).then_some(true);
            return;
        }
        let starting = !g.answered && active_for < START_LIMIT_MS;
        if active_for < START_GRACE_MS || starting {
            g.fails = 0;
            lock(&self.state).gateway_answers = None;
            return;
        }
        lock(&self.state).gateway_answers = Some(false);
        g.fails += 1;
        if g.fails < GATEWAY_FAILS {
            return;
        }
        // An Update restarts OpenClaw itself, and a Doctor session is somebody repairing it.
        if (self.d.hold)().await.is_some() {
            return;
        }
        let now = (self.d.now)();
        if !g.limit.allow(now) {
            return;
        }
        g.fails = 0;
        (self.d.before_restart)().await;
        // Read again, last thing: a Stop or the kill switch that landed meanwhile must win.
        let still = self.same_start(g.started_at).await;
        let Some(still) = still.filter(|s| *s >= START_GRACE_MS) else {
            self.log("OpenClaw was stopped or restarted meanwhile: leaving it");
            lock(&self.state).gateway_answers = None;
            return;
        };
        let hung = g.answered;
        self.log(&if hung {
            "OpenClaw is running but has not answered for two minutes: restarting it".to_string()
        } else {
            format!(
                "OpenClaw has not answered since it started {} minutes ago: restarting it",
                (still / 60_000.0).round()
            )
        });
        let ok = (self.d.restart_openclaw)().await;
        if !ok {
            self.log("the restart failed");
        }
        (self.d.report)(
            if hung {
                "OpenClaw stopped answering and was restarted"
            } else {
                "OpenClaw did not finish starting and was restarted"
            },
            ok,
        );
    }

    /// A unit that is down, not on purpose, for `DOWN_LIMIT_MS` is started.
    async fn check_down(&self, g: &mut Gateway) {
        let Some(down_for) = (self.d.unit_down_for)().await else {
            return;
        };
        if down_for < DOWN_LIMIT_MS || (self.d.stopped_on_purpose)() {
            return;
        }
        if (self.d.hold)().await.is_some() {
            return;
        }
        if !g.start_limit.allow((self.d.now)()) {
            return;
        }
        // Read again, last thing: a Start or a Stop that landed while the hold was read wins.
        let still = (self.d.unit_down_for)().await;
        let Some(still) = still.filter(|_| !(self.d.stopped_on_purpose)()) else {
            return;
        };
        self.log(&format!(
            "OpenClaw has been stopped for {} minutes, and not by the console: starting it",
            (still / 60_000.0).round()
        ));
        let ok = (self.d.start_openclaw)().await;
        if !ok {
            self.log("the start failed");
        }
        (self.d.report)("OpenClaw had been stopped and was started again", ok);
    }

    async fn check_outbound(&self) {
        let mut j = self.jam.lock().await;
        let out = (self.d.outbound)().await;
        lock(&self.state).outbound = out;
        let direct = out == Some(false) && (self.d.proxy_direct)().await;
        lock(&self.state).jammed = direct;
        if !direct {
            j.fails = 0;
            j.since = None;
            return;
        }
        let now = (self.d.now)();
        let since = *j.since.get_or_insert(now);
        j.fails += 1;
        if j.fails < JAM_FAILS || j.refused {
            return;
        }
        // An Update's downloads may be what is still getting through.
        if (self.d.hold)().await == Some("update") {
            return;
        }
        if now - since < JAM_IN_CALL_MS && (self.d.in_call)().await {
            return;
        }
        if !j.limit.allow(now) {
            return;
        }
        j.fails = 0;
        self.log("new connections do not leave this box although they do through the firewall's proxy directly: restarting the redirector");
        let result = (self.d.restart_redirector)().await;
        if result == "refused" {
            j.refused = true;
            self.log("this agent may not restart the redirector (its release is older than this watchdog): not trying again until an Update");
            return;
        }
        if result == "failed" {
            self.log("the redirector could not be restarted");
        }
        (self.d.report)("The agent's web access was stuck and was restarted", result == "ok");
    }
}

/// OpenClaw's own liveness route on loopback, over a new connection. Any HTTP answer counts.
pub async fn gateway_healthz(port: u16, timeout: Duration) -> bool {
    let probe = async {
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        s.write_all(format!("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .ok()?;
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.ok()?;
        head.starts_with(b"HTTP/1.").then_some(())
    };
    matches!(tokio::time::timeout(timeout, probe).await, Ok(Some(())))
}

/// The address of `host`, IPv4, or None when its name does not resolve in time.
pub async fn resolve_host(host: &str, timeout: Duration) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Some(host.to_string());
    }
    let found = tokio::time::timeout(timeout, tokio::net::lookup_host((host, 0)))
        .await
        .ok()?
        .ok()?;
    found.into_iter().find(|a| a.is_ipv4()).map(|a| a.ip().to_string())
}

async fn handshake<S>(stream: S, host: &str, trusted: &[u8]) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (Some(tls), Ok(name)) = (
        crate::boxside::setup::tls_trusting(trusted),
        rustls::pki_types::ServerName::try_from(host.to_string()),
    ) else {
        return false;
    };
    tls.connect(name, stream).await.is_ok()
}

/// A TLS handshake with `host` at `ip:port` (443 on a box), made the way everything on this box
/// reaches the internet: redirected into redsocks, then through the firewall's proxy. `trusted` is
/// the extra roots the process trusts (`HttpClient::extra_roots_pem`), the firewall's CA once it is
/// installed: the firewall inspects the box's traffic, so the public roots alone would fail it.
pub async fn tls_reachable(host: &str, ip: &str, port: u16, trusted: &[u8], timeout: Duration) -> bool {
    let probe = async {
        let Ok(s) = tokio::net::TcpStream::connect((ip, port)).await else {
            return false;
        };
        handshake(s, host, trusted).await
    };
    tokio::time::timeout(timeout, probe).await.unwrap_or(false)
}

/// The same handshake through `CONNECT ip:443` on the firewall's proxy itself, around redsocks. The
/// proxy's `200` proves nothing (it answers before connecting); only the handshake does.
pub async fn proxy_tunnel_reachable(
    proxy_ip: &str,
    proxy_port: u16,
    host: &str,
    ip: &str,
    trusted: &[u8],
    timeout: Duration,
) -> bool {
    let probe = async {
        let Ok(mut s) = tokio::net::TcpStream::connect((proxy_ip, proxy_port)).await else {
            return false;
        };
        if s.write_all(format!("CONNECT {ip}:443 HTTP/1.1\r\nHost: {ip}:443\r\n\r\n").as_bytes())
            .await
            .is_err()
        {
            return false;
        }
        // The head, a byte at a time: nothing past it may be eaten, the TLS answer follows.
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 || s.read_exact(&mut b).await.is_err() {
                return false;
            }
            head.push(b[0]);
        }
        let ok = head.starts_with(b"HTTP/1.0 200") || head.starts_with(b"HTTP/1.1 200");
        let word_end = head.get(12).is_none_or(|c| !c.is_ascii_alphanumeric());
        ok && word_end && handshake(s, host, trusted).await
    };
    tokio::time::timeout(timeout, probe).await.unwrap_or(false)
}

/// A monotonic clock in ms, the one systemd's `ActiveEnterTimestampMonotonic` counts on.
pub fn monotonic_ms() -> f64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    t.tv_sec as f64 * 1000.0 + t.tv_nsec as f64 / 1e6
}

static OWN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// `reportOwnAction`: one line on the Activity page for something this agent's own service did, not
/// OpenClaw (a restart the watchdog made, a file the console wrote).
pub async fn report_own_action(
    app: &crate::app::App,
    tag: &str,
    action: &str,
    line: &str,
    agent_id: &str,
    ok: bool,
) -> Result<(), String> {
    let Some(base) = super::gateway::saas_base_url(app) else {
        return Ok(());
    };
    let id = uuid::Uuid::new_v4();
    let token = cc_auth::sign::box_token(&app.keys).map_err(|e| e.to_string())?;
    let body = json!({ "records": [{
        "source": "tool_action",
        "event_id": format!("{tag}-{id}"),
        "sequence": OWN_SEQUENCE.fetch_add(1, Ordering::SeqCst) + 1,
        "occurred_at": super::time::now_ms(),
        "status": if ok { "succeeded" } else { "failed" },
        "action": action,
        "tool_name": super::common::js_slice(line, 120),
        "tool_call_id": format!("{tag}:{id}"),
        "agent_id": agent_id,
    }] });
    let res = app
        .http
        .get()
        .post(format!("{base}/api/vm-agent/activity"))
        .bearer_auth(token)
        .header("content-type", "application/json")
        .body(body.to_string())
        .timeout(super::metrics::SHIP_TIMEOUT)
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?;
    if !res.status().is_success() {
        tracing::error!("[{tag}] activity report: HTTP {}", res.status().as_u16());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    struct Box_ {
        active_for: Arc<Mutex<Option<f64>>>,
        answers: Arc<AtomicBool>,
        out: Arc<Mutex<Option<bool>>>,
        direct: Arc<AtomicBool>,
        now: Arc<Mutex<f64>>,
        in_call: Arc<AtomicBool>,
        restarts: Arc<AtomicUsize>,
        redirector: Arc<AtomicUsize>,
        reports: Arc<Mutex<Vec<(String, bool)>>>,
        /// When the unit went down; only read while `active_for` is None.
        down_since: Arc<Mutex<f64>>,
        /// The vm-agent's own stop: on by default, the way every older test stopped the unit.
        on_purpose: Arc<AtomicBool>,
        start_ok: Arc<AtomicBool>,
        starts: Arc<AtomicUsize>,
        hold: Arc<Mutex<Option<&'static str>>>,
    }

    fn rig() -> (Watchdog, Box_) {
        let b = Box_ {
            active_for: Arc::new(Mutex::new(Some(10.0 * 60_000.0))),
            answers: Arc::new(AtomicBool::new(true)),
            out: Arc::new(Mutex::new(Some(true))),
            direct: Arc::new(AtomicBool::new(false)),
            now: Arc::new(Mutex::new(1_000_000_000.0)),
            in_call: Arc::new(AtomicBool::new(false)),
            restarts: Arc::new(AtomicUsize::new(0)),
            redirector: Arc::new(AtomicUsize::new(0)),
            reports: Arc::new(Mutex::new(Vec::new())),
            down_since: Arc::new(Mutex::new(1_000_000_000.0 - 60.0 * 60_000.0)),
            on_purpose: Arc::new(AtomicBool::new(true)),
            start_ok: Arc::new(AtomicBool::new(true)),
            starts: Arc::new(AtomicUsize::new(0)),
            hold: Arc::new(Mutex::new(None)),
        };
        let (af, an, out, dir, now, call, rs, rd, rep) = (
            b.active_for.clone(),
            b.answers.clone(),
            b.out.clone(),
            b.direct.clone(),
            b.now.clone(),
            b.in_call.clone(),
            b.restarts.clone(),
            b.redirector.clone(),
            b.reports.clone(),
        );
        let now2 = now.clone();
        let af2 = af.clone();
        let (af3, af4, now3) = (af.clone(), af.clone(), now.clone());
        let (ds, op1, op2, ok, st, hold) = (
            b.down_since.clone(),
            b.on_purpose.clone(),
            b.on_purpose.clone(),
            b.start_ok.clone(),
            b.starts.clone(),
            b.hold.clone(),
        );
        let w = Watchdog::new(WatchdogDeps {
            unit_active_for: Box::new(move || {
                let v = *lock(&af2);
                Box::pin(async move { v })
            }),
            gateway_answers: Box::new(move || {
                let v = an.load(Ordering::SeqCst);
                Box::pin(async move { v })
            }),
            before_restart: Box::new(|| Box::pin(async {})),
            restart_openclaw: Box::new(move || {
                rs.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { true })
            }),
            unit_down_for: Box::new(move || {
                let v = lock(&af3).is_none().then(|| *lock(&now3) - *lock(&ds));
                Box::pin(async move { v })
            }),
            stopped_on_purpose: Box::new(move || op1.load(Ordering::SeqCst)),
            forget_stop: Box::new(move |_| op2.store(false, Ordering::SeqCst)),
            start_openclaw: Box::new(move || {
                st.fetch_add(1, Ordering::SeqCst);
                let ok = ok.load(Ordering::SeqCst);
                if ok {
                    *lock(&af4) = Some(0.0);
                }
                Box::pin(async move { ok })
            }),
            outbound: Box::new(move || {
                let v = *lock(&out);
                Box::pin(async move { v })
            }),
            proxy_direct: Box::new(move || {
                let v = dir.load(Ordering::SeqCst);
                Box::pin(async move { v })
            }),
            restart_redirector: Box::new(move || {
                rd.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { "ok" })
            }),
            hold: Box::new(move || {
                let v = *lock(&hold);
                Box::pin(async move { v })
            }),
            in_call: Box::new(move || {
                let v = call.load(Ordering::SeqCst);
                Box::pin(async move { v })
            }),
            report: Box::new(move |w, ok| lock(&rep).push((w.to_string(), ok))),
            now: Box::new(move || *lock(&now2)),
            log: Box::new(|_| {}),
        });
        let _ = af;
        (w, b)
    }

    fn advance(b: &Box_, ms: f64) {
        *lock(&b.now) += ms;
        if let Some(a) = lock(&b.active_for).as_mut() {
            *a += ms;
        }
    }

    #[tokio::test]
    async fn a_gateway_that_answered_then_stopped_is_restarted_after_four_misses() {
        let (w, b) = rig();
        w.tick().await;
        assert_eq!(w.status().gateway_answers, Some(true));
        b.answers.store(false, Ordering::SeqCst);
        for _ in 0..3 {
            advance(&b, 30_000.0);
            w.tick().await;
        }
        assert_eq!(b.restarts.load(Ordering::SeqCst), 0);
        advance(&b, 30_000.0);
        w.tick().await;
        assert_eq!(b.restarts.load(Ordering::SeqCst), 1);
        assert_eq!(lock(&b.reports)[0].0, "OpenClaw stopped answering and was restarted");
        // Left alone for ten minutes after a restart.
        for _ in 0..4 {
            advance(&b, 30_000.0);
            w.tick().await;
        }
        assert_eq!(b.restarts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_start_that_never_answered_is_left_alone_until_the_limit() {
        let (w, b) = rig();
        *lock(&b.active_for) = Some(4.0 * 60_000.0);
        b.answers.store(false, Ordering::SeqCst);
        for _ in 0..8 {
            w.tick().await;
            advance(&b, 30_000.0);
        }
        assert_eq!(b.restarts.load(Ordering::SeqCst), 0);
        assert_eq!(w.status().gateway_answers, None);
        advance(&b, 8.0 * 60_000.0);
        for _ in 0..4 {
            w.tick().await;
            advance(&b, 30_000.0);
        }
        assert_eq!(b.restarts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_stopped_unit_is_never_started() {
        let (w, b) = rig();
        *lock(&b.active_for) = None;
        b.answers.store(false, Ordering::SeqCst);
        for _ in 0..10 {
            w.tick().await;
        }
        assert_eq!(b.restarts.load(Ordering::SeqCst), 0);
        // Stopped on purpose an hour ago: never started either.
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
    }

    /// The unit goes down now, and not through the vm-agent.
    fn stopped_elsewhere(b: &Box_) {
        *lock(&b.active_for) = None;
        *lock(&b.down_since) = *lock(&b.now);
        b.on_purpose.store(false, Ordering::SeqCst);
    }

    async fn ticks(w: &Watchdog, b: &Box_, n: usize) {
        for _ in 0..n {
            advance(b, 30_000.0);
            w.tick().await;
        }
    }

    const PER_TICK: f64 = 30_000.0;

    #[tokio::test]
    async fn openclaw_stopped_by_something_else_is_started_after_five_minutes_not_during_an_update_or_doctor() {
        let (w, b) = rig();
        stopped_elsewhere(&b);
        *lock(&b.hold) = Some("update");
        ticks(&w, &b, (DOWN_LIMIT_MS / PER_TICK) as usize + 2).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
        *lock(&b.hold) = Some("doctor");
        ticks(&w, &b, 2).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
        *lock(&b.hold) = None;
        ticks(&w, &b, 1).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *lock(&b.reports),
            [("OpenClaw had been stopped and was started again".to_string(), true)]
        );
        assert_eq!(w.status().gateway_answers, None);
    }

    #[tokio::test]
    async fn a_short_stop_is_waited_out_a_failed_start_is_tried_again_only_after_the_quiet_time() {
        let (w, b) = rig();
        stopped_elsewhere(&b);
        ticks(&w, &b, (DOWN_LIMIT_MS / PER_TICK) as usize - 1).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 0);
        b.start_ok.store(false, Ordering::SeqCst);
        ticks(&w, &b, 2).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *lock(&b.reports),
            [("OpenClaw had been stopped and was started again".to_string(), false)]
        );
        ticks(&w, &b, (RESTART_QUIET_MS / PER_TICK) as usize - 2).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 1);
        ticks(&w, &b, 3).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 2);
        // Never more than the hourly cap: the first start was 10.5 minutes ago.
        ticks(&w, &b, ((RESTART_WINDOW_MS - RESTART_QUIET_MS) / PER_TICK) as usize - 5).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 3);
        // No restart of a running unit was counted.
        assert_eq!(b.restarts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn once_openclaw_runs_again_an_old_stop_no_longer_keeps_it_down() {
        let (w, b) = rig();
        // The owner's Stop, then an Update that started it anyway.
        w.tick().await;
        assert!(!b.on_purpose.load(Ordering::SeqCst));
        // Then something else stops it.
        *lock(&b.active_for) = None;
        *lock(&b.down_since) = *lock(&b.now);
        ticks(&w, &b, (DOWN_LIMIT_MS / PER_TICK) as usize + 1).await;
        assert_eq!(b.starts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_redirector_is_restarted_only_when_the_proxy_answers_directly() {
        let (w, b) = rig();
        *lock(&b.out) = Some(false);
        for _ in 0..5 {
            w.tick().await;
        }
        assert_eq!(
            b.redirector.load(Ordering::SeqCst),
            0,
            "the internet is down: not the redirector's fault"
        );
        b.direct.store(true, Ordering::SeqCst);
        b.in_call.store(true, Ordering::SeqCst);
        for _ in 0..3 {
            w.tick().await;
            advance(&b, 30_000.0);
        }
        assert!(w.status().jammed);
        assert_eq!(b.redirector.load(Ordering::SeqCst), 0, "a call is running");
        advance(&b, 5.0 * 60_000.0);
        w.tick().await;
        assert_eq!(
            b.redirector.load(Ordering::SeqCst),
            1,
            "the jam outlasted the call's grace"
        );
    }
}
