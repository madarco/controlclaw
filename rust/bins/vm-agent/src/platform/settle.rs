//! Settings the firewall pushes while an Update runs can land on a half-replaced OpenClaw
//! (`settle.ts`, D16). This waits for the run to finish and the gateway to answer, then retries a
//! failed apply a few times, but only inside an "update window": an ordinary failure is still
//! reported at once. W8's phone setup uses it.

use std::future::Future;
use std::time::Duration;

use serde_json::Value;

use super::time::{date_parse, now_ms};
use super::update::running_phase;

/// A finished run still counts for this long: Ansible's handlers restart OpenClaw after `done`.
pub const UPDATE_WINDOW_MS: i64 = 15 * 60_000;
/// Never wait longer than a stuck run takes to be reported stale (update.rs STALE_MS).
const MAX_WAIT_MS: i64 = 45 * 60_000;
const POLL_MS: i64 = 5_000;
const GATEWAY_MS: i64 = 120_000;
pub const RETRY_DELAY: Duration = Duration::from_secs(60);
pub const RETRY_ATTEMPTS: u32 = 3;

/// What settling reads: the update's status (`update::status`), and optionally whether the gateway
/// answers and whether newer settings replaced these.
pub struct SettleOptions<'a> {
    pub update: &'a (dyn Fn() -> Value + Send + Sync),
    pub gateway_ready: Option<&'a (dyn Fn(Duration) -> cc_http::BoxFuture<bool> + Send + Sync)>,
    pub superseded: Option<&'a (dyn Fn() -> bool + Send + Sync)>,
    /// How to wait; tokio's clock when None (a test passes its own).
    pub sleep: Option<&'a (dyn Fn(Duration) -> cc_http::BoxFuture<()> + Send + Sync)>,
    /// The clock, epoch ms; `now_ms` when None.
    pub now: Option<&'a (dyn Fn() -> i64 + Send + Sync)>,
}

fn clock(o: &SettleOptions<'_>) -> i64 {
    o.now.map_or_else(now_ms, |f| f())
}

async fn pause(o: &SettleOptions<'_>, d: Duration) {
    match o.sleep {
        Some(f) => f(d).await,
        None => tokio::time::sleep(d).await,
    }
}

/// Why an apply around an Update did not go through.
#[derive(Debug, PartialEq)]
pub enum Settled<E> {
    /// Newer settings replaced these (`SupersededError`: "Replaced by newer settings").
    Superseded,
    Failed(E),
}

fn superseded(o: &SettleOptions) -> bool {
    o.superseded.is_some_and(|f| f())
}

/// `updateRunning`.
pub fn update_running(status: &Value) -> bool {
    status["phase"].as_str().is_some_and(running_phase)
}

/// True while a run is going, or finished less than `UPDATE_WINDOW_MS` ago.
pub fn in_update_window(status: &Value, now: i64) -> bool {
    if update_running(status) {
        return true;
    }
    if !matches!(status["phase"].as_str(), Some("done" | "failed")) {
        return false;
    }
    status["at"]
        .as_str()
        .and_then(date_parse)
        .is_some_and(|at| now - at < UPDATE_WINDOW_MS)
}

/// Wait until no run is going, then until the gateway answers. False if a run is still going.
pub async fn wait_until_settled(o: &SettleOptions<'_>, max_wait_ms: i64) -> Result<bool, Settled<()>> {
    let end = clock(o) + max_wait_ms;
    while update_running(&(o.update)()) && clock(o) < end {
        if superseded(o) {
            return Err(Settled::Superseded);
        }
        let wait = POLL_MS.min((end - clock(o)).max(1));
        pause(o, Duration::from_millis(wait as u64)).await;
    }
    if update_running(&(o.update)()) {
        return Ok(false);
    }
    if let Some(ready) = o.gateway_ready {
        let wait = GATEWAY_MS.min((end - clock(o)).max(1_000));
        let _ = ready(Duration::from_millis(wait as u64)).await;
    }
    Ok(true)
}

/// `applyAfterUpdate`: run `apply`; when it fails with a transient error inside an update window,
/// wait for the update to settle and try again, at most `RETRY_ATTEMPTS` more times. A run still
/// going is waited out before the first try.
pub async fn apply_after_update<T, E, F, Fut>(
    mut apply: F,
    o: &SettleOptions<'_>,
    transient: impl Fn(&E) -> bool,
    on_retry: impl Fn(u32),
) -> Result<T, Settled<E>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let settle = |r: Result<bool, Settled<()>>| r.map(|_| ()).map_err(|_| Settled::Superseded);
    if update_running(&(o.update)()) {
        settle(wait_until_settled(o, MAX_WAIT_MS).await)?;
    }
    let mut attempt = 1;
    loop {
        if superseded(o) {
            return Err(Settled::Superseded);
        }
        match apply().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt > RETRY_ATTEMPTS
                    || !transient(&e)
                    || superseded(o)
                    || !in_update_window(&(o.update)(), clock(o))
                {
                    return Err(Settled::Failed(e));
                }
                on_retry(attempt);
                settle(wait_until_settled(o, MAX_WAIT_MS).await)?;
                pause(o, RETRY_DELAY).await;
            }
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn status(phase: &str, ago_ms: i64) -> Value {
        json!({ "phase": phase, "at": super::super::time::iso_ms(now_ms() - ago_ms) })
    }

    #[test]
    fn the_window_is_a_run_or_a_recent_end() {
        assert!(in_update_window(&status("installing", 0), now_ms()));
        assert!(in_update_window(&status("done", 60_000), now_ms()));
        assert!(!in_update_window(&status("done", UPDATE_WINDOW_MS + 1), now_ms()));
        assert!(!in_update_window(&json!({ "phase": "idle" }), now_ms()));
    }

    #[tokio::test]
    async fn a_failure_in_the_window_is_tried_again_and_an_ordinary_one_is_not() {
        let s = Mutex::new(status("done", 0));
        let update = || s.lock().expect("l").clone();
        let nap = |_| Box::pin(async {}) as cc_http::BoxFuture<()>;
        let o = SettleOptions {
            update: &update,
            gateway_ready: None,
            superseded: None,
            sleep: Some(&nap),
            now: None,
        };
        let tries = AtomicU32::new(0);
        let r: Result<u32, Settled<&str>> = apply_after_update(
            || async {
                let n = tries.fetch_add(1, Ordering::SeqCst) + 1;
                if n < 3 { Err("gateway restarting") } else { Ok(n) }
            },
            &o,
            |_| true,
            |_| {},
        )
        .await;
        assert_eq!(r, Ok(3));
        *s.lock().expect("l") = json!({ "phase": "idle" });
        let r: Result<(), Settled<&str>> = apply_after_update(|| async { Err("bad key") }, &o, |_| true, |_| {}).await;
        assert_eq!(r, Err(Settled::Failed("bad key")), "outside a window: at once");
    }

    #[tokio::test]
    async fn newer_settings_stop_the_wait() {
        let update = || status("installing", 0);
        let replaced = || true;
        let nap = |_| Box::pin(async {}) as cc_http::BoxFuture<()>;
        let o = SettleOptions {
            update: &update,
            gateway_ready: None,
            superseded: Some(&replaced),
            sleep: Some(&nap),
            now: None,
        };
        let r: Result<(), Settled<()>> = apply_after_update(|| async { Ok(()) }, &o, |_| true, |_| {}).await;
        assert_eq!(r, Err(Settled::Superseded));
    }
}
