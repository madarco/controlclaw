//! One restart of OpenClaw at a time. With its Telegram bot on, OpenClaw 2026.10 drains its work for
//! up to 330 s before it stops, longer than any firewall call waits. Each push the firewall sent again
//! (a secret every ~35 s) used to issue another `openclaw gateway restart`, so OpenClaw never finished
//! starting (matrix 2, 2026-10-31).
//!
//! Now a restart asked for while one runs joins it only when OpenClaw's service manager says, at the
//! time of the ask, that OpenClaw is stopping (draining) or stopped. The caller wrote its settings
//! before it asked, so the new process, which starts after that, reads them. Any other ask (OpenClaw
//! up, starting, or a pm2 or plain process whose state only its health shows) runs one more restart
//! when this one is over, however many ask. A restart is watched until OpenClaw is seen down and then
//! up again, or, when its command returned with OpenClaw up and it does not go down within [`GRACE`],
//! until then (the restart happened inside the command). It runs on its own task, so a caller that
//! gives up does not cancel it, and callers wait at most [`ANSWER_WITHIN`] for it. A stop ends the
//! watch and drops a queued restart.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_http::BoxFuture;
use tokio::sync::watch;

use super::supervisor::Failure;

/// How long a caller waits for the restart before it answers that OpenClaw is restarting: under the
/// firewall's 25 s call.
pub const ANSWER_WITHIN: Duration = Duration::from_secs(20);
/// How long a restart counts as in flight at most: systemd's 330 s stop timeout and a start.
pub const IN_FLIGHT_AT_MOST: Duration = Duration::from_secs(390);
/// How long a restart whose command returned with OpenClaw up is watched for it to go down.
pub const GRACE: Duration = Duration::from_secs(10);
const POLL: Duration = Duration::from_secs(1);

/// A restart's outcome, once there is one.
type Outcome = Option<Result<(), String>>;

/// Where OpenClaw is, seen from outside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// Its gateway answers and its manager does not say it is down.
    Up,
    /// Its manager runs it, and its gateway does not answer yet: the new process is starting.
    Starting,
    /// Its manager says it is stopping (draining) or stopped: no new process yet.
    Down,
    /// Its gateway does not answer and no manager says why (pm2, a plain process): it may be
    /// starting already.
    Unknown,
}

/// What a restart does, apart from the gate.
pub trait Restarter: Send + Sync + 'static {
    /// The restart command.
    fn issue(self: Arc<Self>) -> BoxFuture<Result<(), Failure>>;
    /// Where OpenClaw is now.
    fn seen(self: Arc<Self>) -> BoxFuture<Seen>;
}

type Waiters = (watch::Sender<Outcome>, watch::Receiver<Outcome>);

#[derive(Default)]
struct Flight {
    /// The restart running, while it does.
    current: Option<watch::Receiver<Outcome>>,
    /// Which restart that is: bumped at each one.
    id: u64,
    /// The one to run when the current one is over, for those that asked too late to join it.
    next: Option<Waiters>,
    /// Bumped by a stop: the restart watched ends.
    stops: u64,
}

pub struct RestartGate {
    flight: Arc<Mutex<Flight>>,
    poll: Duration,
    grace: Duration,
}

impl Default for RestartGate {
    fn default() -> Self {
        Self {
            flight: Arc::default(),
            poll: POLL,
            grace: GRACE,
        }
    }
}

impl RestartGate {
    /// Restart, or join the restart that runs; wait at most `within` for the outcome. Still running
    /// then: `Ok`, with `on_slow` called (OpenClaw drains its work first and comes back by itself).
    pub async fn restart(&self, r: Arc<dyn Restarter>, within: Duration, on_slow: impl FnOnce()) -> Result<(), String> {
        let mut rx = self.ask(r).await;
        let done = rx.wait_for(Option::is_some);
        match tokio::time::timeout(within, done).await {
            Ok(Ok(outcome)) => outcome.clone().unwrap_or(Ok(())),
            Ok(Err(_)) => Err("The restart stopped before it finished".into()),
            Err(_) => {
                on_slow();
                Ok(())
            }
        }
    }

    /// OpenClaw was stopped on purpose: the restart watched ends, and a queued one does not run.
    pub fn stopped(&self) {
        let mut f = lock(&self.flight);
        f.stops += 1;
        if let Some((tx, _)) = f.next.take() {
            let _ = tx.send(Some(Err(STOPPED.into())));
        }
    }

    async fn ask(&self, r: Arc<dyn Restarter>) -> watch::Receiver<Outcome> {
        loop {
            let running = {
                let mut f = lock(&self.flight);
                match &f.current {
                    Some(rx) => (rx.clone(), f.id),
                    None => return self.start(&mut f, r),
                }
            };
            // Looked at now, after the caller's write: stopping or stopped means the new process
            // starts after it.
            let draining = r.clone().seen().await == Seen::Down;
            let mut f = lock(&self.flight);
            if f.current.is_none() || f.id != running.1 {
                continue;
            }
            if draining {
                return running.0;
            }
            return f.next.get_or_insert_with(|| watch::channel(None)).1.clone();
        }
    }

    fn start(&self, f: &mut Flight, r: Arc<dyn Restarter>) -> watch::Receiver<Outcome> {
        let (tx, rx) = watch::channel(None);
        f.current = Some(rx.clone());
        f.id += 1;
        let finish = Finish {
            flight: self.flight.clone(),
            tx: Some(tx),
        };
        tokio::spawn(run(finish, r, self.poll, self.grace));
        rx
    }
}

const STOPPED: &str = "OpenClaw was stopped";

fn lock(f: &Mutex<Flight>) -> std::sync::MutexGuard<'_, Flight> {
    f.lock().unwrap_or_else(|e| e.into_inner())
}

/// The flight's end, also when its task panics: the gate is never left with a flight nobody runs.
struct Finish {
    flight: Arc<Mutex<Flight>>,
    tx: Option<watch::Sender<Outcome>>,
}

impl Finish {
    /// The outcome to those waiting; the next restart's waiters, when someone asked for one.
    /// The flight is updated before anyone hears, so an ask in between cannot join a finished one.
    fn end(&mut self, outcome: Result<(), String>) -> bool {
        let tx = self.tx.take();
        let mut f = lock(&self.flight);
        let more = match f.next.take() {
            Some((next_tx, next_rx)) => {
                f.current = Some(next_rx);
                f.id += 1;
                self.tx = Some(next_tx);
                true
            }
            None => {
                f.current = None;
                false
            }
        };
        drop(f);
        if let Some(tx) = tx {
            let _ = tx.send(Some(outcome));
        }
        more
    }
}

impl Drop for Finish {
    fn drop(&mut self) {
        if self.tx.is_some() {
            let mut f = lock(&self.flight);
            f.current = None;
            if let Some((tx, _)) = f.next.take() {
                let _ = tx.send(Some(Err("The restart stopped before it finished".into())));
            }
        }
    }
}

/// Run restarts until nobody waits for another.
async fn run(mut finish: Finish, r: Arc<dyn Restarter>, poll: Duration, grace: Duration) {
    loop {
        let outcome = once(&finish.flight, &r, poll, grace).await;
        if !finish.end(outcome) {
            return;
        }
    }
}

/// One restart: the command, then OpenClaw watched until it is back.
async fn once(
    flight: &Arc<Mutex<Flight>>,
    r: &Arc<dyn Restarter>,
    poll: Duration,
    grace: Duration,
) -> Result<(), String> {
    let stops = lock(flight).stops;
    let started = tokio::time::Instant::now();
    // Watched while the command runs too: `openclaw gateway restart` waits for the new process.
    let mut seen_down = false;
    let issued = {
        let mut issue = r.clone().issue();
        loop {
            tokio::select! {
                out = &mut issue => break out,
                () = tokio::time::sleep(poll) => {
                    if matches!(r.clone().seen().await, Seen::Down | Seen::Unknown) {
                        seen_down = true;
                    }
                }
            }
        }
    };
    let returned_ok = match issued {
        Ok(()) => true,
        // Slower than the command's limit: still draining.
        Err(f) if f.timed_out => false,
        Err(f) => return Err(f.message),
    };
    let after_command = tokio::time::Instant::now();
    loop {
        if lock(flight).stops != stops {
            return Err(STOPPED.into());
        }
        match r.clone().seen().await {
            Seen::Down | Seen::Unknown => seen_down = true,
            Seen::Starting => {}
            Seen::Up if seen_down => return Ok(()),
            Seen::Up if returned_ok && after_command.elapsed() >= grace => return Ok(()),
            Seen::Up => {}
        }
        if started.elapsed() >= IN_FLIGHT_AT_MOST {
            return Err("OpenClaw did not come back after the restart".into());
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    /// A restart command that runs until the test lets it end, and an OpenClaw the test moves.
    struct Fake {
        issued: AtomicUsize,
        release: Notify,
        timed_out: bool,
        now: Mutex<Seen>,
    }

    impl Restarter for Fake {
        fn issue(self: Arc<Self>) -> BoxFuture<Result<(), Failure>> {
            self.issued.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                self.release.notified().await;
                if self.timed_out {
                    Err(Failure {
                        message: "timed out".into(),
                        timed_out: true,
                    })
                } else {
                    Ok(())
                }
            })
        }

        fn seen(self: Arc<Self>) -> BoxFuture<Seen> {
            let now = *self.now.lock().expect("lock");
            Box::pin(async move { now })
        }
    }

    fn fake(timed_out: bool) -> (Arc<Fake>, Arc<dyn Restarter>) {
        let f = Arc::new(Fake {
            issued: AtomicUsize::new(0),
            release: Notify::new(),
            timed_out,
            now: Mutex::new(Seen::Up),
        });
        (f.clone(), f)
    }

    fn gate() -> Arc<RestartGate> {
        Arc::new(RestartGate {
            flight: Arc::default(),
            poll: Duration::from_millis(1),
            grace: Duration::from_millis(200),
        })
    }

    fn ask(g: &Arc<RestartGate>, r: &Arc<dyn Restarter>) -> tokio::task::JoinHandle<Result<(), String>> {
        let (g, r) = (g.clone(), r.clone());
        tokio::spawn(async move { g.restart(r, Duration::from_secs(10), || {}).await })
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    fn set(f: &Fake, s: Seen) {
        *f.now.lock().expect("lock") = s;
    }

    fn issued(f: &Fake) -> usize {
        f.issued.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn asks_while_openclaw_drains_join_the_restart() {
        let (g, (f, r)) = (gate(), fake(false));
        let first = ask(&g, &r);
        settle().await;
        // systemd: deactivating. The new process starts after these callers wrote.
        set(&f, Seen::Down);
        let joined: Vec<_> = (0..2).map(|_| ask(&g, &r)).collect();
        settle().await;
        assert_eq!(issued(&f), 1, "one command for three asks");
        set(&f, Seen::Up);
        f.release.notify_one();
        assert_eq!(first.await.expect("first"), Ok(()));
        for j in joined {
            assert_eq!(j.await.expect("joined"), Ok(()));
        }
        settle().await;
        assert_eq!(issued(&f), 1);
        assert!(lock(&g.flight).current.is_none());
    }

    /// Up, starting, or not known (pm2, a plain process): the new process may have read its
    /// settings already, so those asks get one more restart, all of them the same one.
    #[tokio::test]
    async fn asks_when_it_is_not_clearly_draining_run_one_more_restart() {
        for state in [Seen::Up, Seen::Starting, Seen::Unknown] {
            let (g, (f, r)) = (gate(), fake(false));
            let first = ask(&g, &r);
            settle().await;
            set(&f, state);
            let late: Vec<_> = (0..2).map(|_| ask(&g, &r)).collect();
            settle().await;
            assert_eq!(issued(&f), 1, "{state:?}");
            set(&f, Seen::Up);
            f.release.notify_one();
            assert_eq!(first.await.expect("first"), Ok(()));
            settle().await;
            assert_eq!(issued(&f), 2, "{state:?}: one more for both");
            f.release.notify_one();
            for l in late {
                assert_eq!(l.await.expect("late"), Ok(()), "{state:?}");
            }
        }
    }

    #[tokio::test]
    async fn a_caller_answers_before_a_slow_restart_ends() {
        let (g, (f, r)) = (gate(), fake(false));
        let mut slow = false;
        let out = g.restart(r, Duration::from_millis(30), || slow = true).await;
        assert_eq!((out, slow), (Ok(()), true));
        assert_eq!(issued(&f), 1);
        f.release.notify_one();
    }

    #[tokio::test]
    async fn a_timed_out_command_is_watched_until_openclaw_is_back() {
        let (g, (f, r)) = (gate(), fake(true));
        let first = ask(&g, &r);
        settle().await;
        set(&f, Seen::Down);
        f.release.notify_one();
        settle().await;
        let second = ask(&g, &r);
        settle().await;
        assert_eq!(issued(&f), 1, "no second restart while it drains");
        set(&f, Seen::Starting);
        settle().await;
        set(&f, Seen::Up);
        assert_eq!(first.await.expect("first"), Ok(()));
        assert_eq!(second.await.expect("second"), Ok(()));
        assert_eq!(issued(&f), 1);
    }

    #[tokio::test]
    async fn a_command_that_returns_before_the_drain_is_watched_through_it() {
        let (g, (f, r)) = (gate(), fake(false));
        let first = ask(&g, &r);
        settle().await;
        f.release.notify_one();
        set(&f, Seen::Down);
        settle().await;
        let joined = ask(&g, &r);
        settle().await;
        assert_eq!(issued(&f), 1, "joined: it drains");
        set(&f, Seen::Up);
        assert_eq!(first.await.expect("first"), Ok(()));
        assert_eq!(joined.await.expect("joined"), Ok(()));
        assert_eq!(issued(&f), 1);
    }

    #[tokio::test]
    async fn a_stop_ends_the_watch_and_drops_a_queued_restart() {
        let (g, (f, r)) = (gate(), fake(false));
        let first = ask(&g, &r);
        settle().await;
        f.release.notify_one();
        settle().await;
        let queued = ask(&g, &r);
        settle().await;
        set(&f, Seen::Down);
        g.stopped();
        assert_eq!(queued.await.expect("queued"), Err(STOPPED.into()));
        assert_eq!(first.await.expect("first"), Err(STOPPED.into()));
        settle().await;
        assert_eq!(issued(&f), 1, "the queued restart did not run");
        assert!(lock(&g.flight).current.is_none());
    }
}
