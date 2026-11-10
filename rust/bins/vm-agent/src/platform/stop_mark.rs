//! Whether the last action this agent took on OpenClaw's unit was a stop (`routes/openclaw.ts`,
//! #601): the console's Stop, the emergency stop, or one of its own short stops (a restore, a
//! meeting), which carry an end. The watchdog starts a unit that is down only when this is not set:
//! anything else that stopped it, such as a failed Update or OpenClaw's own doctor, is not what the
//! owner asked for. A file, so a restart of this agent does not forget an owner's Stop; also kept in
//! memory, so a disk too full to write it on does not either.

use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use serde_json::{Value, json};

use super::common::lock;
use super::time::now_ms;

/// How long this agent's own stops of OpenClaw (a restore, a meeting) count as on purpose for the
/// watchdog. Each starts OpenClaw again itself; this is for one that never got to.
pub const OWN_STOP_MS: i64 = 60 * 60_000;

/// `ACTION_TIMEOUT_MS`.
const ACTION_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Clone, Copy, Debug, PartialEq)]
struct Mark {
    at: f64,
    until: Option<f64>,
}

pub struct StopMark {
    path: PathBuf,
    here: Mutex<Option<Mark>>,
}

/// The agent's own: `STATE_DIR/<CC_SERVICE>-stopped`, read from the environment as the TS reads it.
pub static STOP_MARK: LazyLock<StopMark> = LazyLock::new(|| {
    let dir = std::env::var("STATE_DIR").unwrap_or_else(|_| "/opt/controlclaw/state".into());
    let service = std::env::var("CC_SERVICE").unwrap_or_else(|_| "openclaw".into());
    StopMark::new(Path::new(&dir).join(format!("{service}-stopped")))
});

impl StopMark {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            here: Mutex::new(None),
        }
    }

    /// `noteAction`: called before the action, so a stop the watchdog sees half way already reads
    /// as on purpose. A stop sets the mark (with an end when `for_ms` is given); anything else clears it.
    pub fn note(&self, action: &str, for_ms: Option<i64>) {
        let now = now_ms();
        let mark = (action == "stop").then(|| Mark {
            at: now as f64,
            until: for_ms.filter(|ms| *ms != 0).map(|ms| (now + ms) as f64),
        });
        *lock(&self.here) = mark;
        let written = match mark {
            Some(m) => std::fs::write(
                &self.path,
                format!("{}\n", json!({ "at": m.at as i64, "until": m.until.map(|u| u as i64) })),
            ),
            None => match std::fs::remove_file(&self.path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                r => r,
            },
        };
        if let Err(e) = written {
            tracing::error!("[openclaw] could not note the {action}: {e}");
        }
    }

    /// This agent's own short stop ([`OWN_STOP_MS`]); what [`Self::clear_own`] takes.
    pub fn note_own(&self) -> Option<f64> {
        self.note("stop", Some(OWN_STOP_MS));
        self.read().and_then(|m| m.until)
    }

    /// Clear the mark [`Self::note_own`] set, unless another was noted since (a Stop asked for
    /// meanwhile, which must stand). Whether it was cleared.
    pub fn clear_own(&self, own: Option<f64>) -> bool {
        if own.is_some() && self.read().and_then(|m| m.until) == own {
            self.note("start", None);
            return true;
        }
        false
    }

    /// The mark on disk; the one in memory when there is no file. An unreadable file is a stop all the same.
    fn read(&self) -> Option<Mark> {
        let raw = match std::fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return *lock(&self.here),
            Err(_) => return Some(Mark { at: 0.0, until: None }),
        };
        // `Number(parsed.at) || 0`, `typeof parsed.until === "number" ? parsed.until : null`; JSON
        // that is not an object has neither, and `null` throws: both a stop with no end.
        let parsed: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        let number = |v: Option<&Value>| match v {
            Some(Value::Number(n)) => n.as_f64(),
            Some(Value::String(s)) => {
                let s = s.trim();
                if s.is_empty() { Some(0.0) } else { s.parse().ok() }
            }
            Some(Value::Bool(b)) => Some(f64::from(u8::from(*b))),
            _ => None,
        };
        Some(Mark {
            at: number(parsed.get("at")).filter(|n| n.is_finite()).unwrap_or(0.0),
            until: parsed.get("until").and_then(Value::as_f64),
        })
    }

    /// `stoppedOnPurpose`: a stop is noted and has no end, or its end has not come.
    pub fn stopped_on_purpose(&self, now: i64) -> bool {
        self.read().is_some_and(|m| m.until.is_none_or(|u| (now as f64) < u))
    }

    /// `forgetStop`: the unit has been running for `active_for_ms`. A stop noted before that start
    /// no longer says anything; one noted since is a stop still on its way (systemd takes up to its
    /// stop timeout).
    pub fn forget(&self, active_for_ms: f64, now: i64) {
        if self.read().is_some_and(|m| m.at < now as f64 - active_for_ms) {
            self.note("start", None);
        }
    }

    /// `startUnlessStopped`: the watchdog's start. It notes nothing, and a stop noted while it ran
    /// wins: the unit is stopped again, so a Stop pressed at that moment is never undone.
    pub async fn start_unless_stopped(&self, runner: &dyn Runner, service: &str) -> bool {
        if self.stopped_on_purpose(now_ms()) {
            return false;
        }
        let ok = {
            let _one = super::openclaw::UNIT_ACTIONS.lock().await;
            let cmd = Cmd::sudo("systemctl").args(["start", service]).timeout(ACTION_TIMEOUT);
            runner.run(cmd).await.is_ok_and(|o| o.success())
        };
        if self.stopped_on_purpose(now_ms()) {
            let _one = super::openclaw::UNIT_ACTIONS.lock().await;
            let cmd = Cmd::sudo("systemctl").args(["stop", service]).timeout(ACTION_TIMEOUT);
            let _ = runner.run(cmd).await;
            return false;
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_proc::RecordingRunner;

    fn mark() -> (StopMark, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        (StopMark::new(dir.path().join("openclaw-stopped")), dir)
    }

    #[test]
    fn an_own_stop_is_cleared_only_while_it_is_still_the_mark() {
        let (m, _d) = mark();
        let own = m.note_own();
        assert!(m.stopped_on_purpose(now_ms()));
        assert!(m.clear_own(own));
        assert!(!m.stopped_on_purpose(now_ms()));
        // The owner's Stop, noted while the writes ran, stands.
        let own = m.note_own();
        m.note("stop", None);
        assert!(!m.clear_own(own));
        assert!(m.stopped_on_purpose(now_ms() + OWN_STOP_MS + 1));
    }

    #[test]
    fn a_stop_is_noted_a_start_or_restart_clears_it() {
        let (m, _d) = mark();
        assert!(!m.stopped_on_purpose(now_ms()));
        m.note("stop", None);
        assert!(m.stopped_on_purpose(now_ms()));
        let on_disk: Value = serde_json::from_slice(&std::fs::read(&m.path).expect("mark")).expect("json");
        assert!(on_disk["at"].is_i64() && on_disk["until"].is_null());
        m.note("restart", None);
        assert!(!m.stopped_on_purpose(now_ms()));
        assert!(!m.path.exists());
        m.note("stop", None);
        m.note("start", None);
        assert!(!m.stopped_on_purpose(now_ms()));
    }

    #[test]
    fn the_agents_own_stops_end_and_an_unreadable_mark_is_a_stop() {
        let (m, _d) = mark();
        m.note("stop", Some(60_000));
        assert!(m.stopped_on_purpose(now_ms()));
        assert!(!m.stopped_on_purpose(now_ms() + 61_000));
        std::fs::write(&m.path, "2026-10-20T10:00:00.000Z\n").expect("write");
        assert!(m.stopped_on_purpose(now_ms()));
        std::fs::write(&m.path, "null\n").expect("write");
        assert!(m.stopped_on_purpose(now_ms()));
        m.note("start", None);
        assert!(!m.stopped_on_purpose(now_ms()));
    }

    #[test]
    fn a_mark_that_cannot_be_written_is_kept_in_memory() {
        let m = StopMark::new(PathBuf::from("/nonexistent-cc-dir/openclaw-stopped"));
        m.note("stop", None);
        assert!(m.stopped_on_purpose(now_ms()));
        m.note("start", None);
        assert!(!m.stopped_on_purpose(now_ms()));
    }

    #[test]
    fn a_running_unit_forgets_a_stop_noted_before_it_started_not_one_still_on_its_way() {
        let (m, _d) = mark();
        m.note("stop", None);
        // Running for a minute, so started before a stop noted just now: the stop is on its way.
        m.forget(60_000.0, now_ms());
        assert!(m.stopped_on_purpose(now_ms()));
        m.forget(10.0 * 60_000.0, now_ms() + 20 * 60_000);
        assert!(!m.stopped_on_purpose(now_ms()));
    }

    #[tokio::test]
    async fn the_watchdogs_start_notes_nothing_and_a_stop_noted_during_it_wins() {
        let (m, _d) = mark();
        let m = std::sync::Arc::new(m);
        let lines = |r: &RecordingRunner| -> Vec<String> { r.calls().iter().map(|c| c.args.join(" ")).collect() };
        let r = RecordingRunner::new();
        r.answer(&["sudo"], cc_proc::ok(""));
        assert!(m.start_unless_stopped(&r, "openclaw").await);
        assert_eq!(lines(&r), ["-n systemctl start openclaw"]);
        assert!(!m.stopped_on_purpose(now_ms()));

        // The console's Stop lands while the start runs.
        let r = RecordingRunner::new();
        let during = m.clone();
        r.answer_with(move |c| {
            if c.args.iter().any(|a| a == "start") {
                during.note("stop", None);
            }
            Some(cc_proc::ok(""))
        });
        assert!(!m.start_unless_stopped(&r, "openclaw").await);
        assert_eq!(lines(&r), ["-n systemctl start openclaw", "-n systemctl stop openclaw"]);
        assert!(m.stopped_on_purpose(now_ms()));

        // Already stopped on purpose: nothing is run.
        let r = RecordingRunner::new();
        assert!(!m.start_unless_stopped(&r, "openclaw").await);
        assert!(lines(&r).is_empty());
    }
}
