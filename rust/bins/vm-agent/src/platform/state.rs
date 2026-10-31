//! What the console should call OpenClaw (`openclaw-state.ts`, T-107), from the unit, the
//! automatic restarts systemd logged lately, and whether this agent's gateway socket is connected.

use std::time::Duration;

use cc_proc::{Cmd, Runner};

pub const CRASH_WINDOW_S: u64 = 120;
/// Automatic restarts inside the window that make it a loop rather than a restart or two.
pub const CRASH_RESTARTS: usize = 4;
const EXEC_TIMEOUT: Duration = Duration::from_secs(5);

/// `openClawState`. `gateway` is None when there is no socket to ask.
pub fn open_claw_state(unit: &str, recent_restarts: usize, gateway: Option<bool>) -> &'static str {
    if unit == "active" && gateway != Some(false) {
        return "running";
    }
    if recent_restarts >= CRASH_RESTARTS {
        return "crashing";
    }
    if unit == "failed" {
        return "failed";
    }
    if unit == "active" {
        return "starting";
    }
    if matches!(unit, "activating" | "deactivating" | "reloading") {
        return "restarting";
    }
    if gateway == Some(true) {
        return "running";
    }
    if unit == "inactive" {
        return "stopped";
    }
    "unknown"
}

/// `runIsActive`: the unit's word, also when `systemctl` exits non-zero; `unknown` without output.
pub async fn is_active(runner: &dyn Runner, service: &str) -> String {
    match runner
        .run(Cmd::new("systemctl").args(["is-active", service]).timeout(EXEC_TIMEOUT))
        .await
    {
        // Exited 0: its word, trimmed. Non-zero (inactive, failed) still prints it; with nothing
        // printed at all it is unknown.
        Ok(out) if out.success() || !out.stdout.is_empty() => out.stdout_str().trim().to_string(),
        _ => "unknown".to_string(),
    }
}

/// `recentAutoRestarts`: "Scheduled restart job" lines in the unit's journal over the window.
pub async fn recent_auto_restarts(runner: &dyn Runner, service: &str) -> usize {
    let since = format!("-{CRASH_WINDOW_S}s");
    let cmd = Cmd::sudo("journalctl")
        .args(["-u", service, "--since", &since, "--no-pager", "-o", "cat"])
        .timeout(EXEC_TIMEOUT);
    match runner.run(cmd).await {
        Ok(out) if out.success() => out
            .stdout_str()
            .split('\n')
            .filter(|l| l.contains("Scheduled restart job"))
            .count(),
        _ => 0,
    }
}

/// `runState`: the journal is read only when OpenClaw is not plainly running.
pub async fn run_state(runner: &dyn Runner, service: &str, unit: &str, connected: Option<bool>) -> &'static str {
    let restarts = if unit == "active" && connected != Some(false) {
        0
    } else {
        recent_auto_restarts(runner, service).await
    };
    open_claw_state(unit, restarts, connected)
}

/// `currentOpenClawStateAsync`, for the health summary and the metric sampler (G6).
#[allow(dead_code)]
pub async fn current(runner: &dyn Runner, service: &str, connected: Option<bool>) -> &'static str {
    let unit = is_active(runner, service).await;
    run_state(runner, service, &unit, connected).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_only_once_the_gateway_answered() {
        assert_eq!(open_claw_state("active", 0, Some(true)), "running");
        assert_eq!(open_claw_state("active", 0, Some(false)), "starting");
        assert_eq!(open_claw_state("active", 0, None), "running");
        assert_eq!(open_claw_state("inactive", 0, None), "stopped");
    }

    #[test]
    fn restarting_crashing_stopped_failed_unknown() {
        assert_eq!(open_claw_state("activating", 1, Some(false)), "restarting");
        assert_eq!(open_claw_state("deactivating", 0, Some(true)), "restarting");
        assert_eq!(open_claw_state("active", 1, Some(false)), "starting");
        assert_eq!(open_claw_state("activating", CRASH_RESTARTS, Some(false)), "crashing");
        assert_eq!(open_claw_state("active", CRASH_RESTARTS + 5, Some(false)), "crashing");
        assert_eq!(open_claw_state("active", CRASH_RESTARTS + 5, Some(true)), "running");
        assert_eq!(open_claw_state("inactive", 0, Some(false)), "stopped");
        assert_eq!(open_claw_state("failed", 0, Some(false)), "failed");
        assert_eq!(open_claw_state("unknown", 0, None), "unknown");
        assert_eq!(open_claw_state("unknown", 0, Some(false)), "unknown");
        assert_eq!(open_claw_state("", 0, None), "unknown");
    }

    #[test]
    fn a_gateway_that_answered_is_running_whatever_the_unit_says() {
        assert_eq!(open_claw_state("inactive", 0, Some(true)), "running");
        assert_eq!(open_claw_state("unknown", 0, Some(true)), "running");
        assert_eq!(open_claw_state("deactivating", 0, Some(true)), "restarting");
        assert_eq!(open_claw_state("failed", 0, Some(true)), "failed");
    }
}
