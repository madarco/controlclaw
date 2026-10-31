//! How OpenClaw's answers to a config write read. Copied from gateway.ts with the same patterns,
//! because the write queue (W6) branches on them and they are matched against OpenClaw's own text.

use std::sync::LazyLock;

use regex::Regex;

fn re(pattern: &str) -> Regex {
    // The patterns are constants; a typo is a bug caught by the tests below.
    #[allow(clippy::unwrap_used)]
    Regex::new(pattern).unwrap()
}

static PENDING_RESTART: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)persisted and (updated the active Gateway, but a recovery restart is required|was accepted for restart)")
});
static SUPERSEDED: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)persisted but was not applied to the active Gateway \(superseded\)"));
static STALE_BASE_HASH: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)config changed since last load"));
static RESTART_WINDOW: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)unavailable during gateway restart|gateway not connected|gateway disconnected|ECONNREFUSED")
});

/// Saved, but applied only once a restart the gateway already had coming is done (2026.9.7).
pub fn is_persisted_pending_restart(message: &str) -> bool {
    PENDING_RESTART.is_match(message)
}

/// Saved, but its apply was taken over by a newer write (T-180).
pub fn is_persisted_superseded(message: &str) -> bool {
    SUPERSEDED.is_match(message)
}

/// The base hash the write named is no longer the file's.
pub fn is_stale_base_hash(message: &str) -> bool {
    STALE_BASE_HASH.is_match(message)
}

/// The write never reached a gateway that could take it.
pub fn is_restart_window(message: &str) -> bool {
    RESTART_WINDOW.is_match(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_openclaw_answers() {
        assert!(is_persisted_pending_restart(
            "Config persisted and updated the active Gateway, but a recovery restart is required"
        ));
        assert!(is_persisted_pending_restart(
            "config PERSISTED and was accepted for restart"
        ));
        assert!(is_persisted_superseded(
            "Config persisted but was not applied to the active Gateway (superseded)"
        ));
        assert!(is_stale_base_hash("Config changed since last load; reload and retry"));
        // The client's own texts count as the restart window, as in the TS.
        assert!(is_restart_window("gateway not connected"));
        assert!(is_restart_window("gateway disconnected"));
        assert!(is_restart_window("connect ECONNREFUSED 127.0.0.1:18789"));
        assert!(!is_restart_window("gateway call config.get timed out"));
    }
}
