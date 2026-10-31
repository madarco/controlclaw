//! Which of this box's encrypted stores it could not read (T-53), port of
//! `packages/mitm-agent/src/store-health.ts`.
//!
//! "Started empty" and "holds nothing" look the same from outside the box, so an unreadable store
//! is recorded here and the heartbeat carries it. Process-wide, because several modules and the
//! beat have to agree on it. It holds a store's name and the decrypt error, never its contents.

use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnreadableStore {
    /// The store's short name, the one the console shows: `channels`, `llm`, `google`, ...
    pub store: String,
    pub error: String,
    /// When this box last tried and failed, ISO 8601 with milliseconds, like `Date.toISOString`.
    pub at: String,
}

static UNREADABLE: Mutex<BTreeMap<String, UnreadableStore>> = Mutex::new(BTreeMap::new());

fn registry() -> MutexGuard<'static, BTreeMap<String, UnreadableStore>> {
    UNREADABLE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Record a store this box could not decrypt. Called by `load_store_or_empty`.
pub fn note_store_unreadable(store: &str, error: &str) {
    let entry = UnreadableStore {
        store: store.into(),
        error: error.into(),
        at: iso_now(),
    };
    registry().insert(store.into(), entry);
}

/// Record a store this box read, clearing an earlier failure without waiting for a restart.
pub fn note_store_readable(store: &str) {
    registry().remove(store);
}

pub fn is_store_unreadable(store: &str) -> bool {
    registry().contains_key(store)
}

/// What the heartbeat carries, sorted by name. The TS sorts with `localeCompare`; store names are
/// lower-case ASCII, where the two orders agree.
pub fn unreadable_stores() -> Vec<UnreadableStore> {
    registry().values().cloned().collect()
}

/// Tests only.
pub fn reset_store_health() {
    registry().clear();
}

/// Now as `new Date().toISOString()` gives it: `2026-10-28T12:34:56.789Z`.
pub fn iso_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso_from_millis(now.as_millis() as i64)
}

pub fn iso_from_millis(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn iso_matches_to_iso_string() {
        assert_eq!(iso_from_millis(0), "1970-01-01T00:00:00.000Z");
        // new Date(1793190896789).toISOString()
        assert_eq!(iso_from_millis(1_793_190_896_789), "2026-10-28T12:34:56.789Z");
        assert_eq!(iso_from_millis(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn unreadable_then_readable_clears() {
        note_store_unreadable("zz-test", "boom");
        assert!(is_store_unreadable("zz-test"));
        assert!(
            unreadable_stores()
                .iter()
                .any(|s| s.store == "zz-test" && s.error == "boom")
        );
        note_store_readable("zz-test");
        assert!(!is_store_unreadable("zz-test"));
    }
}
