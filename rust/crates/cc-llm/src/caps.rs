use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Calls per UTC day, per allowance (`review`, and the content rules' own), as `AiClient.take`.
/// Kept in memory only: a restart starts the day again, as the TS does.
#[derive(Debug, Default)]
pub struct DailyAllowance {
    inner: Mutex<(String, HashMap<String, u64>)>,
}

impl DailyAllowance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one call from each allowance. False, taking none, when any is used up.
    pub fn take(&self, caps: &[(&str, u64)]) -> bool {
        self.take_at(caps, SystemTime::now())
    }

    pub fn take_at(&self, caps: &[(&str, u64)], now: SystemTime) -> bool {
        let day = utc_day(now);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 != day {
            g.0 = day;
            g.1.clear();
        }
        if caps.iter().any(|(k, cap)| g.1.get(*k).copied().unwrap_or(0) >= *cap) {
            return false;
        }
        for (k, _) in caps {
            *g.1.entry((*k).to_string()).or_insert(0) += 1;
        }
        true
    }

    /// `(day, calls)` for one allowance; the day is "" before the first call, as in the TS.
    pub fn usage(&self, key: &str) -> (String, u64) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (g.0.clone(), g.1.get(key).copied().unwrap_or(0))
    }
}

/// `new Date(now).toISOString().slice(0, 10)`.
fn utc_day(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn utc_days() {
        assert_eq!(utc_day(UNIX_EPOCH), "1970-01-01");
        assert_eq!(utc_day(UNIX_EPOCH + Duration::from_secs(1_793_145_599)), "2026-10-27");
        assert_eq!(utc_day(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29");
    }

    #[test]
    fn takes_from_every_allowance_or_none() {
        let a = DailyAllowance::new();
        let t = UNIX_EPOCH + Duration::from_secs(1_793_145_599);
        assert!(a.take_at(&[("review", 2)], t));
        assert!(a.take_at(&[("review", 2), ("rules:x", 5)], t));
        // review is used up: rules:x is not charged either.
        assert!(!a.take_at(&[("review", 2), ("rules:x", 5)], t));
        assert_eq!(a.usage("rules:x"), ("2026-10-27".into(), 1));
        // A new UTC day starts over.
        assert!(a.take_at(&[("review", 2)], t + Duration::from_secs(1)));
        assert_eq!(a.usage("review"), ("2026-10-28".into(), 1));
    }
}
