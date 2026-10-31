//! How long activity is kept, as in the SaaS: raw rows 30 days, the hourly rollup 13 months. Run
//! once an hour; also drops expired sessions and permission requests that expired unanswered.

use crate::db::{Db, now_s};

pub const RAW_DAYS: i64 = 30;
/// 13 months, counted as 13 × 31 days so a month boundary never cuts one short.
pub const ROLLUP_DAYS: i64 = 13 * 31;

/// What one pass removed: (raw rows, rollup rows).
pub fn prune(db: &Db, now: i64) -> rusqlite::Result<(usize, usize)> {
    let c = db.lock();
    let raw = c.execute(
        "DELETE FROM activity_raw WHERE occurred_at < ?1",
        [now - RAW_DAYS * 86_400],
    )?;
    let hourly = c.execute(
        "DELETE FROM activity_hourly WHERE hour < ?1",
        [now - ROLLUP_DAYS * 86_400],
    )?;
    c.execute("DELETE FROM sessions WHERE expires_at < ?1", [now])?;
    c.execute(
        "UPDATE permission_requests SET status = 'expired', updated_at = ?1
         WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < ?1",
        [now],
    )?;
    Ok((raw, hourly))
}

/// Every hour, for as long as the firewall runs.
pub fn spawn(db: std::sync::Arc<Db>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            tick.tick().await;
            match prune(&db, now_s()) {
                Ok((0, 0)) => {}
                Ok((raw, hourly)) => tracing::info!("[cc-local] retention removed {raw} raw and {hourly} hourly rows"),
                Err(e) => tracing::error!("[cc-local] retention: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_30_days_raw_and_13_months_of_rollup() {
        let db = Db::memory().expect("db");
        let now = 2_000_000_000;
        {
            let c = db.lock();
            for (age_days, key) in [(29, "new"), (31, "old")] {
                c.execute(
                    "INSERT INTO activity_raw (source, status, dedupe_key, occurred_at, summary, record, created_at)
                     VALUES ('egress', 'allow', ?1, ?2, '', '{}', 0)",
                    rusqlite::params![key, now - age_days * 86_400],
                )
                .expect("raw");
            }
            for age_days in [300, 500] {
                c.execute(
                    "INSERT INTO activity_hourly (hour, vm_id, source, status, count) VALUES (?1, '', 'egress', 'allow', 1)",
                    [now - age_days * 86_400],
                )
                .expect("hourly");
            }
        }
        assert_eq!(prune(&db, now).expect("prune"), (1, 1));
        let left: String = db
            .lock()
            .query_row("SELECT dedupe_key FROM activity_raw", [], |r| r.get(0))
            .expect("one");
        assert_eq!(left, "new");
    }
}
