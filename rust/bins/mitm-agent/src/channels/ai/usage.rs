//! Tokens the firewall spends on its own AI calls (apps/saas/docs/features/ai-usage.md): the
//! request checks, AI Log Review, the content rules. Counted here, per hour, model and kind of
//! check, and sent to the console as `llm_usage` records every 5 minutes. A record is the hour's
//! total, so the console replaces its row. Only the calls this firewall makes itself: the agents'
//! model calls it forwards are counted by the agents, never here, so nothing is counted twice.
//! Counts only, no text. Saved to `ai-usage.json` at most every 30 seconds while calls come in, and
//! after each send, so a restart loses at most those seconds of counts and never sends a total
//! smaller than the console already has for an hour.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

const HOUR_MS: i64 = 60 * 60 * 1000;
const KEEP_MS: i64 = 7 * 24 * HOUR_MS;

/// Which check a call was for. The console names them ("AI review of requests", ...).
pub fn purpose_of_channel(channel: &str) -> &'static str {
    match channel {
        "email" => "email",
        "voice" => "meetings",
        "apps" => "apps",
        "web" | "webhook" => "websites",
        _ => "messages",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    hour: i64,
    provider: String,
    model: String,
    purpose: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
struct Counts {
    calls: u64,
    input: u64,
    output: u64,
    dirty: bool,
}

pub struct UsageCounter {
    buckets: Mutex<BTreeMap<Key, Counts>>,
    path: Option<PathBuf>,
    /// When the file was last written (ms), for the 30-second spacing.
    saved_at: Mutex<i64>,
}

const SAVE_EVERY_MS: i64 = 30_000;

impl UsageCounter {
    pub fn new(path: Option<PathBuf>) -> Self {
        let buckets = path.as_ref().map(Self::load).unwrap_or_default();
        Self {
            buckets: Mutex::new(buckets),
            path,
            saved_at: Mutex::new(0),
        }
    }

    fn load(path: &PathBuf) -> BTreeMap<Key, Counts> {
        let Some(Value::Array(rows)) = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
        else {
            return BTreeMap::new();
        };
        let s = |r: &Value, k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let n = |r: &Value, k: &str| r.get(k).and_then(Value::as_u64).unwrap_or(0);
        rows.iter()
            .map(|r| {
                (
                    Key {
                        hour: r.get("hour").and_then(Value::as_i64).unwrap_or(0),
                        provider: s(r, "provider"),
                        model: s(r, "model"),
                        purpose: s(r, "activity"),
                    },
                    Counts {
                        calls: n(r, "calls"),
                        input: n(r, "input"),
                        output: n(r, "output"),
                        dirty: r.get("dirty").and_then(Value::as_bool).unwrap_or(true),
                    },
                )
            })
            .collect()
    }

    fn save(&self, buckets: &BTreeMap<Key, Counts>) {
        let Some(path) = &self.path else { return };
        let rows: Vec<Value> = buckets.iter().map(|(k, c)| json!({ "hour": k.hour, "provider": k.provider, "model": k.model, "activity": k.purpose, "calls": c.calls, "input": c.input, "output": c.output, "dirty": c.dirty })).collect();
        if let Err(e) = cc_store::write_atomic(
            path,
            Value::Array(rows).to_string().as_bytes(),
            0o600,
            cc_store::TmpName::Suffix,
        ) {
            tracing::warn!("[ai] usage not saved: {e}");
        }
    }

    /// One call. `input`/`output` are None when the provider reported no usage: the call still counts.
    pub fn add(&self, now: i64, provider: &str, model: &str, purpose: &str, input: Option<u64>, output: Option<u64>) {
        let k = Key {
            hour: now.div_euclid(HOUR_MS) * HOUR_MS,
            provider: provider.into(),
            model: model.into(),
            purpose: purpose.into(),
        };
        let Ok(mut b) = self.buckets.lock() else { return };
        let c = b.entry(k).or_default();
        c.calls += 1;
        c.input += input.unwrap_or(0);
        c.output += output.unwrap_or(0);
        c.dirty = true;
        let due = self.saved_at.lock().map(|mut at| {
            let due = now - *at >= SAVE_EVERY_MS;
            if due {
                *at = now;
            }
            due
        });
        if due.unwrap_or(false) {
            self.save(&b);
        }
    }

    /// The records that changed since they were last sent.
    pub fn pending(&self) -> Vec<Value> {
        let Ok(b) = self.buckets.lock() else { return Vec::new() };
        b.iter()
            .filter(|(_, c)| c.dirty)
            .map(|(k, c)| json!({ "source": "llm_usage", "hour": k.hour, "provider": k.provider, "api": "", "model": k.model, "activity": k.purpose, "calls": c.calls, "input": c.input, "output": c.output }))
            .collect()
    }

    /// The console took `sent`: clean, unless counted again since. Old hours go; the rest is saved.
    pub fn sent(&self, sent: &[Value], now: i64) {
        let Ok(mut b) = self.buckets.lock() else { return };
        for r in sent {
            let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            let k = Key {
                hour: r.get("hour").and_then(Value::as_i64).unwrap_or(0),
                provider: s("provider"),
                model: s("model"),
                purpose: s("activity"),
            };
            if let Some(c) = b
                .get_mut(&k)
                .filter(|c| Some(c.calls) == r.get("calls").and_then(Value::as_u64))
            {
                c.dirty = false;
            }
        }
        b.retain(|k, c| c.dirty || now - k.hour <= KEEP_MS);
        self.save(&b);
    }

    pub fn persist(&self) {
        if let Ok(b) = self.buckets.lock() {
            self.save(&b);
        }
    }
}

/// Every 5 minutes, what changed goes to the console's activity endpoint.
pub fn start_shipper(
    counter: std::sync::Arc<UsageCounter>,
    console: cc_client::ConsoleClient,
    activity_url: String,
    now: std::sync::Arc<dyn Fn() -> i64 + Send + Sync>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            let records = counter.pending();
            if records.is_empty() {
                continue;
            }
            counter.persist();
            match console
                .post_json(&activity_url, &json!({ "records": records }), Duration::from_secs(30))
                .await
            {
                Ok(a) if (200..300).contains(&a.status) => counter.sent(&records, now()),
                // A console from before the usage sink: kept for later.
                Ok(a) => tracing::info!("[ai] usage not taken (HTTP {})", a.status),
                Err(cc_client::ClientError::Http(e)) => tracing::info!("[ai] usage not sent: {}", e.without_url()),
                Err(e) => tracing::info!("[ai] usage not sent: {e}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_add_up_per_hour_and_check_and_survive_a_restart() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("ai-usage.json");
        let c = UsageCounter::new(Some(path.clone()));
        let now = 1_794_564_900_000;
        c.add(
            now,
            "controlclaw_included",
            "typesafe-ai/jev",
            "requests",
            Some(80),
            Some(2),
        );
        c.add(
            now + 1000,
            "controlclaw_included",
            "typesafe-ai/jev",
            "requests",
            Some(70),
            None,
        );
        c.add(now, "controlclaw_included", "typesafe-ai/jev", "messages", None, None);
        let p = c.pending();
        assert_eq!(p.len(), 2);
        let req = p.iter().find(|r| r["activity"] == "requests").expect("requests");
        assert_eq!(
            (req["calls"].as_u64(), req["input"].as_u64(), req["output"].as_u64()),
            (Some(2), Some(150), Some(2))
        );
        c.sent(&p, now);
        assert!(c.pending().is_empty());
        c.add(
            now + 2000,
            "controlclaw_included",
            "typesafe-ai/jev",
            "requests",
            Some(1),
            Some(1),
        );
        c.persist();
        let back = UsageCounter::new(Some(path));
        let p = back.pending();
        assert_eq!(p.len(), 1);
        assert_eq!(p[0]["calls"], 3, "the hour's total after a restart");
    }

    #[test]
    fn channels_name_the_check() {
        assert_eq!(purpose_of_channel("telegram"), "messages");
        assert_eq!(purpose_of_channel("email"), "email");
        assert_eq!(purpose_of_channel("voice"), "meetings");
        assert_eq!(purpose_of_channel("web"), "websites");
    }
}
