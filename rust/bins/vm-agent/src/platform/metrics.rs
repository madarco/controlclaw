//! CPU, memory and disk history for the CPU and Memory cards on the agent's Home tab
//! (`metrics.ts`). Once a minute the box takes one sample of what `/health/summary` reports and posts
//! it to the activity route as a `metric` record, with the box's own token.
//!
//! The queue is in memory only and holds a day: while the control plane cannot be reached the samples
//! wait and go with the next post that works. OpenClaw's error text never leaves the box: it is
//! reduced to a code here (`channel_reason`).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{js_number, lock};
use super::cpu::CpuSampler;
use super::time::now_ms;

pub const METRIC_SAMPLE: Duration = Duration::from_secs(60);
/// A day of samples. Past that the oldest go first.
pub const METRIC_QUEUE_MAX: usize = 24 * 60;
/// The ingest route takes at most 500 records a batch.
const BATCH: usize = 500;
/// `SHIP_TIMEOUT_MS` (audit.ts).
pub const SHIP_TIMEOUT: Duration = Duration::from_secs(20);

static LOGGED_OUT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"logged ?out|log ?out|unlinked|session (?:closed|ended|replaced)").expect("regex"));
static AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b401\b|\b403\b|unauthori[sz]ed|invalid_auth|not_authed|token_revoked|account_inactive|invalid token|token.*(?:revoked|invalid|expired)|forbidden")
        .expect("regex")
});
static NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"enotfound|econn|etimedout|eai_again|network|socket|fetch failed|timed? ?out").expect("regex")
});

/// OpenClaw's error text for a channel, as one of four codes. The text itself stays on the box.
pub fn channel_reason(last_error: Option<&str>) -> Option<&'static str> {
    let e = last_error.filter(|e| !e.trim().is_empty())?.to_lowercase();
    Some(if LOGGED_OUT.is_match(&e) {
        "logged_out"
    } else if AUTH.is_match(&e) {
        "auth"
    } else if NETWORK.is_match(&e) {
        "network"
    } else {
        "other"
    })
}

/// Which channels have connected at least once, kept in a small state file so a restart does not
/// forget it. A channel no longer configured, or no longer listed, is forgotten.
pub struct ChannelsSeen {
    path: Option<PathBuf>,
    seen: Mutex<BTreeSet<String>>,
}

pub struct ChannelNow {
    pub kind: String,
    pub configured: bool,
    pub running: bool,
    pub connected: bool,
    pub last_error: Option<String>,
}

impl ChannelsSeen {
    pub fn new(path: Option<PathBuf>) -> Self {
        let seen = path
            .as_ref()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v.as_array().cloned())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        Self {
            path,
            seen: Mutex::new(seen),
        }
    }

    /// Updates from one reading and says, per type, whether it has been seen.
    pub fn note(&self, channels: &[ChannelNow]) -> HashMap<String, bool> {
        let mut seen = lock(&self.seen);
        let before = seen.clone();
        seen.retain(|t| channels.iter().any(|c| &c.kind == t));
        for c in channels {
            if !c.configured {
                seen.remove(&c.kind);
            } else if c.connected {
                seen.insert(c.kind.clone());
            }
        }
        if let Some(p) = &self.path
            && *seen != before
        {
            // Best effort: an unwritable state dir only means a restart forgets it. Insertion
            // order in the TS file; any order reads back the same.
            let _ = std::fs::write(p, json!(seen.iter().collect::<Vec<_>>()).to_string());
        }
        channels
            .iter()
            .map(|c| (c.kind.clone(), seen.contains(&c.kind)))
            .collect()
    }
}

/// The chat channels' states, as `ChannelsService::channel_states` reads them.
pub type ChannelsRead = Box<dyn Fn() -> cc_http::BoxFuture<Option<Map<String, Value>>> + Send + Sync>;

/// What a sample reads; each part can fail on its own.
pub struct Readers {
    /// Off the runtime's threads: a stalled volume blocks statfs.
    pub disk: Box<dyn Fn() -> cc_http::BoxFuture<Option<Value>> + Send + Sync>,
    pub mem_pct: Box<dyn Fn() -> Option<f64> + Send + Sync>,
    pub load1: Box<dyn Fn() -> Option<f64> + Send + Sync>,
    pub openclaw_state: Box<dyn Fn() -> cc_http::BoxFuture<Option<String>> + Send + Sync>,
    /// Per channel type, as `/channels/status` reads it; None when the gateway did not answer.
    pub channels: ChannelsRead,
}

/// Where the samples go: one `POST {records}` with the box's token. Ok(status) when it answered.
pub type Post = Arc<dyn Fn(Value) -> cc_http::BoxFuture<Result<u16, String>> + Send + Sync>;

pub struct MetricSampler {
    queue: Mutex<VecDeque<(u64, Value)>>,
    next_id: std::sync::atomic::AtomicU64,
    cpu: CpuSampler,
    read: Readers,
    post: Post,
    max_queue: usize,
    in_flight: std::sync::atomic::AtomicBool,
    channels_seen: ChannelsSeen,
}

impl MetricSampler {
    pub fn new(cpu: CpuSampler, read: Readers, post: Post, channels_seen: Option<PathBuf>, max_queue: usize) -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            next_id: std::sync::atomic::AtomicU64::new(0),
            cpu,
            read,
            post,
            max_queue,
            in_flight: std::sync::atomic::AtomicBool::new(false),
            channels_seen: ChannelsSeen::new(channels_seen),
        }
    }

    fn log(line: &str) {
        tracing::info!("[metrics] {line}");
    }

    /// The first CPU reading, so the first sample a minute later has a use to report.
    pub fn prime(&self) {
        self.cpu.sample();
    }

    pub fn pending(&self) -> usize {
        lock(&self.queue).len()
    }

    /// Takes one sample and queues it. A reading that fails is null, not a missing sample.
    pub async fn sample(&self) -> Value {
        self.cpu.sample();
        let disk = (self.read.disk)().await;
        let channels = (self.read.channels)().await.map(|read| {
            let now: Vec<ChannelNow> = read
                .iter()
                .map(|(t, c)| ChannelNow {
                    kind: t.clone(),
                    configured: c.get("configured") == Some(&json!(true)),
                    running: c.get("running") == Some(&json!(true)),
                    connected: c.get("connected") == Some(&json!(true)),
                    last_error: c.get("lastError").and_then(Value::as_str).map(str::to_string),
                })
                .collect();
            let seen = self.channels_seen.note(&now);
            now.iter()
                .map(|c| {
                    json!({
                        "type": c.kind, "configured": c.configured, "running": c.running, "connected": c.connected,
                        "reason": channel_reason(c.last_error.as_deref()),
                        "seen": seen.get(&c.kind) == Some(&true),
                    })
                })
                .collect::<Vec<_>>()
        });
        let openclaw = (self.read.openclaw_state)().await.filter(|s| !s.is_empty());
        let mut rec = json!({
            "source": "metric",
            "ts": now_ms(),
            "cpu_pct": self.cpu.used_pct().map(js_number),
            "mem_pct": (self.read.mem_pct)().filter(|v| v.is_finite()).map(js_number),
            "disk_pct": disk.as_ref().map(|d| d["usedPct"].clone()),
            "disk_volume": disk.as_ref().map(|d| d["volume"].clone()),
            "load1": (self.read.load1)().filter(|v| v.is_finite()).map(js_number),
        });
        if let Some(o) = openclaw {
            rec["openclaw"] = json!(o);
        }
        if let Some(c) = channels {
            rec["channels"] = json!(c);
        }
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut q = lock(&self.queue);
        q.push_back((id, rec.clone()));
        while q.len() > self.max_queue {
            q.pop_front();
        }
        rec
    }

    /// Posts what is queued, oldest first, and drops each batch once the control plane took it.
    /// Stops at the first batch that fails; the rest waits for the next tick.
    pub async fn ship(&self) -> usize {
        let Some(_flying) = super::common::Flag::take(&self.in_flight) else {
            return 0;
        };
        let mut shipped = 0;
        loop {
            let batch: Vec<(u64, Value)> = lock(&self.queue).iter().take(BATCH).cloned().collect();
            if batch.is_empty() || !self.post_batch(&batch).await {
                break;
            }
            // By identity, not by count: a sample taken during the post may have trimmed the front.
            let sent: BTreeSet<u64> = batch.iter().map(|b| b.0).collect();
            lock(&self.queue).retain(|r| !sent.contains(&r.0));
            shipped += batch.len();
        }
        shipped
    }

    pub async fn tick(&self) {
        self.sample().await;
        self.ship().await;
    }

    /// True when the batch is done with: taken, or refused for good (400/413, dropped).
    async fn post_batch(&self, batch: &[(u64, Value)]) -> bool {
        let records: Vec<&Value> = batch.iter().map(|b| &b.1).collect();
        match (self.post)(json!({ "records": records })).await {
            Ok(s @ (400 | 413)) => {
                // A control plane from before the `metric` sink answers 400 for every one.
                Self::log(&format!("batch of {} rejected with HTTP {s}; dropped", batch.len()));
                true
            }
            Ok(s) if !(200..300).contains(&s) => {
                Self::log(&format!("ship failed: HTTP {s}; {} samples kept", self.pending()));
                false
            }
            Ok(_) => true,
            Err(e) => {
                Self::log(&format!("ship failed: {e}; {} samples kept", self.pending()));
                false
            }
        }
    }
}

/// The real post: `<base>/api/vm-agent/activity`, the box's token, 20 s.
pub fn activity_post(base: String, keys: cc_auth::keys::KeysDir, http: cc_client::HttpClient) -> Post {
    Arc::new(move |body: Value| {
        let (url, keys, http) = (format!("{base}/api/vm-agent/activity"), keys.clone(), http.get());
        Box::pin(async move {
            let token = cc_auth::sign::box_token(&keys).map_err(|e| e.to_string())?;
            let res = http
                .post(url)
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .timeout(SHIP_TIMEOUT)
                .send()
                .await
                // Without the URL: it names this box's console.
                .map_err(|e| e.without_url().to_string())?;
            Ok(res.status().as_u16())
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_codes() {
        assert_eq!(channel_reason(None), None);
        assert_eq!(channel_reason(Some("  ")), None);
        assert_eq!(channel_reason(Some("Session closed by phone")), Some("logged_out"));
        assert_eq!(channel_reason(Some("HTTP 401 Unauthorized")), Some("auth"));
        assert_eq!(
            channel_reason(Some("getaddrinfo ENOTFOUND api.telegram.org")),
            Some("network")
        );
        assert_eq!(channel_reason(Some("something else")), Some("other"));
    }

    #[test]
    fn a_channel_is_seen_once_connected_and_forgotten_when_unconfigured() {
        let d = tempfile::tempdir().expect("dir");
        let path = d.path().join("seen.json");
        let c = |kind: &str, configured, connected| ChannelNow {
            kind: kind.into(),
            configured,
            running: connected,
            connected,
            last_error: None,
        };
        let s = ChannelsSeen::new(Some(path.clone()));
        assert!(!s.note(&[c("whatsapp", true, false)])["whatsapp"]);
        assert!(s.note(&[c("whatsapp", true, true)])["whatsapp"]);
        assert!(ChannelsSeen::new(Some(path.clone())).note(&[c("whatsapp", true, false)])["whatsapp"]);
        assert!(!s.note(&[c("whatsapp", false, false)])["whatsapp"]);
    }

    fn sampler(status: Arc<Mutex<Result<u16, String>>>, posts: Arc<Mutex<Vec<Value>>>, max: usize) -> MetricSampler {
        let post: Post = Arc::new(move |body| {
            lock(&posts).push(body);
            let r = lock(&status).clone();
            Box::pin(async move { r })
        });
        MetricSampler::new(
            CpuSampler::new(|| Some("cpu 1 0 0 1 0".into())),
            Readers {
                disk: Box::new(|| Box::pin(async { Some(json!({ "usedPct": 41.5, "volume": "data" })) })),
                mem_pct: Box::new(|| Some(50.0)),
                load1: Box::new(|| None),
                openclaw_state: Box::new(|| Box::pin(async { Some("running".to_string()) })),
                channels: Box::new(|| {
                    Box::pin(async {
                        Some(json!({ "telegram": { "configured": true, "running": true, "connected": false, "lastError": "401" } }).as_object().cloned().expect("o"))
                    })
                }),
            },
            post,
            None,
            max,
        )
    }

    #[tokio::test]
    async fn samples_wait_while_the_console_is_away_and_go_with_the_next_post() {
        let status = Arc::new(Mutex::new(Err("down".to_string())));
        let posts = Arc::new(Mutex::new(Vec::new()));
        let s = sampler(status.clone(), posts.clone(), 3);
        let rec = s.sample().await;
        assert_eq!(rec["mem_pct"], json!(50));
        assert_eq!(rec["disk_volume"], json!("data"));
        assert_eq!(rec["load1"], Value::Null);
        assert_eq!(rec["channels"][0]["reason"], json!("auth"));
        assert_eq!(rec["channels"][0]["seen"], json!(false));
        s.tick().await;
        s.tick().await;
        s.tick().await;
        assert_eq!(s.pending(), 3, "a full queue drops the oldest");
        *lock(&status) = Ok(200);
        s.tick().await;
        assert_eq!(s.pending(), 0);
        assert_eq!(
            lock(&posts).last().expect("post")["records"].as_array().map(Vec::len),
            Some(3)
        );
        *lock(&status) = Ok(400);
        s.tick().await;
        assert_eq!(s.pending(), 0, "refused for good is dropped");
    }
}
