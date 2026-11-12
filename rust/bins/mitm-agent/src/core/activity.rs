//! Ships a JSONL log to the console's `POST /api/vm-agent/activity` (`activity.ts`): the proxy's
//! traffic log, and the other logs W4 and W5 ship with a `transform` (content rule audit, app and
//! MCP calls). The file is the queue: the cursor moves only after the server took a batch, and the
//! server dedupes on each record's id.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::activity_sanitize;
use super::log_tail::LogTail;

/// What a line becomes on the wire; `None` leaves it out.
pub type Transform = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;
/// Called with each batch the server accepted (the exit's byte count, the included credit).
pub type OnShipped = Arc<dyn Fn(&[Value]) + Send + Sync>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShipResult {
    pub read: usize,
    pub accepted: u64,
    pub duplicates: u64,
    pub skipped: usize,
}

struct State {
    backoff: Duration,
    next_attempt: Option<Instant>,
    logged: HashSet<String>,
}

pub struct ActivityShipper {
    /// Held through a pass: a slow POST must not overlap the next tick, or a batch ships twice.
    tail: tokio::sync::Mutex<LogTail>,
    url: String,
    client: super::store_client::StoreClient,
    transform: Option<Transform>,
    on_shipped: Vec<OnShipped>,
    state: Mutex<State>,
}

/// `records[3].swapped[0] too_big` from the server's `{path, code}`. Never a record's values.
fn describe_issue(issue: Option<&Value>) -> String {
    let Some(Value::Object(o)) = issue else {
        return "no reason given".into();
    };
    let path = o
        .get("path")
        .and_then(Value::as_str)
        .map(|s| s.chars().take(120).collect())
        .unwrap_or_else(|| "?".to_string());
    let code = o
        .get("code")
        .and_then(Value::as_str)
        .map(|s| s.chars().take(40).collect())
        .unwrap_or_else(|| "?".to_string());
    format!("{path} {code}")
}

static WHITESPACE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\s+").expect("regex"));

/// `describeRefusal`: the error of a 400/413 body and, when the server names one, the field.
pub fn describe_refusal(text: &str) -> String {
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Null) | Err(_) => {
            if text.is_empty() {
                "no reason given".into()
            } else {
                let cut: String = text.chars().take(120).collect();
                WHITESPACE.replace_all(&cut, " ").into_owned()
            }
        }
        Ok(body) => {
            let error = body
                .get("error")
                .and_then(Value::as_str)
                .map(|s| s.chars().take(80).collect())
                .unwrap_or_else(|| "refused".to_string());
            match body.get("issue") {
                Some(i) if super::sync::js_truthy(i) => format!("{error}: {}", describe_issue(Some(i))),
                _ => error,
            }
        }
    }
}

impl ActivityShipper {
    pub fn new(
        log_path: &str,
        cursor_path: &std::path::Path,
        url: &str,
        client: super::store_client::StoreClient,
        transform: Option<Transform>,
        on_shipped: Vec<OnShipped>,
    ) -> Self {
        Self {
            tail: tokio::sync::Mutex::new(LogTail::new(log_path, cursor_path, None)),
            url: url.to_string(),
            client,
            transform,
            on_shipped,
            state: Mutex::new(State {
                backoff: Duration::ZERO,
                next_attempt: None,
                logged: HashSet::new(),
            }),
        }
    }

    fn log_once(&self, key: String, line: &str) {
        let Ok(mut s) = self.state.lock() else { return };
        if s.logged.contains(&key) {
            return;
        }
        if s.logged.len() >= 100 {
            s.logged.clear();
        }
        s.logged.insert(key);
        tracing::error!("{line}");
    }

    /// One pass: everything unshipped, a batch at a time, until caught up or an error.
    pub async fn tick(&self) -> ShipResult {
        let mut total = ShipResult::default();
        if let Ok(s) = self.state.lock()
            && s.next_attempt.is_some_and(|t| Instant::now() < t)
        {
            return total;
        }
        let Ok(mut tail) = self.tail.try_lock() else {
            return total;
        };
        let acc = Mutex::new((0u64, 0u64));
        let r = tail
            .drain(|records| {
                let acc = &acc;
                async move {
                    let Some(ok) = self.post(&records).await else {
                        return false;
                    };
                    if let Ok(mut a) = acc.lock() {
                        a.0 += ok.0;
                        a.1 += ok.1;
                    }
                    if ok.2 {
                        for f in &self.on_shipped {
                            // Accounting must never wedge the shipper: the cursor has moved on.
                            let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&records)));
                            if run.is_err() {
                                tracing::error!("[activity] onShipped failed");
                            }
                        }
                    }
                    true
                }
            })
            .await;
        let (accepted, duplicates) = acc.lock().map(|a| *a).unwrap_or_default();
        total.read = r.read;
        total.skipped = r.skipped;
        total.accepted = accepted;
        total.duplicates = duplicates;
        total
    }

    /// `(accepted, duplicates, delivered)`, or `None` to keep the batch for later.
    async fn post(&self, records: &[Value]) -> Option<(u64, u64, bool)> {
        let shipped: Vec<Value> = match &self.transform {
            Some(t) => records.iter().filter_map(|r| t(r)).filter(|v| !v.is_null()).collect(),
            None => records.to_vec(),
        };
        if shipped.is_empty() {
            return Some((0, 0, true));
        }
        let body = json!({
            "records": shipped
                .into_iter()
                .map(activity_sanitize::agentmail)
                .map(activity_sanitize::phone)
                .collect::<Vec<_>>()
        });
        match self.send(&body).await {
            Ok((status, text)) if status == 400 || status == 413 => {
                // A malformed batch the server will never take: drop it rather than wedge for ever.
                let reason = describe_refusal(&text);
                tracing::error!(
                    "[activity] batch rejected (HTTP {status}); dropping {} records",
                    records.len()
                );
                self.log_once(
                    format!("{status} {reason}"),
                    &format!("[activity] the server said: {reason}"),
                );
                if let Ok(mut s) = self.state.lock() {
                    s.backoff = Duration::ZERO;
                }
                Some((0, 0, false))
            }
            Ok((status, _)) if !(200..300).contains(&status) => self.failed(&format!("HTTP {status}")),
            Ok((_, text)) => {
                let body: Value = match serde_json::from_str(&text) {
                    Ok(b) => b,
                    Err(e) => return self.failed(&e.to_string()),
                };
                if let Ok(mut s) = self.state.lock() {
                    s.backoff = Duration::ZERO;
                }
                let skipped = body.get("skipped").filter(|v| super::sync::js_truthy(v));
                if let Some(n) = skipped {
                    let reason = describe_issue(body.get("issue"));
                    self.log_once(
                        format!("skipped {reason}"),
                        &format!(
                            "[activity] the server skipped {} of {} records: {reason} (logged once)",
                            super::activity_sanitize::js_string(Some(n)),
                            records.len()
                        ),
                    );
                }
                let num = |k: &str| body.get(k).and_then(Value::as_u64).unwrap_or(0);
                Some((num("accepted"), num("duplicates"), true))
            }
            Err(e) => self.failed(&e),
        }
    }

    async fn send(&self, body: &Value) -> Result<(u16, String), String> {
        self.client.post_text(&self.url, body).await
    }

    fn failed(&self, why: &str) -> Option<(u64, u64, bool)> {
        if let Ok(mut s) = self.state.lock() {
            s.backoff = if s.backoff.is_zero() {
                Duration::from_secs(5)
            } else {
                (s.backoff * 2).min(Duration::from_secs(60))
            };
            s.next_attempt = Some(Instant::now() + s.backoff);
            tracing::error!("[activity] ship failed ({why}); retry in {}s", s.backoff.as_secs());
        }
        None
    }
}

/// `connectorCallActivity`: an app or MCP call line as it is, if it is one (`connector_call` with
/// its `id`, `ts` and `vm_id`); the console merges it with the run's row on the same key.
pub fn connector_call_activity(line: &Value) -> Option<Value> {
    let ok = line.get("source").and_then(Value::as_str) == Some("connector_call")
        && line.get("id").is_some_and(Value::is_string)
        && line.get("ts").is_some_and(Value::is_number)
        && line.get("vm_id").is_some_and(Value::is_string);
    ok.then(|| line.clone())
}

/// Ships one of the firewall's own logs on its own cursor (`<log>.cursor`), every `ACTIVITY_POLL_MS`,
/// when there is a control plane to post to (the console, or a standalone firewall's own).
pub fn ship_log(log_path: &str, transform: Transform) {
    let Some(core) = super::core() else { return };
    if core.env.activity_url.is_empty() || !core.uses_http {
        return;
    }
    let shipper = ActivityShipper::new(
        log_path,
        &std::path::PathBuf::from(format!("{log_path}.cursor")),
        &core.env.activity_url,
        core.sync.client.clone(),
        Some(transform),
        Vec::new(),
    );
    let every = Duration::from_millis(core.env.activity_poll_ms);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            shipper.tick().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_are_described() {
        assert_eq!(describe_refusal(""), "no reason given");
        assert_eq!(describe_refusal("not  json\nat all"), "not json at all");
        assert_eq!(describe_refusal("null"), "null");
        assert_eq!(describe_refusal("5"), "refused");
        assert_eq!(describe_refusal(r#"{"error":"bad"}"#), "bad");
        assert_eq!(
            describe_refusal(r#"{"error":"bad","issue":{"path":"records[3].x","code":"too_big"}}"#),
            "bad: records[3].x too_big"
        );
        assert_eq!(describe_refusal(r#"{"issue":{"path":1}}"#), "refused: ? ?");
    }

    #[test]
    fn only_call_lines_are_shipped() {
        let line = json!({"source": "connector_call", "id": "a1", "ts": 1.5, "vm_id": "vm_1", "decision": "allowed"});
        assert_eq!(connector_call_activity(&line), Some(line.clone()));
        for bad in [
            json!({"source": "content_rule", "id": "a1", "ts": 1, "vm_id": "vm_1"}),
            json!({"source": "connector_call", "ts": 1, "vm_id": "vm_1"}),
            json!({"source": "connector_call", "id": 7, "ts": 1, "vm_id": "vm_1"}),
            json!({"source": "connector_call", "id": "a1", "ts": "1", "vm_id": "vm_1"}),
            json!({"source": "connector_call", "id": "a1", "ts": 1}),
            json!("connector_call"),
        ] {
            assert_eq!(connector_call_activity(&bad), None, "{bad}");
        }
    }
}

#[cfg(test)]
mod shipper_tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Answer = Arc<dyn Fn(&Value) -> (u16, Value) + Send + Sync>;

    struct Fake {
        url: String,
        batches: Arc<Mutex<Vec<usize>>>,
        answer: Arc<Mutex<Answer>>,
    }

    async fn fake() -> Fake {
        let batches = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::new(Mutex::new(HashSet::<String>::new()));
        let s = seen.clone();
        let dedupe: Answer = Arc::new(move |body: &Value| {
            let (mut accepted, mut duplicates) = (0, 0);
            for r in body["records"].as_array().cloned().unwrap_or_default() {
                if s.lock()
                    .expect("lock")
                    .insert(r["flow_id"].as_str().unwrap_or_default().to_string())
                {
                    accepted += 1;
                } else {
                    duplicates += 1;
                }
            }
            (200, json!({"accepted": accepted, "duplicates": duplicates}))
        });
        let answer = Arc::new(Mutex::new(dedupe));
        let (b, a) = (batches.clone(), answer.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let (b, a) = (b.clone(), a.clone());
                async move {
                    use http_body_util::BodyExt;
                    let raw = req
                        .into_body()
                        .collect()
                        .await
                        .map(|x| x.to_bytes())
                        .unwrap_or_default();
                    let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                    b.lock()
                        .expect("lock")
                        .push(body["records"].as_array().map(Vec::len).unwrap_or(0));
                    let f = a.lock().expect("lock").clone();
                    let (status, out) = f(&body);
                    cc_http::json(status, &out)
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        Fake {
            url: format!("http://{addr}/activity"),
            batches,
            answer,
        }
    }

    fn rec(i: u32) -> String {
        format!(
            "{}\n",
            json!({"flow_id": format!("f{i}"), "host": "h", "effect": "allow"})
        )
    }

    fn append(p: &std::path::Path, t: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(p)
            .expect("open");
        f.write_all(t.as_bytes()).expect("write");
    }

    fn shipper(dir: &std::path::Path, url: &str, transform: Option<Transform>) -> ActivityShipper {
        let keys = dir.join("keys");
        if !keys.exists() {
            cc_testkit::BoxKeys::write(&keys, "fw_1", "fw.example").expect("keys");
        }
        let client = super::super::store_client::StoreClient {
            http: cc_client::HttpClient::new(true).expect("http"),
            keys: cc_auth::keys::KeysDir::new(keys),
            token: true,
        };
        let s = ActivityShipper::new(
            &dir.join("traffic.jsonl").display().to_string(),
            &dir.join("activity.cursor"),
            url,
            client,
            transform,
            Vec::new(),
        );
        if let Ok(mut t) = s.tail.try_lock() {
            t.batch_size = 3;
        }
        s
    }

    fn offset(dir: &std::path::Path) -> u64 {
        let c: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("activity.cursor")).expect("c")).expect("j");
        c["offset"].as_u64().expect("n")
    }

    #[tokio::test]
    async fn ships_in_batches_follows_rotation_and_keeps_refusals() {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let f = fake().await;
        assert_eq!(shipper(d.path(), &f.url, None).tick().await.read, 0);

        std::fs::write(
            &log,
            format!("{}{}{}{}{{\"flow_id\":\"f5\",\"partial", rec(1), rec(2), rec(3), rec(4)),
        )
        .expect("w");
        let r = shipper(d.path(), &f.url, None).tick().await;
        assert_eq!((r.read, r.accepted), (4, 4));
        assert_eq!(*f.batches.lock().expect("lock"), vec![3, 1]);
        assert_eq!(offset(d.path()), (rec(1) + &rec(2) + &rec(3) + &rec(4)).len() as u64);

        append(&log, &format!("\":1}}\nnot json\n{}", rec(6)));
        let r = shipper(d.path(), &f.url, None).tick().await;
        assert_eq!((r.read, r.skipped, r.accepted), (2, 1, 2));

        // A refused batch keeps the cursor, and an immediate retry waits for the backoff.
        append(&log, &rec(7));
        let ok = f.answer.lock().expect("lock").clone();
        *f.answer.lock().expect("lock") = Arc::new(|_| (503, json!("nope")));
        let s = shipper(d.path(), &f.url, None);
        assert_eq!(s.tick().await.read, 0);
        *f.answer.lock().expect("lock") = ok;
        assert_eq!(s.tick().await.read, 0);

        // Shipping again from 0 is idempotent on the server.
        std::fs::write(d.path().join("activity.cursor"), r#"{"inode":0,"offset":0}"#).expect("w");
        let r = shipper(d.path(), &f.url, None).tick().await;
        assert_eq!((r.duplicates, r.accepted), (6, 1));

        // The proxy rotates: the rest of `.1` first, then the new file.
        shipper(d.path(), &f.url, None).tick().await;
        append(&log, &rec(8));
        std::fs::rename(&log, d.path().join("traffic.jsonl.1")).expect("rotate");
        append(&d.path().join("traffic.jsonl.1"), &rec(9));
        std::fs::write(&log, rec(10) + &rec(11)).expect("w");
        let r = shipper(d.path(), &f.url, None).tick().await;
        assert_eq!(r.accepted, 4);
        assert_eq!(offset(d.path()), (rec(10) + &rec(11)).len() as u64);

        std::fs::write(&log, rec(12)).expect("truncate");
        assert_eq!(shipper(d.path(), &f.url, None).tick().await.accepted, 1);
    }

    #[tokio::test]
    async fn a_batch_the_transform_empties_is_not_sent() {
        let d = tempfile::tempdir().expect("dir");
        let log = d.path().join("traffic.jsonl");
        let f = fake().await;
        std::fs::write(&log, rec(200) + &rec(201)).expect("w");
        let posts = Arc::new(AtomicUsize::new(0));
        let p = posts.clone();
        *f.answer.lock().expect("lock") = Arc::new(move |_| {
            p.fetch_add(1, Ordering::SeqCst);
            (200, json!({"accepted": 0, "duplicates": 0}))
        });
        shipper(d.path(), &f.url, Some(Arc::new(|_| None))).tick().await;
        assert_eq!(posts.load(Ordering::SeqCst), 0);
        append(&log, &rec(202));
        shipper(d.path(), &f.url, Some(Arc::new(|r| Some(r.clone()))))
            .tick()
            .await;
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(*f.batches.lock().expect("lock"), vec![1]);
    }

    #[tokio::test]
    async fn a_malformed_batch_is_dropped() {
        let d = tempfile::tempdir().expect("dir");
        let f = fake().await;
        *f.answer.lock().expect("lock") = Arc::new(|_| (400, json!({"error": "Invalid records"})));
        std::fs::write(d.path().join("traffic.jsonl"), rec(1)).expect("w");
        let r = shipper(d.path(), &f.url, None).tick().await;
        assert_eq!((r.read, r.accepted), (1, 0));
        assert_eq!(offset(d.path()), rec(1).len() as u64);
    }
}
