//! Ships OpenClaw's audit ledger (tool calls and agent runs, metadata only) to the control plane
//! (`audit.ts`). Read with `audit.activity.list` from the cursor's time less a minute, keeping the
//! sequences above the cursor. The cursor moves only after the control plane took the batch, so a
//! crash between the two ships again what the ingest dedupes on `eventId`. Nothing that carries
//! content is in these records: no arguments, no output, no chat text.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::common::{Flag, js_slice, lock};
use super::time::now_ms;

const PAGE_LIMIT: usize = 500;
/// Pages walked per tick; past that the gap below the oldest page is reported and lost.
const MAX_PAGES: usize = 40;
const AFTER_SLACK_MS: i64 = 60_000;
const MIN_BACKOFF_MS: i64 = 5000;
const MAX_BACKOFF_MS: i64 = 60_000;
/// OpenClaw's generic tool: the nested call is the real tool's record.
pub const TOOL_CALL_WRAPPER: &str = "tool_call";
const CALL: Duration = Duration::from_secs(10);

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// One ledger event → one ingest record (`mapAuditEvent`); None for what is not shipped.
pub fn map_audit_event(ev: &Value) -> Option<Map<String, Value>> {
    let kind = s(ev, "kind")?;
    if kind != "tool_action" && kind != "agent_run" {
        return None;
    }
    let status = s(ev, "status");
    if kind == "tool_action"
        && s(ev, "toolName") == Some(TOOL_CALL_WRAPPER)
        && matches!(status, Some("started" | "succeeded"))
    {
        return None;
    }
    let sequence = ev.get("sequence").filter(|v| v.is_number())?;
    let event_id = s(ev, "eventId")?;
    let occurred_at = ev.get("occurredAt").filter(|v| v.is_number())?;
    let nonempty = |k: &str| s(ev, k).filter(|v| !v.is_empty());
    if kind == "tool_action" && nonempty("toolCallId").is_none() {
        return None;
    }
    if kind == "agent_run" && nonempty("runId").is_none() {
        return None;
    }
    let mut rec = Map::new();
    rec.insert("source".into(), json!(kind));
    rec.insert("event_id".into(), json!(js_slice(event_id, 64)));
    rec.insert("sequence".into(), sequence.clone());
    rec.insert("occurred_at".into(), occurred_at.clone());
    rec.insert("status".into(), json!(status.unwrap_or("unknown")));
    rec.insert("action".into(), json!(js_slice(s(ev, "action").unwrap_or(""), 64)));
    // Same caps as the ingest schema: one oversized field must not get a whole batch refused.
    let mut put = |name: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            rec.insert(name.into(), json!(v));
        }
    };
    put("tool_name", nonempty("toolName").map(|v| js_slice(v, 120)));
    put("tool_call_id", nonempty("toolCallId").map(|v| js_slice(v, 200)));
    put("run_id", nonempty("runId").map(|v| js_slice(v, 128)));
    let key = s(ev, "sessionKey").map(|k| {
        if k.contains(":agentmail:") {
            format!("agentmail:{}", hex::encode(Sha256::digest(k.as_bytes())))
        } else {
            js_slice(k, 200)
        }
    });
    put("session_key", key);
    put("agent_id", nonempty("agentId").map(|v| js_slice(v, 64)));
    Some(rec)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cursor {
    pub sequence: f64,
    pub occurred_at: f64,
}

/// Every new ledger event, in sequence order.
pub type OnEvents = Box<dyn Fn(&[Value]) + Send + Sync>;
/// Adds to a batch's records what the ledger does not carry; reads OpenClaw's database, so off the
/// runtime's threads.
pub type Enrich =
    Box<dyn Fn(Vec<Map<String, Value>>, Vec<Value>) -> cc_http::BoxFuture<Vec<Map<String, Value>>> + Send + Sync>;
/// One `POST {records}`: the status and the body the console answered.
pub type PostJson = Box<dyn Fn(Value) -> cc_http::BoxFuture<Result<(u16, Value), String>> + Send + Sync>;

/// What the shipper needs from the box.
pub struct AuditOptions {
    pub connected: Box<dyn Fn() -> bool + Send + Sync>,
    pub call: Box<dyn Fn(Value) -> cc_http::BoxFuture<Result<Value, String>> + Send + Sync>,
    pub cursor_path: PathBuf,
    pub post: PostJson,
    /// Every new ledger event, in sequence order, before it is shipped (stalls, Doing now).
    pub on_events: OnEvents,
    /// Adds what the ledger does not carry to a batch's records (a run's trigger and title).
    pub enrich: Enrich,
    pub log: Box<dyn Fn(&str) + Send + Sync>,
}

struct State {
    cursor: Cursor,
    next_attempt_at: i64,
    backoff: i64,
}

pub struct AuditShipper {
    o: AuditOptions,
    st: Mutex<State>,
    in_flight: AtomicBool,
}

#[derive(Debug, Default, PartialEq)]
pub struct Tick {
    pub read: usize,
    pub accepted: u64,
    pub duplicates: u64,
}

impl AuditShipper {
    pub fn new(o: AuditOptions) -> Self {
        let cursor = Self::load(&o.cursor_path).unwrap_or(Cursor {
            sequence: 0.0,
            occurred_at: now_ms() as f64,
        });
        Self {
            o,
            st: Mutex::new(State {
                cursor,
                next_attempt_at: 0,
                backoff: MIN_BACKOFF_MS,
            }),
            in_flight: AtomicBool::new(false),
        }
    }

    pub fn position(&self) -> Cursor {
        lock(&self.st).cursor
    }

    fn log(&self, line: &str) {
        (self.o.log)(&format!("[audit] {line}"));
    }

    fn load(path: &std::path::Path) -> Option<Cursor> {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()?;
        Some(Cursor {
            sequence: v.get("sequence")?.as_f64()?,
            occurred_at: v.get("occurredAt")?.as_f64()?,
        })
    }

    fn save(&self, c: Cursor) {
        let n = |f: f64| super::common::js_number(f);
        let body = json!({ "sequence": n(c.sequence), "occurredAt": n(c.occurred_at) }).to_string();
        if let Some(d) = self.o.cursor_path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Err(e) = cc_store::write_atomic(&self.o.cursor_path, body.as_bytes(), 0o600, cc_store::TmpName::Suffix) {
            self.log(&format!("cursor not saved: {e}"));
        }
    }

    pub async fn tick(&self) -> Tick {
        let mut total = Tick::default();
        if !(self.o.connected)() || now_ms() < lock(&self.st).next_attempt_at {
            return total;
        }
        let Some(_flying) = Flag::take(&self.in_flight) else {
            return total;
        };
        let mut fresh = match self.fetch_new().await {
            Ok(f) => f,
            Err(e) => {
                // The gateway answers errors while it shuts down or restarts; one line, then wait.
                self.log(&format!("ledger read failed: {e}"));
                lock(&self.st).next_attempt_at = now_ms() + MIN_BACKOFF_MS;
                return total;
            }
        };
        total.read = fresh.len();
        if fresh.is_empty() {
            return total;
        }
        let seq = |v: &Value| v.get("sequence").and_then(Value::as_f64).unwrap_or(0.0);
        fresh.sort_by(|a, b| seq(a).total_cmp(&seq(b)));
        // Before shipping, and whether or not shipping works.
        (self.o.on_events)(&fresh);
        for batch in fresh.chunks(PAGE_LIMIT) {
            let mut records: Vec<Map<String, Value>> = batch.iter().filter_map(map_audit_event).collect();
            let last = batch.last().expect("chunk");
            if !records.is_empty() {
                // Each read in it fails on its own and leaves its field out.
                records = (self.o.enrich)(records, batch.to_vec()).await;
                match self.post(&records).await {
                    Some((a, d)) => {
                        total.accepted += a;
                        total.duplicates += d;
                    }
                    None => {
                        let mut st = lock(&self.st);
                        st.next_attempt_at = now_ms() + st.backoff;
                        st.backoff = (st.backoff * 2).min(MAX_BACKOFF_MS);
                        return total;
                    }
                }
            }
            let cursor = {
                let mut st = lock(&self.st);
                st.cursor = Cursor {
                    sequence: seq(last),
                    occurred_at: st
                        .cursor
                        .occurred_at
                        .max(last.get("occurredAt").and_then(Value::as_f64).unwrap_or(0.0)),
                };
                st.backoff = MIN_BACKOFF_MS;
                st.next_attempt_at = 0;
                st.cursor
            };
            self.save(cursor);
        }
        total
    }

    /// Events with a sequence above the cursor, unordered.
    async fn fetch_new(&self) -> Result<Vec<Value>, String> {
        let cursor = self.position();
        let mut out = Vec::new();
        let after = (cursor.occurred_at - AFTER_SLACK_MS as f64).max(0.0);
        let mut page_cursor: Option<String> = None;
        let mut reached_old = false;
        for _ in 0..MAX_PAGES {
            let mut params = json!({ "after": super::common::js_number(after), "limit": PAGE_LIMIT });
            if let Some(c) = &page_cursor {
                params["cursor"] = json!(c);
            }
            let res = (self.o.call)(params).await?;
            let events = res.get("events").and_then(Value::as_array).cloned().unwrap_or_default();
            let n = events.len();
            for ev in events {
                let Some(sq) = ev.get("sequence").and_then(Value::as_f64) else {
                    continue;
                };
                if sq <= cursor.sequence {
                    reached_old = true;
                    continue;
                }
                out.push(ev);
            }
            let next = res.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty());
            if reached_old || next.is_none() || n < PAGE_LIMIT {
                break;
            }
            page_cursor = next.map(str::to_string);
        }
        if !reached_old && out.len() >= MAX_PAGES * PAGE_LIMIT {
            let oldest = out
                .iter()
                .filter_map(|e| e.get("sequence").and_then(Value::as_f64))
                .fold(f64::INFINITY, f64::min);
            self.log(&format!(
                "backlog larger than {} events; ledger entries below sequence {oldest} are not shipped",
                out.len()
            ));
        }
        Ok(out)
    }

    /// Some((accepted, duplicates)) when done with the batch (taken, or refused for good).
    async fn post(&self, records: &[Map<String, Value>]) -> Option<(u64, u64)> {
        match (self.o.post)(json!({ "records": records })).await {
            Ok((s @ (400 | 413), _)) => {
                // A batch the control plane will never take: dropped rather than wedge the cursor.
                self.log(&format!("batch of {} rejected with HTTP {s}; dropped", records.len()));
                Some((0, 0))
            }
            Ok((s, _)) if !(200..300).contains(&s) => {
                self.log(&format!("ship failed: HTTP {s}"));
                None
            }
            Ok((_, body)) => Some((
                body.get("accepted")
                    .and_then(Value::as_u64)
                    .unwrap_or(records.len() as u64),
                body.get("duplicates").and_then(Value::as_u64).unwrap_or(0),
            )),
            Err(e) => {
                self.log(&format!("ship failed: {e}"));
                None
            }
        }
    }
}

/// The real post: `<base>/api/vm-agent/activity`, the box's token, 20 s; the answer's JSON or `{}`.
pub fn activity_post_json(base: String, keys: cc_auth::keys::KeysDir, http: cc_client::HttpClient) -> PostJson {
    Box::new(move |body: Value| {
        let (url, keys, http) = (format!("{base}/api/vm-agent/activity"), keys.clone(), http.get());
        Box::pin(async move {
            let token = cc_auth::sign::box_token(&keys).map_err(|e| e.to_string())?;
            let res = http
                .post(url)
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(body.to_string())
                .timeout(super::metrics::SHIP_TIMEOUT)
                .send()
                .await
                .map_err(|e| e.without_url().to_string())?;
            let status = res.status().as_u16();
            Ok((status, res.json::<Value>().await.unwrap_or_else(|_| json!({}))))
        })
    })
}

/// `audit.activity.list` over the gateway.
pub fn ledger_call(
    deps: super::common::Deps,
) -> Box<dyn Fn(Value) -> cc_http::BoxFuture<Result<Value, String>> + Send + Sync> {
    Box::new(move |params| {
        let deps = deps.clone();
        Box::pin(async move { deps.call("audit.activity.list", params, CALL).await })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn ev(seq: i64, kind: &str, status: &str) -> Value {
        json!({ "sequence": seq, "eventId": format!("e{seq}"), "occurredAt": 1000 + seq, "kind": kind, "status": status,
                "toolName": "browser", "toolCallId": format!("c{seq}"), "runId": "r1", "sessionKey": "agent:main:main", "agentId": "main", "action": "tool.action" })
    }

    #[test]
    fn records_carry_metadata_only() {
        let r = map_audit_event(&ev(1, "tool_action", "started")).expect("rec");
        assert_eq!(r["source"], json!("tool_action"));
        assert_eq!(r["tool_call_id"], json!("c1"));
        assert!(
            map_audit_event(&json!({ "kind": "message", "sequence": 1, "eventId": "x", "occurredAt": 1 })).is_none()
        );
        let mut w = ev(2, "tool_action", "succeeded");
        w["toolName"] = json!(TOOL_CALL_WRAPPER);
        assert!(map_audit_event(&w).is_none());
        w["status"] = json!("failed");
        assert!(
            map_audit_event(&w).is_some(),
            "a wrapper that failed may be the only record"
        );
        let mut m = ev(3, "agent_run", "started");
        m["sessionKey"] = json!("agent:main:agentmail:ada@example.com");
        let key = map_audit_event(&m).expect("rec")["session_key"]
            .as_str()
            .expect("k")
            .to_string();
        assert!(key.starts_with("agentmail:") && !key.contains("ada"));
    }

    #[tokio::test]
    async fn the_cursor_moves_only_after_the_console_took_the_batch() {
        let d = tempfile::tempdir().expect("dir");
        let status = Arc::new(Mutex::new(Err::<u16, String>("down".into())));
        let posts = Arc::new(Mutex::new(Vec::<Value>::new()));
        let seen = Arc::new(Mutex::new(0usize));
        let (st, ps, sn) = (status.clone(), posts.clone(), seen.clone());
        let ledger = json!({ "events": [ev(3, "tool_action", "succeeded"), ev(2, "tool_action", "started"), ev(1, "agent_run", "started")] });
        let shipper = AuditShipper::new(AuditOptions {
            connected: Box::new(|| true),
            call: Box::new(move |_| {
                let l = ledger.clone();
                Box::pin(async move { Ok(l) })
            }),
            cursor_path: d.path().join("audit.cursor"),
            post: Box::new(move |body| {
                lock(&ps).push(body);
                let r = lock(&st).clone().map(|s| (s, json!({})));
                Box::pin(async move { r })
            }),
            on_events: Box::new(move |e| *lock(&sn) += e.len()),
            enrich: Box::new(|mut recs, _| {
                for r in recs.iter_mut() {
                    if r["source"] == json!("agent_run") {
                        r.insert("trigger".into(), json!("user"));
                    }
                }
                Box::pin(async move { recs })
            }),
            log: Box::new(|_| {}),
        });
        lock(&shipper.st).cursor.sequence = 0.0;
        let t = shipper.tick().await;
        assert_eq!(t.read, 3);
        assert_eq!(shipper.position().sequence, 0.0, "not taken: the cursor stays");
        assert_eq!(*lock(&seen), 3, "fed whether or not shipping works");
        let first = lock(&posts)[0]["records"].clone();
        assert_eq!(first[0]["sequence"], json!(1), "in sequence order");
        assert_eq!(first[0]["trigger"], json!("user"));
        *lock(&status) = Ok(200);
        lock(&shipper.st).next_attempt_at = 0;
        shipper.tick().await;
        assert_eq!(shipper.position().sequence, 3.0);
        let saved: Value =
            serde_json::from_str(&std::fs::read_to_string(d.path().join("audit.cursor")).expect("r")).expect("j");
        assert_eq!(saved["sequence"], json!(3));
        // Read again: nothing above the cursor.
        assert_eq!(shipper.tick().await.read, 0);
    }
}
