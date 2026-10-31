//! The ready report (`ready.ts`): POST `ready_api_url` with a box token, the software report and
//! the rescue session as it is now. The console flips the box to running and locks egress down.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::app::App;

/// `reportReady`. Never fails: up to 20 attempts, 2 s × attempt apart (15 s at most). The body is
/// built per attempt: the release file and the SSH session can change while this runs.
pub async fn report_ready(app: &App, extra: Map<String, Value>, software: impl Fn() -> Value) {
    // An empty file counts as missing, as the TS's falsy checks have it.
    let read = |name: &str| app.keys.read(name).filter(|v| !v.is_empty());
    let (Some(_), Some(url), Some(_)) = (read("vm_id"), read("ready_api_url"), read("vm_private_key.pem")) else {
        tracing::warn!(
            "[ready] missing vm_id / ready_api_url / vm_private_key.pem in KEYS_DIR — skipping ready report"
        );
        return;
    };
    const MAX: u64 = 20;
    for attempt in 1..=MAX {
        let mut body = json!({ "software": software() });
        // Absent, not null, when there is nothing to report: the console reads an absent key as
        // "too old to say" and leaves the grant alone.
        // `{...status, at}`: stamped, because the console skips any grant opened later than this
        // reading. Only an object is a reading; anything else is none.
        if let Some(Value::Object(mut ssh)) = app.contracts.box_setup.get().and_then(|b| b.ssh_reading()) {
            ssh.insert("at".into(), json!(super::time::now_iso()));
            body["ssh"] = Value::Object(ssh);
        }
        for (k, v) in &extra {
            body[k] = v.clone();
        }
        match app.console.post_json(&url, &body, Duration::from_secs(30)).await {
            Ok(a) if (200..300).contains(&a.status) => {
                tracing::info!("[ready] reported ready to SaaS (attempt {attempt})");
                return;
            }
            Ok(a) => tracing::warn!("[ready] attempt {attempt}/{MAX}: HTTP {}", a.status),
            // Without the URL: a request's error text names it.
            Err(cc_client::ClientError::Http(e)) => {
                tracing::warn!(
                    "[ready] attempt {attempt}/{MAX} failed: request failed: {}",
                    e.without_url()
                )
            }
            Err(e) => tracing::warn!("[ready] attempt {attempt}/{MAX} failed: {e}"),
        }
        tokio::time::sleep(Duration::from_millis((2000 * attempt).min(15_000))).await;
    }
    tracing::error!("[ready] gave up reporting ready after {MAX} attempts");
}
