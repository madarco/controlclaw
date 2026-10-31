//! `reportReady` (`ready.ts`): tell the console this firewall is up, signed with the box key, with
//! what it runs, its own view of its rescue shell session (T-63) and its Doctor key. Fire and
//! forget, idempotent, retried.

use std::sync::Arc;
use std::time::Duration;

use cc_auth::keys::KeysDir;
use cc_client::HttpClient;
use serde_json::{Map, Value};

/// This box's rescue session as it is now (`SshLocal.status`, C4), when there is one.
pub type ReadSsh = Arc<dyn Fn() -> Option<Map<String, Value>> + Send + Sync>;
/// The Doctor key (`{pub, sig, fingerprint}`, W5), when Doctor runs.
pub type ReadDoctor = Arc<dyn Fn() -> Option<Value> + Send + Sync>;

/// `ssh` and `doctor` are read on every attempt: the parts that set them may start after this.
pub async fn report_ready(
    keys: &KeysDir,
    http: &HttpClient,
    ssh: impl Fn() -> Option<ReadSsh>,
    doctor: impl Fn() -> Option<ReadDoctor>,
) {
    let (Some(_), Some(url), Some(_)) = (
        keys.vm_id(),
        keys.read("ready_api_url"),
        keys.read("vm_private_key.pem"),
    ) else {
        tracing::warn!("[ready] missing vm_id / ready_api_url / vm_private_key.pem — skipping");
        return;
    };
    const MAX_ATTEMPTS: u64 = 20;
    for attempt in 1..=MAX_ATTEMPTS {
        let mut body = Map::new();
        body.insert("software".into(), super::software::box_software());
        // Absent, not null, when there is nothing to report: the console reads absent as "too old to say".
        if let Some(mut s) = ssh().and_then(|f| f()) {
            s.insert("at".into(), Value::String(cc_crypto::store_health::iso_now()));
            body.insert("ssh".into(), Value::Object(s));
        }
        if let Some(d) = doctor().and_then(|f| f()) {
            body.insert("doctor".into(), d);
        }
        let sent = async {
            let token = cc_auth::sign::box_token(keys).map_err(|e| e.to_string())?;
            http.get()
                .post(url.trim())
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(serde_json::to_vec(&Value::Object(body)).unwrap_or_default())
                .timeout(Duration::from_secs(300))
                .send()
                .await
                .map(|r| r.status().as_u16())
                .map_err(|_| "fetch failed".to_string())
        };
        match sent.await {
            Ok(s) if (200..300).contains(&s) => {
                tracing::info!("[ready] reported ready (attempt {attempt})");
                return;
            }
            Ok(s) => tracing::warn!("[ready] attempt {attempt}/{MAX_ATTEMPTS}: HTTP {s}"),
            Err(e) => tracing::warn!("[ready] attempt {attempt}/{MAX_ATTEMPTS} failed: {e}"),
        }
        tokio::time::sleep(Duration::from_millis((2000 * attempt).min(15_000))).await;
    }
    tracing::error!("[ready] gave up after {MAX_ATTEMPTS} attempts");
}
