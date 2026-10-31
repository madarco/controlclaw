//! The start-up steps around the core (`main` in `index.ts`): the one-shot modes the smoke tests
//! use, the proxy's content-rules file before anything waits on the network, registering the
//! public key, the migration from another box, the pool box's proxy config, and the publish of the
//! signed CA before the first heartbeat.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use cc_client::HttpClient;
use cc_contracts::files::FileSpec;
use cc_crypto::secret_store::Ids;
use serde_json::{Value, json};

use super::activity::ActivityShipper;
use super::env::CoreEnv;
use super::store_client::StoreClient;
use crate::app::Config;

fn die(message: &str) -> ! {
    tracing::error!("[mitm-agent] {message}");
    std::process::exit(1);
}

/// `contentRulesWillRun`: the content-rules module runs on a claimed box with a control channel. A
/// standalone firewall's channel is its own control plane (`local_cp`), always there.
pub fn content_rules_will_run(config: &Config, env: &CoreEnv) -> bool {
    !config.pool_marker.exists()
        && (config.mode.standalone() || (!config.firewall_url.is_empty() && env.uses_http(&config.firewall_url)))
}

/// `settleContentRulesFile`: what the proxy reads before any module runs. A pool box has none; a box
/// whose module will run says "unknown" until it has (the proxy holds Telegram meanwhile); any
/// other box keeps its file, or gets an empty one.
pub fn settle_content_rules_file(
    dir: &Path,
    pool_unclaimed: bool,
    module_will_run: bool,
) -> std::io::Result<&'static str> {
    let path = FileSpec::CONTENT_RULES.path_in(dir);
    if pool_unclaimed {
        cc_contracts::write_atomic(dir, &FileSpec::CONTENT_RULES, &json!({"version": 1, "rules": []}))?;
        return Ok("none");
    }
    if module_will_run {
        cc_contracts::write_atomic(
            dir,
            &FileSpec::CONTENT_RULES,
            &json!({"version": 1, "unreadable": true}),
        )?;
        return Ok("unknown");
    }
    if path.exists() {
        return Ok("kept");
    }
    cc_contracts::write_atomic(dir, &FileSpec::CONTENT_RULES, &json!({"version": 1, "rules": []}))?;
    Ok("none")
}

fn settle_now(config: &Config, env: &CoreEnv) {
    let pool = config.pool_marker.exists();
    let will_run = content_rules_will_run(config, env);
    if let Err(e) = settle_content_rules_file(&config.proxy_config_dir, pool, will_run) {
        tracing::error!("[mitm-agent] could not write the content rules file: {e}");
    }
}

/// A pool box: the proxy config from the other member's routing identity, every 2 s, and the
/// content-rules file (`index.ts:808-821`).
pub fn start_pool(config: &Config) {
    let env = CoreEnv::from_env(&config.proxy_config_dir);
    let refresh = {
        let dir = config.proxy_config_dir.clone();
        let peer = config.pool_peer.clone();
        let cp_inspect = super::cp_inspect::CpInspect::from_env();
        move || {
            let peers = std::fs::read_to_string(&peer)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .unwrap_or_else(|| json!([]));
            let mut cfg = serde_json::Map::new();
            cfg.insert("credentials".into(), json!([]));
            cfg.insert("rules".into(), json!([]));
            let peers = peers.as_array().map(|p| cp_inspect.apply(p)).unwrap_or_default();
            cfg.insert("identities".into(), Value::Array(peers));
            if let Err(e) = super::sync::write_proxy_config(&dir, &cfg) {
                tracing::error!("[mitm-agent] pool config: {e}");
            }
        }
    };
    refresh();
    super::every(Duration::from_secs(2), move || {
        refresh();
        async {}
    });
    settle_now(config, &env);
}

/// Before the STORE_URL check (`index.ts:833-846`): `SHIP_ONCE`, then the content-rules file.
pub async fn early(config: &Config) {
    let env = CoreEnv::from_env(&config.proxy_config_dir);
    if env.ship_once {
        let keys = cc_auth::keys::KeysDir::new(&config.keys_dir);
        let http = HttpClient::new(true).unwrap_or_else(|e| die(&format!("http client: {e}")));
        if env.activity_url.is_empty() || env.traffic_log_path.is_empty() || !env.uses_http(&config.firewall_url) {
            die("SHIP_ONCE needs ACTIVITY_URL and TRAFFIC_LOG_PATH");
        }
        let shipper = ActivityShipper::new(
            &env.traffic_log_path,
            &env.activity_cursor_path,
            &env.activity_url,
            StoreClient {
                http,
                keys,
                token: true,
            },
            None,
            Vec::new(),
        );
        let r = shipper.tick().await;
        tracing::info!(
            "[activity] shipped read={} accepted={} duplicates={} skipped={}",
            r.read,
            r.accepted,
            r.duplicates,
            r.skipped
        );
        std::process::exit(0);
    }
    settle_now(config, &env);
}

/// After the key pair exists: the box key, migrated from another box when `MIGRATE_FROM_URL` and
/// `MASTER_PASSWORD` are set (`maybeMigrate`). The migration's calls are not signed, so it does not
/// wait for the public key's registration, which runs in [`super::start`] once the modules (the
/// content rules among them) are built: the proxy holds Telegram until they are, and that should
/// be seconds, not the minute and a half the registration retries for.
pub async fn box_key(config: &Config, http: &HttpClient) -> String {
    let env = CoreEnv::from_env(&config.proxy_config_dir);
    let log = |l: &str| tracing::info!("{l}");
    if env.migrate_from_url.is_empty() || env.master_password.is_empty() {
        return cc_crypto::secret_store::load_or_create_box_key(&config.box_key_path, &log)
            .unwrap_or_else(|e| die(&format!("box key: {e}")));
    }
    match migrate(config, &env, http).await {
        Ok(key) => key,
        Err(e) => die(&format!("migration failed: {e}")),
    }
}

async fn migrate(config: &Config, env: &CoreEnv, http: &HttpClient) -> Result<String, String> {
    tracing::info!("[mitm-agent] migration requested — deriving from master password");
    // Neither store client signs: `makeStoreClient(url)` is called without a token here.
    let client = StoreClient {
        http: http.clone(),
        keys: cc_auth::keys::KeysDir::new(&config.keys_dir),
        token: false,
    };
    let Some(source) = client.fetch_record(&env.migrate_from_url).await? else {
        die("migration source record not found");
    };
    let moved = cc_crypto::secret_store::migrate_to_new_box(
        &source,
        &env.master_password,
        &Ids {
            org_id: config.org_id.clone(),
            box_id: env.migrate_source_box_id.clone(),
        },
        &config.box_id,
    )
    .map_err(|e| e.0)?;
    cc_store::write_file(&config.box_key_path, moved.box_key.as_bytes(), 0o600).map_err(|e| e.to_string())?;
    client.put_record(&env.store_url, &moved.record).await?;
    tracing::info!(
        "[mitm-agent] migrated to v{} under a fresh box key",
        moved.record.version
    );
    Ok(moved.box_key)
}

/// `publishCa`: the proxy CA and a detached signature by this box's key, so the agents can check it
/// against the pinned key before trusting the proxy. The console stores both and cannot forge the
/// signature. Before the first heartbeat (bounded), because the console reads the CA row in the
/// same breath as the beat after a firewall was put back from its backup.
pub async fn publish_ca(core: Arc<super::Core>) {
    let env = &core.env;
    if env.ca_cert_path.is_empty() || env.ca_url.is_empty() || !core.uses_http {
        return;
    }
    let published = async {
        let cert = std::fs::read_to_string(&env.ca_cert_path).map_err(|e| e.to_string())?;
        let sig = super::keys::sign_detached(&core.app.config.keys_dir, &cert)?;
        let mut body = serde_json::Map::new();
        body.insert("ca_cert".into(), Value::String(cert));
        body.insert("ca_sig".into(), Value::String(sig));
        if let Some(extra) = core.ca_extra.get()
            && let Some((pubkey, pubsig)) = extra()
        {
            body.insert("doctor_ssh_pub".into(), Value::String(pubkey));
            body.insert("doctor_ssh_sig".into(), Value::String(pubsig));
        }
        core.sync
            .client
            .post_text(&env.ca_url, &Value::Object(body))
            .await
            .map(|(status, _)| status)
    };
    match published.await {
        Ok(status) => tracing::info!("[mitm-agent] published signed CA cert (HTTP {status})"),
        Err(e) => tracing::error!("[mitm-agent] CA publish failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_rules_file_settles() {
        let d = tempfile::tempdir().expect("dir");
        let read = || std::fs::read_to_string(d.path().join("content-rules.json")).expect("read");
        assert_eq!(settle_content_rules_file(d.path(), false, false).expect("w"), "none");
        assert_eq!(read(), r#"{"version":1,"rules":[]}"#);
        assert_eq!(settle_content_rules_file(d.path(), false, false).expect("w"), "kept");
        assert_eq!(settle_content_rules_file(d.path(), false, true).expect("w"), "unknown");
        assert_eq!(read(), r#"{"version":1,"unreadable":true}"#);
        assert_eq!(settle_content_rules_file(d.path(), true, true).expect("w"), "none");
        assert_eq!(read(), r#"{"version":1,"rules":[]}"#);
    }
}
