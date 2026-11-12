//! App integrations: the connector store and commands, the 3900 gate in front of OpenConnector,
//! and the run log shipper (`connectors.ts`, `connector-*.ts`).

pub mod firewall;
pub mod gate;
pub mod parse;
pub mod runs;
pub mod runtime;
pub mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::app::{App, Registry};
use crate::integrations::{Env, Shared};

pub const ACTIONS: &[&str] = &["read", "propose", "confirm", "cancel", "callback", "push", "forget"];

/// What a recovery restore must find empty (W3's eligibility, `index.ts` 1746): the agents holding
/// connections, `connectors?.summary().agents ?? 0`. A store that could not be read may hold some:
/// `None`, a refusal (the TS counts it as empty).
fn set_connectors_bound(f: Arc<dyn Fn() -> Option<usize> + Send + Sync>) {
    if let Some(core) = crate::core::core() {
        let _ = core.connectors_bound.set(f);
    }
}

/// The module is off, but a store from when it ran may still be on disk with agents in it: read
/// once, as nothing changes it while the module is off (the TS counts none).
fn off_count(app: &App, path: &std::path::Path) -> Option<usize> {
    if !path.exists() {
        return Some(0);
    }
    let s = store::load(path, &app.box_key, &app.config.org_id, &app.config.box_id);
    (!cc_crypto::store_health::is_store_unreadable(store::STORE)).then_some(store::agents_with_connections(&s))
}

pub fn register(reg: &mut Registry, app: &Arc<App>, env: &Env, shared: &Shared) {
    let path = PathBuf::from(env.get("CONNECTOR_STORE_PATH", "/opt/controlclaw/state/connectors.enc"));
    let url = env.get("CONNECTOR_URL", "");
    let admin = env.get("CONNECTOR_ADMIN_TOKEN", "");
    let (bind, also) = super::gate_binds(app, env.gate_bind());
    if !url.is_empty() && !admin.is_empty() && bind.is_empty() {
        // Without a private address there is nothing an agent box could dial.
        tracing::error!(
            "[mitm-agent] CONNECTOR_GATE_BIND/PRIVATE_IP unset: integrations stay off (there is no address to give the agent boxes)"
        );
        let n = off_count(app, &path);
        set_connectors_bound(Arc::new(move || n));
        return;
    }
    if url.is_empty() || admin.is_empty() {
        tracing::info!("[mitm-agent] no connector runtime on this box (CONNECTOR_URL unset); integrations are off");
        let n = off_count(app, &path);
        set_connectors_bound(Arc::new(move || n));
        return;
    }
    let port: u16 = env.num("CONNECTOR_GATE_PORT", 3900);
    let runtime = runtime::ConnectorRuntime::new(&url, &admin);
    let fw = firewall::ConnectorsFirewall::new(app, path, runtime.clone(), format!("http://{bind}:{port}"));
    let f = fw.clone();
    set_connectors_bound(Arc::new(move || {
        (!cc_crypto::store_health::is_store_unreadable(store::STORE)).then(|| f.agents_with_connections())
    }));
    // `connectors`: the module is running on this firewall.
    super::feature(app, "connectors", || true);
    let (connections, agents) = fw.summary();
    tracing::info!(
        "[mitm-agent] connector store loaded ({connections} connection(s), {agents} agent(s), runtime {url})"
    );
    for action in ACTIONS {
        let fw = fw.clone();
        reg.commands.handle(&format!("connectors.{action}"), move |p| {
            let fw = fw.clone();
            async move { fw.handle(action, p).await }
        });
    }

    // The gate is what the agent boxes dial; the runtime never leaves loopback.
    // `new URL(CONNECTOR_URL)`: its host, and its port or 80.
    let target = match url::Url::parse(&url) {
        Ok(u) if u.host_str().is_some() => (
            u.host_str().unwrap_or_default().trim_matches(['[', ']']).to_string(),
            u.port().unwrap_or(80),
        ),
        _ => {
            tracing::error!("[connectors] CONNECTOR_URL {url} is not an address: the connector gate is off");
            return;
        }
    };
    let calls_log = env.get(
        "CONNECTOR_CALLS_PATH",
        "/opt/controlclaw/mitm/logs/connector-calls.jsonl",
    );
    let resolver = fw.clone();
    let gate = gate::Gate::new(gate::GateOptions {
        target,
        resolve: Arc::new(move |t| resolver.agent_for_runtime_token(t)),
        rules: shared.rules.clone(),
        content: shared.content.clone(),
        asks: shared.asks.clone(),
        locked: shared.locked.clone(),
        log_path: Some(PathBuf::from(&calls_log)),
        ask_state_path: Some(PathBuf::from(
            env.get("CONNECTOR_ASKS_PATH", "/opt/controlclaw/state/connector-asks.json"),
        )),
        app_name: None,
        grant_wait_ms: crate::integrations::call_asks::GRANT_WAIT_MS,
    });
    let router = Arc::new(gate.router());
    if let Some(t) = also {
        let line = format!("[mitm-agent] connector gate also listening on {t}:{port} (the tunnel)");
        super::serve_gate(app, t, port, router.clone(), line, "[connectors] gate:", None);
    }
    let line = format!("[mitm-agent] connector gate listening on {bind}:{port} (the execution routes only)");
    super::serve_gate(app, bind, port, router, line, "[connectors] gate:", None);

    // The gate's own line per call, merged in the console with the run log's row for the same run.
    crate::core::activity::ship_log(&calls_log, Arc::new(crate::core::activity::connector_call_activity));

    let activity = env.get("ACTIVITY_URL", "");
    if !activity.is_empty() {
        let by_token = fw.clone();
        let shipper = Arc::new(runs::RunShipper::new(
            runtime,
            app.console.clone(),
            activity,
            Arc::new(move |id| by_token.agent_for_token(id)),
            PathBuf::from(env.get(
                "CONNECTOR_RUNS_STATE_PATH",
                "/opt/controlclaw/state/connector-runs.json",
            )),
        ));
        let every = Duration::from_millis(env.num("CONNECTOR_RUNS_POLL_MS", 30_000));
        tokio::spawn(async move {
            loop {
                shipper.tick().await;
                tokio::time::sleep(every).await;
            }
        });
        tracing::info!("[mitm-agent] connector run shipper enabled");
    }
}

#[cfg(test)]
mod restore_tests {
    use super::*;

    #[test]
    fn with_the_module_off_a_store_left_on_disk_still_counts() {
        let d = tempfile::tempdir().expect("dir");
        let app = crate::integrations::testing::app(d.path());
        let path = d.path().join("connectors.enc");
        assert_eq!(off_count(&app, &path), Some(0), "no store: nothing bound");
        let held: store::ConnectorStore =
            serde_json::from_value(serde_json::json!({"version": 1, "connections": {}, "agents": {"vm_1": {"connections": ["c1"]}, "vm_2": {}}}))
                .expect("store");
        store::save(&path, &held, &app.box_key, &app.config.org_id, &app.config.box_id).expect("save");
        assert_eq!(
            off_count(&app, &path),
            Some(1),
            "an entry whose connections were removed is not counted"
        );
        std::fs::write(&path, "not a store").expect("write");
        assert_eq!(off_count(&app, &path), None, "a store that does not read is a refusal");
        // Store health is process-wide: leave it as the other tests expect it.
        cc_crypto::store_health::note_store_readable(store::STORE);
    }
}
