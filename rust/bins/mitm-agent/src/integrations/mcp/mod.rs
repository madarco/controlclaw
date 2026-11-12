//! MCP on the firewall: the organization's MCP servers (store, commands, OAuth, the client that
//! reads their tools), the tool catalog, the checks every tool call gets, the 8796 admission
//! service the proxy asks, and the server gate the 3940 listener hands `/servers/*` to.

pub mod admission;
pub mod calls;
pub mod catalog;
pub mod client;
pub mod oauth;
pub mod public;
pub mod server_gate;
pub mod servers;
pub mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::json;

use crate::app::{App, Registry};
use crate::integrations::{Env, Shared, as_map, outcome, tools_gate};

pub const SERVER_ACTIONS: &[&str] = &[
    "read", "propose", "confirm", "cancel", "callback", "tools", "push", "forget",
];

pub fn register(
    reg: &mut Registry,
    app: &Arc<App>,
    env: &Env,
    shared: &Shared,
    local: Option<Arc<dyn tools_gate::LocalTools>>,
) {
    // The 3940 gate is listening (`controlPlaneMcpGateUp`): the agent MCP, MCP server and website
    // logins words need it.
    let gate_up = Arc::new(AtomicBool::new(false));
    if local.is_some() {
        let up = gate_up.clone();
        super::feature(app, "logins", move || {
            super::access_ready() && up.load(Ordering::SeqCst)
        });
    }
    let (bind, also) = super::gate_binds(app, env.gate_bind());
    let firewall_url = app.config.firewall_url.clone();
    let cp_gate_port: u16 = env.num("CONTROLPLANE_MCP_GATE_PORT", tools_gate::CONTROLPLANE_MCP_GATE_PORT);
    let calls_log = PathBuf::from(env.get(
        "MCP_SERVER_CALLS_PATH",
        "/opt/controlclaw/mitm/logs/mcp-server-calls.jsonl",
    ));

    // One line per MCP tool call (the gate's and the proxy's), in Activity beside the app calls.
    crate::core::activity::ship_log(
        &calls_log.to_string_lossy(),
        Arc::new(crate::core::activity::connector_call_activity),
    );

    // MCP tool calls: the catalog of tools, and the one checker the gate and the proxy share.
    let catalog = catalog::McpCatalog::new(
        app,
        PathBuf::from(env.get("MCP_CATALOG_PATH", "/opt/controlclaw/state/mcp-catalog.enc")),
    );
    let checks = calls::McpCalls::new(
        shared,
        catalog.clone(),
        shared.asks.clone(),
        Some(calls_log.clone()),
        Some(PathBuf::from(
            env.get("MCP_ASKS_PATH", "/opt/controlclaw/state/mcp-asks.json"),
        )),
        None,
    );
    // The tools agents' MCP servers listed, for the Integrations rule dialog. Metadata only.
    // `mcpCalls && mcpCatalog`: both are made on every firewall.
    super::feature(app, "mcp_rules", || true);
    let c = catalog.clone();
    reg.commands.handle("mcpcatalog.read", move |_| {
        let c = c.clone();
        async move { outcome(true, "done", None, Some(as_map(json!({"servers": c.servers()})))) }
    });
    let admission = admission::Admission::new(checks.clone());
    let port: u16 = env.num("MCP_ADMISSION_PORT", admission::MCP_ADMISSION_PORT);
    let router = Arc::new(admission.router());
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => {
                tracing::info!("[mitm-agent] MCP admission on 127.0.0.1:{port}");
                cc_http::serve(l, router).await;
            }
            Err(e) => tracing::error!("[mcp-admission] unavailable; the proxy refuses MCP tool calls: {e}"),
        }
    });
    let a = admission.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            a.sweep();
        }
    });

    // The organization's MCP servers, served to agents through the 3940 listener.
    let mut mcp_servers = None;
    // A standalone firewall's control plane is its own panel: the OAuth sign-ins come back to it.
    let standalone = app.config.mode.standalone();
    if !bind.is_empty() && (!firewall_url.is_empty() || standalone) {
        let origin = if standalone {
            crate::core::local_cp::panel_origin()
        } else {
            url::Url::parse(&firewall_url)
                .map(|u| u.origin().ascii_serialization())
                .unwrap_or_default()
        };
        let fw = servers::McpServersFirewall::new(
            app,
            PathBuf::from(env.get("MCP_SERVERS_STORE_PATH", "/opt/controlclaw/state/mcp-servers.enc")),
            format!("http://{bind}:{cp_gate_port}{}", server_gate::SERVER_GATE_PREFIX),
            format!("{origin}/oauth/callback"),
        );
        let (n, agents) = fw.summary();
        tracing::info!("[mitm-agent] MCP servers loaded ({n} server(s), {agents} agent(s))");
        for action in SERVER_ACTIONS {
            let fw = fw.clone();
            reg.commands.handle(&format!("mcpservers.{action}"), move |p| {
                let fw = fw.clone();
                async move { fw.handle(action, p).await }
            });
        }
        mcp_servers = Some(fw);
        let up = gate_up.clone();
        super::feature(app, "mcp_servers", move || up.load(Ordering::SeqCst));
    }
    // Not on a standalone firewall: its gate has no ControlClaw MCP behind `/mcp`.
    let up = gate_up.clone();
    super::feature(app, "controlplane_mcp", move || {
        !standalone && up.load(Ordering::SeqCst)
    });

    // The ControlClaw tools gate: the agent MCP, the website logins tools and `/servers/*`.
    let uses_http = ["STORE_URL", "RULES_URL", "ACTIVITY_URL"]
        .iter()
        .any(|v| env.get(v, "").starts_with("http"))
        || firewall_url.starts_with("http");
    let over = env.get("CONTROLPLANE_MCP_URL", "");
    // A standalone firewall's gate serves its MCP servers (`/servers/*`) and the logins tools; the
    // ControlClaw MCP is the SaaS's, so the gate answers `/mcp` itself (an empty target: 404).
    let (cp_url, uses_http) = if standalone {
        (Some(String::new()), true)
    } else {
        (tools_gate::control_plane_mcp_url(&firewall_url, Some(&over)), uses_http)
    };
    match cp_url.filter(|_| !bind.is_empty() && uses_http) {
        Some(cp_url) => {
            let mut opts =
                server_gate::ServerGateOptions::new(mcp_servers.clone(), Some(checks), shared.locked.clone());
            opts.log_path = Some(calls_log);
            // A template's `managed: true` step. Only under a live grant from an apply for this
            // agent, never on an agent's word; with no grants on this build there is none.
            let a = app.clone();
            opts.give = Some(Arc::new(move |vm, name| {
                let (a, servers) = (a.clone(), mcp_servers.clone());
                Box::pin(async move {
                    let Some(servers) = servers else {
                        return (false, "This firewall does not serve MCP servers.".to_string());
                    };
                    let grants = a.contracts.mcp_grants.get();
                    if !grants.as_ref().is_some_and(|g| g.has(&vm, &name)) {
                        return (
                            false,
                            format!(
                                "Giving this agent the MCP server {name} needs an apply of a template that names it, and this agent has none running for it. Give it on the Integrations page, or apply the template from the console."
                            ),
                        );
                    }
                    let given = servers.give_under_consent(&vm, &name).await;
                    // Used only once it worked: a give that failed for a passing reason keeps its consent.
                    if given.0
                        && let Some(g) = grants
                    {
                        g.use_grant(&vm, &name);
                    }
                    given
                })
            }));
            let servers = server_gate::ServerGate::new(opts);
            let traffic = env.get("TRAFFIC_LOG_PATH", "");
            let gate = tools_gate::ToolsGate::new(
                app,
                cp_url.clone(),
                (!traffic.is_empty()).then(|| PathBuf::from(traffic)),
                shared.locked.clone(),
                local,
                Some(servers),
            );
            let _ = gate
                .ca
                .set(ca_answer(app, std::env::var("CA_CERT_PATH").unwrap_or_default()));
            if standalone {
                vm_agent_listeners(app, gate.clone(), cp_gate_port, bind.clone(), also.clone());
            }
            let router = Arc::new(gate.router());
            let to = if cp_url.is_empty() {
                "no ControlClaw MCP (/mcp answers 404)".to_string()
            } else {
                cp_url.clone()
            };
            if let Some(t) = also {
                let line =
                    format!("[mitm-agent] ControlClaw tools gate also listening on {t}:{cp_gate_port} (the tunnel)");
                super::serve_gate(app, t, cp_gate_port, router.clone(), line, "[cp-mcp] gate:", None);
            }
            let line = format!("[mitm-agent] ControlClaw tools gate listening on {bind}:{cp_gate_port} -> {to}");
            super::serve_gate(app, bind, cp_gate_port, router, line, "[cp-mcp] gate:", Some(gate_up));
        }
        None => tracing::info!("[mitm-agent] ControlClaw tools gate off (no private address or no control plane URL)"),
    }
}

/// A standalone firewall's agent can run in a container whose network its vm-agent is not on (`up
/// --all`): the vm-agent then reaches this firewall at another address, the one the firewall calls it
/// from. `/permission` is also served there, every 30 s for the agents paired since, and only to the
/// paired vm-agent's own address (`ToolsGate::permission_router`).
fn vm_agent_listeners(app: &Arc<App>, gate: Arc<tools_gate::ToolsGate>, port: u16, bind: String, also: Option<String>) {
    let app = app.clone();
    tokio::spawn(async move {
        let router = Arc::new(gate.permission_router());
        let mut bound: std::collections::HashSet<String> = [Some(bind), also].into_iter().flatten().collect();
        let mut every = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            every.tick().await;
            let Ok(ids) = app.contracts.identities.require() else {
                continue;
            };
            for a in ids.agents() {
                let Some(route) = ids.route_for(&a.vm_id) else { continue };
                let Some(local) = local_address_toward(&route.host) else {
                    continue;
                };
                if bound.insert(local.clone()) {
                    let line = format!("[mitm-agent] approvals from vm-agents also on {local}:{port}");
                    crate::integrations::serve_gate(
                        &app,
                        local,
                        port,
                        router.clone(),
                        line,
                        "[auto-approve] gate:",
                        None,
                    );
                }
            }
        }
    });
}

/// This machine's address on the way to `host` (a UDP socket's local address after `connect`; no
/// packet is sent). None for a loopback or unspecified answer.
fn local_address_toward(host: &str) -> Option<String> {
    let ip: std::net::IpAddr = host.parse().ok()?;
    let any: std::net::IpAddr = if ip.is_ipv4() {
        [0, 0, 0, 0].into()
    } else {
        std::net::Ipv6Addr::UNSPECIFIED.into()
    };
    let s = std::net::UdpSocket::bind((any, 0)).ok()?;
    s.connect((ip, 9)).ok()?;
    let local = s.local_addr().ok()?.ip();
    (!local.is_loopback() && !local.is_unspecified()).then(|| local.to_string())
}

/// `GET /ca` on the 3940 gate (`index.ts` `ca:`, main #564): this firewall's CA and its detached
/// signature by the box key, as published to the control plane. A box that confirms it installed
/// THIS CA (its sha256) is recorded for inspection (`core::cp_inspect`); a fetch alone, or a box
/// holding another CA, is not. None (404) without a CA.
pub(crate) fn ca_answer(app: &Arc<App>, path: String) -> tools_gate::CaAnswer {
    let app = app.clone();
    Arc::new(move |vm_id: &str, installed: Option<&str>| {
        if path.is_empty() {
            return Ok(None);
        }
        let Ok(cert) = std::fs::read_to_string(&path) else {
            return Ok(None);
        };
        // Signed first: a box is recorded only with an answer it can check.
        let sig = crate::core::keys::sign_detached(&app.config.keys_dir, &cert)?;
        if installed.is_some_and(|i| i == hex::encode(<sha2::Sha256 as sha2::Digest>::digest(cert.as_bytes())))
            && app.cp_inspect.add(vm_id)
        {
            tracing::info!(
                "[cp-inspect] {vm_id} trusts this firewall's CA; its control-plane traffic is inspected from now on"
            );
        }
        Ok(Some(serde_json::json!({"caCert": cert, "caSig": sig})))
    })
}
