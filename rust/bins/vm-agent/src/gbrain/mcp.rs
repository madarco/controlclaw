//! The organization's brain in this agent's OpenClaw config (`brain-mcp.ts`, `routes/gbrain.ts`,
//! docs/plans/gbrain.md §5): `POST /gbrain/apply` on an agent box.
//!
//! One entry, `mcp.servers.gbrain`, pointing at the brain's gate on the private network. It carries
//! no secret: the gate knows this box by its address and adds this agent's token itself. The
//! firewall is the only writer (its pinned key, purpose `gbrain`), after the owner confirmed the
//! connection with a code; a removal needs no code and comes the same way.
//!
//! An unmanaged agent (a standalone firewall's, `UNMANAGED.md`) has no private network shared with
//! the brain: its entry is the firewall's tools gate, `http://<firewall.gate>:3940/brain/mcp`, which
//! relays each call to the brain (docs/plans/standalone-brain.md B).

use std::sync::Arc;

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, firewall_request, send_json};
use cc_openclaw::PatchOptions;
use serde_json::{Map, Value, json};

use crate::app::App;
use crate::platform::common::{CONFIG_PATCH_RESTART, Deps, GATEWAY_READ};
use crate::stages;

pub const BRAIN_MCP_NAME: &str = "gbrain";
/// The brain's path on the firewall's tools gate (3940), for an unmanaged agent.
pub const GATE_BRAIN_PATH: &str = "/brain/mcp";

/// `http://<private IPv4>:3131/mcp`, and nothing else: a URL is all this entry is.
fn brain_url(u: &str) -> bool {
    u.strip_prefix("http://")
        .and_then(|r| r.strip_suffix(":3131/mcp"))
        .is_some_and(super::gate::is_private_ip)
}

/// What the firewall asks for: the brain's address, or its removal.
#[derive(Debug, Clone, PartialEq)]
pub enum BrainApply {
    Url(String),
    Remove,
}

/// `parseBrainApply`: the input, or the 400's message.
#[cfg(test)]
pub fn parse_brain_apply(body: Option<&Map<String, Value>>) -> Result<BrainApply, &'static str> {
    parse_brain_apply_at(body, None)
}

/// `http://<IPv4>:3940/brain/mcp`, and nothing else: the firewall's tools gate, at the address
/// the firewall has for itself.
fn gate_url(u: &str) -> bool {
    u.strip_prefix("http://")
        .and_then(|r| {
            r.strip_suffix(&format!(
                ":{}{GATE_BRAIN_PATH}",
                crate::platform::mcp_servers::MCP_GATE_PORT
            ))
        })
        .is_some_and(|h| h.parse::<std::net::Ipv4Addr>().is_ok())
}

/// [`parse_brain_apply`] for an agent with a firewall `gate` (unmanaged): only the tools gate's
/// brain path is taken, and it is written on `gate`, where OpenClaw reaches its firewall. Without
/// one, only the brain's private 10.x address, as on a managed box.
pub fn parse_brain_apply_at(
    body: Option<&Map<String, Value>>,
    gate: Option<std::net::Ipv4Addr>,
) -> Result<BrainApply, &'static str> {
    let body = body.ok_or("a JSON body is required")?;
    if body.get("remove") == Some(&json!(true)) {
        return Ok(BrainApply::Remove);
    }
    let url = body.get("url").and_then(Value::as_str);
    match gate {
        None => match url {
            Some(u) if brain_url(u) => Ok(BrainApply::Url(u.to_string())),
            _ => Err("url must be the brain's private address (http://10.x.x.x:3131/mcp)"),
        },
        Some(g) => match url {
            Some(u) if gate_url(u) => Ok(BrainApply::Url(format!(
                "http://{g}:{}{GATE_BRAIN_PATH}",
                crate::platform::mcp_servers::MCP_GATE_PORT
            ))),
            _ => Err("url must be the firewall's gate for the brain (http://<firewall>:3940/brain/mcp)"),
        },
    }
}

/// `BrainMcpService.apply`: `{ok, configured, changed}`.
#[cfg(test)]
pub async fn apply(deps: &Deps, input: &BrainApply) -> Result<Value, String> {
    apply_tidy(deps, input, false).await
}

/// [`apply`]; with `tidy` (an unmanaged agent, whose config is the owner's), a removal that leaves
/// `mcp` holding nothing but an empty `servers` takes `mcp` away too, so the config is as it was
/// before the brain was switched on.
pub async fn apply_tidy(deps: &Deps, input: &BrainApply, tidy: bool) -> Result<Value, String> {
    let writer = deps.gateway()?;
    let entry = match input {
        BrainApply::Remove => Value::Null,
        BrainApply::Url(u) => json!({"url": u, "transport": "streamable-http"}),
    };
    let snapshot = deps.call("config.get", json!({}), GATEWAY_READ).await?;
    let current = snapshot.pointer(&format!("/parsed/mcp/servers/{BRAIN_MCP_NAME}/url"));
    // Already so: a config write restarts OpenClaw's gateway, so do not make one for nothing. Only
    // for adding: a removal is always written, since a disconnect once found no entry in the
    // gateway's view while the file still had one.
    if let BrainApply::Url(u) = input
        && current == Some(&json!(u))
    {
        return Ok(json!({"ok": true, "configured": true, "changed": false}));
    }
    let only_ours = snapshot
        .pointer("/parsed/mcp")
        .and_then(Value::as_object)
        .is_some_and(|m| {
            m.len() == 1
                && m.get("servers")
                    .and_then(Value::as_object)
                    .is_some_and(|s| s.keys().all(|k| k == BRAIN_MCP_NAME))
        });
    let mut opts = PatchOptions::new(CONFIG_PATCH_RESTART);
    opts.base_hash = snapshot
        .get("hash")
        .and_then(Value::as_str)
        .filter(|h| !h.is_empty())
        .map(String::from);
    opts.snapshot = Some(snapshot);
    opts.read_timeout = Some(GATEWAY_READ);
    let patch = if tidy && *input == BrainApply::Remove && only_ours {
        json!({"mcp": null})
    } else {
        json!({"mcp": {"servers": {BRAIN_MCP_NAME: entry}}})
    };
    writer
        .patch(patch.as_object().expect("object"), opts)
        .await
        .map_err(|e| e.to_string())?;
    Ok(json!({"ok": true, "configured": matches!(input, BrainApply::Url(_)), "changed": true}))
}

/// `handleGbrain` on an agent box, in the prefixed groups (index.ts dispatch).
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/gbrain/", move |req, _| {
        let app = app.clone();
        async move {
            let path = cc_http::pathname(&req.uri().to_string());
            if path != "/gbrain/apply" || req.method() != hyper::Method::POST {
                return send_json(404, &json!({"error": "Not found"}));
            }
            let read = ReadBody::Json {
                limit: crate::platform::common::BODY_LIMIT,
            };
            let body = match firewall_request(&app.firewall_auth, req, "gbrain", 0, read).await {
                FirewallRequest::Refused { .. } => {
                    return send_json(401, &json!({"error": "brain changes must come from the org firewall"}));
                }
                FirewallRequest::Accepted { body, .. } => body,
            };
            let body = match &body {
                FirewallBody::Json(m) => Some(m),
                _ => None,
            };
            // An unmanaged agent writes the brain on its firewall's gate, and needs one.
            let unmanaged = app.unmanaged.is_some();
            let gate = app.unmanaged.as_ref().and_then(|u| u.file.firewall.gate);
            if unmanaged && gate.is_none() && body.is_some_and(|b| b.get("remove") != Some(&json!(true))) {
                return send_json(
                    503,
                    &json!({"ok": false, "error": "This agent has no firewall gate in its config (firewall.gate): connect it again with controlclaw connect."}),
                );
            }
            let input = match parse_brain_apply_at(body, gate) {
                Ok(i) => i,
                Err(e) => return send_json(400, &json!({"ok": false, "error": e})),
            };
            match apply_tidy(&Deps::of(&app), &input, unmanaged).await {
                Ok(mut r) => {
                    // Without the brain there is nothing to save to: the switch goes off with it.
                    // (An unmanaged agent never has it: no `cc-instructions` there.)
                    if input == BrainApply::Remove && !unmanaged {
                        super::capture::disable(&app);
                    }
                    tracing::info!(
                        "[gbrain] {} the organization's brain",
                        if r["configured"] == true {
                            "connected to"
                        } else {
                            "disconnected from"
                        }
                    );
                    r["applied"] = json!([]);
                    send_json(200, &r)
                }
                Err(e) => {
                    let lower = e.to_lowercase();
                    send_json(
                        if lower.contains("not running") { 503 } else { 500 },
                        &json!({"ok": false, "error": e}),
                    )
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
