//! The organization's MCP servers on this agent (`mcp-servers.ts`, `routes/mcp-servers.ts`): one
//! `mcp.servers.<name>` entry per server, at the firewall's gate for it, and only the entries this
//! box wrote are ever removed. No secret comes here: the gate knows this agent by its address.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use cc_http::{FirewallBody, Router, send_json};
use cc_openclaw::config_queue::PatchOptions;
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{CONFIG_PATCH_RESTART, Caller, Deps, GATEWAY_READ, PRIVATE_IP, at, caller, fail, lock, not_found};
use super::time::{iso_ms, now_ms};
use crate::app::App;
use crate::stages;

static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,39}$").expect("regex"));
const MAX_SERVERS: usize = 100;
/// W8's brain entry (`BRAIN_MCP_NAME` in brain-mcp.ts).
const BRAIN_MCP_NAME: &str = "gbrain";
/// Keys a plain JavaScript object already has: `s.name in {}` refuses them.
const OBJECT_KEYS: [&str; 12] = [
    "constructor",
    "__proto__",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toLocaleString",
    "toString",
    "valueOf",
    "__defineGetter__",
    "__defineSetter__",
    "__lookupGetter__",
    "__lookupSetter__",
];

/// The firewall's MCP gate (3940): an unmanaged agent writes its servers there only.
pub const MCP_GATE_PORT: u16 = 3940;

#[derive(Debug, Clone, PartialEq)]
pub struct Managed {
    pub name: String,
    pub url: String,
}

/// `parseMcpApply`: each address must be the firewall's gate for that server, and `firewall_ip`,
/// when known, its host. An unmanaged agent passes `gate`, where OpenClaw reaches its firewall
/// (the tunnel's address, a container's gate): the firewall's IPv4 address is then any, and the
/// address written is the same gate path on `gate`.
pub fn parse_apply(
    body: &Map<String, Value>,
    firewall_ip: Option<&str>,
    gate: Option<std::net::Ipv4Addr>,
) -> Result<Vec<Managed>, String> {
    let Some(raw) = body.get("servers").and_then(Value::as_array) else {
        return Err("servers is required".into());
    };
    if raw.len() > MAX_SERVERS {
        return Err(format!("at most {MAX_SERVERS} servers"));
    }
    let mut out: Vec<Managed> = Vec::new();
    for s in raw {
        let name = s.get("name").and_then(Value::as_str);
        let Some(name) = name.filter(|n| {
            NAME_RE.is_match(n) && !n.starts_with("controlclaw") && *n != BRAIN_MCP_NAME && !OBJECT_KEYS.contains(n)
        }) else {
            return Err("servers[].name is invalid".into());
        };
        let Some(url) = s.get("url").and_then(Value::as_str) else {
            return Err("servers[].url is required".into());
        };
        let Ok(u) = url::Url::parse(url) else {
            return Err("servers[].url is not a URL".into());
        };
        let host = u.host_str().unwrap_or_default();
        // On the gate: the MCP gate's own port, nothing else on the firewall.
        let host_ok = match gate {
            Some(_) => host.parse::<std::net::Ipv4Addr>().is_ok() && u.port() == Some(MCP_GATE_PORT),
            None => PRIVATE_IP.is_match(host),
        };
        if u.scheme() != "http"
            || !host_ok
            || u.path() != format!("/servers/{name}/mcp")
            || u.query().is_some_and(|q| !q.is_empty())
            || !u.username().is_empty()
        {
            return Err("servers[].url must be the firewall's gate for that server".into());
        }
        // Checked when known: a missing or blank key file is not known.
        if gate.is_none()
            && let Some(ip) = firewall_ip.map(str::trim).filter(|ip| !ip.is_empty())
            && host != ip
        {
            return Err("servers[].url is not this agent's firewall".into());
        }
        if out.iter().any(|o| o.name == name) {
            return Err("servers[].name is listed twice".into());
        }
        let url = match gate {
            Some(g) => format!("http://{g}:{MCP_GATE_PORT}{}", u.path()),
            None => u.to_string(),
        };
        out.push(Managed { name: name.into(), url });
    }
    Ok(out)
}

fn read_names(path: &Path) -> (Vec<String>, String) {
    let Some(v) = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return (Vec::new(), String::new());
    };
    let names = v
        .get("names")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|n| n.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    (
        names,
        v.get("updatedAt").and_then(Value::as_str).unwrap_or_default().into(),
    )
}

fn write_names(path: &Path, names: &[String]) -> std::io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let body = json!({ "names": names, "updatedAt": iso_ms(now_ms()) });
    cc_store::write_atomic(path, body.to_string().as_bytes(), 0o600, cc_store::TmpName::Suffix)
}

pub struct McpServersService {
    deps: Deps,
    state_path: PathBuf,
    owned: std::sync::Mutex<Vec<String>>,
    turn: tokio::sync::Mutex<()>,
}

impl McpServersService {
    pub fn new(deps: Deps, state_path: PathBuf) -> Self {
        let owned = read_names(&state_path).0;
        Self {
            deps,
            state_path,
            owned: std::sync::Mutex::new(owned),
            turn: tokio::sync::Mutex::new(()),
        }
    }

    /// One apply at a time.
    pub async fn apply(&self, servers: &[Managed]) -> Result<Value, String> {
        let _turn = self.turn.lock().await;
        let w = self.deps.gateway()?;
        let raw = self.deps.call("config.get", json!({}), GATEWAY_READ).await?;
        // `snapshot.parsed?.mcp?.servers`: the file only, not the resolved config.
        let configured = at(&raw, &["parsed", "mcp", "servers"])
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let owned = lock(&self.owned).clone();
        let mut patch = Map::new();
        let mut replaced = Vec::new();
        for s in servers {
            let have = configured.get(&s.name);
            if have.is_some_and(super::llm::truthy) && !owned.contains(&s.name) {
                replaced.push(s.name.clone());
            }
            let extra: Vec<String> = have
                .and_then(Value::as_object)
                .map(|o| o.keys().filter(|k| *k != "url" && *k != "transport").cloned().collect())
                .unwrap_or_default();
            let url_same = have.and_then(|h| h.get("url")) == Some(&json!(s.url));
            let transport_same = have.and_then(|h| h.get("transport")) == Some(&json!("streamable-http"));
            if !url_same || !transport_same || !extra.is_empty() {
                let mut e = Map::new();
                e.insert("url".into(), json!(s.url));
                e.insert("transport".into(), json!("streamable-http"));
                for k in extra {
                    e.insert(k, Value::Null);
                }
                patch.insert(s.name.clone(), Value::Object(e));
            }
        }
        let wanted: Vec<&String> = servers.iter().map(|s| &s.name).collect();
        let removed: Vec<String> = owned
            .iter()
            .filter(|n| !wanted.contains(n) && configured.contains_key(*n))
            .cloned()
            .collect();
        for n in &removed {
            patch.insert(n.clone(), Value::Null);
        }
        // Before the write: a name about to be written is ours, one about to be removed is kept.
        let mut before: Vec<String> = owned
            .iter()
            .cloned()
            .chain(wanted.iter().map(|n| n.to_string()))
            .collect();
        before.sort();
        before.dedup();
        *lock(&self.owned) = before.clone();
        write_names(&self.state_path, &before).map_err(|e| e.to_string())?;
        if !patch.is_empty() {
            let mut opts = PatchOptions {
                snapshot: Some(raw.clone()),
                read_timeout: Some(GATEWAY_READ),
                ..PatchOptions::new(CONFIG_PATCH_RESTART)
            };
            opts.base_hash = raw
                .get("hash")
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .map(str::to_string);
            let mut p = Map::new();
            p.insert("mcp".into(), json!({ "servers": patch }));
            w.patch(&p, opts).await.map_err(|e| e.to_string())?;
        }
        let mut after: Vec<String> = wanted.iter().map(|n| n.to_string()).collect();
        after.sort();
        *lock(&self.owned) = after.clone();
        write_names(&self.state_path, &after).map_err(|e| e.to_string())?;
        if !patch.is_empty() {
            let mut line = format!("[mcp-servers] {} managed server(s)", servers.len());
            if !removed.is_empty() {
                line.push_str(&format!(", removed {}", removed.join(", ")));
            }
            if !replaced.is_empty() {
                line.push_str(&format!(", replaced the agent's own {}", replaced.join(", ")));
            }
            self.deps.log(&line);
        }
        Ok(json!({ "ok": true, "servers": after, "removed": removed, "replaced": replaced }))
    }

    pub async fn status(&self) -> Value {
        let current = match self.deps.call("config.get", json!({}), GATEWAY_READ).await {
            Ok(raw) => at(&raw, &["parsed", "mcp", "servers"])
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            Err(e) => {
                self.deps
                    .log(&format!("[mcp-servers] could not read the OpenClaw config: {e}"));
                Map::new()
            }
        };
        let updated = read_names(&self.state_path).1;
        let servers: Vec<Value> = lock(&self.owned)
            .iter()
            .map(|n| json!({ "name": n, "configured": current.contains_key(n) }))
            .collect();
        json!({ "servers": servers, "updatedAt": if updated.is_empty() { Value::Null } else { json!(updated) } })
    }
}

/// `/mcp-servers/*`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/mcp-servers/", move |req, _| {
        let app = app.clone();
        async move {
            let write = req.method() == Method::POST;
            let (parts, who) = caller(&app, req, "mcp-servers", 65_536).await;
            let Some(who) = who else {
                let error = if write {
                    "MCP server changes must come from the org firewall"
                } else {
                    "Unauthorized"
                };
                return send_json(401, &json!({ "error": error }));
            };
            let Some(service) = app.contracts.platform.get().and_then(|p| p.mcp_servers.get().cloned()) else {
                return send_json(
                    503,
                    &json!({ "ok": false, "error": "This box does not support managed MCP servers yet." }),
                );
            };
            let path = cc_http::pathname(&parts.uri.to_string());
            if path == "/mcp-servers/status" && parts.method == Method::GET {
                return send_json(200, &service.status().await);
            }
            if path == "/mcp-servers/apply" && write {
                let body = match who {
                    Caller::Firewall(FirewallBody::Json(b)) => b,
                    _ => return send_json(400, &json!({ "ok": false, "error": "Invalid JSON body" })),
                };
                let ip = app.keys.read("mitm_box_private_ip");
                let gate = app.unmanaged.as_ref().and_then(|u| u.file.firewall.gate);
                let servers = match parse_apply(&body, ip.as_deref(), gate) {
                    Ok(s) => s,
                    Err(e) => return send_json(400, &json!({ "ok": false, "error": e })),
                };
                return match service.apply(&servers).await {
                    Ok(v) => send_json(200, &v),
                    Err(e) => fail(&e, None),
                };
            }
            not_found()
        }
    });
}

#[cfg(test)]
mod tests {
    use cc_openclaw::config_queue::fake_config::{FakeConfigGateway, FakeOpenClawConfig};

    use super::super::llm::tests::rig;
    use super::*;

    fn url(n: &str) -> String {
        format!("http://10.0.0.2:3940/servers/{n}/mcp")
    }

    fn p(v: Value, ip: Option<&str>) -> Result<Vec<Managed>, String> {
        parse_apply(v.as_object().expect("o"), ip, None)
    }

    fn m(n: &str) -> Managed {
        Managed {
            name: n.into(),
            url: url(n),
        }
    }

    #[test]
    fn only_the_firewalls_gate_by_the_servers_own_name() {
        assert_eq!(
            p(
                json!({ "servers": [{ "name": "docs", "url": url("docs") }] }),
                Some("10.0.0.2")
            ),
            Ok(vec![m("docs")])
        );
        // A blank key file is not a known firewall: the check is skipped, as in the TS.
        assert_eq!(
            p(
                json!({ "servers": [{ "name": "docs", "url": url("docs") }] }),
                Some(" \n")
            ),
            Ok(vec![m("docs")])
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "docs", "url": url("docs") }] }),
                Some("10.0.0.9")
            )
            .is_err()
        );
        assert!(
            p(json!({ "servers": [{ "name": "docs", "url": url("other") }] }), None)
                .expect_err("e")
                .contains("gate for that server")
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "docs", "url": "https://evil.example/mcp" }] }),
                None
            )
            .expect_err("e")
            .contains("gate for that server")
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "docs", "url": url("docs") }] }),
                Some("10.0.0.9")
            )
            .expect_err("e")
            .contains("not this agent's firewall")
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "controlclaw-console", "url": url("controlclaw-console") }] }),
                None
            )
            .expect_err("e")
            .contains("name is invalid")
        );
        assert!(
            p(json!({ "servers": [{ "name": "gbrain", "url": url("gbrain") }] }), None)
                .expect_err("e")
                .contains("name is invalid")
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "constructor", "url": url("constructor") }] }),
                None
            )
            .expect_err("e")
            .contains("name is invalid")
        );
        assert!(
            p(
                json!({ "servers": [{ "name": "a", "url": url("a") }, { "name": "a", "url": url("a") }] }),
                None
            )
            .expect_err("e")
            .contains("twice")
        );
        assert!(p(json!({}), None).expect_err("e").contains("required"));
    }

    #[tokio::test]
    async fn apply_writes_removes_only_its_own_and_says_what_it_replaced() {
        let oc = FakeOpenClawConfig::new(
            json!({ "mcp": { "servers": { "mine": { "command": "npx" }, "docs": { "url": "https://agents-own.example/mcp", "headers": { "X-Key": "k" } }, "controlclaw-console": { "url": "http://10.0.0.2:3940/mcp" } } } }),
            None,
            false,
        );
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let r = rig(gw.clone());
        let svc = McpServersService::new(r.deps.clone(), r.dir.path().join("s.json"));
        let first = svc.apply(&[m("docs"), m("notes")]).await.expect("ok");
        assert_eq!(first["replaced"], json!(["docs"]));
        let servers = || oc.config()["mcp"]["servers"].clone();
        assert_eq!(
            servers()["docs"],
            json!({ "url": url("docs"), "transport": "streamable-http" })
        );
        let n = oc.state().patches.len();
        svc.apply(&[m("docs"), m("notes")]).await.expect("ok");
        assert_eq!(oc.state().patches.len(), n, "no change, no write");
        let second = svc.apply(&[m("notes")]).await.expect("ok");
        assert_eq!(second["removed"], json!(["docs"]));
        assert_eq!(servers()["mine"], json!({ "command": "npx" }));
        svc.apply(&[]).await.expect("ok");
        let mut keys: Vec<String> = servers().as_object().expect("o").keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["controlclaw-console", "mine"]);
        assert_eq!(svc.status().await["servers"], json!([]));
    }

    #[tokio::test]
    async fn a_removal_whose_write_fails_is_tried_again() {
        let oc = FakeOpenClawConfig::new(json!({ "mcp": { "servers": {} } }), None, false);
        let gw = Arc::new(FakeConfigGateway::new(oc.clone(), false));
        let r = rig(gw.clone());
        let svc = McpServersService::new(r.deps.clone(), r.dir.path().join("s.json"));
        svc.apply(&[m("jira")]).await.expect("ok");
        let once = std::sync::atomic::AtomicBool::new(true);
        gw.hook(move |method, _| {
            (method == "config.patch" && once.swap(false, std::sync::atomic::Ordering::SeqCst))
                .then(|| Err("the gateway went away".to_string()))
        });
        assert!(svc.apply(&[]).await.is_err());
        assert!(oc.config()["mcp"]["servers"].get("jira").is_some());
        let again = svc.apply(&[]).await.expect("ok");
        assert_eq!(again["removed"], json!(["jira"]));
        assert_eq!(oc.config()["mcp"]["servers"].get("jira"), None);
    }
}
