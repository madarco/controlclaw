//! What the firewall has learned about the MCP servers its agents use (`mcp-catalog.ts`,
//! docs/plans/mcp-inspection.md §5): per server host, its tools as `tools/list` answers named them,
//! which agents listed them, and each tool's kind. Metadata only. The console reads it for the
//! Integrations rule dialog (`mcpcatalog.read`); the rules read a tool's kind.
//!
//! A tool's kind comes from its annotations when the server gives them; otherwise the AI labels the
//! tool once, keyed by host, name and a hash of its description and argument names. A tool with no
//! kind acts as destructive.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::client::{TOOL_NAME, cut};
use crate::app::App;
use crate::integrations::apps_rules::schema::AppOperation;
use crate::integrations::js;
use crate::integrations::ordmap::OrdMap;

pub const CATALOG_HOSTS_MAX: usize = 200;
pub const CATALOG_TOOLS_MAX: usize = 500;
const AGENTS_MAX: usize = 100;
/// Labels the AI is asked for at once.
const LABEL_BATCH: usize = 20;
/// Labels kept, one per tool shape: the oldest go first.
const LABELS_MAX: usize = 20_000;
/// A tool the AI could not label is not asked about again for this long.
const LABEL_RETRY_MS: i64 = 60 * 60_000;
const SAVE_AFTER: Duration = Duration::from_secs(3);

/// The kind an MCP server's own hints give a tool, or None when they say nothing.
pub fn kind_from_annotations(a: Option<&Value>) -> Option<AppOperation> {
    let a = a?;
    if a.get("readOnlyHint") == Some(&Value::Bool(true)) {
        return Some(AppOperation::Read);
    }
    match a.get("destructiveHint") {
        Some(Value::Bool(true)) => Some(AppOperation::Destructive),
        Some(Value::Bool(false)) => Some(AppOperation::Write),
        _ => None,
    }
}

/// A tool of an MCP server every agent uses without anyone adding it: ControlClaw's default web
/// search, Parallel's free Search MCP (OpenClaw's `parallel-free`). The plugin never lists the tools,
/// so the server's own hints never reach the catalog; these are those hints, as Parallel gives them.
/// A rule on `mcp:search.parallel.ai` still decides over them: only the seeded rule reads the kind.
pub struct Builtin {
    pub kind: AppOperation,
    /// Arguments made fresh for every call, left out of the call's key so a retry is the same call.
    pub per_call: &'static [&'static str],
}

const PARALLEL_SEARCH: &str = "search.parallel.ai";

pub fn builtin(host: &str, tool: &str) -> Option<Builtin> {
    if host != PARALLEL_SEARCH {
        return None;
    }
    match tool {
        // The plugin puts a new random `session_id` in every search. Not `web_fetch`: Parallel
        // fetches any address for it, outside the Internet access rules, so it keeps the default.
        "web_search" => Some(Builtin {
            kind: AppOperation::Read,
            per_call: &["session_id"],
        }),
        "send_feedback" => Some(Builtin {
            kind: AppOperation::Write,
            per_call: &[],
        }),
        _ => None,
    }
}

/// The input a call's key is made from: the call's arguments without the built-in ones made per call.
pub fn key_input(host: &str, tool: &str, args: &Value) -> Value {
    let (Some(b), Value::Object(o)) = (builtin(host, tool), args) else {
        return args.clone();
    };
    Value::Object(
        o.iter()
            .filter(|(k, _)| !b.per_call.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    )
}

/// One tool of a `tools/list` answer, cleaned, in the TS's key order (without `kind`/`kindBy`).
pub fn clean_listed_tool(raw: &Value) -> Option<Map<String, Value>> {
    let t = raw.as_object()?;
    let name = t.get("name")?.as_str().filter(|n| TOOL_NAME.is_match(n))?;
    let a = t.get("annotations").and_then(Value::as_object);
    let mut annotations = Map::new();
    for k in ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] {
        if let Some(b) = a.and_then(|a| a.get(k)).and_then(Value::as_bool) {
            annotations.insert(k.into(), json!(b));
        }
    }
    let argument_names: Vec<Value> = t
        .get("inputSchema")
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
        .map(|p| p.keys().take(50).map(|k| json!(cut(k, 64))).collect())
        .unwrap_or_default();
    let description = t.get("description").and_then(Value::as_str).map(|d| cut(d, 500));
    let shape = hex::encode(Sha256::digest(
        js::stringify(&json!([description, argument_names])).as_bytes(),
    ));
    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    out.insert(
        "title".into(),
        t.get("title")
            .and_then(Value::as_str)
            .map(|s| json!(cut(s, 120)))
            .unwrap_or(Value::Null),
    );
    out.insert("description".into(), json!(description));
    out.insert("annotations".into(), Value::Object(annotations));
    out.insert("argumentNames".into(), Value::Array(argument_names));
    out.insert("shape".into(), json!(&shape[..24]));
    Some(out)
}

fn label_key(host: &str, name: &str, shape: &str) -> String {
    format!("{host}\u{0}{name}\u{0}{shape}")
}

struct State {
    /// host → the server as the store keeps it (JSON, every field kept).
    servers: OrdMap<Map<String, Value>>,
    labels: OrdMap<String>,
    extra: Map<String, Value>,
    /// label key → when the AI last could not label it, and under which accepted AI.
    unlabelled: HashMap<String, (i64, String)>,
    dirty: bool,
}

pub struct McpCatalog {
    app: Arc<App>,
    path: PathBuf,
    aad: String,
    state: Mutex<State>,
    labelling: tokio::sync::Mutex<()>,
}

impl McpCatalog {
    pub fn new(app: &Arc<App>, path: PathBuf) -> Arc<Self> {
        let aad = format!("{}:{}:mcp-catalog", app.config.org_id, app.config.box_id);
        let log = |l: &str| tracing::info!("{l}");
        let stored = cc_crypto::enc_file::load_store_or_empty("mcp-catalog", &path, &app.box_key, &aad, &log);
        let mut servers = OrdMap::new();
        let mut labels = OrdMap::new();
        let mut extra = Map::new();
        if let Some(s) = stored.filter(|s| s.get("version") == Some(&json!(1))) {
            if let Some(o) = s.get("servers").and_then(Value::as_object) {
                for (k, v) in o {
                    if let Some(v) = v.as_object() {
                        servers.insert(k.clone(), v.clone());
                    }
                }
            }
            if let Some(o) = s.get("labels").and_then(Value::as_object) {
                for (k, v) in o {
                    if let Some(v) = v.as_str().filter(|v| AppOperation::parse(v).is_some()) {
                        labels.insert(k.clone(), v.to_string());
                    }
                }
            }
            if let Some(o) = s.as_object() {
                extra = o
                    .iter()
                    .filter(|(k, _)| !["version", "servers", "labels"].contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
            }
        }
        Arc::new(Self {
            app: app.clone(),
            path,
            aad,
            state: Mutex::new(State {
                servers,
                labels,
                extra,
                unlabelled: HashMap::new(),
                dirty: false,
            }),
            labelling: tokio::sync::Mutex::new(()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn save_now(&self) {
        let value = {
            let mut st = self.lock();
            st.dirty = false;
            let mut v = Map::new();
            v.insert("version".into(), json!(1));
            v.insert("servers".into(), serde_json::to_value(&st.servers).unwrap_or(json!({})));
            v.insert("labels".into(), serde_json::to_value(&st.labels).unwrap_or(json!({})));
            v.extend(st.extra.clone());
            Value::Object(v)
        };
        if let Err(e) = cc_crypto::enc_file::save_store("mcp-catalog", &self.path, &value, &self.app.box_key, &self.aad)
        {
            tracing::info!("[mcp-catalog] could not save: {}", e.0);
        }
    }

    /// Agents list tools often: one write a few seconds later, not one per answer.
    fn save_soon(self: &Arc<Self>) {
        {
            let mut st = self.lock();
            if st.dirty {
                return;
            }
            st.dirty = true;
        }
        let me = self.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move {
                tokio::time::sleep(SAVE_AFTER).await;
                me.save_now();
            });
        }
    }

    /// A `tools/list` answer an agent got from `host` (one page of it).
    pub fn listed(self: &Arc<Self>, vm_id: &str, host: &str, raw_tools: &[Value], managed: Option<&str>) {
        let tools: Vec<Map<String, Value>> = raw_tools.iter().filter_map(clean_listed_tool).collect();
        let iso = js::iso(js::now_ms());
        {
            let mut st = self.lock();
            if !st.servers.contains_key(host) {
                if st.servers.len() >= CATALOG_HOSTS_MAX {
                    // The server no agent listed for longest makes room.
                    let oldest = st
                        .servers
                        .iter()
                        .min_by(|a, b| {
                            let u = |m: &Map<String, Value>| {
                                m.get("updatedAt").and_then(Value::as_str).unwrap_or("").to_string()
                            };
                            u(a.1).cmp(&u(b.1))
                        })
                        .map(|(k, _)| k.clone());
                    if let Some(k) = oldest {
                        st.servers.remove(&k);
                    }
                }
                let s = json!({"host": host, "managed": managed, "serverName": null, "tools": [], "agents": {}, "updatedAt": ""});
                st.servers
                    .insert(host.to_string(), s.as_object().cloned().unwrap_or_default());
            }
            let labels: Vec<Option<String>> = tools
                .iter()
                .map(|t| {
                    let key = label_key(
                        host,
                        t["name"].as_str().unwrap_or(""),
                        t["shape"].as_str().unwrap_or(""),
                    );
                    st.labels.get(&key).cloned()
                })
                .collect();
            let Some(s) = st.servers.get_mut(host) else { return };
            if let Some(m) = managed {
                s.insert("managed".into(), json!(m));
            }
            let mut list = s.get("tools").and_then(Value::as_array).cloned().unwrap_or_default();
            for (t, label) in tools.into_iter().zip(labels) {
                let hints = kind_from_annotations(t.get("annotations"));
                let mut next = t.clone();
                let kind = hints.map(|k| k.as_str().to_string()).or(label.clone());
                next.insert("kind".into(), json!(kind));
                next.insert(
                    "kindBy".into(),
                    match (hints, label) {
                        (Some(_), _) => json!("annotation"),
                        (None, Some(_)) => json!("ai"),
                        _ => Value::Null,
                    },
                );
                match list.iter().position(|x| x["name"] == next["name"]) {
                    Some(i) => list[i] = Value::Object(next),
                    None if list.len() < CATALOG_TOOLS_MAX => list.push(Value::Object(next)),
                    None => {}
                }
            }
            s.insert("tools".into(), Value::Array(list));
            let mut agents: Vec<(String, Value)> = s
                .get("agents")
                .and_then(Value::as_object)
                .map(|a| a.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            agents.retain(|(k, _)| k != vm_id);
            agents.push((vm_id.to_string(), json!(iso)));
            agents.sort_by(|a, b| b.1.as_str().unwrap_or("").cmp(a.1.as_str().unwrap_or("")));
            agents.truncate(AGENTS_MAX);
            s.insert("agents".into(), Value::Object(agents.into_iter().collect()));
            s.insert("updatedAt".into(), json!(iso));
        }
        self.save_soon();
        let me = self.clone();
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            rt.spawn(async move { me.label_missing().await });
        }
    }

    /// The kind the rules use for a tool: its hints, the AI's label, or None (acts as destructive).
    /// A tool's kind: what its server or the AI said, else what this firewall knows of a built-in one.
    pub fn kind_of(&self, host: &str, tool: &str) -> Option<AppOperation> {
        let listed = {
            let st = self.lock();
            st.servers
                .get(host)
                .and_then(|s| s.get("tools")?.as_array()?.iter().find(|t| t["name"] == tool).cloned())
                .and_then(|t| t.get("kind").and_then(Value::as_str).and_then(AppOperation::parse))
        };
        listed.or_else(|| builtin(host, tool).map(|b| b.kind))
    }

    pub fn servers(&self) -> Vec<Value> {
        self.lock().servers.values().map(|s| Value::Object(s.clone())).collect()
    }

    /// Ask the AI about tools with no kind, a few at a time, one batch running at once (a second
    /// call waits for it).
    pub async fn label_missing(self: &Arc<Self>) {
        let Some(judge) = self.app.contracts.judge.get() else {
            return;
        };
        let _one = self.labelling.lock().await;
        let epoch = judge.label_epoch();
        let now = js::now_ms();
        let todo: Vec<(String, Map<String, Value>)> = {
            let st = self.lock();
            let tried = |key: &str| {
                st.unlabelled
                    .get(key)
                    .is_some_and(|(at, e)| *e == epoch && now - at < LABEL_RETRY_MS)
            };
            let mut todo = Vec::new();
            for (host, s) in st.servers.iter() {
                for t in s.get("tools").and_then(Value::as_array).into_iter().flatten() {
                    let Some(t) = t.as_object() else { continue };
                    let key = label_key(
                        host,
                        t["name"].as_str().unwrap_or(""),
                        t["shape"].as_str().unwrap_or(""),
                    );
                    if t.get("kind").is_none_or(Value::is_null) && todo.len() < LABEL_BATCH && !tried(&key) {
                        todo.push((host.clone(), t.clone()));
                    }
                }
            }
            todo
        };
        let mut labelled = 0;
        for (host, tool) in todo {
            let name = tool["name"].as_str().unwrap_or("").to_string();
            let key = label_key(&host, &name, tool["shape"].as_str().unwrap_or(""));
            let args: Vec<String> = tool
                .get("argumentNames")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            let kind = judge
                .label_tool(&host, &name, tool.get("description").and_then(Value::as_str), &args)
                .await
                .filter(|k| AppOperation::parse(k).is_some());
            let mut st = self.lock();
            // No answer: this tool stays unknown, acting as destructive, and is not asked about
            // again for an hour. The others still are.
            let Some(kind) = kind else {
                st.unlabelled.insert(key, (js::now_ms(), epoch.clone()));
                continue;
            };
            st.labels.insert(key, kind.clone());
            let first = (st.labels.len() > LABELS_MAX)
                .then(|| st.labels.keys().next().cloned())
                .flatten();
            if let Some(first) = first {
                st.labels.remove(&first);
            }
            if st.unlabelled.len() > LABELS_MAX {
                st.unlabelled.clear();
            }
            if let Some(s) = st.servers.get_mut(&host)
                && let Some(list) = s.get_mut("tools").and_then(Value::as_array_mut)
                && let Some(t) = list.iter_mut().find(|t| t["name"] == name.as_str())
            {
                t["kind"] = json!(kind);
                t["kindBy"] = json!("ai");
            }
            labelled += 1;
        }
        if labelled > 0 {
            self.save_soon();
        }
    }
}
