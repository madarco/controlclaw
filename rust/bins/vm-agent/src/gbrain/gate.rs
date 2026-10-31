//! The gate agents reach the organization's brain through (`gbrain-gate.ts`, docs/plans/gbrain.md
//! §5).
//!
//! GBrain listens on loopback only. This listener is on the brain's private address, port 3131,
//! and forwards `/mcp` and nothing else to it. It knows each connected agent by its private address
//! and adds that agent's GBrain token to every request from it, replacing whatever `Authorization`
//! the request carried. So an agent holds no secret at all: its MCP config is a bare URL that works
//! only from the agent's own address. An address the gate does not know gets a 403.
//!
//! The tokens are minted and revoked here (`cc-gbrain-token`, a root helper), kept in
//! `gbrain-gate.json` in the state directory (inside the encrypted container), and never sent
//! anywhere. Only the org firewall adds or removes an entry (`POST /gbrain/connect|disconnect`).
//!
//! The emergency stop is a lock on top (`POST /gbrain/lock {all, vmIds}`): a locked agent keeps its
//! entry and token and gets a 403 until the stop is released, so releasing it needs no new code.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use cc_http::{Body, Ctx, Req, Resp, json};
use cc_proc::{Cmd, Runner};
use http_body_util::BodyExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::run_helper;

pub const GATE_PORT: u16 = 3131;
const HELPER: &str = "/usr/local/bin/cc-gbrain-token";
const HELPER_TIMEOUT: Duration = Duration::from_secs(25);
/// A tool call can run for minutes (a `think` on the deep model); a GET is the SSE stream.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(600);
static VM_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("regex"));
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]{32,}$").expect("regex"));

/// A private 10.x IPv4 address, written the one way: each octet 0-255 with no leading zero (the
/// standard parser). Rust only: the TS took `10.0.0.999` and `10.010.0.9`, which a URL parser
/// reads as octal.
pub fn is_private_ip(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.octets()[0] == 10)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "vmId", default, skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Value>,
    /// Fields this build does not know, kept for the Node build.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lock {
    pub all: bool,
    #[serde(rename = "vmIds")]
    pub vm_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectInput {
    pub vm_id: String,
    pub ip: String,
    pub scope: String,
}

/// `::ffff:10.0.0.5` and `10.0.0.5` are the same address.
pub fn normalize_ip(a: &str) -> String {
    let lower = a.to_ascii_lowercase();
    let s = if lower.starts_with("::ffff:") { &a[7..] } else { a };
    s.trim().to_string()
}

/// This box's address on the organization's private network, or `None` before the NIC is up:
/// the first non-loopback 10.x address in interface order, as `networkInterfaces()` lists them.
/// Read from `/proc` (the local addresses, the routes that say which interface has each, and the
/// interfaces in order); no syscalls of our own.
pub fn private_address() -> Option<String> {
    let trie = std::fs::read_to_string("/proc/net/fib_trie").ok()?;
    let routes = std::fs::read_to_string("/proc/net/route").unwrap_or_default();
    let devs = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    pick_private_address(&trie, &routes, &devs)
}

pub(super) fn pick_private_address(trie: &str, routes: &str, devs: &str) -> Option<String> {
    let mut locals: Vec<String> = Vec::new();
    let mut last: Option<&str> = None;
    for line in trie.lines() {
        let t = line.trim_start_matches([' ', '|', '+', '-']).trim();
        if line.contains("|--") {
            last = Some(t);
        } else if t.starts_with("/32 host LOCAL")
            && let Some(ip) = last
            && is_private_ip(ip)
            && !locals.iter().any(|l| l == ip)
        {
            locals.push(ip.to_string());
        }
    }
    let order: Vec<&str> = devs
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(n, _)| n.trim())
        .collect();
    let parse_hex = |h: &str| u32::from_str_radix(h, 16).ok().map(u32::swap_bytes);
    // The interface whose route covers the address (`/proc/net/route` is little-endian hex).
    let iface_of = |ip: &str| -> Option<&str> {
        let addr = u32::from(ip.parse::<std::net::Ipv4Addr>().ok()?);
        routes
            .lines()
            .skip(1)
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                let (dest, mask) = (parse_hex(f.get(1)?)?, parse_hex(f.get(7)?)?);
                (mask != 0 && addr & mask == dest & mask).then_some((f[0], mask))
            })
            .max_by_key(|(_, mask)| mask.count_ones())
            .map(|(i, _)| i)
    };
    let rank = |ip: &String| {
        iface_of(ip)
            .filter(|i| *i != "lo")
            .and_then(|i| order.iter().position(|o| *o == i))
            .unwrap_or(usize::MAX)
    };
    locals
        .into_iter()
        .enumerate()
        .min_by_key(|(i, ip)| (rank(ip), *i))
        .map(|(_, ip)| ip)
}

pub fn parse_connect(body: Option<&Map<String, Value>>) -> Result<ConnectInput, &'static str> {
    let Some(body) = body else {
        return Err("a JSON body is required");
    };
    let vm_id = body.get("vmId").and_then(Value::as_str).filter(|v| VM_ID.is_match(v));
    let Some(vm_id) = vm_id else {
        return Err("vmId is required");
    };
    let ip = body.get("ip").and_then(Value::as_str).filter(|v| is_private_ip(v));
    let Some(ip) = ip else {
        return Err("ip must be a private 10.x address");
    };
    let scope = body
        .get("scope")
        .and_then(Value::as_str)
        .filter(|s| *s == "read" || *s == "read_write");
    let Some(scope) = scope else {
        return Err("scope must be read or read_write");
    };
    Ok(ConnectInput {
        vm_id: vm_id.into(),
        ip: ip.into(),
        scope: scope.into(),
    })
}

pub fn parse_lock(body: Option<&Map<String, Value>>) -> Result<Lock, &'static str> {
    const NEED: &str = "all (boolean) and vmIds (array) are required";
    let Some(body) = body else { return Err(NEED) };
    let (Some(all), Some(ids)) = (
        body.get("all").and_then(Value::as_bool),
        body.get("vmIds").and_then(Value::as_array),
    ) else {
        return Err(NEED);
    };
    let vm_ids: Vec<String> = ids
        .iter()
        .filter_map(Value::as_str)
        .filter(|v| VM_ID.is_match(v))
        .map(String::from)
        .collect();
    if vm_ids.len() != ids.len() {
        return Err("vmIds must be vm ids");
    }
    let mut vm_ids: Vec<String> = vm_ids
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    // `[...new Set(ids)].sort()`: UTF-16 order, the same as byte order for these ids.
    vm_ids.sort();
    Ok(Lock { all, vm_ids })
}

pub fn parse_disconnect(body: Option<&Map<String, Value>>) -> Result<String, &'static str> {
    body.and_then(|b| b.get("vmId"))
        .and_then(Value::as_str)
        .filter(|v| VM_ID.is_match(v))
        .map(String::from)
        .ok_or("vmId is required")
}

/// Why the gate turns a request away, or the token it forwards with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Token(String),
    Unknown,
    Stopped,
}

struct State {
    entries: Vec<Entry>,
    lock: Lock,
}

pub struct BrainGate {
    path: PathBuf,
    runner: Arc<dyn Runner>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    state: Mutex<State>,
    /// Held across a whole connect, disconnect or reissue, helper call included: a disconnect
    /// while a connect waits for its token must not be undone when the connect finishes.
    ops: tokio::sync::Mutex<()>,
}

#[derive(Serialize)]
struct Saved<'a> {
    version: u8,
    entries: &'a [Entry],
    lock: &'a Lock,
}

impl BrainGate {
    pub fn new(path: &Path, runner: Arc<dyn Runner>) -> Self {
        Self::with_log(path, runner, Arc::new(|l| tracing::info!("{l}")))
    }

    pub fn with_log(path: &Path, runner: Arc<dyn Runner>, log: Arc<dyn Fn(&str) + Send + Sync>) -> Self {
        let mut lock = Lock::default();
        let entries = Self::load(path, &mut lock, &*log);
        Self {
            path: path.to_path_buf(),
            runner,
            log,
            state: Mutex::new(State { entries, lock }),
            ops: tokio::sync::Mutex::new(()),
        }
    }

    fn load(path: &Path, lock: &mut Lock, log: &(dyn Fn(&str) + Send + Sync)) -> Vec<Entry> {
        let raw = match std::fs::read(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(e) => {
                log(&format!("[gbrain-gate] could not read {}: {e}", path.display()));
                return Vec::new();
            }
        };
        // Unreadable means nobody gets in until the firewall's reconcile re-applies them: fail
        // closed.
        let s: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(e) => {
                log(&format!("[gbrain-gate] could not read {}: {e}", path.display()));
                return Vec::new();
            }
        };
        if let Ok(l) = parse_lock(s.get("lock").and_then(Value::as_object)) {
            *lock = l;
        }
        s.get("entries")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|e| {
                        e.get("token").is_some_and(Value::is_string) && e.get("ip").is_some_and(Value::is_string)
                    })
                    // Only tokens of GBrain's shape: one that could not be a header would never
                    // reach GBrain, and the agent would get nothing but 502s.
                    .filter(|e| {
                        e.get("token")
                            .and_then(Value::as_str)
                            .is_some_and(|t| TOKEN.is_match(t))
                    })
                    .filter_map(|e| serde_json::from_value(e.clone()).ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, st: &State) -> std::io::Result<()> {
        let data = serde_json::to_vec(&Saved {
            version: 1,
            entries: &st.entries,
            lock: &st.lock,
        })
        .map_err(std::io::Error::other)?;
        cc_store::write_atomic(&self.path, &data, 0o600, cc_store::TmpName::Suffix)
    }

    /// What the firewall reads to reconcile. No tokens.
    pub fn list(&self) -> Vec<Value> {
        self.state()
            .entries
            .iter()
            .map(|e| {
                // `({vmId, ip, scope, at})`: a field the entry lacks is left out.
                let mut m = Map::new();
                if let Some(v) = &e.vm_id {
                    m.insert("vmId".into(), Value::String(v.clone()));
                }
                m.insert("ip".into(), Value::String(e.ip.clone()));
                if let Some(v) = &e.scope {
                    m.insert("scope".into(), Value::String(v.clone()));
                }
                if let Some(v) = &e.at {
                    m.insert("at".into(), v.clone());
                }
                Value::Object(m)
            })
            .collect()
    }

    pub fn lock(&self) -> Lock {
        self.state().lock.clone()
    }

    pub fn set_lock(&self, lock: Lock) -> std::io::Result<()> {
        let mut st = self.state();
        st.lock = lock.clone();
        self.save(&st)?;
        drop(st);
        let who = if lock.all {
            "every agent".to_string()
        } else if lock.vm_ids.is_empty() {
            "none".to_string()
        } else {
            lock.vm_ids.join(", ")
        };
        (self.log)(&format!("[gbrain-gate] emergency stop: {who}"));
        Ok(())
    }

    pub fn admit(&self, source_ip: &str) -> Admission {
        let ip = normalize_ip(source_ip);
        let st = self.state();
        let Some(e) = st.entries.iter().find(|x| x.ip == ip) else {
            return Admission::Unknown;
        };
        if st.lock.all || e.vm_id.as_ref().is_some_and(|v| st.lock.vm_ids.contains(v)) {
            return Admission::Stopped;
        }
        Admission::Token(e.token.clone())
    }

    async fn helper(&self, args: &[&str]) -> Result<String, String> {
        let cmd = Cmd::new("sudo")
            .arg(HELPER)
            .args(args.iter().copied())
            .timeout(HELPER_TIMEOUT);
        run_helper(self.runner.as_ref(), cmd).await
    }

    pub async fn connect(&self, input: &ConnectInput) -> Result<(), String> {
        let _op = self.ops.lock().await;
        self.connect_now(input).await
    }

    async fn connect_now(&self, input: &ConnectInput) -> Result<(), String> {
        let token = self
            .helper(&["create", &input.vm_id, &input.scope])
            .await
            .map_err(|e| format!("could not create the agent's brain token: {e}"))?
            .trim()
            .to_string();
        if !TOKEN.is_match(&token) {
            return Err("GBrain returned no usable token".into());
        }
        // Another agent on this address (an address reused after a delete) loses its entry: one
        // address, one agent.
        let displaced: Vec<String> = {
            let mut st = self.state();
            let displaced = st
                .entries
                .iter()
                .filter(|e| e.ip == input.ip && e.vm_id.as_deref() != Some(input.vm_id.as_str()))
                .filter_map(|e| e.vm_id.clone())
                .collect();
            st.entries
                .retain(|e| e.vm_id.as_deref() != Some(input.vm_id.as_str()) && e.ip != input.ip);
            st.entries.push(Entry {
                vm_id: Some(input.vm_id.clone()),
                ip: input.ip.clone(),
                scope: Some(input.scope.clone()),
                token,
                at: Some(Value::String(cc_crypto::store_health::iso_now())),
                extra: Map::new(),
            });
            self.save(&st).map_err(|e| e.to_string())?;
            displaced
        };
        for d in displaced {
            if let Err(e) = self.revoke(&d).await {
                (self.log)(&format!("[gbrain-gate] {e}"));
            }
        }
        (self.log)(&format!(
            "[gbrain-gate] {} at {} may use the brain ({})",
            input.vm_id, input.ip, input.scope
        ));
        Ok(())
    }

    /// Mint every connected agent a new token. After a restore the database's token table is the
    /// backup's, which does not know the tokens minted since. Same agents, same addresses, same
    /// scopes: nothing is widened.
    #[allow(dead_code)] // the brain's backup restore (W7's backup service)
    pub async fn reissue_all(&self) -> (usize, Vec<String>) {
        let _op = self.ops.lock().await;
        let entries: Vec<Entry> = self.state().entries.clone();
        let (mut reissued, mut failed) = (0, Vec::new());
        for e in entries {
            // `connect({vmId, ip, scope})` with what the entry has; an entry without them fails
            // the helper's check, as the TS one would.
            let vm_id = e.vm_id.clone().unwrap_or_else(|| "undefined".into());
            let input = ConnectInput {
                vm_id: vm_id.clone(),
                ip: e.ip.clone(),
                scope: e.scope.clone().unwrap_or_else(|| "undefined".into()),
            };
            match self.connect_now(&input).await {
                Ok(()) => reissued += 1,
                Err(err) => {
                    (self.log)(&format!("[gbrain-gate] could not reissue {vm_id}'s token: {err}"));
                    failed.push(vm_id);
                }
            }
        }
        (reissued, failed)
    }

    pub async fn disconnect(&self, vm_id: &str) -> Result<bool, String> {
        let _op = self.ops.lock().await;
        let had = {
            let mut st = self.state();
            let had = st.entries.iter().any(|e| e.vm_id.as_deref() == Some(vm_id));
            // Out of the gate first: that alone stops the agent, whatever the revoke does.
            st.entries.retain(|e| e.vm_id.as_deref() != Some(vm_id));
            self.save(&st).map_err(|e| e.to_string())?;
            had
        };
        self.revoke(vm_id).await?;
        (self.log)(&format!("[gbrain-gate] {vm_id} disconnected from the brain"));
        Ok(had)
    }

    async fn revoke(&self, vm_id: &str) -> Result<(), String> {
        self.helper(&["revoke", vm_id])
            .await
            .map(|_| ())
            .map_err(|e| format!("could not revoke {vm_id}'s brain token: {e}"))
    }
}

/// `/mcp` and nothing else: GBrain's admin page, OAuth and metadata routes stay unreachable here.
pub fn gate_allows(method: &http::Method, target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("/");
    path == "/mcp" && matches!(method.as_str(), "POST" | "GET" | "DELETE")
}

fn deny(status: u16, message: &str) -> Resp {
    json(status, &serde_json::json!({"error": message}))
}

/// One request through the gate.
pub async fn handle(
    gate: &(dyn Fn(&str) -> Admission + Send + Sync),
    target: &str,
    log: &(dyn Fn(&str) + Send + Sync),
    req: Req,
    ctx: Ctx,
) -> Resp {
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    if !gate_allows(req.method(), &path) {
        return deny(404, "Not found");
    }
    let remote = ctx.remote.ip().to_string();
    let token = match gate(&remote) {
        Admission::Token(t) => t,
        refused => {
            let stopped = refused == Admission::Stopped;
            log(&format!(
                "[gbrain-gate] refused {}: {}",
                normalize_ip(&remote),
                if stopped {
                    "under an emergency stop"
                } else {
                    "not a connected agent"
                }
            ));
            return deny(
                403,
                if stopped {
                    "This agent is under an emergency stop."
                } else {
                    "This agent is not connected to the brain."
                },
            );
        }
    };
    match forward(target, &token, &path, req).await {
        Ok(r) => r,
        Err(e) => {
            log(&format!("[gbrain-gate] upstream failed: {e}"));
            deny(502, "The brain is not answering.")
        }
    }
}

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn forward(target: &str, token: &str, path: &str, req: Req) -> Result<Resp, String> {
    let (mut parts, body) = req.into_parts();
    let tcp = tokio::net::TcpStream::connect(target)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
        .await
        .map_err(|e| e.to_string())?;
    // The connection to GBrain lives as long as the agent's side: when the agent hangs up (an SSE
    // stream or a long `think` it gave up on), dropping the reply aborts it, as Node's
    // `upstream.destroy()` on `res` close did.
    let guard = AbortOnDrop(
        tokio::spawn(async move {
            let _ = conn.await;
        })
        .abort_handle(),
    );
    parts.headers.remove("x-forwarded-for");
    if let Ok(v) = http::HeaderValue::from_str(target) {
        parts.headers.insert(http::header::HOST, v);
    }
    // The agent's own Authorization never goes through, whatever happens to the stored token.
    parts.headers.remove(http::header::AUTHORIZATION);
    let bearer = http::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| "the agent's token is not a header".to_string())?;
    parts.headers.insert(http::header::AUTHORIZATION, bearer);
    parts.uri = path.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let up = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        sender.send_request(http::Request::from_parts(parts, body)),
    )
    .await
    .map_err(|_| "timeout".to_string())?
    .map_err(|e| e.to_string())?;
    let (mut parts, body) = up.into_parts();
    // Framing is hyper's to choose on this side.
    parts.headers.remove(http::header::TRANSFER_ENCODING);
    parts.headers.remove(http::header::CONNECTION);
    // `upstream.setTimeout`: the stream ends when GBrain sends nothing for that long.
    let frames = futures_util::stream::unfold((body, guard), |(mut body, guard)| async move {
        match tokio::time::timeout(UPSTREAM_TIMEOUT, body.frame()).await {
            Ok(Some(Ok(frame))) => Some((Ok(frame), (body, guard))),
            Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e)), (body, guard))),
            Ok(None) => None,
            Err(_) => Some((Err(std::io::Error::other("timeout")), (body, guard))),
        }
    });
    let body: Body = http_body_util::StreamBody::new(frames).boxed();
    Ok(http::Response::from_parts(parts, body))
}
