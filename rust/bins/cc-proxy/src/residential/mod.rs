//! The residential exit. Owner: W1. (appendix F features 12, 13; addon.py 594-862, 3330-3513)
//!
//! A rule with `exit: "residential"` (on an allow or tunnel effect) sends its destination out
//! through the organization's upstream proxy from `exit.json`: HTTP CONNECT (to an `http` or `https`
//! proxy) or SOCKS5 with username and password, both by NAME so the exit resolves it. A TLS flow is
//! relayed whole (the site sees the agent browser's own handshake), counted, and recorded at host
//! level, with an interim record every 64 MB. Plain HTTP goes through an HTTP upstream, one
//! connection per request: a CONNECT to the name on its port, then the request inside (TLS to the
//! site first for HTTPS), as mitmproxy's upstream mode sends it.
//!
//! There is no path from here that dials the site from the firewall's own address: every failure
//! closes the connection and writes one record saying why.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use cc_contracts::{MissingPolicy, MtimeCache, OnError};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value, json};
use sha2::Sha256;

use crate::flow::{Flow, Hook, Pipeline, Step, StepFuture, Verdict, order};
use crate::http::policy::truthy;
use crate::net::Ctx;
use crate::net::rules::RuleView;

/// An interim usage record every this many bytes, so a connection that never closes is still
/// counted against the cap.
pub const INTERIM_BYTES: u64 = 64 * 1024 * 1024;

/// The effects `exit: residential` is honoured on: the two that already let traffic out.
pub const RESIDENTIAL_EFFECTS: &[&str] = &["allow", "tunnel"];

/// `exit.json`: missing means no exit (the file is the credential), broken means none either.
pub struct ExitConfig {
    file: MtimeCache<Map<String, Value>>,
}

/// A usable upstream. No `Debug`: `raw` holds the password.
#[derive(Clone)]
pub struct Upstream {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    raw: Map<String, Value>,
}

impl ExitConfig {
    pub fn new(path: &std::path::Path) -> Self {
        Self {
            file: MtimeCache::new(path, MissingPolicy::Empty, OnError::Empty),
        }
    }

    pub fn get(&self) -> Arc<Map<String, Value>> {
        self.file.get()
    }

    /// One reading of the file, for everything one connection decides (readiness, country,
    /// session): a rewrite in between must not mix two versions.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot(self.get())
    }

    pub fn ready(&self) -> Result<Upstream, String> {
        self.snapshot().ready()
    }

    pub fn session_for(&self, vm_id: Option<&str>) -> Option<String> {
        self.snapshot().session_for(vm_id)
    }

    pub fn country_for(&self, rule: Option<&RuleView>) -> Option<String> {
        self.snapshot().country_for(rule)
    }
}

/// `exit.json` as read once.
pub struct Snapshot(Arc<Map<String, Value>>);

impl Snapshot {
    fn get(&self) -> Arc<Map<String, Value>> {
        self.0.clone()
    }

    /// addon.py `_residential_ready`: the upstream, or why there is none.
    pub fn ready(&self) -> Result<Upstream, String> {
        let cfg = self.get();
        if !truthy(cfg.get("enabled")) {
            return Err("no residential exit is configured".into());
        }
        let Some(up) = cfg.get("upstream").and_then(Value::as_object) else {
            return Err("the residential exit is not configured".into());
        };
        let host = up.get("host").filter(|h| truthy(Some(h)));
        let port = up.get("port").filter(|p| truthy(Some(p)));
        let (Some(host), Some(port)) = (host, port) else {
            return Err("the residential exit is not configured".into());
        };
        let scheme = up.get("scheme").and_then(Value::as_str).unwrap_or("");
        if !["http", "https", "socks5"].contains(&scheme) {
            let shown = match up.get("scheme") {
                Some(Value::String(s)) => format!("'{s}'"),
                None | Some(Value::Null) => "None".into(),
                Some(v) => v.to_string(),
            };
            return Err(format!("unsupported residential exit scheme {shown}"));
        }
        if truthy(cfg.get("sticky")) && py_str(cfg.get("sticky_salt")).chars().count() < 32 {
            return Err("this firewall's sticky-session salt is missing".into());
        }
        let cap = cfg.get("cap_bytes").and_then(Value::as_f64).unwrap_or(0.0);
        let used = cfg.get("used_bytes").and_then(Value::as_f64).unwrap_or(0.0);
        if cap > 0.0 && used >= cap {
            return Err("this month's residential data cap is used up".into());
        }
        let port = crate::net::rules::py_int(port)
            .and_then(|p| u16::try_from(p).ok())
            .ok_or_else(|| "the residential exit is not configured".to_owned())?;
        Ok(Upstream {
            scheme: scheme.to_owned(),
            host: py_str(Some(host)),
            port,
            raw: up.clone(),
        })
    }

    /// addon.py `session_for`: the agent's sticky session, from a salt only this firewall has.
    pub fn session_for(&self, vm_id: Option<&str>) -> Option<String> {
        let cfg = self.get();
        let vm_id = vm_id.filter(|v| !v.is_empty())?;
        if !truthy(cfg.get("sticky")) {
            return None;
        }
        let salt = py_str(cfg.get("sticky_salt"));
        let mut mac = Hmac::<Sha256>::new_from_slice(salt.as_bytes()).ok()?;
        mac.update(vm_id.as_bytes());
        Some(hex::encode(mac.finalize().into_bytes())[..12].to_owned())
    }

    /// addon.py `exit_country_for`: the rule's own country, else the org default; junk is none.
    pub fn country_for(&self, rule: Option<&RuleView>) -> Option<String> {
        rule.and_then(|r| normalize_country(r.raw.get("exit_country")))
            .or_else(|| normalize_country(self.get().get("country")))
    }
}

/// `str(x)` for the values these fields hold (a string as it is, a number as written).
fn py_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// ISO 3166-1 alpha-2, upper case, or none.
pub fn normalize_country(v: Option<&Value>) -> Option<String> {
    let c = v?.as_str()?.trim().to_ascii_uppercase();
    (c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())).then_some(c)
}

impl Upstream {
    fn templates_take_country(&self) -> bool {
        let both = format!(
            "{} {}",
            py_str(self.raw.get("username_template")),
            py_str(self.raw.get("password_template"))
        );
        both.contains("{country}") || both.contains("{country_lc}")
    }

    /// addon.py `country_refusal`.
    pub fn country_refusal(&self, country: Option<&str>) -> Option<String> {
        let c = country?;
        (!self.templates_take_country())
            .then(|| format!("this exit's credential has no country field, so it cannot come out in {c}"))
    }

    /// addon.py `upstream_credentials`.
    pub fn credentials(&self, session: Option<&str>, country: Option<&str>) -> (String, String) {
        let tmpl = |k: &str, default: &str| {
            let t = py_str(self.raw.get(k));
            if t.is_empty() { default.to_owned() } else { t }
        };
        let user = render_template(
            &tmpl("username_template", "{username}"),
            &py_str(self.raw.get("username")),
            "",
            session,
            country,
        );
        let pw = render_template(
            &tmpl("password_template", "{password}"),
            "",
            &py_str(self.raw.get("password")),
            session,
            country,
        );
        (user, pw)
    }
}

const PLACEHOLDERS: &[&str] = &["username", "password", "session", "country", "country_lc"];

/// addon.py `render_template`: `{username}`, `{password}`, `{session}`, `{country}`,
/// `{country_lc}`; a `[...]` segment is kept only when every placeholder in it has a value (one with
/// none follows the session).
pub fn render_template(
    template: &str,
    username: &str,
    password: &str,
    session: Option<&str>,
    country: Option<&str>,
) -> String {
    let session = session.unwrap_or("");
    let country = country.unwrap_or("");
    let value = |name: &str| -> String {
        match name {
            "username" => username.to_owned(),
            "password" => password.to_owned(),
            "session" => session.to_owned(),
            "country" => country.to_ascii_uppercase(),
            "country_lc" => country.to_ascii_lowercase(),
            _ => String::new(),
        }
    };
    let names_in = |s: &str| -> Vec<&'static str> {
        let mut out = Vec::new();
        let mut rest = s;
        while let Some(i) = rest.find('{') {
            let after = &rest[i + 1..];
            if let Some(j) = after.find('}')
                && let Some(n) = PLACEHOLDERS.iter().find(|p| **p == &after[..j])
            {
                out.push(*n);
            }
            rest = &rest[i + 1..];
        }
        out
    };
    // Segments: `[` followed by no `[` or `]` up to `]`.
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find('[') {
        let after = &rest[i + 1..];
        match after.find([']', '[']) {
            Some(j) if after.as_bytes()[j] == b']' => {
                out.push_str(&rest[..i]);
                let inner = &after[..j];
                let names = names_in(inner);
                let keep = if names.is_empty() {
                    !session.is_empty()
                } else {
                    names.iter().all(|n| !value(n).is_empty())
                };
                if keep {
                    out.push_str(inner);
                }
                rest = &after[j + 1..];
            }
            _ => {
                out.push_str(&rest[..=i]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    // Then fill every placeholder.
    let mut filled = String::new();
    let mut rest = out.as_str();
    while let Some(i) = rest.find('{') {
        filled.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after
            .find('}')
            .and_then(|j| PLACEHOLDERS.iter().find(|p| **p == &after[..j]).map(|p| (j, *p)))
        {
            Some((j, name)) => {
                filled.push_str(&value(name));
                rest = &after[j + 1..];
            }
            None => {
                filled.push('{');
                rest = after;
            }
        }
    }
    filled.push_str(rest);
    filled
}

/// Whether `host` is an IP address as the addon's `_is_ip` reads it: digits and dots, or a colon.
fn looks_like_ip(host: &str) -> bool {
    (!host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.')) || host.contains(':')
}

/// addon.py `_connection_matches`: could this rule apply, judged from the connection alone.
fn connection_matches(rule: &RuleView, host: &str, port: Option<u16>, vm_id: Option<&str>) -> bool {
    if !rule.applies_to(vm_id) {
        return false;
    }
    let pattern = match &rule.match_domain {
        None => "",
        Some(Some(p)) => p.as_str(),
        Some(None) => return false,
    };
    if looks_like_ip(host) && (pattern == "*" || pattern.starts_with("*.")) {
        return false;
    }
    crate::net::hosts::host_matches(pattern, host) && rule.port_matches(port)
}

/// Whether any rule with `exit: residential` matches this connection, whatever its priority or
/// effect: one might win for a request where another wins for the connection, so the site must not
/// be dialled from the firewall before the requests are judged.
pub fn any_residential(rules: &[RuleView], host: &str, port: Option<u16>, vm_id: Option<&str>) -> bool {
    rules.iter().any(|r| {
        r.raw.get("exit").and_then(Value::as_str) == Some("residential") && connection_matches(r, host, port, vm_id)
    })
}

/// addon.py `residential_rule`: the rule `match_rule` would pick for this destination, if it is
/// the residential one on an effect that lets traffic out. Never for a locked agent.
pub fn residential_rule(
    rules: &[RuleView],
    host: &str,
    port: Option<u16>,
    vm_id: Option<&str>,
    locked: bool,
) -> Option<RuleView> {
    if host.is_empty() || locked {
        return None;
    }
    let mut candidates: Vec<&RuleView> = rules
        .iter()
        .filter(|r| connection_matches(r, host, port, vm_id))
        .collect();
    candidates.sort_by(|a, b| a.priority.total_cmp(&b.priority));
    let winner = candidates.first()?;
    if winner.raw.get("exit").and_then(Value::as_str) != Some("residential") {
        return None;
    }
    let effect = winner.raw.get("effect").and_then(Value::as_str).unwrap_or("allow");
    if !RESIDENTIAL_EFFECTS.contains(&effect) {
        tracing::warn!(
            "[mitm] ignoring exit=residential on a {effect} rule ({:?})",
            winner.name
        );
        return None;
    }
    Some((*winner).clone())
}

/// The control plane and the backup store never go out through the exit: they are the firewall's
/// own channels, held to their own names by the interception.
pub fn exempt(ctx: &Ctx, host: &str) -> bool {
    let cfg = &ctx.config;
    cfg.control_plane_host.as_deref() == Some(host) || cfg.backup_host.as_deref() == Some(host)
}

/// Whether any rule asks for the exit (the addon defers an incomplete ClientHello only then).
pub fn configured(rules: &[RuleView]) -> bool {
    rules
        .iter()
        .any(|r| r.raw.get("exit").and_then(Value::as_str) == Some("residential"))
}

// ---- the relay ----

use std::net::SocketAddr;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// How long the upstream may take to connect and answer the handshake.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// addon.py `encode_host`: the name as it goes in a CONNECT or a SOCKS5 request, or `None`.
pub fn encode_host(host: &str) -> Option<String> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if looks_like_ip(host) {
        return Some(host.chars().filter(char::is_ascii).collect()).filter(|s: &String| !s.is_empty());
    }
    crate::net::destination::wire_name(host)
}

/// The usage of one relay, as `_residential_record` writes it.
pub struct Usage {
    pub host: String,
    pub port: u16,
    pub vm_id: Option<String>,
    pub rule: Value,
    pub rule_id: Option<String>,
    pub country: Option<String>,
    pub flow_id: String,
    pub started: Instant,
    seq: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    billed_in: u64,
    billed_out: u64,
}

impl Usage {
    pub fn new(host: String, port: u16, vm_id: Option<String>, rule: &RuleView, country: Option<String>) -> Self {
        Self {
            host,
            port,
            vm_id,
            rule: crate::http::policy::rule_label(rule),
            rule_id: rule
                .id
                .clone()
                .filter(|i| !i.is_empty())
                .map(|i| crate::net::target::truncate(&i, 64)),
            country,
            flow_id: uuid::Uuid::new_v4().to_string(),
            started: Instant::now(),
            seq: 0,
            bytes_in: 0,
            bytes_out: 0,
            billed_in: 0,
            billed_out: 0,
        }
    }

    pub fn unbilled(&self) -> u64 {
        (self.bytes_in - self.billed_in) + (self.bytes_out - self.billed_out)
    }

    /// One record for the bytes since the last one (addon.py `_residential_record`). Interim ones
    /// carry a suffixed flow id and no duration, so an at-least-once upload never double-counts.
    pub fn record(&mut self, ctx: &Ctx, interim: bool, error: Option<String>) -> Value {
        self.record_with(&ctx.config.tenant, interim, error)
    }

    pub fn record_with(&mut self, tenant: &str, interim: bool, error: Option<String>) -> Value {
        let moved_in = self.bytes_in - self.billed_in;
        let moved_out = self.bytes_out - self.billed_out;
        self.billed_in = self.bytes_in;
        self.billed_out = self.bytes_out;
        let seq = self.seq;
        self.seq += 1;
        let mut rec = json!({
            "flow_id": if seq == 0 { self.flow_id.clone() } else { format!("{}#{seq}", self.flow_id) },
            "ts": crate::log::now(),
            "tenant": tenant,
            "vm_id": self.vm_id,
            "host": self.host,
            "port": self.port,
            "effect": "residential",
            "rule": self.rule,
            "exit": "residential",
            "rule_id": null,
        });
        let o = rec.as_object_mut().expect("an object");
        if let Some(id) = &self.rule_id {
            o.insert("rule_id".into(), id.clone().into());
        }
        o.insert("bytes_in".into(), moved_in.into());
        o.insert("bytes_out".into(), moved_out.into());
        if let Some(c) = &self.country {
            o.insert("exit_country".into(), c.clone().into());
        }
        if !interim {
            o.insert(
                "duration_ms".into(),
                u64::try_from(self.started.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .into(),
            );
        }
        if let Some(e) = error {
            o.insert("error".into(), crate::net::target::truncate(&e, 200).into());
        }
        rec
    }
}

/// Open a tunnel to `host:port` through the upstream, by name: HTTP CONNECT (over TLS for an
/// `https` proxy) or SOCKS5 with username and password. The upstream's own address is checked like
/// any other (never non-routable, never the firewall's own).
pub async fn open(
    up: &Upstream,
    host: &str,
    port: u16,
    user: &str,
    pw: &str,
    ctx: &Ctx,
) -> Result<Box<dyn Tunnel>, String> {
    let addrs = crate::net::target::resolve_all(&up.host, up.port).await?;
    let addr: SocketAddr = *addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .ok_or("the upstream does not resolve")?;
    let tcp = tokio::time::timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connecting to the upstream {}:{} timed out", up.host, up.port))?
        .map_err(|e| format!("could not connect to the upstream {}:{}: {e}", up.host, up.port))?;
    let _ = tcp.set_nodelay(true);
    let fut = async {
        match up.scheme.as_str() {
            "socks5" => {
                let mut s = tcp;
                socks5(&mut s, host, port, user, pw).await?;
                Ok(Box::new(s) as Box<dyn Tunnel>)
            }
            "https" => {
                let name =
                    crate::tls::config::server_name(&up.host).ok_or("the upstream's name is not valid for TLS")?;
                let connector = tokio_rustls::TlsConnector::from(ctx.upstream_tls.plain());
                let mut s = connector
                    .connect(name, tcp)
                    .await
                    .map_err(|e| format!("TLS with the upstream failed: {e}"))?;
                http_connect(&mut s, host, port, user, pw, up).await?;
                Ok(Box::new(s) as Box<dyn Tunnel>)
            }
            _ => {
                let mut s = tcp;
                http_connect(&mut s, host, port, user, pw, up).await?;
                Ok(Box::new(s) as Box<dyn Tunnel>)
            }
        }
    };
    tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
        .await
        .map_err(|_| "the upstream did not answer in time".to_owned())?
}

pub trait Tunnel: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Tunnel for T {}

fn basic(user: &str, pw: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pw}"))
}

/// `CONNECT host:port`, with `Proxy-Authorization` when there is a credential.
async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    port: u16,
    user: &str,
    pw: &str,
    up: &Upstream,
) -> Result<(), String> {
    let target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if !user.is_empty() || !pw.is_empty() {
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", basic(user, pw)));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("the upstream went away: {e}"))?;
    // The answer's head, a byte at a time: nothing after it may be read here.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 {
            return Err("the upstream's answer is too long".into());
        }
        let mut b = [0u8; 1];
        if s.read(&mut b)
            .await
            .map_err(|e| format!("the upstream went away: {e}"))?
            == 0
        {
            return Err("the upstream closed the connection".into());
        }
        head.push(b[0]);
    }
    let line = String::from_utf8_lossy(&head);
    let first = line.lines().next().unwrap_or("");
    let status = first
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if (200..300).contains(&status) {
        return Ok(());
    }
    // mitmproxy's own words: `Upstream proxy <host>:<port> refused HTTP CONNECT request: <status> <reason>`.
    let rest = first.split_once(' ').map_or("", |(_, r)| r);
    Err(format!(
        "Upstream proxy {}:{} refused HTTP CONNECT request: {}",
        up.host,
        up.port,
        crate::net::target::truncate(rest, 120)
    ))
}

/// SOCKS5 (RFC 1928 + 1929): username/password only (method 0x02, so an upstream that would take
/// us unauthenticated cannot talk us out of the credential), ATYP=domain (resolved at the exit).
async fn socks5<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    port: u16,
    user: &str,
    pw: &str,
) -> Result<(), String> {
    let io = |e: std::io::Error| format!("the upstream went away: {e}");
    s.write_all(b"\x05\x01\x02").await.map_err(io)?;
    let mut g = [0u8; 2];
    s.read_exact(&mut g).await.map_err(io)?;
    if g[0] != 0x05 || g[1] != 0x02 {
        return Err(format!(
            "socks5: upstream refused username/password auth (method {:#04x})",
            g[1]
        ));
    }
    let (u, p) = (
        &user.as_bytes()[..user.len().min(255)],
        &pw.as_bytes()[..pw.len().min(255)],
    );
    let mut auth = vec![0x01, u.len() as u8];
    auth.extend_from_slice(u);
    auth.push(p.len() as u8);
    auth.extend_from_slice(p);
    s.write_all(&auth).await.map_err(io)?;
    let mut a = [0u8; 2];
    s.read_exact(&mut a).await.map_err(io)?;
    if a[1] != 0x00 {
        return Err("socks5: upstream rejected the credential".into());
    }
    let raw = host.as_bytes();
    if raw.len() > 255 {
        return Err("socks5: the name is too long".into());
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, raw.len() as u8];
    req.extend_from_slice(raw);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut r = [0u8; 5];
    s.read_exact(&mut r).await.map_err(io)?;
    if r[1] != 0x00 {
        return Err(format!("socks5: upstream refused the connection (reply {:#04x})", r[1]));
    }
    // The bound address, by its type: the 5 bytes read hold the type and its first byte.
    let rest = match r[3] {
        0x01 => 4 + 2 - 1,
        0x04 => 16 + 2 - 1,
        0x03 => usize::from(r[4]) + 2,
        t => return Err(format!("socks5: bad address type {t:#04x}")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await.map_err(io)?;
    Ok(())
}

// ---- the TLS (and raw TCP) relay ----

/// `rule.get("name")` as the exit records write it (no domain fallback there).
fn rule_name(rule: &RuleView) -> Value {
    rule.raw.get("name").cloned().unwrap_or(Value::Null)
}

/// addon.py `_exit_record`: the one record a refused residential connection leaves behind.
fn exit_record(
    ctx: &Ctx,
    rule: &RuleView,
    host: &str,
    port: u16,
    vm_id: Option<&str>,
    country: Option<&str>,
    error: &str,
) -> Value {
    use sha2::Digest;
    let ts = crate::log::now();
    let id = hex::encode(sha2::Sha256::digest(format!("{}{host}{port}", ts.0).as_bytes()));
    let mut rec = json!({
        "flow_id": format!("res_{}", &id[..24]),
        "ts": ts,
        "tenant": ctx.config.tenant,
        "vm_id": vm_id,
        "host": host,
        "port": port,
        "effect": "residential",
        "rule": rule_name(rule),
        "exit": "residential",
        "error": crate::net::target::truncate(error, 200),
        "rule_id": null,
    });
    let o = rec.as_object_mut().expect("an object");
    if let Some(id) = rule_id(rule) {
        o.insert("rule_id".into(), id.into());
    }
    if let Some(c) = country {
        o.insert("exit_country".into(), c.into());
    }
    rec
}

/// `str(rule["id"])[:64]` for a truthy id.
fn rule_id(rule: &RuleView) -> Option<String> {
    let id = rule.raw.get("id").filter(|v| truthy(Some(v)))?;
    Some(crate::net::target::truncate(&py_str(Some(id)), 64))
}

/// Relay a connection matched by a residential rule through the upstream, untouched (addon.py
/// `_residential_stack`, `tcp_message`, `tcp_end`, `tcp_error`). `buffered` is what the client
/// already sent (its ClientHello); it goes first.
pub async fn relay(
    ctx: &Ctx,
    mut client: tokio::net::TcpStream,
    buffered: Vec<u8>,
    flow: &Flow,
    host: &str,
    port: u16,
    rule: &RuleView,
) -> anyhow::Result<()> {
    let vm_id = flow.vm_id.as_deref();
    let exit = ctx.exit.snapshot();
    let country = exit.country_for(Some(rule));
    let refuse = |why: String| {
        let reason = format!("residential exit unavailable: {why}");
        tracing::warn!("[mitm] {reason} ({host}:{port})");
        ctx.log
            .append_value(&exit_record(ctx, rule, host, port, vm_id, country.as_deref(), &reason));
        Ok(())
    };
    let up = match exit.ready() {
        Ok(up) => up,
        Err(why) => return refuse(why),
    };
    let Some(name) = encode_host(host) else {
        return refuse(format!(
            "{:?} cannot be put in a CONNECT request",
            crate::net::target::truncate(host, 60)
        ));
    };
    if let Some(why) = up.country_refusal(country.as_deref()) {
        return refuse(why);
    }
    let session = exit.session_for(vm_id);
    let (user, pw) = up.credentials(session.as_deref(), country.as_deref());
    let usage = Arc::new(std::sync::Mutex::new(Usage::new(
        host.to_owned(),
        port,
        flow.vm_id.clone(),
        rule,
        country.clone(),
    )));
    let record = |interim: bool, error: Option<String>| {
        let rec = usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .record(ctx, interim, error);
        ctx.log.append_value(&rec);
    };
    tracing::info!(
        "[mitm] residential exit for {host}:{port} (rule={}, tenant={})",
        rule_name(rule),
        ctx.config.tenant
    );
    let tunnel = match open(&up, &name, port, &user, &pw, ctx).await {
        Ok(t) => t,
        Err(e) => {
            record(false, Some(format!("residential exit unreachable: {e}")));
            return Ok(());
        }
    };
    let mut counted = Counted {
        inner: tunnel,
        usage: usage.clone(),
        log: &ctx.log,
        tenant: &ctx.config.tenant,
    };
    if let Err(e) = counted.write_all(&buffered).await {
        record(false, Some(format!("residential exit unreachable: {e}")));
        return Ok(());
    }
    drop(buffered);
    // Both ways at once, so neither side waits on the other (two peers that both send a lot
    // cannot stall the relay).
    let result = tokio::io::copy_bidirectional(&mut client, &mut counted).await;
    // The last record says why a relay ended early.
    record(
        false,
        result.as_ref().err().map(|e| format!("residential relay failed: {e}")),
    );
    result.map(|_| ()).map_err(Into::into)
}

/// The tunnel, counted: bytes written are `bytes_out`, bytes read `bytes_in`, and an interim
/// record goes out every [`INTERIM_BYTES`] (addon.py `tcp_message`).
struct Counted<'a> {
    inner: Box<dyn Tunnel>,
    usage: Arc<std::sync::Mutex<Usage>>,
    log: &'a crate::log::TrafficLog,
    tenant: &'a str,
}

impl Counted<'_> {
    fn count(&self, out: bool, n: usize) {
        let mut u = self.usage.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if out {
            u.bytes_out += n as u64;
        } else {
            u.bytes_in += n as u64;
        }
        if u.unbilled() >= INTERIM_BYTES {
            let rec = u.record_with(self.tenant, true, None);
            self.log.append_value(&rec);
        }
    }
}

impl AsyncRead for Counted<'_> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let r = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len() - before;
        if n > 0 {
            self.count(false, n);
        }
        r
    }
}

impl AsyncWrite for Counted<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let r = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &r {
            self.count(true, *n);
        }
        r
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---- plain HTTP (feature 13) ----

/// What a plain-HTTP residential request carries to the exchange: where to send it, and how. Kept
/// in the flow's extensions (never `flow.meta`, which a record or a later step could copy), so it
/// goes when the flow goes, however the flow ends. No `Debug`: it holds the password.
#[derive(Clone)]
pub struct HttpExit {
    pub upstream: Upstream,
    pub user: String,
    pub password: String,
}

/// The step after `match_rule` (addon.py request 4714-4760): a plain-HTTP request whose rule sends
/// it out residential goes through the upstream as one absolute-form request, with no swap and no
/// AI review after it, or is refused with one record. A TLS flow never gets here (it was relayed).
pub struct ResidentialHttp(pub Arc<Ctx>);

impl Step for ResidentialHttp {
    fn name(&self) -> &'static str {
        "residential_http"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Request]
    }
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            let ctx = &self.0;
            let effect = crate::log::record::meta_str(flow, "effect")
                .unwrap_or("allow")
                .to_owned();
            let Some(rule) = flow.meta.get("rule_view").and_then(RuleView::from_value) else {
                return Verdict::Continue;
            };
            if rule.raw.get("exit").and_then(Value::as_str) != Some("residential")
                || !RESIDENTIAL_EFFECTS.contains(&effect.as_str())
            {
                return Verdict::Continue;
            }
            let host = crate::http::policy::req(flow).host;
            if exempt(ctx, &host) {
                return Verdict::Continue;
            }
            let refuse = |flow: &mut Flow, why: &str| {
                flow.meta.insert("effect", "residential".into());
                let mut rec = http_record(ctx, flow);
                rec.status = cc_contracts::Maybe::Value(403u64.into());
                rec.extra.insert(
                    "error".into(),
                    crate::net::target::truncate(&format!("residential exit unavailable: {why}"), 200).into(),
                );
                crate::log::record::log_once(ctx, flow, &rec);
                Verdict::Answer(Box::new(crate::http::answer::json(
                    http::StatusCode::FORBIDDEN,
                    &json!({"error": "residential_exit_unavailable", "host": host, "tenant": ctx.config.tenant}),
                )))
            };
            let up = match ctx.exit.ready() {
                Ok(up) => up,
                Err(why) => return refuse(flow, &why),
            };
            if up.scheme == "socks5" {
                return refuse(flow, "plain HTTP needs an HTTP upstream, not SOCKS5");
            }
            if encode_host(&host).is_none() {
                let shown = format!("{:?}", crate::net::target::truncate(&host, 60));
                return refuse(flow, &format!("{shown} cannot be put in a CONNECT request"));
            }
            let country = ctx.exit.country_for(Some(&rule));
            if let Some(why) = up.country_refusal(country.as_deref()) {
                return refuse(flow, &why);
            }
            let session = ctx.exit.session_for(flow.vm_id.as_deref());
            let (user, password) = up.credentials(session.as_deref(), country.as_deref());
            flow.meta.insert("effect", "residential".into());
            flow.meta.insert("exit_http", json!({"country": country}));
            flow.extensions.insert(HttpExit {
                upstream: up,
                user,
                password,
            });
            Verdict::Forward
        })
    }
}

/// The exit chosen for this flow, taken out (each is used once).
pub fn take_exit(flow: &mut Flow) -> Option<HttpExit> {
    flow.extensions.remove::<HttpExit>()
}

/// addon.py `_residential_http_record`: host level only, no method or path.
pub fn http_record(ctx: &Ctx, flow: &Flow) -> cc_contracts::traffic::TrafficRecord {
    let mut rec = crate::log::record::http_record(ctx, flow, "residential");
    rec.method = cc_contracts::Maybe::Absent;
    rec.path = cc_contracts::Maybe::Absent;
    let port = flow.destination().map_or(80, |d| d.port);
    rec.port = cc_contracts::Maybe::Value(u64::from(port).into());
    rec.extra.insert("exit".into(), "residential".into());
    if let Some(c) = flow
        .meta
        .get("exit_http")
        .and_then(|e| e.get("country"))
        .and_then(Value::as_str)
    {
        rec.extra.insert("exit_country".into(), c.into());
    }
    rec
}

/// Send one plain-HTTP request through the upstream as an absolute-form request.
pub async fn send_http(
    ctx: &Ctx,
    exit: &HttpExit,
    req: http::Request<crate::http::buffered::Buffered>,
    host: &str,
    port: u16,
    tls: bool,
) -> Result<http::Response<Bytes>, String> {
    // One deadline for all of it: the CONNECT, TLS to the site, the handshake and the answer.
    tokio::time::timeout(
        crate::http::upstream::ANSWER_TIMEOUT,
        send_http_once(ctx, exit, req, host, port, tls),
    )
    .await
    .map_err(|_| "the site did not answer in time".to_owned())?
}

async fn send_http_once(
    ctx: &Ctx,
    exit: &HttpExit,
    req: http::Request<crate::http::buffered::Buffered>,
    host: &str,
    port: u16,
    tls: bool,
) -> Result<http::Response<Bytes>, String> {
    use http_body_util::BodyExt;
    // As mitmproxy's upstream mode sends it: a CONNECT to the name on its port, then the request
    // inside (TLS to the site first for HTTPS), so the exit resolves the name.
    let io = dial_http(ctx, exit, host, port, tls).await?;
    let (mut send, conn) = hyper::client::conn::http1::Builder::new()
        .preserve_header_case(true)
        .handshake(hyper_util::rt::TokioIo::new(io))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(conn);
    let resp = send.send_request(req).await.map_err(|e| e.to_string())?;
    let (parts, body) = resp.into_parts();
    let body = http_body_util::Limited::new(body, crate::http::MAX_BODY)
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok(http::Response::from_parts(parts, body))
}

/// The tunnel through the exit to the site by name, with TLS to the site when `tls`.
async fn dial_http(ctx: &Ctx, exit: &HttpExit, host: &str, port: u16, tls: bool) -> Result<Box<dyn Tunnel>, String> {
    let name = encode_host(host).ok_or_else(|| format!("{host} cannot be put in a CONNECT request"))?;
    let tunnel = open(&exit.upstream, &name, port, &exit.user, &exit.password, ctx).await?;
    if !tls {
        return Ok(tunnel);
    }
    // The site sees a browser's handshake (the built-in profile: a plain request has no
    // ClientHello of the agent's to copy), offering HTTP/1.1, which is what is sent on it.
    let http11 = [crate::tls::config::HTTP11.to_vec()];
    let stream = ctx
        .mirror
        .connect(crate::tls::chrome::hello(), Some(&http11), &name, tunnel, false)
        .await
        .map_err(|e| format!("TLS handshake with {name} failed: {e}"))?;
    Ok(Box::new(stream))
}

/// A websocket upgrade through the exit, as `send_http` sends a request: the site's answer, whose
/// upgrade the caller takes over when it is a 101.
pub async fn upgrade_http(
    ctx: &Ctx,
    exit: &HttpExit,
    req: http::Request<crate::http::buffered::Buffered>,
    host: &str,
    port: u16,
    tls: bool,
) -> Result<http::Response<hyper::body::Incoming>, String> {
    // One deadline for all of it, as `send_http`: the CONNECT, TLS, the handshake and the 101.
    let once = async {
        let io = dial_http(ctx, exit, host, port, tls).await?;
        let (mut send, conn) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!("[proxy] residential websocket connection: {e}");
            }
        });
        send.send_request(req).await.map_err(|e| e.to_string())
    };
    tokio::time::timeout(crate::http::upstream::ANSWER_TIMEOUT, once)
        .await
        .map_err(|_| "the site did not answer in time".to_owned())?
}

/// The residential plain-HTTP record once the answer is in, or the request failed (addon.py
/// `response` and `error` for `cc_exit_http`).
pub struct ResidentialRecord(pub Arc<Ctx>);

impl Step for ResidentialRecord {
    fn name(&self) -> &'static str {
        "residential_record"
    }
    fn hooks(&self) -> &'static [Hook] {
        &[Hook::Response, Hook::Error]
    }
    fn reads_body(&self, _: Hook, _: &mut Flow) -> bool {
        false
    }
    fn run<'a>(&'a self, hook: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
        Box::pin(async move {
            if !flow.meta.contains_key("exit_http") {
                return Verdict::Continue;
            }
            let ctx = &self.0;
            let mut rec = http_record(ctx, flow);
            if hook == Hook::Response {
                if let Some(resp) = &flow.response {
                    rec.status = cc_contracts::Maybe::Value(u64::from(resp.status().as_u16()).into());
                    rec.extra.insert(
                        "bytes_out".into(),
                        flow.request.as_ref().map_or(0, |r| r.body().len()).into(),
                    );
                    rec.extra.insert("bytes_in".into(), resp.body().len().into());
                }
            } else {
                let e = flow.error.clone().unwrap_or_else(|| "upstream error".into());
                let e = if e.is_empty() { "upstream error".to_owned() } else { e };
                rec.extra.insert(
                    "error".into(),
                    crate::net::target::truncate(&format!("residential exit unreachable: {e}"), 200).into(),
                );
            }
            crate::log::record::log_once(ctx, flow, &rec);
            Verdict::Continue
        })
    }
}

/// Add the plain-HTTP residential steps.
pub fn register(pipeline: &mut Pipeline, ctx: &Arc<Ctx>) {
    pipeline.push(order::RESIDENTIAL_HTTP, Arc::new(ResidentialHttp(ctx.clone())));
    pipeline.push(order::RESIDENTIAL_RECORD, Arc::new(ResidentialRecord(ctx.clone())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules(v: Value) -> Vec<RuleView> {
        v.as_array()
            .map(|a| a.iter().filter_map(RuleView::from_value).collect())
            .unwrap_or_default()
    }

    #[test]
    fn templates_render_like_the_addon() {
        let t = "customer-{username}[-cc-{country}][-sessid-{session}]";
        assert_eq!(
            render_template(t, "acme", "", Some("ab12"), Some("DE")),
            "customer-acme-cc-DE-sessid-ab12"
        );
        assert_eq!(render_template(t, "acme", "", None, Some("DE")), "customer-acme-cc-DE");
        assert_eq!(
            render_template(t, "acme", "", Some("ab12"), None),
            "customer-acme-sessid-ab12"
        );
        assert_eq!(render_template(t, "acme", "", None, None), "customer-acme");
        assert_eq!(
            render_template("groups-RESIDENTIAL[,country-{country}]", "", "", None, Some("de")),
            "groups-RESIDENTIAL,country-DE"
        );
        assert_eq!(
            render_template("{username}[-country-{country_lc}]", "z", "", None, Some("DE")),
            "z-country-de"
        );
        assert_eq!(
            render_template("user[-fixed]", "", "", Some("ab12"), None),
            "user-fixed"
        );
        assert_eq!(render_template("user[-fixed]", "", "", None, Some("DE")), "user");
        assert_eq!(
            render_template("user[-cc-{country}]", "", "", Some("ab12"), None),
            "user"
        );
        assert_eq!(render_template("a[b[{session}]c", "", "", Some("s"), None), "a[bsc");
        assert_eq!(render_template("{password}{nope}", "", "pw", None, None), "pw{nope}");
    }

    #[test]
    fn rule_precedence_is_the_engines() {
        let r = rules(json!([
            {"name": "block-social", "match_domain": "*.social.test", "effect": "block", "priority": 10},
            {"name": "scrape-all", "match_domain": "*", "effect": "allow", "exit": "residential", "priority": 500},
            {"name": "by-ip", "match_domain": "10.88.0.10", "match_port": 5432, "exit": "residential", "priority": 600},
            {"name": "ask", "match_domain": "ask.test", "effect": "require_permission", "exit": "residential", "priority": 1},
            {"name": "scoped", "match_domain": "only.test", "exit": "residential", "vm_id": "vm-1", "priority": 2}
        ]));
        let name = |h: &str, p: u16, vm: Option<&str>| residential_rule(&r, h, Some(p), vm, false).and_then(|r| r.name);
        assert_eq!(name("www.social.test", 443, None), None, "a block is never walked past");
        assert_eq!(name("elsewhere.test", 443, None).as_deref(), Some("scrape-all"));
        assert_eq!(
            name("10.88.0.10", 443, None),
            None,
            "a wildcard never matches an address"
        );
        assert_eq!(name("10.88.0.10", 5432, None).as_deref(), Some("by-ip"));
        assert_eq!(
            name("ask.test", 443, None),
            None,
            "only allow and tunnel rules may exit"
        );
        assert_eq!(name("only.test", 443, Some("vm-1")).as_deref(), Some("scoped"));
        assert_eq!(name("only.test", 443, Some("vm-2")).as_deref(), Some("scrape-all"));
        assert!(
            residential_rule(&r, "elsewhere.test", Some(443), None, true).is_none(),
            "never for a locked agent"
        );
        assert!(configured(&r));
    }

    #[test]
    fn sticky_sessions_are_per_agent_and_salted() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("exit.json");
        let salt = "s".repeat(32);
        std::fs::write(
            &path,
            json!({"enabled": true, "sticky": true, "sticky_salt": salt,
            "upstream": {"scheme": "http", "host": "up.example", "port": 3128}})
            .to_string(),
        )?;
        let exit = ExitConfig::new(&path);
        let a = exit.session_for(Some("vm-1"));
        assert_eq!(a.as_ref().map(String::len), Some(12));
        assert_eq!(a, exit.session_for(Some("vm-1")));
        assert_ne!(a, exit.session_for(Some("vm-2")));
        assert!(exit.ready().is_ok());
        std::fs::write(
            &path,
            json!({"enabled": true, "sticky": true, "sticky_salt": "short",
            "upstream": {"scheme": "http", "host": "up.example", "port": 3128}})
            .to_string(),
        )?;
        let f = std::fs::File::options().write(true).open(&path)?;
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))?;
        assert_eq!(
            exit.ready().err().as_deref(),
            Some("this firewall's sticky-session salt is missing")
        );
        std::fs::remove_file(&path)?;
        assert_eq!(exit.ready().err().as_deref(), Some("no residential exit is configured"));
        Ok(())
    }

    #[tokio::test]
    async fn speaks_socks5_with_a_password_only() -> Result<(), Box<dyn std::error::Error>> {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let srv = tokio::spawn(async move {
            let mut g = [0u8; 3];
            server.read_exact(&mut g).await?;
            assert_eq!(g, [5, 1, 2], "only method 0x02 is offered");
            server.write_all(&[5, 2]).await?;
            let mut a = [0u8; 2 + 1 + 1 + 2];
            server.read_exact(&mut a).await?;
            assert_eq!(a, [1, 1, b'u', 2, b'p', b'w']);
            server.write_all(&[1, 0]).await?;
            let mut r = vec![0u8; 5 + 9 + 2];
            server.read_exact(&mut r).await?;
            assert_eq!(&r[..5], &[5, 1, 0, 3, 9]);
            assert_eq!(&r[5..14], b"shop.test");
            assert_eq!(&r[14..], &443u16.to_be_bytes());
            server.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Ok::<_, std::io::Error>(())
        });
        socks5(&mut client, "shop.test", 443, "u", "pw").await?;
        srv.await??;
        // An upstream that offers no authentication is refused.
        let (mut client, mut server) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let mut g = [0u8; 3];
            let _ = server.read_exact(&mut g).await;
            let _ = server.write_all(&[5, 0]).await;
        });
        assert!(socks5(&mut client, "shop.test", 443, "u", "pw").await.is_err());
        Ok(())
    }
}
