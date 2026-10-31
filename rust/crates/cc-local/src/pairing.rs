//! Pairing: an agent's machine joins this firewall with a one-time code (plan §4, step 8).
//!
//! - **The code.** The admin makes one (`mitm-agent pair-code`, or the admin API): 12 characters
//!   of Crockford base32 (60 bits), shown as `4F7K-92QD-XM3P`, single use, 10 minutes by default.
//!   At most [`PENDING_MAX`] wait at once. It travels by hand to the agent's machine. Only the code
//!   can name the agent's address (else it is the address the request comes from, which must be the
//!   one the machine says it has) and allow it to replace an agent already there.
//! - **The exchange.** The code itself never crosses the network, so the pairing endpoint can be
//!   plain HTTP before any tunnel exists. The agent sends its request with
//!   `proof = HMAC-SHA256(code, "cc-pair-v1 request\n" + request)`; the firewall finds the pending
//!   code the proof was made with, records the agent, spends the code, and answers with
//!   `mac = HMAC-SHA256(code, "cc-pair-v1 response\n" + pairing)`. The agent takes the firewall's
//!   key and CA only from an answer whose mac checks, and the answer echoes its nonce. An observer
//!   sees HMACs only, and 60 bits cannot be searched offline within the code's lifetime.
//! - **Guessing online** is throttled: ten wrong codes a minute from one address, then 429 for the
//!   rest of the minute. A try takes its place in the count before the code is checked, so parallel
//!   requests cannot get past it. There is no cap over all addresses: anyone could use one to block
//!   every pairing, and with 60 bits and a 10-minute code even a million tries a minute from many
//!   addresses find one with odds of about 1 in 10^11. Once a code has matched, any refusal spends
//!   it and counts, so a refusal never confirms a guess for free.
//! - The firewall keeps the plain code until it is used or expires (it needs it to check the
//!   HMAC), in `local.db`, which only the firewall's user can read.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use hmac::{Hmac, Mac};
use http::Method;
use rand::Rng;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::db::{Db, now_s};
use crate::wireguard::{self, WgAnswer, WgInfo};

/// Crockford's base32: no I, L, O or U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const CODE_LEN: usize = 12;
pub const TTL_DEFAULT_MIN: i64 = 10;
pub const TTL_MAX_MIN: i64 = 60;
pub const PENDING_MAX: i64 = 20;
const FAILURES_PER_MINUTE: usize = 10;
const BODY_MAX: usize = 32 * 1024;
const NAME_MAX: usize = 64;
pub const REQUEST_TAG: &str = "cc-pair-v1 request\n";
pub const RESPONSE_TAG: &str = "cc-pair-v1 response\n";

/// A new code, grouped by four for reading aloud.
fn new_code() -> String {
    let mut rng = rand::thread_rng();
    let raw: String = (0..CODE_LEN).map(|_| ALPHABET[rng.gen_range(0..32)] as char).collect();
    group(&raw)
}

fn group(raw: &str) -> String {
    raw.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// The code as the HMAC key: upper case, no dashes or spaces, O read as 0 and I or L as 1.
/// `None` when it is not 12 characters of the alphabet.
pub fn normalize(code: &str) -> Option<String> {
    let s: String = code
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect();
    (s.len() == CODE_LEN && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

pub fn hmac_hex(code: &str, tag: &str, text: &str) -> String {
    let mut m = <Hmac<Sha256>>::new_from_slice(code.as_bytes()).expect("any key length");
    m.update(tag.as_bytes());
    m.update(text.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// An address the proxy can see an agent at: not loopback, unspecified, multicast or broadcast.
fn agent_address(a: Ipv4Addr) -> bool {
    !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast())
}

/// Equal in time, whatever the first difference.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct NewCode {
    pub id: i64,
    pub code: String,
    pub name: Option<String>,
    pub address: Option<String>,
    pub replace: bool,
    pub expires_at: i64,
}

/// What the admin says about the agent a code is for.
#[derive(Debug, Clone, Default)]
pub struct CodeFor<'a> {
    pub name: Option<&'a str>,
    /// Minutes; 10 by default, at most 60.
    pub ttl_min: Option<i64>,
    /// The address the proxy will see the agent at, when it is not the one pairing comes from (a
    /// NAT, a container on this machine). Only the admin sets it: the agent cannot choose its own.
    pub address: Option<&'a str>,
    /// Whether the agent may take the place of one already at its address.
    pub replace: bool,
}

/// The firewall's own address, which no agent may have.
fn own_address(c: &rusqlite::Connection) -> rusqlite::Result<Option<String>> {
    c.query_row(
        "SELECT private_ip FROM agents WHERE role = 'mitm' AND private_ip IS NOT NULL",
        [],
        |r| r.get(0),
    )
    .optional()
}

/// A code for one agent.
pub fn create_code(db: &Db, f: &CodeFor) -> Result<NewCode, String> {
    let ttl = f.ttl_min.unwrap_or(TTL_DEFAULT_MIN);
    if !(1..=TTL_MAX_MIN).contains(&ttl) {
        return Err(format!("the code's lifetime is 1 to {TTL_MAX_MIN} minutes"));
    }
    let name = match f.name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => Some(clean_name(n)?),
        None => None,
    };
    let now = now_s();
    let c = db.lock();
    let address = match f.address.map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) => {
            let ip = a
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("address: an IPv4 address, not {a}"))?;
            if !agent_address(ip) || own_address(&c).map_err(|e| e.to_string())? == Some(ip.to_string()) {
                return Err(format!("address: {a} cannot be an agent's address"));
            }
            Some(ip.to_string())
        }
        None => None,
    };
    c.execute("DELETE FROM pairing_codes WHERE expires_at <= ?1", [now])
        .map_err(|e| e.to_string())?;
    let pending: i64 = c
        .query_row("SELECT COUNT(*) FROM pairing_codes", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if pending >= PENDING_MAX {
        return Err(format!(
            "{PENDING_MAX} codes are waiting already: use or revoke one first"
        ));
    }
    let code = new_code();
    let expires_at = now + ttl * 60;
    c.execute(
        "INSERT INTO pairing_codes (code, name, address, replace, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![normalize(&code), name, address, f.replace, now, expires_at],
    )
    .map_err(|e| e.to_string())?;
    Ok(NewCode {
        id: c.last_insert_rowid(),
        code,
        name,
        address,
        replace: f.replace,
        expires_at,
    })
}

/// A code still waiting, without the code.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct PendingCode {
    pub id: i64,
    pub name: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub address: Option<String>,
    pub replace: bool,
}

/// The codes still waiting, without the codes.
pub fn list_pending(db: &Db) -> rusqlite::Result<Vec<PendingCode>> {
    let c = db.lock();
    let mut q = c.prepare(
        "SELECT id, name, created_at, expires_at, address, replace FROM pairing_codes WHERE expires_at > ?1 ORDER BY id",
    )?;
    let rows = q
        .query_map([now_s()], |r| {
            Ok(PendingCode {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                expires_at: r.get(3)?,
                address: r.get(4)?,
                replace: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Whether a waiting code had that id.
pub fn revoke(db: &Db, id: i64) -> rusqlite::Result<bool> {
    Ok(db.lock().execute("DELETE FROM pairing_codes WHERE id = ?1", [id])? > 0)
}

fn clean_name(n: &str) -> Result<String, String> {
    let n = n.trim();
    if n.is_empty() || n.chars().count() > NAME_MAX || n.chars().any(char::is_control) {
        return Err(format!(
            "a name is 1 to {NAME_MAX} characters, with no control characters"
        ));
    }
    Ok(n.to_string())
}

/// What the agent sends, inside `request` (a JSON string, so the proof covers its exact bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub v: u32,
    /// 32 random bytes, hex: the answer must echo it.
    pub nonce: String,
    /// The vm-agent's Ed25519 public key (SPKI PEM), recorded with the agent: a box token from it
    /// verifies with this.
    pub agent_public_key: String,
    #[serde(default)]
    pub name: Option<String>,
    /// The machine's own source address toward the firewall. Under the proof, so a request
    /// replayed from another address is refused (unless the admin set the address on the code).
    #[serde(default)]
    pub source: Option<String>,
    /// sha256 (hex) of a secret the agent keeps: `POST /unpair` with the secret removes the agent
    /// (a connect undone, a disconnect), so the machine can pair again without `--replace`.
    #[serde(default)]
    pub unpair_sha256: Option<String>,
    /// The agent's WireGuard public key: it pairs over the tunnel (remote mode), and its tunnel
    /// address is its identity.
    #[serde(default)]
    pub wg_public_key: Option<String>,
    /// `ip:port` where the vm-agent listens for the firewall's calls, when it is not
    /// `<address>:3100` (`up --local`: the vm-agent on the host, OpenClaw in a container).
    #[serde(default)]
    pub agent_listen: Option<String>,
}

/// Where the firewall calls an agent's vm-agent when pairing does not say.
pub const AGENT_PORT: u16 = 3100;

/// `agent_listen`: an IPv4 address and port where an agent can be (as [`agent_address`]: not
/// loopback, unspecified, multicast or broadcast; nor link-local, the clouds' metadata service), so
/// the firewall's calls cannot be pointed at its own services. Pairing also holds it to the
/// request's source, or to a private address when the code names the agent's.
fn agent_listen(raw: &str) -> Result<SocketAddrV4, String> {
    let a: SocketAddrV4 = raw
        .trim()
        .parse()
        .map_err(|_| format!("agent_listen: an IPv4 address and port, not {raw}"))?;
    if a.port() == 0 || !agent_address(*a.ip()) || a.ip().is_link_local() {
        return Err(format!("agent_listen: {a} cannot be an agent's"));
    }
    Ok(a)
}

/// `up --local`'s layout (packages/cli/src/local.ts): OpenClaw on the `agents` network
/// (172.31.251.0/24), its vm-agent on this machine's side of `outside`.
const LOCAL_AGENTS: Ipv4Addr = Ipv4Addr::new(172, 31, 251, 0);
const LOCAL_HOST_OUTSIDE: Ipv4Addr = Ipv4Addr::new(172, 31, 252, 1);

/// Where an agent's vm-agent may listen: the request's source (the machine itself), or with a code
/// that names the agent's address, that address, or for an `up --local` container (the code names
/// one on `agents`) the machine's side of `outside`.
fn listen_allowed(listen: Ipv4Addr, named: Option<Ipv4Addr>, source: Ipv4Addr) -> Result<(), String> {
    let ok = match named {
        None => listen == source,
        Some(a) => listen == a || (a.octets()[..3] == LOCAL_AGENTS.octets()[..3] && listen == LOCAL_HOST_OUTSIDE),
    };
    if ok {
        return Ok(());
    }
    let want = match named {
        None => source.to_string(),
        Some(a) => format!("{a}, the address on the code"),
    };
    Err(format!(
        "agent_listen: {listen} is not this agent's (it must be {want})"
    ))
}

/// This machine's address toward `to` (a UDP connect sends nothing): where its calls come from.
fn source_toward(to: SocketAddrV4) -> Option<Ipv4Addr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(to).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

/// This machine's own IPv4 addresses (`/proc/net/fib_trie`'s local ones; none where it cannot be
/// read): the firewall's calls must not be pointed at one of its own services.
pub(crate) fn firewall_addresses() -> Vec<Ipv4Addr> {
    let Ok(t) = std::fs::read_to_string("/proc/net/fib_trie") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in t.lines() {
        let l = line.trim_start_matches([' ', '|', '-', '+']).trim();
        if let Ok(ip) = l.parse::<Ipv4Addr>() {
            last = Some(ip);
        } else if l.starts_with("/32 host LOCAL")
            && let Some(ip) = last
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

/// What the firewall answers, inside `pairing`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pairing {
    pub v: u32,
    pub nonce: String,
    pub agent_id: String,
    pub name: String,
    pub address: String,
    /// The firewall's Ed25519 public key (SPKI PEM): the vm-agent pins it.
    pub firewall_public_key: String,
    /// The CA the proxy signs with (PEM).
    pub ca_pem: String,
    /// host:port of the proxy, when the firewall knows the address agents reach it at.
    pub proxy: Option<String>,
    /// The DNS server agents use, when the firewall serves one.
    pub dns: Option<String>,
    /// Agents that were at this address before, and are not any more.
    #[serde(default)]
    pub replaced: Vec<String>,
    /// The tunnel, when the agent paired with a WireGuard key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg: Option<WgAnswer>,
    /// The address the firewall calls `agent_listen` from (its own on that network): the only one
    /// the vm-agent takes connections from. A firewall in a container calls from the container's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calls_from: Option<String>,
}

/// The firewall's side of the answer, read at each pairing (a rotated CA is picked up).
#[derive(Debug, Clone)]
pub struct FirewallInfo {
    pub public_key: String,
    pub ca_pem: String,
    pub proxy: Option<String>,
    pub dns: Option<String>,
    /// The firewall's WireGuard, when it runs one (remote agents).
    pub wg: Option<WgInfo>,
}

pub type InfoHook = Arc<dyn Fn() -> Result<FirewallInfo, String> + Send + Sync>;

/// Tries in the last minute that were not a pairing, by address.
#[derive(Default)]
struct Failures(HashMap<IpAddr, VecDeque<i64>>);

impl Failures {
    fn prune(&mut self, now: i64) {
        self.0.retain(|_, f| {
            while f.front().is_some_and(|t| *t <= now - 60) {
                f.pop_front();
            }
            !f.is_empty()
        });
    }
}

/// The unauthenticated pairing endpoint, `POST /pair`.
pub struct PairService {
    db: Arc<Db>,
    info: InfoHook,
    failures: Mutex<Failures>,
}

/// Why a pairing failed: the status and a message for the agent.
#[derive(Debug, PartialEq)]
pub struct Refusal(pub u16, pub String);

fn refuse(status: u16, msg: impl Into<String>) -> Refusal {
    Refusal(status, msg.into())
}

impl PairService {
    pub fn new(db: Arc<Db>, info: InfoHook) -> Arc<Self> {
        Arc::new(Self {
            db,
            info,
            failures: Mutex::default(),
        })
    }

    /// Counts a try from `ip` before it runs, in one step with the check: `false` when the
    /// address has used its tries this minute.
    fn take_try(&self, ip: IpAddr) -> bool {
        let now = now_s();
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.prune(now);
        let tries = f.0.entry(ip).or_default();
        if tries.len() >= FAILURES_PER_MINUTE {
            return false;
        }
        tries.push_back(now);
        true
    }

    /// A try that was not a wrong code (it paired, or the request was bad) does not count.
    fn give_back(&self, ip: IpAddr) {
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = f.0.get_mut(&ip) {
            t.pop_back();
        }
    }

    /// `{request, proof}` from `ip` → `{pairing, mac}`.
    pub fn pair(&self, body: &Value, ip: IpAddr) -> Result<Value, Refusal> {
        if !self.take_try(ip) {
            return Err(refuse(429, "Too many tries. Wait a minute."));
        }
        let r = self.try_pair(body, ip);
        // A wrong code, or a refusal after a code matched, counts; a bad request does not.
        if !matches!(r, Err(Refusal(401 | 409, _))) {
            self.give_back(ip);
        }
        r
    }

    fn try_pair(&self, body: &Value, ip: IpAddr) -> Result<Value, Refusal> {
        let (Some(text), Some(proof)) = (
            body.get("request").and_then(Value::as_str),
            body.get("proof").and_then(Value::as_str),
        ) else {
            return Err(refuse(400, "request (a JSON string) and proof are required"));
        };
        let req: PairRequest = serde_json::from_str(text).map_err(|e| refuse(400, format!("request: {e}")))?;
        if req.v != 1 {
            return Err(refuse(400, "request: version 1 only"));
        }
        if req.nonce.len() != 64 || !req.nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(refuse(400, "nonce: 32 bytes, hex"));
        }
        if VerifyingKey::from_public_key_pem(req.agent_public_key.trim()).is_err() {
            return Err(refuse(400, "agent_public_key: an Ed25519 public key (PEM)"));
        }
        let name = match req.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
            Some(n) => Some(clean_name(n).map_err(|e| refuse(400, e))?),
            None => None,
        };
        // Required, and checked before any code is tried: a client that does not send it (an older
        // CLI) is told so, and its code is kept.
        let source = match req.source.as_deref().filter(|a| !a.is_empty()) {
            Some(a) => a
                .parse::<Ipv4Addr>()
                .map_err(|_| refuse(400, "source: an IPv4 address"))?,
            None => {
                return Err(refuse(
                    400,
                    "The request does not say the machine's own address (source): update controlclaw.",
                ));
            }
        };
        let listen = match req.agent_listen.as_deref().filter(|a| !a.trim().is_empty()) {
            Some(a) => Some(agent_listen(a).map_err(|e| refuse(400, e))?),
            None => None,
        };
        let wg_key = match req.wg_public_key.as_deref() {
            Some(k) if wireguard::valid_key(k) => Some(k.to_string()),
            Some(_) => return Err(refuse(400, "wg_public_key: a WireGuard key (32 bytes, base64)")),
            None => None,
        };
        // Over the tunnel the firewall calls the agent's tunnel address: nothing may take its calls
        // out of the tunnel.
        if listen.is_some() && wg_key.is_some() {
            return Err(refuse(
                400,
                "agent_listen: not with wg_public_key (the firewall calls the tunnel address)",
            ));
        }
        let unpair = match req.unpair_sha256.as_deref() {
            Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => Some(h.to_ascii_lowercase()),
            Some(_) => return Err(refuse(400, "unpair_sha256: 32 bytes, hex")),
            None => None,
        };

        let mut c = self.db.lock();
        let tx = c.transaction().map_err(internal)?;
        let now = now_s();
        // Where the request came from, worked out before any code is tried, so a refusal for it
        // before a match says nothing about a code. It is the agent's address unless the code
        // names one.
        let own = own_address(&tx).map_err(internal)?;
        if let Some(l) = listen
            && (own.as_deref() == Some(l.ip().to_string().as_str()) || firewall_addresses().contains(l.ip()))
        {
            return Err(refuse(
                400,
                format!("agent_listen: {} is the firewall's own address", l.ip()),
            ));
        }
        let from: Result<Ipv4Addr, String> = match ip.to_canonical() {
            IpAddr::V4(v4) if !agent_address(v4) || own.as_deref() == Some(v4.to_string().as_str()) => Err(format!(
                "This request came from {v4}, where the proxy never sees an agent: make a code with the agent's address (pair-code --address)."
            )),
            IpAddr::V4(v4) if v4 != source => Err(format!(
                "This request came from {v4}, but the machine says it is {source} (a NAT, a reverse proxy, or someone replaying it): make a code with the address the proxy will see (pair-code --address)."
            )),
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(
                "This request came over IPv6: make a code with the agent's IPv4 address (pair-code --address).".into(),
            ),
        };
        type CodeRow = (i64, String, Option<String>, Option<String>, bool);
        let codes: Vec<CodeRow> = {
            let mut q = tx
                .prepare("SELECT id, code, name, address, replace FROM pairing_codes WHERE expires_at > ?1")
                .map_err(internal)?;
            q.query_map([now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .map_err(internal)?
                .collect::<rusqlite::Result<_>>()
                .map_err(internal)?
        };
        // Every pending code is tried, so the time taken says nothing about which one matched.
        let mut found = None;
        for row in codes {
            if same(&hmac_hex(&row.1, REQUEST_TAG, text), &proof.to_ascii_lowercase()) {
                found = Some(row);
            }
        }
        let Some((code_id, code, code_name, code_address, replace)) = found else {
            return Err(refuse(
                401,
                "No waiting pairing code matches. Check the code, or make a new one: it works once and expires.",
            ));
        };
        // From here the code matched: a refusal spends it and counts as a failure, so a refusal
        // never confirms a guess for free.
        let spend = |tx: rusqlite::Transaction, r: Refusal| -> Refusal {
            let _ = tx.execute("DELETE FROM pairing_codes WHERE id = ?1", [code_id]);
            let _ = tx.commit();
            tracing::info!("[cc-local] pairing: code {code_id} spent on a refusal: {}", r.1);
            Refusal(409, format!("{} The code is spent: make a new one.", r.1))
        };
        let info = (self.info)().map_err(|e| {
            tracing::error!("[cc-local] pairing: {e}");
            refuse(500, "The firewall could not read its key or CA")
        })?;
        // Over WireGuard the agent's identity is a fresh tunnel address. Where the request came from
        // does not matter there: a replayed request registers a key whose private half only the
        // real machine has.
        let tunnel = match (&wg_key, &info.wg) {
            (Some(_), None) => {
                return Err(spend(
                    tx,
                    refuse(
                        409,
                        "This firewall runs no WireGuard: pair without remote mode, or set it up (install.sh --wireguard).",
                    ),
                ));
            }
            // A code the admin made for an agent at an address is not for a remote one.
            (Some(_), Some(_)) if code_address.is_some() => {
                let a = code_address.unwrap_or_default();
                return Err(spend(
                    tx,
                    refuse(
                        409,
                        format!(
                            "This code is for the agent at {a}, not for one over WireGuard: make a code without --address."
                        ),
                    ),
                ));
            }
            (Some(k), Some(_))
                if tx
                    .query_row("SELECT 1 FROM agents WHERE wg_public_key = ?1", [k], |_| Ok(()))
                    .optional()
                    .map_err(internal)?
                    .is_some() =>
            {
                return Err(spend(
                    tx,
                    refuse(
                        409,
                        "This WireGuard key belongs to an agent already: make a new key (connect makes one each time).",
                    ),
                ));
            }
            (Some(_), Some(w)) => match wireguard::allocate(&tx, w) {
                Ok(ip) => Some((ip, w.clone())),
                Err(e) => return Err(spend(tx, refuse(409, e))),
            },
            (None, _) => None,
        };
        let named: Option<Ipv4Addr> = code_address.as_deref().and_then(|a| a.parse().ok());
        let address = match (code_address, from) {
            _ if tunnel.is_some() => tunnel.as_ref().map(|(ip, _)| ip.to_string()).unwrap_or_default(),
            // Checked when the code was made; the firewall's own address may have been recorded since.
            (Some(a), _) if own.as_deref() == Some(a.as_str()) => {
                return Err(spend(
                    tx,
                    refuse(409, format!("{a} is now the firewall's own address.")),
                ));
            }
            (Some(a), _) => a,
            (None, Ok(v4)) => v4.to_string(),
            (None, Err(e)) => return Err(spend(tx, refuse(409, e))),
        };
        // The vm-agent listens on the machine's own address, as it pairs; where the admin named the
        // agent's address on the code, there (or, for an `up --local` container, on its host).
        if let Some(l) = listen
            && let Err(e) = listen_allowed(*l.ip(), named, source)
        {
            return Err(spend(tx, refuse(409, e)));
        }
        let agent_id = format!("agent_{}", hex::encode(rand::random::<[u8; 8]>()));
        // The admin's name for the code first, then the machine's.
        let name = code_name.or(name).unwrap_or_else(|| agent_id.clone());
        // One agent per address: the proxy names traffic by its source address alone.
        let replaced: Vec<String> = {
            let mut q = tx
                .prepare("SELECT vm_id FROM agents WHERE private_ip = ?1 AND role <> 'mitm'")
                .map_err(internal)?;
            q.query_map([&address], |r| r.get(0))
                .map_err(internal)?
                .collect::<rusqlite::Result<_>>()
                .map_err(internal)?
        };
        if !replaced.is_empty() && !replace {
            let r = refuse(
                409,
                format!(
                    "{} is already at {address}. To put this machine in its place, make a code with pair-code --replace.",
                    replaced.join(", ")
                ),
            );
            return Err(spend(tx, r));
        }
        tx.execute(
            "DELETE FROM agents WHERE private_ip = ?1 AND role <> 'mitm'",
            [&address],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO agents (vm_id, role, name, private_ip, public_key, created_at, paired_at, unpair_sha256, wg_public_key, agent_addr) VALUES (?1, 'openclaw', ?2, ?3, ?4, ?5, ?5, ?6, ?7, ?8)",
            params![agent_id, name, address, req.agent_public_key.trim(), now, unpair, wg_key, listen.map(|a| a.to_string())],
        )
        .map_err(internal)?;
        tx.execute("DELETE FROM pairing_codes WHERE id = ?1", [code_id])
            .map_err(internal)?;
        tx.commit().map_err(internal)?;
        drop(c);
        for old in &replaced {
            tracing::info!("[cc-local] pairing: {agent_id} replaces {old} at {address}");
        }
        tracing::info!("[cc-local] paired {agent_id} ({name}) at {address}");

        let pairing = Pairing {
            v: 1,
            nonce: req.nonce,
            agent_id,
            name,
            address,
            firewall_public_key: info.public_key,
            ca_pem: info.ca_pem,
            // Over the tunnel, the proxy and DNS are the firewall's tunnel address.
            proxy: match &tunnel {
                Some((_, w)) => Some(format!("{}:{}", w.address, w.proxy_port)),
                None => info.proxy,
            },
            dns: match &tunnel {
                Some((_, w)) => Some(w.address.to_string()),
                None => info.dns,
            },
            replaced,
            calls_from: listen.and_then(source_toward).map(|a| a.to_string()),
            wg: tunnel.map(|(ip, w)| WgAnswer {
                firewall_public_key: w.public_key,
                endpoint: w.endpoint,
                address: ip.to_string(),
                firewall_address: w.address.to_string(),
            }),
        };
        let text = serde_json::to_string(&pairing).map_err(internal)?;
        let mac = hmac_hex(&code, RESPONSE_TAG, &text);
        Ok(json!({"pairing": text, "mac": mac}))
    }

    /// `{agent_id, secret}` → the agent is removed, when the secret is the one it paired with. The
    /// same 404 for an unknown agent and a wrong secret; wrong ones count like wrong codes.
    pub fn unpair(&self, body: &Value, ip: IpAddr) -> Result<Value, Refusal> {
        if !self.take_try(ip) {
            return Err(refuse(429, "Too many tries. Wait a minute."));
        }
        let s = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or_default();
        let (id, secret) = (s("agent_id"), s("secret"));
        let stored: Option<String> = self
            .db
            .lock()
            .query_row(
                "SELECT unpair_sha256 FROM agents WHERE vm_id = ?1 AND role = 'openclaw'",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?
            .flatten();
        let given = hex::encode(Sha256::digest(secret.as_bytes()));
        if secret.is_empty() || !stored.is_some_and(|h| same(&h, &given)) {
            return Err(refuse(404, "No such agent, or not its secret."));
        }
        self.db
            .lock()
            .execute("DELETE FROM agents WHERE vm_id = ?1", [id])
            .map_err(internal)?;
        self.give_back(ip);
        tracing::info!("[cc-local] unpaired {id}");
        Ok(json!({"ok": true}))
    }

    /// `POST /pair` and `POST /unpair`, and 404 for anything else.
    pub fn router(self: &Arc<Self>) -> cc_http::Router {
        let mut r = cc_http::Router::new(&["pair"]);
        let me = self.clone();
        r.exact("pair", Method::POST, "/pair", move |req, ctx| {
            let me = me.clone();
            async move {
                let body = match cc_http::read_body(req.into_body(), BODY_MAX).await {
                    Some(b) => serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null),
                    None => return reply(413, json!({"error": "Body too large or too slow"})),
                };
                match me.pair(&body, ctx.remote.ip()) {
                    Ok(v) => reply(200, v),
                    Err(Refusal(status, error)) => reply(status, json!({"error": error})),
                }
            }
        });
        let me = self.clone();
        r.exact("pair", Method::POST, "/unpair", move |req, ctx| {
            let me = me.clone();
            async move {
                let body = match cc_http::read_body(req.into_body(), BODY_MAX).await {
                    Some(b) => serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null),
                    None => return reply(413, json!({"error": "Body too large or too slow"})),
                };
                match me.unpair(&body, ctx.remote.ip()) {
                    Ok(v) => reply(200, v),
                    Err(Refusal(status, error)) => reply(status, json!({"error": error})),
                }
            }
        });
        r.fallback(cc_http::not_found);
        r
    }
}

fn internal(e: impl std::fmt::Display) -> Refusal {
    tracing::error!("[cc-local] pairing: {e}");
    refuse(500, "Failed")
}

fn reply(status: u16, body: Value) -> cc_http::Resp {
    let mut r = cc_http::json(status, &body);
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", http::HeaderValue::from_static("nosniff"));
    r
}

#[cfg(test)]
mod tests;
