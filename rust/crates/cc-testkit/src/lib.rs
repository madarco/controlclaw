//! Test fixtures shared by every crate, the binaries' tests and the conformance rig: a key folder
//! laid out like `/opt/controlclaw/keys`, tokens signed the way the console and the firewall sign
//! them, and a fake console that records what the agents send it.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cc_auth::jwt::{self, SignKey};
use cc_auth::sign::binding_claims;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

/// One Ed25519 pair as PEM, the way the boxes keep them (PKCS#8 private, SPKI public).
#[derive(Clone)]
pub struct Pair {
    pub private_pem: String,
    pub public_pem: String,
}

impl Pair {
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        Self::from_signing(&sk)
    }

    /// The same pair every time for one seed, so fixtures can be committed.
    pub fn from_seed(seed: u8) -> Self {
        Self::from_signing(&SigningKey::from_bytes(&[seed; 32]))
    }

    fn from_signing(sk: &SigningKey) -> Self {
        Self {
            private_pem: sk
                .to_pkcs8_pem(LineEnding::LF)
                .map(|p| p.to_string())
                .unwrap_or_default(),
            public_pem: sk.verifying_key().to_public_key_pem(LineEnding::LF).unwrap_or_default(),
        }
    }

    pub fn sign_key(&self) -> SignKey {
        SignKey::ed25519_pkcs8_pem(&self.private_pem).unwrap_or_else(|e| panic!("fixture key: {e}"))
    }
}

/// A box's key folder plus the private halves a test needs to sign as the console or the firewall.
pub struct BoxKeys {
    pub dir: PathBuf,
    pub vm_id: String,
    pub hostname: String,
    /// The box's own pair (`vm_private_key.pem`).
    pub vm: Pair,
    /// The console's pair; the box has its public half as `saas_public_key.pem`.
    pub saas: Pair,
    /// The firewall's pair; an agent box has its public half as `mitm_pinned_pubkey.pem`.
    pub firewall: Pair,
}

impl BoxKeys {
    /// Write a key folder at `dir`. Seeds make the keys the same on every run.
    pub fn write(dir: &Path, vm_id: &str, hostname: &str) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let keys = Self {
            dir: dir.to_path_buf(),
            vm_id: vm_id.into(),
            hostname: hostname.into(),
            vm: Pair::from_seed(1),
            saas: Pair::from_seed(2),
            firewall: Pair::from_seed(3),
        };
        std::fs::write(dir.join("vm_id"), format!("{vm_id}\n"))?;
        std::fs::write(dir.join("vm_hostname"), format!("{hostname}\n"))?;
        std::fs::write(dir.join("vm_private_key.pem"), &keys.vm.private_pem)?;
        std::fs::write(dir.join("saas_public_key.pem"), &keys.saas.public_pem)?;
        std::fs::write(dir.join("mitm_pinned_pubkey.pem"), &keys.firewall.public_pem)?;
        Ok(keys)
    }

    /// A console token for this box: `{vmId, …extra}`, 30 s.
    pub fn console_token(&self, extra: Value) -> String {
        let mut c = Map::new();
        c.insert("vmId".into(), Value::String(self.vm_id.clone()));
        if let Value::Object(e) = extra {
            c.extend(e);
        }
        jwt::sign(c, &self.saas.sign_key(), Some(30), None).unwrap_or_default()
    }

    /// A firewall token bound to one request, as the firewall signs them.
    pub fn firewall_token(&self, purpose: &str, method: &str, path: &str, body: Option<&[u8]>) -> String {
        let mut c = binding_claims(method, path, Some(&self.hostname), body);
        c.insert("vmId".into(), Value::String(self.vm_id.clone()));
        c.insert("purpose".into(), Value::String(purpose.into()));
        c.insert("iss".into(), Value::String("fw_test".into()));
        jwt::sign(c, &self.firewall.sign_key(), Some(30), None).unwrap_or_default()
    }

    /// Any claims, signed with one of the three keys.
    pub fn sign_with(&self, who: Signer, claims: Value, lifetime_s: Option<i64>) -> String {
        self.sign_with_at(who, claims, lifetime_s, None)
    }

    /// The same, issued at `iat` (seconds) instead of now.
    pub fn sign_with_at(&self, who: Signer, claims: Value, lifetime_s: Option<i64>, iat: Option<i64>) -> String {
        let key = match who {
            Signer::Console => self.saas.sign_key(),
            Signer::Firewall => self.firewall.sign_key(),
            Signer::Box => self.vm.sign_key(),
        };
        jwt::sign(claims.as_object().cloned().unwrap_or_default(), &key, lifetime_s, iat).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    Console,
    Firewall,
    Box,
}

/// A request the fake console received.
#[derive(Debug, Clone)]
pub struct Received {
    pub method: String,
    pub path: String,
    pub authorization: Option<String>,
    pub body: Value,
}

#[derive(Default)]
struct ConsoleState {
    received: Vec<Received>,
    /// Answers by path, in order; the last one repeats.
    answers: HashMap<String, VecDeque<(u16, Value)>>,
}

/// A stand-in for the console's `/api/vm-agent/*`: records everything, answers what it was told
/// (200 `{}` otherwise). Queue heartbeat commands with [`FakeConsole::queue_command`].
#[derive(Clone)]
pub struct FakeConsole {
    pub addr: SocketAddr,
    state: Arc<Mutex<ConsoleState>>,
}

impl FakeConsole {
    pub async fn start() -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(ConsoleState::default()));
        let mut router = cc_http::Router::new(&["all"]);
        let s = state.clone();
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let s = s.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let raw = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    let path = parts.uri.path().to_string();
                    let (status, answer) = {
                        let mut st = s.lock().unwrap_or_else(|e| e.into_inner());
                        st.received.push(Received {
                            method: parts.method.to_string(),
                            path: path.clone(),
                            authorization: cc_http::header(&parts, "authorization").map(str::to_string),
                            body: serde_json::from_slice(&raw).unwrap_or(Value::Null),
                        });
                        match st.answers.get_mut(&path) {
                            Some(q) if q.len() > 1 => q.pop_front().unwrap_or((200, json!({}))),
                            Some(q) => q.front().cloned().unwrap_or((200, json!({}))),
                            None => (200, json!({})),
                        }
                    };
                    cc_http::json(status, &answer)
                }
            },
        );
        tokio::spawn(cc_http::serve(listener, Arc::new(router)));
        Ok(Self { addr, state })
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    /// Answer `path` with these, in order; the last repeats.
    pub fn answer(&self, path: &str, answers: Vec<(u16, Value)>) {
        if let Ok(mut st) = self.state.lock() {
            st.answers.insert(path.to_string(), answers.into());
        }
    }

    /// Hand out one heartbeat command on the next beat, then `{command: null}`.
    pub fn queue_command(&self, id: &str, action: &str, payload: Value) {
        let path = "/api/vm-agent/firewall";
        if let Ok(mut st) = self.state.lock() {
            let q = st.answers.entry(path.to_string()).or_default();
            if q.is_empty() {
                q.push_back((200, json!({"command": null})));
            }
            q.push_front((
                200,
                json!({"command": {"id": id, "action": action, "payload": payload}}),
            ));
        }
    }

    pub fn received(&self) -> Vec<Received> {
        self.state.lock().map(|s| s.received.clone()).unwrap_or_default()
    }

    /// Wait until a request for `path` has come in, up to `timeout`.
    pub async fn wait_for(&self, path: &str, timeout: std::time::Duration) -> Option<Received> {
        let until = tokio::time::Instant::now() + timeout;
        loop {
            if let Some(r) = self.received().into_iter().rev().find(|r| r.path == path) {
                return Some(r);
            }
            if tokio::time::Instant::now() > until {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}
