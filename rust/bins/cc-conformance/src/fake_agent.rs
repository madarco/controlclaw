//! A stand-in for the agent boxes the firewall calls: HTTPS on `127.0.0.2:443` (the firewall calls
//! `https://<hostname>/__cc/agent/…` with no port), a certificate made for the case that both
//! builds trust through `NODE_EXTRA_CA_CERTS`. Records each call with its token's claims and
//! answers what the case said (200 `{}` otherwise). An identity map whose `hostname` is
//! `127.0.0.2` sends the firewall here. Port 443 needs root or
//! `net.ipv4.ip_unprivileged_port_start <= 443`.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{Value, json};

#[derive(Default)]
struct State {
    received: Vec<Value>,
    answers: HashMap<String, VecDeque<(u16, Value)>>,
}

#[derive(Clone)]
pub struct FakeAgent {
    state: Arc<Mutex<State>>,
    task: Arc<tokio::task::JoinHandle<()>>,
}

impl Drop for FakeAgent {
    fn drop(&mut self) {
        if Arc::strong_count(&self.task) == 1 {
            self.task.abort();
        }
    }
}

fn claims(auth: Option<&str>) -> Value {
    let Some(t) = auth.and_then(|a| a.strip_prefix("Bearer ")) else {
        return Value::Null;
    };
    t.split('.')
        .nth(1)
        .and_then(|p| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or(Value::Null)
}

fn openssl(args: &[&str], dir: &Path) -> Result<()> {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .context("openssl")?;
    if !out.status.success() {
        bail!(
            "openssl {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

/// A throwaway CA (`agent-ca.pem`, what the agent trusts) and a server certificate for
/// `127.0.0.2` signed by it: rustls refuses a CA certificate as a server's own.
pub fn make_cert(dir: &Path) -> Result<(String, String)> {
    openssl(
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=cc conformance CA",
            "-keyout",
            "ca-key.pem",
            "-out",
            "agent-ca.pem",
        ],
        dir,
    )?;
    openssl(
        &[
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=127.0.0.2",
            "-keyout",
            "agent-key.pem",
            "-out",
            "agent.csr",
        ],
        dir,
    )?;
    std::fs::write(
        dir.join("agent.ext"),
        "subjectAltName=IP:127.0.0.2\nbasicConstraints=CA:FALSE\n",
    )?;
    openssl(
        &[
            "x509",
            "-req",
            "-in",
            "agent.csr",
            "-CA",
            "agent-ca.pem",
            "-CAkey",
            "ca-key.pem",
            "-CAcreateserial",
            "-days",
            "2",
            "-extfile",
            "agent.ext",
            "-out",
            "agent-cert.pem",
        ],
        dir,
    )?;
    Ok((
        std::fs::read_to_string(dir.join("agent-cert.pem"))?,
        std::fs::read_to_string(dir.join("agent-key.pem"))?,
    ))
}

static RUN_CERT: std::sync::OnceLock<(String, String, String)> = std::sync::OnceLock::new();

/// One CA and certificate for the whole run, made the first time a case asks; each case gets the
/// CA as `agent-ca.pem` in its own folder.
pub fn cert_for_run(case_root: &Path) -> Result<(String, String)> {
    if RUN_CERT.get().is_none() {
        let dir = tempfile::tempdir()?;
        let (cert, key) = make_cert(dir.path())?;
        let ca = std::fs::read_to_string(dir.path().join("agent-ca.pem"))?;
        let _ = RUN_CERT.set((cert, key, ca));
    }
    let (cert, key, ca) = RUN_CERT.get().cloned().context("the run's certificate")?;
    std::fs::write(case_root.join("agent-ca.pem"), ca)?;
    Ok((cert, key))
}

impl FakeAgent {
    pub async fn start(cert: &str, key: &str) -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.2:443")
            .await
            .context("bind 127.0.0.2:443 (root, or sysctl net.ipv4.ip_unprivileged_port_start=443)")?;
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        let mut router = cc_http::Router::new(&["all"]);
        router.route(
            "all",
            |_, _| true,
            move |req, _| {
                let s = s.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let raw = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                    let path = parts
                        .uri
                        .path()
                        .strip_prefix("/__cc/agent")
                        .unwrap_or(parts.uri.path())
                        .to_string();
                    let (status, answer) = {
                        let mut st = s.lock().unwrap_or_else(|e| e.into_inner());
                        st.received.push(json!({
                            "method": parts.method.as_str(),
                            "path": path,
                            // As sent: with `/__cc/agent` through an agent's HTTPS name, without
                            // it from a standalone firewall, which calls the vm-agent itself.
                            "sent_path": parts.uri.path(),
                            "query": parts.uri.query(),
                            "claims": claims(cc_http::header(&parts, "authorization")),
                            "body": serde_json::from_slice::<Value>(&raw).unwrap_or(Value::Null),
                        }));
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
        let acceptor = cc_http::tls_acceptor(cert, key).map_err(anyhow::Error::msg)?;
        let router = Arc::new(router);
        let task = tokio::spawn(cc_http::serve_mux(listener, router.clone(), router, acceptor));
        Ok(Self {
            state,
            task: Arc::new(task),
        })
    }

    /// Answer `path` (after `/__cc/agent`) with these, in order; the last repeats.
    pub fn answer(&self, path: &str, answers: Vec<(u16, Value)>) {
        if let Ok(mut st) = self.state.lock() {
            st.answers.insert(path.to_string(), answers.into());
        }
    }

    /// Every call so far: `{method, path, sent_path, query, claims, body}`.
    pub fn received(&self) -> Vec<Value> {
        self.state.lock().map(|s| s.received.clone()).unwrap_or_default()
    }
}
