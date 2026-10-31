//! Outbound HTTP for the agents.
//!
//! The agent box trusts its firewall's CA only after the vm-agent installs it, and the Node build
//! adds it to the running process (`setDefaultCACertificates`). Here the client is rebuilt with the
//! extra root instead ([`HttpClient::add_root_pem`]); callers take a fresh handle with
//! [`HttpClient::get`] per call, so the swap reaches every later request.
//!
//! The console client signs every call with the box token, as `makeBoxTokenSigner` does. The
//! firewall's client to its agents (per-request bound tokens, own address map, no redirects,
//! body caps) is W3's, in `bins/mitm-agent/src/core`, on top of [`HttpClient`] and `cc_auth::sign`.

pub mod local;

use std::sync::{Arc, RwLock};
use std::time::Duration;

use cc_auth::keys::KeysDir;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("could not sign the request: {0}")]
    Sign(#[from] cc_auth::sign::SignError),
    /// The URL is taken out first (`without_url`): a URL can carry a token, and this text reaches
    /// logs and command results (host rule).
    #[error("request failed: {0}")]
    Http(reqwest::Error),
    #[error("bad certificate: {0}")]
    Cert(String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        ClientError::Http(e.without_url())
    }
}

#[derive(Clone)]
pub struct HttpClient {
    inner: Arc<RwLock<reqwest::Client>>,
    /// The same roots, never following a redirect (`redirect: "error"`/`"manual"` calls), kept in
    /// step by `set_roots` so it trusts the firewall's CA from the moment `inner` does.
    no_redirect: Arc<RwLock<reqwest::Client>>,
    extra_roots: Arc<RwLock<Vec<reqwest::Certificate>>>,
    /// The PEM the extra roots came from, for the connections made without reqwest (the vm-agent
    /// watchdog's handshakes), so they trust what this client trusts.
    extra_pem: Arc<RwLock<Vec<Vec<u8>>>>,
    follow_redirects: bool,
}

fn build(extra: &[reqwest::Certificate], follow_redirects: bool) -> Result<reqwest::Client, ClientError> {
    let mut b = reqwest::Client::builder()
        // The Mozilla roots, like the ones Node bundles, plus whatever was added.
        .use_rustls_tls()
        .connect_timeout(Duration::from_secs(30))
        // Node's `fetch` ignores HTTP(S)_PROXY; so does this (the agent box's egress is redsocks).
        .no_proxy()
        .redirect(if follow_redirects {
            reqwest::redirect::Policy::limited(20)
        } else {
            reqwest::redirect::Policy::none()
        });
    for c in extra {
        b = b.add_root_certificate(c.clone());
    }
    Ok(b.build()?)
}

impl HttpClient {
    /// `follow_redirects` is what `fetch` does by default; the firewall's calls to agents and the
    /// MCP `publicFetch` do not follow them.
    pub fn new(follow_redirects: bool) -> Result<Self, ClientError> {
        let (mut extra, mut extra_pem) = (Vec::new(), Vec::new());
        // NODE_EXTRA_CA_CERTS is how the Node build picks up the proxy CA after a restart.
        if let Ok(path) = std::env::var("NODE_EXTRA_CA_CERTS")
            && let Ok(pem) = std::fs::read(&path)
            && let Ok(certs) = reqwest::Certificate::from_pem_bundle(&pem)
        {
            extra.extend(certs);
            extra_pem.push(pem);
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(build(&extra, follow_redirects)?)),
            no_redirect: Arc::new(RwLock::new(build(&extra, false)?)),
            extra_roots: Arc::new(RwLock::new(extra)),
            extra_pem: Arc::new(RwLock::new(extra_pem)),
            follow_redirects,
        })
    }

    pub fn get(&self) -> reqwest::Client {
        self.inner.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// A client with the same roots that never follows a redirect, whatever `new` was given.
    pub fn get_no_redirect(&self) -> reqwest::Client {
        self.no_redirect.read().map(|c| c.clone()).unwrap_or_default()
    }

    /// Trust exactly these extra roots from now on, in place of the ones added before
    /// (`setDefaultCACertificates([...bundled, pem])`): after a firewall restore the old CA goes.
    /// A PEM with no certificate in it is refused and changes nothing.
    pub fn replace_roots_pem(&self, pem: &[u8]) -> Result<(), ClientError> {
        self.set_roots(pem, true)
    }

    /// Trust one more root from now on (the firewall's CA, once its signature checked out).
    pub fn add_root_pem(&self, pem: &[u8]) -> Result<(), ClientError> {
        self.set_roots(pem, false)
    }

    /// The extra roots trusted now, as PEM (empty when there are none).
    pub fn extra_roots_pem(&self) -> Vec<u8> {
        self.extra_pem.read().map(|p| p.join(&b'\n')).unwrap_or_default()
    }

    fn set_roots(&self, pem: &[u8], replace: bool) -> Result<(), ClientError> {
        let certs = reqwest::Certificate::from_pem_bundle(pem).map_err(|e| ClientError::Cert(e.to_string()))?;
        if certs.is_empty() {
            return Err(ClientError::Cert("no certificate in the PEM".into()));
        }
        let mut roots = self.extra_roots.write().map_err(|_| ClientError::Cert("lock".into()))?;
        let mut next = if replace { Vec::new() } else { roots.clone() };
        next.extend(certs);
        let client = build(&next, self.follow_redirects)?;
        let no_redirect = build(&next, false)?;
        *roots = next;
        if let Ok(mut p) = self.extra_pem.write() {
            if replace {
                p.clear();
            }
            p.push(pem.to_vec());
        }
        if let Ok(mut c) = self.inner.write() {
            *c = client;
        }
        if let Ok(mut c) = self.no_redirect.write() {
            *c = no_redirect;
        }
        Ok(())
    }
}

/// Calls to the console's `/api/vm-agent/*`, each with a fresh box token.
#[derive(Clone)]
pub struct ConsoleClient {
    keys: KeysDir,
    http: HttpClient,
}

/// A console answer: the status and the body as JSON (`Value::Null` when it is not JSON).
#[derive(Debug, Clone)]
pub struct ConsoleAnswer {
    pub status: u16,
    pub body: Value,
}

impl ConsoleClient {
    pub fn new(keys: KeysDir, http: HttpClient) -> Self {
        Self { keys, http }
    }

    pub async fn post_json(&self, url: &str, body: &Value, timeout: Duration) -> Result<ConsoleAnswer, ClientError> {
        if let Some((status, body)) = local::call("POST", url, Some(body)).await {
            return Ok(ConsoleAnswer { status, body });
        }
        let token = cc_auth::sign::box_token(&self.keys)?;
        let res = self
            .http
            .get()
            .post(url)
            .bearer_auth(token)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body).unwrap_or_default())
            .timeout(timeout)
            .send()
            .await?;
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        Ok(ConsoleAnswer { status, body })
    }

    pub async fn get_json(&self, url: &str, timeout: Duration) -> Result<ConsoleAnswer, ClientError> {
        if let Some((status, body)) = local::call("GET", url, None).await {
            return Ok(ConsoleAnswer { status, body });
        }
        let token = cc_auth::sign::box_token(&self.keys)?;
        let res = self
            .http
            .get()
            .get(url)
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await?;
        let status = res.status().as_u16();
        let body = res.json::<Value>().await.unwrap_or(Value::Null);
        Ok(ConsoleAnswer { status, body })
    }
}
