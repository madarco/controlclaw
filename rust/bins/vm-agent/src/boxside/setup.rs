//! The box-side bootstrap steps W6's start runs (`mitm-ca.ts`, `egress.ts`, `https-ready.ts`,
//! `handle-certificate.ts`), behind the `BoxSetup` contract, and `POST /mitm-ca/refresh`.
//!
//! The org firewall's CA comes from the console but is not trusted on its word: it carries a
//! detached Ed25519 signature from the firewall's own key, checked against the key this box pinned
//! at provisioning (or, on an org's first box, pinned on first sight and never again). Transparent
//! egress is turned on only once the firewall's proxy answers, so a box never cuts its own way out.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cc_http::{BoxFuture, Resp};
use cc_proc::{Cmd, Runner};
use serde_json::{Value, json};

use crate::app::App;

/// Where `cc-install-ca` puts the firewall's CA for the OS (root-owned, written only from a CA
/// that passed the check).
pub const SYSTEM_MITM_CA_PATH: &str = "/usr/local/share/ca-certificates/controlclaw-mitm.crt";
const INSTALL_TIMEOUT: Duration = Duration::from_secs(60);

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

pub use crate::platform::keys::{sha256_hex, verify_detached};

/// The firewall's listener for its agents (the mitm-agent's 3940 gate), which serves `/ca`.
const FIREWALL_GATE_PORT: u16 = 3940;

/// `firewallCa` (main #564): the firewall's signed CA, asked of the firewall itself over the
/// private network. The firewall inspects this box's control-plane traffic too, so once its CA
/// changes (a firewall put back from its backup) the control plane can only be reached through a CA
/// this box does not trust yet. Plain HTTP: the pair is checked against the pinned firewall key,
/// so the transport need not be trusted. `installed`: the sha256 of the CA this box installed,
/// which tells the firewall to inspect this box from now on.
pub async fn firewall_ca(mitm_ip: &str, installed: Option<&str>) -> Option<(String, String)> {
    firewall_ca_at(mitm_ip, FIREWALL_GATE_PORT, installed).await
}

async fn firewall_ca_at(mitm_ip: &str, port: u16, installed: Option<&str>) -> Option<(String, String)> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .ok()?;
    let mut url = format!("http://{mitm_ip}:{port}/ca");
    if let Some(i) = installed {
        url.push_str("?installed=");
        url.push_str(&url::form_urlencoded::byte_serialize(i.as_bytes()).collect::<String>());
    }
    let res = client.get(&url).send().await.ok()?;
    if !res.status().is_success() {
        return None;
    }
    let body: Value = res.json().await.ok()?;
    Some((body["caCert"].as_str()?.to_owned(), body["caSig"].as_str()?.to_owned()))
}

/// One announcement at a time per process.
static ANNOUNCING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `announceToFirewall` (main #564): tell the firewall this box checked and installed its CA and
/// trusts it for the control plane (`GET /ca?installed=<sha256>`). The firewall records the box
/// only when that is its current CA, and until then passes this box's control-plane and backup
/// traffic through rather than inspect it. It may not be listening yet (a ready-pool firewall
/// waiting for its claim), so this keeps asking, every 30 s at first and then less often (at most
/// every 5 minutes), until it answers.
pub fn announce_to_firewall(keys_dir: &Path) {
    use std::sync::atomic::Ordering;
    if ANNOUNCING.swap(true, Ordering::SeqCst) {
        return;
    }
    let keys_dir = keys_dir.to_path_buf();
    tokio::spawn(async move {
        let wait = Duration::from_secs(30);
        for i in 0u32.. {
            let ip = read(&keys_dir.join("mitm_box_private_ip")).filter(|s| !s.is_empty());
            let installed = read(&keys_dir.join("mitm_ca_fingerprint")).filter(|s| !s.is_empty());
            let (Some(ip), Some(installed)) = (ip, installed) else {
                break;
            };
            if firewall_ca(&ip, Some(&installed)).await.is_some() {
                break;
            }
            tokio::time::sleep((wait * 2u32.saturating_pow((i / 10).min(4))).min(wait * 10)).await;
        }
        ANNOUNCING.store(false, Ordering::SeqCst);
    });
}

/// `CaInstallResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInstall {
    pub trusted: bool,
    pub installed: bool,
    pub message: String,
}

#[derive(Clone)]
pub struct BoxSteps {
    app: Arc<App>,
    keys_dir: PathBuf,
    runner: Arc<dyn Runner>,
    /// The OS trust store's copy (`SYSTEM_MITM_CA_PATH`); a test points it elsewhere.
    system_ca: PathBuf,
    /// The proxy's port (`MITM_PROXY_PORT`, 8080).
    proxy_port: u16,
    ssh: Option<Arc<super::ssh::SshAccess>>,
    drive: Option<Arc<super::drive::Drive>>,
    /// Pause between attempts; a test makes it short.
    pace: Duration,
}

impl BoxSteps {
    pub fn new(app: &Arc<App>, ssh: Option<Arc<super::ssh::SshAccess>>) -> Self {
        let proxy_port = std::env::var("MITM_PROXY_PORT")
            .ok()
            .and_then(|v| super::web::parse_int(&v))
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(8080);
        Self {
            app: app.clone(),
            keys_dir: app.config.keys_dir.clone(),
            runner: app.runner.clone(),
            system_ca: SYSTEM_MITM_CA_PATH.into(),
            proxy_port,
            ssh,
            drive: None,
            pace: Duration::from_secs(1),
        }
    }

    /// Drive's count for `/status`, when the box has Drive.
    pub fn with_drive(mut self, drive: Option<Arc<super::drive::Drive>>) -> Self {
        self.drive = drive;
        self
    }

    #[cfg(test)]
    pub fn for_test(mut self, system_ca: PathBuf, pace: Duration) -> Self {
        self.system_ca = system_ca;
        self.pace = pace;
        self
    }

    /// `trustMitmCaInProcess`: this process's own client trusts the installed CA, in place of any
    /// it trusted before (so after a firewall restore the old one is gone).
    pub fn trust_in_process(&self) -> bool {
        // An empty or unreadable file is no CA: the roots trusted now stay as they are.
        let Ok(pem) = std::fs::read(&self.system_ca) else {
            return false;
        };
        if pem.trim_ascii().is_empty() {
            return false;
        }
        self.app.http.replace_roots_pem(&pem).is_ok()
    }

    /// `ensureMitmCaInstalled`: bring the trust store's copy of the firewall's CA up to date.
    pub async fn ensure_ca(&self, max_attempts: u32) -> CaInstall {
        let k = |n: &str| read(&self.keys_dir.join(n)).filter(|s| !s.is_empty());
        if k("mitm_box_private_ip").is_none() {
            return CaInstall {
                trusted: true,
                installed: false,
                message: "This box is not behind a firewall proxy.".into(),
            };
        }
        // Before asking the console: a box with a CA from an earlier boot trusts its proxy anyway.
        self.trust_in_process();
        let (Some(config_url), Some(_), Some(_)) = (k("config_api_url"), k("vm_id"), k("vm_private_key.pem")) else {
            tracing::warn!("[mitm-ca] missing config_api_url / vm_id / vm_private_key.pem — cannot install CA");
            return CaInstall {
                trusted: false,
                installed: false,
                message: "This box cannot ask for the firewall's certificate.".into(),
            };
        };
        let pin_path = self.keys_dir.join("mitm_pinned_pubkey.pem");
        let fpr_path = self.keys_dir.join("mitm_ca_fingerprint");
        let src_path = self.keys_dir.join("mitm-ca.crt");
        let mitm_ip = k("mitm_box_private_ip").unwrap_or_default();
        let mut last = "The firewall has not published a certificate yet.".to_string();
        for attempt in 1..=max_attempts {
            // A box that already has its firewall's key asks the firewall first; the org's first
            // box, which learns the key from the control plane, has to ask there.
            let direct = if pin_path.exists() {
                firewall_ca(&mitm_ip, None).await
            } else {
                None
            };
            let got = match direct {
                Some((ca, sig)) => Ok(cc_client::ConsoleAnswer {
                    status: 200,
                    body: json!({"mitm": {"caCert": ca, "caSig": sig}}),
                }),
                None => self.app.console.get_json(&config_url, Duration::from_secs(30)).await,
            };
            match got {
                Ok(a) if (200..300).contains(&a.status) => {
                    let m = &a.body["mitm"];
                    let ca = m["caCert"].as_str().filter(|s| !s.is_empty());
                    let sig = m["caSig"].as_str().filter(|s| !s.is_empty());
                    if let (Some(ca), Some(sig)) = (ca, sig) {
                        // The baked pin wins; else, on the org's first box, pin what is offered.
                        let mut pin = read(&pin_path).filter(|s| !s.is_empty());
                        let mut unpinned = None;
                        if pin.is_none()
                            && let Some(pk) = m["pubKey"].as_str().filter(|s| !s.is_empty())
                        {
                            // A pin that could not be saved is no pin: TS's write throws here.
                            match cc_store::write_file(&pin_path, pk.as_bytes(), 0o644) {
                                Ok(()) => {
                                    tracing::info!("[mitm-ca] TOFU-pinned mitm public key (first box for this org)");
                                    pin = Some(pk.to_string());
                                }
                                Err(e) => unpinned = Some(e.to_string()),
                            }
                        }
                        if let Some(e) = unpinned {
                            tracing::warn!("[mitm-ca] attempt {attempt}/{max_attempts} failed: {e}");
                            last = e;
                        } else {
                            match pin {
                                None => {
                                    tracing::warn!("[mitm-ca] attempt {attempt}: CA present but no pin available yet");
                                    last = "This box has no pinned firewall key yet.".into();
                                }
                                Some(p) if !verify_detached(ca, sig, &p) => {
                                    tracing::error!(
                                        "[mitm-ca] attempt {attempt}: CA signature does NOT match pinned key — refusing"
                                    );
                                    last = "The certificate on offer is not signed by this box's pinned firewall key, so it was refused.".into();
                                }
                                Some(_) => {
                                    let fpr = sha256_hex(ca);
                                    if read(&fpr_path).as_deref() == Some(fpr.as_str()) {
                                        announce_to_firewall(&self.keys_dir);
                                        return CaInstall {
                                            trusted: true,
                                            installed: false,
                                            message: "Already up to date.".into(),
                                        };
                                    }
                                    match self.install(&src_path, ca).await {
                                        Ok(()) => {
                                            self.trust_in_process();
                                            let _ = cc_store::write_file(&fpr_path, fpr.as_bytes(), 0o644);
                                            // Installed and trusted: now the firewall may inspect
                                            // this box's control-plane traffic.
                                            announce_to_firewall(&self.keys_dir);
                                            tracing::info!("[mitm-ca] installed mitm CA (sha256={}…)", &fpr[..16]);
                                            return CaInstall {
                                                trusted: true,
                                                installed: true,
                                                message: format!(
                                                    "Installed the firewall's certificate (sha256={}…).",
                                                    &fpr[..16]
                                                ),
                                            };
                                        }
                                        Err(e) => {
                                            tracing::warn!("[mitm-ca] attempt {attempt}/{max_attempts} failed: {e}");
                                            last = e;
                                        }
                                    }
                                }
                            }
                        }
                    } else if a.body.is_null() {
                        // `res.json()` throwing in TS: the attempt fails with that.
                        tracing::warn!("[mitm-ca] attempt {attempt}/{max_attempts} failed: the answer is not JSON");
                        last = "The control plane's answer is not JSON.".into();
                    } else {
                        tracing::info!("[mitm-ca] attempt {attempt}/{max_attempts}: mitm CA not published yet");
                    }
                }
                Ok(a) => {
                    tracing::warn!("[mitm-ca] attempt {attempt}/{max_attempts}: config HTTP {}", a.status);
                    last = format!("The control plane answered HTTP {}.", a.status);
                }
                Err(e) => {
                    // Never reqwest's text: it carries the URL.
                    let e = match e {
                        cc_client::ClientError::Http(h) => h.without_url().to_string(),
                        other => other.to_string(),
                    };
                    tracing::warn!("[mitm-ca] attempt {attempt}/{max_attempts} failed: {e}");
                    last = e;
                }
            }
            if attempt < max_attempts {
                tokio::time::sleep((self.pace * attempt).min(self.pace * 10)).await;
            }
        }
        tracing::error!("[mitm-ca] gave up waiting for a trusted mitm CA");
        CaInstall {
            trusted: false,
            installed: false,
            message: last,
        }
    }

    /// `installCa`: the CA to the fixed box-owned path, then `sudo cc-install-ca`.
    async fn install(&self, src: &Path, ca: &str) -> Result<(), String> {
        cc_store::write_file(src, ca.as_bytes(), 0o644).map_err(|e| e.to_string())?;
        let cmd = Cmd::new("sudo")
            .arg("/usr/local/bin/cc-install-ca")
            .timeout(INSTALL_TIMEOUT);
        match self.runner.run(cmd).await {
            Ok(o) if o.success() => Ok(()),
            Ok(_) => Err("Command failed: sudo /usr/local/bin/cc-install-ca".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// `enableTransparentEgress`: once the proxy answers, `sudo cc-enable-egress`.
    pub async fn enable_egress(&self) -> bool {
        let Some(ip) = read(&self.keys_dir.join("mitm_box_private_ip")).filter(|s| !s.is_empty()) else {
            return true;
        };
        if !self.wait_for_proxy(&ip).await {
            tracing::error!("[egress] gave up waiting for the mitm proxy — NOT activating egress");
            return false;
        }
        let cmd = Cmd::new("sudo")
            .arg("/usr/local/bin/cc-enable-egress")
            .timeout(INSTALL_TIMEOUT);
        match self.runner.run(cmd).await {
            Ok(o) if o.success() => {
                tracing::info!("[egress] transparent egress activated (redirect + DNS → mitm box)");
                true
            }
            _ => {
                tracing::error!(
                    "[egress] cc-enable-egress failed: Command failed: sudo /usr/local/bin/cc-enable-egress"
                );
                false
            }
        }
    }

    /// `waitForMitmProxy`: a TCP connect, 90 tries over about 14 minutes.
    async fn wait_for_proxy(&self, ip: &str) -> bool {
        for attempt in 1..=90u32 {
            let connect = tokio::net::TcpStream::connect((ip, self.proxy_port));
            if matches!(tokio::time::timeout(Duration::from_secs(3), connect).await, Ok(Ok(_))) {
                return true;
            }
            if attempt % 10 == 0 || attempt <= 3 {
                tracing::info!(
                    "[egress] attempt {attempt}/90: mitm proxy {ip}:{} not reachable yet",
                    self.proxy_port
                );
            }
            tokio::time::sleep((self.pace * attempt).min(self.pace * 10)).await;
        }
        false
    }
}

/// The chain a browser sees: the public roots plus the firewall's CA when there is one.
pub fn own_certificate_tls(system_ca: &Path) -> Option<tokio_rustls::TlsConnector> {
    tls_trusting(&std::fs::read(system_ca).unwrap_or_default())
}

/// The public roots plus the certificates in `extra_pem`.
pub fn tls_trusting(extra_pem: &[u8]) -> Option<tokio_rustls::TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for c in rustls_pemfile::certs(&mut &extra_pem[..]).flatten() {
        let _ = roots.add(c);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Some(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// `ownCertificateServes`: a TLS handshake with this box's own HTTPS on 127.0.0.1, with `hostname`
/// as the name, within 5 s. The handshake is the whole check; nothing is asked of the site.
pub async fn own_certificate_serves(hostname: &str, tls: &tokio_rustls::TlsConnector, port: u16) -> bool {
    let Ok(name) = rustls::pki_types::ServerName::try_from(hostname.to_string()) else {
        return false;
    };
    let handshake = async {
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        tls.connect(name, tcp).await.ok()
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(5), handshake).await,
        Ok(Some(_))
    )
}

/// `waitForOwnCertificate`: bounded, 2 s doubling to 5 s between tries.
pub async fn wait_for_own_certificate<F, Fut>(probe: F, timeout: Duration) -> bool
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut delay = Duration::from_secs(2);
    loop {
        if probe().await {
            return true;
        }
        if tokio::time::Instant::now() + delay > deadline {
            return false;
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(5));
    }
}

impl crate::contracts::BoxSetup for BoxSteps {
    /// `reportHandleCertificate`: once `access_hostname` serves its certificate, tell the console;
    /// every 5 s until it is taken (or it says 409).
    fn report_handle_certificate(&self) {
        let Some(hostname) = read(&self.keys_dir.join("access_hostname")).filter(|s| !s.is_empty()) else {
            return;
        };
        let Some(base) = super::saas_base_url(&self.app) else {
            return;
        };
        let (console, ca) = (self.app.console.clone(), self.system_ca.clone());
        tokio::spawn(async move {
            loop {
                // Built each time: the firewall's CA is usually installed after this starts.
                if let Some(tls) = own_certificate_tls(&ca)
                    && own_certificate_serves(&hostname, &tls, 443).await
                    && let Ok(a) = console
                        .post_json(
                            &format!("{base}/api/vm-agent/handle-certificate"),
                            &json!({"hostname": hostname}),
                            Duration::from_secs(5),
                        )
                        .await
                    && ((200..300).contains(&a.status) || a.status == 409)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    fn install_ca(&self) -> BoxFuture<bool> {
        let me = Arc::new(self.clone());
        Box::pin(async move { me.ensure_ca(90).await.trusted })
    }

    /// The ready-pool path: once the CA the root worker installed is trusted, the firewall is told.
    fn trust_ca_in_process(&self) -> bool {
        let trusted = self.trust_in_process();
        if trusted {
            announce_to_firewall(&self.keys_dir);
        }
        trusted
    }

    fn enable_egress(&self) -> BoxFuture<bool> {
        let me = Arc::new(self.clone());
        Box::pin(async move { me.enable_egress().await })
    }

    fn own_certificate(&self, hostname: String, timeout: Duration) -> BoxFuture<bool> {
        let tls = own_certificate_tls(&self.system_ca);
        Box::pin(async move {
            let Some(tls) = tls else { return false };
            wait_for_own_certificate(|| own_certificate_serves(&hostname, &tls, 443), timeout).await
        })
    }

    fn ssh_reading(&self) -> Option<Value> {
        self.ssh.as_ref().map(|s| s.status())
    }

    /// `drive?.summary() ?? null`: None on a box without Drive, or before its first reconcile.
    fn drive_summary(&self) -> Option<Value> {
        self.drive.as_ref().and_then(|d| d.summary())
    }
}

/// `POST /mitm-ca/refresh`: a few attempts, as right after a firewall restore the proxy may still
/// be coming back.
pub async fn handle_refresh(steps: &BoxSteps) -> Resp {
    let r = steps.ensure_ca(4).await;
    cc_http::json(
        if r.trusted { 200 } else { 503 },
        &json!({"ok": r.trusted, "installed": r.installed, "message": r.message}),
    )
}

#[cfg(test)]
mod tests;
