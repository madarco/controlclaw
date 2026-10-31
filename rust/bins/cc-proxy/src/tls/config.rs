//! The two TLS sides of an intercepted connection: the server the agent talks to (a leaf for the
//! name it asked for, ALPN chosen from what it offered), and the client the firewall dials the
//! site with (system roots, SNI = the destination's name).

use std::sync::{Arc, OnceLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};

pub const H2: &[u8] = b"h2";
pub const HTTP11: &[u8] = b"http/1.1";

/// One leaf, whatever the hello says: the name was read from the ClientHello before the handshake.
#[derive(Debug)]
struct OneLeaf(Arc<CertifiedKey>);

impl ResolvesServerCert for OneLeaf {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The ALPN the proxy answers with, from the client's offers: h2 when offered, else http/1.1 when
/// offered, else none (mitmproxy with `connection_strategy=lazy` picks from the client's offers,
/// since there is no server to ask yet).
pub fn server_alpn(offered: &[Vec<u8>]) -> Vec<Vec<u8>> {
    [H2, HTTP11]
        .iter()
        .filter(|p| offered.iter().any(|o| o == *p))
        .map(|p| p.to_vec())
        .collect()
}

/// The server side for one connection.
pub fn server_config(leaf: Arc<CertifiedKey>, offered: &[Vec<u8>]) -> Arc<ServerConfig> {
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map(|b| {
            b.with_no_client_auth()
                .with_cert_resolver(Arc::new(OneLeaf(leaf.clone())))
        })
        .unwrap_or_else(|_| {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(OneLeaf(leaf)))
        });
    // Only protocols both sides speak, so a client offering something else is not refused.
    cfg.alpn_protocols = server_alpn(offered).into_iter().take(1).collect();
    Arc::new(cfg)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The roots upstream certificates are checked against: the system store (what the firewall's own
/// tools trust), or the bundled Mozilla roots when the system has none.
fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            let found = rustls_native_certs::load_native_certs();
            for e in &found.errors {
                tracing::warn!("[proxy] system roots: {e}");
            }
            let (added, _) = store.add_parsable_certificates(found.certs);
            if added == 0 {
                store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }
            Arc::new(store)
        })
        .clone()
}

/// The upstream TLS configs, one per ALPN choice, built once.
pub struct Upstream {
    h2: Arc<ClientConfig>,
    http11: Arc<ClientConfig>,
    /// No ALPN: the residential exit's own TLS to an `https` upstream proxy.
    plain: Arc<ClientConfig>,
}

impl Upstream {
    /// `insecure`: `MITM_DEV_INSECURE_UPSTREAM` (smoke rigs only, behind the dev-flag switch), the
    /// `--ssl-insecure` the smoke compose files give mitmproxy.
    pub fn new(insecure: bool) -> Self {
        let make = |alpn: &[&[u8]]| {
            let builder = ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap_or_else(|_| ClientConfig::builder());
            let mut cfg = if insecure {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerify))
                    .with_no_client_auth()
            } else {
                builder.with_root_certificates(roots()).with_no_client_auth()
            };
            cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
            Arc::new(cfg)
        };
        Self {
            h2: make(&[H2, HTTP11]),
            http11: make(&[HTTP11]),
            plain: make(&[]),
        }
    }

    /// No ALPN: the residential exit's own TLS to an `https` upstream proxy.
    pub fn plain(&self) -> Arc<ClientConfig> {
        self.plain.clone()
    }

    /// Offer the site what the agent offered us: h2 only when the agent speaks h2 on this connection.
    pub fn config(&self, client_h2: bool) -> Arc<ClientConfig> {
        if client_h2 {
            self.h2.clone()
        } else {
            self.http11.clone()
        }
    }
}

/// The name to send as SNI and check the certificate against: an IP address when the destination
/// is one (no SNI is sent then), else the DNS name.
pub fn server_name(name: &str) -> Option<ServerName<'static>> {
    ServerName::try_from(name.to_owned()).ok()
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}
