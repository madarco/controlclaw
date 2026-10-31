//! The upstream TLS handshake, on BoringSSL: a copy of the agent's own ClientHello (owner,
//! 2026-10-28). A site sees the agent's browser, curl or Python as they are, never a handshake the
//! firewall made up; the box's Chrome is matched whatever version it is.
//!
//! Copied, in the agent's order: the cipher suites (TLS 1.3 included), the extension order (for
//! Chromium, which shuffles it on every connection, shuffled the same way), the
//! supported groups and the groups with a key share, the signature algorithms, ALPN, ALPS and its
//! codepoint, certificate compression, OCSP and SCT requests, session tickets, the record size
//! limit, delegated credentials, trust anchors (`tls::anchors`), GREASE, ECH GREASE and the TLS
//! versions. The key material is the
//! firewall's own. What BoringSSL cannot send (an OpenSSL client's `encrypt_then_mac`, a cipher it
//! does not have) is left out and named in one log line per fingerprint. With no ClientHello to
//! copy, the built-in profile (`tls::chrome`) is used.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use btls::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType, KeyShare, SslConnector, SslMethod,
    SslOptions, SslSignatureAlgorithm, SslVerifyMode, SslVersion,
};
use btls::x509::X509;
use btls::x509::store::{X509Store, X509StoreBuilder};
use tokio::io::{AsyncRead, AsyncWrite};

use super::hello::{Hello, ext, is_grease};

/// Connectors kept built. Chrome orders its extensions afresh on every connection, so for it most
/// lookups miss; building one is cheap (the trust store is shared), the cache spares the rest.
const CACHE: usize = 256;

/// A connector made from one ClientHello, and what that ClientHello asked for per connection.
#[derive(Clone)]
struct Built {
    connector: SslConnector,
    /// What could not be copied (logged once, kept for tests).
    dropped: Vec<String>,
    key_shares: Vec<KeyShare>,
    ech_grease: bool,
    alps: Vec<Vec<u8>>,
    alps_new: bool,
    /// The trust anchor IDs the agent requested (wire form), when it sent the extension.
    trust_anchors: Option<Vec<u8>>,
}

pub struct UpstreamTls {
    insecure: bool,
    /// The system's trust store (as rustls-native-certs reads it), built once and shared by every
    /// connector (a reference, not a copy).
    roots: Option<X509Store>,
    built: Mutex<HashMap<BuiltKey, Built>>,
    /// The "could not copy" lines already logged: each once, not once per connection.
    logged: crate::log::Once,
}

/// A ClientHello and the ALPN list that replaced its own, if any.
type BuiltKey = (Hello, Option<Vec<Vec<u8>>>);

/// The upstream TLS stream.
pub type Stream<S> = tokio_btls::SslStream<S>;

impl UpstreamTls {
    /// `insecure`: `MITM_DEV_INSECURE_UPSTREAM` (smoke rigs only, behind the dev-flag switch).
    pub fn new(insecure: bool) -> Self {
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            tracing::warn!("[proxy] system roots: {e}");
        }
        let roots = X509StoreBuilder::new().ok().map(|mut store| {
            let mut added = 0;
            for c in native.certs.iter().filter_map(|c| X509::from_der(c).ok()) {
                if store.add_cert(c).is_ok() {
                    added += 1;
                }
            }
            if added == 0 && !insecure {
                tracing::error!("[proxy] no system root certificates: every upstream TLS check will fail");
            }
            store.build()
        });
        Self {
            insecure,
            roots,
            built: Mutex::new(HashMap::new()),
            logged: crate::log::Once::new(),
        }
    }

    /// Connect TLS to `name` over `io` with `hello`'s fingerprint. `alpn` replaces its ALPN list
    /// when given (a websocket upgrade asks for HTTP/1.1 only, as Chrome does). `allow_weak`: a
    /// site may pick one of Chrome's static-RSA suites (see [`is_weak`]); else that is refused.
    pub async fn connect<S>(
        &self,
        hello: &Hello,
        alpn: Option<&[Vec<u8>]>,
        name: &str,
        io: S,
        allow_weak: bool,
    ) -> Result<Stream<S>, String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let built = self.built(hello, alpn)?;
        let mut cfg = built.connector.configure().map_err(|e| e.to_string())?;
        if !built.key_shares.is_empty() && cfg.set_client_key_shares(&built.key_shares).is_err() {
            self.log_once("the key-share groups (BoringSSL refused them; its default is sent)".into());
        }
        cfg.set_enable_ech_grease(built.ech_grease);
        if let Some(ids) = &built.trust_anchors
            && !super::anchors::set_requested(&mut cfg, ids)
        {
            self.log_once("the trust_anchors extension (its ID list did not parse)".into());
        }
        if !built.alps.is_empty() {
            cfg.set_alps_use_new_codepoint(built.alps_new);
            for p in &built.alps {
                cfg.add_application_settings(p).map_err(|e| e.to_string())?;
            }
        }
        // An address has no SNI and is checked as an address.
        let is_ip = name.parse::<std::net::IpAddr>().is_ok();
        cfg.set_use_server_name_indication(!is_ip);
        if self.insecure {
            cfg.set_verify_hostname(false);
        }
        let ssl = cfg.into_ssl(name).map_err(|e| e.to_string())?;
        let mut stream = tokio_btls::SslStream::new(ssl, io).map_err(|e| e.to_string())?;
        std::pin::Pin::new(&mut stream)
            .connect()
            .await
            .map_err(|e| e.to_string())?;
        // A cipher offered so the hello stays Chrome's: only for a connection that may carry no
        // credential the firewall puts in.
        let cipher = stream.ssl().current_cipher().map(btls::ssl::SslCipherRef::protocol_id);
        if let Some(c) = cipher.filter(|c| !cipher_allowed(*c) && !allow_weak) {
            return Err(format!(
                "the site chose cipher 0x{c:04x}, below the firewall's floor (allowed only for requests the firewall sends unchanged)"
            ));
        }
        Ok(stream)
    }

    fn built(&self, hello: &Hello, alpn: Option<&[Vec<u8>]>) -> Result<Built, String> {
        // Chromium's GREASE values and extension order change on every connection (and are drawn
        // again here): they are not part of the key, so one Chrome's connectors are built once.
        let key = (hello.key_form(), alpn.map(<[Vec<u8>]>::to_vec));
        if let Some(b) = self.built.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
            return Ok(b.clone());
        }
        // A ClientHello BoringSSL cannot build at all (a TLS 1.3-only cipher list, say): the built-in
        // profile, with the ALPN the agent asked for.
        let b = match self.build(hello, alpn) {
            Ok(b) => b,
            Err(e) => {
                self.log_once(format!(
                    "everything: {e}; the built-in profile ({}) is used",
                    super::chrome::VERSION
                ));
                let profile_alpn = alpn.map_or_else(|| hello.alpn.clone(), <[Vec<u8>]>::to_vec);
                self.build(super::chrome::hello(), Some(&profile_alpn))?
            }
        };
        if !b.dropped.is_empty() {
            self.log_once(b.dropped.join(", "));
        }
        let mut cache = self.built.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() >= CACHE {
            cache.clear();
        }
        cache.insert(key, b.clone());
        Ok(b)
    }

    fn build(&self, hello: &Hello, alpn: Option<&[Vec<u8>]>) -> Result<Built, String> {
        let s = |e: btls::error::ErrorStack| e.to_string();
        let mut dropped: Vec<String> = Vec::new();
        let mut b = SslConnector::builder(SslMethod::tls()).map_err(s)?;

        // Versions: the highest and lowest the client listed (no supported_versions: TLS 1.2 at most),
        // never below TLS 1.2. An agent cannot make the firewall send a password or a swapped key
        // in a weaker session than it would open itself (the floor, host review of #615).
        let versions: Vec<u16> = hello.versions.iter().copied().filter(|v| !is_grease(*v)).collect();
        let max = versions.iter().max().copied().unwrap_or(0x0303);
        let min = versions.iter().min().copied().unwrap_or(0x0301);
        if min < FLOOR_VERSION {
            dropped.push("TLS versions below 1.2".into());
        }
        b.set_max_proto_version(version(max.max(FLOOR_VERSION))).map_err(s)?;
        // A version BoringSSL does not know (a draft, a later one): the floor, never its default.
        b.set_min_proto_version(version(min.max(FLOOR_VERSION)).or(Some(SslVersion::TLS1_2)))
            .map_err(s)?;
        b.set_grease_enabled(hello.grease());

        // Ciphers, TLS 1.3 included, in order. Chrome's own static-RSA suites are offered, so its
        // hello stays Chrome's, and refused if the site picks one (`connect`).
        let mut names = Vec::new();
        for c in hello.ciphers.iter().filter(|c| !is_grease(**c)) {
            if !cipher_allowed(*c) && !CHROME_COMPAT.contains(c) {
                dropped.push(format!("cipher 0x{c:04x} (below the floor)"));
                continue;
            }
            match cipher_name(*c).filter(|n| cipher_known(n)) {
                Some(n) => names.push(n),
                None => dropped.push(format!("cipher 0x{c:04x}")),
            }
        }
        b.set_preserve_tls13_cipher_list(true);
        if names.is_empty() {
            // Nothing the agent asked for is allowed: the allowed ones, never BoringSSL's default
            // list (it has static RSA).
            names = ALLOWED_CIPHERS
                .iter()
                .filter_map(|c| cipher_name(*c))
                .filter(|n| cipher_known(n))
                .collect();
        }
        b.set_cipher_list(&names.join(":")).map_err(s)?;

        // Groups.
        let mut curves = Vec::new();
        for g in hello.groups.iter().filter(|g| !is_grease(**g)) {
            match group_name(*g).filter(|n| curve_known(n)) {
                Some(n) => curves.push(n),
                None => dropped.push(format!("group 0x{g:04x}")),
            }
        }
        if !curves.is_empty() {
            b.set_curves_list(&curves.join(":")).map_err(s)?;
        }
        // Only for groups BoringSSL took above.
        let key_shares: Vec<KeyShare> = hello
            .key_shares
            .iter()
            .filter(|g| !is_grease(**g))
            .filter(|g| group_name(**g).is_some_and(|n| curves.contains(&n)))
            .filter_map(|g| key_share(*g))
            .collect();

        // Signature algorithms.
        let mut algs = Vec::new();
        for a in &hello.sigalgs {
            if is_grease(*a) {
                // Chrome GREASEs this list; this BoringSSL does not.
                dropped.push("GREASE in signature_algorithms".into());
            } else if sha1_sigalg(*a) {
                dropped.push(format!("SHA-1 signature algorithm 0x{a:04x} (below the floor)"));
            } else if sigalg_known(*a) {
                algs.push(SslSignatureAlgorithm::from(*a));
            } else {
                dropped.push(match *a {
                    0x0904..=0x0906 => format!("ML-DSA signature algorithm 0x{a:04x}"),
                    _ => format!("signature algorithm 0x{a:04x}"),
                });
            }
        }
        if algs.is_empty() {
            // Nothing usable asked for: Chrome's list, never BoringSSL's default (it has SHA-1).
            algs = CHROME_SIGALGS
                .iter()
                .copied()
                .filter(|a| sigalg_known(*a))
                .map(SslSignatureAlgorithm::from)
                .collect();
        }
        b.set_verify_algorithm_prefs(&algs).map_err(s)?;

        // ALPN.
        let protos = alpn.map_or_else(|| hello.alpn.clone(), <[Vec<u8>]>::to_vec);
        if !protos.is_empty() {
            let wire: Vec<u8> = protos
                .iter()
                .flat_map(|p| std::iter::once(u8::try_from(p.len()).unwrap_or(0)).chain(p.iter().copied()))
                .collect();
            b.set_alpn_protos(&wire).map_err(s)?;
        }

        // The extensions that say "yes" by being there.
        if hello.has(ext::STATUS_REQUEST) {
            b.enable_ocsp_stapling();
        }
        if hello.has(ext::SCT) {
            b.enable_signed_cert_timestamps();
        }
        if !hello.has(ext::SESSION_TICKET) {
            b.set_options(SslOptions::NO_TICKET);
        }
        for alg in &hello.cert_compression {
            let added = match *alg {
                1 => b.add_certificate_compression_algorithm(Zlib).is_ok(),
                2 => b.add_certificate_compression_algorithm(Brotli).is_ok(),
                3 => b.add_certificate_compression_algorithm(Zstd).is_ok(),
                _ => false,
            };
            if !added {
                dropped.push(format!("certificate compression {alg}"));
            }
        }
        if let Some(limit) = hello.record_size_limit {
            b.set_record_size_limit(limit);
        }
        if !hello.delegated_credentials.is_empty() {
            let names: Vec<&str> = hello
                .delegated_credentials
                .iter()
                .filter(|a| !sha1_sigalg(**a))
                .filter_map(|a| sigalg_name(*a))
                .collect();
            if b.set_delegated_credentials(&names.join(":")).is_err() {
                dropped.push("delegated_credentials".into());
            }
        }

        // The extensions. Chromium's are shuffled for each connection, as Chromium does it
        // (BoringSSL's own permutation, the one Chrome uses); any other client's order is copied
        // as sent. GREASE is placed by BoringSSL itself, as in Chrome.
        let sent: Vec<u16> = hello.extensions.iter().copied().filter(|e| !is_grease(*e)).collect();
        for e in sent.iter().filter(|e| !EXTENSIONS.contains(e)) {
            dropped.push(format!("extension {}", ext_name(*e)));
        }
        if hello.permutes() {
            b.set_permute_extensions(true);
        } else {
            let order: Vec<ExtensionType> = sent
                .iter()
                .filter(|e| EXTENSIONS.contains(e))
                .map(|e| ExtensionType::from(*e))
                .collect();
            if !order.is_empty() && b.set_extension_permutation(&order).is_err() {
                dropped.push("the extension order".into());
            }
        }

        // The certificate check: the system's roots and the site's name.
        if self.insecure {
            b.set_verify(SslVerifyMode::NONE);
        } else {
            if let Some(roots) = &self.roots {
                b.set_cert_store_ref(roots);
            }
            b.set_verify(SslVerifyMode::PEER);
        }

        Ok(Built {
            connector: b.build(),
            dropped,
            key_shares,
            ech_grease: hello.has(ext::ECH),
            alps: if hello.has(ext::ALPS) || hello.has(ext::ALPS_OLD) {
                hello.alps.clone()
            } else {
                Vec::new()
            },
            alps_new: hello.has(ext::ALPS),
            trust_anchors: hello.trust_anchors.clone(),
        })
    }
}

impl UpstreamTls {
    /// Each line once, and a bounded number of them: they come from agent-chosen ClientHellos.
    fn log_once(&self, what: String) {
        if let Some(what) = self.logged.first(&what) {
            tracing::info!(
                "[proxy] upstream TLS copies the agent's ClientHello without: {what} (BoringSSL cannot send them)"
            );
        }
    }
}

/// The lowest TLS version the firewall sends a request in, whatever the agent asked for.
const FLOOR_VERSION: u16 = 0x0303;

/// The cipher suites a request may go out in: TLS 1.3, ECDHE with AEAD, and ECDHE with CBC-SHA
/// for compatibility. Never static RSA key exchange, 3DES, or CBC-SHA256/384 (the floor, host
/// review of #615): an agent that asks for those gets them left out.
const ALLOWED_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, // TLS 1.3
    0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, // ECDHE + AEAD
    0xc009, 0xc00a, 0xc013, 0xc014, // ECDHE + CBC-SHA
];

fn cipher_allowed(c: u16) -> bool {
    ALLOWED_CIPHERS.contains(&c)
}

/// Whether the connection went with one of Chrome's static-RSA suites (below the floor). Such a
/// connection carries only requests sent as the agent sent them (owner, 2026-10-29): never one
/// with a credential or a login the firewall put in.
pub fn is_weak<S>(stream: &Stream<S>) -> bool {
    stream
        .ssl()
        .current_cipher()
        .is_some_and(|c| !cipher_allowed(c.protocol_id()))
}

/// The static-RSA suites Chrome itself offers: offered as it does (a hello without them is not
/// Chrome's); a connection a site makes in one of them is only for requests the firewall sends
/// unchanged.
const CHROME_COMPAT: &[u16] = &[0x009c, 0x009d, 0x002f, 0x0035];

/// Chrome's signature algorithms, without SHA-1: what is offered when the agent's list has
/// nothing usable.
const CHROME_SIGALGS: &[u16] = &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

/// The SHA-1 signature algorithms, below the floor.
fn sha1_sigalg(a: u16) -> bool {
    matches!(a, 0x0201 | 0x0203)
}

/// The extensions BoringSSL can send, so can place in the order.
const EXTENSIONS: &[u16] = &[
    ext::SERVER_NAME,
    ext::STATUS_REQUEST,
    ext::SUPPORTED_GROUPS,
    ext::EC_POINT_FORMATS,
    ext::SIGNATURE_ALGORITHMS,
    ext::ALPN,
    ext::SCT,
    ext::PADDING,
    ext::EXTENDED_MASTER_SECRET,
    ext::COMPRESS_CERTIFICATE,
    ext::RECORD_SIZE_LIMIT,
    ext::DELEGATED_CREDENTIALS,
    ext::SESSION_TICKET,
    ext::PRE_SHARED_KEY,
    ext::EARLY_DATA,
    ext::SUPPORTED_VERSIONS,
    ext::PSK_KEY_EXCHANGE_MODES,
    ext::KEY_SHARE,
    ext::ALPS_OLD,
    ext::ALPS,
    ext::ECH,
    ext::RENEGOTIATION_INFO,
    ext::TRUST_ANCHORS,
];

fn ext_name(e: u16) -> String {
    match e {
        ext::ENCRYPT_THEN_MAC => "encrypt_then_mac (22)".into(),
        49 => "post_handshake_auth (49)".into(),
        50 => "signature_algorithms_cert (50)".into(),
        other => other.to_string(),
    }
}

fn version(v: u16) -> Option<SslVersion> {
    match v {
        0x0304 => Some(SslVersion::TLS1_3),
        0x0303 => Some(SslVersion::TLS1_2),
        0x0302 => Some(SslVersion::TLS1_1),
        0x0301 => Some(SslVersion::TLS1),
        _ => None,
    }
}

/// BoringSSL's name for an IANA cipher suite.
fn cipher_name(c: u16) -> Option<&'static str> {
    Some(match c {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        0xc02b => "ECDHE-ECDSA-AES128-GCM-SHA256",
        0xc02f => "ECDHE-RSA-AES128-GCM-SHA256",
        0xc02c => "ECDHE-ECDSA-AES256-GCM-SHA384",
        0xc030 => "ECDHE-RSA-AES256-GCM-SHA384",
        0xcca9 => "ECDHE-ECDSA-CHACHA20-POLY1305",
        0xcca8 => "ECDHE-RSA-CHACHA20-POLY1305",
        0xc009 => "ECDHE-ECDSA-AES128-SHA",
        0xc00a => "ECDHE-ECDSA-AES256-SHA",
        0xc013 => "ECDHE-RSA-AES128-SHA",
        0xc014 => "ECDHE-RSA-AES256-SHA",
        0xc023 => "ECDHE-ECDSA-AES128-SHA256",
        0xc027 => "ECDHE-RSA-AES128-SHA256",
        0xc024 => "ECDHE-ECDSA-AES256-SHA384",
        0xc028 => "ECDHE-RSA-AES256-SHA384",
        0x009c => "AES128-GCM-SHA256",
        0x009d => "AES256-GCM-SHA384",
        0x002f => "AES128-SHA",
        0x0035 => "AES256-SHA",
        0x003c => "AES128-SHA256",
        0x003d => "AES256-SHA256",
        0x000a => "DES-CBC3-SHA",
        _ => return None,
    })
}

/// Whether BoringSSL takes this cipher name (asked once per name).
fn cipher_known(name: &str) -> bool {
    // A list of TLS 1.3 suites alone is refused ("no cipher match"): asked next to a TLS 1.2 one.
    known(name, |b, n| {
        b.set_strict_cipher_list(&format!("{n}:ECDHE-RSA-AES128-GCM-SHA256"))
            .is_ok()
    })
}

fn curve_known(name: &str) -> bool {
    known(name, |b, n| b.set_curves_list(n).is_ok())
}

fn known(name: &str, test: fn(&mut btls::ssl::SslConnectorBuilder, &str) -> bool) -> bool {
    static SEEN: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    let seen = SEEN.get_or_init(Default::default);
    if let Some(v) = seen.lock().unwrap_or_else(PoisonError::into_inner).get(name) {
        return *v;
    }
    let ok = SslConnector::builder(SslMethod::tls()).is_ok_and(|mut b| {
        b.set_preserve_tls13_cipher_list(true);
        test(&mut b, name)
    });
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(name.to_owned(), ok);
    ok
}

fn group_name(g: u16) -> Option<&'static str> {
    Some(match g {
        0x11ec => "X25519MLKEM768",
        0x6399 => "X25519Kyber768Draft00",
        0x001d => "X25519",
        0x0017 => "P-256",
        0x0018 => "P-384",
        0x0019 => "P-521",
        _ => return None,
    })
}

fn key_share(g: u16) -> Option<KeyShare> {
    Some(match g {
        0x11ec => KeyShare::X25519_MLKEM768,
        0x6399 => KeyShare::X25519_KYBER768_DRAFT00,
        0x001d => KeyShare::X25519,
        0x0017 => KeyShare::P256,
        0x0018 => KeyShare::P384,
        0x0019 => KeyShare::P521,
        _ => return None,
    })
}

/// The signature schemes BoringSSL verifies.
fn sigalg_known(a: u16) -> bool {
    sigalg_name(a).is_some()
}

fn sigalg_name(a: u16) -> Option<&'static str> {
    Some(match a {
        0x0201 => "rsa_pkcs1_sha1",
        0x0203 => "ecdsa_sha1",
        0x0401 => "rsa_pkcs1_sha256",
        0x0501 => "rsa_pkcs1_sha384",
        0x0601 => "rsa_pkcs1_sha512",
        0x0403 => "ecdsa_secp256r1_sha256",
        0x0503 => "ecdsa_secp384r1_sha384",
        0x0603 => "ecdsa_secp521r1_sha512",
        0x0804 => "rsa_pss_rsae_sha256",
        0x0805 => "rsa_pss_rsae_sha384",
        0x0806 => "rsa_pss_rsae_sha512",
        0x0807 => "ed25519",
        _ => return None,
    })
}

struct Zlib;
struct Brotli;
struct Zstd;

impl CertificateCompressor for Zlib {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        std::io::copy(&mut flate2::read::ZlibDecoder::new(input), output).map(|_| ())
    }
}

impl CertificateCompressor for Brotli {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        std::io::copy(&mut brotli_decompressor::Decompressor::new(input, 4096), output).map(|_| ())
    }
}

impl CertificateCompressor for Zstd {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: std::io::Write>(&self, input: &[u8], output: &mut W) -> std::io::Result<()> {
        let mut d = ruzstd::decoding::StreamingDecoder::new(input).map_err(std::io::Error::other)?;
        std::io::copy(&mut d, output).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chromes_hello_builds_and_names_what_it_drops() {
        let t = UpstreamTls::new(false);
        let b = t.build(crate::tls::chrome::hello(), None);
        assert!(b.is_ok(), "{:?}", b.err());
        let b = b.ok();
        assert!(
            b.as_ref()
                .is_some_and(|b| b.ech_grease && b.alps_new && b.key_shares.len() == 2)
        );
        // Chrome 153 sends what this BoringSSL cannot: named in the log line, nothing else.
        assert_eq!(
            b.map(|b| b.dropped).unwrap_or_default(),
            [
                "GREASE in signature_algorithms",
                "ML-DSA signature algorithm 0x0904",
                "ML-DSA signature algorithm 0x0905",
                "ML-DSA signature algorithm 0x0906"
            ]
        );
    }

    #[test]
    fn a_hello_boringssl_cannot_build_falls_back_to_the_profile() {
        let t = UpstreamTls::new(false);
        let only13 = Hello {
            ciphers: vec![0x1301, 0x1302],
            versions: vec![0x0304],
            alpn: vec![b"http/1.1".to_vec()],
            ..Hello::default()
        };
        assert!(t.build(&only13, None).is_err());
        assert!(t.built(&only13, None).is_ok());
    }

    /// A hello asking for TLS 1.0, 3DES and SHA-1 (curl --tlsv1.0 --tls-max 1.0 --ciphers
    /// DES-CBC3-SHA): the site still gets TLS 1.2 or later with an ECDHE or TLS 1.3 cipher, and
    /// what was below the floor is named.
    #[tokio::test]
    async fn an_agent_cannot_downgrade_the_firewalls_handshake() -> Result<(), Box<dyn std::error::Error>> {
        let weak = Hello {
            versions: vec![0x0301],
            ciphers: vec![0x000a],
            sigalgs: vec![0x0201, 0x0203],
            alpn: vec![b"http/1.1".to_vec()],
            ..Hello::default()
        };
        let t = UpstreamTls::new(true);
        let built = t.build(&weak, None)?;
        for want in [
            "TLS versions below 1.2",
            "cipher 0x000a (below the floor)",
            "SHA-1 signature algorithm 0x0201 (below the floor)",
        ] {
            assert!(built.dropped.iter().any(|d| d == want), "{:?}", built.dropped);
        }
        // A site that would take anything: what the firewall sends is above the floor.
        let ca = crate::tls::ca::Ca::from_pem(include_bytes!("testdata/ca-pkcs8.pem"), "test")?;
        let leaf = ca.leaf("weak.example")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(crate::tls::config::server_config(leaf, &[]));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((tcp, _)) = listener.accept().await {
                let _ = acceptor.accept(tcp).await;
            }
        });
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let stream = t.connect(&weak, None, "weak.example", tcp, false).await?;
        let version = stream.ssl().version_str();
        let cipher = stream
            .ssl()
            .current_cipher()
            .map(|c| c.name().to_owned())
            .unwrap_or_default();
        assert!(matches!(version, "TLSv1.2" | "TLSv1.3"), "{version}");
        assert!(cipher.starts_with("TLS_") || cipher.contains("ECDHE"), "{cipher}");
        Ok(())
    }

    /// Chrome's static-RSA suites are offered (its hello stays Chrome's). A site that picks one is
    /// refused for a request a step changed, and kept, marked weak, for one sent unchanged.
    #[tokio::test]
    async fn a_static_rsa_site_carries_only_unchanged_requests() -> Result<(), Box<dyn std::error::Error>> {
        use btls::asn1::Asn1Time;
        use btls::bn::BigNum;
        use btls::hash::MessageDigest;
        use btls::pkey::PKey;
        use btls::rsa::Rsa;
        use btls::ssl::SslAcceptor;
        use btls::x509::{X509, X509NameBuilder};
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "rsa.example")?;
        let name = name.build();
        let mut cert = X509::builder()?;
        cert.set_version(2)?;
        cert.set_subject_name(&name)?;
        cert.set_issuer_name(&name)?;
        cert.set_pubkey(&key)?;
        let (from, until) = (Asn1Time::days_from_now(0)?, Asn1Time::days_from_now(1)?);
        let serial = BigNum::from_u32(1)?.to_asn1_integer()?;
        cert.set_not_before(&from)?;
        cert.set_not_after(&until)?;
        cert.set_serial_number(&serial)?;
        cert.sign(&key, MessageDigest::sha256())?;
        let cert = cert.build();
        let mut site = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        site.set_private_key(&key)?;
        site.set_certificate(&cert)?;
        site.set_cipher_list("AES128-SHA")?;
        site.set_max_proto_version(Some(SslVersion::TLS1_2))?;
        let site = site.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((tcp, _)) = listener.accept().await
                    && let Ok(ssl) = btls::ssl::Ssl::new(site.context())
                    && let Ok(mut s) = tokio_btls::SslStream::new(ssl, tcp)
                {
                    let _ = std::pin::Pin::new(&mut s).accept().await;
                }
            }
        });
        let hello = Hello {
            ciphers: vec![0x002f, 0xc02f],
            alpn: vec![b"http/1.1".to_vec()],
            ..Hello::default()
        };
        let t = UpstreamTls::new(true);
        let dropped = t.build(&hello, None)?.dropped;
        assert!(!dropped.iter().any(|d| d.contains("cipher")), "{dropped:?}");
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        match t.connect(&hello, None, "rsa.example", tcp, false).await {
            Ok(_) => panic!("a static-RSA session was kept"),
            Err(e) => assert!(e.contains("cipher 0x002f, below the firewall's floor"), "{e}"),
        }
        // For requests sent unchanged it is kept, and named weak so nothing else goes on it.
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let stream = t.connect(&hello, None, "rsa.example", tcp, true).await?;
        assert!(is_weak(&stream));
        Ok(())
    }

    /// The extensions of each ClientHello `t` sends with `hello`, for `n` connections to a
    /// listener that reads the hello and hangs up.
    async fn sent_orders(t: &UpstreamTls, hello: &Hello, n: usize) -> std::io::Result<Vec<Vec<u16>>> {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let site = tokio::spawn(async move {
            let mut orders = Vec::new();
            for _ in 0..n {
                let Ok((mut tcp, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while crate::tls::hello::handshake_of(&buf).is_none() {
                    match tcp.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(k) => buf.extend_from_slice(&chunk[..k]),
                    }
                }
                if let Some(h) = crate::tls::hello::handshake_of(&buf).and_then(|h| crate::tls::hello::parse(&h)) {
                    orders.push(h.extensions.into_iter().filter(|e| !is_grease(*e)).collect());
                }
            }
            orders
        });
        for _ in 0..n {
            let tcp = tokio::net::TcpStream::connect(addr).await?;
            let _ = t.connect(hello, None, "order.example", tcp, false).await;
        }
        site.await.map_err(std::io::Error::other)
    }

    /// Chromium's hellos, whatever their order, share one connector, and each connection's
    /// extensions are shuffled afresh (the same set, as Chrome does). Another client's order is
    /// sent as it came, every time.
    #[tokio::test]
    async fn chromium_order_is_shuffled_and_others_are_copied() -> Result<(), Box<dyn std::error::Error>> {
        let t = UpstreamTls::new(true);
        let chrome = crate::tls::chrome::hello().clone();
        assert!(chrome.permutes());
        // Another connection of the same Chrome: a new order and new GREASE values.
        let mut reordered = chrome.clone();
        reordered.extensions.reverse();
        let regrease = |v: &mut Vec<u16>| v.iter_mut().filter(|x| is_grease(**x)).for_each(|x| *x = 0xdada);
        regrease(&mut reordered.ciphers);
        regrease(&mut reordered.extensions);
        regrease(&mut reordered.groups);
        regrease(&mut reordered.key_shares);
        regrease(&mut reordered.versions);
        assert_ne!(reordered, chrome);
        t.built(&chrome, None)?;
        t.built(&reordered, None)?;
        assert_eq!(t.built.lock().unwrap_or_else(PoisonError::into_inner).len(), 1);

        let orders = sent_orders(&t, &chrome, 8).await?;
        assert_eq!(orders.len(), 8);
        let mut set = orders[0].clone();
        set.sort_unstable();
        assert!(orders.iter().all(|o| {
            let mut s = o.clone();
            s.sort_unstable();
            s == set
        }));
        let distinct: std::collections::HashSet<_> = orders.iter().collect();
        assert!(distinct.len() > 1, "{orders:?}");

        // A curl-like hello (no GREASE, no ALPS): its order, as sent.
        let mut curl = chrome.clone();
        curl.extensions
            .retain(|e| !is_grease(*e) && *e != ext::ALPS && *e != ext::ALPS_OLD && *e != ext::ECH);
        curl.ciphers.retain(|c| !is_grease(*c));
        curl.alps.clear();
        assert!(!curl.permutes());
        let orders = sent_orders(&t, &curl, 3).await?;
        assert_eq!(orders.len(), 3);
        assert!(orders.iter().all(|o| o == &orders[0]), "{orders:?}");
        let wanted: Vec<u16> = curl
            .extensions
            .iter()
            .copied()
            .filter(|e| orders[0].contains(e))
            .collect();
        assert_eq!(orders[0], wanted);
        Ok(())
    }

    #[test]
    fn names_boringssl_has() {
        assert!(cipher_known("TLS_AES_128_GCM_SHA256"));
        assert!(cipher_known("ECDHE-RSA-AES128-GCM-SHA256"));
        assert!(cipher_known("TLS_CHACHA20_POLY1305_SHA256"));
        assert!(!cipher_known("NOT-A-CIPHER"));
        assert!(curve_known("X25519MLKEM768"));
    }
}

#[cfg(test)]
mod live {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `cargo test -p cc-proxy --lib -- --ignored tls::mirror::live`: what tls.peet.ws sees of the
    /// built-in profile (internet needed).
    #[tokio::test]
    #[ignore]
    async fn fingerprint_seen_by_tls_peet_ws() -> anyhow::Result<()> {
        let t = UpstreamTls::new(false);
        let tcp = tokio::net::TcpStream::connect("tls.peet.ws:443").await?;
        let http11 = [b"http/1.1".to_vec()];
        let mut s = t
            .connect(crate::tls::chrome::hello(), Some(&http11), "tls.peet.ws", tcp, false)
            .await
            .map_err(anyhow::Error::msg)?;
        s.write_all(b"GET /api/all HTTP/1.1\r\nHost: tls.peet.ws\r\nConnection: close\r\n\r\n")
            .await?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).await?;
        let text = String::from_utf8_lossy(&out);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        std::fs::write(std::env::temp_dir().join("cc-proxy-peet.json"), body)?;
        Ok(())
    }
}
