//! The interception CA and the leaf certificates minted from it (appendix F §1.2).
//!
//! The CA is the one `gen-ca.sh` wrote for mitmproxy: `mitmproxy-ca.pem` in the CA folder, an RSA
//! key followed by its certificate. Agents already trust its public half, so nothing changes on the
//! agent box. Each leaf is for one name (the SNI, or the address when there is none), signed by the
//! CA, with one ECDSA P-256 key shared by every leaf of this process (mitmproxy also uses one key),
//! and kept in a small cache so a name is signed once.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// The file mitmproxy loads from its `confdir`: key and certificate in one PEM.
pub const CA_FILE: &str = "mitmproxy-ca.pem";

/// How many leaves are kept. A name past this is signed again when it comes back.
const CACHE_SIZE: usize = 4096;
/// Leaves are valid from a day before they are made (clock skew on the agent box) for a year,
/// as mitmproxy's are.
const BACKDATE: Duration = Duration::from_secs(24 * 3600);
const LIFETIME: Duration = Duration::from_secs(365 * 24 * 3600);

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("could not read {0}: {1}")]
    Read(String, std::io::Error),
    #[error("{0} has no private key")]
    NoKey(String),
    #[error("{0} has no certificate")]
    NoCert(String),
    #[error("the CA could not be loaded: {0}")]
    Load(String),
    #[error("a certificate could not be made: {0}")]
    Sign(String),
}

pub struct Ca {
    issuer: rcgen::Certificate,
    issuer_key: KeyPair,
    /// The CA certificate as it is on disk, sent after each leaf.
    ca_der: CertificateDer<'static>,
    leaf_key: KeyPair,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    leaves: HashMap<String, (u64, Arc<CertifiedKey>)>,
    tick: u64,
}

impl Ca {
    /// Load `mitmproxy-ca.pem` from the CA folder.
    pub fn load(dir: &Path) -> Result<Self, CaError> {
        let path = dir.join(CA_FILE);
        let shown = path.display().to_string();
        let pem = std::fs::read(&path).map_err(|e| CaError::Read(shown.clone(), e))?;
        Self::from_pem(&pem, &shown)
    }

    pub fn from_pem(pem: &[u8], shown: &str) -> Result<Self, CaError> {
        let mut key: Option<Vec<u8>> = None;
        let mut cert: Option<CertificateDer<'static>> = None;
        for item in rustls_pemfile::read_all(&mut &pem[..]) {
            match item.map_err(|e| CaError::Load(e.to_string()))? {
                rustls_pemfile::Item::Pkcs8Key(k) if key.is_none() => key = Some(k.secret_pkcs8_der().to_vec()),
                rustls_pemfile::Item::Pkcs1Key(k) if key.is_none() => key = Some(pkcs1_to_pkcs8(k.secret_pkcs1_der())),
                rustls_pemfile::Item::Sec1Key(_) if key.is_none() => {
                    return Err(CaError::Load("an EC CA key is not supported".into()));
                }
                rustls_pemfile::Item::X509Certificate(c) if cert.is_none() => cert = Some(c),
                _ => {}
            }
        }
        let key = key.ok_or_else(|| CaError::NoKey(shown.into()))?;
        let ca_der = cert.ok_or_else(|| CaError::NoCert(shown.into()))?;
        let issuer_key = KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(key), &rcgen::PKCS_RSA_SHA256)
            .map_err(|e| CaError::Load(e.to_string()))?;
        let params = CertificateParams::from_ca_cert_der(&ca_der).map_err(|e| CaError::Load(e.to_string()))?;
        // Only used as the issuer: its name and key identifier go into each leaf.
        let issuer = params
            .self_signed(&issuer_key)
            .map_err(|e| CaError::Load(e.to_string()))?;
        let leaf_key =
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| CaError::Sign(e.to_string()))?;
        let signing_key = any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            leaf_key.serialize_der(),
        )))
        .map_err(|e| CaError::Sign(e.to_string()))?;
        Ok(Self {
            issuer,
            issuer_key,
            ca_der,
            leaf_key,
            signing_key,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// The certificate chain and key to present for `name` (a host name or an IP address).
    pub fn leaf(&self, name: &str) -> Result<Arc<CertifiedKey>, CaError> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        {
            let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            c.tick += 1;
            let tick = c.tick;
            if let Some((used, ck)) = c.leaves.get_mut(&name) {
                *used = tick;
                return Ok(ck.clone());
            }
        }
        let ck = Arc::new(self.sign(&name)?);
        let mut c = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if c.leaves.len() >= CACHE_SIZE {
            // Evict the least recently used eighth in one pass rather than one per insert.
            let mut ages: Vec<u64> = c.leaves.values().map(|(t, _)| *t).collect();
            ages.sort_unstable();
            let cut = ages[ages.len() / 8];
            c.leaves.retain(|_, (t, _)| *t > cut);
        }
        let tick = c.tick;
        c.leaves.insert(name, (tick, ck.clone()));
        Ok(ck)
    }

    fn sign(&self, name: &str) -> Result<CertifiedKey, CaError> {
        let err = |e: rcgen::Error| CaError::Sign(e.to_string());
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.subject_alt_names = vec![match name.parse::<IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(name.to_owned().try_into().map_err(err)?),
        }];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = SystemTime::now();
        params.not_before = (now - BACKDATE).into();
        params.not_after = (now + LIFETIME).into();
        params.serial_number = Some(rand_serial().into());
        let cert = params
            .signed_by(&self.leaf_key, &self.issuer, &self.issuer_key)
            .map_err(err)?;
        Ok(CertifiedKey::new(
            vec![cert.der().clone(), self.ca_der.clone()],
            self.signing_key.clone(),
        ))
    }
}

fn rand_serial() -> Vec<u8> {
    let mut b = uuid::Uuid::new_v4().into_bytes().to_vec();
    // A positive integer: clear the top bit.
    b[0] &= 0x7f;
    b
}

/// Wrap a PKCS#1 RSA key in PKCS#8 (`openssl genrsa` before OpenSSL 3 wrote PKCS#1).
fn pkcs1_to_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier { rsaEncryption, NULL }
    const ALG: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut body = vec![0x02, 0x01, 0x00];
    body.extend_from_slice(ALG);
    body.push(0x04);
    der_len(&mut body, pkcs1.len());
    body.extend_from_slice(pkcs1);
    let mut out = vec![0x30];
    der_len(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{ServerName, UnixTime};

    fn verify(pem: &[u8], name: &str) -> Result<(), Box<dyn std::error::Error>> {
        let ca = Ca::from_pem(pem, "test")?;
        let leaf = ca.leaf(name)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.ca_der.clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        verifier.verify_server_cert(
            &leaf.cert[0],
            &leaf.cert[1..],
            &ServerName::try_from(name.to_owned())?,
            &[],
            UnixTime::now(),
        )?;
        Ok(())
    }

    #[test]
    fn leaves_chain_to_the_ca_from_either_key_format() -> Result<(), Box<dyn std::error::Error>> {
        verify(include_bytes!("testdata/ca-pkcs8.pem"), "api.example.com")?;
        verify(include_bytes!("testdata/ca-pkcs1.pem"), "api.example.com")?;
        verify(include_bytes!("testdata/ca-pkcs8.pem"), "203.0.113.5")?;
        Ok(())
    }

    #[test]
    fn a_name_is_signed_once() -> Result<(), Box<dyn std::error::Error>> {
        let ca = Ca::from_pem(include_bytes!("testdata/ca-pkcs8.pem"), "test")?;
        let a = ca.leaf("a.example")?;
        let b = ca.leaf("A.Example.")?;
        assert!(Arc::ptr_eq(&a, &b));
        assert!(Ca::from_pem(b"not a pem", "x").is_err());
        Ok(())
    }
}
