//! Compact JWTs, checked the way `jose` 6 checks them in the TS agents, so a token one build takes
//! the other takes too.
//!
//! What `jwtVerify(token, key, { algorithms: ["EdDSA"], clockTolerance })` does, in its order:
//! three parts; a protected header that is a JSON object with a string `alg` that is on the list;
//! no `crit`; a valid signature over `<header>.<payload>`; a payload that is a JSON object; then
//! `iat`, `nbf` and `exp` must be numbers when present, `nbf` not in the future and `exp` not in
//! the past (both with the tolerance). Nothing else: no `iss`, `aud` or `typ` unless asked, and
//! `exp` is not required.

use base64::Engine;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

pub type Claims = Map<String, Value>;

/// base64url, with or without padding on the way in (jose takes both), never padded on the way out.
const B64: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JwtError {
    #[error("malformed token")]
    Malformed,
    #[error("algorithm not allowed")]
    Algorithm,
    #[error("bad signature")]
    Signature,
    #[error("claim {0} is not a number")]
    ClaimType(&'static str),
    #[error("token not yet valid")]
    NotYet,
    #[error("token expired")]
    Expired,
    #[error("bad key")]
    Key,
}

/// The key a token is checked with.
#[derive(Clone)]
pub enum VerifyKey {
    Ed25519(VerifyingKey),
    Hs256(Vec<u8>),
}

impl VerifyKey {
    /// An SPKI PEM Ed25519 public key, as `importSPKI(pem, "EdDSA")` takes it.
    pub fn ed25519_spki_pem(pem: &str) -> Result<Self, JwtError> {
        VerifyingKey::from_public_key_pem(pem.trim())
            .map(VerifyKey::Ed25519)
            .map_err(|_| JwtError::Key)
    }

    fn alg(&self) -> &'static str {
        match self {
            VerifyKey::Ed25519(_) => "EdDSA",
            VerifyKey::Hs256(_) => "HS256",
        }
    }
}

/// The key a token is signed with.
pub enum SignKey {
    Ed25519(Box<SigningKey>),
    Hs256(Vec<u8>),
}

impl SignKey {
    /// A PKCS#8 PEM Ed25519 private key, as `importPKCS8(pem, "EdDSA")` takes it.
    pub fn ed25519_pkcs8_pem(pem: &str) -> Result<Self, JwtError> {
        SigningKey::from_pkcs8_pem(pem.trim())
            .map(|k| SignKey::Ed25519(Box::new(k)))
            .map_err(|_| JwtError::Key)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VerifyOptions {
    /// Seconds, as jose's `clockTolerance`.
    pub clock_tolerance_s: i64,
    /// Seconds since the epoch; the system clock when `None`.
    pub now: Option<i64>,
}

pub fn now_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn decode_json_object(part: &str) -> Result<Claims, JwtError> {
    let raw = B64.decode(part).map_err(|_| JwtError::Malformed)?;
    match serde_json::from_slice::<Value>(&raw) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(JwtError::Malformed),
    }
}

/// A claim jose reads as a NumericDate: absent, or any JSON number (fractions included).
fn numeric(claims: &Claims, name: &'static str) -> Result<Option<f64>, JwtError> {
    match claims.get(name) {
        None => Ok(None),
        Some(Value::Number(n)) => n.as_f64().map(Some).ok_or(JwtError::ClaimType(name)),
        Some(_) => Err(JwtError::ClaimType(name)),
    }
}

pub fn verify(token: &str, key: &VerifyKey, opts: VerifyOptions) -> Result<Claims, JwtError> {
    let mut parts = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed);
    };
    let header = decode_json_object(h)?;
    let Some(Value::String(alg)) = header.get("alg") else {
        return Err(JwtError::Malformed);
    };
    // jose refuses any `crit` it does not know, and it knows none for these algorithms.
    if header.contains_key("crit") {
        return Err(JwtError::Malformed);
    }
    if alg != key.alg() {
        return Err(JwtError::Algorithm);
    }
    let sig = B64.decode(s).map_err(|_| JwtError::Signature)?;
    let signed = format!("{h}.{p}");
    match key {
        VerifyKey::Ed25519(k) => {
            let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| JwtError::Signature)?;
            k.verify_strict(signed.as_bytes(), &sig)
                .map_err(|_| JwtError::Signature)?;
        }
        VerifyKey::Hs256(secret) => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| JwtError::Key)?;
            mac.update(signed.as_bytes());
            mac.verify_slice(&sig).map_err(|_| JwtError::Signature)?;
        }
    }
    let claims = decode_json_object(p)?;
    let now = opts.now.unwrap_or_else(now_s) as f64;
    let tol = opts.clock_tolerance_s as f64;
    numeric(&claims, "iat")?;
    if let Some(nbf) = numeric(&claims, "nbf")?
        && nbf > now + tol
    {
        return Err(JwtError::NotYet);
    }
    if let Some(exp) = numeric(&claims, "exp")?
        && exp <= now - tol
    {
        return Err(JwtError::Expired);
    }
    Ok(claims)
}

/// Sign like `new SignJWT(claims).setProtectedHeader({alg}).setIssuedAt().setExpirationTime("<n>s")`:
/// the header is exactly `{"alg":"…"}` and `iat`, then `exp`, come after the caller's claims.
pub fn sign(mut claims: Claims, key: &SignKey, lifetime_s: Option<i64>, now: Option<i64>) -> Result<String, JwtError> {
    let now = now.unwrap_or_else(now_s);
    claims.insert("iat".into(), Value::from(now));
    if let Some(l) = lifetime_s {
        claims.insert("exp".into(), Value::from(now + l));
    }
    let alg = match key {
        SignKey::Ed25519(_) => "EdDSA",
        SignKey::Hs256(_) => "HS256",
    };
    let header = B64.encode(format!(r#"{{"alg":"{alg}"}}"#));
    let payload = B64.encode(serde_json::to_vec(&Value::Object(claims)).map_err(|_| JwtError::Malformed)?);
    let signed = format!("{header}.{payload}");
    let sig = match key {
        SignKey::Ed25519(k) => k.sign(signed.as_bytes()).to_bytes().to_vec(),
        SignKey::Hs256(secret) => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| JwtError::Key)?;
            mac.update(signed.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(format!("{signed}.{}", B64.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use serde_json::json;

    fn keys() -> (SignKey, VerifyKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pem = sk.to_pkcs8_pem(Default::default()).expect("pem");
        let pubpem = sk.verifying_key().to_public_key_pem(Default::default()).expect("pem");
        (
            SignKey::ed25519_pkcs8_pem(&pem).expect("sign key"),
            VerifyKey::ed25519_spki_pem(&pubpem).expect("verify key"),
        )
    }

    fn obj(v: Value) -> Claims {
        v.as_object().cloned().unwrap_or_default()
    }

    #[test]
    fn round_trip_and_claim_order() {
        let (sk, vk) = keys();
        let t = sign(obj(json!({"vmId": "vm_1"})), &sk, Some(30), Some(1000)).expect("sign");
        let header = B64.decode(t.split('.').next().unwrap_or_default()).expect("b64");
        assert_eq!(header, br#"{"alg":"EdDSA"}"#);
        let payload = B64.decode(t.split('.').nth(1).unwrap_or_default()).expect("b64");
        assert_eq!(payload, br#"{"vmId":"vm_1","iat":1000,"exp":1030}"#);
        let c = verify(
            &t,
            &vk,
            VerifyOptions {
                now: Some(1010),
                ..Default::default()
            },
        )
        .expect("verify");
        assert_eq!(c["vmId"], "vm_1");
    }

    #[test]
    fn time_rules_match_jose() {
        let (sk, vk) = keys();
        let t = sign(Claims::new(), &sk, Some(30), Some(1000)).expect("sign");
        // exp <= now - tolerance is expired: at exactly exp it is refused.
        assert_eq!(
            verify(
                &t,
                &vk,
                VerifyOptions {
                    now: Some(1030),
                    ..Default::default()
                }
            ),
            Err(JwtError::Expired)
        );
        assert!(
            verify(
                &t,
                &vk,
                VerifyOptions {
                    now: Some(1029),
                    ..Default::default()
                }
            )
            .is_ok()
        );
        assert!(
            verify(
                &t,
                &vk,
                VerifyOptions {
                    now: Some(1100),
                    clock_tolerance_s: 120
                }
            )
            .is_ok()
        );
        // No exp at all is taken, as jose does without `requiredClaims`.
        let forever = sign(Claims::new(), &sk, None, Some(1000)).expect("sign");
        assert!(
            verify(
                &forever,
                &vk,
                VerifyOptions {
                    now: Some(9_999_999),
                    ..Default::default()
                }
            )
            .is_ok()
        );
        let nbf = sign(obj(json!({"nbf": 2000})), &sk, None, Some(1000)).expect("sign");
        assert_eq!(
            verify(
                &nbf,
                &vk,
                VerifyOptions {
                    now: Some(1999),
                    ..Default::default()
                }
            ),
            Err(JwtError::NotYet)
        );
        let bad_iat = sign(obj(json!({"exp": "soon"})), &sk, None, Some(1000));
        // `sign` overwrites iat; a string exp is refused on the way in.
        assert_eq!(
            verify(&bad_iat.expect("sign"), &vk, VerifyOptions::default()),
            Err(JwtError::ClaimType("exp"))
        );
    }

    #[test]
    fn refuses_tampering_and_other_algorithms() {
        let (sk, vk) = keys();
        let t = sign(obj(json!({"vmId": "a"})), &sk, Some(30), None).expect("sign");
        let mut parts: Vec<&str> = t.split('.').collect();
        let other = B64.encode(br#"{"vmId":"b"}"#);
        parts[1] = &other;
        assert_eq!(
            verify(&parts.join("."), &vk, VerifyOptions::default()),
            Err(JwtError::Signature)
        );
        let hs = sign(Claims::new(), &SignKey::Hs256(vec![1; 32]), Some(30), None).expect("sign");
        assert_eq!(verify(&hs, &vk, VerifyOptions::default()), Err(JwtError::Algorithm));
        assert_eq!(verify("a.b", &vk, VerifyOptions::default()), Err(JwtError::Malformed));
        let crit = format!(
            "{}.{}.{}",
            B64.encode(br#"{"alg":"EdDSA","crit":["x"]}"#),
            parts[1],
            parts[2]
        );
        assert_eq!(verify(&crit, &vk, VerifyOptions::default()), Err(JwtError::Malformed));
    }

    #[test]
    fn hs256_round_trip() {
        let secret = vec![9u8; 32];
        let t = sign(
            obj(json!({"sub": "vm"})),
            &SignKey::Hs256(secret.clone()),
            Some(60),
            None,
        )
        .expect("sign");
        assert!(verify(&t, &VerifyKey::Hs256(secret), VerifyOptions::default()).is_ok());
        assert_eq!(
            verify(&t, &VerifyKey::Hs256(vec![8; 32]), VerifyOptions::default()),
            Err(JwtError::Signature)
        );
    }
}
