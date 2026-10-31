//! The OIDC check on a webhook delivery (`jwtVerify` with `createRemoteJWKSet`, as the ingress uses
//! them): the issuer's keys found by OIDC discovery and cached, the signature checked with `ring`
//! (RS256, ES256, EdDSA), then the issuer, the audience and the expiry, in jose's order.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::{Map, Value};

/// `OIDC_DISCOVERY_TIMEOUT_MS`, and jose's own timeout for the key set.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// jose's `cacheMaxAge` and `cooldownDuration`.
const CACHE_MAX_AGE: Duration = Duration::from_secs(600);
const COOLDOWN: Duration = Duration::from_secs(30);

/// Why a token was refused, as the ingress tells them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// The `aud` claim was not the one asked for.
    Audience,
    /// The `iss` claim was not the one asked for.
    Issuer,
    Expired,
    /// No key in the set has the token's `kid` and type: the issuer may have rotated.
    NoKey,
    /// Anything else: a bad signature, a malformed token, a key set that would not load.
    Other(String),
}

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
}

fn verify_with(jwk: &Map<String, Value>, alg: &str, msg: &[u8], sig: &[u8]) -> bool {
    use ring::signature;
    let s = |k: &str| jwk.get(k).and_then(Value::as_str).and_then(b64);
    match (alg, jwk.get("kty").and_then(Value::as_str)) {
        ("RS256", Some("RSA")) => {
            let (Some(n), Some(e)) = (s("n"), s("e")) else {
                return false;
            };
            signature::RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, msg, sig)
                .is_ok()
        }
        ("ES256", Some("EC")) => {
            let (Some(x), Some(y)) = (s("x"), s("y")) else {
                return false;
            };
            let mut point = vec![4u8];
            point.extend(x);
            point.extend(y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(msg, sig)
                .is_ok()
        }
        ("EdDSA", Some("OKP")) => {
            let Some(x) = s("x") else { return false };
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(msg, sig)
                .is_ok()
        }
        _ => false,
    }
}

/// The keys a token may be checked with: the one with its `kid`, else any of a usable type.
fn candidates<'a>(keys: &'a [Value], kid: Option<&str>, alg: &str) -> Vec<&'a Map<String, Value>> {
    let kty = match alg {
        "RS256" => "RSA",
        "ES256" => "EC",
        "EdDSA" => "OKP",
        _ => return Vec::new(),
    };
    keys.iter()
        .filter_map(Value::as_object)
        .filter(|k| k.get("kty").and_then(Value::as_str) == Some(kty))
        .filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid)
        .filter(|k| k.get("alg").and_then(Value::as_str).is_none_or(|a| a == alg))
        .filter(|k| k.get("use").and_then(Value::as_str).is_none_or(|u| u == "sig"))
        .collect()
}

/// Check the signature against `keys`, then the claims. `None` from `keys` is a key set that
/// would not load.
pub fn verify(token: &str, keys: &[Value], issuer: &str, audience: &str) -> Result<Map<String, Value>, JwtError> {
    let bad = || JwtError::Other("the token did not verify".into());
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts.as_slice() else { return Err(bad()) };
    let header: Map<String, Value> = b64(h).and_then(|b| serde_json::from_slice(&b).ok()).ok_or_else(bad)?;
    let alg = header.get("alg").and_then(Value::as_str).ok_or_else(bad)?;
    let kid = header.get("kid").and_then(Value::as_str);
    let sig = b64(s).ok_or_else(bad)?;
    let msg = format!("{h}.{p}");
    let usable = candidates(keys, kid, alg);
    if usable.is_empty() {
        return Err(JwtError::NoKey);
    }
    if !usable.iter().any(|k| verify_with(k, alg, msg.as_bytes(), &sig)) {
        return Err(bad());
    }
    let claims: Map<String, Value> = b64(p).and_then(|b| serde_json::from_slice(&b).ok()).ok_or_else(bad)?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(JwtError::Issuer);
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(a)) => a == audience,
        Some(Value::Array(a)) => a.iter().any(|x| x.as_str() == Some(audience)),
        _ => false,
    };
    if !aud_ok {
        return Err(JwtError::Audience);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
        .floor();
    for k in ["iat", "nbf", "exp"] {
        if claims.get(k).is_some_and(|v| !v.is_number()) {
            return Err(bad());
        }
    }
    if claims.get("nbf").and_then(Value::as_f64).is_some_and(|nbf| nbf > now) {
        return Err(bad());
    }
    if claims.get("exp").and_then(Value::as_f64).is_some_and(|exp| exp <= now) {
        return Err(JwtError::Expired);
    }
    Ok(claims)
}

struct KeySet {
    keys: Vec<Value>,
    at: Instant,
}

/// The issuers' key sets, found by discovery and cached for the life of the process.
#[derive(Default)]
pub struct Jwks {
    /// Per issuer, so one slow discovery does not hold up the others.
    uris: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Option<String>>>>>,
    sets: Mutex<HashMap<String, KeySet>>,
}

fn trim_slash(s: &str) -> &str {
    s.strip_suffix('/').unwrap_or(s)
}

impl Jwks {
    /// `jwksFor`: `<issuer>/.well-known/openid-configuration`, its `jwks_uri`, and the document
    /// has to agree about who it is.
    async fn uri_for(&self, http: &reqwest::Client, issuer: &str) -> Result<String, String> {
        let slot = {
            let mut all = self.uris.lock().unwrap_or_else(|e| e.into_inner());
            all.entry(issuer.to_string()).or_default().clone()
        };
        let mut uri = slot.lock().await;
        if let Some(u) = uri.as_ref() {
            return Ok(u.clone());
        }
        let discovery = format!("{}/.well-known/openid-configuration", trim_slash(issuer));
        let res = http
            .get(&discovery)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|_| "fetch failed".to_string())?;
        if !res.status().is_success() {
            return Err(format!("discovery for {issuer} answered {}", res.status().as_u16()));
        }
        let doc: Value = res.json().await.map_err(|e| e.without_url().to_string())?;
        let found = doc
            .get("jwks_uri")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("discovery for {issuer} names no jwks_uri"))?;
        if let Some(claimed) = doc.get("issuer").and_then(Value::as_str)
            && trim_slash(claimed) != trim_slash(issuer)
        {
            return Err(format!("discovery for {issuer} claims to be {claimed}"));
        }
        let found = found.to_string();
        *uri = Some(found.clone());
        Ok(found)
    }

    async fn fetch(http: &reqwest::Client, uri: &str) -> Result<Vec<Value>, String> {
        let res = http
            .get(uri)
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|_| "fetch failed".to_string())?;
        if !res.status().is_success() {
            return Err("Expected 200 OK from the JSON Web Key Set HTTP response".into());
        }
        let doc: Value = res.json().await.map_err(|e| e.without_url().to_string())?;
        doc.get("keys")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| "JSON Web Key Set malformed".to_string())
    }

    /// The token checked against the issuer's keys, fetched again (at most every 30 s) when none
    /// of the cached ones has its `kid`.
    pub async fn verify(
        &self,
        http: &reqwest::Client,
        token: &str,
        issuer: &str,
        audience: &str,
    ) -> Result<Map<String, Value>, JwtError> {
        let uri = self.uri_for(http, issuer).await.map_err(JwtError::Other)?;
        let cached = self
            .sets
            .lock()
            .ok()
            .and_then(|s| s.get(&uri).map(|k| (k.keys.clone(), k.at)));
        if let Some((keys, at)) = cached
            && at.elapsed() < CACHE_MAX_AGE
        {
            let r = verify(token, &keys, issuer, audience);
            // No key with its id: the issuer may have rotated, so look again, not too often.
            if !(matches!(r, Err(JwtError::NoKey)) && at.elapsed() >= COOLDOWN) {
                return r;
            }
        }
        let keys = Self::fetch(http, &uri).await.map_err(JwtError::Other)?;
        if let Ok(mut s) = self.sets.lock() {
            s.insert(
                uri,
                KeySet {
                    keys: keys.clone(),
                    at: Instant::now(),
                },
            );
        }
        verify(token, &keys, issuer, audience)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use serde_json::json;

    /// A token signed with a fixed Ed25519 key, and that key as a JWK.
    pub fn sign(claims: Value) -> (String, Value) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let enc = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
        let h = enc(json!({"alg": "EdDSA", "kid": "test-key"}).to_string().as_bytes());
        let p = enc(claims.to_string().as_bytes());
        let sig = key.sign(format!("{h}.{p}").as_bytes());
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": enc(key.verifying_key().as_bytes()), "kid": "test-key", "alg": "EdDSA"});
        (format!("{h}.{p}.{}", enc(&sig.to_bytes())), jwk)
    }

    #[test]
    fn claims_are_checked_in_order() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("t").as_secs();
        let (t, jwk) = sign(json!({"iss": "https://i", "aud": "https://a", "exp": now + 60, "email": "x@y"}));
        let keys = vec![jwk];
        assert_eq!(verify(&t, &keys, "https://i", "https://a").expect("ok")["email"], "x@y");
        assert_eq!(verify(&t, &keys, "https://i", "https://b"), Err(JwtError::Audience));
        assert_eq!(verify(&t, &keys, "https://j", "https://a"), Err(JwtError::Issuer));
        let (t, _) = sign(json!({"iss": "https://i", "aud": ["https://a"], "exp": now - 1}));
        assert_eq!(verify(&t, &keys, "https://i", "https://a"), Err(JwtError::Expired));
        let mut forged = t.clone();
        forged.push('A');
        assert!(matches!(
            verify(&forged, &keys, "https://i", "https://a"),
            Err(JwtError::Other(_))
        ));
        assert_eq!(verify(&t, &[], "https://i", "https://a"), Err(JwtError::NoKey));
    }
}
