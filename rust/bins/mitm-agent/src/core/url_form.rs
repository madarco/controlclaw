//! URL-form signatures (`url-form.ts`): Twilio-style HMAC-SHA1 over the URL and the sorted form.
//! W4's phone registrations use it through the ingress; the decoding is strict, so an ambiguous
//! form (a duplicate key, a bad escape) never reaches a verifier.

use std::sync::LazyLock;

use base64::Engine;
use hmac::{Hmac, Mac};
use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormError(pub &'static str);

/// The form in the order it came, keys unique.
pub type Form = Vec<(String, String)>;

static BAD_ESCAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)%([^0-9a-f]|[0-9a-f][^0-9a-f]|[0-9a-f]?$)").expect("re"));
static CONTROL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F]").expect("re"));
static SIGNATURE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{27}=$").expect("re"));
pub static QUERY_VALUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9_-]{1,160}$").expect("re"));

/// `decodeURIComponent`: percent escapes as UTF-8; anything malformed is an error.
fn decode_component(s: &str) -> Result<String, FormError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3).ok_or(FormError("invalid_form"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| FormError("invalid_form"))?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| FormError("invalid_form"))
}

/// `decodeForm`.
pub fn decode_form(body: &[u8]) -> Result<Form, FormError> {
    let body = std::str::from_utf8(body).map_err(|_| FormError("invalid_form"))?;
    if body.len() > 1024 * 1024 || BAD_ESCAPE.is_match(body) {
        return Err(FormError("invalid_form"));
    }
    let entries: Vec<&str> = if body.is_empty() {
        Vec::new()
    } else {
        body.split('&').collect()
    };
    if entries.len() > 128 {
        return Err(FormError("invalid_form"));
    }
    let mut out: Form = Vec::new();
    for entry in entries {
        let (k, v) = match entry.find('=') {
            Some(i) => (&entry[..i], &entry[i + 1..]),
            None => (entry, ""),
        };
        let key = decode_component(&k.replace('+', " "))?;
        let value = decode_component(&v.replace('+', " "))?;
        if key.is_empty() || out.iter().any(|(x, _)| *x == key) || CONTROL.is_match(&format!("{key}{value}")) {
            return Err(FormError("invalid_form"));
        }
        out.push((key, value));
    }
    Ok(out)
}

/// `urlFormSignature`: base64 HMAC-SHA1 of the URL and every key and value, sorted by key.
pub fn url_form_signature(secret: &str, url: &str, form: &Form) -> String {
    let mut sorted: Vec<&(String, String)> = form.iter().collect();
    // JavaScript compares UTF-16 code units.
    sorted.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    let mut material = url.to_string();
    for (k, v) in sorted {
        material.push_str(k);
        material.push_str(v);
    }
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(material.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// `verifyUrlForm`.
pub fn verify_url_form(secret: &str, url: &str, form: &Form, signature: &str) -> bool {
    if !SIGNATURE.is_match(signature) {
        return false;
    }
    cc_crypto::ct_eq(url_form_signature(secret, url, form).as_bytes(), signature.as_bytes())
}

/// `hookQuery`: the query of a hook's request URL, when it holds only what a phone callback sends.
pub fn hook_query(raw: &str) -> Result<String, FormError> {
    if raw.encode_utf16().count() > 2048 || !raw.starts_with('/') || raw.contains('#') {
        return Err(FormError("invalid_url"));
    }
    let query = raw.find('?').map(|i| &raw[i..]).unwrap_or("");
    let parsed = decode_form(query.get(1..).unwrap_or("").as_bytes())?;
    for (k, v) in &parsed {
        let bad = if k == "type" {
            v != "status"
        } else {
            !["callId", "turnToken", "ccCall"].contains(&k.as_str()) || !QUERY_VALUE.is_match(v)
        };
        if bad {
            return Err(FormError("invalid_query"));
        }
    }
    Ok(query.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_are_strict() {
        assert_eq!(
            decode_form(b"a=1&b=x+y%21&c").expect("form"),
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "x y!".into()),
                ("c".into(), String::new())
            ]
        );
        assert!(decode_form(b"a=1&a=2").is_err());
        assert!(decode_form(b"a=%zz").is_err());
        assert!(decode_form(b"a=%2").is_err());
        assert!(decode_form(b"=1").is_err());
        assert!(decode_form(b"a=%01").is_err());
        assert!(decode_form(b"a=%C3").is_err());
        assert_eq!(decode_form(b"").expect("empty"), Vec::<(String, String)>::new());
    }

    #[test]
    fn twilio_signature() {
        // The value the TS `urlFormSignature` gives for the same input.
        let form = decode_form(
            b"CallSid=CA1234567890ABCDE&Caller=%2B12349013030&Digits=1234&From=%2B12349013030&To=%2B18005551212",
        )
        .expect("form");
        let sig = url_form_signature("12345", "https://mycompany.com/myapp.php?foo=1&bar=2", &form);
        assert_eq!(sig, "0/KCTR6DLpKmkAf8muzZqo1nDgQ=");
        assert!(verify_url_form(
            "12345",
            "https://mycompany.com/myapp.php?foo=1&bar=2",
            &form,
            &sig
        ));
        assert!(!verify_url_form("12345", "https://other", &form, &sig));
        assert_eq!(
            hook_query("/hook/x?callId=a_1&type=status").expect("q"),
            "?callId=a_1&type=status"
        );
        assert!(hook_query("/hook/x?evil=1").is_err());
        assert!(hook_query("/hook/x?type=other").is_err());
        assert_eq!(hook_query("/hook/x").expect("q"), "");
    }
}
