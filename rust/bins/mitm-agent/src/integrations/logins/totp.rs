//! Two-step codes for website logins (`logins-totp.ts`, docs/plans/website-credentials.md §4.5):
//! RFC 6238 TOTP from a seed kept on the firewall, given as the base32 key a site shows or as the
//! `otpauth://` link the QR code holds.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Totp {
    pub secret: String,
    pub digits: u32,
    pub period: u64,
    /// `SHA1`, `SHA256` or `SHA512`.
    pub algorithm: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn clean(input: &str) -> String {
    let s = input.trim_end_matches('=');
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_uppercase()
}

pub fn base32_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for c in clean(input).chars() {
        let Some(i) = ALPHABET.find(c) else {
            return Err(
                "That is not a two-step key: use the letters and digits the site shows, or the otpauth:// link.".into(),
            );
        };
        value = (value << 5) | i as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    Ok(out)
}

/// A base32 key or an `otpauth://totp/...` link, checked and normalised. Fails with a sentence.
pub fn parse_totp(input: &str) -> Result<Totp, String> {
    let text = crate::integrations::js::trim(input);
    let mut secret = text.to_string();
    let mut digits = 6f64;
    let mut period = 30f64;
    let mut algorithm = "SHA1".to_string();
    if text.to_ascii_lowercase().starts_with("otpauth:") {
        let url = url::Url::parse(text).map_err(|_| "That otpauth:// link could not be read.".to_string())?;
        if url.host_str().map(str::to_lowercase).as_deref() != Some("totp") {
            return Err("Only time-based codes (otpauth://totp/...) are supported.".into());
        }
        let q = |k: &str| url.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
        secret = q("secret").unwrap_or_default();
        // `Number(...)`: anything that is not a number is NaN, which the checks below refuse.
        let num = |v: Option<String>, d: f64| v.map(|s| s.trim().parse::<f64>().unwrap_or(f64::NAN)).unwrap_or(d);
        digits = num(q("digits"), 6.0);
        period = num(q("period"), 30.0);
        algorithm = q("algorithm").unwrap_or_else(|| "SHA1".into()).to_uppercase();
        if !["SHA1", "SHA256", "SHA512"].contains(&algorithm.as_str()) {
            return Err("That two-step link uses an algorithm that is not supported.".into());
        }
    }
    if digits.fract() != 0.0 || !(6.0..=8.0).contains(&digits) {
        return Err("Two-step codes must have 6 to 8 digits.".into());
    }
    if period.fract() != 0.0 || !(15.0..=120.0).contains(&period) {
        return Err("That two-step link has an unusual period.".into());
    }
    if base32_decode(&secret)?.len() < 10 {
        return Err("That two-step key is too short. Copy the whole key the site shows.".into());
    }
    Ok(Totp {
        secret: clean(&secret),
        digits: digits as u32,
        period: period as u64,
        algorithm,
        extra: Map::new(),
    })
}

fn hmac_of(algorithm: &str, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($t:ty) => {{
            let mut m = <Hmac<$t>>::new_from_slice(key).expect("any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match algorithm {
        "SHA256" => run!(sha2::Sha256),
        "SHA512" => run!(sha2::Sha512),
        _ => run!(sha1::Sha1),
    }
}

/// The code for `at_ms`, and how many seconds it has left.
pub fn totp_code(t: &Totp, at_ms: i64) -> (String, u64) {
    // A store written elsewhere is read as it is: a period or a length no code can have is not a
    // reason to stop (`parse_totp` never makes one).
    let t = &Totp {
        period: t.period.max(1),
        digits: t.digits.clamp(1, 9),
        ..t.clone()
    };
    let seconds = (at_ms.max(0) / 1000) as u64;
    let counter = seconds / t.period;
    let key = base32_decode(&t.secret).unwrap_or_default();
    let digest = hmac_of(&t.algorithm, &key, &counter.to_be_bytes());
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | digest[offset + 3] as u32;
    let code = binary % 10u32.pow(t.digits);
    (
        format!("{code:0width$}", width = t.digits as usize),
        t.period - (seconds % t.period),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_key_no_code_can_have_does_not_stop_anything() {
        let t = Totp {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 12,
            period: 0,
            algorithm: "SHA1".into(),
            extra: Map::new(),
        };
        let (code, left) = totp_code(&t, 59_000);
        assert_eq!((code.len(), left), (9, 1));
    }

    #[test]
    fn rfc_6238_vectors() {
        // RFC 6238 appendix B, the SHA1 seed "12345678901234567890", 8 digits.
        let t = Totp {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 8,
            period: 30,
            algorithm: "SHA1".into(),
            extra: Map::new(),
        };
        assert_eq!(totp_code(&t, 59_000).0, "94287082");
        assert_eq!(totp_code(&t, 1_111_111_109_000).0, "07081804");
        assert_eq!(totp_code(&t, 20_000_000_000_000).0, "65353130");
        assert_eq!(totp_code(&t, 59_000).1, 1);
        let sha256 = Totp {
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA".into(),
            algorithm: "SHA256".into(),
            ..t.clone()
        };
        assert_eq!(totp_code(&sha256, 59_000).0, "46119246");
    }

    #[test]
    fn keys_and_links() {
        let t = parse_totp("jbsw y3dp ehpk 3pxp").expect("key");
        assert_eq!((t.secret.as_str(), t.digits, t.period), ("JBSWY3DPEHPK3PXP", 6, 30));
        let l =
            parse_totp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8&period=60&algorithm=sha256").expect("link");
        assert_eq!((l.digits, l.period, l.algorithm.as_str()), (8, 60, "SHA256"));
        assert_eq!(
            parse_totp("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").expect_err("hotp"),
            "Only time-based codes (otpauth://totp/...) are supported."
        );
        assert_eq!(
            parse_totp("JBSW").expect_err("short"),
            "That two-step key is too short. Copy the whole key the site shows."
        );
        assert!(parse_totp("not!base32").is_err());
        assert_eq!(
            parse_totp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=x").expect_err("nan"),
            "Two-step codes must have 6 to 8 digits."
        );
    }
}
