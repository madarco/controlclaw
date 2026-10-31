//! Base64 the way the TS code reads and writes it: standard alphabet, padded on output, and on input
//! as forgiving as `atob`/`Buffer.from(s, "base64")` (whitespace dropped, padding optional).

use base64::Engine;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn decode(s: &str) -> crate::Result<Vec<u8>> {
    let cleaned: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    LENIENT
        .decode(cleaned)
        .map_err(|_| crate::CryptoError::new("The string to be decoded is not correctly encoded."))
}
