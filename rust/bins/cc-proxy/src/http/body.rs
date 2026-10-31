//! Reading a buffered body as text, as mitmproxy's `get_text(strict=False)` does: the
//! `content-encoding` undone (gzip, deflate, br, zstd, identity), then decoded as UTF-8 with bad
//! bytes replaced. Checks read bodies through this; one that rewrites a body sends it back without
//! an encoding ([`set_text`]).

use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, HeaderValue};

/// The most a decoded body may grow to: a small compressed body must not unpack into gigabytes.
pub const MAX_DECODED: u64 = 64 * 1024 * 1024;

/// The body with its `content-encoding` undone, or `None` when the encoding is unknown or the
/// bytes do not decode (mitmproxy then gives up on the text too).
pub fn decoded(headers: &HeaderMap, body: &Bytes) -> Option<Bytes> {
    let enc = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let mut out = Vec::new();
    // One byte past the cap tells a body that is too big from one that is exactly the cap: too big
    // is "cannot decode", never a body cut short.
    let read = |r: &mut dyn Read, out: &mut Vec<u8>| {
        r.take(MAX_DECODED + 1)
            .read_to_end(out)
            .ok()
            .filter(|n| (*n as u64) <= MAX_DECODED)
    };
    match enc.as_str() {
        "" | "identity" | "none" => return Some(body.clone()),
        "gzip" | "x-gzip" => read(&mut flate2::read::GzDecoder::new(&body[..]), &mut out)?,
        "deflate" => {
            // Servers send zlib-wrapped or raw deflate under this name; mitmproxy takes both.
            if read(&mut flate2::read::ZlibDecoder::new(&body[..]), &mut out).is_none() {
                out.clear();
                read(&mut flate2::read::DeflateDecoder::new(&body[..]), &mut out)?
            } else {
                0
            }
        }
        "br" => read(&mut brotli_decompressor::Decompressor::new(&body[..], 4096), &mut out)?,
        "zstd" => {
            let mut dec = ruzstd::decoding::StreamingDecoder::new(&body[..]).ok()?;
            read(&mut dec, &mut out)?
        }
        _ => return None,
    };
    Some(Bytes::from(out))
}

/// Undo a buffered body's `content-encoding` in place, as mitmproxy's `.content` reads it: the
/// header goes (the body is sent on as it now is) and `content-length` follows. `true` when the
/// body is now what the server reads; `false` when the encoding is unknown or does not decode (the
/// body and its headers are left as they came, and the checks refuse to read it).
pub fn decode_in_place(headers: &mut HeaderMap, body: &mut Bytes) -> bool {
    let encoded = headers
        .get(CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
        .is_some_and(|v| !matches!(v.as_str(), "" | "identity" | "none"));
    if !encoded {
        return headers.get_all(CONTENT_ENCODING).iter().count() <= 1;
    }
    let Some(plain) = decoded(headers, body) else {
        return false;
    };
    headers.remove(CONTENT_ENCODING);
    if headers.contains_key(http::header::CONTENT_LENGTH) {
        headers.insert(http::header::CONTENT_LENGTH, plain.len().into());
    }
    *body = plain;
    true
}

/// The body as text (`get_text(strict=False)`).
pub fn text(headers: &HeaderMap, body: &Bytes) -> Option<String> {
    decoded(headers, body).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Replace a body with `bytes`, sent with no encoding (the bytes are the decoded body, changed).
pub fn set_bytes(headers: &mut HeaderMap, body: &mut Bytes, bytes: Vec<u8>) {
    headers.remove(CONTENT_ENCODING);
    *body = Bytes::from(bytes);
    if headers.contains_key(CONTENT_LENGTH) {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
}

/// Replace a body with `text`, sent with no encoding (mitmproxy re-encodes; identity is what any
/// client takes), with its length put right.
pub fn set_text(headers: &mut HeaderMap, body: &mut Bytes, text: String) {
    headers.remove(CONTENT_ENCODING);
    *body = Bytes::from(text);
    if headers.contains_key(CONTENT_LENGTH) {
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_body_is_decoded_in_place_for_the_checks() -> std::io::Result<()> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"{\"to\": \"a@b.c\"}")?;
        let zipped = gz.finish()?;
        let mut h = HeaderMap::new();
        h.insert(CONTENT_ENCODING, "gzip".parse().map_err(std::io::Error::other)?);
        h.insert(http::header::CONTENT_LENGTH, zipped.len().into());
        let mut body = Bytes::from(zipped);
        assert!(decode_in_place(&mut h, &mut body));
        assert_eq!(&body[..], b"{\"to\": \"a@b.c\"}");
        assert!(h.get(CONTENT_ENCODING).is_none());
        assert_eq!(h[http::header::CONTENT_LENGTH], body.len().to_string());
        // No encoding: as it is, and decoded.
        let mut plain = Bytes::from_static(b"x");
        assert!(decode_in_place(&mut HeaderMap::new(), &mut plain));
        // An encoding it does not know: left alone, and not decoded.
        let mut h = HeaderMap::new();
        h.insert(CONTENT_ENCODING, "compress".parse().map_err(std::io::Error::other)?);
        let mut odd = Bytes::from_static(b"\x1f\x9d");
        assert!(!decode_in_place(&mut h, &mut odd));
        assert_eq!(h[CONTENT_ENCODING], "compress");
        Ok(())
    }

    fn headers(enc: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(enc) {
            h.insert(CONTENT_ENCODING, v);
        }
        h
    }

    #[test]
    fn undoes_the_encodings_mitmproxy_undoes() -> std::io::Result<()> {
        let plain = b"{\"error\":{\"type\":\"quota_for_entity_exceeded\"}}";
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(plain)?;
        let gz = Bytes::from(gz.finish()?);
        assert_eq!(decoded(&headers("gzip"), &gz).as_deref(), Some(&plain[..]));
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(plain)?;
        assert_eq!(
            decoded(&headers("deflate"), &Bytes::from(z.finish()?)).as_deref(),
            Some(&plain[..])
        );
        let raw = Bytes::from_static(plain);
        assert_eq!(decoded(&HeaderMap::new(), &raw).as_deref(), Some(&plain[..]));
        assert_eq!(decoded(&headers("compress"), &raw), None);
        assert_eq!(decoded(&headers("gzip"), &raw), None, "not gzip at all");
        let mut h = headers("gzip");
        h.insert(CONTENT_LENGTH, HeaderValue::from(gz.len()));
        let mut b = gz;
        set_text(&mut h, &mut b, "new".into());
        assert!(h.get(CONTENT_ENCODING).is_none());
        assert_eq!(h[CONTENT_LENGTH], "3");
        Ok(())
    }
}
