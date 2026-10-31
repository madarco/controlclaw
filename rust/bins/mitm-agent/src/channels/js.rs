//! JavaScript string lengths and slices: the TS counts and cuts UTF-16 units, so the Rust port
//! does the same wherever a limit is copied from it.

/// `s.length`.
pub fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// `s.slice(0, n)`. A surrogate pair cut in two becomes U+FFFD.
pub fn js_slice(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let units: Vec<u16> = s.encode_utf16().take(n).collect();
    String::from_utf16_lossy(&units)
}

/// `s.slice(a, b)`.
pub fn js_slice_range(units: &[u16], a: usize, b: usize) -> String {
    let b = b.min(units.len());
    String::from_utf16_lossy(&units[a.min(b)..b])
}
