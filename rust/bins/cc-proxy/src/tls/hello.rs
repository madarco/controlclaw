//! The agent's ClientHello as the upstream handshake copies it: every cipher suite and every
//! extension, in the order sent, with the lists inside the extensions the upstream TLS can set.
//!
//! Only what decides the fingerprint is kept. The random, the session id, the key-share key bytes,
//! the PSK (the agent's tickets are for our certificate, not the site's) and the padding length are
//! not: the upstream handshake makes its own.

/// TLS GREASE values (RFC 8701): `0x?a?a` with both bytes equal.
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

pub mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const STATUS_REQUEST: u16 = 5;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const SCT: u16 = 18;
    pub const PADDING: u16 = 21;
    pub const ENCRYPT_THEN_MAC: u16 = 22;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const COMPRESS_CERTIFICATE: u16 = 27;
    pub const RECORD_SIZE_LIMIT: u16 = 28;
    pub const DELEGATED_CREDENTIALS: u16 = 34;
    pub const SESSION_TICKET: u16 = 35;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const KEY_SHARE: u16 = 51;
    pub const ALPS_OLD: u16 = 17513;
    pub const ALPS: u16 = 17613;
    pub const ECH: u16 = 0xfe0d;
    pub const TRUST_ANCHORS: u16 = 0xca34;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// One ClientHello, as far as the upstream handshake copies it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Hello {
    /// Cipher suites in order, GREASE included where it was sent.
    pub ciphers: Vec<u16>,
    /// Extension types in order, GREASE included where it was sent.
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    /// The groups that carry a key share, in order.
    pub key_shares: Vec<u16>,
    pub sigalgs: Vec<u16>,
    pub alpn: Vec<Vec<u8>>,
    pub versions: Vec<u16>,
    pub cert_compression: Vec<u16>,
    /// ALPS protocols, under whichever codepoint the client used.
    pub alps: Vec<Vec<u8>>,
    pub record_size_limit: Option<u16>,
    pub delegated_credentials: Vec<u16>,
    /// The trust anchor IDs the client requested, in wire form (each 8-bit length-prefixed), the
    /// list's own 16-bit length taken off; `Some` (maybe empty) when it sent the extension.
    pub trust_anchors: Option<Vec<u8>>,
}

impl Hello {
    pub fn has(&self, ext: u16) -> bool {
        self.extensions.contains(&ext)
    }

    /// Whether the client sent GREASE (in its ciphers or its extensions).
    pub fn grease(&self) -> bool {
        self.ciphers.iter().chain(&self.extensions).any(|v| is_grease(*v))
    }

    /// The hello with what a client draws afresh for each connection taken out, for keying the
    /// connectors built from it: every GREASE value becomes one fixed value (BoringSSL draws its
    /// own), and a shuffled extension order ([`Hello::permutes`]) is sorted.
    pub fn key_form(&self) -> Hello {
        let fixed = |v: &[u16]| -> Vec<u16> { v.iter().map(|x| if is_grease(*x) { 0x0a0a } else { *x }).collect() };
        let mut h = self.clone();
        h.ciphers = fixed(&self.ciphers);
        h.extensions = fixed(&self.extensions);
        h.groups = fixed(&self.groups);
        h.key_shares = fixed(&self.key_shares);
        h.sigalgs = fixed(&self.sigalgs);
        h.versions = fixed(&self.versions);
        if self.permutes() {
            h.extensions.sort_unstable();
        }
        h
    }

    /// Whether this is a Chromium hello (GREASE and ALPS, which only Chromium sends): Chromium
    /// shuffles its extensions afresh on every connection, so its order says nothing to copy.
    pub fn permutes(&self) -> bool {
        self.grease() && (self.has(ext::ALPS) || self.has(ext::ALPS_OLD))
    }
}

/// Parse a ClientHello handshake message (type, length, body). `None` for anything malformed: the
/// built-in profile is used then.
pub fn parse(handshake: &[u8]) -> Option<Hello> {
    let mut r = Reader(handshake);
    if r.u8()? != 1 {
        return None;
    }
    let len = r.u24()?;
    let mut body = Reader(r.take(len)?);
    body.take(2 + 32)?; // legacy version, random
    let sid = body.u8()?;
    body.take(usize::from(sid))?;
    let mut hello = Hello::default();
    let mut ciphers = Reader(body.vec16()?);
    while !ciphers.0.is_empty() {
        hello.ciphers.push(ciphers.u16()?);
    }
    let comp = body.u8()?;
    body.take(usize::from(comp))?;
    if body.0.is_empty() {
        return Some(hello);
    }
    let mut exts = Reader(body.vec16()?);
    while !exts.0.is_empty() {
        let typ = exts.u16()?;
        let data = exts.vec16()?;
        hello.extensions.push(typ);
        let mut d = Reader(data);
        match typ {
            ext::SUPPORTED_GROUPS => hello.groups = Reader(d.vec16()?).u16s()?,
            ext::SIGNATURE_ALGORITHMS => hello.sigalgs = Reader(d.vec16()?).u16s()?,
            ext::DELEGATED_CREDENTIALS => hello.delegated_credentials = Reader(d.vec16()?).u16s()?,
            ext::SUPPORTED_VERSIONS => hello.versions = Reader(d.vec8()?).u16s()?,
            ext::COMPRESS_CERTIFICATE => hello.cert_compression = Reader(d.vec8()?).u16s()?,
            ext::RECORD_SIZE_LIMIT => hello.record_size_limit = Some(d.u16()?),
            ext::KEY_SHARE => {
                let mut shares = Reader(d.vec16()?);
                while !shares.0.is_empty() {
                    hello.key_shares.push(shares.u16()?);
                    shares.vec16()?;
                }
            }
            ext::ALPN => hello.alpn = Reader(d.vec16()?).strings()?,
            ext::ALPS | ext::ALPS_OLD => hello.alps = Reader(d.vec16()?).strings()?,
            ext::TRUST_ANCHORS => hello.trust_anchors = Some(d.vec16()?.to_vec()),
            _ => {}
        }
    }
    Some(hello)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some(usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
    fn u16s(mut self) -> Option<Vec<u16>> {
        let mut out = Vec::new();
        while !self.0.is_empty() {
            out.push(self.u16()?);
        }
        Some(out)
    }
    fn strings(mut self) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        while !self.0.is_empty() {
            out.push(self.vec8()?.to_vec());
        }
        Some(out)
    }
}

/// The handshake message inside the records `buf` starts with (the bytes `read_client_hello`
/// collected), or `None` when it is not all there.
pub fn handshake_of(buf: &[u8]) -> Option<Vec<u8>> {
    let mut msg = Vec::new();
    let mut at = 0;
    while buf.len() >= at + 5 && buf[at] == 0x16 {
        let len = usize::from(u16::from_be_bytes([buf[at + 3], buf[at + 4]]));
        msg.extend_from_slice(buf.get(at + 5..at + 5 + len)?);
        at += 5 + len;
        if msg.len() >= 4 {
            let want = 4 + (usize::from(msg[1]) << 16 | usize::from(msg[2]) << 8 | usize::from(msg[3]));
            if msg.len() >= want {
                msg.truncate(want);
                return Some(msg);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_values() {
        assert!(is_grease(0x0a0a) && is_grease(0xfafa) && is_grease(0x3a3a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1301) && !is_grease(0xfe0d));
    }
}
