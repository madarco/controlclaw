//! The agent's HTTP/2 fingerprint, read off the start of its connection: the SETTINGS it sends and
//! their order, its connection WINDOW_UPDATE, the PRIORITY frames before its first request, and
//! that request's priority and pseudo-header order. The upstream h2 connection sends the same.
//!
//! The bytes read are kept and served to hyper as they came (`Prefixed`), so reading them here
//! changes nothing for the agent.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// How much of the connection's start is read to find the first HEADERS frame.
const MAX_READ: usize = 64 * 1024;
/// How long the agent's SETTINGS may take to come.
const WAIT: Duration = Duration::from_millis(1500);
/// How long after its SETTINGS the agent's first request may take. Chrome sends it in the same
/// flight; a client that waits for our SETTINGS first is held only this long, and gets the
/// SETTINGS it sent and the rest from the built-in profile.
const WAIT_AFTER_SETTINGS: Duration = Duration::from_millis(50);

const FRAME_HEADERS: u8 = 1;
const FRAME_PRIORITY: u8 = 2;
const FRAME_SETTINGS: u8 = 4;
const FRAME_WINDOW_UPDATE: u8 = 8;
const FRAME_CONTINUATION: u8 = 9;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// A stream priority as a HEADERS or PRIORITY frame carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Priority {
    pub stream: u32,
    pub depends_on: u32,
    pub exclusive: bool,
    /// As sent (the weight minus one).
    pub weight: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct H2Print {
    /// SETTINGS in the order sent.
    pub settings: Vec<(u16, u32)>,
    /// The connection-level WINDOW_UPDATE increment, if one was sent before the first request.
    pub window_update: Option<u32>,
    /// PRIORITY frames before the first request (Firefox's tree; Chrome sends none).
    pub priorities: Vec<Priority>,
    /// The first request's HEADERS priority, if it carried one.
    pub headers_priority: Option<Priority>,
    /// Pseudo-header names of the first request in order (`:method`, `:authority`, ...).
    pub pseudo_order: Vec<String>,
    /// Whether the whole first HEADERS frame was seen (else the request part comes from the
    /// built-in profile).
    pub saw_headers: bool,
}

/// Read the agent's connection start until its first HEADERS frame (or the limits), returning the
/// bytes read and what they say. `None`: not an HTTP/2 preface.
pub async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<(Vec<u8>, Option<H2Print>)> {
    let mut buf = Vec::new();
    let mut deadline = tokio::time::Instant::now() + WAIT;
    let mut settings_in = false;
    loop {
        if let Some(done) = parse(&buf) {
            return Ok((buf, done.map(|(p, _)| p)));
        }
        if !settings_in && parse_partial(&buf).is_some_and(|p| !p.settings.is_empty()) {
            settings_in = true;
            deadline = deadline.min(tokio::time::Instant::now() + WAIT_AFTER_SETTINGS);
        }
        if buf.len() >= MAX_READ {
            return Ok((buf.clone(), parse_partial(&buf)));
        }
        let mut chunk = [0u8; 8192];
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok((buf.clone(), parse_partial(&buf))),
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok((buf.clone(), parse_partial(&buf))),
        }
    }
}

/// `Some(None)`: not a preface. `Some(Some(..))`: the first HEADERS frame is in. `None`: more is
/// needed.
fn parse(buf: &[u8]) -> Option<Option<(H2Print, usize)>> {
    if buf.len() < PREFACE.len() {
        return (!PREFACE.starts_with(buf)).then_some(None);
    }
    if !buf.starts_with(PREFACE) {
        return Some(None);
    }
    let (print, done) = frames(&buf[PREFACE.len()..]);
    done.then_some(Some((print, buf.len())))
}

/// What the bytes so far say, when no HEADERS frame came.
fn parse_partial(buf: &[u8]) -> Option<H2Print> {
    buf.starts_with(PREFACE).then(|| frames(&buf[PREFACE.len()..]).0)
}

/// The frames in `b` up to the first HEADERS: what they say, and whether that HEADERS was seen.
fn frames(mut b: &[u8]) -> (H2Print, bool) {
    let mut p = H2Print::default();
    while b.len() >= 9 {
        let len = (usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]);
        let (typ, flags) = (b[3], b[4]);
        let stream = u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & 0x7fff_ffff;
        if b.len() < 9 + len {
            break;
        }
        let payload = &b[9..9 + len];
        match typ {
            FRAME_SETTINGS if flags & FLAG_ACK == 0 && stream == 0 && p.settings.is_empty() => {
                p.settings = payload
                    .as_chunks::<6>()
                    .0
                    .iter()
                    .map(|c| {
                        (
                            u16::from_be_bytes([c[0], c[1]]),
                            u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                        )
                    })
                    .collect();
            }
            FRAME_WINDOW_UPDATE if stream == 0 && payload.len() == 4 && p.window_update.is_none() => {
                p.window_update =
                    Some(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff);
            }
            FRAME_PRIORITY if payload.len() == 5 => p.priorities.push(priority(stream, payload)),
            FRAME_HEADERS => {
                let mut block = payload;
                if flags & FLAG_PADDED != 0 {
                    let pad = usize::from(*block.first().unwrap_or(&0));
                    block = block.get(1..block.len().saturating_sub(pad)).unwrap_or(&[]);
                }
                if flags & FLAG_PRIORITY != 0 && block.len() >= 5 {
                    p.headers_priority = Some(priority(stream, block));
                    block = &block[5..];
                }
                // A header block too big for one frame goes on in CONTINUATION frames: the whole
                // block is decoded once it is all in.
                let mut whole = block.to_vec();
                let mut ended = flags & FLAG_END_HEADERS != 0;
                let mut rest = &b[9 + len..];
                while !ended {
                    if rest.len() < 9 {
                        return (p, false);
                    }
                    let clen = (usize::from(rest[0]) << 16) | (usize::from(rest[1]) << 8) | usize::from(rest[2]);
                    if rest.len() < 9 + clen {
                        return (p, false);
                    }
                    if rest[3] != FRAME_CONTINUATION {
                        // Not HTTP/2 as written: the request part comes from the profile.
                        return (p, true);
                    }
                    whole.extend_from_slice(&rest[9..9 + clen]);
                    ended = rest[4] & FLAG_END_HEADERS != 0;
                    rest = &rest[9 + clen..];
                }
                p.pseudo_order = pseudo_names(&whole);
                p.saw_headers = true;
                return (p, true);
            }
            _ => {}
        }
        b = &b[9 + len..];
    }
    (p, false)
}

fn priority(stream: u32, b: &[u8]) -> Priority {
    let dep = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    Priority {
        stream,
        depends_on: dep & 0x7fff_ffff,
        exclusive: dep & 0x8000_0000 != 0,
        weight: b[4],
    }
}

/// The pseudo-header names of one header block, in order.
fn pseudo_names(block: &[u8]) -> Vec<String> {
    let mut decoder = hpack::Decoder::new();
    decoder
        .decode(block)
        .map(|headers| {
            headers
                .into_iter()
                .map(|(name, _)| String::from_utf8_lossy(&name).into_owned())
                .filter(|n| n.starts_with(':'))
                .collect()
        })
        .unwrap_or_default()
}

/// Parse a whole captured connection start (tests and the built-in profile).
pub fn from_bytes(buf: &[u8]) -> Option<H2Print> {
    parse_partial(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROME: &[u8] = include_bytes!("../tls/testdata/chrome-153-h2-preface.bin");

    #[test]
    fn reads_chromes_preface() {
        let p = from_bytes(CHROME).expect("a preface");
        assert_eq!(p.settings, [(1, 65536), (2, 0), (4, 6_291_456), (6, 262_144)]);
        assert_eq!(p.window_update, Some(15_663_105));
        assert!(p.priorities.is_empty());
        assert_eq!(
            p.headers_priority,
            Some(Priority {
                stream: 1,
                depends_on: 0,
                exclusive: true,
                weight: 255
            })
        );
        assert_eq!(p.pseudo_order, [":method", ":authority", ":scheme", ":path"]);
        assert!(p.saw_headers);
    }

    #[test]
    fn a_header_block_in_continuation_frames_is_read_whole() {
        // Chrome's preface, its first HEADERS split in two: HEADERS without END_HEADERS, then a
        // CONTINUATION with it.
        let at = PREFACE.len() + 9 + 24 + 9 + 4; // preface, SETTINGS (4 settings), WINDOW_UPDATE
        let head = &CHROME[at..at + 9];
        let len = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let payload = &CHROME[at + 9..at + 9 + len];
        let split = 5 + 3; // priority, then three bytes of the block
        let mut b = CHROME[..at].to_vec();
        let first = &payload[..split];
        b.extend_from_slice(&[
            0,
            0,
            u8::try_from(first.len()).unwrap_or(0),
            1,
            head[4] & !FLAG_END_HEADERS,
        ]);
        b.extend_from_slice(&head[5..9]);
        b.extend_from_slice(first);
        let second = &payload[split..];
        b.extend_from_slice(&u32::try_from(second.len()).unwrap_or(0).to_be_bytes()[1..]);
        b.extend_from_slice(&[FRAME_CONTINUATION, FLAG_END_HEADERS]);
        b.extend_from_slice(&head[5..9]);
        b.extend_from_slice(second);
        let p = from_bytes(&b).expect("a preface");
        assert_eq!(p.pseudo_order, [":method", ":authority", ":scheme", ":path"]);
        assert!(p.saw_headers);
        // Only the first part: not done yet.
        assert!(parse(&b[..b.len() - 3]).is_none());
    }

    #[tokio::test]
    async fn reading_keeps_every_byte() -> std::io::Result<()> {
        let mut src: &[u8] = CHROME;
        let (bytes, print) = read(&mut src).await?;
        assert_eq!(bytes, CHROME);
        assert!(print.is_some_and(|p| p.saw_headers));
        let mut not_h2: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
        let (bytes, print) = read(&mut not_h2).await?;
        assert_eq!(bytes, b"GET / HTTP/1.1\r\n\r\n");
        assert!(print.is_none());
        Ok(())
    }
}
