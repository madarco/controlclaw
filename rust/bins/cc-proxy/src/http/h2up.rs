//! The HTTP/2 connection to a site, on the `http2` crate (an `h2` that can order SETTINGS and
//! pseudo-headers): it opens with the agent's own SETTINGS in the agent's order, the agent's
//! connection WINDOW_UPDATE and PRIORITY frames, and sends every request with the agent's
//! pseudo-header order and HEADERS priority (`http::h2print`). With nothing read from the agent
//! (it spoke HTTP/1.1 to us, or sent no request yet), the built-in profile (`tls::chrome`).

use std::time::Duration;

use bytes::Bytes;
use http2::frame::{
    ExperimentalSettings, Priorities, Priority, PseudoId, PseudoOrder, Setting, SettingId, SettingsOrder,
    StreamDependency,
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::h2print::H2Print;

/// HTTP/2's own initial connection window (RFC 9113 §6.9.2).
const DEFAULT_WINDOW: u32 = 65_535;
/// The frame sizes a peer may announce (RFC 9113 §6.5.2); `http2` asserts on any other.
const FRAME_SIZES: std::ops::RangeInclusive<u32> = 16_384..=16_777_215;
/// The largest header table the firewall keeps for a site's headers (Chrome's own is 64 KiB).
const MAX_HEADER_TABLE: u32 = 65_536;
/// The most a site may send before the firewall has read it, per stream and per connection:
/// what the firewall may hold for an agent that reads slowly. Chrome's are 6 MiB and 15 MiB.
const MAX_STREAM_WINDOW: u32 = 16 << 20;
const MAX_CONNECTION_WINDOW: u32 = 16 << 20;
/// The largest header list the firewall accepts from a site (Chrome's is 256 KiB).
const MAX_HEADER_LIST: u32 = 1 << 20;
/// At most this many SETTINGS are copied; Chrome sends four, GREASE adds one.
const MAX_SETTINGS: usize = 16;
/// At most this many PRIORITY frames are copied, for streams up to this ID (Firefox sends six,
/// for 3 to 13). The requests' own stream IDs start past the highest, so a high one would leave
/// no room for any.
const MAX_PRIORITIES: usize = 16;
const MAX_PRIORITY_STREAM: u32 = 99;

/// What went wrong with one request, and whether any of it was sent.
pub enum H2Error {
    Unsent(String),
    Sent(String),
}

#[derive(Clone)]
pub struct H2Sender {
    send: http2::client::SendRequest<Bytes>,
    /// Set by the connection's task when the connection ends (GOAWAY, the site went away). Read
    /// instead of polling the sender: a poll from outside a request would take the place of the
    /// waker of a request waiting for room on the connection, which then never wakes.
    closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// What was left out of an agent's preface, each line once (they are agent-chosen).
fn log_once(what: &str) {
    static LOGGED: crate::log::Once = crate::log::Once::new();
    if let Some(what) = LOGGED.first(what) {
        tracing::info!("[proxy] upstream HTTP/2 copies the agent's preface without: {what}");
    }
}

/// Open HTTP/2 on `io` with `print`'s connection settings.
pub async fn handshake<S>(io: S, print: &H2Print) -> Result<H2Sender, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut b = http2::client::Builder::new();
    let mut order = SettingsOrder::builder();
    let mut experimental = ExperimentalSettings::builder();
    let mut dropped = Vec::new();
    // Pushed streams would be held for nobody (the agent never sees them): push is off even when
    // the agent's SETTINGS leave it out (HTTP/2's default is on).
    b.enable_push(false);
    for (i, (id, v)) in print.settings.iter().enumerate() {
        if i >= MAX_SETTINGS {
            dropped.push(format!("{} more SETTINGS", print.settings.len() - MAX_SETTINGS));
            break;
        }
        // Values HTTP/2 refuses, or that would make the firewall keep more than it should for one
        // connection, are left out (and the site's default applies).
        let out_of_range = match *id {
            1 => *v > MAX_HEADER_TABLE,
            4 => *v > MAX_STREAM_WINDOW,
            5 => !FRAME_SIZES.contains(v),
            6 => *v > MAX_HEADER_LIST,
            _ => false,
        };
        if out_of_range {
            dropped.push(format!("SETTINGS {id} (out of range)"));
            continue;
        }
        match *id {
            1 => {
                b.header_table_size(*v);
            }
            2 => {
                if *v != 0 {
                    dropped.push("ENABLE_PUSH=1 (sent as 0)".to_owned());
                }
            }
            3 => {
                b.max_concurrent_streams(*v);
            }
            4 => {
                b.initial_window_size(*v);
            }
            5 => {
                b.max_frame_size(*v);
            }
            6 => {
                b.max_header_list_size(*v);
            }
            8 => {
                b.enable_connect_protocol(*v != 0);
            }
            9 => {
                b.no_rfc7540_priorities(*v != 0);
            }
            // A setting HTTP/2 does not define (GREASE, a draft): sent as the agent sent it.
            other => match Setting::from_id(other, *v) {
                Some(setting) => experimental = experimental.push(setting),
                None => {
                    dropped.push(format!("SETTINGS {other}"));
                    continue;
                }
            },
        }
        order = order.push(SettingId::from(*id));
    }
    b.settings_order(order.build());
    b.experimental_settings(experimental.build());
    if let Some(inc) = print.window_update {
        b.initial_connection_window_size(DEFAULT_WINDOW.saturating_add(inc).min(MAX_CONNECTION_WINDOW));
    }
    if !print.pseudo_order.is_empty() {
        let ids = print.pseudo_order.iter().filter_map(|n| match n.as_str() {
            ":method" => Some(PseudoId::Method),
            ":scheme" => Some(PseudoId::Scheme),
            ":authority" => Some(PseudoId::Authority),
            ":path" => Some(PseudoId::Path),
            ":protocol" => Some(PseudoId::Protocol),
            _ => None,
        });
        b.headers_pseudo_order(PseudoOrder::builder().extend(ids).build());
    }
    if let Some(p) = print.headers_priority.filter(|p| p.depends_on <= MAX_PRIORITY_STREAM) {
        b.headers_stream_dependency(StreamDependency::new(p.depends_on.into(), p.weight, p.exclusive));
    }
    if !print.priorities.is_empty() {
        let usable = |p: &&super::h2print::Priority| {
            p.stream != 0
                && p.stream <= MAX_PRIORITY_STREAM
                && p.depends_on <= MAX_PRIORITY_STREAM
                && p.depends_on != p.stream
        };
        if print.priorities.len() > MAX_PRIORITIES || !print.priorities.iter().all(|p| usable(&p)) {
            dropped.push("some PRIORITY frames (out of range)".to_owned());
        }
        let list = print.priorities.iter().filter(usable).take(MAX_PRIORITIES).map(|p| {
            Priority::new(
                p.stream.into(),
                StreamDependency::new(p.depends_on.into(), p.weight, p.exclusive),
            )
        });
        b.priorities(Priorities::builder().extend(list).build());
    }
    if !dropped.is_empty() {
        log_once(&dropped.join(", "));
    }
    let (send, conn) = b.handshake::<_, Bytes>(io).await.map_err(|e| e.to_string())?;
    let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ended = closed.clone();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("[proxy] upstream h2 connection: {e}");
        }
        ended.store(true, std::sync::atomic::Ordering::Release);
    });
    Ok(H2Sender { send, closed })
}

impl H2Sender {
    /// Send one request (its body streamed up by a task of its own, with flow control) and return
    /// the answer once its head is in; the body streams from the site as it is read.
    pub async fn send_head(
        &self,
        head: http::Request<()>,
        body: super::upstream::UpBody,
        answer_timeout: Duration,
    ) -> Result<http::Response<RecvBody>, (H2Error, Option<super::upstream::UpBody>)> {
        use http_body::Body as _;
        let mut sender = match self.send.clone().ready().await {
            Ok(s) => s,
            // Nothing of it was taken: its body may go on a new connection.
            Err(e) => return Err((H2Error::Unsent(e.to_string()), Some(body))),
        };
        let end = body.is_end_stream();
        let (answer, stream) = match sender.send_request(head, end) {
            Ok(r) => r,
            Err(e) => {
                let unsent = matches!(e.reason(), Some(http2::Reason::REFUSED_STREAM)) || e.is_go_away() || e.is_io();
                return Err(if unsent {
                    (H2Error::Unsent(e.to_string()), Some(body))
                } else {
                    (H2Error::Sent(e.to_string()), None)
                });
            }
        };
        // The body goes up while the answer is awaited: a site that answers early (a 401, a 413)
        // and stops taking the body is heard. The upload ends with the answer's body.
        let upload = (!end).then(|| tokio::spawn(upload(body, stream)));
        let stop = |upload: &Option<tokio::task::JoinHandle<()>>| {
            if let Some(u) = upload {
                u.abort();
            }
        };
        let resp = match tokio::time::timeout(answer_timeout, answer).await {
            Err(_) => {
                stop(&upload);
                return Err((H2Error::Sent("the site did not answer in time".into()), None));
            }
            Ok(Err(e)) => {
                stop(&upload);
                return Err((H2Error::Sent(e.to_string()), None));
            }
            Ok(Ok(r)) => r,
        };
        let (parts, body) = resp.into_parts();
        Ok(http::Response::from_parts(
            parts,
            RecvBody {
                inner: body,
                done: false,
                upload: upload.map(|u| u.abort_handle()),
            },
        ))
    }

    /// Whether the connection can still take a request: until its task ends.
    pub fn is_open(&self) -> bool {
        !self.closed.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Send a request body on its stream: data within the window the site grants, then trailers or the
/// end of the stream. A body that fails partway resets the stream.
async fn upload(mut body: super::upstream::UpBody, mut stream: http2::SendStream<Bytes>) {
    use http_body_util::BodyExt;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(_) => {
                stream.send_reset(http2::Reason::CANCEL);
                return;
            }
        };
        let frame = match frame.into_data() {
            Ok(mut data) => {
                while !data.is_empty() {
                    stream.reserve_capacity(data.len());
                    let cap = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
                        Some(Ok(n)) => n,
                        // The stream is over (the site answered and closed it): nothing more to send.
                        _ => return,
                    };
                    let chunk = data.split_to(cap.min(data.len()));
                    if stream.send_data(chunk, false).is_err() {
                        return;
                    }
                }
                continue;
            }
            Err(f) => f,
        };
        if let Ok(t) = frame.into_trailers() {
            let _ = stream.send_trailers(t);
            return;
        }
    }
    let _ = stream.send_data(Bytes::new(), true);
}

/// The answer's body from an HTTP/2 stream: window given back as it is read, then the trailers.
/// Dropping it stops the request's upload too.
pub struct RecvBody {
    inner: http2::RecvStream,
    done: bool,
    upload: Option<tokio::task::AbortHandle>,
}

impl Drop for RecvBody {
    fn drop(&mut self) {
        if let Some(u) = &self.upload {
            u.abort();
        }
    }
}

impl http_body::Body for RecvBody {
    type Data = Bytes;
    type Error = super::upstream::BoxError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        if self.done {
            return Poll::Ready(None);
        }
        match self.inner.poll_data(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Some(Ok(data))) => {
                let _ = self.inner.flow_control().release_capacity(data.len());
                return Poll::Ready(Some(Ok(http_body::Frame::data(data))));
            }
            Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => {}
        }
        match self.inner.poll_trailers(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(t)) => {
                self.done = true;
                Poll::Ready(t.map(|t| Ok(http_body::Frame::trailers(t))))
            }
            Poll::Ready(Err(e)) => {
                self.done = true;
                Poll::Ready(Some(Err(e.into())))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::h2print::{self, Priority};
    use tokio::io::AsyncReadExt;

    /// An agent's preface with values HTTP/2 refuses (or that `http2` asserts on): the handshake
    /// still opens, and the SETTINGS sent leave them out.
    #[tokio::test]
    async fn out_of_range_settings_are_left_out() {
        let print = H2Print {
            settings: vec![
                (2, 1),
                (1, u32::MAX),
                (4, u32::MAX),
                (5, 0),
                (5, u32::MAX),
                (6, u32::MAX),
                (4, 0x7fff_ffff),
            ],
            window_update: Some(0x7fff_ffff),
            priorities: vec![
                Priority {
                    stream: 0x7fff_fff1,
                    depends_on: 0,
                    exclusive: false,
                    weight: 1,
                },
                Priority {
                    stream: 3,
                    depends_on: 3,
                    exclusive: false,
                    weight: 1,
                },
                Priority {
                    stream: 0,
                    depends_on: 0,
                    exclusive: false,
                    weight: 1,
                },
            ],
            headers_priority: Some(Priority {
                stream: 1,
                depends_on: 0x7fff_ffff,
                exclusive: true,
                weight: 255,
            }),
            pseudo_order: vec![":method".into(), ":authority".into(), ":scheme".into(), ":path".into()],
            saw_headers: true,
        };
        let (ours, mut site) = tokio::io::duplex(1 << 16);
        let sender = handshake(ours, &print).await;
        assert!(sender.is_ok());
        let mut got = vec![0u8; h2print::PREFACE.len() + 9];
        site.read_exact(&mut got).await.expect("the preface");
        let len = (usize::from(got[got.len() - 9]) << 16)
            | (usize::from(got[got.len() - 8]) << 8)
            | usize::from(got[got.len() - 7]);
        let mut payload = vec![0u8; len];
        site.read_exact(&mut payload).await.expect("the SETTINGS");
        let sent: Vec<(u16, u32)> = payload
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
        // Push asked for, sent as off; everything out of range left out.
        assert_eq!(sent, [(2, 0)]);
    }
}
