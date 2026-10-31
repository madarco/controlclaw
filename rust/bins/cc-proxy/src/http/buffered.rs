//! A buffered body that still carries its trailers. gRPC answers end in trailers (`grpc-status`),
//! and mitmproxy passes them on; `Full` has no room for them. The trailers ride in the message's
//! extensions as [`Trailers`] while steps see the body as plain bytes.

use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};

/// The trailers a buffered body came with.
#[derive(Debug, Clone)]
pub struct Trailers(pub HeaderMap);

/// The whole body, then its trailers, if any.
pub struct Buffered {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
    len: u64,
}

impl Buffered {
    pub fn new(data: Bytes, trailers: Option<HeaderMap>) -> Self {
        Self {
            len: data.len() as u64,
            data: Some(data).filter(|d| !d.is_empty()),
            trailers: trailers.filter(|t| !t.is_empty()),
        }
    }

    /// The data and the trailers.
    pub fn into_parts(self) -> (Bytes, Option<HeaderMap>) {
        (self.data.unwrap_or_default(), self.trailers)
    }

    pub fn empty() -> Self {
        Self::new(Bytes::new(), None)
    }
}

impl Body for Buffered {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        if let Some(d) = self.data.take() {
            return Poll::Ready(Some(Ok(Frame::data(d))));
        }
        if let Some(t) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(t))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}
