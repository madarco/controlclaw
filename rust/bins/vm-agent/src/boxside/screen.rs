//! A small picture of the agent's screen for the console's agent card (`screen-thumb.ts`).
//! `GET /screen/thumb`, the console's token only. Taken from the X screen (Xvfb `:1`) as a pipe of
//! four small programs under `nice`, 320 px across at JPEG quality 50, at most once every 30 s
//! whoever asks, one capture at a time, killed after 5 s. Nothing is written to disk.
//!
//! The pipe is spawned here rather than through the `cc_proc` runner, which runs one program at a
//! time and cannot connect one's output to the next one's input. Every program is killed with its
//! handle when the capture ends early (the timer, too large a picture), as the TS does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use cc_http::{BoxFuture, Resp};
use futures_util::FutureExt;
use futures_util::future::Shared;
use serde_json::json;

use super::web;

pub const THUMB_MIN_INTERVAL: Duration = Duration::from_secs(30);
pub const THUMB_CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);
pub const THUMB_WIDTH: u32 = 320;
const THUMB_QUALITY: u32 = 50;
const THUMB_MAX_BYTES: usize = 256 * 1024;
pub const FAILURE_BACKOFF: Duration = Duration::from_secs(30);

/// `ThumbUnavailableError`: `unsupported`, `no-screen` or `failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    pub message: String,
    pub code: &'static str,
}

fn unavailable(message: impl Into<String>, code: &'static str) -> Unavailable {
    Unavailable {
        message: message.into(),
        code,
    }
}

/// `captureCommands`: each program under `nice -n 10`.
pub fn capture_commands(display: &str) -> Vec<Vec<String>> {
    [
        vec!["xwd", "-root", "-silent", "-display", display],
        vec!["xwdtopnm", "-quiet"],
        vec!["pamscale", "-quiet", "-width", &THUMB_WIDTH.to_string()],
        vec!["pnmtojpeg", "-quiet", &format!("-quality={THUMB_QUALITY}")],
    ]
    .iter()
    .map(|argv| ["-n", "10"].iter().chain(argv.iter()).map(|s| s.to_string()).collect())
    .collect()
}

pub type Capture = Arc<dyn Fn() -> BoxFuture<Result<Bytes, Unavailable>> + Send + Sync>;

/// `screenCapture`: one frame from the pipe. `nice` is the program run, so a missing tool shows
/// as its exit 127.
pub fn screen_capture(display: String) -> Capture {
    Arc::new(move || {
        let display = display.clone();
        async move {
            // On the timer the pipe is dropped, and with it every child (`kill_on_drop`).
            match tokio::time::timeout(THUMB_CAPTURE_TIMEOUT, capture(&display)).await {
                Ok(r) => r,
                Err(_) => Err(unavailable("The screen took too long to capture.", "failed")),
            }
        }
        .boxed()
    })
}

/// A program's stderr, read while it runs so a full pipe never stalls it; the first 2000 bytes kept.
fn drain(mut err: tokio::process::ChildStderr) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut kept = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(n) = err.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if kept.len() < 2000 {
                kept.extend_from_slice(&buf[..n.min(2000 - kept.len())]);
            }
        }
        String::from_utf8_lossy(&kept).into_owned()
    })
}

async fn capture(display: &str) -> Result<Bytes, Unavailable> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".into());
    let failed = |e: std::io::Error| unavailable(format!("The screen could not be captured: {e}"), "failed");
    let commands = capture_commands(display);
    let last_index = commands.len() - 1;
    let mut children = Vec::new();
    let mut stderrs = Vec::new();
    let mut previous: Option<Stdio> = None;
    let mut last = None;
    for (i, argv) in commands.iter().enumerate() {
        let mut child = tokio::process::Command::new("nice")
            .args(argv)
            .env_clear()
            .env("PATH", &path)
            .stdin(previous.take().unwrap_or_else(Stdio::null))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(failed)?;
        if let Some(err) = child.stderr.take() {
            stderrs.push(drain(err));
        }
        let out = child.stdout.take();
        if i == last_index {
            last = out;
        } else if let Some(out) = out {
            previous = Some(out.try_into().map_err(failed)?);
        }
        children.push(child);
    }
    let mut out = Vec::new();
    if let Some(mut last) = last {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match last.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    out.extend_from_slice(&buf[..n]);
                    if out.len() > THUMB_MAX_BYTES {
                        // Dropping the children kills them.
                        return Err(unavailable("The picture came out too large.", "failed"));
                    }
                }
            }
        }
    }
    let mut codes = Vec::new();
    for c in children.iter_mut() {
        codes.push(c.wait().await.ok().and_then(|s| s.code()));
    }
    let mut stderr = String::new();
    for h in stderrs {
        stderr.push_str(&h.await.unwrap_or_default());
    }
    if codes.iter().all(|c| *c == Some(0)) && !out.is_empty() {
        return Ok(Bytes::from(out));
    }
    if codes.contains(&Some(127)) {
        return Err(unavailable(
            "This agent has no tools to capture its screen with. Update the agent.",
            "unsupported",
        ));
    }
    if stderr.to_lowercase().contains("open display") {
        return Err(unavailable("The agent's screen is not running.", "no-screen"));
    }
    let shown: Vec<String> = codes
        .iter()
        .map(|c| c.map(|c| c.to_string()).unwrap_or_else(|| "null".into()))
        .collect();
    Err(unavailable(
        format!("The screen could not be captured (exit {}).", shown.join(",")),
        "failed",
    ))
}

type Running = Shared<BoxFuture<Result<(Bytes, i64), Unavailable>>>;

#[derive(Default)]
struct State {
    last: Option<(Bytes, i64, std::time::Instant)>,
    failed_at: Option<std::time::Instant>,
    last_error: Option<Unavailable>,
    running: Option<Running>,
}

/// `ScreenThumbService`: the last picture and the one capture that may be running.
pub struct ScreenThumbs {
    capture: Capture,
    state: Arc<Mutex<State>>,
}

impl ScreenThumbs {
    pub fn new(capture: Capture) -> Self {
        Self {
            capture,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// From memory when it is younger than 30 s, otherwise a new one.
    pub async fn get(&self) -> Result<(Bytes, i64), Unavailable> {
        let fut = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((jpeg, at, taken)) = &s.last
                && taken.elapsed() < THUMB_MIN_INTERVAL
            {
                return Ok((jpeg.clone(), *at));
            }
            if let Some(r) = &s.running {
                r.clone()
            } else {
                if let (Some(e), Some(t)) = (&s.last_error, s.failed_at)
                    && t.elapsed() < FAILURE_BACKOFF
                {
                    return Err(e.clone());
                }
                // Dated from when the capture started.
                let at = web::time_ms(std::time::SystemTime::now());
                let started = std::time::Instant::now();
                let capture = self.capture.clone();
                let state = self.state.clone();
                // A task of its own, so the result is kept even when every caller has gone.
                let task = tokio::spawn(async move {
                    let r = capture().await;
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    s.running = None;
                    match r {
                        Ok(jpeg) => {
                            s.last = Some((jpeg.clone(), at, started));
                            s.last_error = None;
                            Ok((jpeg, at))
                        }
                        Err(e) => {
                            s.failed_at = Some(std::time::Instant::now());
                            s.last_error = Some(e.clone());
                            Err(e)
                        }
                    }
                });
                let f: Running = async move {
                    task.await
                        .unwrap_or_else(|_| Err(unavailable("The screen could not be captured.", "failed")))
                }
                .boxed()
                .shared();
                s.running = Some(f.clone());
                f
            }
        };
        fut.await
    }
}

/// `handleScreenThumb`; the console's token was checked by the gate.
pub async fn handle(thumbs: &ScreenThumbs) -> Resp {
    match thumbs.get().await {
        Ok((jpeg, at)) => web::with_headers(
            cc_http::full(http::StatusCode::OK, "image/jpeg", jpeg.clone()),
            &[
                ("content-length", jpeg.len().to_string()),
                ("cache-control", "no-store".into()),
                ("x-content-type-options", "nosniff".into()),
                ("x-captured-at", web::iso(at)),
            ],
        ),
        Err(e) => {
            if e.code == "failed" {
                tracing::warn!("[screen-thumb] {}", e.message);
            }
            web::send_json(503, &json!({"error": e.message, "code": e.code}), &[])
        }
    }
}

#[cfg(test)]
mod tests;
