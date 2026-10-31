use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The gateway protocol version this client speaks (both bounds of the handshake).
pub const PROTOCOL: u32 = 4;
/// `operator.admin` is needed for the `*.approval.requested` broadcasts (OpenClaw 2026.9.3).
pub const GATEWAY_SCOPES: [&str; 3] = ["operator.read", "operator.approvals", "operator.admin"];
/// Opening the socket and the handshake together, as in the TS.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_MIN_BACKOFF: Duration = Duration::from_secs(1);
/// Capped low on purpose: a gateway start takes 12-17 s and a longer cap slept through it (T-102).
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(2);

/// The gateway methods that write OpenClaw's config file.
const CONFIG_WRITE_METHODS: [&str; 3] = ["config.patch", "config.apply", "config.set"];

/// Where and how to connect.
#[derive(Debug, Clone)]
pub struct GatewayOptions {
    pub url: String,
    pub token: String,
    pub scopes: Vec<String>,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub connect_timeout: Duration,
}

impl GatewayOptions {
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            token: token.into(),
            scopes: GATEWAY_SCOPES.iter().map(|s| s.to_string()).collect(),
            min_backoff: DEFAULT_MIN_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }

    /// The gateway on this box: `ws://127.0.0.1:<OPENCLAW_GATEWAY_PORT>`.
    pub fn local(port: u16, token: impl Into<String>) -> Self {
        Self::new(format!("ws://127.0.0.1:{port}"), token)
    }

    /// As index.ts `startGatewayBridge`: the token is `KEYS_DIR/openclaw_gateway_token`, trimmed.
    /// None when the file is missing or empty, and then the bridge stays off.
    pub fn from_keys_dir(keys_dir: &Path, port: u16) -> Option<Self> {
        let token = std::fs::read_to_string(keys_dir.join("openclaw_gateway_token")).ok()?;
        let token = token.trim();
        (!token.is_empty()).then(|| Self::local(port, token))
    }
}

/// A gateway broadcast: `{type: "event", event, payload}`.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayEvent {
    pub event: String,
    pub payload: Value,
}

/// A config write was sent, or has settled whatever its answer (`onConfigWrite` in the TS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigWritePhase {
    Start,
    End,
}

/// Failures of [`GatewayClient::call`]. The texts are the TS ones: callers match on them
/// (`is_restart_window`) and so do the console's tests.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway not connected")]
    NotConnected,
    #[error("gateway call {method} timed out")]
    Timeout { method: String },
    #[error("gateway disconnected")]
    Disconnected,
    /// An `ok: false` answer: its `error.message`, else `error.code`, else "gateway error".
    #[error("{}", remote_text(.code, .message))]
    Remote {
        code: Option<String>,
        message: Option<String>,
    },
    #[error("{0}")]
    Send(String),
}

fn remote_text(code: &Option<String>, message: &Option<String>) -> String {
    message
        .clone()
        .or_else(|| code.clone())
        .unwrap_or_else(|| "gateway error".into())
}

#[derive(Serialize)]
struct ReqFrame<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    id: &'a str,
    method: &'a str,
    params: &'a Value,
}

#[derive(Deserialize)]
struct InFrame {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    payload: Option<Value>,
    #[serde(default)]
    error: Option<RemoteError>,
    #[serde(default)]
    event: Option<String>,
}

#[derive(Deserialize)]
struct RemoteError {
    #[serde(default)]
    code: Option<Value>,
    #[serde(default)]
    message: Option<Value>,
}

type Pending = HashMap<String, oneshot::Sender<Result<Value, GatewayError>>>;
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

struct Inner {
    opts: GatewayOptions,
    seq: AtomicU64,
    pending: Mutex<Pending>,
    /// Frames to write; Some while a socket is open (calls may go out before the handshake ends,
    /// as with the TS, whose `call` only needs the socket to be open).
    out: Mutex<Option<mpsc::UnboundedSender<Message>>>,
    connected: watch::Sender<bool>,
    events: broadcast::Sender<GatewayEvent>,
    config_writes: broadcast::Sender<ConfigWritePhase>,
    stopped: AtomicBool,
    running: AtomicBool,
    /// `true` once stopped. A watch keeps its value, so a stop sent while nothing is waiting on it
    /// is still seen by the next wait (a `Notify` would drop it).
    stop: watch::Sender<bool>,
}

/// A persistent connection to the gateway that reconnects by itself. Cheap to clone.
#[derive(Clone)]
pub struct GatewayClient {
    inner: Arc<Inner>,
}

impl GatewayClient {
    pub fn new(opts: GatewayOptions) -> Self {
        let (connected, _) = watch::channel(false);
        let (events, _) = broadcast::channel(256);
        let (config_writes, _) = broadcast::channel(64);
        Self {
            inner: Arc::new(Inner {
                opts,
                seq: AtomicU64::new(0),
                pending: Mutex::new(HashMap::new()),
                out: Mutex::new(None),
                connected,
                events,
                config_writes,
                stopped: AtomicBool::new(false),
                running: AtomicBool::new(false),
                stop: watch::channel(false).0,
            }),
        }
    }

    /// Start connecting in the background (needs a tokio runtime). A second call does nothing.
    pub fn start(&self) {
        self.inner.stopped.store(false, Ordering::SeqCst);
        self.inner.stop.send_replace(false);
        if self.inner.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            this.run().await;
            this.inner.running.store(false, Ordering::SeqCst);
        });
    }

    /// Close the socket and stop reconnecting.
    pub fn stop(&self) {
        self.inner.stopped.store(true, Ordering::SeqCst);
        self.inner.stop.send_replace(true);
    }

    /// Whether the handshake is done on the current socket.
    pub fn connected(&self) -> bool {
        *self.inner.connected.borrow()
    }

    /// Changes of [`Self::connected`]: covers the TS `onConnected` and `onDisconnected`.
    pub fn connection_state(&self) -> watch::Receiver<bool> {
        self.inner.connected.subscribe()
    }

    /// True once connected (at once if already), false after `timeout`.
    pub async fn when_connected(&self, timeout: Duration) -> bool {
        let mut rx = self.connection_state();
        tokio::time::timeout(timeout, rx.wait_for(|c| *c))
            .await
            .is_ok_and(|r| r.is_ok())
    }

    /// Every gateway event. A slow receiver loses the oldest (broadcast lag), it does not stall the socket.
    pub fn events(&self) -> broadcast::Receiver<GatewayEvent> {
        self.inner.events.subscribe()
    }

    /// Start and end of every config write sent through [`Self::call`].
    pub fn config_writes(&self) -> broadcast::Receiver<ConfigWritePhase> {
        self.inner.config_writes.subscribe()
    }

    /// One request and its answer's `payload` (Null when the answer has none).
    pub async fn call(&self, method: &str, params: Value, timeout: Duration) -> Result<Value, GatewayError> {
        if !CONFIG_WRITE_METHODS.contains(&method) {
            return self.send(method, &params, timeout).await;
        }
        // Sent only to subscribers; nobody listening is fine.
        let _ = self.inner.config_writes.send(ConfigWritePhase::Start);
        let result = self.send(method, &params, timeout).await;
        let _ = self.inner.config_writes.send(ConfigWritePhase::End);
        result
    }

    async fn send(&self, method: &str, params: &Value, timeout: Duration) -> Result<Value, GatewayError> {
        let sender = lock(&self.inner.out).clone().ok_or(GatewayError::NotConnected)?;
        let id = (self.inner.seq.fetch_add(1, Ordering::SeqCst) + 1).to_string();
        let frame = serde_json::to_string(&ReqFrame {
            kind: "req",
            id: &id,
            method,
            params,
        })
        .map_err(|e| GatewayError::Send(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        lock(&self.inner.pending).insert(id.clone(), tx);
        if sender.send(Message::text(frame)).is_err() {
            lock(&self.inner.pending).remove(&id);
            return Err(GatewayError::Disconnected);
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            // The sender was dropped without an answer: the socket went away.
            Ok(Err(_)) => Err(GatewayError::Disconnected),
            Err(_) => {
                lock(&self.inner.pending).remove(&id);
                Err(GatewayError::Timeout {
                    method: method.to_string(),
                })
            }
        }
    }

    /// Resolves once [`Self::stop`] has been called, also if that was before this wait began.
    async fn stopping(&self) {
        let mut rx = self.inner.stop.subscribe();
        let _ = rx.wait_for(|stopped| *stopped).await;
    }

    async fn run(&self) {
        let opts = &self.inner.opts;
        let mut backoff = opts.min_backoff;
        let mut outage_logged = false;
        while !self.inner.stopped.load(Ordering::SeqCst) {
            let handshook = self.session().await;
            if handshook {
                backoff = opts.min_backoff;
                outage_logged = false;
            }
            if self.inner.stopped.load(Ordering::SeqCst) {
                break;
            }
            if !outage_logged {
                let reason = if handshook {
                    "connection closed"
                } else {
                    "gateway unreachable"
                };
                tracing::info!("[gateway] down ({reason}); retrying in the background");
                outage_logged = true;
            }
            let delay = backoff;
            backoff = (backoff * 2).min(opts.max_backoff);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.stopping() => break,
            }
        }
    }

    /// One socket from open to close. True if its handshake succeeded.
    async fn session(&self) -> bool {
        let opts = &self.inner.opts;
        let deadline = tokio::time::Instant::now() + opts.connect_timeout;
        let ws: Socket = tokio::select! {
            r = tokio::time::timeout_at(deadline, tokio_tungstenite::connect_async(opts.url.as_str())) => match r {
                Ok(Ok((ws, _))) => ws,
                _ => return false,
            },
            _ = self.stopping() => return false,
        };
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        *lock(&self.inner.out) = Some(tx);
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if sink.send(m).await.is_err() {
                    break;
                }
            }
            let _ = sink.close().await;
        });

        let hello = json!({
            "minProtocol": PROTOCOL,
            "maxProtocol": PROTOCOL,
            "client": { "id": "gateway-client", "version": "controlclaw-vm-agent", "platform": "linux", "mode": "backend" },
            "role": "operator",
            "scopes": opts.scopes,
            "caps": ["approvals", "exec-approvals"],
            "auth": { "token": opts.token },
        });
        let this = self.clone();
        let timeout = opts.connect_timeout;
        let mut handshake = tokio::spawn(async move { this.send("connect", &hello, timeout).await });
        let mut handshook = false;
        let mut waiting = true;

        loop {
            tokio::select! {
                r = &mut handshake, if waiting => {
                    waiting = false;
                    match r {
                        Ok(Ok(_)) => {
                            handshook = true;
                            self.inner.connected.send_replace(true);
                            tracing::info!("[gateway] connected");
                        }
                        Ok(Err(e)) => {
                            tracing::info!("[gateway] handshake failed: {e}");
                            break;
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep_until(deadline), if !handshook => break,
                _ = self.stopping() => break,
                frame = stream.next() => match frame {
                    Some(Ok(Message::Text(text))) => self.dispatch(text.as_str()),
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(_)) => {}
                },
            }
        }

        handshake.abort();
        self.inner.connected.send_replace(false);
        // Dropping the sender ends the writer, which closes the socket.
        *lock(&self.inner.out) = None;
        let pending: Vec<_> = lock(&self.inner.pending).drain().collect();
        for (_, p) in pending {
            let _ = p.send(Err(GatewayError::Disconnected));
        }
        let _ = writer.await;
        handshook
    }

    fn dispatch(&self, text: &str) {
        // Frames that are not JSON are ignored, as in the TS.
        let Ok(frame) = serde_json::from_str::<InFrame>(text) else {
            return;
        };
        match frame.kind.as_str() {
            "res" => {
                let Some(id) = frame.id else { return };
                let Some(p) = lock(&self.inner.pending).remove(&id) else {
                    return;
                };
                let result = if frame.ok == Some(true) {
                    Ok(frame.payload.unwrap_or(Value::Null))
                } else {
                    let e = frame.error.unwrap_or(RemoteError {
                        code: None,
                        message: None,
                    });
                    Err(GatewayError::Remote {
                        code: text_of(e.code),
                        message: text_of(e.message),
                    })
                };
                let _ = p.send(result);
            }
            "event" => {
                let Some(event) = frame.event else { return };
                let _ = self.inner.events.send(GatewayEvent {
                    event,
                    payload: frame.payload.unwrap_or(Value::Null),
                });
            }
            _ => {}
        }
    }
}

/// `error.message ?? error.code`: a non-empty string only, the way the TS `??` treats a missing field.
fn text_of(v: Option<Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panic while holding one of these maps leaves plain data behind; keep going with it.
    m.lock().unwrap_or_else(|e| e.into_inner())
}
