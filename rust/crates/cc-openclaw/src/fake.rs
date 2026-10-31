//! A scripted OpenClaw gateway for tests and the conformance rig.
//!
//! It speaks the handshake the client sends (a `connect` request first, checked for the token and
//! the protocol range) and answers other requests from handlers set with [`FakeGateway::on`]. Every
//! request frame it receives is kept, so a test can check exactly what was sent.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_tungstenite::tungstenite::Message;

use crate::PROTOCOL;

/// What a scripted method answers.
#[derive(Debug, Clone)]
pub enum FakeReply {
    Ok(Value),
    Err {
        code: Option<String>,
        message: Option<String>,
    },
    /// Never answers: for timeouts.
    Silent,
}

type Handler = Arc<dyn Fn(&Value) -> FakeReply + Send + Sync>;

struct State {
    token: String,
    handlers: Mutex<HashMap<String, Handler>>,
    received: Mutex<Vec<Value>>,
    conns: Mutex<Vec<mpsc::UnboundedSender<Message>>>,
    handshakes: AtomicUsize,
    kick: Notify,
}

pub struct FakeGateway {
    addr: SocketAddr,
    state: Arc<State>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeGateway {
    /// Listen on a free loopback port.
    pub async fn start(token: &str) -> std::io::Result<Self> {
        Self::start_on("127.0.0.1:0".parse().map_err(std::io::Error::other)?, token).await
    }

    pub async fn start_on(addr: SocketAddr, token: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(State {
            token: token.to_string(),
            handlers: Mutex::new(HashMap::new()),
            received: Mutex::new(Vec::new()),
            conns: Mutex::new(Vec::new()),
            handshakes: AtomicUsize::new(0),
            kick: Notify::new(),
        });
        let s = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let s = s.clone();
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(tcp).await {
                        serve(s, ws).await;
                    }
                });
            }
        });
        Ok(Self { addr, state, task })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }

    /// Answer `method` with whatever `f` returns for the request's params.
    pub fn on(&self, method: &str, f: impl Fn(&Value) -> FakeReply + Send + Sync + 'static) {
        lock(&self.state.handlers).insert(method.to_string(), Arc::new(f));
    }

    /// Answer `method` with this payload every time.
    pub fn reply(&self, method: &str, payload: Value) {
        self.on(method, move |_| FakeReply::Ok(payload.clone()));
    }

    /// Broadcast an event to every connection that has done the handshake.
    pub fn emit(&self, event: &str, payload: Value) {
        let frame = json!({ "type": "event", "event": event, "payload": payload }).to_string();
        lock(&self.state.conns).retain(|c| c.send(Message::text(frame.clone())).is_ok());
    }

    /// Every request frame received, the `connect` ones included, in order.
    pub fn received(&self) -> Vec<Value> {
        lock(&self.state.received).clone()
    }

    /// The params of every request for `method`.
    pub fn calls(&self, method: &str) -> Vec<Value> {
        self.received()
            .into_iter()
            .filter(|f| f["method"] == method)
            .map(|f| f["params"].clone())
            .collect()
    }

    /// How many handshakes were accepted.
    pub fn handshakes(&self) -> usize {
        self.state.handshakes.load(Ordering::SeqCst)
    }

    /// Close every open connection, as a gateway restart does.
    pub fn drop_connections(&self) {
        lock(&self.state.conns).clear();
        self.state.kick.notify_waiters();
    }
}

impl Drop for FakeGateway {
    fn drop(&mut self) {
        self.task.abort();
        self.drop_connections();
    }
}

async fn serve(state: Arc<State>, ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
    let (mut sink, mut stream) = ws.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let writer = tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            if sink.send(m).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let mut hello_done = false;
    loop {
        let msg = tokio::select! {
            m = stream.next() => m,
            _ = state.kick.notified() => break,
        };
        let text = match msg {
            Some(Ok(Message::Text(t))) => t.to_string(),
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            Some(Ok(_)) => continue,
        };
        let Ok(frame) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if frame["type"] != "req" {
            continue;
        }
        lock(&state.received).push(frame.clone());
        let id = frame["id"].clone();
        let method = frame["method"].as_str().unwrap_or_default().to_string();
        let params = frame.get("params").cloned().unwrap_or(Value::Null);
        if !hello_done {
            match check_hello(&state, &method, &params) {
                Ok(payload) => {
                    hello_done = true;
                    let _ = tx.send(Message::text(
                        json!({ "type": "res", "id": id, "ok": true, "payload": payload }).to_string(),
                    ));
                    lock(&state.conns).push(tx.clone());
                    state.handshakes.fetch_add(1, Ordering::SeqCst);
                }
                Err(message) => {
                    let _ = tx.send(Message::text(
                        json!({ "type": "res", "id": id, "ok": false, "error": { "code": "unauthorized", "message": message } })
                            .to_string(),
                    ));
                    break;
                }
            }
            continue;
        }
        let handler = lock(&state.handlers).get(&method).cloned();
        let reply = match handler {
            Some(h) => h(&params),
            None => FakeReply::Err {
                code: Some("unknown_method".into()),
                message: Some(format!("unknown method: {method}")),
            },
        };
        let out = match reply {
            FakeReply::Ok(payload) => json!({ "type": "res", "id": id, "ok": true, "payload": payload }),
            FakeReply::Err { code, message } => {
                let mut error = serde_json::Map::new();
                if let Some(c) = code {
                    error.insert("code".into(), c.into());
                }
                if let Some(m) = message {
                    error.insert("message".into(), m.into());
                }
                json!({ "type": "res", "id": id, "ok": false, "error": error })
            }
            FakeReply::Silent => continue,
        };
        let _ = tx.send(Message::text(out.to_string()));
    }
    lock(&state.conns).retain(|c| !c.same_channel(&tx));
    drop(tx);
    let _ = writer.await;
}

/// The first request must be `connect` with this gateway's token and a protocol range holding 4.
fn check_hello(state: &State, method: &str, params: &Value) -> Result<Value, String> {
    if method != "connect" {
        return Err("handshake required".into());
    }
    if params["auth"]["token"].as_str() != Some(state.token.as_str()) {
        return Err("unauthorized: gateway token mismatch".into());
    }
    let p = u64::from(PROTOCOL);
    let (min, max) = (
        params["minProtocol"].as_u64().unwrap_or(0),
        params["maxProtocol"].as_u64().unwrap_or(0),
    );
    if min > p || max < p {
        return Err("protocol mismatch".into());
    }
    Ok(json!({ "type": "hello-ok", "protocol": PROTOCOL, "auth": { "scopes": params["scopes"].clone() } }))
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
