//! A Chrome DevTools Protocol connection to the meeting browser's loopback debugger (port 9223),
//! as the caption tap and the microphone settings use it: commands with ids, answers matched back,
//! events handed to the owner, and every wait bounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

/// Messages larger than this are dropped, as the TS's `data.length` check does.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
const ANSWER_WAIT: Duration = Duration::from_secs(5);

type Waiting = Arc<Mutex<HashMap<u64, oneshot::Sender<Option<Value>>>>>;

/// One open debugger connection. Dropping it, or `close`, ends it.
pub struct Cdp {
    out: mpsc::UnboundedSender<Message>,
    next: AtomicU64,
    waiting: Waiting,
    open: Arc<std::sync::atomic::AtomicBool>,
}

impl Cdp {
    /// Connect within 5 s (a debugger that takes the connection but never upgrades it must not
    /// hold anything up). Events (messages without an id) arrive on the receiver; it ends when the
    /// connection closes.
    pub async fn connect(url: &str) -> Result<(Cdp, mpsc::UnboundedReceiver<Value>), String> {
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE))
            .max_frame_size(Some(MAX_MESSAGE));
        let (ws, _) = tokio::time::timeout(
            ANSWER_WAIT,
            tokio_tungstenite::connect_async_with_config(url, Some(config), false),
        )
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|_| "failed".to_string())?;
        let (mut sink, mut stream) = ws.split();
        let (out, mut out_rx) = mpsc::unbounded_channel::<Message>();
        let (events, events_rx) = mpsc::unbounded_channel::<Value>();
        let waiting: Waiting = Arc::default();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                let close = matches!(m, Message::Close(_));
                if sink.send(m).await.is_err() || close {
                    return;
                }
            }
        });
        let (w, o) = (waiting.clone(), open.clone());
        tokio::spawn(async move {
            while let Some(Ok(m)) = stream.next().await {
                let Message::Text(text) = m else { continue };
                if text.len() > MAX_MESSAGE {
                    continue;
                }
                let Ok(msg) = serde_json::from_str::<Value>(text.as_str()) else {
                    continue;
                };
                match msg.get("id").and_then(Value::as_u64) {
                    Some(id) => {
                        if let Some(done) = w.lock().unwrap_or_else(|e| e.into_inner()).remove(&id) {
                            let _ = done.send(Some(msg));
                        }
                    }
                    None => {
                        let _ = events.send(msg);
                    }
                }
            }
            o.store(false, Ordering::SeqCst);
            // Everyone still waiting gets no answer.
            w.lock().unwrap_or_else(|e| e.into_inner()).clear();
        });
        Ok((
            Cdp {
                out,
                next: AtomicU64::new(0),
                waiting,
                open,
            },
            events_rx,
        ))
    }

    pub fn open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }

    fn frame(&self, method: &str, params: Value, session: Option<&str>) -> (u64, String) {
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        let mut m = Map::new();
        m.insert("id".into(), json!(id));
        m.insert("method".into(), json!(method));
        m.insert("params".into(), params);
        if let Some(s) = session {
            m.insert("sessionId".into(), json!(s));
        }
        (id, Value::Object(m).to_string())
    }

    /// Send without waiting for the answer.
    pub fn send(&self, method: &str, params: Value, session: Option<&str>) {
        let (_, text) = self.frame(method, params, session);
        let _ = self.out.send(Message::text(text));
    }

    /// Send and wait up to 5 s for the answer's `result`; `None` without one.
    pub async fn call(&self, method: &str, params: Value, session: Option<&str>) -> Option<Value> {
        self.answer(method, params, session, Some(ANSWER_WAIT))
            .await
            .and_then(|m| m.get("result").cloned())
    }

    /// Send and wait for any answer (a result or an error), for at most `wait` (`None`: until the
    /// connection closes). The whole answer, or `None`.
    pub async fn answer(
        &self,
        method: &str,
        params: Value,
        session: Option<&str>,
        wait: Option<Duration>,
    ) -> Option<Value> {
        let (id, text) = self.frame(method, params, session);
        let (tx, rx) = oneshot::channel();
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        if !self.open() || self.out.send(Message::text(text)).is_err() {
            self.waiting.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            return None;
        }
        let answer = match wait {
            Some(w) => tokio::time::timeout(w, rx).await.ok().and_then(Result::ok).flatten(),
            None => rx.await.ok().flatten(),
        };
        self.waiting.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        answer
    }

    pub fn close(&self) {
        self.open.store(false, Ordering::SeqCst);
        let _ = self.out.send(Message::Close(None));
    }
}

impl Drop for Cdp {
    fn drop(&mut self) {
        self.close();
    }
}

/// One client for the loopback debugger: no proxy, 3 s per call.
pub fn debugger_client() -> Option<&'static reqwest::Client> {
    static CLIENT: std::sync::LazyLock<Option<reqwest::Client>> = std::sync::LazyLock::new(|| {
        reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .ok()
    });
    CLIENT.as_ref()
}

/// `GET <base><path>` on the loopback debugger, as JSON, within 3 s; no proxy.
pub async fn debugger_json(base: &str, path: &str) -> Result<Value, String> {
    let client = debugger_client().ok_or("no client")?;
    client
        .get(format!("{base}{path}"))
        .send()
        .await
        .map_err(|e| e.without_url().to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.without_url().to_string())
}
