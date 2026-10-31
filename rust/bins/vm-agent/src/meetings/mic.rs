//! The voice meeting browser's microphone settings (`meeting-mic.ts`, T-meettone).
//!
//! The guest browser's microphone in a voice meeting is the agent itself: a virtual source that
//! carries only what the voice adapter plays. Chrome's echo cancellation, noise suppression and
//! automatic gain pull the listening chimes down there, so every page and frame of the meeting
//! browser gets `MIC_SCRIPT` (JavaScript carried unchanged from the TS) before it runs: the browser
//! pauses each new target until the script is registered on it, then resumes it.

use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use regex::Regex;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::captions::mic_script;
use super::cdp::{Cdp, debugger_json};

static BROWSER_SOCKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^ws://127\.0\.0\.1:[0-9]+/devtools/browser/").expect("regex"));

#[derive(Default)]
struct State {
    cdp: Option<Arc<Cdp>>,
    closed: bool,
}

/// One browser-level debugger session for the meeting browser's lifetime (`MeetingMic`).
pub struct MeetingMic {
    cdp_base: String,
    /// Wait before connecting again after the debugger connection drops.
    retry: Duration,
    state: Mutex<State>,
    /// One start at a time: a second caller waits and then finds the connection open.
    starting: tokio::sync::Mutex<()>,
}

impl MeetingMic {
    pub fn new() -> Arc<Self> {
        Self::with("http://127.0.0.1:9223", Duration::from_secs(1))
    }

    pub fn with(cdp_base: &str, retry: Duration) -> Arc<Self> {
        Arc::new(Self {
            cdp_base: cdp_base.into(),
            retry,
            state: Mutex::default(),
            starting: tokio::sync::Mutex::new(()),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn connected(&self) -> bool {
        self.state().cdp.as_ref().is_some_and(|c| c.open())
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        let _one = self.starting.lock().await;
        {
            let st = self.state();
            if st.closed || st.cdp.as_ref().is_some_and(|c| c.open()) {
                return Ok(());
            }
        }
        let version = debugger_json(&self.cdp_base, "/json/version").await?;
        // Only the loopback debugger of the guest browser.
        let Some(url) = version
            .get("webSocketDebuggerUrl")
            .and_then(Value::as_str)
            .filter(|u| BROWSER_SOCKET.is_match(u))
        else {
            return Err("Meeting browser debugger not found".into());
        };
        let (cdp, events) = Cdp::connect(url).await.map_err(|e| {
            if e == "timed out" {
                "Meeting browser debugger timed out".to_string()
            } else {
                "Meeting browser debugger failed".to_string()
            }
        })?;
        let cdp = Arc::new(cdp);
        {
            let mut st = self.state();
            if st.closed {
                cdp.close();
                return Ok(());
            }
            st.cdp = Some(cdp.clone());
        }
        self.listen(cdp.clone(), events);
        // Pages already open are attached now; new ones are paused until set up. Once Chrome has
        // answered, no page can start without the script.
        // An error reply is an answer too, as in the TS.
        let answered = cdp
            .answer(
                "Target.setAutoAttach",
                json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}),
                None,
                Some(Duration::from_secs(5)),
            )
            .await;
        if answered.is_none() {
            // The TS closes the socket on this timeout; the next start connects afresh.
            let mut st = self.state();
            if st.cdp.as_ref().is_some_and(|c| Arc::ptr_eq(c, &cdp)) {
                st.cdp = None;
            }
            cdp.close();
            return Err("Meeting browser debugger did not answer".into());
        }
        Ok(())
    }

    fn listen(self: &Arc<Self>, cdp: Arc<Cdp>, mut events: mpsc::UnboundedReceiver<Value>) {
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(msg) = events.recv().await {
                if msg.get("method").and_then(Value::as_str) != Some("Target.attachedToTarget") {
                    continue;
                }
                let Some(session) = msg
                    .pointer("/params/sessionId")
                    .and_then(Value::as_str)
                    .map(String::from)
                else {
                    continue;
                };
                let kind = msg
                    .pointer("/params/targetInfo/type")
                    .and_then(Value::as_str)
                    .map(String::from);
                let cdp = cdp.clone();
                tokio::spawn(async move {
                    // Its own frames and workers are paused the same way, and resumed once set up.
                    let resume = |cdp: &Cdp| {
                        cdp.send(
                            "Target.setAutoAttach",
                            json!({"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}),
                            Some(&session),
                        );
                        cdp.send("Runtime.runIfWaitingForDebugger", json!({}), Some(&session));
                    };
                    if !matches!(kind.as_deref(), Some("page" | "iframe")) {
                        return resume(&cdp);
                    }
                    // Resumed only once Chrome has the script: sent in one go, a page sometimes ran
                    // before it.
                    cdp.send("Page.enable", json!({}), Some(&session));
                    // Any answer, a result or an error, resumes it; the TS has no time limit here
                    // and neither has this (the wait ends when the connection does).
                    let answer = cdp
                        .answer(
                            "Page.addScriptToEvaluateOnNewDocument",
                            json!({"source": mic_script(), "runImmediately": true}),
                            Some(&session),
                            None,
                        )
                        .await;
                    if answer.is_some() {
                        resume(&cdp);
                    }
                });
            }
            // The connection dropped: open it again while the browser runs.
            let reconnect = {
                let mut st = me.state();
                let ours = st.cdp.as_ref().is_some_and(|c| Arc::ptr_eq(c, &cdp));
                if ours {
                    st.cdp = None;
                }
                ours && !st.closed
            };
            if reconnect {
                tracing::warn!("[meetings] microphone settings: debugger connection dropped, connecting again");
                tokio::time::sleep(me.retry).await;
                let _ = Box::pin(me.start()).await;
            }
        });
    }

    pub fn close(&self) {
        let mut st = self.state();
        st.closed = true;
        if let Some(c) = st.cdp.take() {
            c.close();
        }
    }
}

#[cfg(test)]
mod tests;
