//! Meet's captions for a whole Bidi meeting, with speaker names (`meeting-captions.ts`,
//! docs/plans/meet-wake-improvements.md, 1).
//!
//! The tap attaches to the guest browser's loopback debugger and runs its own observer in the Meet
//! page (`CAPTION_SCRIPT`, JavaScript carried unchanged from the TS in `page_scripts.json`). Rows
//! reach the vm-agent through a CDP binding. The tap only reads: it sends no Input or navigation
//! commands, so OpenClaw's own control of the page is unaffected.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::cdp::{Cdp, debugger_json};

const BINDING: &str = "__ccCap";
const MAX_TEXT: usize = 20_000;

use super::js::{head16, safe_int, tail16};
pub use super::scripts::{caption as caption_script, mic as mic_script};

/// One row from the page's observer.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptionEvent {
    pub seq: i64,
    pub id: String,
    pub rev: i64,
    pub speaker: String,
    pub own: bool,
    pub text: String,
    pub is_final: bool,
    pub at: f64,
}

static ROW_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]{1,10}-b[0-9]{1,9}\.[0-9]{1,6}$").expect("regex"));

/// Valid rows from the page (untrusted): at most 500, typed, oldest first (`parseCaptionEvents`).
pub fn parse_caption_events(raw: &Value) -> Vec<CaptionEvent> {
    let Some(list) = raw.as_array() else { return Vec::new() };
    let mut out = Vec::new();
    for e in list.iter().take(500) {
        let (Some(seq), Some(rev)) = (safe_int(e.get("seq")), safe_int(e.get("rev"))) else {
            continue;
        };
        let Some(id) = e.get("id").and_then(Value::as_str).filter(|i| ROW_ID.is_match(i)) else {
            continue;
        };
        let Some(text) = e.get("text").and_then(Value::as_str).filter(|t| !t.trim().is_empty()) else {
            continue;
        };
        let Some(speaker) = e.get("speaker").and_then(Value::as_str) else {
            continue;
        };
        let Some(at) = e.get("at").and_then(Value::as_f64).filter(|f| f.is_finite()) else {
            continue;
        };
        out.push(CaptionEvent {
            seq,
            id: id.into(),
            rev,
            speaker: head16(speaker, 80),
            own: e.get("self") == Some(&json!(true)),
            text: tail16(text, MAX_TEXT),
            is_final: e.get("final") == Some(&json!(true)),
            at,
        });
    }
    out.sort_by_key(|e| e.seq);
    out
}

pub type OnCaptions = Arc<dyn Fn(Vec<CaptionEvent>) + Send + Sync>;

#[derive(Default)]
struct TapState {
    cdp: Option<Arc<Cdp>>,
    /// The newest row seen from each page document, in the order the documents appeared.
    last: Vec<(String, i64)>,
    closed: bool,
}

/// The caption tap on one meeting's Meet tab (`CaptionTap`).
pub struct CaptionTap {
    /// The Meet page this meeting is on (origin + path).
    url: String,
    cdp_base: String,
    on_captions: OnCaptions,
    state: Mutex<TapState>,
}

static PAGE_SOCKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^ws://127\.0\.0\.1:[0-9]+/devtools/page/").expect("regex"));

impl CaptionTap {
    pub fn new(url: &str, on_captions: OnCaptions) -> Arc<Self> {
        Self::with_debugger(url, on_captions, "http://127.0.0.1:9223")
    }

    pub fn with_debugger(url: &str, on_captions: OnCaptions, cdp_base: &str) -> Arc<Self> {
        Arc::new(Self {
            url: url.into(),
            cdp_base: cdp_base.into(),
            on_captions,
            state: Mutex::default(),
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, TapState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Connected to the Meet tab now (a dropped connection needs `attach` again).
    pub fn attached(&self) -> bool {
        self.state().cdp.as_ref().is_some_and(|c| c.open())
    }

    fn origin(&self) -> String {
        url::Url::parse(&self.url)
            .map(|u| u.origin().ascii_serialization())
            .unwrap_or_default()
    }

    /// Attach to the Meet tab; false when there is none yet (the caller retries on its next poll).
    pub async fn attach(self: &Arc<Self>) -> Result<bool, String> {
        {
            let st = self.state();
            if st.closed {
                return Ok(false);
            }
            if st.cdp.as_ref().is_some_and(|c| c.open()) {
                return Ok(true);
            }
        }
        let targets = debugger_json(&self.cdp_base, "/json/list").await?;
        let page = targets.as_array().into_iter().flatten().find(|t| {
            let (Some(ty), Some(u), Some(_)) = (
                t.get("type").and_then(Value::as_str),
                t.get("url").and_then(Value::as_str),
                t.get("webSocketDebuggerUrl").and_then(Value::as_str),
            ) else {
                return false;
            };
            ty == "page" && super::policy::is_meet_page(u, &self.url)
        });
        // Only the loopback debugger of the guest browser.
        let Some(socket) = page
            .and_then(|p| p.get("webSocketDebuggerUrl"))
            .and_then(Value::as_str)
            .filter(|s| PAGE_SOCKET.is_match(s))
        else {
            return Ok(false);
        };
        let (cdp, events) = Cdp::connect(socket).await.map_err(|e| {
            if e == "timed out" {
                "Caption tap timed out".to_string()
            } else {
                "Caption tap failed".to_string()
            }
        })?;
        let cdp = Arc::new(cdp);
        {
            let mut st = self.state();
            if st.closed {
                cdp.close();
                return Ok(false);
            }
            st.cdp = Some(cdp.clone());
        }
        self.listen(cdp.clone(), events);
        cdp.call("Runtime.enable", json!({}), None).await;
        cdp.call("Runtime.addBinding", json!({"name": BINDING}), None).await;
        cdp.call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({"source": caption_script()}),
            None,
        )
        .await;
        cdp.call("Runtime.evaluate", json!({"expression": caption_script()}), None)
            .await;
        // What the page holds that has not arrived here (rows sent while the connection was down).
        self.pull("since").await;
        Ok(true)
    }

    fn listen(self: &Arc<Self>, cdp: Arc<Cdp>, mut events: mpsc::UnboundedReceiver<Value>) {
        let me = self.clone();
        let origin = self.origin();
        tokio::spawn(async move {
            while let Some(msg) = events.recv().await {
                let method = msg.get("method").and_then(Value::as_str);
                let params = msg.get("params");
                if method == Some("Runtime.bindingCalled")
                    && params.and_then(|p| p.get("name")).and_then(Value::as_str) == Some(BINDING)
                    && let Some(payload) = params.and_then(|p| p.get("payload")).and_then(Value::as_str)
                {
                    me.deliver(payload);
                }
                // A new document in the Meet tab: run the observer there too (it ignores a page
                // that already has it).
                let context = params.and_then(|p| p.get("context"));
                if method == Some("Runtime.executionContextCreated")
                    && context.and_then(|c| c.pointer("/auxData/isDefault")) == Some(&json!(true))
                    && context.and_then(|c| c.get("origin")).and_then(Value::as_str) == Some(origin.as_str())
                    && let Some(id) = context.and_then(|c| c.get("id")).and_then(Value::as_i64)
                {
                    cdp.send(
                        "Runtime.evaluate",
                        json!({"expression": caption_script(), "contextId": id}),
                        None,
                    );
                }
            }
            // The connection dropped: no longer attached, so the next poll attaches again.
            let mut st = me.state();
            if st.cdp.as_ref().is_some_and(|c| Arc::ptr_eq(c, &cdp)) {
                st.cdp = None;
            }
        });
    }

    /// Everything still open on the page, as final rows (the meeting is ending).
    pub async fn flush(&self) {
        if self.attached() {
            self.pull("flush").await;
        }
    }

    pub fn close(&self) {
        let mut st = self.state();
        st.closed = true;
        if let Some(c) = st.cdp.take() {
            c.close();
        }
    }

    /// Rows the page holds after the last one seen from its current document.
    async fn pull(&self, f: &str) {
        let (cdp, seen) = {
            let st = self.state();
            let mut m = serde_json::Map::new();
            for (doc, n) in &st.last {
                m.insert(doc.clone(), json!(n));
            }
            (st.cdp.clone(), Value::Object(m).to_string())
        };
        let Some(cdp) = cdp else { return };
        let expression = format!(
            r#"window.__ccCaps ? JSON.stringify(window.__ccCaps.{f}(({seen})[window.__ccCaps.doc] ?? 0)) : "[]""#
        );
        let result = cdp
            .call(
                "Runtime.evaluate",
                json!({"expression": expression, "returnByValue": true}),
                None,
            )
            .await;
        if let Some(value) = result
            .as_ref()
            .and_then(|r| r.pointer("/result/value"))
            .and_then(Value::as_str)
        {
            self.deliver(value);
        }
    }

    fn deliver(&self, payload: &str) {
        let Ok(raw) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let events: Vec<CaptionEvent> = {
            let mut st = self.state();
            parse_caption_events(&raw)
                .into_iter()
                .filter(|e| {
                    let doc = e.id.split('-').next().unwrap_or_default().to_string();
                    match st.last.iter_mut().find(|(d, _)| *d == doc) {
                        Some((_, last)) if e.seq <= *last => false,
                        Some((_, last)) => {
                            *last = e.seq;
                            true
                        }
                        None => {
                            st.last.push((doc, e.seq));
                            true
                        }
                    }
                })
                .collect()
        };
        if !events.is_empty() {
            (self.on_captions)(events);
        }
    }
}

/// A caption line as the voice adapter reads it.
pub type Line = (String, String, String);

fn line_json(l: &Line) -> Value {
    json!({"at": l.0, "speaker": l.1, "text": l.2})
}

/// The captions for the voice adapter, next to its `meeting.jsonl` (`CaptionContext`):
/// `captions.jsonl` (final lines, appended) and `captions-live.json` (the blocks Meet is still
/// writing). The agent's own captioned speech is left out; its words are in `meeting.jsonl`.
pub struct CaptionContext {
    pub dir: PathBuf,
    live: Mutex<Vec<(String, Line)>>,
}

impl CaptionContext {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
            live: Mutex::default(),
        }
    }

    fn file(&self) -> PathBuf {
        self.dir.join("captions.jsonl")
    }

    fn live_file(&self) -> PathBuf {
        self.dir.join("captions-live.json")
    }

    pub fn start(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        cc_store::write_file(&self.file(), b"", 0o600)?;
        self.live.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.write_live();
        Ok(())
    }

    /// Rows from the caption observer, as they come.
    pub fn rows(&self, events: &[CaptionEvent]) {
        let mut done: Vec<Line> = Vec::new();
        {
            let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            for e in events.iter().filter(|e| !e.own) {
                let speaker = if e.speaker.is_empty() {
                    "Unknown speaker".to_string()
                } else {
                    e.speaker.clone()
                };
                let row = (crate::platform::time::iso_ms(e.at as i64), speaker, e.text.clone());
                if e.is_final {
                    live.retain(|(id, _)| *id != e.id);
                    done.push(row);
                } else if let Some(slot) = live.iter_mut().find(|(id, _)| *id == e.id) {
                    slot.1 = row;
                } else {
                    live.push((e.id.clone(), row));
                }
            }
        }
        self.add(&done);
        self.write_live();
    }

    /// Final lines, appended; the context is optional, so a failed write is ignored.
    pub fn add(&self, lines: &[Line]) {
        if lines.is_empty() {
            return;
        }
        let text: String = lines.iter().map(|l| line_json(l).to_string() + "\n").collect();
        let _ = append(&self.file(), text.as_bytes());
    }

    fn write_live(&self) {
        let rows: Vec<Value> = {
            let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
            live.iter()
                .skip(live.len().saturating_sub(20))
                .map(|(_, l)| line_json(l))
                .collect()
        };
        let value = json!({"at": crate::platform::time::now_iso(), "rows": rows});
        let _ = cc_store::write_json_atomic(&self.live_file(), &value, 0o600, cc_store::TmpName::Suffix);
    }

    pub fn end(&self) {
        self.live.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let _ = std::fs::remove_file(self.file());
        let _ = std::fs::remove_file(self.live_file());
    }
}

fn append(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}

#[cfg(test)]
mod tests;
