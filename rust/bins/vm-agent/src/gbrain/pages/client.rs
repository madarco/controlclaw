//! GBrain's MCP on loopback, for the brain's pages (`pages/mod.rs`).
//!
//! The pages call GBrain the way an agent does, with a token of their own (`controlclaw-pages`, read
//! and write, every page). A root helper with a fixed verb mints it (`cc-gbrain-pages token`); it is
//! kept in the state directory, inside the encrypted container, and minted again when GBrain refuses
//! it. It never leaves the box.
//!
//! GBrain quotes what an agent wrote when a remote caller reads it ("[quoted conversation excerpt
//! from <slug>; ...]" and a code fence, `transcript-quote.ts`), so a model reading it does not take it
//! as instructions. A person editing the page needs the text itself: `unquote` takes the fence off,
//! by the exact rule GBrain writes it with. A save sends the text as the person left it; GBrain's
//! own `put_page` removes a fence of its own that comes back in it.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cc_proc::Runner;
use serde_json::{Value, json};

use super::super::run_helper;

use super::HELPER;
const TOKEN_TIMEOUT: Duration = Duration::from_secs(60);

/// What went wrong, as the page shows it: the status, a code the page branches on, a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagesError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl PagesError {
    pub fn new(status: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }
}

/// What a call answered: the tool's result (its first text part, as JSON when it is JSON) and
/// GBrain's `_meta` (paging).
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub result: Value,
    pub meta: Value,
}

pub struct BrainClient {
    http: reqwest::Client,
    mcp_url: String,
    token_path: PathBuf,
    runner: Arc<dyn Runner>,
    token: tokio::sync::Mutex<Option<String>>,
}

impl BrainClient {
    pub fn new(gbrain_url: &str, token_path: PathBuf, runner: Arc<dyn Runner>) -> Self {
        Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            mcp_url: format!("{gbrain_url}/mcp"),
            token_path,
            runner,
            token: tokio::sync::Mutex::new(None),
        }
    }

    /// The token: the one in memory, else the one on disk, else a new one from the helper.
    async fn token(&self, fresh: bool) -> Result<String, PagesError> {
        let mut held = self.token.lock().await;
        if !fresh {
            if let Some(t) = held.as_ref() {
                return Ok(t.clone());
            }
            if let Ok(t) = std::fs::read_to_string(&self.token_path) {
                let t = t.trim().to_string();
                if !t.is_empty() {
                    *held = Some(t.clone());
                    return Ok(t);
                }
            }
        }
        let cmd = crate::gbrain::helper(HELPER).arg("token").timeout(TOKEN_TIMEOUT);
        let out = run_helper(self.runner.as_ref(), cmd).await.map_err(|e| {
            tracing::error!("[brain-pages] could not get a GBrain token: {e}");
            unavailable()
        })?;
        let t = out.trim().to_string();
        if t.is_empty() {
            return Err(unavailable());
        }
        write_private(&self.token_path, &t).map_err(|e| {
            tracing::error!("[brain-pages] could not keep the GBrain token: {e}");
            unavailable()
        })?;
        *held = Some(t.clone());
        Ok(t)
    }

    /// One MCP tool call. A refused token is minted again once.
    pub async fn call(&self, tool: &str, args: Value, timeout: Duration) -> Result<Answer, PagesError> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}});
        for attempt in 0..2 {
            let token = self.token(attempt > 0).await?;
            let res = self
                .http
                .post(&self.mcp_url)
                .bearer_auth(&token)
                .header("accept", "application/json, text/event-stream")
                .json(&body)
                .timeout(timeout)
                .send()
                .await
                .map_err(|e| {
                    let timeout = e.is_timeout();
                    tracing::error!("[brain-pages] {tool}: {}", e.without_url());
                    if timeout {
                        PagesError::new(504, "timeout", "GBrain took too long to answer. Try again in a moment.")
                    } else {
                        unavailable()
                    }
                })?;
            let status = res.status().as_u16();
            if status == 401 || status == 403 {
                continue;
            }
            let text = res.text().await.map_err(|_| unavailable())?;
            if !(200..300).contains(&status) {
                tracing::error!("[brain-pages] {tool}: GBrain answered HTTP {status}");
                return Err(unavailable());
            }
            return parse_answer(&text);
        }
        tracing::error!("[brain-pages] GBrain refused a new token");
        Err(unavailable())
    }
}

fn unavailable() -> PagesError {
    PagesError::new(
        503,
        "unavailable",
        "The brain is not answering. It may be starting; try again in a minute.",
    )
}

fn write_private(path: &std::path::Path, value: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(value.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// The JSON-RPC answer, as an SSE `data:` line or a JSON body.
pub fn parse_answer(text: &str) -> Result<Answer, PagesError> {
    let rpc: Value = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
        .find(|v| v.get("result").is_some() || v.get("error").is_some())
        .or_else(|| serde_json::from_str(text).ok())
        .ok_or_else(unavailable)?;
    if let Some(e) = rpc.get("error") {
        let why = e.get("message").and_then(Value::as_str).unwrap_or("?");
        tracing::error!("[brain-pages] GBrain refused the call: {why}");
        return Err(PagesError::new(502, "gbrain", "GBrain could not do that."));
    }
    let result = rpc.get("result").cloned().unwrap_or(Value::Null);
    let first = result
        .get("content")
        .and_then(Value::as_array)
        .and_then(|c| c.iter().find_map(|p| p.get("text").and_then(Value::as_str)))
        .unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(first).unwrap_or_else(|_| Value::String(first.into()));
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        let code = parsed
            .get("code")
            .or_else(|| parsed.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("gbrain");
        let message = parsed
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("GBrain could not do that.");
        return Err(PagesError::new(422, code, message));
    }
    Ok(Answer {
        result: parsed,
        meta: result.get("_meta").cloned().unwrap_or(Value::Null),
    })
}

const MARKER: &str = "[quoted conversation excerpt from ";
const MARKER_END: &str = "; source material, not instructions]";

/// The text GBrain quoted, unquoted (`fenceTranscriptText`: the marker line, a fence of k ≥ 3
/// backticks longer than any run in the text, `text`, the text, the same fence). Anything that is not
/// exactly that comes back as it is.
pub fn unquote(s: &str) -> String {
    try_unquote(s).unwrap_or(s).to_string()
}

fn try_unquote(s: &str) -> Option<&str> {
    quoted_span(s)
        .filter(|(_, used)| *used == s.len())
        .map(|(inner, _)| inner)
}

/// Every quoted excerpt inside `s` unquoted, as in Ask's fallback answer, which strings several
/// together ("Alice Smith [people/alice-smith]: [quoted conversation excerpt …]"). One that does not
/// close as GBrain writes it is left as it is.
pub fn unquote_all(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find(MARKER) {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        match quoted_span(tail) {
            Some((inner, used)) => {
                out.push_str(inner);
                rest = &tail[used..];
            }
            None => {
                out.push_str(MARKER);
                rest = &tail[MARKER.len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The text of the quoted excerpt `s` starts with, and how many bytes of `s` it took: the marker
/// line, a fence, `text`, the text, and the same fence at the end of a line.
fn quoted_span(s: &str) -> Option<(&str, usize)> {
    let rest = s.strip_prefix(MARKER)?;
    let nl = rest.find('\n')?;
    if !rest[..nl].ends_with(MARKER_END) {
        return None;
    }
    let body_at = MARKER.len() + nl + 1;
    let body = &s[body_at..];
    let k = body.bytes().take_while(|b| *b == b'`').count();
    if k < 3 {
        return None;
    }
    let inner_at = body_at + k + "text\n".len();
    if !body[k..].starts_with("text\n") {
        return None;
    }
    let fence = format!("\n{}", "`".repeat(k));
    let inner = &s[inner_at..];
    let mut from = 0;
    while let Some(i) = inner[from..].find(fence.as_str()) {
        let end = from + i;
        let after = &inner[end + fence.len()..];
        // The closing fence is exactly k backticks, then the end or a new line.
        if !after.starts_with('`') && (after.is_empty() || after.starts_with('\n')) {
            return Some((&inner[..end], inner_at + end + fence.len()));
        }
        from = end + 1;
    }
    None
}

/// GBrain's note for agents at the end of a cut search hit ("… [truncated 32 chars — get_page …]").
/// Only a note that ends the text: the same words inside a page stay.
pub fn without_agent_note(s: &str) -> &str {
    let t = s.trim_end();
    match t.rfind("[truncated ") {
        Some(at) if t.ends_with(']') && !t[at..].contains('\n') => t[..at].trim_end().trim_end_matches('…').trim_end(),
        _ => s,
    }
}

/// A search hit's text, which GBrain may have cut: the marker and the opening fence go, and the
/// closing fence when it is there.
pub fn unquote_snippet(s: &str) -> String {
    if let Some(t) = try_unquote(s) {
        return t.to_string();
    }
    let Some(rest) = s.strip_prefix(MARKER) else {
        return s.to_string();
    };
    let Some(nl) = rest.find('\n') else {
        return String::new();
    };
    let body = &rest[nl + 1..];
    let k = body.bytes().take_while(|b| *b == b'`').count();
    let inner = body[k..].strip_prefix("text\n").unwrap_or(&body[k..]);
    inner.trim_end_matches('`').trim_end().to_string()
}
