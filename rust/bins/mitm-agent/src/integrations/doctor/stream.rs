//! What a coding agent prints, read as its own records (`doctor-stream.ts`). Only completed
//! messages leave the firewall: streaming deltas can split a secret across events. Anything that is
//! not one JSON record a line (stderr, unstructured output) never enters the transcript.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::integrations::connectors::firewall::js_slice;
use crate::integrations::js;

const MAX_LINE: usize = 2 * 1024 * 1024;
pub const MAX_EVENT_TEXT: usize = 16_000;
pub const CHECK_CONFINED: &str =
    "Confinement checked from inside the session: no network, no provider key, none of the firewall's files.";
pub const CHECK_TOOLS_OK: &str = "Tools checked: the coding agent started with the test's one tool and no other.";
pub const CHECK_WRONG_TOOLS: &str = "This test was stopped: the coding agent did not say it started with the test's one tool and no other. Update the firewall, and tell ControlClaw if it happens again.";
pub const CHECK_UNCONFINED: &str = "This test was not started: its session could reach something it should not. Update the firewall, and tell ControlClaw if it happens again.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cli {
    Claude,
    Codex,
    Pi,
}

impl Cli {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "pi" => Some(Self::Pi),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Pi => "pi",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::Pi => "Pi",
        }
    }
}

/// One event of a transcript, as it is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// `text`, `tool_call`, `tool_result`, `status` or `user`.
    pub kind: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub kind: &'static str,
    pub text: String,
}

/// What Claude Code says it starts with: the tools offered to the model and its MCP servers.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Init {
    pub tools: Vec<String>,
    pub mcp: Vec<String>,
    pub slash: Option<Vec<String>>,
    pub skills: Option<Vec<String>>,
    pub agents: Option<Vec<String>>,
}

/// Every string a value holds, and each of its lines: what a transcript must never show.
pub fn secret_values(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => std::iter::once(s.clone())
            .chain(
                s.split('\n')
                    .map(|l| l.strip_suffix('\r').unwrap_or(l).to_string())
                    .filter(|l| !l.is_empty()),
            )
            .collect(),
        Value::Array(a) => a.iter().flat_map(secret_values).collect(),
        Value::Object(o) => o.values().flat_map(secret_values).collect(),
        _ => vec![],
    }
}

/// `split(/\r?\n/)` of a string's lines, for a secret given as text.
pub fn secret_lines(s: &str) -> Vec<String> {
    secret_values(&Value::String(s.into()))
}

/// Every exact match of a secret replaced; the text is not cut. Longest first, so a shorter one
/// does not hide part of a longer one before it is replaced.
pub fn redact_secrets<'a>(text: &str, secrets: impl IntoIterator<Item = &'a String>) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut list: Vec<&String> = secrets
        .into_iter()
        .filter(|s| !s.is_empty() && seen.insert(*s))
        .collect();
    list.sort_by_key(|s| std::cmp::Reverse(s.encode_utf16().count()));
    let mut out = text.to_string();
    for s in list {
        out = out.split(s.as_str()).collect::<Vec<_>>().join("[REDACTED]");
    }
    out
}

pub fn redact_text<'a>(text: &str, secrets: impl IntoIterator<Item = &'a String>) -> String {
    let t = redact_secrets(text, secrets);
    if t.encode_utf16().count() > MAX_EVENT_TEXT {
        format!("{}\n[output truncated]", js_slice(&t, MAX_EVENT_TEXT))
    } else {
        t
    }
}

fn stringify(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "\"\"".into(),
        other => js::stringify(other),
    }
}

/// `typeof x === "string" ? x : JSON.stringify(x ?? "")`, for a field that may be missing.
fn field_text(v: Option<&Value>) -> Option<String> {
    match v {
        None => Some("\"\"".into()),
        Some(v) => Some(stringify(v)),
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Record {
    pub events: Vec<Parsed>,
    pub resume_id: Option<String>,
    pub failed: bool,
    pub init: Option<Init>,
}

fn add(events: &mut Vec<Parsed>, kind: &'static str, v: Option<&Value>) {
    // `text !== undefined && text !== ""`.
    match v {
        None => {}
        Some(Value::String(s)) if s.is_empty() => {}
        Some(v) => events.push(Parsed {
            kind,
            text: stringify(v),
        }),
    }
}

fn names(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .map(|e| match e {
                Value::String(s) => s.clone(),
                Value::Object(o) => o.get("name").and_then(Value::as_str).unwrap_or("?").to_string(),
                _ => "?".into(),
            })
            .collect(),
        _ => vec!["?".into()],
    }
}

/// One record of a CLI's JSON output, read for what the transcript shows.
pub fn parse_record(cli: Cli, value: &Value) -> Record {
    let empty = serde_json::Map::new();
    let r = value.as_object().unwrap_or(&empty);
    let ty = r.get("type").and_then(Value::as_str);
    let mut out = Record::default();
    let ev = &mut out.events;
    match cli {
        Cli::Claude => {
            if let Some(id) = r.get("session_id").and_then(Value::as_str) {
                out.resume_id = Some(id.into());
            }
            // The first record of a turn. A list that is not a list of strings reads as "something unexpected".
            if ty == Some("system") && r.get("subtype").and_then(Value::as_str) == Some("init") {
                out.init = Some(Init {
                    tools: names(r.get("tools")),
                    mcp: names(r.get("mcp_servers")),
                    slash: r.get("slash_commands").map(|v| names(Some(v))),
                    skills: r.get("skills").map(|v| names(Some(v))),
                    agents: r.get("agents").map(|v| names(Some(v))),
                });
            }
            if ty == Some("assistant") || ty == Some("user") {
                let content = r
                    .get("message")
                    .and_then(|m| m.get("content"))
                    .and_then(Value::as_array);
                for c in content.into_iter().flatten() {
                    let ct = c.get("type").and_then(Value::as_str);
                    if ct == Some("text") {
                        add(ev, "text", c.get("text"));
                    }
                    if ct == Some("tool_use") {
                        let mut call = serde_json::Map::new();
                        if let Some(n) = c.get("name") {
                            call.insert("name".into(), n.clone());
                        }
                        if let Some(i) = c.get("input") {
                            call.insert("input".into(), i.clone());
                        }
                        add(ev, "tool_call", Some(&Value::Object(call)));
                    }
                    if ct == Some("tool_result") {
                        add(ev, "tool_result", c.get("content"));
                    }
                }
            }
            if ty == Some("result") && r.get("is_error").is_some_and(truthy) {
                out.failed = true;
                ev.push(Parsed {
                    kind: "status",
                    text: "The doctor turn failed.".into(),
                });
            }
            // A Final check's unit checks its own confinement before the model runs. Fixed words.
            if ty == Some("cc_confined") {
                ev.push(Parsed {
                    kind: "status",
                    text: CHECK_CONFINED.into(),
                });
            }
            if ty == Some("cc_unconfined") {
                out.failed = true;
                ev.push(Parsed {
                    kind: "status",
                    text: CHECK_UNCONFINED.into(),
                });
            }
        }
        Cli::Codex => {
            if ty == Some("thread.started")
                && let Some(id) = r.get("thread_id").and_then(Value::as_str)
            {
                out.resume_id = Some(id.into());
            }
            if ty == Some("item.completed") {
                let item = r.get("item").filter(|i| i.is_object()).cloned().unwrap_or(json!({}));
                let it = item.get("type").and_then(Value::as_str);
                if it == Some("agent_message") {
                    add(ev, "text", item.get("text"));
                }
                if it == Some("command_execution") {
                    add(ev, "tool_call", item.get("command"));
                    add(ev, "tool_result", item.get("aggregated_output"));
                }
                if matches!(it, Some("file_change" | "mcp_tool_call" | "web_search")) {
                    add(ev, "tool_result", Some(&item));
                }
            }
            if ty == Some("turn.failed") || ty == Some("error") {
                out.failed = true;
                ev.push(Parsed {
                    kind: "status",
                    text: "The doctor turn failed.".into(),
                });
            }
        }
        Cli::Pi => {
            if ty == Some("session")
                && let Some(id) = r.get("id").and_then(Value::as_str)
            {
                out.resume_id = Some(id.into());
            }
            if ty == Some("message_end") {
                let m = r.get("message").filter(|m| m.is_object()).cloned().unwrap_or(json!({}));
                let assistant = m.get("role").and_then(Value::as_str) == Some("assistant");
                if assistant && matches!(m.get("stopReason").and_then(Value::as_str), Some("error" | "aborted")) {
                    out.failed = true;
                    ev.push(Parsed {
                        kind: "status",
                        text: "The doctor turn failed.".into(),
                    });
                }
                for c in m.get("content").and_then(Value::as_array).into_iter().flatten() {
                    let ct = c.get("type").and_then(Value::as_str);
                    if ct == Some("text") && assistant {
                        add(ev, "text", c.get("text"));
                    }
                    if ct == Some("toolCall") {
                        let mut call = serde_json::Map::new();
                        if let Some(n) = c.get("name") {
                            call.insert("name".into(), n.clone());
                        }
                        if let Some(a) = c.get("arguments") {
                            call.insert("arguments".into(), a.clone());
                        }
                        add(ev, "tool_call", Some(&Value::Object(call)));
                    }
                }
            }
            if ty == Some("tool_execution_end") {
                add(ev, "tool_result", r.get("result"));
            }
        }
    }
    let _ = field_text;
    out
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

/// The CLI's stdout, line by line. A line longer than 2 MB is dropped whole.
pub struct DoctorStream {
    cli: Cli,
    pending: String,
    dropping: bool,
    pub failed: bool,
}

/// One thing a line gave, in the order the lines came.
pub enum Item {
    Event(Parsed),
    Init(Init),
    Resume(String),
}

/// What a chunk of output gave.
#[derive(Default)]
pub struct Out {
    pub items: Vec<Item>,
}

impl Out {
    /// The events alone (the tests read these).
    #[cfg(test)]
    pub fn events(self) -> Vec<Parsed> {
        self.items
            .into_iter()
            .filter_map(|i| if let Item::Event(e) = i { Some(e) } else { None })
            .collect()
    }
}

impl DoctorStream {
    pub fn new(cli: Cli) -> Self {
        Self {
            cli,
            pending: String::new(),
            dropping: false,
            failed: false,
        }
    }

    pub fn write(&mut self, chunk: &str) -> Out {
        let mut out = Out::default();
        let mut rest = chunk;
        while !rest.is_empty() {
            let (part, tail) = match rest.find('\n') {
                Some(i) => rest.split_at(i + 1),
                None => (rest, ""),
            };
            rest = tail;
            if !self.dropping {
                self.pending.push_str(part);
            }
            if self.pending.encode_utf16().count() > MAX_LINE {
                self.pending.clear();
                self.dropping = true;
            }
            if !part.ends_with('\n') {
                continue;
            }
            if !self.dropping {
                let line = js::trim(&self.pending).to_string();
                self.line(&line, &mut out);
            }
            self.pending.clear();
            self.dropping = false;
        }
        out
    }

    pub fn end(&mut self) -> Out {
        let mut out = Out::default();
        let line = js::trim(&self.pending).to_string();
        if !self.dropping && !line.is_empty() {
            self.line(&line, &mut out);
        }
        self.pending.clear();
        out
    }

    fn line(&mut self, line: &str, out: &mut Out) {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let r = parse_record(self.cli, &value);
        if r.failed {
            self.failed = true;
        }
        if let Some(i) = r.init {
            out.items.push(Item::Init(i));
        }
        if let Some(id) = r.resume_id
            && !id.is_empty()
            && id.encode_utf16().count() <= 128
            && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            out.items.push(Item::Resume(id));
        }
        out.items.extend(r.events.into_iter().map(Item::Event));
    }
}

#[cfg(test)]
mod tests;
