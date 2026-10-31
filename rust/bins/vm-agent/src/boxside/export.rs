//! Download workspace (`workspace-export.ts`): a readable .zip of what is in the agent, streamed
//! from the box to the browser with nothing staged on disk.
//!
//!   README.md         what each folder is and how to take it to another assistant
//!   workspace/        ~/.openclaw/workspace as it is, minus the exclusions
//!   memory/           MEMORY.md, USER.md, DREAMS.md and memory/, copied out of the workspace
//!   conversations/    one Markdown file per conversation (W6's transcripts)
//!   meetings/         one per meeting (W8's records)
//!   calls/            one per phone call (W8's records)
//!
//! Left out: anything on another filesystem or behind a symlink (Drive folders are FUSE mounts),
//! files named like credentials, and what a backup skips. Nothing outside the workspace is walked.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use cc_http::BoxFuture;
use serde_json::{Value, json};

use super::archive::should_exclude;
use super::web;
use super::zip::ZipWriter;

/// Directory names that hold keys or tool state rather than anything the agent made.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".ssh",
    ".gnupg",
    ".aws",
    ".docker",
    ".kube",
    ".openclaw",
    ".config",
];
const MEMORY_FILES: &[&str] = &["MEMORY.md", "USER.md", "DREAMS.md"];
/// Generated Markdown per conversation is roughly this share of its stored transcript.
const TRANSCRIPT_TEXT_SHARE: f64 = 0.35;

/// `SECRET_NAME`: credentials by convention.
static SECRET_NAME: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)^(\.env(\..+)?|.+\.(pem|key|p12|pfx|jks|keystore|kdbx|ovpn)|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|\.netrc|\.npmrc|\.pypirc|\.pgpass|\.git-credentials|.*credentials.*|.*secrets?\.(json|ya?ml|toml|txt|env)|auth[-_]?profiles?.*\.json|tokens?\.json|client_secret.*\.json|service[-_]account.*\.json)$").expect("regex")
});
/// Already compressed: stored, not deflated again.
static STORED: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"(?i)\.(zip|gz|tgz|bz2|xz|zst|7z|rar|jpe?g|png|gif|webp|avif|heic|mp3|m4a|aac|ogg|opus|mp4|m4v|mov|webm|mkv|pdf|docx|xlsx|pptx|woff2?)$").expect("regex")
});

pub fn is_secret_name(name: &str) -> bool {
    SECRET_NAME.is_match(name)
}

fn is_memory(rel: &str) -> bool {
    MEMORY_FILES.contains(&rel) || (rel.starts_with("memory/") && rel.to_lowercase().ends_with(".md"))
}

/// `MEETING_JSON`: a saved meeting's raw record; its readable form goes in meetings/.
fn is_meeting_json(rel: &str) -> bool {
    let Some(name) = rel.strip_prefix("meetings/").and_then(|n| n.strip_suffix(".json")) else {
        return false;
    };
    name.len() == 36
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

/// `slug`: NFKD, accents dropped, anything else a dash, trimmed, at most `max`.
pub fn slug(s: &str, max: usize) -> String {
    use unicode_normalization::UnicodeNormalization;
    let folded: String = s.nfkd().filter(|c| !('\u{300}'..='\u{36f}').contains(c)).collect();
    let mut out = String::new();
    let mut dash = false;
    for c in folded.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let out = out.trim_matches(|c| c == '-' || c == '.');
    // `.slice(0, max)` counts UTF-16 units; everything left is ASCII.
    let cut: String = out.chars().take(max).collect();
    cut.trim_end_matches(['-', '.']).to_string()
}

fn ymd(t: Option<i64>) -> String {
    t.map(|ms| web::iso(ms)[..10].to_string())
        .unwrap_or_else(|| "undated".into())
}

fn ymdhm(t: Option<i64>) -> String {
    t.map(|ms| web::iso(ms)[..16].replacen('T', "-", 1).replacen(':', "", 1))
        .unwrap_or_else(|| "undated".into())
}

/// `when`: `2026-10-08 14:51 UTC`.
pub fn when(t: Option<i64>) -> String {
    t.map(|ms| format!("{} UTC", web::iso(ms)[..16].replacen('T', " ", 1)))
        .unwrap_or_else(|| "unknown time".into())
}

fn clock(t: Option<i64>) -> String {
    t.map(|ms| web::iso(ms)[11..19].to_string()).unwrap_or_default()
}

const CHANNEL_NAMES: &[(&str, &str)] = &[
    ("telegram", "Telegram"),
    ("whatsapp", "WhatsApp"),
    ("discord", "Discord"),
    ("slack", "Slack"),
    ("signal", "Signal"),
    ("imessage", "iMessage"),
    ("email", "Email"),
    ("agentmail", "Email"),
    ("gmail", "Gmail"),
    ("web chat", "Web chat"),
    ("webchat", "Web chat"),
    ("voice", "Phone"),
    ("clickclack", "Team chat"),
];

pub fn channel_name(channel: &str) -> String {
    let lower = channel.to_lowercase();
    if let Some((_, n)) = CHANNEL_NAMES.iter().find(|(k, _)| *k == lower) {
        return n.to_string();
    }
    let mut c = channel.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// A number field (ms), when it is a finite number.
fn num(v: &Value, k: &str) -> Option<i64> {
    v.get(k)
        .and_then(Value::as_f64)
        .filter(|f| f.is_finite())
        .map(|f| f as i64)
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str)
}

/// `Date.parse` of a string field.
fn parsed(v: &Value, k: &str) -> Option<i64> {
    text(v, k).and_then(web::date_parse)
}

pub fn conversation_file_name(
    created_at: Option<i64>,
    session_key: &str,
    label: Option<&str>,
    session_id: &str,
    channels: &[String],
) -> String {
    let parts: Vec<&str> = session_key.split(':').collect();
    let rest: Vec<&str> = if parts.first() == Some(&"agent") {
        parts.iter().skip(2).copied().collect()
    } else {
        parts.clone()
    };
    let channel = channels.first().cloned().or_else(|| {
        rest.first().map(|r| {
            if *r == "main" {
                "web-chat".to_string()
            } else {
                r.to_string()
            }
        })
    });
    let tail = label.map(str::to_string).unwrap_or_else(|| {
        let from = if rest.len() > 2 { 2 } else { 1 };
        rest.iter().skip(from).copied().collect::<Vec<_>>().join("-")
    });
    let joined: Vec<String> = [channel.unwrap_or_default(), tail]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let what = slug(&joined.join("-"), 60);
    let id: String = session_id.chars().take(8).collect();
    format!(
        "{}-{}-{id}.md",
        ymd(created_at),
        if what.is_empty() { "chat".to_string() } else { what }
    )
}

fn meeting_file_name(m: &Value) -> String {
    let code = slug(text(m, "meetingCode").unwrap_or("meeting"), 40);
    format!(
        "{}-{}.md",
        ymdhm(parsed(m, "startedAt")),
        if code.is_empty() { "meeting".to_string() } else { code }
    )
}

fn call_file_name(c: &Value) -> String {
    let outbound = text(c, "direction") == Some("outbound");
    let other = text(c, if outbound { "to" } else { "from" }).unwrap_or_default();
    let digits: String = other.chars().filter(char::is_ascii_digit).collect();
    let s = slug(&digits, 40);
    format!(
        "{}-{}-{}.md",
        ymdhm(num(c, "startedAt")),
        text(c, "direction").unwrap_or_default(),
        if s.is_empty() { "call".to_string() } else { s }
    )
}

/// `body`: line endings made `\n`, a stray `---` line defused.
fn body(s: &str) -> String {
    s.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|l| if l == "---" { "\\---" } else { l })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn conversation_markdown(c: &Value, agent: &str) -> String {
    let channels: Vec<String> = c
        .get("channels")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(channel_name).collect())
        .unwrap_or_default();
    let turns: Vec<&Value> = c
        .get("turns")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    let person = turns.iter().find(|t| {
        text(t, "kind") == Some("message")
            && text(t, "role") == Some("user")
            && text(t, "sender").is_some_and(|s| !s.is_empty())
    });
    let peer = text(c, "peer").map(str::to_string);
    let who = peer
        .clone()
        .or_else(|| person.and_then(|p| text(p, "sender")).map(str::to_string));
    let title = text(c, "label").map(str::to_string).unwrap_or_else(|| match &who {
        Some(w) => format!(
            "{} · {w}",
            channels.first().cloned().unwrap_or_else(|| "undefined".into())
        ),
        None => channels.join(", "),
    });
    let messages = turns.iter().filter(|t| text(t, "kind") == Some("message")).count();
    let chat = match text(c, "chatType") {
        Some(t) if !t.is_empty() => format!(" ({})", if t == "direct" { "direct chat" } else { t }),
        _ => String::new(),
    };
    let mut lines = vec![
        format!("# {title}"),
        String::new(),
        format!(
            "- {}: {}{chat}",
            if channels.len() > 1 { "Channels" } else { "Channel" },
            channels.join(", ")
        ),
    ];
    if let Some(p) = &peer {
        lines.push(format!("- With: {p}"));
    }
    lines.push(format!("- Started: {}", when(num(c, "startedAt"))));
    lines.push(format!("- Messages: {messages}"));
    if let Some(a) = text(c, "agentId").filter(|a| *a != "main") {
        lines.push(format!("- Agent: {a}"));
    }
    lines.extend(["".into(), "---".into(), "".into()]);
    for t in turns {
        if text(t, "kind") == Some("reset") {
            lines.extend([
                format!("*New session started · {}*", when(num(t, "at"))),
                String::new(),
                "---".into(),
                String::new(),
            ]);
            continue;
        }
        let speaker = if text(t, "role") == Some("assistant") {
            agent.to_string()
        } else {
            text(t, "sender").unwrap_or("User").to_string()
        };
        let via = match text(t, "channel") {
            Some(ch) if channels.len() > 1 && !ch.is_empty() => format!(" · {}", channel_name(ch)),
            _ => String::new(),
        };
        lines.push(format!("**{speaker}** · {}{via}", when(num(t, "at"))));
        lines.push(String::new());
        lines.push(body(text(t, "text").unwrap_or_default()));
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn meeting_markdown(m: &Value, agent: &str) -> String {
    let start = parsed(m, "startedAt");
    let end = parsed(m, "endedAt");
    let minutes = match (start, end) {
        (Some(s), Some(e)) => Some(((e - s) as f64 / 60_000.0).round().max(0.0) as i64),
        _ => None,
    };
    let code = text(m, "meetingCode").filter(|c| !c.is_empty());
    let mut lines = vec![
        format!("# Meeting{}", code.map(|c| format!(" {c}")).unwrap_or_default()),
        String::new(),
        format!("- Date: {}", when(start)),
    ];
    if let Some(min) = minutes {
        lines.push(format!("- Length: {min} min"));
    }
    lines.push(format!(
        "- Joined by: {agent}{}",
        if text(m, "mode") == Some("bidi") {
            " (could speak)"
        } else {
            " (listening)"
        }
    ));
    if let Some(e) = text(m, "error").filter(|e| !e.is_empty()) {
        lines.push(format!("- Note: {e}"));
    }
    lines.push(String::new());
    lines.extend(["## Notes".to_string(), String::new()]);
    lines.push(match text(m, "notes").filter(|n| !n.is_empty()) {
        Some(n) => body(n.trim()),
        None => "*No notes were written for this meeting.*".into(),
    });
    lines.push(String::new());
    lines.extend(["## Transcript".to_string(), String::new()]);
    if let Some(note) = text(m, "transcriptNote").filter(|n| !n.is_empty()) {
        lines.extend([format!("*{note}*"), String::new()]);
    }
    let transcript: Vec<&Value> = m
        .get("transcript")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if transcript.is_empty() {
        lines.extend(["*No captions were recorded.*".to_string(), String::new()]);
    }
    for t in transcript {
        lines.push(format!(
            "**{}** ({}): {}",
            text(t, "speaker").unwrap_or_default(),
            clock(parsed(t, "at")),
            text(t, "text").unwrap_or_default()
        ));
        lines.push(String::new());
    }
    lines.join("\n")
}

pub fn call_markdown(c: &Value, agent: &str) -> String {
    let outbound = text(c, "direction") == Some("outbound");
    let (from, to) = (text(c, "from").unwrap_or_default(), text(c, "to").unwrap_or_default());
    let mut lines = vec![
        format!(
            "# Phone call · {}",
            if outbound {
                format!("to {to}")
            } else {
                format!("from {from}")
            }
        ),
        String::new(),
        format!(
            "- Direction: {}",
            if outbound {
                "the agent called out"
            } else {
                "someone called the agent"
            }
        ),
        format!("- From: {from}"),
        format!("- To: {to}"),
        format!("- Started: {}", when(num(c, "startedAt"))),
    ];
    if let Some(d) = num(c, "durationSeconds") {
        lines.push(format!("- Length: {} min {} s", d / 60, d % 60));
    }
    if let Some(r) = text(c, "endReason").filter(|r| !r.is_empty()) {
        lines.push(format!("- Ended: {r}"));
    }
    lines.extend([
        String::new(),
        "Phone numbers are shortened to their last four digits, as on the Calls page.".into(),
        String::new(),
        "## Transcript".into(),
        String::new(),
    ]);
    let transcript: Vec<&Value> = c
        .get("transcript")
        .and_then(Value::as_array)
        .map(|a| a.iter().collect())
        .unwrap_or_default();
    if transcript.is_empty() {
        lines.extend([
            "*Nothing was said, or nothing was transcribed.*".to_string(),
            String::new(),
        ]);
    }
    for t in transcript {
        let who = if text(t, "speaker") == Some("agent") {
            agent
        } else {
            "Caller"
        };
        lines.push(format!(
            "**{who}** ({}): {}",
            clock(num(t, "at")),
            text(t, "text").unwrap_or_default()
        ));
        lines.push(String::new());
    }
    if c.get("transcriptTruncated") == Some(&Value::Bool(true)) {
        lines.extend([
            "*The transcript was cut short when it was saved.*".to_string(),
            String::new(),
        ]);
    }
    lines.join("\n")
}

fn count(n: usize, one: &str) -> String {
    format!("{n} {}", if n == 1 { one.to_string() } else { format!("{one}s") })
}

pub struct ReadmeFacts<'a> {
    pub agent: &'a str,
    pub files: usize,
    pub memory: usize,
    pub conversations: usize,
    pub meetings: usize,
    pub calls: usize,
    pub mounts: &'a [String],
    pub secrets: &'a [String],
    pub at_ms: i64,
}

pub fn readme(o: &ReadmeFacts<'_>) -> String {
    let mut lines = vec![
        format!("# {}: workspace download", o.agent),
        String::new(),
        format!(
            "Downloaded {} from the agent's own server. It went straight from the agent to you; ControlClaw did not see or keep a copy.",
            when(Some(o.at_ms))
        ),
        String::new(),
        "## What is in here".into(),
        String::new(),
        format!(
            "- **workspace/**: the agent's working folder as it is on the server ({}). Its instructions and personality (`AGENTS.md`, `SOUL.md`, `IDENTITY.md`), what it knows about you (`USER.md`), the skills it has written (`skills/`), and every file it has made or you have given it.",
            count(o.files, "file")
        ),
        format!(
            "- **memory/**: what the agent has written down to remember ({}). `MEMORY.md` is the short list of lasting facts and decisions, `USER.md` is about you, and `daily/` has its working notes, one file a day. The same files are also in workspace/.",
            count(o.memory, "file")
        ),
    ];
    if o.conversations > 0 {
        lines.push(format!(
            "- **conversations/**: {}, one file each, with the channel, the date and who said what. Times are in UTC.",
            count(o.conversations, "conversation")
        ));
    }
    if o.meetings > 0 {
        lines.push(format!(
            "- **meetings/**: {} the agent joined, with its notes and the transcript.",
            count(o.meetings, "meeting")
        ));
    }
    if o.calls > 0 {
        lines.push(format!(
            "- **calls/**: {}, with the transcript. Phone numbers are shortened to their last four digits.",
            count(o.calls, "phone call")
        ));
    }
    lines.extend([
        String::new(),
        "Everything is plain text or the original file, so any editor can open it.".into(),
        String::new(),
        "## What is not in here".into(),
        String::new(),
        "- Passwords, keys and tokens: the agent's model and channel credentials, its settings file and the server's own keys.".into(),
        "- Google Drive folders and anything else linked into the workspace from elsewhere. Those files are still in Drive.".into(),
        "- Caches, logs, the agent's internal databases and search index.".into(),
    ]);
    if !o.mounts.is_empty() {
        lines.push(format!(
            "- These folders, because they are mounted or linked from elsewhere: {}.",
            o.mounts.iter().map(|m| format!("`{m}`")).collect::<Vec<_>>().join(", ")
        ));
    }
    if !o.secrets.is_empty() {
        let shown: Vec<String> = o.secrets.iter().take(50).map(|m| format!("`{m}`")).collect();
        let more = if o.secrets.len() > 50 {
            format!(" and {} more", o.secrets.len() - 50)
        } else {
            String::new()
        };
        lines.push(format!("- These files, because their names say they hold credentials: {}{more}. If you need one, download it on its own from the Files page.", shown.join(", ")));
    }
    lines.extend([
        String::new(),
        "## Using it with another assistant".into(),
        String::new(),
        "- **Most assistants that read files (Claude, ChatGPT, Gemini and others):** start a project, upload `memory/MEMORY.md`, `memory/USER.md` and `workspace/AGENTS.md`, and ask it to work from them. Add conversations or meeting notes when they matter.".into(),
        "- **Another OpenClaw agent:** copy the contents of `workspace/` into its workspace folder (`~/.openclaw/workspace`). It picks up the same instructions, memory and skills the next time it starts. It will need its own model and channel credentials.".into(),
        "- **A coding agent or a plain folder:** unzip it somewhere and point the assistant at it. Each skill in `workspace/skills/` is a folder with a `SKILL.md` describing what it does.".into(),
        String::new(),
    ]);
    lines.join("\n")
}

#[derive(Debug, Clone)]
struct Walked {
    rel: String,
    abs: PathBuf,
    size: u64,
    mtime_ms: i64,
    /// Device and inode at the walk, checked again when the file is read.
    id: (u64, u64),
}

/// The sources besides the workspace (W6's transcripts, W8's meetings and calls). An empty source
/// is a folder that is not in the zip.
/// A conversation's text, read when its turn comes.
pub type ReadConversation = Arc<dyn Fn(&Value) -> Option<Value> + Send + Sync>;

pub struct Sources {
    pub conversations: Arc<dyn Fn() -> Vec<Value> + Send + Sync>,
    pub read_conversation: ReadConversation,
    pub meetings: Arc<dyn Fn() -> Vec<Value> + Send + Sync>,
    pub calls: Arc<dyn Fn() -> Vec<Value> + Send + Sync>,
}

pub struct WorkspaceExporter {
    openclaw_home: PathBuf,
    agent_name: Arc<dyn Fn() -> String + Send + Sync>,
    sources: Sources,
    running: Arc<AtomicBool>,
}

impl WorkspaceExporter {
    pub fn new(openclaw_home: PathBuf, agent_name: Arc<dyn Fn() -> String + Send + Sync>, sources: Sources) -> Self {
        Self {
            openclaw_home,
            agent_name,
            sources,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    fn now_ms() -> i64 {
        web::time_ms(std::time::SystemTime::now())
    }

    /// `<agent>-workspace-2026-10-08`.
    pub fn base_name(&self) -> String {
        let a = slug(&(self.agent_name)(), 40);
        format!(
            "{}-workspace-{}",
            if a.is_empty() { "agent".to_string() } else { a },
            &web::iso(Self::now_ms())[..10]
        )
    }

    /// Every file that goes into workspace/, in a stable order. Mounts are recognised by device; a
    /// symlink is never followed.
    fn walk(&self) -> (Vec<Walked>, Vec<String>, Vec<String>) {
        use std::os::unix::fs::MetadataExt;
        let (mut files, mut mounts, mut secrets) = (Vec::new(), Vec::new(), Vec::new());
        let Ok(root) = std::fs::canonicalize(self.openclaw_home.join("workspace")) else {
            return (files, mounts, secrets);
        };
        let Ok(root_dev) = std::fs::metadata(&root).map(|m| m.dev()) else {
            return (files, mounts, secrets);
        };
        fn visit(
            root: &Path,
            root_dev: u64,
            rel: &str,
            files: &mut Vec<Walked>,
            mounts: &mut Vec<String>,
            secrets: &mut Vec<String>,
        ) {
            let dir = if rel.is_empty() {
                root.to_path_buf()
            } else {
                root.join(rel)
            };
            let Ok(rd) = std::fs::read_dir(&dir) else { return };
            let mut names: Vec<String> = rd
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            // `localeCompare(b, "en")`: case and accents count only to break a tie.
            names.sort_by(|a, b| super::files::locale_compare(a, b).then_with(|| a.cmp(b)));
            for name in names {
                let child = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let abs = root.join(&child);
                let Ok(st) = std::fs::symlink_metadata(&abs) else {
                    continue;
                };
                if st.file_type().is_symlink() {
                    // A link to a folder is how a mount can look too.
                    if std::fs::metadata(&abs).is_ok_and(|m| m.is_dir()) {
                        mounts.push(child);
                    }
                    continue;
                }
                if st.is_dir() {
                    if st.dev() != root_dev || (rel.is_empty() && name == "Drive") {
                        mounts.push(child);
                        continue;
                    }
                    if SKIPPED_DIRS.contains(&name.as_str()) || should_exclude(&child, "workspace") {
                        continue;
                    }
                    visit(root, root_dev, &child, files, mounts, secrets);
                    continue;
                }
                if !st.is_file() || should_exclude(&child, "workspace") || is_meeting_json(&child) {
                    continue;
                }
                if is_secret_name(&name) {
                    secrets.push(child);
                    continue;
                }
                files.push(Walked {
                    rel: child,
                    abs,
                    size: st.len(),
                    mtime_ms: st.modified().map(web::time_ms).unwrap_or(0),
                    id: (st.dev(), st.ino()),
                });
            }
        }
        visit(&root, root_dev, "", &mut files, &mut mounts, &mut secrets);
        (files, mounts, secrets)
    }

    /// What the zip would hold and roughly how big (`plan()`).
    pub fn plan_now(&self) -> Value {
        let (files, mounts, secrets) = self.walk();
        let memory: Vec<&Walked> = files.iter().filter(|f| is_memory(&f.rel)).collect();
        let conversations = (self.sources.conversations)();
        let meetings = (self.sources.meetings)();
        let calls = (self.sources.calls)();
        let file_bytes: u64 = files.iter().map(|f| f.size).sum::<u64>() + memory.iter().map(|f| f.size).sum::<u64>();
        let len = |v: &Value, k: &str| text(v, k).map(|s| s.encode_utf16().count()).unwrap_or(0) as u64;
        let generated: u64 = conversations
            .iter()
            .map(|c| (num(c, "bytes").unwrap_or(0) as f64 * TRANSCRIPT_TEXT_SHARE + 0.5).floor() as u64)
            .sum::<u64>()
            + meetings
                .iter()
                .map(|m| {
                    400 + len(m, "notes")
                        + m.get("transcript")
                            .and_then(Value::as_array)
                            .map(|t| t.iter().map(|x| len(x, "text") + 40).sum::<u64>())
                            .unwrap_or(0)
                })
                .sum::<u64>()
            + calls
                .iter()
                .map(|c| {
                    300 + c
                        .get("transcript")
                        .and_then(Value::as_array)
                        .map(|t| t.iter().map(|x| len(x, "text") + 30).sum::<u64>())
                        .unwrap_or(0)
                })
                .sum::<u64>();
        json!({
            "filename": format!("{}.zip", self.base_name()),
            "bytes": file_bytes + generated + 4000,
            "files": files.len(),
            "memoryFiles": memory.len(),
            "conversations": conversations.len(),
            "meetings": meetings.len(),
            "calls": calls.len(),
            "mounts": mounts,
            "secrets": secrets,
        })
    }

    /// Write the zip into `out`. A browser that leaves ends it with a broken pipe. Blocking: run it
    /// on a thread of its own.
    fn write(&self, out: &mut Sink) -> std::io::Result<()> {
        let agent = (self.agent_name)();
        let (files, mounts, secrets) = self.walk();
        let refs = (self.sources.conversations)();
        let meetings = (self.sources.meetings)();
        let calls = (self.sources.calls)();
        let memory: Vec<&Walked> = files.iter().filter(|f| is_memory(&f.rel)).collect();
        let agents: std::collections::BTreeSet<&str> = refs.iter().filter_map(|r| text(r, "agentId")).collect();
        let multi_agent = agents.len() > 1;
        let now = Self::now_ms();
        let mut z = Zip {
            zip: ZipWriter::new(out),
            base: self.base_name(),
            names: std::collections::HashSet::new(),
        };
        let facts = ReadmeFacts {
            agent: &agent,
            files: files.len(),
            memory: memory.len(),
            conversations: refs.len(),
            meetings: meetings.len(),
            calls: calls.len(),
            mounts: &mounts,
            secrets: &secrets,
            at_ms: now,
        };
        z.text("README.md", &readme(&facts), now)?;
        for f in &memory {
            let p = match f.rel.strip_prefix("memory/") {
                Some(rest) => format!("memory/daily/{rest}"),
                None => format!("memory/{}", f.rel),
            };
            z.file(&p, f, true)?;
        }
        for r in &refs {
            let folder = if multi_agent {
                format!("conversations/{}", slug(text(r, "agentId").unwrap_or_default(), 40))
            } else {
                "conversations".into()
            };
            let channels: Vec<String> = r
                .get("channels")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let name = conversation_file_name(
                num(r, "createdAt"),
                text(r, "sessionKey").unwrap_or_default(),
                text(r, "label"),
                text(r, "sessionId").unwrap_or_default(),
                &channels,
            );
            // Read when its turn comes, so only one conversation is in memory at a time.
            let content = match (self.sources.read_conversation)(r) {
                Some(c) => conversation_markdown(&c, &agent),
                None => "# Conversation\n\nThis conversation has no messages to show.\n".into(),
            };
            z.text(&format!("{folder}/{name}"), &content, now)?;
        }
        for m in &meetings {
            z.text(
                &format!("meetings/{}", meeting_file_name(m)),
                &meeting_markdown(m, &agent),
                now,
            )?;
        }
        for c in &calls {
            z.text(&format!("calls/{}", call_file_name(c)), &call_markdown(c, &agent), now)?;
        }
        for f in &files {
            z.file(&format!("workspace/{}", f.rel), f, !STORED.is_match(&f.rel))?;
        }
        z.zip.finish()?;
        Ok(())
    }
}

/// The zip being written, with the names already used (`unique`).
struct Zip<'a> {
    zip: ZipWriter<&'a mut Sink>,
    base: String,
    names: std::collections::HashSet<String>,
}

impl Zip<'_> {
    /// `unique`: `a.md`, then `a-2.md`, `a-3.md`.
    fn unique(&mut self, path: &str) -> String {
        let mut candidate = path.to_string();
        let mut i = 2;
        while self.names.contains(&candidate) {
            // `path.replace(/(\.[^./]+)?$/, "-<i>$1")`: before the last extension, if there is one.
            let last = path.rsplit('/').next().unwrap_or(path);
            candidate = match last.rfind('.').filter(|d| *d + 1 < last.len()) {
                Some(d) => {
                    let at = path.len() - last.len() + d;
                    format!("{}-{i}{}", &path[..at], &path[at..])
                }
                None => format!("{path}-{i}"),
            };
            i += 1;
        }
        self.names.insert(candidate.clone());
        candidate
    }

    fn text(&mut self, path: &str, content: &str, mtime_ms: i64) -> std::io::Result<()> {
        let unique = self.unique(path);
        let name = format!("{}/{unique}", self.base);
        let mut e = self.zip.start(&name, mtime_ms.div_euclid(1000), true)?;
        e.write(content.as_bytes())?;
        e.finish()
    }

    /// A file that vanished or became unreadable ends early rather than failing the whole zip.
    fn file(&mut self, path: &str, f: &Walked, compress: bool) -> std::io::Result<()> {
        use std::io::Read;
        let unique = self.unique(path);
        let name = format!("{}/{unique}", self.base);
        let mut e = self.zip.start(&name, f.mtime_ms.div_euclid(1000), compress)?;
        // Not through a link, and the file the walk saw: one swapped for a link since (a parent
        // folder included) is left empty, as one that vanished.
        if let Some(mut src) = open_unchanged(&f.abs, f.id) {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = src.read(&mut buf) {
                if n == 0 {
                    break;
                }
                e.write(&buf[..n])?;
            }
        }
        e.finish()
    }
}

fn open_unchanged(abs: &Path, id: (u64, u64)) -> Option<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(super::backup::O_NOFOLLOW)
        .open(abs)
        .ok()?;
    let m = f.metadata().ok()?;
    (m.is_file() && (m.dev(), m.ino()) == id).then_some(f)
}

/// The zip's bytes, into the response channel in pieces; a closed channel is the browser leaving.
struct Sink {
    tx: tokio::sync::mpsc::Sender<Bytes>,
    buf: Vec<u8>,
    sent: u64,
}

impl std::io::Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        if self.buf.len() >= 64 * 1024 {
            self.flush()?;
        }
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.sent += chunk.len() as u64;
        self.tx
            .blocking_send(chunk)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the browser went away"))
    }
}

/// Clears the busy flag however the zip ends.
struct Running(Arc<AtomicBool>);
impl Drop for Running {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl super::Exporter for WorkspaceExporter {
    fn plan(&self) -> BoxFuture<Value> {
        let me = self.snapshot();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || me.plan_now())
                .await
                .unwrap_or(Value::Null)
        })
    }

    fn busy(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    fn base_name(&self) -> String {
        WorkspaceExporter::base_name(self)
    }

    fn stream(&self, tx: tokio::sync::mpsc::Sender<Bytes>, done: Box<dyn FnOnce(bool, u64) + Send>) -> bool {
        // One at a time per box: the check and the claim are one step.
        if self.running.swap(true, Ordering::SeqCst) {
            return false;
        }
        let me = self.snapshot();
        let running = Running(self.running.clone());
        tokio::task::spawn_blocking(move || {
            let mut sink = Sink {
                tx,
                buf: Vec::new(),
                sent: 0,
            };
            let completed = match me.write(&mut sink) {
                Ok(()) => std::io::Write::flush(&mut sink).is_ok(),
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        tracing::error!("[export] {e}");
                    }
                    false
                }
            };
            // Free before saying so: whoever hears `done` may start the next one.
            drop(running);
            done(completed, sink.sent);
        });
        true
    }
}

impl WorkspaceExporter {
    /// The same exporter (shared busy flag) for a task of its own.
    fn snapshot(&self) -> Arc<WorkspaceExporter> {
        Arc::new(WorkspaceExporter {
            openclaw_home: self.openclaw_home.clone(),
            agent_name: self.agent_name.clone(),
            sources: Sources {
                conversations: self.sources.conversations.clone(),
                read_conversation: self.sources.read_conversation.clone(),
                meetings: self.sources.meetings.clone(),
                calls: self.sources.calls.clone(),
            },
            running: self.running.clone(),
        })
    }
}

#[cfg(test)]
mod tests;
