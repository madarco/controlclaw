//! A capture session (`doctor-capture.ts`, docs/plans/template-ai-sessions.md, "Capture"): a
//! Doctor session that reads an agent and writes a template of it. What is added to an agent
//! repair is here: where the session writes (asked of the agent), the first message, and the check
//! of the template it wrote before a person may send it to ControlClaw as a draft.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::repair::{PACK_FILES, PACK_TOTAL_BYTES, PATH, REPAIR_STEP, RepairFile, read_file, scan, sized, unique};

pub const CAPTURE_WINDOW_MS: i64 = 60 * 60_000;
const NOT_A_DRAFT: &str = "the agent's answer is not in the form of a template";

static FILE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(template\.yaml|README\.md|(files|scripts)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)$").expect("pattern")
});
/// The workspace files a template.yaml's `file` and `line` steps write: `path:` and `file:` values.
static WRITES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:path|file)[ \t]*:[ \t]*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s,{}#\n]+))"#).expect("pattern")
});

/// The agent's answer to `/templates/capture/facts`: the folder capture sessions write under.
pub fn read_capture_facts(raw: &Map<String, Value>) -> Option<String> {
    raw.get("base")
        .and_then(Value::as_str)
        .filter(|b| PATH.is_match(b) && !b.split('/').any(|x| x == ".."))
        .map(String::from)
}

/// The first message of a capture session, written here. The model gets no text from the console.
pub fn capture_prompt(base: &str, session_id: &str) -> String {
    let dir = format!("{base}/{session_id}");
    [
        "Write a template of this agent: the steps that would set another agent up the way this one is set up now.".to_string(),
        String::new(),
        "Run every command below on the agent, through this session's SSH connection to it. None of them is for this firewall, and the folders they name are on the agent.".into(),
        String::new(),
        format!("1. Run: sudo -u controlclaw cc-runbook capture-folder --session {session_id}"),
        format!("   It makes an empty folder for this session ({dir}). Write the template there and nowhere else: template.yaml, and its files under files/ and scripts/."),
        "2. Run: sudo -u controlclaw cc-runbook capture".into(),
        "   It prints what ControlClaw already reads by itself: the instruction files, the plugins, a few OpenClaw settings, the scheduled jobs and the MCP servers. ControlClaw writes those steps itself. Your work is what it cannot read: a package or a tool installed by hand, a skill outside the workspace, a plugin with settings, anything that needed a command.".into(),
        "3. For each such thing write a step. Use a declarative kind where one fits, and otherwise a run step with an apply script and a verify script. Read an existing template under /opt/controlclaw/agent/templates/ for the format.".into(),
        format!("4. Check your work: sudo -u controlclaw cc-runbook verify {dir}"),
        "   Every step must hold on this agent. Take out a step whose check cannot pass here, and say so in README.md.".into(),
        format!("5. Then: sudo -u controlclaw cc-runbook capture-pack --session {session_id}"),
        "   It says what is refused. Fix the folder until it prints the files.".into(),
        String::new(),
        "Rules. Change nothing on this agent outside that folder. Copy no value of a secret, a token or a password into any file: refer to it as ${NAME} and name it in the step's needs. Do not open or copy MEMORY.md, the memory folder, USER.md, IDENTITY.md, TOOLS.md, conversations or channel logins. Write no controlclaw.setting step: ControlClaw adds those itself.".into(),
        String::new(),
        "When the session ends, the firewall reads the folder and shows every file to the owner as a draft. Files that hold a secret are refused.".into(),
    ]
    .join("\n")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Held {
    pub id: String,
    pub holds: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapturePack {
    pub files: Vec<RepairFile>,
    pub held: Vec<Held>,
    pub at: String,
}

/// What is kept with the transcript: the template the session wrote, or why it cannot be shown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CaptureRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<CapturePack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_hash: Option<String>,
}

/// What a session's template may never hold or write, by a part of the path, whatever the capitals.
pub fn capture_private_path(path: &str) -> bool {
    const PRIVATE: &[&str] = &[
        "user.md",
        "memory.md",
        "identity.md",
        "tools.md",
        "memory",
        "sessions",
        "credentials",
        "auth-profiles.json",
        ".env",
    ];
    path.split(['/', '\\']).filter(|p| !p.is_empty()).any(|part| {
        let l = part.to_lowercase();
        PRIVATE.contains(&l.as_str()) || l.ends_with(".env")
    })
}

/// The agent's pack, read as text from a box a model had root on. Refused whole on any problem.
pub fn read_capture_pack(raw: &Value, secrets: &[String]) -> Result<CapturePack, Vec<String>> {
    let Some(o) = raw.as_object() else {
        return Err(vec![NOT_A_DRAFT.into()]);
    };
    let mut problems: Vec<String> = Vec::new();
    let at = o.get("at").and_then(Value::as_str);
    let at_ok = at.is_some_and(|a| a.encode_utf16().count() <= 40 && crate::integrations::js::parse_iso(a).is_some());
    if o.keys().any(|k| !["files", "held", "at"].contains(&k.as_str())) || !at_ok {
        problems.push(NOT_A_DRAFT.into());
    }
    let mut files: Vec<RepairFile> = Vec::new();
    let mut total = 0usize;
    match o
        .get("files")
        .and_then(Value::as_array)
        .filter(|l| l.len() <= PACK_FILES)
    {
        None => problems.push(format!("a template has at most {PACK_FILES} files")),
        Some(list) => {
            for item in list {
                let Some(f) = read_file(item) else {
                    problems.push(NOT_A_DRAFT.into());
                    continue;
                };
                if f.path.encode_utf16().count() > 200
                    || !FILE_PATH.is_match(&f.path)
                    || f.path.split('/').any(|p| p == "." || p == "..")
                {
                    problems.push("a file has a path a template cannot have".into());
                    continue;
                }
                if files.iter().any(|x| x.path == f.path) {
                    problems.push(format!("{}: this file is there twice", f.path));
                    continue;
                }
                if capture_private_path(&f.path) {
                    problems.push(format!("{}: a template never holds what the agent remembers, what it knows about its person, conversations or logins", f.path));
                    continue;
                }
                if !sized(&f.path, &f.content, &mut total, &mut problems) {
                    continue;
                }
                files.push(f);
            }
        }
    }
    if total > PACK_TOTAL_BYTES {
        problems.push(format!(
            "the files are larger than {} KB in all",
            PACK_TOTAL_BYTES / 1024
        ));
    }
    let yaml = files
        .iter()
        .find(|f| f.path == "template.yaml")
        .map(|f| f.content.clone())
        .unwrap_or_default();
    for c in WRITES.captures_iter(&yaml) {
        let written = c.get(1).or(c.get(2)).or(c.get(3)).map(|m| m.as_str()).unwrap_or("");
        if capture_private_path(written) {
            problems.push("template.yaml: a step writes a file a template never writes (what the agent remembers, what it knows about its person, conversations or logins)".into());
        }
    }
    if problems.is_empty() && !files.iter().any(|f| f.path == "template.yaml") {
        problems.push("the session wrote no template.yaml".into());
    }
    let held: Option<Vec<Held>> = o
        .get("held")
        .and_then(Value::as_array)
        .filter(|h| h.len() <= 300)
        .and_then(|list| {
            list.iter()
                .map(|h| {
                    let h = h.as_object().filter(|h| h.len() == 2)?;
                    let id = h.get("id")?.as_str().filter(|i| REPAIR_STEP.is_match(i))?;
                    Some(Held {
                        id: id.into(),
                        holds: h.get("holds")?.as_bool()?,
                    })
                })
                .collect()
        });
    if held.is_none() {
        problems.push(NOT_A_DRAFT.into());
    }
    let refs: Vec<&RepairFile> = files.iter().collect();
    scan(&refs, secrets, &mut problems);
    if !problems.is_empty() {
        return Err(unique(problems));
    }
    Ok(CapturePack {
        files,
        held: held.unwrap_or_default(),
        at: at.unwrap_or_default().into(),
    })
}

/// What a kept draft is, in one value: one that changed since it was sent is sent again.
pub fn capture_hash(p: &CapturePack) -> String {
    use sha2::{Digest, Sha256};
    let v: Vec<Value> = p
        .files
        .iter()
        .map(|f| serde_json::json!([f.path, f.executable, f.content]))
        .collect();
    hex::encode(Sha256::digest(
        crate::integrations::js::stringify(&Value::Array(v)).as_bytes(),
    ))
}

#[cfg(test)]
mod tests;
