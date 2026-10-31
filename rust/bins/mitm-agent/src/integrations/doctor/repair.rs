//! A Doctor repair of one failed step of an agent's template (`doctor-repair.ts`,
//! docs/plans/template-ai-sessions.md, "Repair"): the facts asked of the AGENT before the code is
//! sent, the first message written here, and the check of what the repair changed. Nothing in this
//! file is taken from the control plane.

use std::sync::LazyLock;

use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const REPAIR_WINDOW_MS: i64 = 60 * 60_000;

fn re(p: &str) -> Regex {
    Regex::new(p).expect("pattern")
}

static TEMPLATE: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,62}$"));
/// A step of the template itself. One of a shared bundle (`bundle/step`) is not repaired here.
pub static REPAIR_STEP: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,62}$"));
static ANY_STEP: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-z0-9][a-z0-9-]{0,62}(/[a-z0-9][a-z0-9-]{0,62})?$"));
static HASH: LazyLock<Regex> = LazyLock::new(|| re(r"^[a-f0-9]{12,64}$"));
/// A path the agent names, put in a command line of the first message.
pub static PATH: LazyLock<Regex> = LazyLock::new(|| re(r"^/[A-Za-z0-9._/-]{1,300}$"));
static FILE_PATH: LazyLock<Regex> =
    LazyLock::new(|| re(r"^(README\.md|(files|scripts)/[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)$"));
pub static STAND_IN: LazyLock<Regex> =
    LazyLock::new(|| re(r"\b(cctc_|ccb_)[A-Za-z0-9_-]{8,}|\bCC-[A-Z]{2,12}-[A-Fa-f0-9]{16,}"));
const MIN_SECRET: usize = 8;

/// The same limits a template of an organization has (`BUNDLE_LIMITS`).
pub const PACK_FILES: usize = 40;
pub const PACK_FILE_BYTES: usize = 64 * 1024;
pub const PACK_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairFacts {
    pub template: String,
    pub hash: String,
    pub org: bool,
    /// The steps that failed in the agent's last run: the one it stopped at first.
    pub failed_steps: Vec<String>,
    pub dir: String,
    pub repair_dir: String,
    pub vars: Option<String>,
}

fn path_ok(p: &str) -> bool {
    PATH.is_match(p) && !p.split('/').any(|x| x == "..")
}

/// The agent's answer to `/templates/repair/facts`, or None for one that is not in its form.
pub fn read_repair_facts(raw: &Map<String, Value>) -> Option<RepairFacts> {
    let s = |k: &str| raw.get(k).and_then(Value::as_str);
    let template = s("template").filter(|t| TEMPLATE.is_match(t))?;
    let hash = s("hash").filter(|h| HASH.is_match(h))?;
    let dir = s("dir").filter(|d| path_ok(d))?;
    let repair_dir = s("repairDir").filter(|d| path_ok(d))?;
    let failed = raw.get("failedSteps")?.as_array()?;
    if failed.len() > 300 {
        return None;
    }
    let failed_steps: Option<Vec<String>> = failed
        .iter()
        .map(|x| x.as_str().filter(|x| ANY_STEP.is_match(x)).map(String::from))
        .collect();
    let vars = match raw.get("vars") {
        None | Some(Value::Null) => None,
        Some(Value::String(v)) if path_ok(v) => Some(v.clone()),
        Some(_) => return None,
    };
    Some(RepairFacts {
        template: template.into(),
        hash: hash.into(),
        org: raw.get("org") == Some(&Value::Bool(true)),
        failed_steps: failed_steps?,
        dir: dir.into(),
        repair_dir: repair_dir.into(),
        vars,
    })
}

/// What the session is named in the code message and on the record: all of it from the agent's answer.
pub fn repair_subject(f: &RepairFacts, step: &str) -> String {
    format!(
        "step \"{step}\" of template \"{}\" (files {})",
        f.template,
        &f.hash[..12.min(f.hash.len())]
    )
}

/// The first message of a repair, written here. The model gets no text from the console.
pub fn repair_prompt(f: &RepairFacts, step: &str, session_id: &str) -> String {
    let as_ = if f.org {
        format!(" --as {}", f.template)
    } else {
        String::new()
    };
    let run = format!(
        "sudo -u controlclaw cc-runbook run {} --from {step} --repairs{}{as_}",
        f.dir,
        f.vars.as_ref().map(|v| format!(" --vars {v}")).unwrap_or_default()
    );
    [
        format!("Step \"{step}\" of the template \"{}\" failed on the agent. Repair that step so that it works there.", f.template),
        String::new(),
        "Run every command below on the agent, through this session's SSH connection to it. None of them is for this firewall, and the folders they name are on the agent.".into(),
        String::new(),
        format!("1. Run: sudo -u controlclaw cc-runbook repair {} --session {session_id}{as_}", f.dir),
        format!("   It prints a folder ({}) with a fresh copy of the template's files, made for this session. Edit the copy. Leave {} as it is.", f.repair_dir, f.dir),
        "2. Read the step in template.yaml and the script or files it names. To see why it fails, run it again with the files of the copy:".into(),
        format!("   {run}"),
        "3. Change only the files this step uses, in the copy. A change to a file of another step is shown to the owner as one that does not belong to this repair. Do not change template.yaml: it must stay the same byte for byte, or the copy is not used.".into(),
        "   Write no secret, token or password into a file. Refer to a secret as ${NAME}.".into(),
        "4. Run the step again until it holds. Then say in a few lines what you changed and why.".into(),
        String::new(),
        "When the session ends, the firewall reads the changed files and shows them to the owner as a proposed update to the template. Files that hold a secret are refused.".into(),
    ]
    .join("\n")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairFile {
    pub path: String,
    pub executable: bool,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RepairPack {
    pub base: String,
    pub files: Vec<RepairFile>,
    pub before: Vec<RepairFile>,
    pub steps: Vec<String>,
}

/// What is kept with the transcript: the step that was repaired and what the repair changed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RepairRecord {
    pub template: String,
    pub hash: String,
    pub step: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<RepairPack>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problems: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_hash: Option<String>,
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A secret as a file may hold it: plain, base64, base64url, URL-encoded; at least 8 long.
pub fn forms(value: &str) -> Vec<String> {
    let all = [
        value.to_string(),
        base64::engine::general_purpose::STANDARD.encode(value.as_bytes()),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes()),
        encode_uri_component(value),
    ];
    let mut out: Vec<String> = Vec::new();
    for f in all {
        if f.encode_utf16().count() >= MIN_SECRET && !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// `[...new Set(problems)].slice(0, 20)`.
pub fn unique(problems: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in problems {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out.truncate(20);
    out
}

const NOT_A_REPAIR: &str = "the agent's answer is not in the form of a repair";

/// One file of an agent's answer: exactly `path`, `executable`, `content`.
pub fn read_file(item: &Value) -> Option<RepairFile> {
    let o = item.as_object()?;
    if o.len() != 3 {
        return None;
    }
    Some(RepairFile {
        path: o.get("path")?.as_str()?.into(),
        executable: o.get("executable")?.as_bool()?,
        content: o.get("content")?.as_str()?.into(),
    })
}

/// Sizes and text: a file over its cap, or not text, is a problem.
pub fn sized(path: &str, content: &str, total: &mut usize, problems: &mut Vec<String>) -> bool {
    let size = content.len();
    *total += size;
    if size > PACK_FILE_BYTES {
        problems.push(format!("{path}: larger than {} KB", PACK_FILE_BYTES / 1024));
        return false;
    }
    if content.contains('\0') || content.contains('\u{FFFD}') {
        problems.push(format!("{path}: is not a text file"));
        return false;
    }
    true
}

fn file_list(raw: Option<&Value>, problems: &mut Vec<String>) -> Vec<RepairFile> {
    let Some(list) = raw.and_then(Value::as_array).filter(|l| l.len() <= PACK_FILES) else {
        problems.push(format!("a repair changes at most {PACK_FILES} files"));
        return vec![];
    };
    let mut files: Vec<RepairFile> = Vec::new();
    let mut total = 0usize;
    for item in list {
        let Some(f) = read_file(item) else {
            problems.push(NOT_A_REPAIR.into());
            continue;
        };
        // `template.yaml` is not among them: a repair leaves it as it is.
        if f.path.encode_utf16().count() > 200
            || !FILE_PATH.is_match(&f.path)
            || f.path.split('/').any(|p| p == "." || p == "..")
        {
            problems.push("a changed file has a path a template cannot have".into());
            continue;
        }
        if files.iter().any(|x| x.path == f.path) {
            problems.push(format!("{}: this file is there twice", f.path));
            continue;
        }
        if !sized(&f.path, &f.content, &mut total, problems) {
            continue;
        }
        files.push(f);
    }
    if total > PACK_TOTAL_BYTES {
        problems.push(format!(
            "the changed files are larger than {} KB in all",
            PACK_TOTAL_BYTES / 1024
        ));
    }
    files
}

/// Every line of `files` checked for a secret in any of its forms, and for a stand-in.
pub fn scan(files: &[&RepairFile], secrets: &[String], problems: &mut Vec<String>) {
    let needles: Vec<String> = secrets.iter().flat_map(|s| forms(s)).collect();
    for f in files {
        for (i, line) in f.content.split('\n').enumerate() {
            if needles.iter().any(|n| line.contains(n.as_str())) {
                problems.push(format!(
                    "{}: line {} holds a value this firewall keeps secret",
                    f.path,
                    i + 1
                ));
            } else if STAND_IN.is_match(line) {
                problems.push(format!(
                    "{}: line {} holds a stand-in that belongs to this agent only",
                    f.path,
                    i + 1
                ));
            }
        }
    }
}

/// The agent's pack, read as text from a box a model had root on. A pack with a problem is refused
/// whole; nothing is masked.
pub fn read_repair_pack(raw: &Value, hash: &str, secrets: &[String]) -> Result<RepairPack, Vec<String>> {
    let Some(o) = raw.as_object() else {
        return Err(vec![NOT_A_REPAIR.into()]);
    };
    let mut problems = Vec::new();
    let known = ["base", "files", "before", "steps"];
    let base = o.get("base").and_then(Value::as_str);
    let base_ok =
        base.is_some_and(|b| b.len() == 64 && b.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
    if o.keys().any(|k| !known.contains(&k.as_str())) || !base_ok {
        problems.push(NOT_A_REPAIR.into());
    } else if base != Some(hash) {
        // The files the code message named. An agent whose template changed since is not the one confirmed.
        problems.push("the template's files on the agent are not the ones this repair was confirmed for".into());
    }
    let files = file_list(o.get("files"), &mut problems);
    let before = file_list(o.get("before"), &mut problems);
    if files.is_empty() && problems.is_empty() {
        problems.push("the repair changed no file".into());
    }
    if before.iter().any(|b| !files.iter().any(|f| f.path == b.path)) {
        problems.push(NOT_A_REPAIR.into());
    }
    let steps: Option<Vec<String>> = o
        .get("steps")
        .and_then(Value::as_array)
        .filter(|s| s.len() <= 100)
        .and_then(|s| {
            s.iter()
                .map(|x| x.as_str().filter(|x| REPAIR_STEP.is_match(x)).map(String::from))
                .collect()
        });
    if steps.is_none() {
        problems.push(NOT_A_REPAIR.into());
    }
    let all: Vec<&RepairFile> = files.iter().chain(before.iter()).collect();
    scan(&all, secrets, &mut problems);
    if !problems.is_empty() {
        return Err(unique(problems));
    }
    Ok(RepairPack {
        base: base.unwrap_or_default().into(),
        files,
        before,
        steps: steps.unwrap_or_default(),
    })
}

/// The agent's own refusals, kept as short lines of text; a line that holds a secret is dropped.
pub fn read_repair_problems(raw: Option<&Value>, secrets: &[String]) -> Vec<String> {
    let Some(list) = raw.and_then(Value::as_array) else {
        return vec!["The agent could not read the repair's changes.".into()];
    };
    let needles: Vec<String> = secrets.iter().flat_map(|s| forms(s)).collect();
    let lines: Vec<String> = list
        .iter()
        .filter_map(Value::as_str)
        .map(|p| {
            let clean: String = p
                .chars()
                .map(|c| if (c as u32) < 0x20 || c as u32 == 0x7f { ' ' } else { c })
                .collect();
            crate::integrations::connectors::firewall::js_slice(&clean, 300)
        })
        .filter(|p| !p.trim().is_empty() && !needles.iter().any(|n| p.contains(n.as_str())) && !STAND_IN.is_match(p))
        .collect();
    if lines.is_empty() {
        return vec!["The agent refused the repair's changes.".into()];
    }
    lines.into_iter().take(20).collect()
}

/// `packHash`: what a kept pack is, in one value.
pub fn pack_hash(p: &RepairPack) -> String {
    use sha2::{Digest, Sha256};
    let files: Vec<Value> = p
        .files
        .iter()
        .map(|f| serde_json::json!([f.path, f.executable, f.content]))
        .collect();
    let v = serde_json::json!([p.base, files]);
    hex::encode(Sha256::digest(crate::integrations::js::stringify(&v).as_bytes()))
}

#[cfg(test)]
mod tests;
