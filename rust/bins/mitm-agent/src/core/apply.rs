//! The code for applying a template, a skill or shared notes to agents that already run
//! (`apply.ts`). The console names the agents by id and, for each, the preview it made; where an
//! agent is and what it is called come from this firewall's record. Each agent is asked what its
//! preview holds (`GET /apply/pending`), the message is written from those answers, and after the
//! right code each agent gets a ticket for its own hash (`POST /apply/ticket`). Nothing is stored;
//! no recovery-key fallback.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::agent_client::{AgentClient, AgentError, AgentTarget};
use super::code_message::{CodeParts, Details, FACTS_MAX, Laid, TypedLine, clean_line, cost, record_host, record_name};
use super::identities::Agents;
use super::kit::{CHANNELS_UNREADABLE, Kit, awaiting, fail, obj, ok, text};
use super::now_ms;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeSent};

pub const APPLY_MAX_AGENTS: usize = 20;
pub const APPLY_PROPOSALS_MAX: usize = 6;
pub const APPLY_PROPOSALS_WINDOW_MS: u64 = 10 * 60_000;
pub const APPLY_NAME_MAX: usize = 200;
/// As long as a ticket lasts on the agent.
pub const MCP_GRANT_MS: u64 = 30 * 60_000;
/// Room kept in the first part for the sentence about what the template is filled with.
const FILLED_ROOM: i64 = 220;

static ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,64}$").expect("re"));
static REF: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{8,64}$").expect("re"));
static NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,62}$").expect("re"));
static HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("re"));
static SKILL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,63}$").expect("re"));
/// `MCP_NAME_RE` (`mcp-servers.ts`, W5).
static MCP_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{0,39}$").expect("re"));

#[derive(Debug, Clone)]
struct ApplyAgent {
    vm_id: String,
    name: String,
    hostname: String,
    r#ref: String,
    /// Auto approve rules the template adds for this agent (its `security_create_rule` steps),
    /// put in this firewall's store under the same code.
    auto: Vec<cc_contracts::auto_approve::AutoRule>,
}

/// The most Auto approve rules one apply adds for one agent.
pub const APPLY_AUTO_MAX: usize = 20;

impl ApplyAgent {
    fn target(&self) -> AgentTarget {
        AgentTarget::new(&self.vm_id, &self.hostname)
    }
    fn label(&self) -> String {
        format!("{} ({})", self.name, record_host(Some(&self.hostname)))
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Facts {
    Notes {
        name: String,
        hash: String,
        files: u64,
        always: bool,
        bytes: u64,
        replaces: bool,
        changed: bool,
        payload: String,
    },
    Skill {
        name: String,
        hash: String,
        files: u64,
        runnable: u64,
        settings: u64,
        replaces: bool,
        changed: bool,
        payload: String,
    },
    Template {
        name: String,
        hash: String,
        org: bool,
        beside: bool,
        steps: u64,
        change: u64,
        scripts: u64,
        filled_name: String,
        note: String,
        note_cut: bool,
        payload: String,
        mcp: Vec<String>,
    },
}

impl Facts {
    fn kind(&self) -> &'static str {
        match self {
            Facts::Notes { .. } => "notes",
            Facts::Skill { .. } => "skill",
            Facts::Template { .. } => "template",
        }
    }
    fn name(&self) -> &str {
        match self {
            Facts::Notes { name, .. } | Facts::Skill { name, .. } | Facts::Template { name, .. } => name,
        }
    }
    fn hash(&self) -> &str {
        match self {
            Facts::Notes { hash, .. } | Facts::Skill { hash, .. } | Facts::Template { hash, .. } => hash,
        }
    }
    fn payload(&self) -> &str {
        match self {
            Facts::Notes { payload, .. } | Facts::Skill { payload, .. } | Facts::Template { payload, .. } => payload,
        }
    }
    fn changed(&self) -> bool {
        match self {
            Facts::Notes { changed, .. } | Facts::Skill { changed, .. } => *changed,
            Facts::Template { .. } => false,
        }
    }
    fn replaces(&self) -> bool {
        match self {
            Facts::Notes { replaces, .. } | Facts::Skill { replaces, .. } => *replaces,
            Facts::Template { .. } => false,
        }
    }
}

/// As the agent computes it (`overwriteTicket`).
pub fn overwrite_ticket(hash: &str) -> String {
    hex::encode(Sha256::digest(format!("{hash}\0overwrite").as_bytes()))
}

/// A count an agent gave: a whole number 0..=1000.
fn count(v: Option<&Value>) -> Option<u64> {
    let n = v?.as_f64()?;
    (n.fract() == 0.0 && (0.0..=1000.0).contains(&n)).then_some(n as u64)
}

fn str_re<'a>(raw: &'a Map<String, Value>, k: &str, re: &Regex) -> Option<&'a str> {
    raw.get(k).and_then(Value::as_str).filter(|s| re.is_match(s))
}

/// An optional boolean: absent is fine, anything else not a boolean fails.
fn opt_bool(raw: &Map<String, Value>, k: &str) -> Result<bool, ()> {
    match raw.get(k) {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(()),
    }
}

/// `parseFacts`.
fn parse_facts(raw: &Map<String, Value>) -> Option<Facts> {
    let kind = raw.get("kind").and_then(Value::as_str);
    if kind == Some("notes") {
        let files = count(raw.get("files"));
        let name = str_re(raw, "name", &SKILL)?;
        let hash = str_re(raw, "hash", &HASH)?;
        let bytes = raw
            .get("bytes")
            .and_then(Value::as_f64)
            .filter(|b| b.fract() == 0.0 && (0.0..=(64.0 * 1024.0 * 1024.0)).contains(b));
        let always = raw.get("always").and_then(Value::as_bool);
        let replaces = raw.get("replaces").and_then(Value::as_bool);
        let changed = opt_bool(raw, "changed").ok()?;
        let (Some(files), Some(bytes), Some(always), Some(replaces)) =
            (files.filter(|f| *f >= 1), bytes, always, replaces)
        else {
            return None;
        };
        let payload = if changed {
            overwrite_ticket(hash)
        } else {
            hash.to_string()
        };
        if raw.get("payload").and_then(Value::as_str) != Some(payload.as_str()) {
            return None;
        }
        return Some(Facts::Notes {
            name: name.into(),
            hash: hash.into(),
            files,
            always,
            bytes: bytes as u64,
            replaces: replaces || changed,
            changed,
            payload,
        });
    }
    if kind == Some("skill") {
        let name = str_re(raw, "name", &SKILL)?;
        let hash = str_re(raw, "hash", &HASH)?;
        let (Some(files), Some(runnable), Some(settings)) = (
            count(raw.get("files")),
            count(raw.get("runnable")),
            count(raw.get("settings")),
        ) else {
            return None;
        };
        if files < 1 || runnable > files {
            return None;
        }
        let replaces = opt_bool(raw, "replaces").ok()?;
        let changed = opt_bool(raw, "changed").ok()?;
        let payload = if changed {
            overwrite_ticket(hash)
        } else {
            hash.to_string()
        };
        if raw.get("payload").and_then(Value::as_str) != Some(payload.as_str()) {
            return None;
        }
        return Some(Facts::Skill {
            name: name.into(),
            hash: hash.into(),
            files,
            runnable,
            settings,
            replaces: replaces || changed,
            changed,
            payload,
        });
    }
    let (steps, change, scripts) = (
        count(raw.get("steps")),
        count(raw.get("change")),
        count(raw.get("scripts")),
    );
    if kind != Some("template") {
        return None;
    }
    let name = str_re(raw, "name", &NAME)?;
    let hash = str_re(raw, "hash", &HASH)?;
    let payload = str_re(raw, "payload", &HASH)?;
    let note = raw
        .get("note")
        .and_then(Value::as_str)
        .filter(|n| n.encode_utf16().count() <= 2000)?;
    let note_cut = raw.get("noteCut").and_then(Value::as_bool)?;
    let filled_name = raw
        .get("filledName")
        .and_then(Value::as_str)
        .filter(|n| n.encode_utf16().count() <= APPLY_NAME_MAX)?;
    let (Some(steps), Some(change), Some(scripts)) = (steps, change, scripts) else {
        return None;
    };
    if change > steps || scripts > steps {
        return None;
    }
    let mcp = match raw.get("mcp") {
        None => Vec::new(),
        Some(Value::Array(l))
            if l.len() <= 20 && l.iter().all(|n| n.as_str().is_some_and(|s| MCP_NAME.is_match(s))) =>
        {
            let mut out: Vec<String> = Vec::new();
            for n in l.iter().filter_map(Value::as_str) {
                if !out.iter().any(|x| x == n) {
                    out.push(n.into());
                }
            }
            out
        }
        Some(_) => return None,
    };
    let org = raw.get("org") == Some(&Value::Bool(true));
    Some(Facts::Template {
        name: name.into(),
        hash: hash.into(),
        org,
        beside: org && raw.get("beside") == Some(&Value::Bool(true)),
        steps,
        change,
        scripts,
        filled_name: filled_name.into(),
        note: note.into(),
        note_cut,
        payload: payload.into(),
        mcp,
    })
}

fn facts_json(f: &Facts) -> Value {
    match f {
        Facts::Notes {
            name,
            hash,
            files,
            always,
            bytes,
            replaces,
            changed,
            payload,
        } => {
            json!({"kind": "notes", "name": name, "hash": hash, "files": files, "always": always, "bytes": bytes, "replaces": replaces, "changed": changed, "payload": payload})
        }
        Facts::Skill {
            name,
            hash,
            files,
            runnable,
            settings,
            replaces,
            changed,
            payload,
        } => {
            json!({"kind": "skill", "name": name, "hash": hash, "files": files, "runnable": runnable, "settings": settings, "replaces": replaces, "changed": changed, "payload": payload})
        }
        Facts::Template {
            name,
            hash,
            org,
            beside,
            steps,
            change,
            scripts,
            filled_name,
            note,
            note_cut,
            payload,
            mcp,
        } => json!({
            "kind": "template", "name": name, "hash": hash, "org": org, "beside": beside, "steps": steps, "change": change,
            "scripts": scripts, "filledName": filled_name, "note": note, "noteCut": note_cut, "payload": payload, "mcp": mcp,
        }),
    }
}

#[derive(Debug, Clone)]
struct Proposal {
    change_id: String,
    agents: Vec<ApplyAgent>,
    facts: Vec<Facts>,
}

impl Proposal {
    fn to_json(&self) -> Value {
        json!({
            "changeId": self.change_id,
            "agents": self.agents.iter().map(|a| {
                let mut o = json!({"vmId": a.vm_id, "name": a.name, "hostname": a.hostname, "ref": a.r#ref});
                if !a.auto.is_empty() {
                    o["autoApprove"] = json!(a.auto);
                }
                o
            }).collect::<Vec<_>>(),
            "facts": self.facts.iter().map(facts_json).collect::<Vec<_>>(),
        })
    }
    fn from_json(v: &Value) -> Option<Self> {
        let agents = v
            .get("agents")?
            .as_array()?
            .iter()
            .map(|a| {
                let s = |k: &str| a.get(k).and_then(Value::as_str).map(str::to_string);
                let auto = match a.get("autoApprove") {
                    None => Vec::new(),
                    Some(v) => v
                        .as_array()?
                        .iter()
                        .map(|r| super::auto_approve::parse_rule(r).ok())
                        .collect::<Option<Vec<_>>>()?,
                };
                Some(ApplyAgent {
                    vm_id: s("vmId")?,
                    name: s("name")?,
                    hostname: s("hostname")?,
                    r#ref: s("ref")?,
                    auto,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        let facts = v
            .get("facts")?
            .as_array()?
            .iter()
            .map(|f| f.as_object().and_then(parse_facts))
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            change_id: v.get("changeId")?.as_str()?.into(),
            agents,
            facts,
        })
    }
}

fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

fn template_words(org: bool, beside: bool, name: &str, hash: &str) -> String {
    if org {
        format!(
            "your organization's {} \"{name}\" (files {})",
            if beside { "bundle" } else { "template" },
            short(hash)
        )
    } else {
        format!("ControlClaw's template \"{name}\"")
    }
}

/// The first ten names, and how many more.
fn some_names(names: &[String]) -> String {
    if names.len() <= 10 {
        names.join(", ")
    } else {
        format!("{} and {} more", names[..10].join(", "), names.len() - 10)
    }
}

/// JS `toFixed(d)` for the sizes here: an exact tie rounds up (Rust's formatting rounds it to
/// even). The sizes are bytes over powers of two, so `v * 10^d` is exact.
fn fixed(v: f64, d: usize) -> String {
    let scale = 10f64.powi(d as i32);
    format!("{:.d$}", (v * scale).round() / scale)
}

fn size_text(bytes: u64) -> String {
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{} KB", fixed(b / 1024.0, if bytes < 10 * 1024 { 1 } else { 0 }))
    } else {
        format!("{} MB", fixed(b / 1024.0 / 1024.0, 1))
    }
}

/// `listAgents`: as many as fit the first part, by this firewall's record, the rest counted.
fn list_agents(agents: &[ApplyAgent]) -> String {
    let mut listed: Vec<String> = Vec::new();
    for a in agents {
        let next = a.label();
        let mut trial = listed.clone();
        trial.push(next.clone());
        if cost(&trial.join("; ")) > FACTS_MAX - FILLED_ROOM - 200 {
            break;
        }
        listed.push(next);
    }
    let rest = agents.len() - listed.len();
    format!(
        "{}{}",
        listed.join("; "),
        if rest > 0 {
            format!("; and {rest} more")
        } else {
            String::new()
        }
    )
}

/// `summarize`: in this firewall's words, from facts it can stand behind.
fn summarize(p: &Proposal) -> String {
    let one = p.agents.len() == 1;
    match &p.facts[0] {
        Facts::Notes {
            name,
            hash,
            files,
            always,
            ..
        } => {
            let what = format!("the shared notes \"{name}\" (files {})", short(hash));
            let has = format!(
                "{}{}",
                plural(*files, "file", "files"),
                if *always {
                    ", one of them loaded into every conversation"
                } else {
                    ""
                }
            );
            if one {
                format!("Put {what} on {}: {has}", p.agents[0].label())
            } else {
                format!(
                    "Put {what} on {} agents: {}: {has}",
                    p.agents.len(),
                    list_agents(&p.agents)
                )
            }
        }
        Facts::Skill {
            name,
            hash,
            files,
            runnable,
            settings,
            ..
        } => {
            let what = format!("the skill \"{name}\" (files {})", short(hash));
            let overwrites = p
                .facts
                .iter()
                .filter(|f| matches!(f, Facts::Skill { changed: true, .. }))
                .count() as u64;
            let sets = if *settings > 0 {
                format!(", and {}", plural(*settings, "settings step", "settings steps"))
            } else {
                String::new()
            };
            let over = if overwrites == 0 {
                String::new()
            } else if one {
                ". It overwrites changes made to the agent's copy".into()
            } else {
                format!(
                    ". It overwrites changes made to the copy on {}",
                    plural(overwrites, "agent", "agents")
                )
            };
            let has = format!(
                "{}, {runnable} of which can be run{sets}{over}",
                plural(*files, "file", "files")
            );
            if one {
                format!("Install {what} on {}: {has}", p.agents[0].label())
            } else {
                format!(
                    "Install {what} on {} agents: {}: {has}",
                    p.agents.len(),
                    list_agents(&p.agents)
                )
            }
        }
        Facts::Template {
            name,
            hash,
            org,
            beside,
            steps,
            change,
            scripts,
            ..
        } => {
            let what = template_words(*org, *beside, name, hash);
            let rules: usize = p.agents.iter().map(|a| a.auto.len()).sum();
            let scripts = format!(
                "{}{}",
                if *scripts > 0 {
                    format!(", {} a script", plural(*scripts, "runs", "run"))
                } else {
                    String::new()
                },
                if rules > 0 {
                    format!(
                        ", and it adds {}",
                        plural(rules as u64, "Auto approve rule", "Auto approve rules")
                    )
                } else {
                    String::new()
                }
            );
            if one {
                return format!(
                    "Apply {what} to {}: {change} of {} on the agent would change{scripts}",
                    p.agents[0].label(),
                    plural(*steps, "step", "steps")
                );
            }
            let head = format!("Apply {what} to {} agents: ", p.agents.len());
            let end = format!(": {} on each agent{scripts}", plural(*steps, "step", "steps"));
            let more = |n: usize| format!("; and {n} more");
            let mut listed: Vec<String> = Vec::new();
            for a in &p.agents {
                let next = a.label();
                let left = p.agents.len() - listed.len() - 1;
                let mut trial = listed.clone();
                trial.push(next.clone());
                let text = format!(
                    "{head}{}{}{end}",
                    trial.join("; "),
                    if left > 0 { more(left) } else { String::new() }
                );
                if cost(&text) > FACTS_MAX - FILLED_ROOM {
                    break;
                }
                listed.push(next);
            }
            let rest = p.agents.len() - listed.len();
            format!(
                "{head}{}{}{end}",
                listed.join("; "),
                if rest > 0 { more(rest) } else { String::new() }
            )
        }
    }
}

/// `typedLines`: the name and note a template is filled with, for the message's last part.
fn typed_lines(p: &Proposal) -> Vec<TypedLine> {
    let one = p.agents.len() == 1;
    let mut lines = Vec::new();
    for (agent, f) in p.agents.iter().zip(&p.facts) {
        let Facts::Template {
            filled_name,
            note,
            note_cut,
            ..
        } = f
        else {
            continue;
        };
        if clean_line(filled_name).0 != agent.name {
            lines.push(TypedLine {
                label: if one {
                    "Name in the template's files".into()
                } else {
                    format!("Name of {} in the template's files", agent.name)
                },
                text: if filled_name.is_empty() {
                    " ".into()
                } else {
                    filled_name.clone()
                },
                more: None,
            });
        }
        if !note.is_empty() {
            lines.push(TypedLine {
                label: if one {
                    "Note".into()
                } else {
                    format!("Note for {}", agent.name)
                },
                text: note.clone(),
                more: note_cut.then(|| "(and more: the agent gave only the start of it)".to_string()),
            });
        }
    }
    lines
}

/// The Auto approve rules a template adds, in the firewall's words (part one): what each does, from
/// its fields; its name and text are typed, so they are at the end ([`auto_lines`]).
fn auto_words(p: &Proposal) -> String {
    let all: Vec<(&ApplyAgent, &cc_contracts::auto_approve::AutoRule)> = p
        .agents
        .iter()
        .flat_map(|a| a.auto.iter().map(move |r| (a, r)))
        .collect();
    if all.is_empty() {
        return String::new();
    }
    let n = plural(all.len() as u64, "Auto approve rule", "Auto approve rules");
    if all.len() > 3 {
        return format!(" It adds {n} to your firewall; each is at the end of this message.");
    }
    let each: Vec<String> = all
        .iter()
        .map(|(a, r)| super::auto_approve::rule_words(r, &a.name))
        .collect();
    format!(" It adds {n} to your firewall: {}.", each.join("; "))
}

/// Each added rule's name and text, for the message's last part.
fn auto_lines(p: &Proposal) -> Vec<TypedLine> {
    let mut lines = Vec::new();
    for a in &p.agents {
        for r in &a.auto {
            lines.push(TypedLine {
                label: format!("Auto approve rule for {}", a.name),
                text: r.name.clone(),
                more: None,
            });
            if let Some(t) = r.title() {
                lines.push(TypedLine {
                    label: format!("Its text ({})", if r.exact() { "exactly" } else { "contains" }),
                    text: t.to_string(),
                    more: None,
                });
            }
        }
    }
    lines
}

/// `messageParts`.
fn message_parts(p: &Proposal) -> CodeParts {
    let one = p.agents.len() == 1;
    let names_where = |pred: &dyn Fn(&Facts) -> bool| -> Vec<String> {
        p.agents
            .iter()
            .zip(&p.facts)
            .filter(|(_, f)| pred(f))
            .map(|(a, _)| a.name.clone())
            .collect()
    };
    match &p.facts[0] {
        Facts::Notes {
            name,
            hash,
            files,
            always,
            bytes,
            ..
        } => {
            let what = format!("the shared notes \"{name}\" (files {})", short(hash));
            let over = names_where(&|f| f.replaces());
            let edited = names_where(&|f| f.changed());
            let lost = if edited.is_empty() {
                String::new()
            } else if one {
                "The agent's copy was changed there; this overwrites those changes. ".into()
            } else if edited.len() == p.agents.len() {
                "Each agent's copy was changed there; this overwrites those changes. ".into()
            } else {
                format!(
                    "The copy on {} was changed there; this overwrites those changes. ",
                    some_names(&edited)
                )
            };
            let replaces = if over.is_empty() {
                String::new()
            } else if one {
                " It replaces the set of that name already on the agent.".into()
            } else if over.len() == p.agents.len() {
                " It replaces the set of that name already on each of them.".into()
            } else {
                format!(" It replaces the set of that name already on {}.", over.join(", "))
            };
            let has = format!(
                "It has {} of notes ({}) the agent can search; nothing in it is run.{replaces} {} Compare the files' version with the one on the notes' page in your console.",
                plural(*files, "file", "files"),
                size_text(*bytes),
                if *always {
                    "One file is loaded into every conversation of the agent."
                } else {
                    "No file is loaded into every conversation."
                }
            );
            if one {
                CodeParts {
                    ask: format!("Put {what} on {}", p.agents[0].label()),
                    details: Some(Details::Text(format!("{lost}{has}"))),
                    ..Default::default()
                }
            } else {
                CodeParts {
                    ask: format!("Put {what} on {} agents", p.agents.len()),
                    details: Some(Details::Text(format!(
                        "{lost}The agents: {}. {has}",
                        list_agents(&p.agents)
                    ))),
                    ..Default::default()
                }
            }
        }
        Facts::Skill {
            name,
            hash,
            files,
            runnable,
            settings,
            ..
        } => {
            let what = format!("the skill \"{name}\" (files {})", short(hash));
            let sets = if *settings > 0 {
                format!(
                    " It also changes settings: {} from its controlclaw.yaml.",
                    plural(*settings, "settings step", "settings steps")
                )
            } else {
                String::new()
            };
            let said = |names: Vec<String>, single: &str, all: &str, some: &dyn Fn(String) -> String| -> String {
                if names.is_empty() {
                    String::new()
                } else if one {
                    single.into()
                } else if names.len() == p.agents.len() {
                    all.into()
                } else {
                    some(some_names(&names))
                }
            };
            let over = said(
                names_where(&|f| f.replaces()),
                "It replaces the skill of that name already on the agent. ",
                "It replaces the skill of that name already on each of them. ",
                &|l| format!("It replaces the skill of that name already on {l}. "),
            );
            let lost = said(
                names_where(&|f| f.changed()),
                "The agent's copy was changed there; this overwrites those changes. ",
                "Each agent's copy was changed there; this overwrites those changes. ",
                &|l| format!("The copy on {l} was changed there; this overwrites those changes. "),
            );
            let runs = if *runnable == 0 {
                "none can be run".to_string()
            } else {
                format!("{runnable} can be run")
            };
            let has = format!(
                "It has {}; {runs}.{sets} Compare the files' version with the one on the skill's page in your console.",
                plural(*files, "file", "files")
            );
            if one {
                CodeParts {
                    ask: format!("Install {what} on {}", p.agents[0].label()),
                    details: Some(Details::Text(format!("{lost}{over}{has}"))),
                    ..Default::default()
                }
            } else {
                CodeParts {
                    ask: format!("Install {what} on {} agents", p.agents.len()),
                    details: Some(Details::Text(format!(
                        "{lost}{over}The agents: {}. {has}",
                        list_agents(&p.agents)
                    ))),
                    ..Default::default()
                }
            }
        }
        Facts::Template {
            name,
            hash,
            org,
            beside,
            steps,
            change,
            scripts,
            mcp,
            ..
        } => {
            let mut typed = typed_lines(p);
            let names = typed.iter().any(|l| l.label.starts_with("Name"));
            let notes = typed.iter().any(|l| l.label.starts_with("Note"));
            typed.extend(auto_lines(p));
            let rules = auto_words(p);
            let what = template_words(*org, *beside, name, hash);
            let scripts = if *scripts > 0 {
                format!(", {} a script", plural(*scripts, "runs", "run"))
            } else {
                String::new()
            };
            let servers = if mcp.is_empty() {
                String::new()
            } else {
                format!(
                    " It gives {} your organization's MCP server{} {}.",
                    if one { "the agent" } else { "each agent" },
                    if mcp.len() == 1 { "" } else { "s" },
                    mcp.join(", ")
                )
            };
            let filled_with = match (names, notes, one) {
                (true, true, true) => "a name and a note",
                (true, true, false) => "its name and its note",
                (false, true, true) => "a note",
                (false, true, false) => "its note",
                (_, _, true) => "a name",
                (_, _, false) => "its name",
            };
            let filled = move |laid: Laid| -> String {
                let is = if one { "It is" } else { "Each is" };
                if !names && !notes {
                    return format!("{is} filled with no note.");
                }
                let where_ = if laid.left_out || laid.long {
                    "They follow in this message as far as there is room: read them all in the console's preview before you use the code."
                } else if (names && notes) || !one {
                    "They are at the end of this message."
                } else {
                    "It is at the end of this message."
                };
                format!(
                    "{is} filled with {filled_with}{}. {where_}",
                    if names && !notes { " and no note" } else { "" }
                )
            };
            let steps_text = plural(*steps, "step", "steps");
            if one {
                let change = *change;
                let details = move |laid: Laid| {
                    Ok(format!(
                        "{change} of {steps_text} on the agent would change{scripts}.{servers}{rules} {}",
                        filled(laid)
                    ))
                };
                return CodeParts {
                    ask: format!("Apply {what} to {}", p.agents[0].label()),
                    details: Some(Details::Laid(Arc::new(details))),
                    typed,
                    ..Default::default()
                };
            }
            let mut listed: Vec<String> = Vec::new();
            for a in &p.agents {
                let next = a.label();
                let mut trial = listed.clone();
                trial.push(next.clone());
                if cost(&trial.join("; ")) > FACTS_MAX - FILLED_ROOM - 200 {
                    break;
                }
                listed.push(next);
            }
            let rest = p.agents.len() - listed.len();
            let list = format!(
                "{}{}",
                listed.join("; "),
                if rest > 0 {
                    format!("; and {rest} more")
                } else {
                    String::new()
                }
            );
            let details = move |laid: Laid| {
                Ok(format!(
                    "The agents: {list}. {steps_text} on each agent{scripts}.{servers}{rules} {}",
                    filled(laid)
                ))
            };
            CodeParts {
                ask: format!("Apply {what} to {} agents", p.agents.len()),
                details: Some(Details::Laid(Arc::new(details))),
                typed,
                ..Default::default()
            }
        }
    }
}

#[derive(Default)]
struct St {
    /// Which change waits for a code, by agent.
    waiting: HashMap<String, String>,
    /// When each waiting change's code runs out.
    until: HashMap<String, u64>,
    /// When each agent was last named in a proposal.
    asked: HashMap<String, Vec<u64>>,
    /// Per agent: the organization's MCP servers a confirmed apply gives, until when.
    mcp: HashMap<String, (Vec<String>, u64)>,
}

pub struct Apply {
    agent: AgentClient,
    kit: Kit,
    agents: Arc<Agents>,
    st: Mutex<St>,
    /// The Auto approve rules, which a confirmed template may add to.
    auto: Option<Arc<super::auto_approve::AutoApproveFirewall>>,
}

impl Apply {
    pub fn new(agent: AgentClient, kit: Kit, agents: Arc<Agents>) -> Self {
        Self {
            agent,
            kit,
            agents,
            st: Mutex::new(St::default()),
            auto: None,
        }
    }

    /// The Auto approve rules a confirmed template adds to.
    pub fn with_auto(mut self, store: Arc<super::auto_approve::AutoApproveFirewall>) -> Self {
        self.auto = Some(store);
        self
    }

    fn st(&self) -> std::sync::MutexGuard<'_, St> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `hasMcpGrant`: whether a confirmed apply covers giving this agent this server (W5).
    #[allow(dead_code)]
    pub fn has_mcp_grant(&self, vm_id: &str, name: &str) -> bool {
        self.st()
            .mcp
            .get(vm_id)
            .is_some_and(|(names, until)| *until >= now_ms() && names.iter().any(|n| n == name))
    }

    /// `useMcpGrant`: the server was given.
    #[allow(dead_code)]
    pub fn use_mcp_grant(&self, vm_id: &str, name: &str) {
        let mut st = self.st();
        let Some((names, _)) = st.mcp.get_mut(vm_id) else {
            return;
        };
        names.retain(|n| n != name);
        if names.is_empty() {
            st.mcp.remove(vm_id);
        }
    }

    fn scope(change_id: &str) -> String {
        format!("apply:{change_id}")
    }

    fn forget(&self, change_id: &str) {
        self.kit.consent.forget(&Self::scope(change_id));
        let mut st = self.st();
        st.until.remove(change_id);
        st.waiting.retain(|_, id| id != change_id);
    }

    fn purge(&self) {
        let now = now_ms();
        let gone: Vec<String> = self
            .st()
            .until
            .iter()
            .filter(|(_, u)| **u < now)
            .map(|(c, _)| c.clone())
            .collect();
        for c in gone {
            self.forget(&c);
        }
    }

    /// `admit`: one more proposal for each of these agents, counted when allowed.
    fn admit(&self, vm_ids: &[String]) -> bool {
        let now = now_ms();
        let mut st = self.st();
        st.asked.retain(|_, times| {
            times.retain(|t| now.saturating_sub(*t) < APPLY_PROPOSALS_WINDOW_MS);
            !times.is_empty()
        });
        if vm_ids
            .iter()
            .any(|id| st.asked.get(id).map_or(0, Vec::len) >= APPLY_PROPOSALS_MAX)
        {
            return false;
        }
        for id in vm_ids {
            st.asked.entry(id.clone()).or_default().push(now);
        }
        true
    }

    /// `ticket`: every agent its own; a template stops at the first refusal, a skill or notes
    /// leave the refusing agents out and fail only when none took it.
    async fn ticket(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let hash = p.facts[0].hash().to_string();
        let skill = !matches!(p.facts[0], Facts::Template { .. });
        let (mut took, mut refused): (Vec<&ApplyAgent>, Vec<&ApplyAgent>) = (Vec::new(), Vec::new());
        let mut why = String::new();
        for (agent, f) in p.agents.iter().zip(&p.facts) {
            match self
                .agent
                .post(
                    &agent.target(),
                    "/apply/ticket",
                    &json!({"ref": agent.r#ref, "hash": f.payload()}),
                )
                .await
            {
                Ok(_) => {
                    took.push(agent);
                    if let Facts::Template { mcp, .. } = f
                        && !mcp.is_empty()
                    {
                        let now = now_ms();
                        let mut st = self.st();
                        let mut names: Vec<String> = st
                            .mcp
                            .get(&agent.vm_id)
                            .filter(|(_, u)| *u >= now)
                            .map(|(n, _)| n.clone())
                            .unwrap_or_default();
                        for n in mcp {
                            if !names.contains(n) {
                                names.push(n.clone());
                            }
                        }
                        st.mcp.insert(agent.vm_id.clone(), (names, now + MCP_GRANT_MS));
                    }
                }
                Err(e) => {
                    if !skill {
                        return Err(format!(
                            "{} did not take the confirmation ({e}). Ask for a new preview and try again.",
                            agent.name
                        ));
                    }
                    why = e.to_string();
                    tracing::info!("[apply] {} did not take the confirmation ({why})", agent.name);
                    refused.push(agent);
                }
            }
        }
        if took.is_empty() {
            let who = if refused.len() == 1 {
                format!("{} did", refused[0].name)
            } else {
                "The agents did".to_string()
            };
            return Err(format!(
                "{who} not take the confirmation ({why}). Start the install again."
            ));
        }
        tracing::info!(
            "[apply] confirmed for {}",
            took.iter().map(|a| a.name.as_str()).collect::<Vec<_>>().join(", ")
        );
        let mut out = obj(&[("vmIds", json!(took.iter().map(|a| &a.vm_id).collect::<Vec<_>>()))]);
        if !refused.is_empty() {
            out.insert(
                "refused".into(),
                json!(refused.iter().map(|a| &a.vm_id).collect::<Vec<_>>()),
            );
        }
        out.insert("hash".into(), json!(hash));
        Ok(out)
    }

    pub async fn propose(&self, payload: Map<String, Value>) -> CommandOutcome {
        let malformed = || CommandOutcome::failed("failed", "malformed apply.propose payload");
        let change_id = text(&payload, "changeId").filter(|c| ID.is_match(c));
        let list = payload
            .get("agents")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let Some(change_id) = change_id.filter(|_| !list.is_empty() && list.len() <= APPLY_MAX_AGENTS) else {
            return malformed();
        };
        let mut given = Vec::new();
        for raw in &list {
            let empty = Map::new();
            let a = raw.as_object().unwrap_or(&empty);
            let (Some(vm_id), Some(r)) = (
                text(a, "vmId").filter(|v| ID.is_match(v)),
                text(a, "ref").filter(|r| REF.is_match(r)),
            ) else {
                return malformed();
            };
            if given.iter().any(|(v, _, _): &(String, String, _)| *v == vm_id) {
                return malformed();
            }
            // A template's Auto approve rules for this agent: each one is for this agent only.
            let auto = match a.get("autoApprove") {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(rules)) if rules.len() <= APPLY_AUTO_MAX => {
                    let mut out = Vec::new();
                    for r in rules {
                        let Ok(mut rule) = super::auto_approve::parse_rule(r) else {
                            return malformed();
                        };
                        if rule.vm_id.as_deref().is_some_and(|v| v != vm_id) {
                            return malformed();
                        }
                        rule.vm_id = Some(vm_id.clone());
                        out.push(rule);
                    }
                    out
                }
                Some(_) => return malformed(),
            };
            given.push((vm_id, r, auto));
        }
        let mut data = obj(&[("changeId", json!(change_id))]);
        self.purge();
        // Where each agent is and what it is called: this firewall's record, never the proposal's.
        let mut agents = Vec::new();
        for (vm_id, r, auto) in &given {
            let Some(hostname) = self.agents.host_for(vm_id) else {
                return fail(
                    "failed",
                    "Your firewall does not know that agent. If it was just created, try again in a minute.",
                    data,
                );
            };
            let rec = self
                .agents
                .agents()
                .into_iter()
                .find(|i| super::activity_sanitize::js_string(i.get("vm_id")) == *vm_id);
            let name = rec.and_then(|i| {
                i.get("name")
                    .filter(|n| !n.is_null())
                    .map(|n| super::activity_sanitize::js_string(Some(n)))
            });
            agents.push(ApplyAgent {
                vm_id: vm_id.clone(),
                r#ref: r.clone(),
                hostname,
                name: record_name(name.as_deref(), vm_id),
                auto: auto.clone(),
            });
        }
        if !self.admit(&agents.iter().map(|a| a.vm_id.clone()).collect::<Vec<_>>()) {
            return fail(
                "failed",
                "Too many confirmation codes were asked for this agent in a short time. Wait ten minutes and try again.",
                data,
            );
        }
        // What each agent says its preview found.
        let mut facts = Vec::new();
        for agent in &agents {
            let path = format!(
                "/apply/pending?ref={}",
                url::form_urlencoded::byte_serialize(agent.r#ref.as_bytes()).collect::<String>()
            );
            let answer = match self.agent.get(&agent.target(), &path).await {
                Ok(a) => a,
                Err(e) => {
                    let gone = matches!(&e, AgentError::Status { message, .. } if message.starts_with("agent 404: "));
                    let m = if gone {
                        format!(
                            "{} has no preview waiting to be confirmed. Ask for a new preview.",
                            agent.name
                        )
                    } else {
                        format!(
                            "Your firewall could not ask {} what would be applied ({e}).",
                            agent.name
                        )
                    };
                    return fail("failed", m, data);
                }
            };
            let kind = answer.get("kind").and_then(Value::as_str);
            if kind == Some("template") && (answer.get("payload").is_none() || answer.get("filledName").is_none()) {
                return fail(
                    "failed",
                    format!(
                        "Update {} first: its software is older than your firewall's and cannot say what a code would confirm.",
                        agent.name
                    ),
                    data,
                );
            }
            let Some(said) = parse_facts(&answer) else {
                let m = match kind {
                    Some("skill") | Some("notes") => format!(
                        "{} gave an answer about the {} that your firewall could not read. Start the install again.",
                        agent.name,
                        if kind == Some("notes") { "notes" } else { "skill" }
                    ),
                    _ => format!(
                        "{} gave an answer about its preview that your firewall could not read. Ask for a new preview.",
                        agent.name
                    ),
                };
                return fail("failed", m, data);
            };
            facts.push(said);
        }
        let first = facts[0].clone();
        let same = |f: &Facts| {
            f.kind() == first.kind()
                && f.hash() == first.hash()
                && f.name() == first.name()
                && match (f, &first) {
                    (Facts::Template { org: a, beside: b, .. }, Facts::Template { org: c, beside: d, .. }) => {
                        a == c && b == d
                    }
                    _ => true,
                }
        };
        if !facts.iter().all(same) {
            return fail(
                "failed",
                "These agents do not hold the same files for it, so one code cannot cover them. Apply to them one at a time.",
                data,
            );
        }
        let counts = |f: &Facts| match f {
            Facts::Skill {
                files,
                runnable,
                settings,
                ..
            } => format!("{files}/{runnable}/{settings}"),
            Facts::Notes {
                files, always, bytes, ..
            } => format!("{files}/{always}/{bytes}"),
            Facts::Template { .. } => String::new(),
        };
        if !matches!(first, Facts::Template { .. }) && facts.iter().any(|f| counts(f) != counts(&first)) {
            return fail(
                "failed",
                "These agents do not say the same about its files, so one code cannot cover them. Install on them one at a time.",
                data,
            );
        }
        if !matches!(first, Facts::Template { .. }) && agents.iter().any(|a| !a.auto.is_empty()) {
            return malformed();
        }
        if agents.iter().any(|a| !a.auto.is_empty()) && self.auto.as_ref().is_none_or(|s| !s.active()) {
            return fail(
                "failed",
                "Your firewall does not keep Auto approve rules yet, so it cannot add the template's. Update the firewall, then apply again.",
                data,
            );
        }
        // Checked now, so no code is sent for rules that could not be added (an id already there).
        if let Some(store) = &self.auto {
            let rules: Vec<_> = agents.iter().flat_map(|a| a.auto.iter().cloned()).collect();
            if let Err(m) = store.fits(&rules) {
                return fail("failed", &m, data);
            }
        }
        let p = Proposal {
            change_id: change_id.clone(),
            agents,
            facts,
        };
        let summary = summarize(&p);
        data.insert("summary".into(), json!(summary));
        data.insert("hash".into(), json!(first.hash()));
        data.insert("kind".into(), json!(first.kind()));
        let Some(routes) = self.kit.routes() else {
            return fail("failed", CHANNELS_UNREADABLE, data);
        };
        // One change at a time for each agent.
        for agent in &p.agents {
            let earlier = self.st().waiting.get(&agent.vm_id).cloned();
            if let Some(e) = earlier {
                self.forget(&e);
            }
        }
        // With nobody to tell, an overwrite of an agent's own changes is never done.
        let unsaid: Vec<String> = if routes.is_empty() {
            p.agents
                .iter()
                .zip(&p.facts)
                .filter(|(_, f)| f.changed())
                .map(|(a, _)| a.name.clone())
                .collect()
        } else {
            Vec::new()
        };
        if !unsaid.is_empty() {
            let notes = first.kind() == "notes";
            let m = format!(
                "{} changed {} copy of {}, and nobody in your organization is approved on a chat channel, so your firewall cannot tell anyone that the changes would be overwritten. Approve someone on a channel, or put {} back on {} first.",
                some_names(&unsaid),
                if unsaid.len() == 1 { "its" } else { "their" },
                if notes { "these notes" } else { "this skill" },
                if notes { "the notes" } else { "the skill" },
                if unsaid.len() == 1 {
                    "that agent"
                } else {
                    "those agents"
                }
            );
            return fail("failed", m, data);
        }
        if routes.is_empty() {
            return match self.ticket_and_rules(&p).await {
                Ok(applied) => {
                    data.extend(applied);
                    data.insert("tofu".into(), json!(true));
                    ok("applied", data)
                }
                Err(e) => CommandOutcome::failed("failed", e),
            };
        }
        let subject = if p.agents.len() == 1 {
            p.agents[0].name.clone()
        } else {
            format!("{} agents", p.agents.len())
        };
        let sent = self
            .kit
            .consent
            .send(CodeAsk {
                scope: Self::scope(&change_id),
                change_id: change_id.clone(),
                proposal: p.to_json(),
                agent_name: subject.clone(),
                summary,
                routes,
                parts: Some(message_parts(&p)),
                ..Default::default()
            })
            .await;
        if let CodeSent::Sent {
            sent_via, expires_at, ..
        } = &sent
        {
            let mut st = self.st();
            for agent in &p.agents {
                st.waiting.insert(agent.vm_id.clone(), change_id.clone());
            }
            if let Some(u) = super::ssh::parse_iso_ms(expires_at) {
                st.until.insert(change_id.clone(), u as u64);
            }
            drop(st);
            tracing::info!("[apply] code sent for {subject} via {sent_via}");
        }
        awaiting(sent, data)
    }

    /// The tickets, then the template's Auto approve rules: confirmed by the same code.
    async fn ticket_and_rules(&self, p: &Proposal) -> Result<Map<String, Value>, String> {
        let rules: Vec<_> = p.agents.iter().flat_map(|a| a.auto.iter().cloned()).collect();
        // The rules are checked before any agent gets its ticket, so a template is never applied
        // without them.
        let store = match (&self.auto, rules.is_empty()) {
            (_, true) => None,
            (Some(store), false) => Some(store),
            (None, false) => return Err("Your firewall does not keep Auto approve rules yet.".into()),
        };
        // The rule-change lock from the check to the add: a rule put meanwhile cannot make the add
        // fail after the agents got their tickets.
        let held = match store {
            Some(s) => Some(s.template_lock().await),
            None => None,
        };
        if let (Some(s), Some(_)) = (store, &held) {
            s.fits(&rules)?;
        }
        let mut applied = self.ticket(p).await?;
        if let (Some(store), Some(held)) = (store, &held) {
            store.add_locked(held, &rules)?;
            applied.insert(
                "autoApprove".into(),
                json!(rules.iter().map(|r| r.id.clone()).collect::<Vec<_>>()),
            );
        }
        Ok(applied)
    }

    pub async fn confirm(&self, payload: Map<String, Value>) -> CommandOutcome {
        let Some(change_id) = text(&payload, "changeId") else {
            return CommandOutcome::failed("failed", "malformed apply.confirm payload");
        };
        self.purge();
        let code = text(&payload, "code").unwrap_or_default();
        let data = obj(&[("changeId", json!(change_id))]);
        match self.kit.consent.verify(&Self::scope(&change_id), &change_id, &code) {
            CodeCheck::Expired => {
                self.forget(&change_id);
                fail("expired", "Nothing is waiting for a code, or the code expired.", data)
            }
            CodeCheck::Wrong { tries_left } => {
                if tries_left == 0 {
                    self.forget(&change_id);
                }
                let mut d = data;
                d.insert("attemptsLeft".into(), json!(tries_left));
                fail("invalid_code", "Wrong code.", d)
            }
            CodeCheck::Ok { proposal, sent_via } => {
                self.forget(&change_id);
                let Some(p) = Proposal::from_json(&proposal) else {
                    return CommandOutcome::failed("failed", "That change could not be read.");
                };
                match self.ticket_and_rules(&p).await {
                    Ok(applied) => {
                        let mut d = data;
                        d.extend(applied);
                        d.insert("summary".into(), json!(summarize(&p)));
                        d.insert("sentVia".into(), json!(sent_via));
                        d.insert("tofu".into(), json!(false));
                        ok("applied", d)
                    }
                    Err(e) => CommandOutcome::failed("failed", e),
                }
            }
        }
    }

    pub fn cancel(&self, payload: Map<String, Value>) -> CommandOutcome {
        let change_id = text(&payload, "changeId");
        if let Some(c) = &change_id {
            self.forget(c);
        }
        ok("cancelled", obj(&[("changeId", super::kit::null_or(change_id))]))
    }
}

/// The `McpGrants` slot the MCP server gate reads.
pub struct McpGrants(pub Arc<Apply>);

impl crate::contracts::McpGrants for McpGrants {
    fn has(&self, vm_id: &str, name: &str) -> bool {
        self.0.has_mcp_grant(vm_id, name)
    }

    fn use_grant(&self, vm_id: &str, name: &str) {
        self.0.use_mcp_grant(vm_id, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn agent(name: &str) -> ApplyAgent {
        ApplyAgent {
            vm_id: format!("vm_{name}"),
            name: name.into(),
            hostname: format!("{name}.example"),
            r#ref: "ref_12345".into(),
            auto: vec![],
        }
    }

    #[test]
    fn facts_and_words() {
        let t = json!({"kind": "template", "name": "sales", "hash": H, "org": true, "beside": false, "steps": 4, "change": 2, "scripts": 1, "filledName": "atlas", "note": "hi", "noteCut": false, "payload": H, "mcp": ["crm", "crm"]});
        let f = parse_facts(t.as_object().expect("o")).expect("template");
        assert!(matches!(&f, Facts::Template { mcp, .. } if mcp == &vec!["crm".to_string()]));
        let p = Proposal {
            change_id: "c".into(),
            agents: vec![agent("atlas")],
            facts: vec![f.clone()],
        };
        assert_eq!(
            summarize(&p),
            "Apply your organization's template \"sales\" (files aaaaaaaaaaaa) to atlas (atlas.example): 2 of 4 steps on the agent would change, 1 runs a script"
        );
        assert_eq!(typed_lines(&p).len(), 1);
        let back = Proposal::from_json(&p.to_json()).expect("back");
        assert_eq!(back.facts, p.facts);
        let s = json!({"kind": "skill", "name": "x", "hash": H, "files": 2, "runnable": 1, "settings": 0, "changed": true, "payload": overwrite_ticket(H)});
        let sf = parse_facts(s.as_object().expect("o")).expect("skill");
        assert!(sf.replaces() && sf.changed());
        let bad = json!({"kind": "skill", "name": "x", "hash": H, "files": 2, "runnable": 1, "settings": 0, "payload": H, "changed": "yes"});
        assert!(parse_facts(bad.as_object().expect("o")).is_none());
        assert_eq!(size_text(500), "500 bytes");
        assert_eq!(size_text(2048), "2.0 KB");
        assert_eq!(size_text(20 * 1024), "20 KB");
        // Ties round up, as `toFixed` does.
        assert_eq!(size_text(10752), "11 KB");
        assert_eq!(size_text(1280), "1.3 KB");
    }

    #[test]
    fn a_templates_auto_approve_rules_are_in_the_message_and_kept_with_the_change() {
        let t = json!({"kind": "template", "name": "sales", "hash": H, "org": true, "beside": false, "steps": 4, "change": 2, "scripts": 0, "filledName": "atlas", "note": "", "noteCut": false, "payload": H, "mcp": []});
        let f = parse_facts(t.as_object().expect("o")).expect("template");
        let rule = super::super::auto_approve::parse_rule(&json!({"id": "tpl_git", "name": "Let it run the tests", "kinds": ["exec"], "title_like": "npm test", "vm_id": "vm_atlas", "effect": "allow"})).expect("rule");
        let mut a = agent("atlas");
        a.auto = vec![rule];
        let p = Proposal {
            change_id: "c".into(),
            agents: vec![a],
            facts: vec![f],
        };
        assert!(summarize(&p).ends_with("2 of 4 steps on the agent would change, and it adds 1 Auto approve rule"));
        let parts = message_parts(&p);
        let Some(Details::Laid(details)) = &parts.details else {
            panic!("details")
        };
        let text = details(Laid {
            left_out: false,
            long: false,
        })
        .expect("text");
        assert!(
            text.contains("It adds 1 Auto approve rule to your firewall: one that approves shell commands containing its text from atlas."),
            "{text}"
        );
        assert!(
            !text.contains("npm test") && !text.contains("Let it run"),
            "typed text stays in the last part"
        );
        let typed: Vec<(String, String)> = parts.typed.iter().map(|l| (l.label.clone(), l.text.clone())).collect();
        assert_eq!(
            typed,
            vec![
                (
                    "Auto approve rule for atlas".to_string(),
                    "Let it run the tests".to_string()
                ),
                ("Its text (contains)".to_string(), "npm test".to_string())
            ]
        );
        let back = Proposal::from_json(&p.to_json()).expect("back");
        assert_eq!(back.agents[0].auto, p.agents[0].auto);
    }
}
