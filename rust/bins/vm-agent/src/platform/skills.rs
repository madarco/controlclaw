//! The skills report and switch (`skills.ts`, `routes/skills.ts`): every skill OpenClaw can see,
//! where it is, whether it is on and ready, and for the managed ones what was installed and whether
//! it changed. Names, versions and hashes only. It switches one skill on or off
//! (`skills.entries.<name>.enabled`), removes one the skills directory installed, and removes a set
//! of shared notes. All behind the console's token.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use cc_http::{BodyBinding, Router, send_json};
use cc_openclaw::config_queue::QueueOptions;
use futures_util::FutureExt;
use futures_util::future::Shared;
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{Deps, OPENCLAW_BIN, lock};
use super::skill_files::{
    BUILTIN_SKILL_NAMES, CONFIG_CHANGED_MEANWHILE, NotesPlace, SKILL_NAME, SkillHashes, is_hash, notes_locked,
    notes_name_ok, object_key, read_skill_record, remove_notes_record, report_notes,
};
use super::time::{iso_ms, now_ms};
use crate::app::App;
use crate::stages;

const MAX_REPORTED_SKILLS: usize = 300;
const MAX_MANAGED_SKILLS: usize = 100;
const MAX_REPORTED_NOTES: usize = 60;
const MAX_MISSING: usize = 8;
const MAX_MISSING_LENGTH: usize = 100;
const CACHE: Duration = Duration::from_secs(15);
const LIST: Duration = Duration::from_secs(45);
const WRITE: Duration = Duration::from_secs(20);
const WRITE_TRIES: usize = 4;
const WRITE_RETRY: Duration = Duration::from_secs(3);

static REPORTED_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$").expect("regex"));

/// `isReportedSkillName`: safe as one part of a config path, and not a name every object has.
pub fn is_reported_name(name: &str) -> bool {
    REPORTED_NAME.is_match(name) && !object_key(name)
}

/// `placeOf`.
pub fn place_of(source: Option<&str>, bundled: bool) -> &'static str {
    let source = source.unwrap_or_default();
    if source == "openclaw-managed" {
        return "managed";
    }
    if source.contains("workshop") {
        return "workshop";
    }
    if source == "openclaw-workspace" {
        return "workspace";
    }
    if bundled || source.starts_with("openclaw-") {
        "openclaw"
    } else {
        "workspace"
    }
}

/// `missingOf`: what a skill needs and does not have, as `bin:x`, `env:Y`; at most 8.
fn missing_of(missing: Option<&Value>) -> Vec<String> {
    let Some(m) = missing.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, label) in [
        ("bins", "bin"),
        ("anyBins", "bin"),
        ("env", "env"),
        ("config", "config"),
        ("os", "os"),
    ] {
        for n in m.get(key).and_then(Value::as_array).into_iter().flatten() {
            if let Some(n) = n.as_str() {
                let s = format!("{label}:{n}");
                out.push(String::from_utf16_lossy(
                    &s.encode_utf16().take(MAX_MISSING_LENGTH).collect::<Vec<u16>>(),
                ));
            }
        }
    }
    out.truncate(MAX_MISSING);
    out
}

/// `jsonFrom`: the CLI prints log lines before its JSON.
fn json_from(stdout: &str) -> Option<Value> {
    let lines: Vec<&str> = stdout.split('\n').collect();
    for i in 0..lines.len() {
        if !lines[i].trim_start().starts_with('{') {
            continue;
        }
        if let Ok(v) = serde_json::from_str(&lines[i..].join("\n")) {
            return Some(v);
        }
    }
    None
}

/// A refusal with its status (`SkillsError`, `NotesError`).
#[derive(Debug, Clone, PartialEq)]
pub struct SkillsError {
    pub status: u16,
    pub message: String,
}

fn err(status: u16, message: impl Into<String>) -> SkillsError {
    SkillsError {
        status,
        message: message.into(),
    }
}

/// JavaScript's `slice(0, n)`.
fn cut(s: &str, n: usize) -> String {
    String::from_utf16_lossy(&s.encode_utf16().take(n).collect::<Vec<u16>>())
}

type Report = Result<Value, SkillsError>;

struct Inner {
    cached: Option<(Instant, Value)>,
    pending: Option<(u64, Shared<cc_http::BoxFuture<Report>>)>,
    names: BTreeSet<String>,
}

pub struct SkillsService {
    deps: Deps,
    bin: String,
    home: PathBuf,
    notes: NotesPlace,
    generation: AtomicU64,
    hashes: SkillHashes,
    inner: Mutex<Inner>,
    /// One switch or removal at a time.
    writes: tokio::sync::Mutex<()>,
}

impl SkillsService {
    pub fn new(deps: Deps, home: PathBuf, notes: NotesPlace) -> Self {
        Self {
            deps,
            bin: OPENCLAW_BIN.into(),
            home,
            notes,
            generation: AtomicU64::new(0),
            hashes: SkillHashes::default(),
            inner: Mutex::new(Inner {
                cached: None,
                pending: None,
                names: BTreeSet::new(),
            }),
            writes: tokio::sync::Mutex::new(()),
        }
    }

    #[cfg(test)]
    pub fn with_bin(mut self, bin: &str) -> Self {
        self.bin = bin.into();
        self
    }

    fn managed_dir(&self) -> PathBuf {
        self.home.join(".openclaw").join("skills")
    }

    /// The report, at most 15 s old; callers at the same time share one CLI run.
    pub async fn report(self: &Arc<Self>) -> Report {
        let fut = {
            let mut i = lock(&self.inner);
            if let Some((at, r)) = &i.cached
                && at.elapsed() < CACHE
            {
                return Ok(r.clone());
            }
            let generation = self.generation.load(Ordering::SeqCst);
            match &i.pending {
                // A list started before the last change is not this caller's answer.
                Some((g, p)) if *g == generation => p.clone(),
                _ => {
                    let me = self.clone();
                    let f: cc_http::BoxFuture<Report> = Box::pin(async move {
                        let r = me.build(generation).await;
                        let mut i = lock(&me.inner);
                        if let Ok(v) = &r
                            && generation == me.generation.load(Ordering::SeqCst)
                        {
                            i.cached = Some((Instant::now(), v.clone()));
                        }
                        if i.pending.as_ref().is_some_and(|(g, _)| *g == generation) {
                            i.pending = None;
                        }
                        r
                    });
                    let shared = f.shared();
                    i.pending = Some((generation, shared.clone()));
                    shared
                }
            }
        };
        fut.await
    }

    fn managed_names(&self) -> Vec<String> {
        let dir = self.managed_dir();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| is_reported_name(n) && dir.join(n).join("SKILL.md").exists())
            .collect();
        names.sort();
        names.truncate(MAX_MANAGED_SKILLS);
        names
    }

    fn managed(&self, name: &str, entry: &mut Map<String, Value>) {
        let dir = self.managed_dir().join(name);
        let record = read_skill_record(&dir);
        entry.insert("currentHash".into(), json!(self.hashes.of(&dir)));
        if let Some(r) = record {
            entry.insert(
                "installed".into(),
                json!({ "source": r.source, "id": cut(&r.id, 200), "version": r.version.map(|v| cut(&v, 64)), "hash": r.installed_hash }),
            );
        }
    }

    async fn build(&self, generation: u64) -> Report {
        let out = self
            .deps
            .exec(&self.bin, &["skills", "list", "--json"], LIST, None, &[])
            .await
            .map_err(|line| err(502, cut(&format!("OpenClaw could not list its skills: {line}"), 300)))?;
        let answer = json_from(&out).ok_or_else(|| {
            err(
                502,
                cut(
                    "OpenClaw could not list its skills: OpenClaw printed no skills list",
                    300,
                ),
            )
        })?;
        let listed = answer
            .get("skills")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let managed_names = self.managed_names();
        let mut skills: Vec<(u8, String, Value)> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        let mut off: BTreeSet<String> = BTreeSet::new();
        let order = |w: &str| match w {
            "managed" => 0,
            "openclaw" => 1,
            "workshop" => 2,
            _ => 3,
        };
        for s in &listed {
            let Some(name) = s.get("name").and_then(Value::as_str).filter(|n| is_reported_name(n)) else {
                continue;
            };
            let source = s.get("source").and_then(Value::as_str);
            let where_ = place_of(source, s.get("bundled") == Some(&json!(true)));
            if !seen.insert(format!("{where_}:{name}")) {
                continue;
            }
            names.insert(name.into());
            if s.get("disabled") == Some(&json!(true)) {
                off.insert(name.into());
            }
            let mut e = Map::new();
            e.insert("name".into(), json!(name));
            e.insert("where".into(), json!(where_));
            e.insert("enabled".into(), json!(s.get("disabled") != Some(&json!(true))));
            e.insert("eligible".into(), json!(s.get("eligible") == Some(&json!(true))));
            e.insert("missing".into(), json!(missing_of(s.get("missing"))));
            if source == Some("openclaw-workspace") {
                e.insert("own".into(), json!(true));
            }
            if where_ == "managed" && managed_names.iter().any(|m| m == name) {
                self.managed(name, &mut e);
            }
            skills.push((order(where_), name.into(), Value::Object(e)));
        }
        for name in &managed_names {
            if seen.contains(&format!("managed:{name}")) {
                continue;
            }
            let mut e = Map::new();
            e.insert("name".into(), json!(name));
            e.insert("where".into(), json!("managed"));
            e.insert("enabled".into(), json!(!off.contains(name)));
            e.insert("eligible".into(), json!(false));
            e.insert("missing".into(), json!([]));
            if names.contains(name) {
                e.insert("hidden".into(), json!(true));
            }
            self.managed(name, &mut e);
            skills.push((0, name.clone(), Value::Object(e)));
            names.insert(name.clone());
        }
        let dirs: Vec<PathBuf> = managed_names.iter().map(|n| self.managed_dir().join(n)).collect();
        self.hashes.keep(&dirs);
        // A list that started before a change does not put back a name it removed.
        if generation == self.generation.load(Ordering::SeqCst) {
            lock(&self.inner).names = names;
        }
        // Stable, as Array.prototype.sort is: by place, then by name.
        skills.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let truncated = skills.len() > MAX_REPORTED_SKILLS;
        let list: Vec<Value> = skills.into_iter().take(MAX_REPORTED_SKILLS).map(|s| s.2).collect();
        let mut notes = report_notes(&self.home, &self.notes);
        notes.truncate(MAX_REPORTED_NOTES);
        let mut report = json!({ "at": iso_ms(now_ms()), "skills": list, "truncated": truncated, "notes": notes });
        if notes_locked(&self.notes) {
            report["notesLocked"] = json!(true);
        }
        Ok(report)
    }

    /// A config write through the CLI, in the config queue, tried again when the file moved.
    async fn config_write(&self, args: &[&str]) -> Result<(), SkillsError> {
        for attempt in 1.. {
            let run = || async {
                let cmd = cc_proc::Cmd::new(&self.bin)
                    .args(args.iter().copied())
                    .timeout(WRITE)
                    .env("HOME", self.home.to_string_lossy().to_string())
                    .stdin(Vec::new());
                match self.deps.runner.run(cmd).await {
                    Ok(o) if o.success() => Ok(()),
                    Ok(o) => Err((
                        format!("{}\n{}", o.stdout_str(), o.stderr_str()),
                        super::openclaw::exec_failure_line(
                            &o.stderr_str(),
                            &o.stdout_str(),
                            &format!("Command failed: {} {}", self.bin, args.join(" ")),
                        ),
                    )),
                    Err(e) => Err((String::new(), super::common::spawn_message(&self.bin, &e))),
                }
            };
            let r = match self.deps.client() {
                Some(w) => w.file_write(run, QueueOptions::default()).await,
                None => run().await,
            };
            match r {
                Ok(()) => return Ok(()),
                Err((output, line)) => {
                    if attempt < WRITE_TRIES && CONFIG_CHANGED_MEANWHILE.is_match(&output) {
                        tokio::time::sleep(WRITE_RETRY).await;
                        continue;
                    }
                    return Err(err(502, cut(&format!("OpenClaw did not take the change: {line}"), 300)));
                }
            }
        }
        Ok(())
    }

    /// The next report is read again; a list already running is not this one's answer.
    pub fn forget(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        lock(&self.inner).cached = None;
    }

    fn after_write(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let mut i = lock(&self.inner);
        i.cached = None;
        i.pending = None;
    }

    /// Switch one skill on or off; answers once OpenClaw has taken it.
    pub async fn set_enabled(
        self: &Arc<Self>,
        name: Option<&Value>,
        enabled: Option<&Value>,
    ) -> Result<Value, SkillsError> {
        let (Some(name), Some(enabled)) = (
            name.and_then(Value::as_str).filter(|n| is_reported_name(n)),
            enabled.and_then(Value::as_bool),
        ) else {
            return Err(err(400, "name and enabled are required"));
        };
        if lock(&self.inner).names.is_empty() {
            self.report().await?;
        }
        if !lock(&self.inner).names.contains(name) {
            return Err(err(404, "This agent has no skill with that name."));
        }
        let _turn = self.writes.lock().await;
        let path = format!("skills.entries.{name}.enabled");
        self.config_write(&[
            "config",
            "set",
            &path,
            if enabled { "true" } else { "false" },
            "--strict-json",
        ])
        .await?;
        self.after_write();
        Ok(json!({ "ok": true }))
    }

    /// Remove a skill the skills directory installed: its folder, then its `skills.entries` line.
    pub async fn remove(
        &self,
        name: Option<&Value>,
        expected: Option<&Value>,
        even_if_changed: Option<&Value>,
    ) -> Result<Value, SkillsError> {
        let (Some(name), Some(expected)) = (
            name.and_then(Value::as_str)
                .filter(|n| SKILL_NAME.is_match(n) && !object_key(n)),
            expected.and_then(Value::as_str).filter(|h| is_hash(h)),
        ) else {
            return Err(err(400, "name and expectedHash are required"));
        };
        if BUILTIN_SKILL_NAMES.contains(&name) {
            return Err(err(
                409,
                "That skill comes with every agent. It can be switched off, not removed.",
            ));
        }
        // The checks and the removal in one turn: nothing changes the folder in between.
        let _turn = self.writes.lock().await;
        let dir = self.managed_dir().join(name);
        let Ok(there) = std::fs::symlink_metadata(&dir) else {
            return Ok(json!({ "ok": true, "removed": false }));
        };
        let record = if there.is_dir() { read_skill_record(&dir) } else { None };
        if record.map(|r| r.source).as_deref() != Some("organization") {
            return Err(err(
                409,
                "That skill was not installed from the skills directory, so it is not removed from here.",
            ));
        }
        if even_if_changed != Some(&json!(true)) && self.hashes.of(&dir).as_deref() != Some(expected) {
            return Ok(json!({ "ok": false, "changed": true }));
        }
        if let Err(e) = std::fs::remove_dir_all(&dir)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => "EACCES",
                _ => "error",
            };
            return Err(err(500, format!("The skill's folder could not be removed ({code}).")));
        }
        // A line left for a skill that is not there does nothing: failing to clear it is logged.
        let path = format!("skills.entries.{name}");
        if let Err(e) = self.config_write(&["config", "unset", &path]).await {
            self.deps.log(&format!(
                "[skills] {name} was removed; its entry could not be cleared: {}",
                e.message
            ));
        }
        self.after_write();
        Ok(json!({ "ok": true, "removed": true }))
    }

    /// Remove a set of shared notes with the root helper.
    pub async fn remove_notes(&self, name: Option<&Value>) -> Result<Value, SkillsError> {
        let Some(name) = name.and_then(Value::as_str).filter(|n| notes_name_ok(n)) else {
            return Err(err(400, "Name the set."));
        };
        if notes_locked(&self.notes) {
            return Err(err(
                423,
                "This agent's disk is locked, and its notes are in the locked part. Open the disk first.",
            ));
        }
        let there = self.notes.root.join(name).is_dir();
        if there {
            let (command, rest) = self
                .notes
                .helper
                .split_first()
                .map_or(("", &[][..]), |(c, r)| (c.as_str(), r));
            let mut args: Vec<&str> = rest.iter().map(String::as_str).collect();
            args.extend(["remove", name]);
            if let Err(line) = self.deps.exec(command, &args, Duration::from_secs(60), None, &[]).await {
                return Err(err(500, cut(&format!("The notes could not be removed: {line}"), 300)));
            }
        }
        remove_notes_record(&self.home, name);
        self.forget();
        Ok(json!({ "ok": true, "removed": there }))
    }
}

/// `/skills`, `/skills/enabled`, `/skills/remove`, `/skills/restore`, `/notes/remove`, `/notes/restore`:
/// behind the console's token, which the stage's gate has checked.
pub fn register(router: &mut Router, app: &Arc<App>) {
    const PATHS: [&str; 6] = [
        "/skills",
        "/skills/enabled",
        "/skills/remove",
        "/notes/remove",
        "/skills/restore",
        "/notes/restore",
    ];
    let app = app.clone();
    router.route(
        stages::CONSOLE,
        |_, p| PATHS.contains(&p),
        move |req, _| {
            let app = app.clone();
            async move {
                let (parts, body) = req.into_parts();
                let path = cc_http::pathname(&parts.uri.to_string());
                let Some(svc) = app.contracts.platform.get().and_then(|p| p.skills.get().cloned()) else {
                    return send_json(500, &json!({ "error": "The skills could not be read." }));
                };
                let read = || async {
                    cc_http::read_json_body(body, 1024, &BodyBinding::not_firewall())
                        .await
                        .unwrap_or_default()
                };
                let result = match (parts.method.clone(), path.as_str()) {
                    (Method::GET, "/skills") => svc.report().await,
                    (Method::POST, "/skills/enabled") => {
                        let b = read().await;
                        svc.set_enabled(b.get("name"), b.get("enabled")).await
                    }
                    (Method::POST, "/skills/remove") => {
                        let b = read().await;
                        svc.remove(b.get("name"), b.get("expectedHash"), b.get("evenIfChanged"))
                            .await
                    }
                    (Method::POST, "/notes/remove") => {
                        let b = read().await;
                        svc.remove_notes(b.get("name")).await
                    }
                    (Method::POST, "/skills/restore" | "/notes/restore") => {
                        let b = read().await;
                        // The template service puts a skill or a set back (G5b); until then the TS's
                        // answer for an agent without one.
                        match app.contracts.platform.get().and_then(|p| p.restore.get().cloned()) {
                            Some(restore) => {
                                let r = restore(path.clone(), b).await;
                                // Only a put-back changes what the report says (the TS forgets after one).
                                if r.is_ok() {
                                    svc.forget();
                                }
                                r
                            }
                            None => return send_json(503, &json!({ "error": "This agent is not set up yet." })),
                        }
                    }
                    _ => return send_json(404, &json!({ "error": "Not found" })),
                };
                match result {
                    Ok(v) => send_json(200, &v),
                    Err(e) if e.status != 0 => send_json(e.status, &json!({ "error": e.message })),
                    Err(e) => {
                        tracing::error!("[skills] {}", e.message);
                        send_json(500, &json!({ "error": "The skills could not be read." }))
                    }
                }
            }
        },
    );
}

/// What `/skills/restore` and `/notes/restore` hand to the template service: the path and the body.
pub type Restore =
    Arc<dyn Fn(String, Map<String, Value>) -> cc_http::BoxFuture<Result<Value, SkillsError>> + Send + Sync>;

#[cfg(test)]
mod tests {
    //! skills.test.ts and the notes removal from notes.test.ts, with a recording CLI.

    use std::collections::HashSet;
    use std::sync::atomic::AtomicUsize;

    use cc_proc::{Output, RecordingRunner};

    use super::super::llm::tests::{Fake, rig};
    use super::super::skill_files::{SKILL_RECORD, hash_skill_files};
    use super::*;

    struct Box_ {
        svc: Arc<SkillsService>,
        home: PathBuf,
        _dir: tempfile::TempDir,
        runner: RecordingRunner,
        lists: Arc<AtomicUsize>,
    }

    fn missing_none() -> Value {
        json!({ "bins": [], "anyBins": [], "env": [], "config": [], "os": [] })
    }

    /// A box with skills in its managed folder, and an OpenClaw that lists `listed`.
    fn boxed(listed: Vec<Value>, managed: &[(&str, &str)]) -> Box_ {
        let dir = tempfile::tempdir().expect("dir");
        let home = dir.path().to_path_buf();
        for (name, body) in managed {
            std::fs::create_dir_all(home.join(".openclaw/skills").join(name)).expect("d");
            std::fs::write(home.join(".openclaw/skills").join(name).join("SKILL.md"), body).expect("w");
        }
        std::fs::create_dir_all(home.join(".openclaw/skills/.openclaw-install-backups")).expect("d");
        let disabled: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let lists = Arc::new(AtomicUsize::new(0));
        let runner = RecordingRunner::new();
        let (d, l) = (disabled.clone(), lists.clone());
        runner.answer_with(move |c| {
            let a = &c.args;
            Some(match a.first().map(String::as_str) {
                Some("skills") => {
                    l.fetch_add(1, Ordering::SeqCst);
                    let skills: Vec<Value> = listed
                        .iter()
                        .map(|s| {
                            let mut e = json!({ "eligible": true, "bundled": false, "missing": missing_none() });
                            for (k, v) in s.as_object().expect("o") {
                                e[k] = v.clone();
                            }
                            e["disabled"] = json!(lock(&d).contains(s["name"].as_str().unwrap_or_default()));
                            e
                        })
                        .collect();
                    cc_proc::ok(&format!(
                        "[skills] loading\n{}",
                        serde_json::to_string_pretty(&json!({ "workspaceDir": "/w", "skills": skills })).expect("j")
                    ))
                }
                Some("config") if a.get(1).map(String::as_str) == Some("set") => {
                    let name = a[2]
                        .strip_prefix("skills.entries.")
                        .and_then(|n| n.strip_suffix(".enabled"))
                        .unwrap_or_default()
                        .to_string();
                    if a[3] == "false" {
                        lock(&d).insert(name);
                    } else {
                        lock(&d).remove(&name);
                    }
                    cc_proc::ok("Updated.")
                }
                Some("config") => cc_proc::ok("Removed."),
                _ => Output {
                    code: Some(1),
                    stderr: b"unexpected".to_vec(),
                    ..Default::default()
                },
            })
        });
        let mut r = rig(Fake::new());
        r.deps.runner = Arc::new(runner.clone());
        let notes = NotesPlace {
            root: home.join("notes-sets"),
            helper: vec!["/fake/cc-notes".into()],
        };
        let svc = Arc::new(SkillsService::new(r.deps.clone(), home.clone(), notes).with_bin("/fake/openclaw"));
        Box_ {
            svc,
            home,
            _dir: dir,
            runner,
            lists,
        }
    }

    fn record(dir: &std::path::Path, source: &str) -> String {
        let mut files = Vec::new();
        for e in std::fs::read_dir(dir).expect("rd").filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if name != SKILL_RECORD {
                files.push(super::super::skill_files::SkillFile {
                    content: std::fs::read(e.path()).expect("r"),
                    path: name,
                    executable: false,
                });
            }
        }
        let hash = hash_skill_files(&files);
        std::fs::write(dir.join(SKILL_RECORD), json!({ "source": source, "id": "skl-abcdefgh1234", "version": "2", "installedHash": hash, "installedAt": "t" }).to_string()).expect("w");
        hash
    }

    #[test]
    fn place_of_cases() {
        assert_eq!(place_of(Some("openclaw-managed"), false), "managed");
        assert_eq!(place_of(Some("openclaw-workspace"), false), "workspace");
        assert_eq!(place_of(Some("openclaw-workshop"), false), "workshop");
        assert_eq!(place_of(Some("openclaw-bundled"), true), "openclaw");
        assert_eq!(place_of(Some("openclaw-extra"), false), "openclaw");
        assert_eq!(place_of(Some("agents-skills-personal"), false), "workspace");
    }

    #[tokio::test]
    async fn the_report_names_places_states_and_hashes_and_nothing_of_the_content() {
        let b = boxed(
            vec![
                json!({ "name": "weather", "source": "openclaw-bundled", "bundled": true, "description": "Weather." }),
                json!({ "name": "1password", "source": "openclaw-bundled", "bundled": true, "eligible": false, "missing": { "bins": ["op"] } }),
                json!({ "name": "house-style", "source": "openclaw-managed", "description": "How we write." }),
                json!({ "name": "dropped-in", "source": "openclaw-managed" }),
                json!({ "name": "own", "source": "openclaw-workspace" }),
                json!({ "name": "shadow", "source": "openclaw-workspace" }),
                json!({ "name": "bad name", "source": "openclaw-workspace" }),
                json!({ "name": "constructor", "source": "openclaw-workspace" }),
            ],
            &[
                ("house-style", "---\nname: house-style\n---\nSECRET-BODY"),
                ("dropped-in", "---\nname: dropped-in\n---\n"),
                ("shadow", "---\nname: shadow\n---\n"),
                ("unreadable", "no front matter"),
            ],
        );
        let dir = b.home.join(".openclaw/skills/house-style");
        let installed = record(&dir, "template");
        std::fs::write(
            dir.join("SKILL.md"),
            "---\nname: house-style\n---\nchanged by the agent",
        )
        .expect("w");
        let r = b.svc.report().await.expect("report");
        let names: Vec<String> = r["skills"]
            .as_array()
            .expect("a")
            .iter()
            .map(|s| format!("{}:{}", s["where"].as_str().expect("w"), s["name"].as_str().expect("n")))
            .collect();
        assert_eq!(
            names,
            [
                "managed:dropped-in",
                "managed:house-style",
                "managed:shadow",
                "managed:unreadable",
                "openclaw:1password",
                "openclaw:weather",
                "workspace:own",
                "workspace:shadow"
            ]
        );
        let by = |n: &str, w: &str| {
            r["skills"]
                .as_array()
                .expect("a")
                .iter()
                .find(|s| s["name"] == n && s["where"] == w)
                .cloned()
                .expect("s")
        };
        assert_eq!(
            by("1password", "openclaw"),
            json!({ "name": "1password", "where": "openclaw", "enabled": true, "eligible": false, "missing": ["bin:op"] })
        );
        let house = by("house-style", "managed");
        assert_eq!(
            house["installed"],
            json!({ "source": "template", "id": "skl-abcdefgh1234", "version": "2", "hash": installed })
        );
        assert!(
            house["currentHash"]
                .as_str()
                .is_some_and(|h| h.len() == 64 && h != installed)
        );
        assert!(by("dropped-in", "managed").get("installed").is_none());
        assert_eq!(by("shadow", "managed")["hidden"], json!(true));
        assert!(by("shadow", "workspace").get("hidden").is_none());
        assert_eq!(by("own", "workspace")["own"], json!(true));
        let u = by("unreadable", "managed");
        assert!(u.get("hidden").is_none());
        assert_eq!(u["eligible"], json!(false));
        let text = r.to_string();
        assert!(!text.contains("SECRET-BODY") && !text.contains("How we write") && !text.contains("Weather."));
    }

    #[tokio::test]
    async fn cached_shared_and_capped_with_ours_first() {
        let mut listed: Vec<Value> = (0..400)
            .map(|i| json!({ "name": format!("0a{i}"), "source": "openclaw-workspace" }))
            .collect();
        listed.push(json!({ "name": "house-style", "source": "openclaw-managed" }));
        listed.push(json!({ "name": "weather", "source": "openclaw-bundled", "bundled": true }));
        listed.push(json!({ "name": "zz-last", "source": "openclaw-workspace" }));
        let b = boxed(listed, &[("house-style", "---\nname: house-style\n---\n")]);
        let (x, y) = tokio::join!(b.svc.report(), b.svc.report());
        assert_eq!(x.clone().expect("x"), y.expect("y"));
        b.svc.report().await.expect("cached");
        assert_eq!(b.lists.load(Ordering::SeqCst), 1);
        let r = x.expect("r");
        assert_eq!(
            (r["skills"].as_array().expect("a").len(), r["truncated"].clone()),
            (300, json!(true))
        );
        assert_eq!(r["skills"][0]["name"], "house-style");
        assert_eq!(r["skills"][1]["name"], "weather");
        // Past the cut, and still a skill of this agent.
        assert_eq!(
            b.svc.set_enabled(Some(&json!("zz-last")), Some(&json!(false))).await,
            Ok(json!({ "ok": true }))
        );
    }

    #[tokio::test]
    async fn switching_writes_skills_entries_only_for_a_skill_this_agent_has() {
        let b = boxed(
            vec![json!({ "name": "weather", "source": "openclaw-bundled", "bundled": true })],
            &[],
        );
        assert_eq!(
            b.svc.set_enabled(Some(&json!("weather")), Some(&json!(false))).await,
            Ok(json!({ "ok": true }))
        );
        assert_eq!(b.svc.report().await.expect("r")["skills"][0]["enabled"], json!(false));
        let set = b
            .runner
            .calls()
            .into_iter()
            .find(|c| c.args.first().map(String::as_str) == Some("config"))
            .expect("set");
        assert_eq!(
            set.args,
            [
                "config",
                "set",
                "skills.entries.weather.enabled",
                "false",
                "--strict-json"
            ]
        );
        b.svc
            .set_enabled(Some(&json!("weather")), Some(&json!(true)))
            .await
            .expect("on");
        assert_eq!(b.svc.report().await.expect("r")["skills"][0]["enabled"], json!(true));
        for (name, enabled, status) in [
            (json!("nope"), json!(false), 404),
            (json!("a.b"), json!(false), 400),
            (json!("weather"), json!("false"), 400),
            (Value::Null, json!(true), 400),
            (json!("weather --x"), json!(true), 400),
            (json!("constructor"), json!(false), 400),
            (json!("__proto__"), json!(false), 400),
        ] {
            let e = b
                .svc
                .set_enabled(Some(&name), Some(&enabled))
                .await
                .expect_err("refused");
            assert_eq!(e.status, status, "{name}");
        }
    }

    #[tokio::test]
    async fn a_switch_refused_because_the_config_moved_is_sent_again_and_another_refusal_is_not() {
        let b = boxed(
            vec![json!({ "name": "a", "source": "openclaw-bundled", "bundled": true })],
            &[],
        );
        b.svc.report().await.expect("r");
        let refusals = Arc::new(AtomicUsize::new(1));
        let r = refusals.clone();
        let runner = RecordingRunner::new();
        runner.answer_with(move |_| {
            Some(if r.fetch_sub(1, Ordering::SeqCst) > 0 {
                Output {
                    code: Some(1),
                    stderr: b"Config file changed while this command was running. Run the command again.".to_vec(),
                    ..Default::default()
                }
            } else {
                Output {
                    code: Some(1),
                    stderr: b"Config validation failed: skills.entries.a.enabled".to_vec(),
                    ..Default::default()
                }
            })
        });
        let mut deps = rig(Fake::new()).deps;
        deps.runner = Arc::new(runner.clone());
        let svc = Arc::new(SkillsService::new(deps, b.home.clone(), b.svc.notes.clone()));
        lock(&svc.inner).names.insert("a".into());
        let e = svc
            .set_enabled(Some(&json!("a")), Some(&json!(false)))
            .await
            .expect_err("fails");
        assert_eq!(e.status, 502);
        assert!(e.message.contains("Config validation failed"), "{}", e.message);
        assert_eq!(
            runner.calls().len(),
            2,
            "the moved-config refusal was tried again, the other was not"
        );
    }

    #[tokio::test]
    async fn removing_a_directory_skill_and_what_is_refused() {
        let b = boxed(
            vec![json!({ "name": "house-style", "source": "openclaw-managed" })],
            &[
                ("house-style", "---\nname: house-style\n---\nShort.\n"),
                ("agentmail", "---\nname: agentmail\n---\n"),
                ("from-template", "---\nname: from-template\n---\n"),
                ("by-hand", "---\nname: by-hand\n---\n"),
                ("says-ours", "---\nname: says-ours\n---\n"),
                ("changed", "---\nname: changed\n---\nShort.\n"),
            ],
        );
        let skills = b.home.join(".openclaw/skills");
        let hash = record(&skills.join("house-style"), "organization");
        record(&skills.join("agentmail"), "controlclaw");
        record(&skills.join("from-template"), "template");
        record(&skills.join("says-ours"), "controlclaw");
        let changed = record(&skills.join("changed"), "organization");
        std::fs::write(
            skills.join("changed/SKILL.md"),
            "---\nname: changed\n---\nWhat the agent found works better.\n",
        )
        .expect("w");
        std::fs::create_dir_all(b.home.join("elsewhere")).expect("d");
        std::fs::write(b.home.join("elsewhere/keep.txt"), "x").expect("w");
        std::os::unix::fs::symlink(b.home.join("elsewhere"), skills.join("linked")).expect("l");

        assert_eq!(
            b.svc
                .remove(Some(&json!("house-style")), Some(&json!(hash)), Some(&json!(false)))
                .await,
            Ok(json!({ "ok": true, "removed": true }))
        );
        assert!(!skills.join("house-style").exists());
        assert_eq!(
            b.runner.calls().last().expect("c").args,
            ["config", "unset", "skills.entries.house-style"]
        );
        assert_eq!(
            b.svc
                .remove(Some(&json!("house-style")), Some(&json!(hash)), Some(&json!(false)))
                .await,
            Ok(json!({ "ok": true, "removed": false }))
        );

        assert_eq!(
            b.svc
                .remove(Some(&json!("changed")), Some(&json!(changed)), Some(&json!(false)))
                .await,
            Ok(json!({ "ok": false, "changed": true }))
        );
        assert_eq!(
            b.svc
                .remove(Some(&json!("changed")), Some(&json!(changed)), Some(&json!("true")))
                .await,
            Ok(json!({ "ok": false, "changed": true }))
        );
        assert_eq!(
            b.svc
                .remove(Some(&json!("changed")), Some(&json!(changed)), Some(&json!(true)))
                .await,
            Ok(json!({ "ok": true, "removed": true }))
        );

        let h = json!("a".repeat(64));
        for (name, status) in [
            ("agentmail", 409),
            ("from-template", 409),
            ("by-hand", 409),
            ("says-ours", 409),
            ("linked", 409),
        ] {
            assert_eq!(
                b.svc
                    .remove(Some(&json!(name)), Some(&h), Some(&json!(true)))
                    .await
                    .expect_err("refused")
                    .status,
                status,
                "{name}"
            );
        }
        for name in [
            json!("../../.ssh"),
            json!("a/b"),
            json!(""),
            json!("constructor"),
            json!("UPPER"),
            json!(".openclaw-install-backups"),
            json!(5),
            Value::Null,
        ] {
            assert_eq!(
                b.svc
                    .remove(Some(&name), Some(&h), Some(&json!(true)))
                    .await
                    .expect_err("bad")
                    .status,
                400,
                "{name}"
            );
        }
        assert_eq!(
            b.svc
                .remove(Some(&json!("x")), Some(&json!("nope")), Some(&json!(true)))
                .await
                .expect_err("bad")
                .status,
            400
        );
        for n in ["agentmail", "from-template", "by-hand", "says-ours"] {
            assert!(skills.join(n).join("SKILL.md").exists(), "{n}");
        }
        assert!(b.home.join("elsewhere/keep.txt").exists());
    }

    #[tokio::test]
    async fn removing_notes_asks_the_helper_drops_the_record_and_says_when_it_fails() {
        let b = boxed(vec![], &[]);
        let sets = b.home.join("notes-sets");
        std::fs::create_dir_all(sets.join("handbook")).expect("d");
        std::fs::write(sets.join("handbook/a.md"), "A").expect("w");
        std::fs::create_dir_all(b.home.join(".controlclaw/notes")).expect("d");
        std::fs::write(
            b.home.join(".controlclaw/notes/handbook.json"),
            json!({ "source": "organization", "id": "n1", "hash": "b".repeat(64) }).to_string(),
        )
        .expect("w");
        // The fake CLI fails anything it does not know, the helper included.
        let e = b
            .svc
            .remove_notes(Some(&json!("handbook")))
            .await
            .expect_err("helper fails");
        assert_eq!(e.status, 500);
        assert!(e.message.starts_with("The notes could not be removed: "));
        assert!(
            b.home.join(".controlclaw/notes/handbook.json").exists(),
            "the record stays"
        );
        // With a helper that works.
        let ok_runner = RecordingRunner::new();
        ok_runner.answer(&["/fake/cc-notes", "remove"], cc_proc::ok(""));
        let mut deps = rig(Fake::new()).deps;
        deps.runner = Arc::new(ok_runner.clone());
        let svc = SkillsService::new(
            deps,
            b.home.clone(),
            NotesPlace {
                root: sets.clone(),
                helper: vec!["/fake/cc-notes".into()],
            },
        );
        assert_eq!(
            svc.remove_notes(Some(&json!("handbook"))).await,
            Ok(json!({ "ok": true, "removed": true }))
        );
        assert_eq!(ok_runner.calls()[0].args, ["remove", "handbook"]);
        assert!(!b.home.join(".controlclaw/notes/handbook.json").exists());
        assert_eq!(
            svc.remove_notes(Some(&json!("nope"))).await,
            Ok(json!({ "ok": true, "removed": false }))
        );
        assert_eq!(svc.remove_notes(Some(&json!("_x"))).await.expect_err("bad").status, 400);
    }
}
