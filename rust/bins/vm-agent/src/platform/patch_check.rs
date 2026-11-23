//! Whether ControlClaw's patches and add-ons still match the OpenClaw this box runs
//! (`patch-check.ts`, `GET /health/patches`). An update that moves OpenClaw past the version a
//! hash-pinned patch was reviewed for leaves the feature behind it failing with a generic error;
//! this names which one. Read-only, and it answers with names, versions and fixed status words.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::Deps;

const HOST: &str = "/usr/lib/node_modules/openclaw";
const MEETING_PATCH: &str = "/opt/controlclaw/meeting-runtime-patch.py";
const VOICE_DIR: &str = "/opt/controlclaw/meeting-voice";
const GUARD: &str = "/opt/controlclaw/meeting-guard/index.js";
const CHECK_TIMEOUT: Duration = Duration::from_secs(15);
/// `openclaw plugins list --json` reads the plugin registry, a few seconds on a small box.
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// What the role's OpenClaw resolver last decided (`files/cc-openclaw-patch`): root's,
/// world-readable, in a root-owned folder.
const OPENCLAW_PATCH_STATE: &str = "/var/lib/controlclaw/openclaw-patch.json";

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// `(… .version as string | undefined) ?? null`: a version that is there is taken as it is.
fn version_of(dir: &Path) -> Option<Value> {
    read_json(&dir.join("package.json"))?
        .get("version")
        .filter(|v| !v.is_null())
        .cloned()
}

/// How `find_plugin` orders the copies: at the expected version, in `extensions/`, in a generation
/// directory, and the project directory's time.
type Rank = (bool, bool, bool, std::time::SystemTime);

/// Where an installed `@openclaw/<name>` plugin lives under OpenClaw's state dir, if anywhere: the
/// fallback when OpenClaw does not say (`installed_plugin_dirs`).
///
/// OpenClaw 2026.10 and later install an update of a plugin into a new project directory
/// (`<project>__openclaw-generation__g-<hash>`) next to the previous one, and can touch the old
/// one's time after. So a copy at `version` is preferred, then `extensions/<name>` (where OpenClaw puts
/// a plugin it installs from elsewhere), then one in a generation directory, then the newest project
/// directory; the name breaks a tie, so the listing's order does not matter.
pub fn find_plugin(state_dir: &Path, name: &str, version: Option<&str>) -> Option<PathBuf> {
    let projects = state_dir.join("npm").join("projects");
    let mut found: Vec<(Rank, String, PathBuf)> = std::fs::read_dir(&projects)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let dir = e.path().join("node_modules/@openclaw").join(name);
            if !dir.join("package.json").exists() {
                return None;
            }
            let project = e.file_name().to_string_lossy().into_owned();
            let made = e.metadata().and_then(|m| m.modified()).unwrap_or(std::time::UNIX_EPOCH);
            Some((
                (false, false, project.contains("__openclaw-generation__"), made),
                project,
                dir,
            ))
        })
        .collect();
    let direct = state_dir.join("extensions").join(name);
    if direct.join("package.json").exists() {
        found.push(((false, true, false, std::time::UNIX_EPOCH), String::new(), direct));
    }
    for f in &mut found {
        f.0.0 = version.is_some() && version_of(&f.2).as_ref().and_then(Value::as_str) == version;
    }
    found.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    found.into_iter().next().map(|(_, _, dir)| dir)
}

fn item(id: &str, status: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("id".into(), json!(id));
    m.insert("status".into(), json!(status));
    m
}

/// The meeting patch script's verdict, reduced to one status. A `files` that is not a list, or that
/// holds something other than objects, reads as no status where the TS would throw a 500.
pub fn meetings_runtime_item(raw: &Value, openclaw: Option<&str>) -> Map<String, Value> {
    let expected = raw.get("reviewed").and_then(Value::as_str);
    let status = if raw.is_null() || !raw.is_object() {
        "unknown"
    } else if raw.get("plugin") == Some(&json!("missing")) {
        "missing"
    } else if raw.get("error").is_some_and(super::llm::truthy) {
        "unknown"
    } else {
        let statuses: Vec<&Value> = raw
            .get("files")
            .and_then(Value::as_array)
            .map(|f| f.iter().map(|x| x.get("status").unwrap_or(&Value::Null)).collect())
            .unwrap_or_default();
        let has = |s: &str| statuses.iter().any(|v| v.as_str() == Some(s));
        if has("unknown") {
            "mismatch"
        } else if has("missing") {
            "missing"
        } else if has("unpatched") {
            "unpatched"
        } else if !statuses.is_empty() {
            "ok"
        } else {
            "unknown"
        }
    };
    let mut m = item("meetings_runtime", status);
    m.insert("expected".into(), json!(expected));
    m.insert("actual".into(), json!(openclaw));
    m
}

/// `python3 meeting-runtime-patch.py --check …`; null when the script cannot check (older Ansible).
async fn meeting_check(deps: &Deps, host: &str, plugin_root: &Path) -> Value {
    // An older copy of the script has no `--check` and would read the flag as a path.
    // `readFileSync(…, "utf8")` decodes a stray byte rather than failing.
    let Ok(raw) = std::fs::read(MEETING_PATCH) else {
        return Value::Null;
    };
    let source = String::from_utf8_lossy(&raw);
    if !source.contains("def check(") {
        return Value::Null;
    }
    let state = plugin_root.to_string_lossy().to_string();
    match deps
        .exec(
            "/usr/bin/python3",
            &[MEETING_PATCH, "--check", host, &state],
            CHECK_TIMEOUT,
            None,
            &[],
        )
        .await
    {
        Ok(out) => serde_json::from_str(&out).unwrap_or_else(|_| json!({ "error": true })),
        Err(_) => json!({ "error": true }),
    }
}

fn phone_plugin_item(dir: Option<&Path>) -> Map<String, Value> {
    let expected = crate::phone::apply::PHONE_VERSION;
    let Some(dir) = dir else {
        let mut m = item("phone_plugin", "not_installed");
        m.insert("expected".into(), json!(expected));
        return m;
    };
    let (status, version) = crate::phone::compat::phone_patch_status(dir);
    let mut m = item("phone_plugin", status);
    m.insert("expected".into(), json!(expected));
    m.insert("actual".into(), json!(version));
    m
}

fn phone_runtime_item(host: &Path, openclaw: Option<&str>) -> Map<String, Value> {
    let status = match crate::phone::compat::admission_status(&host.join("dist")) {
        Ok(_) => "ok",
        Err(status) => status,
    };
    let mut m = item("phone_runtime", status);
    m.insert("actual".into(), json!(openclaw));
    m
}

fn browser_stealth_item(host: &Path) -> Map<String, Value> {
    let link = host.join("node_modules").join("playwright-core");
    match std::fs::symlink_metadata(&link) {
        Err(_) => item("browser_stealth", "missing"),
        Ok(m) if m.file_type().is_symlink() => item("browser_stealth", "ok"),
        // A real directory: the role skips the alias when OpenClaw wants another playwright.
        Ok(_) => {
            let mut m = item("browser_stealth", "mismatch");
            m.insert("actual".into(), version_of(&link).unwrap_or(Value::Null));
            m
        }
    }
}

fn voice_adapter_item() -> Map<String, Value> {
    let dir = Path::new(VOICE_DIR);
    // `!manifest`: a file that reads as null, false, 0 or "" is missing too.
    let Some(manifest) = read_json(&dir.join("openclaw.plugin.json")).filter(super::llm::truthy) else {
        return item("voice_adapter", "missing");
    };
    if !dir.join("capabilities.json").exists() {
        return item("voice_adapter", "missing");
    }
    item(
        "voice_adapter",
        if manifest.to_string().contains("cc-phone-voice") {
            "ok"
        } else {
            "mismatch"
        },
    )
}

fn email_cli_item(state_dir: &Path) -> Map<String, Value> {
    let dir = state_dir.join("extensions").join("agentmail");
    if !dir.join("package.json").exists() {
        return item("email_cli", "not_installed");
    }
    let arch = if std::env::consts::ARCH == "aarch64" {
        "linux-arm64"
    } else {
        "linux-x64"
    };
    let release = read_json(&dir.join("dist/cli/agentmail-cli-release.json"));
    let has = release
        .as_ref()
        .and_then(|r| r.pointer(&format!("/assets/{arch}")))
        .is_some_and(super::llm::truthy);
    let mut m = item("email_cli", if has { "ok" } else { "missing" });
    m.insert("actual".into(), version_of(&dir).unwrap_or(Value::Null));
    m
}

/// The primary model's provider has a block when OpenClaw does not know it by itself (`controlclaw`).
pub fn model_provider_item(config: Option<&Value>) -> Map<String, Value> {
    // `!config`; a value that is there but not an object has no primary model.
    let Some(config) = config.filter(|c| super::llm::truthy(c)) else {
        return item("model_provider", "unknown");
    };
    let Some(config) = config.as_object() else {
        return item("model_provider", "not_installed");
    };
    let model = config
        .get("agents")
        .and_then(|a| a.get("defaults"))
        .and_then(|d| d.get("model"));
    let primary = match model {
        Some(Value::String(s)) => Some(s.as_str()),
        Some(Value::Object(o)) => o.get("primary").and_then(Value::as_str),
        _ => None,
    };
    let Some(primary) = primary.filter(|p| p.contains('/')) else {
        return item("model_provider", "not_installed");
    };
    let provider = &primary[..primary.find('/').unwrap_or(0)];
    if provider != "controlclaw" {
        return item("model_provider", "ok");
    }
    let block = config
        .get("models")
        .and_then(|m| m.get("providers"))
        .and_then(|p| p.get(provider));
    let ok = block.is_some_and(|b| {
        b.get("baseUrl").is_some_and(Value::is_string)
            && b.get("models").and_then(Value::as_array).is_some_and(|m| !m.is_empty())
    });
    item("model_provider", if ok { "ok" } else { "missing" })
}

/// `YYYY.M.D` as numbers, for comparing OpenClaw versions.
fn version_key(v: Option<&str>) -> Option<(u64, u64, u64)> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d{4}\.\d+\.\d+$").expect("regex"));
    let v = v.filter(|v| RE.is_match(v))?;
    let mut it = v.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// `openclawPatchItem`: a newer OpenClaw patch the resolver did not install, because the Meet patch
/// of this agent's role does not know it yet (T-openclaw-autopatch): `mismatch`, with the waiting
/// version in `actual`. `expected` stays empty: it names a reviewed version, and the waiting one is not.
pub fn openclaw_patch_item(state: Option<&Value>, openclaw: Option<&str>) -> Map<String, Value> {
    let installed = version_key(openclaw);
    // No state (a role older than the check), or no version to compare with.
    let (Some(state), Some(installed)) = (state.filter(|s| s.is_object()), installed) else {
        return item("openclaw_patch", "unknown");
    };
    let waiting = state.get("waiting").and_then(Value::as_str);
    if version_key(waiting).is_some_and(|w| w > installed) {
        let mut m = item("openclaw_patch", "mismatch");
        m.insert("actual".into(), json!(waiting));
        return m;
    }
    item("openclaw_patch", "ok")
}

/// Where OpenClaw itself says each installed plugin is (`plugins list --json`, `rootDir`), by id.
/// Empty when the CLI cannot answer; the lookup then falls back to `find_plugin`.
async fn installed_plugin_dirs(deps: &Deps) -> std::collections::HashMap<String, PathBuf> {
    let Ok(out) = deps
        .exec(&deps.bin, &["plugins", "list", "--json"], LIST_TIMEOUT, None, &[])
        .await
    else {
        return Default::default();
    };
    plugin_dirs_of(&out)
}

/// The `{id: rootDir}` of a `plugins list --json` answer, which may follow a banner.
pub fn plugin_dirs_of(out: &str) -> std::collections::HashMap<String, PathBuf> {
    let parsed = out
        .find('{')
        .and_then(|i| serde_json::from_str::<Value>(&out[i..]).ok());
    let plugins = parsed
        .as_ref()
        .and_then(|v| v.get("plugins"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    plugins
        .iter()
        // A plugin that failed to load is not the one in use.
        .filter(|p| p.get("status").and_then(Value::as_str) != Some("error"))
        .filter_map(|p| {
            let id = p.get("id")?.as_str()?;
            let dir = PathBuf::from(p.get("rootDir")?.as_str()?);
            dir.join("package.json").exists().then(|| (id.to_string(), dir))
        })
        .collect()
}

/// `patchReport`: `{openclaw, items}` in the TS's order.
pub async fn patch_report(deps: &Deps, state_dir: &Path, host: &Path, openclaw: Option<String>) -> Value {
    let host_s = host.to_string_lossy().to_string();
    let (dirs, config) = tokio::join!(installed_plugin_dirs(deps), async {
        match deps
            .call("config.get", json!({}), super::health_summary::CONFIG_READ_TIMEOUT)
            .await
        {
            // `snapshot.parsed ?? snapshot.config ?? null`.
            Ok(raw) => match raw.get("parsed") {
                Some(v) if !v.is_null() => Some(v.clone()),
                _ => raw.get("config").filter(|v| !v.is_null()).cloned(),
            },
            Err(_) => None,
        }
    });
    // The Meet patch's own check is given the plugin directory: the one OpenClaw names, else the
    // fallback lookup's, else the state dir for the script to search.
    let meet_root = dirs
        .get("google-meet")
        .cloned()
        .or_else(|| find_plugin(state_dir, "google-meet", Some(cc_meetings::policy::MEET_PLUGIN_VERSION)))
        .unwrap_or_else(|| state_dir.to_path_buf());
    let meeting = meeting_check(deps, &host_s, &meet_root).await;
    // The rest reads and hashes files: off the runtime's threads.
    let (state, host, version) = (state_dir.to_path_buf(), host.to_path_buf(), openclaw.clone());
    let items = tokio::task::spawn_blocking(move || {
        file_items(&state, &dirs, &host, &meeting, config.as_ref(), version.as_deref())
    })
    .await
    .unwrap_or_default();
    json!({ "openclaw": openclaw, "items": items })
}

fn file_items(
    state_dir: &Path,
    dirs: &std::collections::HashMap<String, PathBuf>,
    host: &Path,
    meeting: &Value,
    config: Option<&Value>,
    openclaw: Option<&str>,
) -> Vec<Map<String, Value>> {
    let plugin_dir = |id: &str, version: &str| {
        dirs.get(id)
            .cloned()
            .or_else(|| find_plugin(state_dir, id, Some(version)))
    };
    let meet_dir = plugin_dir("google-meet", cc_meetings::policy::MEET_PLUGIN_VERSION);
    let meet_version = meet_dir.as_deref().and_then(version_of);
    let reviewed = meeting.get("reviewed").and_then(Value::as_str);
    let mut plugin = item(
        "meetings_plugin",
        match (&meet_dir, reviewed) {
            (None, _) => "missing",
            (Some(_), Some(r)) if meet_version.as_ref().and_then(Value::as_str) != Some(r) => "mismatch",
            _ => "ok",
        },
    );
    plugin.insert("expected".into(), json!(reviewed));
    plugin.insert("actual".into(), meet_version.unwrap_or(Value::Null));
    let wake = crate::meetings::voice_log::local_wake_installed();
    vec![
        meetings_runtime_item(meeting, openclaw),
        plugin,
        phone_plugin_item(plugin_dir("voice-call", crate::phone::apply::PHONE_VERSION).as_deref()),
        phone_runtime_item(host, openclaw),
        voice_adapter_item(),
        item("wake", if wake { "ok" } else { "missing" }),
        item(
            "meeting_guard",
            if Path::new(GUARD).exists() { "ok" } else { "missing" },
        ),
        browser_stealth_item(host),
        email_cli_item(state_dir),
        model_provider_item(config),
        openclaw_patch_item(
            std::fs::read_to_string(OPENCLAW_PATCH_STATE)
                .ok()
                .and_then(|t| serde_json::from_str::<Value>(&t).ok())
                .as_ref(),
            openclaw,
        ),
    ]
}

/// The real paths: `OPENCLAW_STATE_DIR` or `$HOME/.openclaw`, and the global OpenClaw install.
pub async fn patch_report_here(deps: &Deps) -> Value {
    // `process.env.OPENCLAW_STATE_DIR ?? …`: set but empty is kept, as in the TS.
    let state = std::env::var("OPENCLAW_STATE_DIR")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| deps.home.join(".openclaw"));
    patch_report(deps, &state, Path::new(HOST), super::software::openclaw_version()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_meeting_scripts_verdict_as_one_word() {
        let m = |v: Value| meetings_runtime_item(&v, Some("2026.9.7"))["status"].clone();
        assert_eq!(m(Value::Null), json!("unknown"));
        assert_eq!(m(json!({ "error": true })), json!("unknown"));
        assert_eq!(m(json!({ "plugin": "missing" })), json!("missing"));
        assert_eq!(
            m(json!({ "files": [{ "status": "ok" }, { "status": "unknown" }] })),
            json!("mismatch")
        );
        assert_eq!(m(json!({ "files": [{ "status": "unpatched" }] })), json!("unpatched"));
        assert_eq!(m(json!({ "files": [{ "status": "ok" }] })), json!("ok"));
        assert_eq!(m(json!({ "files": [] })), json!("unknown"));
        let full = meetings_runtime_item(&json!({ "reviewed": "2026.9.7", "files": [] }), None);
        assert_eq!(
            Value::Object(full),
            json!({ "id": "meetings_runtime", "status": "unknown", "expected": "2026.9.7", "actual": null })
        );
    }

    #[test]
    fn our_model_provider_needs_its_block() {
        let c = |v: Value| v;
        let s = |v: Option<&Value>| model_provider_item(v)["status"].clone();
        assert_eq!(s(None), json!("unknown"));
        assert_eq!(s(Some(&json!(""))), json!("unknown"));
        assert_eq!(s(Some(&json!([]))), json!("not_installed"));
        assert_eq!(s(Some(&c(json!({})))), json!("not_installed"));
        assert_eq!(
            s(Some(&c(
                json!({ "agents": { "defaults": { "model": "openai/gpt-5" } } })
            ))),
            json!("ok")
        );
        assert_eq!(
            s(Some(&c(
                json!({ "agents": { "defaults": { "model": { "primary": "controlclaw/m" } } } })
            ))),
            json!("missing")
        );
        assert_eq!(
            s(Some(&c(
                json!({ "agents": { "defaults": { "model": "controlclaw/m" } }, "models": { "providers": { "controlclaw": { "baseUrl": "u", "models": [{}] } } } })
            ))),
            json!("ok")
        );
    }

    #[test]
    fn openclaw_names_where_each_plugin_is() {
        let d = tempfile::tempdir().expect("dir");
        let meet = d.path().join("meet");
        std::fs::create_dir_all(&meet).expect("mk");
        std::fs::write(meet.join("package.json"), "{}").expect("w");
        let out = format!(
            "banner line\n{}",
            json!({ "plugins": [
                { "id": "google-meet", "rootDir": meet.display().to_string() },
                { "id": "voice-call", "rootDir": d.path().join("gone").display().to_string() },
                { "id": "browser" }
            ] })
        );
        let dirs = plugin_dirs_of(&out);
        assert_eq!(dirs.get("google-meet"), Some(&meet));
        // A directory that is not there, or no rootDir: not named, so the lookup falls back.
        assert_eq!(dirs.len(), 1);
        assert!(plugin_dirs_of("not json").is_empty());
    }

    #[test]
    fn plugins_are_found_where_openclaw_installs_them() {
        let d = tempfile::tempdir().expect("dir");
        assert!(find_plugin(d.path(), "voice-call", None).is_none());
        let p = d.path().join("npm/projects/b/node_modules/@openclaw/voice-call");
        std::fs::create_dir_all(&p).expect("mk");
        std::fs::write(p.join("package.json"), r#"{"version":"1"}"#).expect("w");
        assert_eq!(find_plugin(d.path(), "voice-call", None), Some(p.clone()));
        // An update installed into a new generation directory, the old one left in place, and the
        // old one touched after it (seen on 2026.11.3): the generation directory is the one in use.
        let newer = d
            .path()
            .join("npm/projects/b__openclaw-generation__g-0000/node_modules/@openclaw/voice-call");
        std::fs::create_dir_all(&newer).expect("mk");
        std::fs::write(newer.join("package.json"), r#"{"version":"2"}"#).expect("w");
        let old = std::fs::File::open(d.path().join("npm/projects/b")).expect("open");
        old.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
            .expect("mtime");
        assert_eq!(find_plugin(d.path(), "voice-call", None), Some(newer.clone()));
        // The copy at the expected version wins over the rest.
        assert_eq!(find_plugin(d.path(), "voice-call", Some("1")), Some(p.clone()));
        assert_eq!(find_plugin(d.path(), "voice-call", Some("2")), Some(newer.clone()));
        // A copy in extensions/ comes before the npm projects, unless one of those is at the version.
        let ext = d.path().join("extensions/voice-call");
        std::fs::create_dir_all(&ext).expect("mk");
        std::fs::write(ext.join("package.json"), r#"{"version":"3"}"#).expect("w");
        assert_eq!(find_plugin(d.path(), "voice-call", None), Some(ext.clone()));
        assert_eq!(find_plugin(d.path(), "voice-call", Some("2")), Some(newer));
        assert_eq!(find_plugin(d.path(), "voice-call", Some("3")), Some(ext));
        assert_eq!(
            Value::Object(phone_plugin_item(None)),
            json!({ "id": "phone_plugin", "status": "not_installed", "expected": "2026.11.3" })
        );
    }

    #[test]
    fn stealth_and_runtime_items() {
        let d = tempfile::tempdir().expect("dir");
        assert_eq!(
            Value::Object(browser_stealth_item(d.path())),
            json!({ "id": "browser_stealth", "status": "missing" })
        );
        assert_eq!(phone_runtime_item(d.path(), Some("x"))["status"], json!("missing"));
        std::fs::create_dir_all(d.path().join("dist")).expect("mk");
        assert_eq!(
            Value::Object(phone_runtime_item(d.path(), Some("x"))),
            json!({ "id": "phone_runtime", "status": "mismatch", "actual": "x" })
        );
    }

    #[test]
    fn a_waiting_openclaw_patch() {
        let st = |v: Value, o: Option<&str>| openclaw_patch_item(Some(&v), o);
        assert_eq!(openclaw_patch_item(None, Some("2026.9.7"))["status"], json!("unknown"));
        assert_eq!(st(json!({"waiting": "2026.9.35"}), None)["status"], json!("unknown"));
        let m = st(json!({"waiting": "2026.9.35"}), Some("2026.9.7"));
        assert_eq!(
            (m["status"].clone(), m["actual"].clone()),
            (json!("mismatch"), json!("2026.9.35"))
        );
        assert!(m.get("expected").is_none());
        assert_eq!(
            st(json!({"waiting": "2026.9.7"}), Some("2026.9.7"))["status"],
            json!("ok")
        );
        assert_eq!(
            st(json!({"waiting": "2026.9.6"}), Some("2026.9.7"))["status"],
            json!("ok")
        );
        assert_eq!(st(json!({"waiting": "soon"}), Some("2026.9.7"))["status"], json!("ok"));
        assert_eq!(st(json!({}), Some("2026.9.7"))["status"], json!("ok"));
        assert_eq!(st(json!([1]), Some("2026.9.7"))["status"], json!("unknown"));
    }
}
