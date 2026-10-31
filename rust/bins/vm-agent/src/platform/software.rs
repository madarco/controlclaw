//! What this box is running (`software.ts`): this agent's build, the Ansible release, OpenClaw's
//! version and the features the console asks about. Nothing here fails: a box that cannot describe
//! itself still answers `/status` and still reports ready.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

use super::time::{iso_ms, now_ms};
use crate::app::App;

const RELEASE_PATH: &str = "/etc/controlclaw/release.json";
const OPENCLAW_CANDIDATES: [&str; 2] = [
    "/usr/lib/node_modules/openclaw/package.json",
    "/usr/local/lib/node_modules/openclaw/package.json",
];
const OPENCLAW_BIN: &str = "/usr/bin/openclaw";
const VOICE_CAPABILITIES: &str = "/opt/controlclaw/meeting-voice/capabilities.json";
const WAKE_DETECTOR: &str = "/opt/controlclaw/meeting-voice/cc-wake.py";
const WAKE_MODEL: &str = "/opt/controlclaw/cc-wake/model/conf/model.conf";
/// Longest value passed on.
const MAX_FIELD: usize = 64;

static SEMVER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+\.\d+\.\d+$").expect("regex"));
static FIREWALL_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$").expect("regex")
});

/// The build stamp, baked in at build time (`CC_BUILD_VERSION`, `CC_BUILD_COMMIT`, `CC_BUILD_AT`),
/// with the TS fallbacks for a build that set none.
fn build() -> Value {
    json!({
        "version": option_env!("CC_BUILD_VERSION").unwrap_or("dev"),
        "commit": option_env!("CC_BUILD_COMMIT").unwrap_or("unknown"),
        "builtAt": option_env!("CC_BUILD_AT").unwrap_or("unknown"),
    })
}

/// When the machine booted, from `/proc/uptime`, read once.
static BOOTED_AT: LazyLock<String> = LazyLock::new(|| {
    let up = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
        .unwrap_or(0.0);
    iso_ms(now_ms() - (up * 1000.0) as i64)
});

/// JavaScript's `slice(0, 64)` counts UTF-16 units; the fields are ASCII in practice.
fn clip(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.chars().take(MAX_FIELD).collect()),
        _ => None,
    }
}

fn read_json(path: &Path) -> Option<Map<String, Value>> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str::<Value>(&text).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

/// `readRelease`: the three fields or nothing; `version` only when it is x.y.z.
pub fn read_release(path: &Path) -> Value {
    let Some(raw) = read_json(path) else {
        return Value::Null;
    };
    let (Some(commit), Some(commit_date), Some(installed_at)) = (
        clip(raw.get("commit")),
        clip(raw.get("commitDate")),
        clip(raw.get("installedAt")),
    ) else {
        return Value::Null;
    };
    let mut out = json!({ "commit": commit, "commitDate": commit_date, "installedAt": installed_at });
    if let Some(v) = clip(raw.get("version")).filter(|v| SEMVER.is_match(v)) {
        out["version"] = json!(v);
    }
    out
}

/// The OpenClaw this box runs (`readOpenClawVersion()` with the real paths).
pub fn openclaw_version() -> Option<String> {
    let candidates: Vec<PathBuf> = OPENCLAW_CANDIDATES.iter().map(PathBuf::from).collect();
    read_openclaw_version(&candidates, Path::new(OPENCLAW_BIN))
}

/// `readOpenClawVersion`: the two npm layouts, then the package root above where the bin links to.
pub fn read_openclaw_version(candidates: &[PathBuf], bin: &Path) -> Option<String> {
    for p in candidates {
        if let Some(v) = read_json(p).and_then(|m| clip(m.get("version"))) {
            return Some(v);
        }
    }
    let mut dir = std::fs::canonicalize(bin).ok()?.parent()?.to_path_buf();
    for _ in 0..4 {
        if let Some(pkg) = read_json(&dir.join("package.json"))
            && pkg.get("name") == Some(&json!("openclaw"))
        {
            return clip(pkg.get("version"));
        }
        match dir.parent() {
            Some(p) if p != dir => dir = p.to_path_buf(),
            _ => break,
        }
    }
    None
}

/// `speechFeatures`: which speech families the installed voice adapter drives.
pub fn speech_features(path: &Path, local_wake: bool) -> Vec<&'static str> {
    let Some(caps) = read_json(path) else {
        return Vec::new();
    };
    let families = caps
        .get("speechFamilies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let yes = |k: &str| caps.get(k) == Some(&Value::Bool(true));
    let mut out = Vec::new();
    for (f, name) in [("realtime", "speech_realtime"), ("live", "speech_live")] {
        if families.contains(&json!(f)) {
            out.push(name);
        }
    }
    if yes("wakeWords") {
        out.push("speech_wake");
    }
    if yes("wakeLocal") && local_wake {
        out.push("speech_wake_local");
    }
    for (k, name) in [
        ("alwaysListening", "speech_always"),
        ("fullAgent", "meeting_full_agent"),
        ("present", "meeting_present"),
        ("consultModel", "meeting_consult_model"),
    ] {
        if yes(k) {
            out.push(name);
        }
    }
    out
}

/// `firewallOrigin()` (access-state.ts, W7's store): the origin in `state/access.json`, if valid.
pub fn firewall_origin(state_dir: &Path) -> Option<String> {
    let m = read_json(&state_dir.join("access.json"))?;
    match m.get("firewallOrigin") {
        Some(Value::String(o)) if o.len() <= 261 && FIREWALL_ORIGIN.is_match(o) => Some(o.clone()),
        _ => None,
    }
}

const AGENT_FEATURES: [&str; 23] = [
    "logs_page",
    "whatsapp_page",
    "meetings_page",
    "phone_page",
    "phone_voice_edit",
    "meetings_autojoin",
    "meeting_followup",
    "meeting_instructions",
    "templates",
    "templates_apply",
    "templates_org",
    "templates_review",
    "templates_capture",
    "templates_steps2",
    "templates_bundles",
    "templates_check",
    "templates_repair",
    "templates_capture_ai",
    "skills_start",
    "skills_remove",
    "skills_capture",
    "notes_start",
    "storage_grow",
];

/// `boxSoftware()`: the object reported on `/ready` and `/status`, in the TS key order.
pub fn box_software(app: &App, console_mcp: bool, doctor_fingerprint: Option<&str>) -> Value {
    let brain = super::is_brain(app);
    let local_wake = Path::new(WAKE_DETECTOR).exists() && Path::new(WAKE_MODEL).exists();
    let mut features: Vec<&str> = speech_features(Path::new(VOICE_CAPABILITIES), local_wake);
    // `rust_runtime` where the TS has `runtimeFallback`. No `runtime_fallback`: the agent box has no
    // other unit with a Rust build, and a marker for this one is stale while it runs.
    features.push("rust_runtime");
    if console_mcp {
        features.push("console_mcp");
    }
    if super::doctor::available(doctor_fingerprint) {
        features.push("doctor_v1");
    }
    if !brain {
        features.extend(AGENT_FEATURES);
    }
    if Path::new("/etc/controlclaw/disk-partners").exists() {
        features.push("disk_partners");
    }
    if firewall_origin(&app.config.state_dir).is_some() {
        features.push("open_v1");
    }
    if !brain && app.config.keys_dir.join("mitm_pinned_pubkey.pem").exists() {
        features.extend(["templates_code", "skills_apply"]);
        let notes = std::env::var("CC_NOTES_HELPER").unwrap_or_else(|_| "/usr/local/sbin/cc-notes".into());
        if Path::new(&notes).exists() {
            features.push("notes_apply");
        }
    }
    if app.firewall_auth.tokens_bound() {
        features.push("fw_tokens_bound");
    }
    let release = std::env::var("RELEASE_FILE").unwrap_or_else(|_| RELEASE_PATH.into());
    json!({
        "rebootRequired": Path::new("/var/run/reboot-required").exists(),
        "bootedAt": *BOOTED_AT,
        "agent": build(),
        "release": read_release(Path::new(&release)),
        "openclaw": openclaw_version(),
        "features": features,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str =
        r#"{"commit":"a1b2c3d4e5f6","commitDate":"2026-09-19T08:11:00Z","installedAt":"2026-09-19T09:02:44Z"}"#;

    fn at(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("dir");
        }
        std::fs::write(&p, body).expect("write");
        p
    }

    #[test]
    fn release_file() {
        let d = tempfile::tempdir().expect("dir");
        let base: Value = serde_json::from_str(RELEASE).expect("json");
        assert_eq!(read_release(&at(d.path(), "ok.json", RELEASE)), base);
        let mut v = base.clone();
        v["version"] = json!("1.4.0");
        assert_eq!(read_release(&at(d.path(), "v.json", &v.to_string())), v);
        for bad in [json!("1.4"), json!("v1.4.0"), json!(140), json!("")] {
            let mut b = base.clone();
            b["version"] = bad;
            assert_eq!(read_release(&at(d.path(), "bad.json", &b.to_string())), base);
        }
        assert_eq!(read_release(&d.path().join("missing.json")), Value::Null);
        assert_eq!(
            read_release(&at(d.path(), "half.json", r#"{"commit":"a1b2c3d","commitDa"#)),
            Value::Null
        );
        assert_eq!(
            read_release(&at(d.path(), "p.json", r#"{"commit":"a1b2c3d"}"#)),
            Value::Null
        );
        let mut typed = base.clone();
        typed["commit"] = json!(12345);
        assert_eq!(read_release(&at(d.path(), "t.json", &typed.to_string())), Value::Null);
        assert_eq!(read_release(&at(d.path(), "a.json", r#"["a1b2c3d"]"#)), Value::Null);
        assert_eq!(read_release(&at(d.path(), "s.json", r#""a1b2c3d""#)), Value::Null);
        let mut long = base.clone();
        long["commit"] = json!("z".repeat(5000));
        assert_eq!(
            read_release(&at(d.path(), "l.json", &long.to_string()))["commit"]
                .as_str()
                .map(str::len),
            Some(64)
        );
    }

    #[test]
    fn openclaw_version() {
        let d = tempfile::tempdir().expect("dir");
        let pkg = at(
            d.path(),
            "openclaw/package.json",
            r#"{"name":"openclaw","version":"2026.9.14"}"#,
        );
        let nobin = d.path().join("no-such-bin");
        assert_eq!(read_openclaw_version(&[pkg], &nobin).as_deref(), Some("2026.9.14"));
        assert_eq!(
            read_openclaw_version(&[d.path().join("nope/package.json")], &nobin),
            None
        );
        let broken = at(d.path(), "broken.json", "{not json");
        assert_eq!(read_openclaw_version(&[broken], &nobin), None);
        // Through the bin's link, up to the package root.
        at(
            d.path(),
            "lib/openclaw/package.json",
            r#"{"name":"openclaw","version":"2026.9.7"}"#,
        );
        let cli = at(d.path(), "lib/openclaw/dist/cli.js", "");
        let bin = d.path().join("openclaw-bin");
        std::os::unix::fs::symlink(&cli, &bin).expect("link");
        assert_eq!(read_openclaw_version(&[], &bin).as_deref(), Some("2026.9.7"));
    }

    #[test]
    fn speech_families() {
        let d = tempfile::tempdir().expect("dir");
        let f = d.path().join("capabilities.json");
        assert!(speech_features(&f, false).is_empty());
        let w = |body: &str| std::fs::write(&f, body).expect("write");
        w(r#"{"speechFamilies":["realtime"]}"#);
        assert_eq!(speech_features(&f, false), ["speech_realtime"]);
        w(r#"{"speechFamilies":["live","realtime","other"]}"#);
        assert_eq!(speech_features(&f, false), ["speech_realtime", "speech_live"]);
        w(r#"{"speechFamilies":["realtime","live"],"wakeWords":true}"#);
        assert_eq!(
            speech_features(&f, false),
            ["speech_realtime", "speech_live", "speech_wake"]
        );
        w(r#"{"speechFamilies":["realtime","live"],"wakeWords":true,"wakeLocal":true}"#);
        assert_eq!(
            speech_features(&f, true),
            ["speech_realtime", "speech_live", "speech_wake", "speech_wake_local"]
        );
        assert_eq!(
            speech_features(&f, false),
            ["speech_realtime", "speech_live", "speech_wake"]
        );
        w(r#"{"speechFamilies":["realtime","live"],"wakeWords":true,"wakeLocal":true,"alwaysListening":true}"#);
        assert_eq!(
            speech_features(&f, true),
            [
                "speech_realtime",
                "speech_live",
                "speech_wake",
                "speech_wake_local",
                "speech_always"
            ]
        );
        w(r#"{"speechFamilies":["live"],"fullAgent":true,"present":true}"#);
        assert_eq!(
            speech_features(&f, false),
            ["speech_live", "meeting_full_agent", "meeting_present"]
        );
        w("not json");
        assert!(speech_features(&f, false).is_empty());
    }

    #[test]
    fn firewall_origin_from_access_state() {
        let d = tempfile::tempdir().expect("dir");
        assert_eq!(firewall_origin(d.path()), None);
        at(
            d.path(),
            "access.json",
            r#"{"firewallOrigin":"https://fw.example.com","revoked":{}}"#,
        );
        assert_eq!(firewall_origin(d.path()).as_deref(), Some("https://fw.example.com"));
        at(d.path(), "access.json", r#"{"firewallOrigin":"http://fw.example.com"}"#);
        assert_eq!(firewall_origin(d.path()), None);
    }
}
