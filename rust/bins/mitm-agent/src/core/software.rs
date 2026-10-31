//! What this firewall box runs (`software.ts`), on `/ready` and on every beat: this build, the
//! Ansible release on disk, whether a reboot is due, when it booted. Never fails: a box that
//! cannot describe itself must still beat.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};

/// The build stamp, set at build time (`CC_BUILD_VERSION`, `CC_BUILD_COMMIT`, `CC_BUILD_AT`), as
/// tsup bakes `__CC_BUILD_*__` into the Node bundle; `dev` and `unknown` without.
fn build() -> Value {
    json!({
        "version": option_env!("CC_BUILD_VERSION").unwrap_or("dev"),
        "commit": option_env!("CC_BUILD_COMMIT").unwrap_or("unknown"),
        "builtAt": option_env!("CC_BUILD_AT").unwrap_or("unknown"),
    })
}

static BOOTED_AT: LazyLock<String> = LazyLock::new(|| {
    let up = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0);
    cc_crypto::store_health::iso_from_millis((now - up * 1000.0) as i64)
});

const MAX_FIELD: usize = 64;
static SEMVER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+$").expect("regex"));

fn clip(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(String::from_utf16_lossy(
            &s.encode_utf16().take(MAX_FIELD).collect::<Vec<u16>>(),
        )),
        _ => None,
    }
}

/// `readRelease`: all three fields, or nothing; `version` only when it is a release version.
pub fn read_release(path: &Path) -> Value {
    let Some(Value::Object(rec)) = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
    else {
        return Value::Null;
    };
    let (Some(commit), Some(date), Some(installed)) = (
        clip(rec.get("commit")),
        clip(rec.get("commitDate")),
        clip(rec.get("installedAt")),
    ) else {
        return Value::Null;
    };
    let mut m = Map::new();
    m.insert("commit".into(), json!(commit));
    m.insert("commitDate".into(), json!(date));
    m.insert("installedAt".into(), json!(installed));
    if let Some(v) = clip(rec.get("version")).filter(|v| SEMVER.is_match(v)) {
        m.insert("version".into(), json!(v));
    }
    Value::Object(m)
}

/// `llm_blocks`, then `rust_runtime`, and `runtime_fallback` when the proxy beside this agent was put
/// back on mitmproxy (the TS's `runtimeFallback`). The console keeps these from the software report;
/// the beat's own `features` is the complete list of what this firewall can do, so they stay off it.
fn features(markers: &Path) -> Vec<String> {
    let mut f = vec!["llm_blocks".to_string()];
    f.extend(cc_store::runtime_features(&["controlclaw-mitmproxy"], markers));
    f
}

/// `boxSoftware`.
pub fn box_software() -> Value {
    let release = std::env::var("RELEASE_FILE").unwrap_or_else(|_| "/etc/controlclaw/release.json".into());
    json!({
        "agent": build(),
        "release": read_release(Path::new(&release)),
        "rebootRequired": Path::new("/var/run/reboot-required").exists(),
        "bootedAt": *BOOTED_AT,
        "features": features(Path::new(cc_store::RUNTIME_MARKERS_DIR)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_files() {
        let d = tempfile::tempdir().expect("dir");
        let p = d.path().join("release.json");
        assert_eq!(read_release(&p), Value::Null);
        std::fs::write(
            &p,
            r#"{"commit":"abc","commitDate":"2026-10-01","installedAt":"2026-10-02","version":"1.4.0"}"#,
        )
        .expect("w");
        assert_eq!(
            read_release(&p),
            json!({"commit":"abc","commitDate":"2026-10-01","installedAt":"2026-10-02","version":"1.4.0"})
        );
        std::fs::write(
            &p,
            format!(
                r#"{{"commit":"{}","commitDate":"d","installedAt":"i","version":"v1"}}"#,
                "x".repeat(100)
            ),
        )
        .expect("w");
        assert_eq!(
            read_release(&p),
            json!({"commit": "x".repeat(64),"commitDate":"d","installedAt":"i"})
        );
        std::fs::write(&p, r#"{"commit":"abc","commitDate":""}"#).expect("w");
        assert_eq!(read_release(&p), Value::Null);
        std::fs::write(&p, "[1]").expect("w");
        assert_eq!(read_release(&p), Value::Null);
        let s = box_software();
        assert_eq!(s["features"][0], json!("llm_blocks"));
        let keys: Vec<&String> = s.as_object().expect("obj").keys().collect();
        assert_eq!(keys, ["agent", "release", "rebootRequired", "bootedAt", "features"]);
    }

    #[test]
    fn runtime_features_follow_llm_blocks() {
        let d = tempfile::tempdir().expect("dir");
        assert_eq!(features(d.path()), ["llm_blocks", "rust_runtime"]);
        std::fs::write(d.path().join("controlclaw-mitmproxy.fallback"), "{}").expect("marker");
        assert_eq!(features(d.path()), ["llm_blocks", "rust_runtime", "runtime_fallback"]);
    }
}
