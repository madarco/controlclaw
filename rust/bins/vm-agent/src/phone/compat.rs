//! The reviewed fixes to the pinned voice-call plugin (`phone-compat.ts`,
//! `phone-realtime-compat.ts`, `phone-reply-compat.ts`, and the admission stages) and the realtime
//! consult runtime check (`phone-runtime.ts`, every reviewed admission build).
//!
//! The patches are JavaScript source edits: exact string swaps, each file's sha256 checked before
//! and after. They stay JavaScript; this build carries them byte for byte in `compat.json`, which
//! `rust/conformance/cases/w8/phone-compat/gen.mts` writes from the TS tables (`--check` compares).
//! Never patch an unknown file.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize)]
pub struct Patch {
    pub file: String,
    pub before: String,
    pub after: String,
    pub changes: Vec<(String, String)>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Compat {
    admission_digests: Vec<String>,
    no_reply_text: String,
    patches: Vec<Patch>,
}

static COMPAT: LazyLock<Compat> =
    LazyLock::new(|| serde_json::from_str(include_str!("compat.json")).expect("compat.json"));

/// Every reviewed patch, in the order `patchPhonePlugin` applies them.
pub fn patches() -> &'static [Patch] {
    &COMPAT.patches
}

/// What a failed classic reply says to the caller (`PHONE_NO_REPLY_TEXT`).
pub fn no_reply_text() -> &'static str {
    &COMPAT.no_reply_text
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// `patchPhoneSource`: one reviewed patch, refusing anything but its exact starting file. A file
/// already patched is returned as it is.
pub fn patch_source(source: &str, patch: &Patch) -> Result<String, &'static str> {
    if sha256_hex(source) == patch.after {
        return Ok(source.to_string());
    }
    if sha256_hex(source) != patch.before {
        return Err("voice plugin source integrity mismatch");
    }
    let mut result = source.to_string();
    for (before, after) in &patch.changes {
        if result.matches(before.as_str()).count() != 1 {
            return Err("voice plugin patch mismatch");
        }
        result = result.replacen(before.as_str(), after, 1);
    }
    if sha256_hex(&result) != patch.after {
        return Err("voice plugin patched integrity mismatch");
    }
    Ok(result)
}

/// `patchPhoneStages`: the file's own place in a chain of patches, and every later one, so an
/// install patched by an older release is brought up to date.
pub fn patch_stages(source: &str, steps: &[&Patch]) -> Result<String, &'static str> {
    let digest = sha256_hex(source);
    if steps.last().is_some_and(|s| s.after == digest) {
        return Ok(source.to_string());
    }
    let start = steps
        .iter()
        .position(|s| s.before == digest)
        .ok_or("voice plugin source integrity mismatch")?;
    let mut source = source.to_string();
    for step in &steps[start..] {
        source = patch_source(&source, step)?;
    }
    Ok(source)
}

/// `patchPhonePlugin`: every file is checked before any is written, and a file is replaced with
/// a temporary file and a rename, so an interrupted patch resumes safely.
pub fn patch_plugin(install_path: &Path) -> Result<(), String> {
    let mut names: Vec<&str> = Vec::new();
    for p in patches() {
        if !names.contains(&p.file.as_str()) {
            names.push(&p.file);
        }
    }
    let mut files: Vec<(PathBuf, String, String)> = Vec::new();
    for name in names {
        let path = install_path.join("dist").join(".setup").join(name);
        let source = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let steps: Vec<&Patch> = patches().iter().filter(|p| p.file == name).collect();
        let patched = patch_stages(&source, &steps)?;
        files.push((path, source, patched));
    }
    for (path, source, patched) in files {
        if source != patched {
            let tmp = PathBuf::from(format!("{}.cc-tmp", path.display()));
            std::fs::write(&tmp, patched).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

static BUILD_HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"-[A-Za-z0-9_-]{8}(\.mjs["'])"#).expect("regex"));
static ADMISSION_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^gateway-work-admission-[A-Za-z0-9_-]{8}\.mjs$").expect("regex"));

/// `phoneAdmissionDigest`: only bundler file names may vary; the code and export aliases are pinned.
pub fn admission_digest(source: &str) -> String {
    sha256_hex(&BUILD_HASH.replace_all(source, "-BUILDHASH$1"))
}

/// `resolvePhoneAdmission`: the one gateway admission module, if its code is the reviewed one.
pub fn resolve_admission(dir: &Path) -> Result<PathBuf, &'static str> {
    const UNSUPPORTED: &str = "Unsupported realtime consult runtime";
    let files: Vec<String> = std::fs::read_dir(dir)
        .map_err(|_| UNSUPPORTED)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| ADMISSION_FILE.is_match(n))
        .collect();
    let [only] = files.as_slice() else {
        return Err(UNSUPPORTED);
    };
    let path = dir.join(only);
    let source = std::fs::read_to_string(&path).map_err(|_| UNSUPPORTED)?;
    if !phone_admission_ok(&source) {
        return Err(UNSUPPORTED);
    }
    Ok(path)
}

/// `isReviewedAdmission`: this admission module's code is one of the reviewed builds.
pub fn phone_admission_ok(source: &str) -> bool {
    COMPAT.admission_digests.contains(&admission_digest(source))
}

/// `phonePluginItem` for the health check, with the plugin installed at `plugin_dir`: `ok` when
/// every file is at its last reviewed stage, `unpatched` when one could still be patched,
/// `missing` when a file cannot be read, `mismatch` for another version or an unknown file. The
/// second value is the installed version.
pub fn phone_patch_status(plugin_dir: &Path) -> (&'static str, Option<serde_json::Value>) {
    // The raw value, as the TS passes it on (`version as string ?? null`): a number stays a number.
    let version = std::fs::read(plugin_dir.join("package.json"))
        .ok()
        .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        .and_then(|j| j.get("version").filter(|v| !v.is_null()).cloned());
    if version.as_ref().and_then(serde_json::Value::as_str) != Some(super::apply::PHONE_VERSION) {
        return ("mismatch", version);
    }
    let mut names: Vec<&str> = Vec::new();
    for p in patches() {
        if !names.contains(&p.file.as_str()) {
            names.push(&p.file);
        }
    }
    let mut unpatched = false;
    for name in names {
        // `readFileSync(path, "utf8")` decodes bad bytes rather than failing.
        let Ok(raw) = std::fs::read(plugin_dir.join("dist").join(".setup").join(name)) else {
            return ("missing", version);
        };
        let source = String::from_utf8_lossy(&raw);
        let steps: Vec<&Patch> = patches().iter().filter(|p| p.file == name).collect();
        match patch_stages(&source, &steps) {
            Ok(patched) if patched != source => unpatched = true,
            Ok(_) => {}
            Err(_) => return ("mismatch", version),
        }
    }
    (if unpatched { "unpatched" } else { "ok" }, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(before: &str, after: &str, from: &str, to: &str) -> Patch {
        Patch {
            file: "f.mjs".into(),
            before: sha256_hex(before),
            after: sha256_hex(after),
            changes: vec![(from.into(), to.into())],
        }
    }

    /// `phone.test.ts`: "compatibility patch refuses unknown or tampered files and resumes an
    /// applied patch".
    #[test]
    fn refuses_unknown_or_tampered_files_and_resumes() {
        let patch = step("original", "fixed", "original", "fixed");
        assert_eq!(patch_source("original", &patch).as_deref(), Ok("fixed"));
        assert_eq!(patch_source("fixed", &patch).as_deref(), Ok("fixed"));
        assert_eq!(
            patch_source("unknown", &patch),
            Err("voice plugin source integrity mismatch")
        );
        let wrong = Patch {
            after: sha256_hex("unexpected"),
            ..patch
        };
        assert_eq!(
            patch_source("original", &wrong),
            Err("voice plugin patched integrity mismatch")
        );
        // A string that is in the file twice is not a reviewed swap.
        let twice = step("aa", "ba", "a", "b");
        assert_eq!(patch_source("aa", &twice), Err("voice plugin patch mismatch"));
    }

    /// `patch-check.test.ts`: "the voice-call plugin: not installed, wrong version, missing file,
    /// unreviewed file" (not installed is the caller's: it has no directory).
    #[test]
    fn patch_status_for_the_health_check() {
        let dir = tempfile::tempdir().expect("dir");
        let d = dir.path();
        assert_eq!(phone_patch_status(d), ("mismatch", None));
        std::fs::write(d.join("package.json"), r#"{"version":"2026.9.9"}"#).expect("w");
        assert_eq!(phone_patch_status(d), ("mismatch", Some(serde_json::json!("2026.9.9"))));
        std::fs::write(d.join("package.json"), r#"{"version":"2026.9.7"}"#).expect("w");
        assert_eq!(phone_patch_status(d), ("missing", Some(serde_json::json!("2026.9.7"))));
        let setup = d.join("dist").join(".setup");
        std::fs::create_dir_all(&setup).expect("dir");
        for p in patches() {
            std::fs::write(setup.join(&p.file), "not the reviewed source").expect("w");
        }
        assert_eq!(phone_patch_status(d), ("mismatch", Some(serde_json::json!("2026.9.7"))));
        // A version that is not text is passed on as it is.
        std::fs::write(d.join("package.json"), r#"{"version":2026}"#).expect("w");
        assert_eq!(phone_patch_status(d), ("mismatch", Some(serde_json::json!(2026))));
        assert!(!phone_admission_ok("not the reviewed module"));
    }

    /// "plugin upgrades resume every reviewed stage, including already patched older installs".
    #[test]
    fn upgrades_resume_every_stage() {
        let sources = ["stock", "classic", "realtime-old", "realtime-current"];
        let steps: Vec<Patch> = (0..3)
            .map(|i| step(sources[i], sources[i + 1], sources[i], sources[i + 1]))
            .collect();
        let all: Vec<&Patch> = steps.iter().collect();
        for s in sources {
            assert_eq!(patch_stages(s, &all).as_deref(), Ok("realtime-current"));
        }
        assert!(patch_stages("realtime-tampered", &all).is_err());
        assert!(patch_stages("stock", &[&steps[0], &steps[2]]).is_err());
    }

    #[test]
    fn the_tables_chain_per_file() {
        // Each file's patches form one chain: every step starts where the one before ended.
        let mut last: std::collections::HashMap<&str, &str> = Default::default();
        for p in patches() {
            if let Some(prev) = last.get(p.file.as_str()) {
                assert_eq!(*prev, p.before, "{} does not continue its chain", p.file);
            }
            last.insert(&p.file, &p.after);
        }
        assert_eq!(patches().len(), 9);
        assert!(no_reply_text().starts_with("Sorry"));
    }

    #[test]
    fn patch_plugin_checks_every_file_before_writing_any() {
        let dir = tempfile::tempdir().expect("dir");
        let setup = dir.path().join("dist").join(".setup");
        std::fs::create_dir_all(&setup).expect("dir");
        for name in [
            "runtime-entry-BNOQRXii.mjs",
            "response-generator-BzKrJMEb.mjs",
            "twilio-Bp3gfmUB.mjs",
        ] {
            std::fs::write(setup.join(name), "not the pinned source").expect("file");
        }
        assert!(patch_plugin(dir.path()).is_err());
        // Nothing was written, and the missing file is an error too.
        assert_eq!(
            std::fs::read_to_string(setup.join("twilio-Bp3gfmUB.mjs")).expect("file"),
            "not the pinned source"
        );
    }

    /// `phone-runtime.test.ts`: OpenClaw 2026.9.7's admission module and 9.8's (only an import
    /// changed) are accepted; two at once, none, or changed code are refused.
    #[test]
    fn admission_runtime() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packages/vm-agent/src/phone-admission.fixture.txt");
        let original = std::fs::read_to_string(fixture).expect("fixture");
        let upgraded = original.replace("./subsystem-SFVirYCI.mjs", "./subsystem-CeqVSEVi.mjs");
        for (name, source) in [
            ("gateway-work-admission-DPOFUg7J.mjs", &original),
            ("gateway-work-admission-B4bQUVQ6.mjs", &upgraded),
        ] {
            let dir = tempfile::tempdir().expect("dir");
            assert_eq!(admission_digest(source), COMPAT.admission_digests[0]);
            assert!(phone_admission_ok(source));
            std::fs::write(dir.path().join(name), source).expect("file");
            assert_eq!(resolve_admission(dir.path()), Ok(dir.path().join(name)));
            std::fs::write(dir.path().join("gateway-work-admission-Xxxxxxxx.mjs"), source).expect("file");
            assert!(resolve_admission(dir.path()).is_err(), "two modules are ambiguous");
        }
        let dir = tempfile::tempdir().expect("dir");
        assert!(resolve_admission(dir.path()).is_err());
        std::fs::write(dir.path().join("gateway-work-admission-AbCd1234.mjs"), "changed code").expect("file");
        assert_eq!(
            resolve_admission(dir.path()),
            Err("Unsupported realtime consult runtime")
        );
        // Only the bundler's 8-character names change the source; they do not change the digest.
        assert_eq!(
            admission_digest(r#"import "./chunk-AbCd1234.mjs";"#),
            admission_digest(r#"import "./chunk-ZyXw9876.mjs";"#)
        );
        assert_ne!(admission_digest("a"), admission_digest("b"));
    }

    #[test]
    fn openclaw_2026_9_35s_admission_module_is_a_reviewed_build() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packages/vm-agent/src/phone-admission-2026.9.35.fixture.txt");
        let source = std::fs::read_to_string(fixture).expect("fixture");
        assert!(phone_admission_ok(&source));
        assert_ne!(admission_digest(&source), COMPAT.admission_digests[0]);
        assert!(!phone_admission_ok(&source.replacen("export", "export ", 1)));
        // The plugin is moved on to accept them: the last stage of its file.
        assert!(patches().iter().any(|p| {
            p.changes
                .iter()
                .any(|(_, a)| a.contains(COMPAT.admission_digests[2].as_str()))
        }));
    }
}
