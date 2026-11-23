//! The reviewed fixes to the pinned voice-call plugin (`phone-compat.ts`,
//! `phone-realtime-compat.ts`, `phone-reply-compat.ts`, and the admission stages) and the realtime
//! consult runtime check (`phone-runtime.ts`, every reviewed admission build).
//!
//! The patches are JavaScript source edits: exact string swaps, each file's sha256 checked before
//! and after. They stay JavaScript; this build carries them byte for byte in `compat.json`, first
//! written from the retired TS vm-agent's tables and edited here since.
//! Never patch an unknown file.

use std::collections::BTreeMap;
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
    /// Each reviewed admission build's digest, and the export its bundler gave
    /// `tryBeginGatewayIndependentRootWorkAdmission` (`A` in 2026.11.3 and 11.4, `k` in 11.5).
    admission_exports: BTreeMap<String, String>,
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
/// From OpenClaw 2026.11.5 the admission module keeps its state in a module of its own.
static ADMISSION_STATE_FILE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^gateway-work-admission-state-[A-Za-z0-9_-]{8}\.mjs$").expect("regex"));

/// `phoneAdmissionDigest`: only bundler file names may vary; the code and export aliases are pinned.
/// The state module's code, when there is one, follows the admission module's: both are reviewed.
pub fn admission_digest(source: &str, state: Option<&str>) -> String {
    let code = |s: &str| BUILD_HASH.replace_all(s, "-BUILDHASH$1").into_owned();
    sha256_hex(&(code(source) + &state.map(code).unwrap_or_default()))
}

/// The one gateway admission module in OpenClaw's `dist`, if its code (with its state module's) is a
/// reviewed build. Err `missing` when the folder or a module cannot be read, `mismatch` for none or
/// two of either module, or code that is not reviewed.
pub fn admission_status(dir: &Path) -> Result<PathBuf, &'static str> {
    let names: Vec<String> = std::fs::read_dir(dir)
        .map_err(|_| "missing")?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let of = |re: &Regex| names.iter().filter(|n| re.is_match(n)).collect::<Vec<_>>();
    let (admission, state) = (of(&ADMISSION_FILE), of(&ADMISSION_STATE_FILE));
    let [only] = admission.as_slice() else {
        return Err("mismatch");
    };
    if state.len() > 1 {
        return Err("mismatch");
    }
    let path = dir.join(only);
    let source = std::fs::read(&path).map_err(|_| "missing")?;
    let state = match state.first() {
        Some(name) => Some(std::fs::read(dir.join(name)).map_err(|_| "missing")?),
        None => None,
    };
    // `readFileSync(path, "utf8")` decodes bad bytes rather than failing.
    let state = state.as_deref().map(String::from_utf8_lossy);
    if !phone_admission_ok(&String::from_utf8_lossy(&source), state.as_deref()) {
        return Err("mismatch");
    }
    Ok(path)
}

/// `resolvePhoneAdmission`: the one gateway admission module, if its code is the reviewed one.
pub fn resolve_admission(dir: &Path) -> Result<PathBuf, &'static str> {
    admission_status(dir).map_err(|_| "Unsupported realtime consult runtime")
}

/// `isReviewedAdmission`: this admission module's code, with its state module's, is one of the
/// reviewed builds.
pub fn phone_admission_ok(source: &str, state: Option<&str>) -> bool {
    COMPAT.admission_exports.contains_key(&admission_digest(source, state))
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
        // The version before this pin is another version.
        std::fs::write(d.join("package.json"), r#"{"version":"2026.9.7"}"#).expect("w");
        assert_eq!(phone_patch_status(d), ("mismatch", Some(serde_json::json!("2026.9.7"))));
        let pinned = serde_json::json!(super::super::apply::PHONE_VERSION);
        std::fs::write(
            d.join("package.json"),
            serde_json::json!({"version": pinned}).to_string(),
        )
        .expect("w");
        assert_eq!(phone_patch_status(d), ("missing", Some(pinned.clone())));
        let setup = d.join("dist").join(".setup");
        std::fs::create_dir_all(&setup).expect("dir");
        for p in patches() {
            std::fs::write(setup.join(&p.file), "not the reviewed source").expect("w");
        }
        assert_eq!(phone_patch_status(d), ("mismatch", Some(pinned)));
        // A version that is not text is passed on as it is.
        std::fs::write(d.join("package.json"), r#"{"version":2026}"#).expect("w");
        assert_eq!(phone_patch_status(d), ("mismatch", Some(serde_json::json!(2026))));
        assert!(!phone_admission_ok("not the reviewed module", None));
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
        // Voice-call 2026.11.3 on four files, and one later stage on the consult's file (the
        // admission builds of OpenClaw 2026.11.5), so a plugin patched by the release before goes on
        // from where it is.
        assert_eq!(patches().len(), 5);
        let files: std::collections::HashSet<&str> = patches().iter().map(|p| p.file.as_str()).collect();
        assert_eq!(files.len(), 4);
        assert!(no_reply_text().starts_with("Sorry"));
    }

    #[test]
    fn patch_plugin_checks_every_file_before_writing_any() {
        let dir = tempfile::tempdir().expect("dir");
        let setup = dir.path().join("dist").join(".setup");
        std::fs::create_dir_all(&setup).expect("dir");
        for name in [
            "runtime-entry-Cy51Uayg.mjs",
            "response-generator-CZJCHbml.mjs",
            "twilio-CrPMFGbz.mjs",
        ] {
            std::fs::write(setup.join(name), "not the pinned source").expect("file");
        }
        assert!(patch_plugin(dir.path()).is_err());
        // Nothing was written, and the missing file is an error too.
        assert_eq!(
            std::fs::read_to_string(setup.join("twilio-CrPMFGbz.mjs")).expect("file"),
            "not the pinned source"
        );
    }

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/phone/fixtures")
            .join(name);
        std::fs::read_to_string(path).expect("fixture")
    }

    /// `phone-runtime.test.ts`: OpenClaw 2026.11.3's admission module is accepted, also under
    /// other bundler names; two at once, none, or changed code are refused.
    #[test]
    fn admission_runtime() {
        let original = fixture("phone-admission-2026.11.3.fixture.txt");
        let upgraded = original.replace("./subsystem-mStysHHC.mjs", "./subsystem-AbCd1234.mjs");
        assert_ne!(original, upgraded);
        for (name, source) in [
            ("gateway-work-admission-FWbk4b3p.mjs", &original),
            ("gateway-work-admission-B4bQUVQ6.mjs", &upgraded),
        ] {
            let dir = tempfile::tempdir().expect("dir");
            assert_eq!(
                COMPAT
                    .admission_exports
                    .get(&admission_digest(source, None))
                    .map(String::as_str),
                Some("A")
            );
            assert!(phone_admission_ok(source, None));
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
        assert!(!phone_admission_ok(&original.replacen("export", "export ", 1), None));
        // Only the bundler's 8-character names change the source; they do not change the digest.
        assert_eq!(
            admission_digest(r#"import "./chunk-AbCd1234.mjs";"#, None),
            admission_digest(r#"import "./chunk-ZyXw9876.mjs";"#, None)
        );
        assert_ne!(admission_digest("a", None), admission_digest("b", None));
    }

    /// The plugin is pinned to 2026.11.3, which needs OpenClaw 2026.11.3: the 9.x admission modules
    /// (9.7/9.8, 9.33 to 9.37) are no longer reviewed builds.
    #[test]
    fn older_admission_modules_are_refused() {
        for name in ["phone-admission.fixture.txt", "phone-admission-2026.9.35.fixture.txt"] {
            assert!(!phone_admission_ok(&fixture(name), None), "{name}");
        }
        assert_eq!(COMPAT.admission_exports.len(), 2);
    }

    /// OpenClaw 2026.11.5 moved the admission state to a module of its own and minified the names;
    /// the function and what it returns are unchanged, and its export is `k` (`A` is now
    /// `tryBeginGatewayPreparedRestartRootWorkAdmission`, which the consult must never call).
    #[test]
    fn admission_2026_11_5() {
        let source = fixture("phone-admission-2026.11.5.fixture.txt");
        let state = fixture("phone-admission-state-2026.11.5.fixture.txt");
        assert!(phone_admission_ok(&source, Some(&state)));
        assert_eq!(
            COMPAT
                .admission_exports
                .get(&admission_digest(&source, Some(&state)))
                .map(String::as_str),
            Some("k")
        );
        // The admission module alone, or with a state module that is not the reviewed one, is not.
        assert!(!phone_admission_ok(&source, None));
        assert!(!phone_admission_ok(
            &source,
            Some(&state.replacen("e.signal", "e.signal ", 1))
        ));
        assert!(source.contains("tryBeginGatewayIndependentRootWorkAdmission as k,"));
        assert!(source.contains("tryBeginGatewayPreparedRestartRootWorkAdmission as A,"));
        let dir = tempfile::tempdir().expect("dir");
        let main = dir.path().join("gateway-work-admission-C_AYjV_d.mjs");
        std::fs::write(&main, &source).expect("file");
        assert_eq!(
            admission_status(dir.path()),
            Err("mismatch"),
            "its state module is missing"
        );
        // The state module is read with it, and is not a second admission module.
        std::fs::write(dir.path().join("gateway-work-admission-state-X3ZM0tLe.mjs"), &state).expect("file");
        assert_eq!(resolve_admission(dir.path()), Ok(main.clone()));
        std::fs::write(dir.path().join("gateway-work-admission-state-Ab12Cd34.mjs"), &state).expect("file");
        assert_eq!(admission_status(dir.path()), Err("mismatch"), "two state modules");
        assert_eq!(admission_status(&dir.path().join("none")), Err("missing"));
    }

    /// The patched consult, at its last stage, checks the same builds and imports the export each
    /// gives `tryBeginGatewayIndependentRootWorkAdmission` (`A` in 11.3/11.4, `k` in 11.5; it was
    /// `E` up to 9.37).
    #[test]
    fn the_consult_stage_checks_the_reviewed_digests() {
        let map = serde_json::to_string(&COMPAT.admission_exports).expect("json");
        let consult = patches()
            .iter()
            .flat_map(|p| p.changes.iter())
            .filter(|(_, a)| a.contains("beginPhoneConsult"))
            .map(|(_, a)| a.as_str())
            .next_back()
            .expect("consult change");
        assert!(
            consult.contains(&format!("const admissionExport = {map}[createHash(")),
            "{consult}"
        );
        assert!(consult.contains("if (!admissionExport) throw new Error(\"Unsupported realtime consult runtime\");"));
        assert!(consult.contains("const { [admissionExport]: beginPhoneConsult } = await import(admissionPath);"));
    }

    /// The stock voice-call 2026.11.3 file goes through both stages, and a file patched by the
    /// release before (its first stage only) is brought to the same result.
    #[test]
    fn the_consult_file_reaches_its_last_stage() {
        let steps: Vec<&Patch> = patches()
            .iter()
            .filter(|p| p.file.starts_with("runtime-entry-"))
            .collect();
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[1].before, steps[0].after);
    }
}
