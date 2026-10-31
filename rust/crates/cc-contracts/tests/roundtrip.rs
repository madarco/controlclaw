//! Every sample file read into its type and written back must be the same JSON: no key lost, none
//! added, `null`s kept, numbers in the form they came. Samples follow the TS writers
//! (packages/mitm-agent/src) and the addon's own config (packages/mitm-proxy/config).

use std::path::PathBuf;

use cc_contracts::content::{ContentAuditRecord, ContentOwnFile, ContentRulesFile};
use cc_contracts::credentials::CredentialsFile;
use cc_contracts::exit::ExitFile;
use cc_contracts::grants::GrantsFile;
use cc_contracts::identities::{IdentitiesFile, vm_id_for_ip};
use cc_contracts::login_targets::LoginTargetsFile;
use cc_contracts::media::{MeetingMediaFile, PhoneMediaFile, RawLeases, meeting_lease_for, phone_leases_for};
use cc_contracts::pending::PendingRecord;
use cc_contracts::rules::RulesFile;
use cc_contracts::traffic::TrafficRecord;
use cc_contracts::{FileSpec, write_atomic};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

type Res = Result<(), Box<dyn std::error::Error>>;

fn sample(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Parse as `T`, write back, and compare with the original as JSON values.
fn same<T: DeserializeOwned + Serialize>(text: &str) -> Res {
    let typed: T = serde_json::from_str(text)?;
    let back: Value = serde_json::to_value(&typed)?;
    let original: Value = serde_json::from_str(text)?;
    assert_eq!(back, original, "round trip changed\n{text}");
    Ok(())
}

fn same_lines<T: DeserializeOwned + Serialize>(text: &str) -> Res {
    for line in text.lines().filter(|l| !l.is_empty()) {
        same::<T>(line)?;
    }
    Ok(())
}

#[test]
fn every_file_round_trips() -> Res {
    same::<RulesFile>(&sample("rules.json"))?;
    same::<CredentialsFile>(&sample("credentials.json"))?;
    same::<IdentitiesFile>(&sample("identities.json"))?;
    same::<GrantsFile>(&sample("grants.json"))?;
    same::<ExitFile>(&sample("exit.json"))?;
    same::<ExitFile>(&sample("exit-off.json"))?;
    same::<MeetingMediaFile>(&sample("meeting-media.json"))?;
    same::<PhoneMediaFile>(&sample("phone-media.json"))?;
    same::<LoginTargetsFile>(&sample("login-targets.json"))?;
    same::<ContentRulesFile>(&sample("content-rules.json"))?;
    same::<ContentRulesFile>(&sample("content-rules-unreadable.json"))?;
    same::<ContentOwnFile>(&sample("content-own.json"))?;
    same_lines::<PendingRecord>(&sample("pending.jsonl"))?;
    same_lines::<TrafficRecord>(&sample("traffic.jsonl"))?;
    same_lines::<ContentAuditRecord>(&sample("content-rules.jsonl"))?;
    Ok(())
}

#[test]
fn numbers_keep_their_form() -> Res {
    // An integer must not come back as 1767225600.0, nor a float lose its fraction.
    let ids: IdentitiesFile = serde_json::from_str(&sample("identities.json"))?;
    let text = serde_json::to_string(&ids)?;
    assert!(text.contains(r#""code_until":1767225600.5"#), "{text}");
    assert!(text.contains(r#""update_until":1767225600}"#), "{text}");
    Ok(())
}

#[test]
fn readers_answer_like_the_addon() -> Res {
    let ids: IdentitiesFile = serde_json::from_str(&sample("identities.json"))?;
    assert_eq!(vm_id_for_ip(&ids, "10.0.0.4"), Some("vm_def"));
    assert_eq!(vm_id_for_ip(&ids, ""), None);
    assert!(ids[1].is_locked() && !ids[0].is_locked() && ids[0].on_tailnet());

    let creds: CredentialsFile = serde_json::from_str(&sample("credentials.json"))?;
    assert_eq!(creds.iter().filter(|c| c.is_login()).count(), 1);
    assert_eq!(creds.iter().filter(|c| c.is_custom_secret()).count(), 1);

    let exit: ExitFile = serde_json::from_str(&sample("exit.json"))?;
    assert!(exit.is_enabled());
    assert!(!serde_json::from_str::<ExitFile>(&sample("exit-off.json"))?.is_enabled());

    let rules: ContentRulesFile = serde_json::from_str(&sample("content-rules.json"))?;
    assert_eq!(rules.known_rules().map(<[_]>::len), Some(1));
    let unknown: ContentRulesFile = serde_json::from_str(&sample("content-rules-unreadable.json"))?;
    assert!(unknown.known_rules().is_none());
    Ok(())
}

#[test]
fn one_bad_lease_costs_only_its_own_agent() -> Res {
    let mut raw: RawLeases = serde_json::from_str(&sample("meeting-media.json"))?;
    raw.insert("vm_bad".into(), serde_json::json!({"id": 7}));
    assert!(meeting_lease_for(&raw, "vm_abc").is_some());
    assert!(meeting_lease_for(&raw, "vm_bad").is_none());
    let phone: RawLeases = serde_json::from_str(&sample("phone-media.json"))?;
    assert_eq!(phone_leases_for(&phone, "vm_abc").len(), 1);
    assert!(phone_leases_for(&phone, "vm_none").is_empty());
    Ok(())
}

#[test]
fn written_files_read_back() -> Res {
    let dir = tempfile::tempdir()?;
    let rules: RulesFile = serde_json::from_str(&sample("rules.json"))?;
    write_atomic(dir.path(), &FileSpec::RULES, &rules)?;
    let again: RulesFile = serde_json::from_str(&std::fs::read_to_string(dir.path().join("rules.json"))?)?;
    assert_eq!(again, rules);
    Ok(())
}
