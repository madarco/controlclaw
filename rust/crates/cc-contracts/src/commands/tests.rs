//! Every payload a conformance case sends parses as its action's type, and the table is sorted
//! with no name twice.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{ACTIONS, Scope, check};

/// Payloads the cases send malformed on purpose, to see the handler refuse them: (case file, id).
const MALFORMED: &[(&str, &str)] = &[
    ("w3/fw-controls.yaml", "q1"),
    ("w4/fw-agentmail.yaml", "a_claim"),
    ("w4/fw-agentmail.yaml", "a_create"),
    ("w4/fw-agentmail.yaml", "a_delete"),
    ("w4/fw-agentmail.yaml", "a_import"),
    ("w4/fw-agentmail.yaml", "a_senders"),
    ("w4/fw-channels-commands.yaml", "c_bad"),
    ("w4/fw-channels-commands.yaml", "c_bad2"),
    ("w4/fw-content-rules.yaml", "r_noid"),
    ("w4/fw-google-drive.yaml", "d_bad"),
    ("w4/fw-google-drive.yaml", "g_push_bad"),
    ("w4/fw-llm-commands.yaml", "c_bad"),
    ("w0/fw-heartbeat.yaml", "cmd_1"),
    ("w4/fw-llm-commands.yaml", "c_bad2"),
    ("w5/fw-connectors.yaml", "c6"),
];

fn cases_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases")
}

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).expect("cases dir") {
        let p = e.expect("entry").path();
        if p.is_dir() {
            yaml_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "yaml" || x == "yml") {
            out.push(p);
        }
    }
}

/// Every `command:` in a case: (id, action, payload).
fn commands(v: &Value, out: &mut Vec<(String, String, Value)>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Object(c)) = m.get("command")
                && let Some(action) = c.get("action").and_then(Value::as_str)
            {
                let id = c.get("id").and_then(Value::as_str).unwrap_or_default().to_string();
                let payload = c
                    .get("payload")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Default::default()));
                out.push((id, action.to_string(), payload));
            }
            m.values().for_each(|x| commands(x, out));
        }
        Value::Array(a) => a.iter().for_each(|x| commands(x, out)),
        _ => {}
    }
}

/// A case as JSON, with its tags (`!port 3101`) dropped for the value they carry.
fn json_of(y: serde_yaml::Value) -> Value {
    use serde_yaml::Value as Y;
    match y {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(b),
        Y::Number(n) => serde_json::to_value(n).unwrap_or(Value::Null),
        Y::String(s) => Value::String(s),
        Y::Sequence(a) => Value::Array(a.into_iter().map(json_of).collect()),
        Y::Mapping(m) => Value::Object(
            m.into_iter()
                .map(|(k, v)| (k.as_str().map_or_else(|| format!("{k:?}"), str::to_string), json_of(v)))
                .collect(),
        ),
        Y::Tagged(t) => json_of(t.value),
    }
}

#[test]
fn the_table_is_sorted_and_unique() {
    for w in ACTIONS.windows(2) {
        assert!(w[0].action < w[1].action, "{} before {}", w[0].action, w[1].action);
    }
    for a in ACTIONS {
        assert_eq!(
            a.scope == Scope::Both,
            a.payload.is_some(),
            "{}: a type for every both action only",
            a.action
        );
    }
}

#[test]
fn case_payloads_parse_as_their_types() {
    let mut files = Vec::new();
    yaml_files(&cases_dir(), &mut files);
    files.sort();
    let (mut seen, mut bad) = (0, Vec::new());
    for f in &files {
        let text = std::fs::read_to_string(f).expect("read case");
        let y: serde_yaml::Value = serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let v = json_of(y);
        let mut cmds = Vec::new();
        commands(&v, &mut cmds);
        let name = f.strip_prefix(cases_dir()).unwrap_or(f).display().to_string();
        for (id, action, payload) in cmds {
            if MALFORMED.contains(&(name.as_str(), id.as_str())) {
                continue;
            }
            seen += 1;
            if let Err(e) = check(&action, &payload) {
                bad.push(format!("{name} {id} {action}: {e}"));
            }
        }
    }
    assert!(seen > 100, "only {seen} payloads found under {}", cases_dir().display());
    assert!(
        bad.is_empty(),
        "{} payload(s) do not parse:\n{}",
        bad.len(),
        bad.join("\n")
    );
}

/// Every endpoint has a control-plane case (`cases/cp`), and every case names an endpoint.
#[test]
fn every_endpoint_has_a_case() {
    let mut files = Vec::new();
    yaml_files(&cases_dir().join("cp"), &mut files);
    let mut covered = std::collections::BTreeSet::new();
    for f in &files {
        let y: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(f).expect("read")).expect("yaml");
        let case = json_of(y);
        let endpoint = case["endpoint"].as_str().unwrap_or_default().to_string();
        let path = if endpoint.starts_with("/api/") {
            endpoint
        } else {
            format!("/api/vm-agent{endpoint}")
        };
        let e = crate::control_plane::ENDPOINTS
            .iter()
            .find(|e| e.path == path)
            .unwrap_or_else(|| panic!("{}: {path} is not an endpoint of the contract", f.display()));
        // The local target skips a case by its own `scope`, so it must be the endpoint's.
        let scope = match e.scope {
            Scope::Both => "both",
            Scope::SaasOnly => "saas-only",
        };
        assert_eq!(
            case["scope"].as_str(),
            Some(scope),
            "{}: the scope of {path}",
            f.display()
        );
        covered.insert(path);
    }
    for e in crate::control_plane::ENDPOINTS {
        assert!(covered.contains(e.path), "{} has no case under cases/cp", e.path);
    }
}
