//! The redaction the transcripts get (`doctor-redaction.test.ts`, the parts of it that are this file's).

use super::*;

#[test]
fn every_string_of_a_secret_and_each_of_its_lines_is_masked_longest_first() {
    let v = serde_json::json!({"a": "line-one\nline-two", "b": ["key-three"], "c": 4});
    let mut got = secret_values(&v);
    got.sort();
    assert_eq!(
        got,
        ["key-three", "key-three", "line-one", "line-one\nline-two", "line-two"]
    );
    let secrets = ["abc".to_string(), "abcdef".to_string(), String::new()];
    assert_eq!(
        redact_secrets("x abcdef y abc", secrets.iter()),
        "x [REDACTED] y [REDACTED]"
    );
    let long = "y".repeat(MAX_EVENT_TEXT + 5);
    let cut = redact_text(&long, std::iter::empty());
    assert!(cut.ends_with("\n[output truncated]") && cut.encode_utf16().count() == MAX_EVENT_TEXT + 19);
}
