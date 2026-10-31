//! JSON keys as Go's `encoding/json` matches them to struct fields (ClickClack, GitHub's MCP
//! server), and the key one object names twice (`go-json.ts`).

/// `goJsonKey`: any ASCII case, and the two non-ASCII letters whose case folding reaches ASCII,
/// `ſ` (U+017F) as `s` and the Kelvin sign (U+212A) as `k`. `ı` (U+0131) and `İ` (U+0130) are read
/// as `i` too: Go 1.27 keeps them apart from `i`, but another decoder might not, and reading a key
/// as a field it is not can only make a check read or refuse more. Compare with a lower-case name.
pub fn go_json_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{130}' | '\u{131}' => 'i',
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// `duplicateKey`: the first key, at any depth, that one object of this JSON text names twice as
/// Go reads it, or `None`. Read off the text, because a parser keeps only the last of two equal
/// keys while Go may keep the first: `{"body":"…","body":null}` is the text to Go (a null leaves a
/// string field as it was). Only for text a JSON parser has accepted.
pub fn duplicate_key(text: &str) -> Option<String> {
    let b = text.as_bytes();
    // A set per open object, `None` per open array.
    let mut objects: Vec<Option<std::collections::HashSet<String>>> = Vec::new();
    let mut expect_key = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'"' => {
                let mut end = i + 1;
                while end < b.len() && b[end] != b'"' {
                    end += if b[end] == b'\\' { 2 } else { 1 };
                }
                if expect_key && let Some(Some(keys)) = objects.last_mut() {
                    let raw = text.get(i..=end.min(b.len() - 1)).unwrap_or("\"\"");
                    let key = go_json_key(&serde_json::from_str::<String>(raw).unwrap_or_default());
                    if !keys.insert(key.clone()) {
                        return Some(key);
                    }
                    expect_key = false;
                }
                i = end;
            }
            b'{' => {
                objects.push(Some(Default::default()));
                expect_key = true;
            }
            b'[' => {
                objects.push(None);
                expect_key = false;
            }
            b'}' | b']' => {
                objects.pop();
                expect_key = false;
            }
            b',' => expect_key = matches!(objects.last(), Some(Some(_))),
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_fold_as_go_reads_them() {
        assert_eq!(go_json_key("Body"), "body");
        assert_eq!(go_json_key("BODY"), "body");
        assert_eq!(go_json_key("\u{17F}ub"), "sub");
        assert_eq!(go_json_key("\u{212A}ey"), "key");
        assert_eq!(go_json_key("D\u{131}splay_name"), "display_name");
        assert_eq!(go_json_key("\u{130}d"), "id");
    }

    #[test]
    fn a_key_named_twice() {
        assert_eq!(duplicate_key(r#"{"body":"x","body":null}"#).as_deref(), Some("body"));
        assert_eq!(duplicate_key(r#"{"body":"x","Body":"y"}"#).as_deref(), Some("body"));
        assert_eq!(duplicate_key(r#"{"a":{"b":1,"B":2}}"#).as_deref(), Some("b"));
        assert_eq!(duplicate_key(r#"[{"a":1},{"a":2}]"#), None);
        assert_eq!(duplicate_key(r#"{"a":"\"a\"","b":["a","a"]}"#), None);
        assert_eq!(duplicate_key(r#"{"ab":1,"ab":2}"#).as_deref(), Some("ab"));
        assert_eq!(duplicate_key(r#"{"a":1,"b":{"a":2}}"#), None);
    }
}
