//! JSON comparison with a few matchers for values that differ by run.

use serde_json::Value;

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.chars().all(|c| c.is_ascii_hexdigit()))
}

fn matcher(want: &str, got: &Value) -> Option<bool> {
    Some(match want {
        "$any" => true,
        "$number" => got.is_number(),
        "$string" => got.is_string(),
        "$uuid" => got.as_str().is_some_and(is_uuid),
        "$absent" => false,
        "$optional" => true,
        _ => return None,
    })
}

/// Where `got` differs from `want`, or `None` when it matches. `subset` ignores keys of `got`
/// objects that `want` does not name.
pub fn diff(want: &Value, got: &Value, subset: bool, at: &str) -> Option<String> {
    if let Value::String(w) = want
        && let Some(ok) = matcher(w, got)
    {
        return (!ok).then(|| format!("{at}: wanted {w}, got {got}"));
    }
    match (want, got) {
        (Value::Object(w), Value::Object(g)) => {
            for (k, wv) in w {
                let path = format!("{at}.{k}");
                if wv == "$absent" {
                    if g.contains_key(k) {
                        return Some(format!("{path}: should be absent, got {}", g[k]));
                    }
                    continue;
                }
                // A key one control plane sends and the other does not.
                if wv == "$optional" && !g.contains_key(k) {
                    continue;
                }
                match g.get(k) {
                    Some(gv) => {
                        if let Some(d) = diff(wv, gv, subset, &path) {
                            return Some(d);
                        }
                    }
                    None => return Some(format!("{path}: missing")),
                }
            }
            if !subset && let Some(extra) = g.keys().find(|k| !w.contains_key(*k)) {
                return Some(format!("{at}.{extra}: not expected (got {})", g[extra]));
            }
            None
        }
        (Value::Array(w), Value::Array(g)) => {
            if w.len() != g.len() {
                return Some(format!("{at}: wanted {} items, got {}", w.len(), g.len()));
            }
            w.iter()
                .zip(g)
                .enumerate()
                .find_map(|(i, (wv, gv))| diff(wv, gv, subset, &format!("{at}[{i}]")))
        }
        _ => (want != got).then(|| format!("{at}: wanted {want}, got {got}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matchers_and_subsets() {
        let got = json!({"a": 1, "b": "x", "id": "0d9ad2c4-1f1e-4b3a-9c51-7a1c2e3f4b5d", "c": [1, 2]});
        assert_eq!(
            diff(
                &json!({"a": "$number", "b": "$string", "id": "$uuid", "c": [1, 2]}),
                &got,
                false,
                "$"
            ),
            None
        );
        assert!(diff(&json!({"a": 1}), &got, false, "$").is_some());
        assert_eq!(diff(&json!({"a": 1, "z": "$absent"}), &got, true, "$"), None);
        assert!(diff(&json!({"c": [1]}), &got, true, "$").is_some());
    }
}
