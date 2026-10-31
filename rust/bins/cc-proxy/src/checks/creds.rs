//! `credentials.json` as the checks read it (addon.py `_Cache` and `credentials_for`): re-read when
//! its mtime changes, the last good copy kept when it goes missing or does not parse.
//!
//! W1 reads the same file for its swaps. W1: when your cache lands, this can read from it.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde_json::Value;

use super::record::{host_matches, secret_host_matches};
use super::telegram::idna_ascii;

pub struct Creds {
    path: PathBuf,
    cache: Mutex<(Option<SystemTime>, Arc<Vec<Value>>)>,
}

impl Creds {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cache: Mutex::new((None, Arc::new(Vec::new()))),
        }
    }

    /// Every entry (`_creds.get()`). The file is looked at and read outside the lock: a slow disk
    /// holds up only this request.
    pub fn all(&self) -> Arc<Vec<Value>> {
        let lock = || self.cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let Ok(mtime) = std::fs::metadata(&self.path).and_then(|m| m.modified()) else {
            return lock().1.clone();
        };
        {
            let c = lock();
            if c.0 == Some(mtime) {
                return c.1.clone();
            }
        }
        let read = std::fs::read(&self.path)
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok());
        let mut c = lock();
        match read {
            // Another request may have stored a newer copy meanwhile: only a newer one replaces it.
            Some(Value::Array(list)) if c.0.is_none_or(|old| old < mtime) => *c = (Some(mtime), Arc::new(list)),
            Some(Value::Array(_)) => {}
            _ => tracing::warn!("[mitm] failed to load {}", self.path.display()),
        }
        c.1.clone()
    }

    /// `credentials_for(host, vm_id)`: the entries for this host, an agent's own winning over the
    /// organization's for the same placeholder. Custom secrets and logins are this agent's only,
    /// on the hosts they were given (a login's sites in punycode too).
    pub fn for_host(&self, host: &str, vm_id: Option<&str>) -> Vec<Value> {
        let mut by_placeholder: Vec<(String, Value)> = Vec::new();
        for c in self.all().iter() {
            let truthy = |k: &str| truthy(c.get(k));
            if truthy("secret_name") || truthy("login_id") {
                let cv = c.get("vm_id").and_then(Value::as_str);
                if !truthy("vm_id") || cv != vm_id {
                    continue;
                }
                let patterns: Vec<&str> = c
                    .get("allowed_hosts")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let ok = patterns.iter().any(|p| secret_host_matches(p, host))
                    || (truthy("login_id") && !host.is_ascii() && {
                        let ascii = ascii_host(host).unwrap_or_else(|| host.to_owned());
                        patterns.iter().any(|p| secret_host_matches(p, &ascii))
                    });
                if !ok {
                    continue;
                }
            } else if !host_matches(c.get("match_domain").and_then(Value::as_str).unwrap_or(""), host) {
                continue;
            }
            let cv = c.get("vm_id").filter(|v| !v.is_null());
            if cv.is_some_and(|v| v.as_str() != vm_id) {
                continue;
            }
            let ph = c.get("placeholder").and_then(Value::as_str).unwrap_or("").to_owned();
            match by_placeholder.iter_mut().find(|(p, _)| *p == ph) {
                None => by_placeholder.push((ph, c.clone())),
                Some((_, existing)) if existing.get("vm_id").is_none_or(Value::is_null) && cv.is_some() => {
                    *existing = c.clone()
                }
                Some(_) => {}
            }
        }
        by_placeholder.into_iter().map(|(_, c)| c).collect()
    }
}

/// Python truthiness.
pub fn truthy(v: Option<&Value>) -> bool {
    super::email::admission::truthy(v)
}

/// `_ascii_host`: lower case, no trailing dot, an international name in punycode; `None` when it is
/// not a host name.
pub fn ascii_host(host: &str) -> Option<String> {
    let h = host.to_lowercase();
    let h = h.trim_end_matches('.');
    let h = if h.is_ascii() { h.to_owned() } else { idna_ascii(h)? };
    is_host_name(&h).then_some(h)
}

/// `_HOST_NAME.fullmatch`: dot-separated labels of letters, digits and inner hyphens, two or more.
fn is_host_name(h: &str) -> bool {
    let labels: Vec<&str> = h.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            (1..=63).contains(&b.len())
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_for_like_the_addon() {
        let dir = tempfile::tempdir().expect("dir");
        let p = dir.path().join("credentials.json");
        std::fs::write(
            &p,
            r#"[{"placeholder": "A", "match_domain": "api.example.com", "secret": "org"},
                {"placeholder": "A", "match_domain": "api.example.com", "secret": "mine", "vm_id": "a"},
                {"placeholder": "L", "login_id": "lg1", "vm_id": "a", "allowed_hosts": ["*.example.org", "xn--bcher-kva.example"]},
                {"placeholder": "S", "secret_name": "s", "vm_id": "b", "allowed_hosts": ["api.example.com"]}]"#,
        )
        .expect("write");
        let c = Creds::new(p.clone());
        let got = c.for_host("api.example.com", Some("a"));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["secret"], "mine");
        assert_eq!(
            c.for_host("api.example.com", Some("b")).len(),
            2,
            "the org entry and b's own secret"
        );
        assert_eq!(c.for_host("x.example.org", Some("a")).len(), 1);
        assert!(
            c.for_host("example.org", Some("a")).is_empty(),
            "not the apex of a wildcard"
        );
        assert_eq!(
            c.for_host("b\u{fc}cher.example", Some("a")).len(),
            1,
            "an international name in punycode"
        );
        std::fs::write(&p, "nope").expect("write");
        assert_eq!(c.all().len(), 4, "a broken file keeps the last good copy");
        assert_eq!(ascii_host("Login.Example.COM."), Some("login.example.com".into()));
        assert_eq!(ascii_host("localhost"), None);
    }
}
