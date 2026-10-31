//! The firewall's own messages (`own-messages.ts`, the memory half): texts the firewall has an
//! agent send for it (codes, notices) are remembered for ten minutes, so the proxy can ask, on
//! loopback, for a message with the firewall's text taken out before its content rules check the
//! rest. W4 serves that question (`/own`) with [`own_rest`]; the marker file tells the proxy when
//! there is anything to ask about (a time, never the text).

use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use super::now_ms;

const OWN_TTL_MS: u64 = 10 * 60_000;
const OWN_MAX: usize = 100;

struct Own {
    recent: Vec<(String, u64)>,
    marker: Option<PathBuf>,
}

static OWN: LazyLock<Mutex<Own>> = LazyLock::new(|| {
    Mutex::new(Own {
        recent: Vec::new(),
        marker: None,
    })
});

fn prune(own: &mut Own, now: u64) {
    own.recent.retain(|(_, at)| now.saturating_sub(*at) < OWN_TTL_MS);
    let n = own.recent.len();
    if n > OWN_MAX {
        own.recent.drain(..n - OWN_MAX);
    }
}

/// `setOwnMarker`: where the proxy looks (`content-own.json` next to its rule file).
pub fn set_own_marker(path: PathBuf) {
    if let Ok(mut o) = OWN.lock() {
        o.marker = Some(path);
    }
}

/// `rememberOwn`: the firewall is about to have an agent send `text`.
pub fn remember_own(text: &str) {
    remember_own_at(text, now_ms());
}

pub fn remember_own_at(text: &str, now: u64) {
    let Ok(mut o) = OWN.lock() else { return };
    prune(&mut o, now);
    o.recent.push((text.to_string(), now));
    let Some(marker) = o.marker.clone() else { return };
    let ms = now + OWN_TTL_MS;
    // `JSON.stringify` writes a whole number of seconds without a fraction.
    let until = if ms.is_multiple_of(1000) {
        format!("{}", ms / 1000)
    } else {
        format!("{}", ms as f64 / 1000.0)
    };
    let body = format!("{{\"until\":{until}}}");
    // No marker: the proxy does not ask, and a rule that matches the message stops it, as before.
    let _ = cc_store::write_atomic(&marker, body.as_bytes(), 0o644, cc_store::TmpName::Suffix);
}

/// The forms a text takes on its way out: as given, as Telegram HTML, and inside Slack's code block.
fn forms(text: &str) -> Vec<String> {
    let html = text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let mut slack = String::new();
    let mut run = 0;
    for ch in text.chars().chain(std::iter::once('\0')) {
        if ch == '`' {
            run += 1;
            continue;
        }
        slack.push_str(&if run >= 3 { "'".repeat(run) } else { "`".repeat(run) });
        run = 0;
        if ch != '\0' {
            slack.push(match ch {
                '<' => '‹',
                '>' => '›',
                c => c,
            });
        }
    }
    let mut out = vec![text.to_string()];
    for f in [html, slack] {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    out
}

/// `ownRest`: the message with the firewall's own text taken out, or `None` when none is in it.
pub fn own_rest(text: &str) -> Option<String> {
    own_rest_at(text, now_ms())
}

pub fn own_rest_at(text: &str, now: u64) -> Option<String> {
    let mut o = OWN.lock().ok()?;
    prune(&mut o, now);
    for (own, _) in o.recent.iter().rev() {
        for form in forms(own) {
            if let Some(at) = text.find(&form) {
                return Some(format!("{}\n{}", &text[..at], &text[at + form.len()..]));
            }
        }
    }
    None
}

#[cfg(test)]
pub fn forget_own() {
    if let Ok(mut o) = OWN.lock() {
        o.recent.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_text_is_taken_out_in_each_form() {
        forget_own();
        let t0 = 1_000_000;
        remember_own_at("Code: 123 456 <b> & ```x```", t0);
        assert_eq!(
            own_rest_at("hi Code: 123 456 <b> & ```x``` bye", t0),
            Some("hi \n bye".into())
        );
        assert_eq!(
            own_rest_at("Code: 123 456 &lt;b&gt; &amp; ```x```", t0),
            Some("\n".into())
        );
        assert_eq!(own_rest_at("Code: 123 456 ‹b› & '''x'''!", t0), Some("\n!".into()));
        assert_eq!(own_rest_at("other", t0), None);
        assert_eq!(own_rest_at("Code: 123 456 <b> & ```x```", t0 + OWN_TTL_MS), None);
    }
}
