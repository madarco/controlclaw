//! Masks secrets in log lines before they leave a box. Port of `packages/log-redact`, shared by the
//! agent's Logs page and the firewall's, so the two mask the same shapes.
//!
//! Two nets: the exact values the box knows are secret (a gateway token, a channel token, a key
//! file), and anything that looks like a credential in a URL or header. Phone numbers keep only
//! their last four digits, the way the console shows a number.

use regex::{Captures, Regex};
use std::sync::LazyLock;

/// Values shorter than this are skipped: masking a short word would mask ordinary text too.
pub const MIN_SECRET_LENGTH: usize = 8;

// ASCII `\b` and `[0-9]`, as in JavaScript: Rust's defaults are Unicode-aware.
static PARAM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?-u:\b)(token|api[_-]?key|key|secret|password|passwd|code_challenge|code_verifier|access_token|refresh_token|client_secret|authorization)=([^&\s"'`,;]+)"#)
        .expect("valid regex")
});
static BEARER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u:\b)Bearer\s+[A-Za-z0-9._~+/=-]{8,}").expect("valid regex"));
// Phone numbers in international format, as Twilio and the voice-call plugin write them.
static PHONE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\+[0-9]{7,15}(?-u:\b)").expect("valid regex"));

/// A redactor for these exact values plus the patterns.
pub struct Redactor {
    /// Longest secrets first, as one alternation; split over several when one would be too big.
    secret_res: Vec<Regex>,
}

impl Redactor {
    /// Multi-line values (a PEM key) are also masked line by line, since a log carries them one line
    /// at a time. Longest first, so a value that contains another is masked whole.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut exact: Vec<String> = Vec::new();
        for value in values {
            let value = value.as_ref();
            for part in std::iter::once(value).chain(value.split('\n')) {
                let v = js_trim(part);
                if v.chars().map(char::len_utf16).sum::<usize>() >= MIN_SECRET_LENGTH && !exact.iter().any(|e| e == v) {
                    exact.push(v.to_string());
                }
            }
        }
        // Stable sort by UTF-16 length, as `Array.prototype.sort` with `b.length - a.length`.
        exact.sort_by_key(|s| std::cmp::Reverse(s.encode_utf16().count()));
        let secret_res = build_alternations(&exact);
        Self { secret_res }
    }

    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        for re in &self.secret_res {
            out = re.replace_all(&out, "[redacted]").into_owned();
        }
        out = PARAM_RE
            .replace_all(&out, |c: &Captures| format!("{}=[redacted]", &c[1]))
            .into_owned();
        out = BEARER_RE.replace_all(&out, "Bearer [redacted]").into_owned();
        out = PHONE_RE
            .replace_all(&out, |c: &Captures| {
                let m = &c[0];
                format!("+…{}", &m[m.len() - 4..])
            })
            .into_owned();
        out
    }
}

/// `String.prototype.trim`: JavaScript's whitespace set, which is close to Unicode White_Space plus BOM.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// The TS `makeRedactor` shape.
/// One regex for all of `exact` (already longest first). JS has no size limit on a RegExp; the
/// regex crate does, so the limit is raised and, past it, the list is halved until each part
/// builds. Splitting keeps longest-first within each part, and the parts run in order, so a longer
/// secret is still replaced before a shorter one inside it.
fn build_alternations(exact: &[String]) -> Vec<Regex> {
    if exact.is_empty() {
        return Vec::new();
    }
    let alternation = exact.iter().map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
    match regex::RegexBuilder::new(&alternation).size_limit(1 << 28).build() {
        Ok(re) => vec![re],
        Err(_) if exact.len() > 1 => {
            let (a, b) = exact.split_at(exact.len() / 2);
            let mut out = build_alternations(a);
            out.extend(build_alternations(b));
            out
        }
        // A single secret too large for a regex: matched literally.
        Err(_) => regex::RegexBuilder::new(&regex::escape(&exact[0]))
            .size_limit(usize::MAX >> 1)
            .build()
            .into_iter()
            .collect(),
    }
}

pub fn make_redactor<I, S>(values: I) -> impl Fn(&str) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let r = Redactor::new(values);
    move |text| r.redact(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_exact_values_longest_first() {
        let r = make_redactor(["abcdefgh12345678", "abcdefgh"]);
        assert_eq!(r("x abcdefgh12345678 y abcdefgh"), "x [redacted] y [redacted]");
    }

    #[test]
    fn skips_short_values() {
        assert_eq!(make_redactor(["short"])("a short word"), "a short word");
    }

    #[test]
    fn masks_each_line_of_a_multi_line_value() {
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIPx1yz\n-----END PRIVATE KEY-----";
        assert_eq!(
            make_redactor([pem])("line MC4CAQAwBQYDK2VwBCIEIPx1yz"),
            "line [redacted]"
        );
    }

    #[test]
    fn masks_credential_parameters_bearer_values_and_phone_numbers() {
        let r = make_redactor(Vec::<String>::new());
        assert_eq!(
            r("GET /cb?code_verifier=abc123&state=1"),
            "GET /cb?code_verifier=[redacted]&state=1"
        );
        assert_eq!(
            r("Authorization: Bearer sk-abcdef123456"),
            "Authorization: Bearer [redacted]"
        );
        assert_eq!(r("call from +14155550123"), "call from +…0123");
    }

    #[test]
    fn param_keeps_the_key_as_written_and_ignores_word_inside() {
        let r = make_redactor(Vec::<String>::new());
        assert_eq!(r("API_KEY=abc&x=1"), "API_KEY=[redacted]&x=1");
        // `\b` is ASCII: `monkey=` has no boundary before `key`.
        assert_eq!(r("monkey=banana"), "monkey=banana");
        // Too many digits is not a phone number.
        assert_eq!(r("+12345678901234567890"), "+12345678901234567890");
    }
}
