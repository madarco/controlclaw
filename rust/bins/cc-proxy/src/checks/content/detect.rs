//! The built-in detectors (addon.py `content_detect`) and the word search (`content_phrase_in`).
//!
//! The expressions are the addon's, each linear. Python's `re` on `str` is Unicode-aware, and so is
//! the `regex` crate, with one difference that matters here: a word character. Python's is a
//! letter, a number or `_` (`str.isalnum`), while `regex` also counts combining marks, so a key
//! written right after an accent would have no word edge in front of it. So `\b` is not left to
//! `regex`: the secret expressions are searched without it and their edges checked by hand
//! ([`PyRe`]), and the two expressions whose edges `regex` cannot express are walked by hand the
//! way `re.finditer` walks them: the IBAN ([`ibans`], a `\b` after a part of varying length) and
//! the card number ([`cards`], a look-behind and a look-ahead).

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
fn re(p: &str) -> Regex {
    Regex::new(p).expect("valid expression")
}

/// An expression with an optional `\b` at each end, matched with Python's word characters.
///
/// Every expression here with a leading `\b` starts with a word character, so the edge is "the
/// start of the text or a character that is not a word character" right before it, and that is
/// written into the expression itself (`(?:^|[^\p{L}\p{N}_])(core)`). The search is then one
/// linear pass: checking the edge after a match and trying again one character later is
/// quadratic on a long run such as `xsk-xsk-...`.
pub struct PyRe {
    re: Regex,
    lead: bool,
    trail: bool,
}

impl PyRe {
    fn new(p: &str) -> Self {
        let lead = p.starts_with(r"\b");
        let trail = p.ends_with(r"\b");
        let core = &p[if lead { 2 } else { 0 }..p.len() - if trail { 2 } else { 0 }];
        let re = if lead {
            self::re(&format!(r"(?:^|[^\p{{L}}\p{{N}}_])({core})"))
        } else {
            self::re(&format!("({core})"))
        };
        Self { re, lead, trail }
    }

    /// The next match at or after `from`, as `re.search(text, from)` finds it. Every expression
    /// with a trailing `\b` here ends in a part of fixed length (at most 50 characters), so a
    /// failed trailing edge never has a shorter match to fall back on at the same start, and the
    /// retry one character later costs at most that much again.
    pub fn find_at(&self, text: &str, mut from: usize) -> Option<(usize, usize)> {
        while from <= text.len() {
            // The character before `from` is the one the leading edge looks at.
            let at = if self.lead {
                text[..from].char_indices().next_back().map_or(0, |(i, _)| i)
            } else {
                from
            };
            let mut c = self.re.captures_at(text, at)?;
            if c.get(1).is_some_and(|m| m.start() < from) {
                // `^` matched at the start of the text, one word character before `from`: a match
                // at `from` cannot have an edge there, so the search goes on from `from`.
                c = self.re.captures_at(text, from)?;
            }
            let m = c.get(1)?;
            let (s, e) = (m.start(), m.end());
            if !self.trail || is_edge(text, e) {
                return Some((s, e));
            }
            from = s + text[s..].chars().next().map_or(1, char::len_utf8);
        }
        None
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.find_at(text, 0).is_some()
    }

    /// `pattern.sub(rep, text)`.
    pub fn replace_all<'t>(&self, text: &'t str, rep: &str) -> Cow<'t, str> {
        let mut out = String::new();
        let mut last = 0;
        let mut from = 0;
        while let Some((s, e)) = self.find_at(text, from) {
            out.push_str(&text[last..s]);
            out.push_str(rep);
            last = e;
            from = if e > s {
                e
            } else {
                e + text[e..].chars().next().map_or(1, char::len_utf8)
            };
        }
        if last == 0 && out.is_empty() {
            return Cow::Borrowed(text);
        }
        out.push_str(&text[last..]);
        Cow::Owned(out)
    }
}

/// Python's `\b` at byte `i`: a word character on one side only.
fn is_edge(text: &str, i: usize) -> bool {
    let before = text[..i].chars().next_back().is_some_and(is_word_char);
    let after = text[i..].chars().next().is_some_and(is_word_char);
    before != after
}

pub static SECRET_RES: LazyLock<Vec<PyRe>> = LazyLock::new(|| {
    [
        r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----",
        r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{32,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{36,}",
        r"\bgithub_pat_[A-Za-z0-9_]{40,}",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        r"\b\d{6,12}:AA[A-Za-z0-9_-]{33}\b",
        r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"\bvck_[A-Za-z0-9]{24,}",
    ]
    .iter()
    .map(|p| PyRe::new(p))
    .collect()
});

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| re(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}"));
static DIGIT_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^\d$"));
static ALNUM_RE: LazyLock<Regex> = LazyLock::new(|| re(r"^[\p{L}\p{N}]$"));

pub const EMAILS_BULK: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Detector {
    Secrets,
    Iban,
    Card,
    Emails,
}

impl Detector {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "secrets" => Self::Secrets,
            "iban" => Self::Iban,
            "card" => Self::Card,
            "emails" => Self::Emails,
            _ => return None,
        })
    }
}

/// One built-in detector on one text.
pub fn detect(d: Detector, text: &str) -> bool {
    match d {
        Detector::Secrets => SECRET_RES.iter().any(|r| r.is_match(text)),
        Detector::Iban => ibans(&text.to_uppercase()).into_iter().any(iban_ok),
        Detector::Card => cards(text).into_iter().any(luhn_ok),
        Detector::Emails => {
            let mut seen = std::collections::HashSet::new();
            for m in EMAIL_RE.find_iter(text) {
                seen.insert(m.as_str().to_lowercase());
            }
            seen.len() >= EMAILS_BULK
        }
    }
}

/// A Unicode decimal digit (`\d`), and its value, as Python's `int(c)` reads it. Decimal digits
/// come in runs whose length is a multiple of ten starting at a zero, so the value is the distance
/// from the start of the run, modulo ten.
fn digit_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return c.to_digit(10);
    }
    if !is_digit(c) {
        return None;
    }
    let mut start = c as u32;
    while let Some(prev) = start.checked_sub(1).and_then(char::from_u32) {
        if !is_digit(prev) {
            break;
        }
        start -= 1;
    }
    Some((c as u32 - start) % 10)
}

fn is_digit(c: char) -> bool {
    c.is_ascii_digit() || (!c.is_ascii() && DIGIT_RE.is_match(c.encode_utf8(&mut [0; 4])))
}

fn iban_ok(candidate: &str) -> bool {
    let s: Vec<char> = candidate.chars().filter(|c| *c != ' ').collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    // The digits of `int(c, 36)` for each character, rotated, as one number modulo 97.
    let mut rem: u64 = 0;
    for c in s[4..].iter().chain(&s[..4]) {
        let v = match c.to_digit(36).or_else(|| digit_value(*c)) {
            Some(v) => v,
            None => return false,
        };
        for d in v.to_string().bytes() {
            rem = (rem * 10 + u64::from(d - b'0')) % 97;
        }
    }
    rem == 1
}

fn luhn_ok(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(digit_value).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut total = 0;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut d = *d;
        if i % 2 == 1 {
            d = if d > 4 { d * 2 - 9 } else { d * 2 };
        }
        total += d;
    }
    total % 10 == 0
}

/// A cursor over a text by byte offset, with the character there.
fn char_at(text: &str, i: usize) -> Option<char> {
    text.get(i..).and_then(|t| t.chars().next())
}

/// The matches of `\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`, as
/// `re.finditer` returns them: at each start, the groups and the tail are tried longest first and
/// the first end on a word edge is the match.
pub fn ibans(text: &str) -> Vec<&str> {
    let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        let Some(c0) = char_at(text, i) else { break };
        let next = i + c0.len_utf8();
        if !c0.is_ascii_uppercase() || !is_edge(text, i) {
            i = next;
            continue;
        }
        let end = (|| {
            let mut k = i + 1;
            if !char_at(text, k).is_some_and(|c| c.is_ascii_uppercase()) {
                return None;
            }
            k += 1;
            for _ in 0..2 {
                let c = char_at(text, k).filter(|c| is_digit(*c))?;
                k += c.len_utf8();
            }
            // The ends after 1..=7 groups (a group: an optional space, then four).
            let mut ends = Vec::new();
            let mut at = k;
            while ends.len() < 7 {
                let mut j = at;
                if char_at(text, j) == Some(' ') {
                    j += 1;
                }
                if (0..4).all(|n| alnum(char_at(text, j + n))) {
                    at = j + 4;
                    ends.push(at);
                } else {
                    break;
                }
            }
            for groups in (2..=ends.len()).rev() {
                let g = ends[groups - 1];
                // The tail, present (longest first), then absent.
                let mut j = g;
                if char_at(text, j) == Some(' ') {
                    j += 1;
                }
                let avail = (0..3).take_while(|n| alnum(char_at(text, j + n))).count();
                for n in (1..=avail).rev() {
                    if is_edge(text, j + n) {
                        return Some(j + n);
                    }
                }
                if is_edge(text, g) {
                    return Some(g);
                }
            }
            None
        })();
        match end {
            Some(e) => {
                out.push(&text[i..e]);
                i = e;
            }
            None => i = next,
        }
    }
    out
}

/// The matches of `(?<![\d-])[2-6]\d{3}(?:[ -]?\d{4}){2}[ -]?\d{1,7}(?![\d-])`, as
/// `re.finditer` returns them. Each optional separator is taken when it is there (a digit cannot
/// match it), and the last run takes as many digits as it can (fewer would leave a digit for the
/// look-ahead), so from each start there is at most one match.
pub fn cards(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        // A match starts on an ASCII 2-6, so nothing else is looked at.
        if !(b'2'..=b'6').contains(&bytes[i]) {
            i += 1;
            continue;
        }
        let before_ok = text[..i].chars().next_back().is_none_or(|c| !(is_digit(c) || c == '-'));
        match before_ok.then(|| card_at(text, i)).flatten() {
            Some(j) => {
                out.push(&text[i..j]);
                i = j;
            }
            None => i += 1,
        }
    }
    out
}

/// Where a card match starting at byte `i` ends (exclusive), or `None`.
fn card_at(text: &str, i: usize) -> Option<usize> {
    let sep = |c: Option<char>| matches!(c, Some(' ' | '-'));
    let digits = |mut k: usize, n: usize| -> Option<usize> {
        for _ in 0..n {
            let c = char_at(text, k).filter(|c| is_digit(*c))?;
            k += c.len_utf8();
        }
        Some(k)
    };
    let mut k = digits(i + 1, 3)?;
    for _ in 0..2 {
        if sep(char_at(text, k)) {
            k += 1;
        }
        k = digits(k, 4)?;
    }
    if sep(char_at(text, k)) {
        k += 1;
    }
    let mut n = 0;
    while n < 7 {
        match char_at(text, k).filter(|c| is_digit(*c)) {
            Some(c) => {
                k += c.len_utf8();
                n += 1;
            }
            None => break,
        }
    }
    if n == 0 || char_at(text, k).is_some_and(|c| is_digit(c) || c == '-') {
        return None;
    }
    Some(k)
}

/// `str.isalnum()`: a letter or a number.
pub fn is_alnum(c: char) -> bool {
    c != '_' && is_word_char(c)
}

/// Python's word character: `str.isalnum()` (a letter or a number, not a combining mark) or `_`.
pub fn is_word_char(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    ALNUM_RE.is_match(c.encode_utf8(&mut [0; 4]))
}

/// Spaces and line breaks, the same set as `content-engine.ts`.
fn is_content_ws(c: char) -> bool {
    matches!(c,
        '\t' | '\n' | '\x0b' | '\x0c' | '\r' | '\x1c'..='\x1f' | ' ' | '\u{85}' | '\u{a0}' | '\u{1680}'
        | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}')
}

/// Lower case (of the whole text, so a final sigma is one), every run of spaces and line breaks
/// one space, no space at either end.
pub fn fold(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut in_ws = false;
    for c in lower.chars() {
        if is_content_ws(c) {
            in_ws = true;
            continue;
        }
        if in_ws {
            out.push(' ');
            in_ws = false;
        }
        out.push(c);
    }
    if in_ws {
        out.push(' ');
    }
    out.trim_matches(' ').to_owned()
}

/// A folded phrase in a folded text, on word edges.
pub fn phrase_in_folded(needle: &str, hay: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let step = needle.chars().next().map_or(1, char::len_utf8);
    let mut from = 0;
    while let Some(off) = hay[from..].find(needle) {
        let start = from + off;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        let after = hay[end..].chars().next();
        if !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char) {
            return true;
        }
        from = start + step;
    }
    false
}

/// A word or phrase in a text, case-insensitive, on word edges. A plain search, never a regex.
pub fn phrase_in(phrase: &str, text: &str) -> bool {
    phrase_in_folded(&fold(phrase), &fold(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detectors() {
        assert!(detect(Detector::Iban, "pay to GB82 WEST 1234 5698 7654 32 please"));
        assert!(
            !detect(Detector::Iban, "pay to GB82 WEST 1234 5698 7654 33 please"),
            "checksum"
        );
        assert!(detect(Detector::Card, "card 4111 1111 1111 1111 exp"));
        assert!(!detect(Detector::Card, "order 4111 1111 1111 1112"), "Luhn");
        assert!(!detect(Detector::Card, "call +39 333 123 4567"), "a phone number");
        let five: Vec<String> = (0..5).map(|i| format!("p{i}@example.com")).collect();
        assert!(detect(Detector::Emails, &five.join(" ")));
        assert!(!detect(Detector::Emails, &five[..4].join(" ")));
        for secret in [
            format!("sk-proj-{}", "A".repeat(40)),
            "AKIAABCDEFGHIJKLMNOP".into(),
            format!("ghp_{}", "a".repeat(36)),
            "-----BEGIN OPENSSH PRIVATE KEY-----".into(),
            format!("123456789:AA{}", "b".repeat(33)),
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c".into(),
            "xoxb-1234567890-abcdef".into(),
            format!("AIza{}", "x".repeat(35)),
        ] {
            assert!(detect(Detector::Secrets, &format!("here: {secret} ok")), "{secret}");
        }
        for plain in ["hello there", "my sk-cc placeholder", "ghp_short", "eyJ only"] {
            assert!(!detect(Detector::Secrets, plain), "{plain}");
        }
    }

    #[test]
    fn python_word_edges() {
        // An accent before a key is not a word character to Python: the key has its edge.
        let key = format!("\u{301}sk-proj-{}", "A".repeat(40));
        assert!(detect(Detector::Secrets, &key));
        assert!(!detect(Detector::Secrets, &format!("xsk-proj-{}", "A".repeat(40))));
        // A vowel sign after a phrase does not join it to the word.
        assert!(phrase_in("\u{928}\u{92e}", "\u{928}\u{92e}\u{93e}"));
        // Superscript two is a number to Python.
        assert!(is_word_char('\u{b2}') && !is_word_char('\u{24b6}') && !is_word_char('\u{301}'));
        // A final sigma folds as one.
        assert!(phrase_in(
            "\u{3bf}\u{3b4}\u{3bf}\u{3c2}",
            "\u{39f}\u{394}\u{39f}\u{3a3}"
        ));
        // Masking replaces each match.
        let r = &SECRET_RES[1];
        assert_eq!(
            r.replace_all("a sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA b", "[secret]"),
            "a [secret] b"
        );
        assert!(matches!(r.replace_all("nothing", "[secret]"), Cow::Borrowed(_)));
        // A trailing edge: 17 characters after AKIA have none after the 16th.
        assert!(!detect(Detector::Secrets, "AKIAABCDEFGHIJKLMNOPQ"));
        assert!(detect(Detector::Secrets, "AKIAABCDEFGHIJKLMNOP\u{301}"));
    }

    /// A long run that keeps almost matching must not take the proxy down (one linear pass).
    #[test]
    fn no_quadratic_search() {
        // 512 KiB, the most a long channel reads, in a release build. Debug builds run the
        // regex code unoptimised, 100 times slower, so they get 16 KiB: still quadratic there
        // would take tens of seconds.
        let size = if cfg!(debug_assertions) { 64 * 1024 } else { 512 * 1024 };
        for piece in ["xsk-", "xxoxb-", "xgithub_pat_", "eyJ-", "-"] {
            let text = piece.repeat(size / piece.len());
            let t = std::time::Instant::now();
            assert!(!detect(Detector::Secrets, &text), "{piece}");
            let masked = SECRET_RES[1].replace_all(&text, "[secret]");
            assert_eq!(masked.len(), text.len());
            eprintln!("{piece}: {:?}", t.elapsed());
            assert!(
                t.elapsed() < std::time::Duration::from_secs(5),
                "{piece}: {:?}",
                t.elapsed()
            );
        }
        // The edge is still checked: a key glued to a word is not one, after a space it is.
        let key = format!("sk-proj-{}", "A".repeat(40));
        assert!(!detect(Detector::Secrets, &format!("x{key}")));
        assert!(detect(Detector::Secrets, &format!("x {key}")));
        assert!(detect(Detector::Secrets, &key));
        assert_eq!(SECRET_RES[1].find_at(&format!("ab {key}"), 3), Some((3, 3 + key.len())));
        assert_eq!(SECRET_RES[1].replace_all(&format!("{key} {key}"), "[s]"), "[s] [s]");
    }

    #[test]
    fn ibans_backtrack_like_re() {
        assert_eq!(ibans("GB82 WEST 1234 5698 7654 32"), ["GB82 WEST 1234 5698 7654 32"]);
        assert_eq!(ibans("PAY GB82WEST12345698765432."), ["GB82WEST12345698765432"]);
        // An accent after the last digits is an edge to Python.
        assert!(detect(Detector::Iban, "GB82 WEST 1234 5698 7654 32\u{301}"));
        // A letter right after: the tail gives back characters until there is an edge, or none.
        assert_eq!(ibans("GB82 WEST 1234 5698 7654 32X"), ["GB82 WEST 1234 5698 7654 32X"]);
        assert_eq!(ibans("XGB82WEST1234"), Vec::<&str>::new());
    }

    #[test]
    fn cards_walk_like_finditer() {
        assert_eq!(cards("4111 1111 1111 1111"), ["4111 1111 1111 1111"]);
        assert_eq!(
            cards("x4111-1111-1111-1111-"),
            Vec::<&str>::new(),
            "a dash after: no match"
        );
        assert_eq!(cards("-4111111111111111"), Vec::<&str>::new(), "a dash before");
        assert_eq!(cards("14111111111111111"), Vec::<&str>::new(), "a digit before");
        assert_eq!(
            cards("4111111111111111 5500000000000004"),
            ["4111111111111111", "5500000000000004"]
        );
        // Eight digits in the last run: the look-ahead fails at every length.
        assert_eq!(cards("411111111111111111111"), Vec::<&str>::new());
        // Arabic-Indic digits are digits to `\d`, and to the Luhn sum.
        // The first digit is `[2-6]`, ASCII only.
        let arabic: String = "111111111111111"
            .chars()
            .map(|c| char::from_u32(0x0660 + (c as u32 - 0x30)).unwrap_or(c))
            .collect();
        assert!(detect(Detector::Card, &format!("4{arabic}")));
        assert!(!detect(Detector::Card, &format!("\u{0664}{arabic}")));
        assert_eq!(digit_value('\u{0669}'), Some(9));
        assert_eq!(
            digit_value('\u{1D7D8}'),
            Some(0),
            "the third run of mathematical digits"
        );
        assert_eq!(digit_value('x'), None);
    }

    #[test]
    fn fold_and_phrases() {
        assert_eq!(fold("  A\u{a0}\u{a0}B\n\tc  "), "a b c");
        assert!(phrase_in("customer list", "Here is the Customer List."));
        assert!(!phrase_in("customer list", "customer listing"));
        assert!(phrase_in("customer list", "customer\nlist"));
        assert!(!phrase_in("", "anything"));
        assert!(phrase_in("café", "un CAFÉ noir"));
        // A later occurrence on word edges after one inside a word.
        assert!(phrase_in("ab", "xab ab"));
    }
}
