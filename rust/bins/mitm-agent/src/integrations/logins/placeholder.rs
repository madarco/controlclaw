//! The stand-in an agent types instead of a password (`logins-placeholder.ts`,
//! docs/plans/website-credentials.md §4.2). It has the real password's length (4 to 128) and the
//! same kinds of characters, so the page's own checks treat it as they would the password. Its
//! symbols are only `-`, `_` and `.`: they survive every encoding a sign-in uses as they are, so the
//! proxy finds the placeholder by plain substring wherever the page put it.

use rand::Rng;

const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGIT: &str = "23456789";
const SYMBOL: &str = "-_.";

pub const PLACEHOLDER_MIN: usize = 4;
pub const PLACEHOLDER_MAX: usize = 128;

pub fn placeholder_classes(password: &str) -> Vec<&'static str> {
    let mut classes = Vec::new();
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        classes.push(LOWER);
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        classes.push(UPPER);
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        classes.push(DIGIT);
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        classes.push(SYMBOL);
    }
    // No ASCII letters or digits at all (all symbols, or letters from another script).
    if classes.is_empty() || (classes.len() == 1 && classes[0] == SYMBOL) {
        classes.insert(0, LOWER);
    }
    classes
}

/// `[...password].length`: code points.
fn placeholder_length(password: &str) -> usize {
    password.chars().count().clamp(PLACEHOLDER_MIN, PLACEHOLDER_MAX)
}

/// Same length and character kinds as `password`, random otherwise.
pub fn make_placeholder(password: &str) -> String {
    make_with(password, &mut |max| rand::thread_rng().gen_range(0..max))
}

pub fn make_with(password: &str, pick: &mut dyn FnMut(usize) -> usize) -> String {
    let length = placeholder_length(password);
    let classes = placeholder_classes(password);
    let all: String = classes.concat();
    let plain: Vec<&str> = classes.iter().copied().filter(|c| *c != SYMBOL).collect();
    let plain_all: String = plain.concat();
    let char_of = |pool: &str, pick: &mut dyn FnMut(usize) -> usize| -> char {
        let chars: Vec<char> = pool.chars().collect();
        chars[pick(chars.len())]
    };
    // A symbol at either end could be trimmed by a page or read as punctuation; keep them inside.
    let mut first = char_of(&plain_all, pick);
    let mut last = char_of(&plain_all, pick);
    let missing = |first: char, last: char| -> Vec<&'static str> {
        classes
            .iter()
            .copied()
            .filter(|pool| !pool.contains(first) && !pool.contains(last))
            .collect()
    };
    // A short password with many kinds: the ends cover two of them, or the middle could not hold the rest.
    if missing(first, last).len() > length - 2 {
        first = char_of(plain[0], pick);
        last = char_of(plain[1 % plain.len()], pick);
    }
    let mut middle: Vec<char> = missing(first, last).iter().map(|p| char_of(p, pick)).collect();
    while middle.len() < length - 2 {
        middle.push(char_of(&all, pick));
    }
    for i in (1..middle.len()).rev() {
        let j = pick(i + 1);
        middle.swap(i, j);
    }
    let mut out = String::new();
    out.push(first);
    out.extend(middle);
    out.push(last);
    out
}

/// Whether a placeholder made for an old password still fits a new one (same length and kinds).
pub fn placeholder_fits(placeholder: &str, password: &str) -> bool {
    if placeholder.chars().count() != placeholder_length(password) {
        return false;
    }
    let want = placeholder_classes(password);
    [LOWER, UPPER, DIGIT, SYMBOL]
        .iter()
        .all(|pool| want.contains(pool) == placeholder.chars().any(|c| pool.contains(c)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_shape_as_the_password() {
        for pw in [
            "Ab1!",
            "1234",
            "correct horse battery staple",
            "pässwörd",
            "!!!!!!",
            "x".repeat(200).as_str(),
        ] {
            for _ in 0..50 {
                let p = make_placeholder(pw);
                assert!(placeholder_fits(&p, pw), "{pw} -> {p}");
                assert!(
                    !SYMBOL.contains(p.chars().next().expect("first")),
                    "no symbol at the start: {p}"
                );
                assert!(
                    !SYMBOL.contains(p.chars().last().expect("last")),
                    "no symbol at the end: {p}"
                );
                assert!(p.chars().all(|c| c.is_ascii_alphanumeric() || SYMBOL.contains(c)));
            }
        }
        assert_eq!(make_placeholder("ab").chars().count(), 4);
        assert_eq!(make_placeholder(&"y".repeat(300)).chars().count(), 128);
        assert!(!placeholder_fits("abcd", "ABCD"));
    }
}
