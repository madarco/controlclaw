//! `_placeholder_re`: how a login's stand-in is found. A long one with a letter is unmistakable
//! anywhere. An all-digit one stands alone among digits. A short one (a PIN, a 4-7 character
//! password) stands alone as a value: no letter, digit or `-_.` on either side.

pub const LOGIN_SHORT: usize = 8;

pub struct Finder {
    needle: String,
    kind: Kind,
}

#[derive(Clone, Copy)]
enum Kind {
    /// Found anywhere.
    Plain,
    /// No digit on either side.
    Digits,
    /// No letter, digit or `-_.` on either side.
    Short,
}

impl Finder {
    pub fn new(placeholder: &str) -> Self {
        let kind = if placeholder.chars().count() < LOGIN_SHORT {
            Kind::Short
        } else if placeholder.chars().all(|c| c.is_ascii_digit()) {
            Kind::Digits
        } else {
            Kind::Plain
        };
        Self {
            needle: placeholder.to_owned(),
            kind,
        }
    }

    fn neighbour(&self, c: char) -> bool {
        match self.kind {
            Kind::Plain => false,
            Kind::Digits => c.is_ascii_digit(),
            Kind::Short => c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'),
        }
    }

    /// The matches, left to right, not overlapping (`finditer`).
    pub fn find_iter<'a>(&'a self, text: &'a str) -> impl Iterator<Item = (usize, usize)> + 'a {
        let mut from = 0;
        std::iter::from_fn(move || {
            if self.needle.is_empty() {
                return None;
            }
            while let Some(off) = text.get(from..)?.find(&self.needle) {
                let s = from + off;
                let e = s + self.needle.len();
                let ok = !text[..s].chars().next_back().is_some_and(|c| self.neighbour(c))
                    && !text[e..].chars().next().is_some_and(|c| self.neighbour(c));
                if ok {
                    from = e;
                    return Some((s, e));
                }
                from = s + text[s..].chars().next().map_or(1, char::len_utf8);
            }
            None
        })
    }

    pub fn search(&self, text: &str) -> bool {
        self.find_iter(text).next().is_some()
    }

    pub fn count(&self, text: &str) -> usize {
        self.find_iter(text).count()
    }

    /// Every match replaced by `rep(match start)`.
    pub fn replace(&self, text: &str, mut rep: impl FnMut(usize) -> String) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for (s, e) in self.find_iter(text) {
            out.push_str(&text[last..s]);
            out.push_str(&rep(s));
            last = e;
        }
        out.push_str(&text[last..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standing_alone_or_not() {
        let digits = Finder::new("48213907");
        assert!(!digits.search("ts=1748213907001"));
        assert!(digits.search("pin=48213907&x"));
        let short = Finder::new("ab12");
        assert!(!short.search("xab12"));
        assert!(!short.search("ab12.5"));
        assert!(short.search("p=ab12&"));
        let long = Finder::new("Kq7-xT2_mN9.vRw4bZ");
        assert!(long.search("xKq7-xT2_mN9.vRw4bZx"));
        assert_eq!(long.count("Kq7-xT2_mN9.vRw4bZ Kq7-xT2_mN9.vRw4bZ"), 2);
        assert_eq!(digits.replace("a 48213907 b", |_| "X".into()), "a X b");
    }
}
