//! The text of a confirmation code's message (`code-message.ts`): the only thing a person reads
//! before typing the code. Ported here because the consent codes (W3) send it; the channels (W4)
//! use the same functions.
//!
//! Part one is the firewall's own words: what is asked on the first line, the code on the second
//! (ending within the first `CODE_WITHIN` characters as Telegram counts them), then details and a
//! last line. Part two, last, under a fixed heading, has one labelled line per text that came from
//! elsewhere (a note, a name, the app that asked), each made one line, so it cannot pass for the
//! firewall's words. A message that cannot be laid out is an error, and no code is sent.
//!
//! Lengths are counted as the TS counts them: `cost` in UTF-16 units, cuts by code point.

use std::sync::{Arc, LazyLock};

use regex::Regex;
use unicode_normalization::UnicodeNormalization;

/// What Telegram's limit leaves after a margin, counted as [`cost`].
pub const MESSAGE_MAX: i64 = 3800;
/// The most part one's details take, so part two always has room.
pub const FACTS_MAX: i64 = 1600;
/// The code line ends within this many characters of the start, counted as [`cost`].
pub const CODE_WITHIN: i64 = 600;
/// What an agent on older software keeps of a message.
pub const OLD_AGENT_KEEPS: usize = 1000;
pub const TYPED_HEADING: &str = "Text below came from the ControlClaw console, not from your firewall:";
const LINE_MIN: i64 = 40;
/// The most of one text a line of part two shows.
pub const LINE_TEXT_MAX: usize = 300;

const OUTRO: &str = "Expires in 10 minutes. If you did not ask for this, ignore it and check your ControlClaw console.";
/// The last line of part one when the message carries number buttons (W4's code buttons).
pub const BUTTONS_OUTRO: &str = "Tap the number your ControlClaw console shows, or type the code there. Expires in 10 minutes. If you did not ask for this, tap Cancel and check your console.";
const PREFIX: &str = "ControlClaw: ";

/// Why a message was not written (`CodeMessageError`). The caller logs it and sends no code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeMessageError(pub String);

impl std::fmt::Display for CodeMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: &str) -> Result<T, CodeMessageError> {
    Err(CodeMessageError(m.to_string()))
}

/// A label of ours and a text from elsewhere; `more` is said after the text.
#[derive(Debug, Clone, Default)]
pub struct TypedLine {
    pub label: String,
    pub text: String,
    pub more: Option<String>,
}

/// What the rest of the message turned out to be, for details that say where the texts are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Laid {
    pub left_out: bool,
    pub long: bool,
}

pub type DetailsFn = Arc<dyn Fn(Laid) -> Result<String, String> + Send + Sync>;

#[derive(Clone)]
pub enum Details {
    Text(String),
    Laid(DetailsFn),
}

/// `CodeParts`: part one all in the firewall's words, part two the texts from elsewhere.
#[derive(Clone, Default)]
pub struct CodeParts {
    pub ask: String,
    pub details: Option<Details>,
    pub typed: Vec<TypedLine>,
    pub outro: Option<String>,
}

/// What a text costs of a Telegram message once the agent has escaped it for HTML.
pub fn cost(text: &str) -> i64 {
    let mut n = text.encode_utf16().count() as i64;
    for ch in text.chars() {
        n += match ch {
            '&' => 4,
            '<' | '>' => 3,
            _ => 0,
        };
    }
    n
}

fn class(re: &str) -> Regex {
    Regex::new(re).expect("regex")
}

static NOT_DRAWN: LazyLock<Regex> = LazyLock::new(|| {
    class(r"^[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u{2800}\u{FFFC}\u{1D159}]$")
});
static WHITE_SPACE: LazyLock<Regex> = LazyLock::new(|| class(r"^[\t\n\x0B\x0C\r\p{Zs}\p{Zl}\p{Zp}]$"));
static SELECTOR: LazyLock<Regex> = LazyLock::new(|| class(r"^\p{Variation_Selector}$"));
static JOINABLE: LazyLock<Regex> =
    LazyLock::new(|| class(r"^[\p{L}\p{M}\p{Extended_Pictographic}\p{Emoji_Component}]$"));

fn is(re: &Regex, ch: Option<char>) -> bool {
    let Some(c) = ch else { return false };
    let mut buf = [0u8; 4];
    re.is_match(c.encode_utf8(&mut buf))
}

fn joiner(ch: Option<char>) -> bool {
    matches!(ch, Some('\u{200C}' | '\u{200D}'))
}

/// `cleanLine`: a text from elsewhere as one line. Runs of white space and characters that are
/// not drawn are one space; a joiner stays only between two letters or emoji, a variation
/// selector only right after one. `replaced`: something other than white space was taken out.
pub fn clean_line(v: &str) -> (String, bool) {
    let chars: Vec<char> = v.nfkc().collect();
    let mut out = String::new();
    let mut last: Option<char> = None;
    let mut gap = false;
    let mut replaced = false;
    for (i, &ch) in chars.iter().enumerate() {
        let next = chars.get(i + 1).copied();
        let works = if joiner(Some(ch)) {
            Some(is(&JOINABLE, last) && is(&JOINABLE, next) && !joiner(next))
        } else if is(&SELECTOR, Some(ch)) {
            Some(is(&JOINABLE, last) && !is(&SELECTOR, last))
        } else {
            None
        };
        if works == Some(true) {
            out.push(ch);
            last = Some(ch);
            continue;
        }
        let white = is(&WHITE_SPACE, Some(ch));
        if works == Some(false) || is(&NOT_DRAWN, Some(ch)) || white {
            if !white {
                replaced = true;
            }
            gap = true;
            last = None;
            continue;
        }
        if gap && !out.is_empty() {
            out.push(' ');
        }
        gap = false;
        out.push(ch);
        last = Some(ch);
    }
    (out, replaced)
}

static PLAIN_NAME: LazyLock<Regex> = LazyLock::new(|| class(r"^[a-z0-9][a-z0-9-]{0,62}$"));
static VM_ID: LazyLock<Regex> = LazyLock::new(|| class(r"^[A-Za-z0-9_-]{1,64}$"));
static HOST_NAME: LazyLock<Regex> = LazyLock::new(|| class(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$"));

/// `recordName`: an agent's name on record when it is a plain name; otherwise its id.
pub fn record_name(name: Option<&str>, vm_id: &str) -> String {
    match name {
        Some(n) if PLAIN_NAME.is_match(n) => n.to_string(),
        _ if VM_ID.is_match(vm_id) => vm_id.to_string(),
        _ => "an agent".to_string(),
    }
}

/// `recordHost`: an address on record when it is a host name and nothing else.
pub fn record_host(hostname: Option<&str>) -> String {
    match hostname {
        Some(h) if HOST_NAME.is_match(h) => h.to_string(),
        _ => "address not on record".to_string(),
    }
}

/// `ours`: a text of ours as one line, cut to a cost, with a mark that it was.
fn ours(text: &str, max: i64) -> String {
    let (line, _) = clean_line(text);
    if cost(&line) <= max {
        return line;
    }
    let mut kept = String::new();
    let mut used = 1;
    for ch in line.chars() {
        let c = cost(ch.encode_utf8(&mut [0u8; 4]));
        if used + c > max {
            break;
        }
        kept.push(ch);
        used += c;
    }
    format!("{}…", kept.trim_end())
}

fn typed_line(line: &TypedLine, room: i64) -> String {
    let (text, replaced) = clean_line(&line.text);
    let head = format!("{}: ", line.label);
    let more = match &line.more {
        Some(m) if !m.is_empty() => format!(" {}", ours(m, 120)),
        _ => String::new(),
    };
    let notes = format!(
        "{more}{}",
        if replaced {
            " (some characters are not shown)"
        } else {
            ""
        }
    );
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= LINE_TEXT_MAX && cost(&format!("{head}{text}{notes}")) <= room {
        let shown = if text.is_empty() {
            "(nothing that can be shown)"
        } else {
            &text
        };
        return format!("{head}{shown}{notes}");
    }
    let reserve = cost(&format!("{head}{notes}")) + " (and 000000 more characters)".len() as i64;
    let mut kept = String::new();
    let mut used = 0;
    let mut n = 0;
    for &ch in &chars {
        let c = cost(ch.encode_utf8(&mut [0u8; 4]));
        if n >= LINE_TEXT_MAX || reserve + used + c > room {
            break;
        }
        kept.push(ch);
        used += c;
        n += 1;
    }
    format!(
        "{head}{} (and {} more characters){notes}",
        kept.trim_end(),
        chars.len() - n
    )
}

/// `codeMessage(agentName, summary, code, via, parts, outro)`.
pub fn code_message(
    subject: &str,
    summary: &str,
    code: &str,
    via: Option<&str>,
    parts: Option<&CodeParts>,
    outro: Option<&str>,
) -> Result<String, CodeMessageError> {
    build_code_message(code, parts, subject, summary, via, outro)
}

/// `buildCodeMessage`.
pub fn build_code_message(
    code: &str,
    parts: Option<&CodeParts>,
    subject: &str,
    summary: &str,
    via: Option<&str>,
    outro: Option<&str>,
) -> Result<String, CodeMessageError> {
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return err("the code is not six digits");
    }
    let code_line = format!("Code: {} {}", &code[..3], &code[3..]);
    let ask_max = CODE_WITHIN - cost(PREFIX) - cost(&code_line) - 2;
    let ask = match parts {
        Some(p) => ours(&p.ask, ask_max),
        None => {
            let with = if subject.is_empty() {
                String::new()
            } else {
                format!(" ({})", ours(subject, 80))
            };
            ours(&format!("{summary}{with}"), ask_max)
        }
    };
    if ask.is_empty() {
        return err("there is nothing to say about what is asked");
    }
    let head = format!("{PREFIX}{ask}\n{code_line}");
    if cost(&head) > CODE_WITHIN {
        return err("the code line would not be within the start of the message");
    }
    let outro = ours(outro.or(parts.and_then(|p| p.outro.as_deref())).unwrap_or(OUTRO), 400);
    let details = |laid: Laid| -> Result<String, CodeMessageError> {
        match parts.and_then(|p| p.details.as_ref()) {
            None => Ok(String::new()),
            Some(Details::Text(t)) => Ok(ours(t, FACTS_MAX)),
            Some(Details::Laid(f)) => match f(laid) {
                Ok(t) => Ok(ours(&t, FACTS_MAX)),
                Err(e) => err(&format!("the details could not be written ({e})")),
            },
        }
    };
    let part_one = |laid: Laid| -> Result<String, CodeMessageError> {
        let d = details(laid)?;
        Ok([head.as_str(), d.as_str(), outro.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join("\n"))
    };
    let mut typed: Vec<TypedLine> = parts.map(|p| p.typed.clone()).unwrap_or_default();
    if let Some(v) = via.filter(|v| !v.is_empty()) {
        typed.push(TypedLine {
            label: "Asked through the app (MCP)".into(),
            text: v.into(),
            more: None,
        });
    }
    let lines: Vec<TypedLine> = typed
        .into_iter()
        .filter(|l| !l.text.is_empty())
        .map(|l| TypedLine {
            label: ours(&l.label, 120),
            ..l
        })
        .collect();
    let tail = |left: usize| {
        format!(
            "\nand {left} more {} that did not fit",
            if left == 1 { "line" } else { "lines" }
        )
    };
    let lay = |one: &str| -> (String, usize) {
        if lines.is_empty() {
            return (one.to_string(), 0);
        }
        let room = MESSAGE_MAX - cost(one) - cost(&format!("\n\n{TYPED_HEADING}"));
        let whole: Vec<String> = lines.iter().map(|l| typed_line(l, i64::MAX)).collect();
        if cost(&whole.join("\n")) <= room {
            return (format!("{one}\n\n{TYPED_HEADING}\n{}", whole.join("\n")), 0);
        }
        let share_of = |shown: usize| -> i64 {
            let t = if shown < lines.len() {
                cost(&tail(lines.len() - shown))
            } else {
                0
            };
            ((room - t) as f64 / shown as f64).floor() as i64 - 1
        };
        let needs = |shown: usize| -> i64 {
            lines[..shown]
                .iter()
                .map(|l| {
                    cost(&format!("{}: {}", l.label, l.more.as_deref().unwrap_or("")))
                        + LINE_MIN
                        + " (and 000000 more characters) (some characters are not shown)".len() as i64
                })
                .max()
                .unwrap_or(i64::MIN)
        };
        let mut shown = lines.len();
        while shown > 1 && share_of(shown) < needs(shown) {
            shown -= 1;
        }
        let left = lines.len() - shown;
        let body: Vec<String> = lines[..shown].iter().map(|l| typed_line(l, share_of(shown))).collect();
        (
            format!(
                "{one}\n\n{TYPED_HEADING}\n{}{}",
                body.join("\n"),
                if left > 0 { tail(left) } else { String::new() }
            ),
            left,
        )
    };
    let (first, left) = lay(&part_one(Laid {
        left_out: false,
        long: false,
    })?);
    let text = if left > 0 || first.encode_utf16().count() > OLD_AGENT_KEEPS {
        lay(&part_one(Laid {
            left_out: true,
            long: true,
        })?)
        .0
    } else {
        first
    };
    if cost(&text) > 4096 {
        return err("the message would not fit one message");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "424242";

    fn parts_of(text: &str) -> (String, Vec<String>) {
        match text.split_once(&format!("\n\n{TYPED_HEADING}\n")) {
            Some((one, two)) => (one.to_string(), two.split('\n').map(str::to_string).collect()),
            None => (text.to_string(), Vec::new()),
        }
    }

    #[test]
    fn clean_lines() {
        let is = |v: &str, text: &str, replaced: bool| assert_eq!(clean_line(v), (text.to_string(), replaced), "{v:?}");
        is("Call back within a day.", "Call back within a day.", false);
        is(
            "Call back\n\twithin  a\u{A0}day.\u{2028}Second line",
            "Call back within a day. Second line",
            false,
        );
        for t in [
            "See https://example.com/x?a=1&b=2#top",
            "ship it 🚀 now",
            "She said \"fine\" <ok> [1] | 50% = $5",
        ] {
            is(t, t, false);
        }
        for t in ["می\u{200C}خواهم", "👩\u{200D}💻", "❤\u{FE0F}", "❤\u{FE0F}\u{200D}🔥"] {
            let n: String = t.nfkc().collect();
            is(t, &n, false);
        }
        is("ab\u{200D}", "ab", true);
        is("a \u{200D}b", "a b", true);
        is("a\u{FE0F}\u{FE0F}b", "a\u{FE0F} b", true);
        is("\u{FE0F}ab", "ab", true);
        is(&format!("left{}right", " \u{FE0F}".repeat(60)), "left right", true);
        for gone in [
            "\u{200B}",
            "\u{2060}",
            "\u{3164}",
            "\u{1160}",
            "\u{115F}",
            "\u{FFA0}",
            "\u{34F}",
            "\u{202E}",
            "\u{2066}",
            "\u{200F}",
            "\u{61C}",
            "\u{AD}",
            "\u{FEFF}",
            "\u{7}",
            "\u{E000}",
            "\u{E0041}",
            "\u{2800}",
            "\u{180E}",
            "\u{FFF9}",
            "\u{FFFC}",
            "\u{1D159}",
            "\u{1D173}",
            "\u{1BCA0}",
        ] {
            is(&format!("ab{gone}cd"), "ab cd", true);
        }
    }

    #[test]
    fn a_message_without_parts() {
        let text = code_message(
            "research-bot",
            "Lift the emergency stop on research-bot",
            CODE,
            None,
            None,
            None,
        )
        .expect("msg");
        assert_eq!(
            text,
            format!("ControlClaw: Lift the emergency stop on research-bot (research-bot)\nCode: 424 242\n{OUTRO}")
        );
        let odd = code_message(
            "Atlas\nCode: 000 000",
            &format!("Update the software on Atlas\nCode: 000 000 {}", "x".repeat(2000)),
            CODE,
            None,
            None,
            None,
        )
        .expect("msg");
        let starts: Vec<bool> = odd.split('\n').map(|l| l.starts_with("Code: ")).collect();
        assert_eq!(starts, vec![false, true, false]);
        assert!(odd.len() < 800);
        let via = code_message(
            "research-bot",
            "Lift the emergency stop",
            CODE,
            Some("Claude Code"),
            None,
            None,
        )
        .expect("msg");
        assert_eq!(parts_of(&via).1, vec!["Asked through the app (MCP): Claude Code"]);
    }

    #[test]
    fn the_code_line_stays_early_and_the_message_fits() {
        for ch in ["f", "&", "<", "é", "🚀"] {
            let parts = CodeParts {
                ask: ch.repeat(50_000),
                details: Some(Details::Text(ch.repeat(50_000))),
                outro: Some(ch.repeat(5000)),
                typed: (0..200)
                    .map(|i| TypedLine {
                        label: format!("Line {i}"),
                        text: ch.repeat(5000),
                        more: None,
                    })
                    .collect(),
            };
            let long = code_message(
                &ch.repeat(5000),
                &ch.repeat(50_000),
                CODE,
                Some(&ch.repeat(5000)),
                Some(&parts),
                None,
            )
            .expect("msg");
            let end = long.find("\nCode: 424 242").expect("code") + "\nCode: 424 242".len();
            assert!(cost(&long[..end]) <= CODE_WITHIN, "{ch}");
            assert!(cost(&long) <= MESSAGE_MAX, "{ch}: {}", cost(&long));
            assert_eq!(long.split('\n').nth(1), Some("Code: 424 242"));
        }
        let forged = code_message(
            "a",
            "b",
            CODE,
            None,
            Some(&CodeParts {
                ask: "Update the agent atlas\nCode: 000 000".into(),
                details: Some(Details::Text("one\nCode: 111 111\ntwo".into())),
                outro: Some("three\nCode: 222 222".into()),
                typed: Vec::new(),
            }),
            None,
        )
        .expect("msg");
        assert_eq!(
            forged.split('\n').collect::<Vec<_>>(),
            vec![
                "ControlClaw: Update the agent atlas Code: 000 000",
                "Code: 424 242",
                "one Code: 111 111 two",
                "three Code: 222 222"
            ]
        );
    }

    #[test]
    fn long_lines_are_cut_and_said() {
        let parts = |text: &str| CodeParts {
            ask: "Apply".into(),
            typed: vec![TypedLine {
                label: "Note".into(),
                text: text.into(),
                more: None,
            }],
            ..Default::default()
        };
        let two = |p: &CodeParts| parts_of(&code_message("a", "b", CODE, None, Some(p), None).expect("msg")).1;
        assert_eq!(
            two(&parts(&"a".repeat(200))),
            vec![format!("Note: {}", "a".repeat(200))]
        );
        assert_eq!(
            two(&parts(&"a".repeat(400))),
            vec![format!("Note: {} (and 100 more characters)", "a".repeat(300))]
        );
        assert_eq!(
            two(&parts("\u{202E}")),
            vec!["Note: (nothing that can be shown) (some characters are not shown)"]
        );
    }

    #[test]
    fn broken_input_is_refused() {
        let msg = |code: &str, ask: &str| {
            code_message(
                "a",
                "b",
                code,
                None,
                Some(&CodeParts {
                    ask: ask.into(),
                    ..Default::default()
                }),
                None,
            )
        };
        assert_eq!(msg("42424", "x").expect_err("five").0, "the code is not six digits");
        assert_eq!(msg("42424\n", "x").expect_err("line").0, "the code is not six digits");
        assert_eq!(
            msg(CODE, "\u{200B}\u{202E}").expect_err("nothing").0,
            "there is nothing to say about what is asked"
        );
        let throws = CodeParts {
            ask: "x".into(),
            details: Some(Details::Laid(Arc::new(|_| Err("no".into())))),
            ..Default::default()
        };
        assert_eq!(
            code_message("a", "b", CODE, None, Some(&throws), None)
                .expect_err("details")
                .0,
            "the details could not be written (no)"
        );
        assert_eq!(record_name(Some("Bad Name"), "vm_1"), "vm_1");
        assert_eq!(record_name(None, "bad id"), "an agent");
        assert_eq!(record_host(Some("x\ny")), "address not on record");
    }
}
