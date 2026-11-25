//! The TS twin (`packages/cc-shell/src/twin.test.ts`) renders the same inputs and checks the same
//! files, so the two shells cannot drift. Keep the inputs in step with that test. After a deliberate
//! change to both, rewrite the files with
//! `CC_SHELL_WRITE_FIXTURE=1 pnpm --filter @controlclaw/cc-shell test` and run this one again.

use super::*;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../packages/cc-shell/fixtures");

fn same_as(file: &str, html: &str) {
    let want = std::fs::read_to_string(format!("{FIXTURES}/{file}")).unwrap_or_default();
    if html != want {
        let at = html
            .bytes()
            .zip(want.bytes())
            .position(|(a, b)| a != b)
            .unwrap_or(html.len().min(want.len()));
        let from = at.saturating_sub(80);
        panic!(
            "the Rust shell differs from the TS twin ({file}) at byte {at}:\n rust: {}\n   ts: {}",
            html.get(from..(at + 80).min(html.len())).unwrap_or(""),
            want.get(from..(at + 80).min(want.len())).unwrap_or("")
        );
    }
}

fn item(label: &str, href: Option<&str>, icon: &'static str, group: Option<&'static str>) -> NavItem {
    NavItem {
        label: label.into(),
        href: href.map(String::from),
        icon,
        group,
        ..NavItem::default()
    }
}

const ASSETS: Assets<'static> = Assets {
    css: "/__cc/files-ui/tw.css",
    js: "/__cc/shell.js",
};

#[test]
fn frame_matches_the_ts_twin() {
    let nav = [
        NavItem {
            active: true,
            badge: Some("live".into()),
            ..item("Meetings", Some("/__cc/meetings"), "meetings", None)
        },
        item("Screen", Some("/__cc/browser"), "screen", None),
        item(
            "Link <WhatsApp>",
            Some("/__cc/whatsapp?a=1&b=2"),
            "whatsapp",
            Some("Waiting for you"),
        ),
        NavItem {
            external: true,
            ..item(
                "Doctor",
                Some("https://console.example/doctor?vm=1&x=2"),
                "doctor",
                Some("Help & more"),
            )
        },
        item("Nowhere", None, "logs", Some("Help & more")),
    ];
    let header = ShellHeader {
        mark: "mark",
        name: "a&b <x>",
        sub: "a&b.example \"q\"",
        console_url: Some("https://console.example/agents/1?x=1&y=\"2\""),
    };
    let card = ShellCard {
        mark: "mark",
        name: "a&b <x>",
        sub: "a&b.example \"q\"",
        status: Some("Running · OpenClaw 2026.11.5 <b>"),
        status_tone: Tone::Allow,
    };
    let foot = shell_foot(
        "Served by <this> agent",
        "Read from a&b.example. It never passes through ControlClaw.",
    );
    same_as(
        "frame.html",
        &shell_frame(&Frame {
            title: "Screen & <co>",
            assets: &ASSETS,
            header: &header,
            page: "Screen <1>",
            card: &card,
            nav_label: "Agent \"pages\"",
            nav: &nav,
            foot: &foot,
            body: "<p>body</p>",
            head: r#"<meta name="x">"#,
            tail: r#"<script src="/t.js"></script>"#,
        }),
    );
}

/// The firewall's additions: an amber badge, a red status dot, the review icon, the minimal frame's
/// foot line.
#[test]
fn tones_and_the_minimal_frame_match_the_ts_twin() {
    let assets = Assets {
        css: "/__cc/doctor/ui/shell-abc.css",
        js: "/__cc/doctor/ui/shell.js",
    };
    let nav = [
        NavItem {
            active: true,
            ..item("Logs", Some("/__cc/doctor/logs/"), "logs", None)
        },
        NavItem {
            badge: Some("2 <held>".into()),
            badge_tone: Some(Tone::Ask),
            ..item("Content rules", Some("https://c.example/x?a=1&b=2"), "content", None)
        },
        item("AI review", None, "review", None),
        item("Website logins", Some("/l"), "logins", Some("Set up")),
        item("Doctor", Some("/d"), "doctor", Some("Help")),
    ];
    let header = ShellHeader {
        mark: "shield",
        name: "Firewall",
        sub: "fw.example",
        console_url: None,
    };
    let card = ShellCard {
        mark: "shield",
        name: "Firewall",
        sub: "fw.example",
        status: Some("1 service failing · 1.58.2"),
        status_tone: Tone::Block,
    };
    same_as(
        "frame-tones.html",
        &shell_frame(&Frame {
            title: "Logs",
            assets: &assets,
            header: &header,
            page: "Logs",
            card: &card,
            nav_label: "Firewall pages",
            nav: &nav,
            foot: "",
            body: "<p>b</p>",
            head: "",
            tail: "",
        }),
    );
    same_as(
        "minimal.html",
        &shell_minimal_frame(
            "A <login>",
            &assets,
            "<p>card</p>",
            r#"<meta name="m">"#,
            r#"<script src="/m.js"></script>"#,
            &shell_minimal_foot(
                "Served by your firewall, ",
                "fw&.example",
                ". It never passes through ControlClaw.",
            ),
        ),
    );
}
