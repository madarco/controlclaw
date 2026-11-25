//! The one look every page this box serves under `/__cc/` shares: the frame is `cc-shell` (the
//! twin of `packages/cc-shell`, which the firewall's pages use too); this is the agent's half of it,
//! `routes/cc-shell.ts` (the sidebar of the agent's pages, the console links).

use crate::contracts::Contracts;

pub use cc_shell::SHELL_JS;
pub use cc_shell::{NavItem, ShellCard, ShellHeader, Tone, escape_html, inline_json, json_string, shell_foot};

/// Where the agent serves the stylesheet and the theme script.
const ASSETS: cc_shell::Assets<'static> = cc_shell::Assets {
    css: "/__cc/files-ui/tw.css",
    js: "/__cc/shell.js",
};

/// What `shellFrame` takes beyond the header: the page's name, the sidebar card, its entries and foot.
pub struct Frame<'a> {
    pub title: &'a str,
    pub header: &'a ShellHeader<'a>,
    pub page: &'a str,
    pub card: &'a ShellCard<'a>,
    pub nav_label: &'a str,
    pub nav: &'a [NavItem],
    pub foot: &'a str,
    pub body: &'a str,
    pub head: &'a str,
    pub tail: &'a str,
}

/// `shellFrame`, with the agent's stylesheet and theme script.
pub fn shell_frame(f: &Frame<'_>) -> String {
    cc_shell::shell_frame(&cc_shell::Frame {
        title: f.title,
        assets: &ASSETS,
        header: f.header,
        page: f.page,
        card: f.card,
        nav_label: f.nav_label,
        nav: f.nav,
        foot: f.foot,
        body: f.body,
        head: f.head,
        tail: f.tail,
    })
}

/// `shellCardFrame`: the header alone, over a centred card.
pub fn shell_card_frame(title: &str, header: &ShellHeader<'_>, body: &str, head: &str, tail: &str) -> String {
    cc_shell::shell_card_frame(title, &ASSETS, header, body, head, tail)
}

// ---- The agent's half (`routes/cc-shell.ts`) ----

/// What every shell page knows about the box it is on (`ShellContext`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellContext {
    pub hostname: Option<String>,
    pub console_url: String,
    /// Absent on a box that is not an agent (a brain).
    pub doctor_url: Option<String>,
    /// "Running · OpenClaw 2026.11.5" under the sidebar card, when the box knows both cheaply.
    pub status: Option<String>,
}

/// Which optional pages this agent has (`ShellNavState`). Screen, Files and Logs are on every agent box.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NavState {
    pub meetings: bool,
    pub phone: bool,
    pub whatsapp: bool,
    /// A meeting is on now: "live" beside Meetings. From the service's own state, no new request.
    pub meeting_live: bool,
}

impl NavState {
    /// What the providers say now (`setShellNav` in index.ts): an empty slot is a page this box
    /// does not have.
    pub fn current(contracts: &Contracts) -> Self {
        let pages = contracts.pages.get();
        Self {
            meetings: pages.as_ref().is_some_and(|p| p.meetings_listed()),
            phone: pages.as_ref().is_some_and(|p| p.phone_listed()),
            whatsapp: contracts
                .whatsapp
                .get()
                .and_then(|w| w.whatsapp_login())
                .is_some_and(|l| l.state != "idle"),
            meeting_live: pages.as_ref().is_some_and(|p| p.meeting_live()),
        }
    }
}

pub fn agent_name_of(hostname: Option<&str>) -> String {
    match hostname {
        Some(h) => h.split('.').next().unwrap_or_default().to_string(),
        None => "your agent".to_string(),
    }
}

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// This agent's page in the console (`consoleAgentUrl`).
pub fn console_agent_url(console_origin: Option<&str>, vm_id: &str) -> String {
    let origin = console_origin.unwrap_or("https://controlclaw.com");
    if vm_id.is_empty() {
        format!("{origin}/dashboard/agents")
    } else {
        format!("{origin}/dashboard/agents/{}", encode_uri_component(vm_id))
    }
}

/// The console route that opens Doctor on the firewall for this agent (`consoleDoctorUrl`).
pub fn console_doctor_url(console_origin: Option<&str>, vm_id: &str) -> String {
    let origin = console_origin.unwrap_or("https://controlclaw.com");
    if vm_id.is_empty() {
        format!("{origin}/dashboard/doctor/firewall")
    } else {
        format!("{origin}/dashboard/doctor/firewall?vm={}", encode_uri_component(vm_id))
    }
}

/// `/__cc/doctor` and everything under it: the firewall's Doctor paths, asked of this box by mistake.
pub fn is_doctor_path(pathname: &str) -> bool {
    pathname == "/__cc/doctor" || pathname.starts_with("/__cc/doctor/")
}

/// (page, label, href, listed only when, icon, group). Screen keeps `/__cc/browser`, the path the
/// console's Screen button and old links use.
type NavRow = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static str,
    Option<&'static str>,
);

const NAV: &[NavRow] = &[
    (
        "meetings",
        "Meetings",
        "/__cc/meetings",
        Some("meetings"),
        "meetings",
        None,
    ),
    ("phone", "Calls", "/__cc/phone", Some("phone"), "phone", None),
    ("browser", "Screen", "/__cc/browser", None, "screen", None),
    ("files", "Files", "/__cc/files", None, "files", None),
    ("logs", "Logs", "/__cc/logs", None, "logs", None),
    (
        "whatsapp",
        "Link WhatsApp",
        "/__cc/whatsapp",
        Some("whatsapp"),
        "whatsapp",
        Some("Waiting for you"),
    ),
];

/// The breadcrumb's name of a page: its sidebar label.
pub fn page_name(page: Option<&str>) -> &'static str {
    NAV.iter().find(|n| Some(n.0) == page).map_or("", |n| n.1)
}

/// The pages a firewall login ticket may name in `next` (`LOGIN_PAGES`).
pub const LOGIN_PAGES: &[&str] = &["files", "logs", "whatsapp", "meetings", "phone"];

pub fn is_login_page(value: &str) -> bool {
    LOGIN_PAGES.contains(&value)
}

/// Where a login ticket with `next: page` lands: the same path as the page's sidebar link.
pub fn login_landing(page: &str) -> Option<&'static str> {
    NAV.iter().find(|n| n.0 == page).map(|n| n.2)
}

/// The sidebar entries for this agent; the current page is always listed (`shellNav`).
pub fn shell_nav(active: Option<&str>, state: NavState) -> Vec<(&'static str, &'static str, &'static str)> {
    NAV.iter()
        .filter(|(page, _, _, when, _, _)| {
            let listed = match when {
                None => true,
                Some("meetings") => state.meetings,
                Some("phone") => state.phone,
                Some("whatsapp") => state.whatsapp,
                Some(_) => false,
            };
            listed || Some(*page) == active
        })
        .map(|(p, l, h, _, _, _)| (*p, *l, *h))
        .collect()
}

fn header(ctx: &ShellContext) -> (String, String) {
    (
        agent_name_of(ctx.hostname.as_deref()),
        ctx.hostname.clone().unwrap_or_default(),
    )
}

/// `shellPage`: a page with the header and the sidebar.
pub fn shell_page(
    ctx: &ShellContext,
    title: &str,
    active: Option<&str>,
    body: &str,
    head: &str,
    nav: NavState,
) -> String {
    let mut items: Vec<NavItem> = shell_nav(active, nav)
        .into_iter()
        .map(|(page, label, href)| {
            let row = NAV.iter().find(|n| n.0 == page);
            NavItem {
                label: label.to_string(),
                href: Some(href.to_string()),
                icon: row.map_or(page, |n| n.4),
                active: Some(page) == active,
                badge: (page == "meetings" && nav.meeting_live).then(|| "live".to_string()),
                badge_tone: None,
                external: false,
                group: row.and_then(|n| n.5),
            }
        })
        .collect();
    // Doctor runs on the firewall, so this entry leaves the box: never the current page.
    if let Some(d) = &ctx.doctor_url
        && !d.is_empty()
    {
        items.push(NavItem {
            label: "Doctor".into(),
            href: Some(d.clone()),
            icon: "doctor",
            active: false,
            badge: None,
            badge_tone: None,
            external: true,
            group: Some("Help"),
        });
    }
    let (name, sub) = header(ctx);
    let h = ShellHeader {
        mark: "mark",
        name: &name,
        sub: &sub,
        console_url: Some(&ctx.console_url),
    };
    let card = ShellCard {
        mark: "mark",
        name: &name,
        sub: &sub,
        status: ctx.status.as_deref(),
        status_tone: Tone::Allow,
    };
    let foot = shell_foot(
        "Served by this agent",
        &format!(
            "What you see here is read straight from {}. It never passes through ControlClaw.",
            if sub.is_empty() { "this agent" } else { &sub }
        ),
    );
    shell_frame(&Frame {
        title,
        header: &h,
        page: page_name(active),
        card: &card,
        nav_label: "Agent pages",
        nav: &items,
        foot: &foot,
        body,
        head,
        tail: "",
    })
}

/// `shellBarePage`: the header alone, over a centred card.
pub fn shell_bare_page(ctx: &ShellContext, title: &str, body: &str, css: &str, script: &str) -> String {
    let (name, sub) = header(ctx);
    let h = ShellHeader {
        mark: "mark",
        name: &name,
        sub: &sub,
        console_url: Some(&ctx.console_url),
    };
    let head = if css.is_empty() {
        String::new()
    } else {
        format!("<style>{css}</style>")
    };
    let tail = if script.is_empty() {
        String::new()
    } else {
        format!("<script>{script}</script>")
    };
    shell_card_frame(title, &h, body, &head, &tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ShellContext {
        ShellContext {
            hostname: Some("ada.ccl.bot".into()),
            console_url: "https://console.example/dashboard/agents/vm_1".into(),
            doctor_url: None,
            status: None,
        }
    }

    const NONE: NavState = NavState {
        meetings: false,
        phone: false,
        whatsapp: false,
        meeting_live: false,
    };

    fn pages(v: Vec<(&str, &str, &str)>) -> Vec<String> {
        v.into_iter().map(|p| p.0.to_string()).collect()
    }

    #[test]
    fn the_sidebar_lists_only_the_pages_this_agent_has_and_always_the_current_one() {
        assert_eq!(pages(shell_nav(None, NONE)), ["browser", "files", "logs"]);
        let mp = NavState {
            meetings: true,
            phone: true,
            ..NONE
        };
        assert_eq!(
            pages(shell_nav(None, mp)),
            ["meetings", "phone", "browser", "files", "logs"]
        );
        assert_eq!(
            pages(shell_nav(Some("whatsapp"), NONE)),
            ["browser", "files", "logs", "whatsapp"]
        );
    }

    #[test]
    fn screen_is_the_browser_path_whatsapp_waits_for_you_and_a_live_meeting_is_marked() {
        let live = NavState {
            meetings: true,
            whatsapp: true,
            meeting_live: true,
            ..NONE
        };
        let mut c = ctx();
        c.doctor_url = Some("https://console.example/dashboard/doctor/firewall?vm=vm_1".into());
        c.status = Some("Running · OpenClaw 2026.11.5".into());
        let page = shell_page(&c, "x", Some("browser"), "", "", live);
        assert!(page.contains(r#"<a href="/__cc/browser" aria-current="page""#));
        assert!(page.contains("<span>Screen</span>"));
        assert!(!page.contains("<span>Browser</span>"));
        assert!(page.contains(r#"<span aria-current="page" class="truncate font-medium text-ink">Screen</span>"#));
        let wa = page.find("Waiting for you").expect("group");
        assert!(wa < page.find("<span>Link WhatsApp</span>").expect("whatsapp"));
        assert!(page.find("Help").expect("help") < page.find("<span>Doctor</span>").expect("doctor"));
        let re = regex::Regex::new(r#"<span>Meetings</span><span class="[^"]*text-block-fg[^"]*">.*?live</span>"#)
            .expect("re");
        assert!(re.is_match(&page));
        assert!(page.contains("(opens through the console)"));
        assert!(page.contains("Running · OpenClaw 2026.11.5"));
        assert!(page.contains("It never passes through ControlClaw."));
        // No status known: no line.
        assert!(!shell_page(&ctx(), "x", Some("files"), "", "", NONE).contains("Running ·"));
        assert_eq!(login_landing("files"), Some("/__cc/files"));
    }

    #[test]
    fn back_to_console_goes_to_this_agent_in_the_console_the_box_came_from() {
        assert_eq!(
            console_agent_url(Some("https://dev.trycloudflare.com"), "vm_1"),
            "https://dev.trycloudflare.com/dashboard/agents/vm_1"
        );
        assert_eq!(
            console_agent_url(None, "vm_1"),
            "https://controlclaw.com/dashboard/agents/vm_1"
        );
        assert_eq!(console_agent_url(None, ""), "https://controlclaw.com/dashboard/agents");
    }

    #[test]
    fn doctor_a_sidebar_entry_through_the_console_and_the_firewall_paths_recognised() {
        assert_eq!(
            console_doctor_url(Some("https://dev.trycloudflare.com"), "vm_1"),
            "https://dev.trycloudflare.com/dashboard/doctor/firewall?vm=vm_1"
        );
        assert_eq!(
            console_doctor_url(None, ""),
            "https://controlclaw.com/dashboard/doctor/firewall"
        );
        for p in [
            "/__cc/doctor",
            "/__cc/doctor/",
            "/__cc/doctor/start/",
            "/__cc/doctor/chat/x",
        ] {
            assert!(is_doctor_path(p), "{p}");
        }
        for p in ["/__cc/doctorx", "/doctor/status", "/__cc/logs"] {
            assert!(!is_doctor_path(p), "{p}");
        }
        let mut c = ctx();
        c.doctor_url = Some("https://console.example/dashboard/doctor/firewall?vm=vm_1&x=<y>".into());
        let page = shell_page(&c, "x", Some("files"), "", "", NONE);
        let re = regex::Regex::new(r#"<a href="https://console\.example/dashboard/doctor/firewall\?vm=vm_1&amp;x=&lt;y&gt;" class="[^"]*"><svg[^>]*>.*?</svg><span>Doctor</span><svg[^>]*>.*?</svg><span class="sr-only"> \(opens through the console\)</span></a></nav>"#).expect("re");
        assert!(re.is_match(&page));
        assert!(!shell_page(&ctx(), "x", Some("files"), "", "", NONE).contains("<span>Doctor</span>"));
    }

    #[test]
    fn pages_carry_the_header_the_stylesheet_and_theme_script_and_escape_what_they_print() {
        let mut c = ctx();
        c.hostname = Some("<b>.ccl.bot".into());
        let page = shell_page(&c, "x", Some("files"), "<div id=root></div>", "", NONE);
        assert!(
            page.contains(
                r#"<script src="/__cc/shell.js"></script><link rel="stylesheet" href="/__cc/files-ui/tw.css">"#
            )
        );
        assert!(page.contains("Back to console"));
        let re = regex::Regex::new(r#"aria-current="page" class="[^"]*"><svg[^>]*>.*?</svg><span>Files</span>"#)
            .expect("re");
        assert!(re.is_match(&page));
        assert!(!page.contains("<b>"));
        let bare = shell_bare_page(&ctx(), "Opening", "<h1>Opening</h1>", "", "");
        assert!(bare.contains(r#"href="https://console.example/dashboard/agents/vm_1""#));
        assert!(!bare.contains(r#"aria-label="Agent pages""#));
    }

    #[test]
    fn uri_components_like_js() {
        assert_eq!(encode_uri_component("a b/c?d=é~*'()!"), "a%20b%2Fc%3Fd%3D%C3%A9~*'()!");
    }

    #[test]
    fn inline_json_escapes_lt() {
        assert_eq!(
            inline_json(&serde_json::json!({"a": "</script>"})),
            "{\"a\":\"\\u003c/script>\"}"
        );
    }
}
