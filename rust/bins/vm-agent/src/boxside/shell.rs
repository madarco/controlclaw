//! The one look every page this box serves under `/__cc/` shares: `packages/cc-shell` (the frame,
//! which the firewall's pages use too) and the agent's half of it, `routes/cc-shell.ts` (the
//! sidebar of the agent's pages, the console links). Strings only, byte for byte what the TS
//! prints: the console's Tailwind build scans the TS for these classes.

use serde_json::Value;

use crate::contracts::Contracts;

pub fn icon_paths(name: &str) -> &'static str {
    match name {
        "meetings" => {
            r#"<path d="m16 13 5.223 3.482a.5.5 0 0 0 .777-.416V7.87a.5.5 0 0 0-.752-.432L16 10.5"/><rect x="2" y="6" width="14" height="12" rx="2"/>"#
        }
        "phone" => {
            r#"<path d="M13.832 16.568a1 1 0 0 0 1.213-.303l.355-.465A2 2 0 0 1 17 15h3a2 2 0 0 1 2 2v3a2 2 0 0 1-2 2A18 18 0 0 1 2 4a2 2 0 0 1 2-2h3a2 2 0 0 1 2 2v3a2 2 0 0 1-.8 1.6l-.468.351a1 1 0 0 0-.292 1.233 14 14 0 0 0 6.392 6.384"/>"#
        }
        "files" => {
            r#"<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/>"#
        }
        "logs" => {
            r#"<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>"#
        }
        "whatsapp" => r#"<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/>"#,
        "browser" => {
            r#"<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>"#
        }
        "screen" => r#"<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/>"#,
        "external" => {
            r#"<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>"#
        }
        "shieldCheck" => {
            r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>"#
        }
        "doctor" => {
            r#"<path d="M11 2v2"/><path d="M5 2v2"/><path d="M5 3H4a2 2 0 0 0-2 2v4a6 6 0 0 0 12 0V5a2 2 0 0 0-2-2h-1"/><path d="M8 15a6 6 0 0 0 12 0v-3"/><circle cx="20" cy="10" r="2"/>"#
        }
        "logins" => {
            r#"<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>"#
        }
        "content" => {
            r#"<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="m14.5 7.5-5 5"/><path d="m9.5 7.5 5 5"/>"#
        }
        "back" => r#"<path d="m12 19-7-7 7-7"/><path d="M19 12H5"/>"#,
        // The brain's pages (`gbrain/pages`): lucide's book-open, clock, message-circle-question,
        // upload, download and settings-2.
        "pages" => {
            r#"<path d="M12 7v14"/><path d="M3 18a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h5a4 4 0 0 1 4 4 4 4 0 0 1 4-4h5a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1h-6a3 3 0 0 0-3 3 3 3 0 0 0-3-3z"/>"#
        }
        "lately" => r#"<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>"#,
        "ask" => {
            r#"<path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>"#
        }
        "import" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>"#
        }
        "export" => {
            r#"<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>"#
        }
        "admin" => {
            r#"<path d="M20 7h-9"/><path d="M14 17H5"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/>"#
        }
        "mark" => {
            r#"<path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/>"#
        }
        "shield" => {
            r#"<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>"#
        }
        _ => "",
    }
}

pub fn icon(name: &str, cls: &str) -> String {
    format!(
        r#"<svg class="{cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{}</svg>"#,
        icon_paths(name)
    )
}

/// `escapeHtml`: the five characters, nothing else.
pub fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `JSON.stringify(value)`, as the TS prints a value into a page's script.
pub fn json_string(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// `inlineJson`: `<` inside inline JSON would let a value close the script element.
pub fn inline_json(value: &Value) -> String {
    json_string(value).replace('<', "\\u003c")
}

/// Light or dark from the system, set before the first paint (`SHELL_JS`).
pub const SHELL_JS: &str = r#"(function(){var m=window.matchMedia("(prefers-color-scheme: dark)");var a=function(){document.documentElement.classList.toggle("dark",m.matches)};a();m.addEventListener("change",a)})();"#;

const ASSET_CSS: &str = "/__cc/files-ui/tw.css";
const ASSET_JS: &str = "/__cc/shell.js";

pub fn shell_head(title: &str, extra_head: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{}</title><script src="{}"></script><link rel="stylesheet" href="{}">{extra_head}</head>"#,
        escape_html(title),
        escape_html(ASSET_JS),
        escape_html(ASSET_CSS)
    )
}

/// The left of the header: whose pages these are.
pub struct ShellHeader<'a> {
    pub mark: &'a str,
    pub name: &'a str,
    pub sub: &'a str,
    pub console_url: Option<&'a str>,
}

fn back_link(console_url: Option<&str>) -> String {
    match console_url {
        Some(url) => format!(
            r#"<a href="{}" class="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink shadow-sm hover:bg-bg">{}<span class="hidden sm:inline">Back to console</span><span class="sm:hidden">Console</span></a>"#,
            escape_html(url),
            icon("back", "h-4 w-4 text-ink-2")
        ),
        None => String::new(),
    }
}

/// `shellHeader`: the pages before sign-in, the box's name and address, and Back to console.
pub fn shell_header(h: &ShellHeader<'_>) -> String {
    format!(
        r#"<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5"><span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand">{}</span><div class="min-w-0 leading-tight"><div class="truncate text-[14px] font-semibold text-ink">{}</div><div class="truncate font-mono text-[11.5px] text-ink-2">{}</div></div><span class="flex-1"></span>{}</header>"#,
        icon(h.mark, "h-[18px] w-[18px]"),
        escape_html(h.name),
        escape_html(h.sub),
        back_link(h.console_url)
    )
}

/// `brandMark(size)`: the ControlClaw mark, as the console's header draws it.
pub fn brand_mark(size: u32) -> String {
    let claw = |d: &str| {
        format!(
            r#"<path d="{d}" stroke="white" stroke-width="2.4" stroke-linecap="round" fill="none" opacity="0.95"/>"#
        )
    };
    format!(
        r#"<svg width="{size}" height="{size}" viewBox="0 0 48 48" fill="none" aria-hidden="true" class="shrink-0"><defs><linearGradient id="cc-brand-mark" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="oklch(0.7 0.17 265)"/><stop offset="1" stop-color="oklch(0.34 0.17 265)"/></linearGradient></defs><path d="M24 3 L42 10 L42 24 C42 34 34 42 24 45 C14 42 6 34 6 24 L6 10 Z" fill="url(#cc-brand-mark)"/>{}{}{}</svg>"#,
        claw("M15 18 C18 23 20 28 19 34"),
        claw("M22 15 C25 21 27 28 25 35"),
        claw("M29 16 C32 22 33 28 31 34")
    )
}

/// `shellBrandHeader`: the signed-in pages, ControlClaw, where you are (box › page), Back to console.
pub fn shell_brand_header(h: &ShellHeader<'_>, page: &str) -> String {
    format!(
        r#"<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5"><span class="flex min-w-0 items-center gap-[9px] md:w-[196px] md:shrink-0">{}<span class="hidden text-[15px] font-semibold tracking-[-0.01em] text-ink md:inline">ControlClaw</span><span class="truncate text-[14px] font-semibold text-ink md:hidden">{name}</span></span><nav aria-label="Breadcrumb" class="hidden min-w-0 items-center gap-2 text-[13.5px] text-ink-2 md:flex"><span class="truncate">{name}</span><span aria-hidden="true" class="text-muted-foreground">›</span><span aria-current="page" class="truncate font-medium text-ink">{}</span></nav><span class="flex-1"></span>{}</header>"#,
        brand_mark(26),
        escape_html(page),
        back_link(h.console_url),
        name = escape_html(h.name),
    )
}

/// The card at the top of the sidebar (`ShellCard`).
pub struct ShellCard<'a> {
    pub mark: &'a str,
    pub name: &'a str,
    pub sub: &'a str,
    pub status: Option<&'a str>,
}

fn shell_card(c: &ShellCard<'_>) -> String {
    let status = match c.status {
        Some(s) if !s.is_empty() => format!(
            r#"<div class="flex items-center gap-1.5 px-[10px] pt-2 text-[11.5px] text-ink-2"><span aria-hidden="true" class="h-[7px] w-[7px] shrink-0 rounded-full bg-allow"></span><span class="truncate">{}</span></div>"#,
            escape_html(s)
        ),
        _ => String::new(),
    };
    format!(
        r#"<div class="hidden pb-3 md:block"><div class="flex min-w-0 items-center gap-2.5 rounded-xl border border-line bg-surface px-[10px] py-2.5 shadow-sm"><span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand text-white">{}</span><div class="min-w-0 leading-tight"><div class="truncate text-[13.5px] font-semibold text-ink">{}</div><div class="truncate font-mono text-[11px] text-ink-2">{}</div></div></div>{status}</div>"#,
        icon(c.mark, "h-[17px] w-[17px]"),
        escape_html(c.name),
        escape_html(c.sub)
    )
}

const BODY: &str = r#"<body class="bg-bg-2 font-sans text-ink antialiased">"#;

pub struct NavItem {
    pub label: String,
    pub href: Option<String>,
    pub icon: &'static str,
    pub active: bool,
    /// A short red note beside the label ("live").
    pub badge: Option<String>,
    /// The link leaves this box (Doctor).
    pub external: bool,
    /// A label printed above the first entry of each group.
    pub group: Option<&'static str>,
}

fn nav_link(item: &NavItem) -> String {
    let tag = if item.href.is_none() { "span" } else { "a" };
    let href = item
        .href
        .as_ref()
        .map(|h| format!(r#" href="{}""#, escape_html(h)))
        .unwrap_or_default();
    let current = if item.active { r#" aria-current="page""# } else { "" };
    let cls = if item.active {
        "bg-surface font-semibold text-ink shadow-sm"
    } else {
        "text-ink-2 hover:bg-bg"
    };
    let icon_cls = format!(
        "h-4 w-4 shrink-0 {}",
        if item.active { "text-brand" } else { "text-ink-2" }
    );
    let badge = match &item.badge {
        Some(b) if !b.is_empty() => format!(
            r#"<span class="ml-auto inline-flex shrink-0 items-center gap-1 pl-1 text-[11px] font-medium text-block-fg"><span aria-hidden="true" class="h-1.5 w-1.5 rounded-full bg-block"></span>{}</span>"#,
            escape_html(b)
        ),
        _ => String::new(),
    };
    let ext = if item.external {
        format!(
            r#"{}<span class="sr-only"> (opens through the console)</span>"#,
            icon(
                "external",
                "ml-auto hidden h-3.5 w-3.5 shrink-0 text-muted-foreground md:block"
            )
        )
    } else {
        String::new()
    };
    format!(
        r#"<{tag}{href}{current} class="flex shrink-0 items-center gap-[11px] rounded-lg px-[10px] py-2 text-[13.5px] focus-visible:outline-2 focus-visible:outline-brand {cls}">{}<span>{}</span>{badge}{ext}</{tag}>"#,
        icon(item.icon, &icon_cls),
        escape_html(&item.label)
    )
}

/// `shellFoot`: the note under the sidebar, where these pages come from.
pub fn shell_foot(title: &str, text: &str) -> String {
    format!(
        r#"<div class="mt-auto hidden pt-4 md:block"><div class="rounded-xl border border-line bg-surface p-3 shadow-sm"><div class="flex items-center gap-1.5 text-[12.5px] font-semibold text-ink">{}{}</div><p class="mt-1 text-[11.5px] leading-[1.45] text-ink-2">{}</p></div></div>"#,
        icon("shieldCheck", "h-3.5 w-3.5 shrink-0 text-brand"),
        escape_html(title),
        escape_html(text)
    )
}

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

/// `shellFrame`: the header and the sidebar, `body` in the main panel.
pub fn shell_frame(f: &Frame<'_>) -> String {
    let mut group: Option<&str> = None;
    let mut links = String::new();
    for item in f.nav {
        if let Some(g) = item.group
            && Some(g) != group
        {
            links.push_str(&format!(
                r#"<div class="hidden px-[10px] pt-4 pb-1 text-[11px] font-semibold tracking-[0.06em] text-muted-foreground uppercase md:block">{}</div>"#,
                escape_html(g)
            ));
        }
        group = item.group;
        links.push_str(&nav_link(item));
    }
    format!(
        r#"{}{BODY}<div class="grid min-h-dvh grid-cols-[minmax(0,1fr)] grid-rows-[58px_auto_1fr] md:h-dvh md:grid-cols-[232px_minmax(0,1fr)] md:grid-rows-[58px_1fr] md:overflow-hidden"><div class="min-w-0 md:col-span-2">{}</div><div class="relative min-w-0 md:flex md:min-h-0 md:flex-col md:overflow-y-auto md:px-3 md:pb-3">{}<nav aria-label="{}" class="relative flex min-w-0 gap-0.5 overflow-x-auto px-3 pr-8 pb-2 md:flex-col md:overflow-x-visible md:px-0 md:pr-0 md:pb-0">{links}</nav><span aria-hidden="true" class="pointer-events-none absolute inset-y-0 right-0 w-10 bg-gradient-to-l from-bg-2 to-transparent md:hidden"></span>{}</div><main class="min-w-0 border-t border-line bg-surface md:overflow-y-auto md:mr-2 md:mb-2 md:rounded-tl-2xl md:border shadow-sm">{}</main></div>{}</body></html>"#,
        shell_head(f.title, f.head),
        shell_brand_header(f.header, f.page),
        shell_card(f.card),
        escape_html(f.nav_label),
        f.foot,
        f.body,
        f.tail
    )
}

/// `shellCardFrame`: the header alone, over a centred card.
pub fn shell_card_frame(title: &str, header: &ShellHeader<'_>, body: &str, head: &str, tail: &str) -> String {
    format!(
        r#"{}{BODY}<div class="grid min-h-dvh grid-rows-[58px_1fr]">{}<div class="grid place-items-center px-4 py-8"><main class="w-full max-w-[26rem] rounded-2xl border border-line bg-surface p-6 shadow-sm sm:p-8">{body}</main></div></div>{tail}</body></html>"#,
        shell_head(title, head),
        shell_header(header)
    )
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

    /// The TS twin (`packages/cc-shell`, `twin.test.ts`) renders the same inputs and checks the same
    /// file, so the two shells cannot drift. Keep the inputs in step with that test.
    #[test]
    fn frame_matches_the_ts_twin() {
        let item = |label: &str, href: Option<&str>, icon, active, badge: Option<&str>, external, group| NavItem {
            label: label.into(),
            href: href.map(String::from),
            icon,
            active,
            badge: badge.map(String::from),
            external,
            group,
        };
        let nav = [
            item(
                "Meetings",
                Some("/__cc/meetings"),
                "meetings",
                true,
                Some("live"),
                false,
                None,
            ),
            item("Screen", Some("/__cc/browser"), "screen", false, None, false, None),
            item(
                "Link <WhatsApp>",
                Some("/__cc/whatsapp?a=1&b=2"),
                "whatsapp",
                false,
                None,
                false,
                Some("Waiting for you"),
            ),
            item(
                "Doctor",
                Some("https://console.example/doctor?vm=1&x=2"),
                "doctor",
                false,
                None,
                true,
                Some("Help & more"),
            ),
            item("Nowhere", None, "logs", false, None, false, Some("Help & more")),
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
        };
        let foot = shell_foot(
            "Served by <this> agent",
            "Read from a&b.example. It never passes through ControlClaw.",
        );
        let html = shell_frame(&Frame {
            title: "Screen & <co>",
            header: &header,
            page: "Screen <1>",
            card: &card,
            nav_label: "Agent \"pages\"",
            nav: &nav,
            foot: &foot,
            body: "<p>body</p>",
            head: r#"<meta name="x">"#,
            tail: r#"<script src="/t.js"></script>"#,
        });
        let want = include_str!("../../../../../packages/cc-shell/fixtures/frame.html");
        if html != want {
            let at = html
                .bytes()
                .zip(want.bytes())
                .position(|(a, b)| a != b)
                .unwrap_or(html.len().min(want.len()));
            let from = at.saturating_sub(80);
            panic!(
                "the Rust shell differs from the TS twin at byte {at}:\n rust: {}\n   ts: {}",
                html.get(from..(at + 80).min(html.len())).unwrap_or(""),
                want.get(from..(at + 80).min(want.len())).unwrap_or("")
            );
        }
    }

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
