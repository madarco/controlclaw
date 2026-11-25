//! The frame every page a box serves under `/__cc/` shares, on the agent (`vm-agent`, its
//! `boxside/shell.rs` adds the agent's sidebar) and on the firewall (`mitm-agent`, `core/fw_shell.rs`
//! adds the firewall's): the console's header, the sidebar with the box's card, the phone tab strip,
//! the card frame before sign-in and the minimal frame for a page with one purpose.
//!
//! Strings only, byte for byte what `packages/cc-shell` (TS) prints: the console's Tailwind builds
//! scan the TS for these classes, and the two box builds scan both. The fixture tests below render
//! the same inputs as `packages/cc-shell/src/twin.test.ts` and compare with the same files, so
//! neither side can change alone.

use serde_json::Value;

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
        "info" => r#"<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>"#,
        // The firewall's AI review history: lucide's scan-eye.
        "review" => {
            r#"<path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><circle cx="12" cy="12" r="1"/><path d="M18.944 12.33a1 1 0 0 0 0-.66 7.5 7.5 0 0 0-13.888 0 1 1 0 0 0 0 .66 7.5 7.5 0 0 0 13.888 0"/>"#
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

/// Where a box serves the stylesheet and the theme script (`ShellAssets`). Same origin, always.
pub struct Assets<'a> {
    pub css: &'a str,
    pub js: &'a str,
}

/// `shellHead`.
pub fn shell_head(title: &str, assets: &Assets<'_>, extra_head: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{}</title><script src="{}"></script><link rel="stylesheet" href="{}">{extra_head}</head>"#,
        escape_html(title),
        escape_html(assets.js),
        escape_html(assets.css)
    )
}

/// The left of the header: whose pages these are (`ShellHeader`).
pub struct ShellHeader<'a> {
    pub mark: &'a str,
    pub name: &'a str,
    pub sub: &'a str,
    /// Where "Back to console" goes; no button without it.
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

/// The colour of a dot: green for fine, amber for waiting on someone, red for broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tone {
    #[default]
    Allow,
    Ask,
    Block,
}

/// The card at the top of the sidebar (`ShellCard`).
pub struct ShellCard<'a> {
    pub mark: &'a str,
    pub name: &'a str,
    pub sub: &'a str,
    /// "Running · OpenClaw 2026.11.5", when the box knows it cheaply; no line without it.
    pub status: Option<&'a str>,
    /// The status line's dot (`statusTone`); green when left out.
    pub status_tone: Tone,
}

fn shell_card(c: &ShellCard<'_>) -> String {
    let dot = match c.status_tone {
        Tone::Allow => "bg-allow",
        Tone::Ask => "bg-ask",
        Tone::Block => "bg-block",
    };
    let status = match c.status {
        Some(s) if !s.is_empty() => format!(
            r#"<div class="flex items-center gap-1.5 px-[10px] pt-2 text-[11.5px] text-ink-2"><span aria-hidden="true" class="h-[7px] w-[7px] shrink-0 rounded-full {dot}"></span><span class="truncate">{}</span></div>"#,
            escape_html(s)
        ),
        _ => String::new(),
    };
    format!(
        r#"<div class="hidden pb-3 md:block"><div class="flex min-w-0 items-center gap-2.5 rounded-xl border border-line bg-surface px-[10px] py-2.5"><span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand text-white">{}</span><div class="min-w-0 leading-tight"><div class="truncate text-[13.5px] font-semibold text-ink">{}</div><div class="truncate font-mono text-[11px] text-ink-2">{}</div></div></div>{status}</div>"#,
        icon(c.mark, "h-[17px] w-[17px]"),
        escape_html(c.name),
        escape_html(c.sub)
    )
}

const BODY: &str = r#"<body class="bg-bg-2 font-sans text-ink antialiased">"#;

/// One sidebar entry (`ShellNavItem`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NavItem {
    pub label: String,
    /// `None`: shown, but not a link (there is nowhere it could go).
    pub href: Option<String>,
    pub icon: &'static str,
    pub active: bool,
    /// A short note beside the label ("live", "1 held").
    pub badge: Option<String>,
    /// The badge's colour (`badgeTone`): red when `None`, amber for something waiting on a person.
    pub badge_tone: Option<Tone>,
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
    let (fg, dot) = match item.badge_tone.unwrap_or(Tone::Block) {
        Tone::Ask => ("text-ask-fg", "bg-ask"),
        Tone::Allow => ("text-allow-fg", "bg-allow"),
        Tone::Block => ("text-block-fg", "bg-block"),
    };
    let badge = match &item.badge {
        Some(b) if !b.is_empty() => format!(
            r#"<span class="ml-auto inline-flex shrink-0 items-center gap-1 pl-1 text-[11px] font-medium {fg}"><span aria-hidden="true" class="h-1.5 w-1.5 rounded-full {dot}"></span>{}</span>"#,
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
        r#"<div class="mt-auto hidden pt-4 md:block"><div class="rounded-xl border border-line bg-surface p-3"><div class="flex items-center gap-1.5 text-[12.5px] font-semibold text-ink">{}{}</div><p class="mt-1 text-[11.5px] leading-[1.45] text-ink-2">{}</p></div></div>"#,
        icon("shieldCheck", "h-3.5 w-3.5 shrink-0 text-brand"),
        escape_html(title),
        escape_html(text)
    )
}

/// What `shellFrame` takes: the page's name, the header, the sidebar card, its entries and foot.
pub struct Frame<'a> {
    pub title: &'a str,
    pub assets: &'a Assets<'a>,
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

/// `shellFrame`: the header and the sidebar, `body` in the main panel. On a phone the sidebar is a
/// row of tabs under the header, which scrolls sideways.
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
        shell_head(f.title, f.assets, f.head),
        shell_brand_header(f.header, f.page),
        shell_card(f.card),
        escape_html(f.nav_label),
        f.foot,
        f.body,
        f.tail
    )
}

/// `shellCardFrame`: the header alone, over a centred card.
pub fn shell_card_frame(
    title: &str,
    assets: &Assets<'_>,
    header: &ShellHeader<'_>,
    body: &str,
    head: &str,
    tail: &str,
) -> String {
    format!(
        r#"{}{BODY}<div class="grid min-h-dvh grid-rows-[58px_1fr]">{}<div class="grid place-items-center px-4 py-8"><main class="w-full max-w-[26rem] rounded-2xl border border-line bg-surface p-6 shadow-sm sm:p-8">{body}</main></div></div>{tail}</body></html>"#,
        shell_head(title, assets, head),
        shell_header(header)
    )
}

/// `shellMinimalFoot`: the line under the minimal frame's card, "Served by …" with the box's address
/// in mono. `lead` and `rest` are text, printed either side of `address`.
pub fn shell_minimal_foot(lead: &str, address: &str, rest: &str) -> String {
    format!(
        r#"<p class="mt-4 flex flex-wrap items-center justify-center gap-x-1.5 gap-y-0.5 px-2 text-center text-[12px] text-ink-2">{}<span>{}<span class="font-mono">{}</span>{}</span></p>"#,
        icon("shieldCheck", "h-3.5 w-3.5 shrink-0 text-brand"),
        escape_html(lead),
        escape_html(address),
        escape_html(rest)
    )
}

/// `shellMinimalFrame`: the ControlClaw mark over one card and nothing else, a page with a single
/// purpose (an agent asking for a login in a chat, a notice). `foot` is `shell_minimal_foot(...)` or
/// nothing.
pub fn shell_minimal_frame(title: &str, assets: &Assets<'_>, body: &str, head: &str, tail: &str, foot: &str) -> String {
    format!(
        r#"{}{BODY}<div class="mx-auto w-full max-w-[36rem] px-4 pt-6 pb-12 sm:pt-12"><div class="mb-5 flex items-center gap-[9px]">{}<span class="text-[15px] font-semibold tracking-[-0.01em] text-ink">ControlClaw</span></div><main class="min-w-0 rounded-2xl border border-line bg-surface p-5 shadow-sm sm:p-8">{body}</main>{foot}</div>{tail}</body></html>"#,
        shell_head(title, assets, head),
        brand_mark(26)
    )
}

#[cfg(test)]
mod tests;
