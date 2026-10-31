//! The look of the pages this firewall serves itself (`fw-shell.ts`, and the parts of
//! `@controlclaw/cc-shell` it uses): the header and sidebar the agent's `/__cc/` pages have, a
//! minimal frame for a page with one purpose, and the stylesheet and theme script under
//! `/__cc/doctor/ui/`, the prefix Caddy on every firewall already hands to this daemon.
//!
//! The stylesheet is the console's theme built by `apps/firewall-panel/scripts/build-fw-files.mjs`
//! into the firewall's `dist-ui/app.css`. The Node build inlines it at build time; this one
//! reads it at start from `CC_FW_UI_DIR`, or `dist-ui/` next to the binary (empty when neither is
//! there, as the TS is without its build).
//!
//! The sidebar's links go through the console: every page here has its own short grant, bought
//! with an intent only the console can sign.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use sha2::{Digest, Sha256};

pub const FW_UI_ROOT: &str = "/__cc/doctor/ui";

/// Where the built page assets are (`app.css`, `app.js`, `doctor-start.js`).
pub fn ui_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CC_FW_UI_DIR") {
        return PathBuf::from(d);
    }
    std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|p| p.join("dist-ui")))
        .unwrap_or_else(|| PathBuf::from("dist-ui"))
}

/// One built asset, read once; empty when it is not there.
pub fn ui_asset(name: &str) -> String {
    std::fs::read_to_string(ui_dir().join(name)).unwrap_or_default()
}

// ---- @controlclaw/cc-shell ----

pub fn icon_path(name: &str) -> &'static str {
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
        icon_path(name)
    )
}

/// The ControlClaw mark, as the console's header draws it.
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

/// Light or dark from the system, set before the first paint.
pub const SHELL_JS: &str = r#"(function(){var m=window.matchMedia("(prefers-color-scheme: dark)");var a=function(){document.documentElement.classList.toggle("dark",m.matches)};a();m.addEventListener("change",a)})();"#;

pub struct ShellAssets {
    pub css: String,
    pub js: String,
}

pub struct ShellHeader {
    pub mark: &'static str,
    pub name: String,
    pub sub: String,
    pub console_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ShellNavItem {
    pub label: &'static str,
    pub href: Option<String>,
    pub icon: &'static str,
    pub active: bool,
}

fn shell_head(title: &str, assets: &ShellAssets, extra: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>{}</title><script src="{}"></script><link rel="stylesheet" href="{}">{extra}</head>"#,
        escape_html(title),
        escape_html(&assets.js),
        escape_html(&assets.css)
    )
}

fn shell_header(h: &ShellHeader) -> String {
    let back = match &h.console_url {
        Some(url) if !url.is_empty() => format!(
            r#"<a href="{}" class="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink shadow-sm hover:bg-bg">{}<span class="hidden sm:inline">Back to console</span><span class="sm:hidden">Console</span></a>"#,
            escape_html(url),
            icon("back", "h-4 w-4 text-ink-2")
        ),
        _ => String::new(),
    };
    format!(
        r#"<header class="flex h-full min-w-0 items-center gap-3 px-4 md:px-5"><span class="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand-soft text-brand">{}</span><div class="min-w-0 leading-tight"><div class="truncate text-[14px] font-semibold text-ink">{}</div><div class="truncate font-mono text-[11.5px] text-ink-2">{}</div></div><span class="flex-1"></span>{back}</header>"#,
        icon(h.mark, "h-[18px] w-[18px]"),
        escape_html(&h.name),
        escape_html(&h.sub)
    )
}

const BODY: &str = r#"<body class="bg-bg-2 font-sans text-ink antialiased">"#;

pub fn shell_frame(
    title: &str,
    assets: &ShellAssets,
    header: &ShellHeader,
    nav_label: &str,
    nav: &[ShellNavItem],
    body: &str,
    tail: &str,
) -> String {
    let links: String = nav
        .iter()
        .map(|item| {
            let tag = if item.href.is_some() { "a" } else { "span" };
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
            let icls = format!("h-4 w-4 shrink-0 {}", if item.active { "text-brand" } else { "text-ink-2" });
            format!(
                r#"<{tag}{href}{current} class="flex shrink-0 items-center gap-[11px] rounded-lg px-[10px] py-2 text-[13.5px] {cls}">{}<span>{}</span></{tag}>"#,
                icon(item.icon, &icls),
                escape_html(item.label)
            )
        })
        .collect();
    format!(
        r#"{}{BODY}<div class="grid min-h-dvh grid-rows-[58px_auto_1fr] md:h-dvh md:grid-cols-[220px_1fr] md:grid-rows-[58px_1fr] md:overflow-hidden"><div class="min-w-0 md:col-span-2">{}</div><nav aria-label="{}" class="flex min-w-0 gap-0.5 overflow-x-auto px-3 pb-2 md:flex-col md:overflow-x-visible md:overflow-y-auto md:pb-4">{links}</nav><main class="min-w-0 border-t border-line bg-surface md:overflow-y-auto md:mr-2 md:mb-2 md:rounded-tl-2xl md:border shadow-sm">{body}</main></div>{tail}</body></html>"#,
        shell_head(title, assets, ""),
        shell_header(header),
        escape_html(nav_label)
    )
}

pub fn shell_minimal_frame(title: &str, assets: &ShellAssets, body: &str, tail: &str) -> String {
    format!(
        r#"{}{BODY}<div class="mx-auto w-full max-w-[36rem] px-4 pt-6 pb-12 sm:pt-12"><div class="mb-5 flex items-center gap-[9px]">{}<span class="text-[15px] font-semibold tracking-[-0.01em] text-ink">ControlClaw</span></div><main class="min-w-0 rounded-2xl border border-line bg-surface p-5 shadow-sm sm:p-8">{body}</main></div>{tail}</body></html>"#,
        shell_head(title, assets, ""),
        brand_mark(26)
    )
}

// ---- fw-shell.ts ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwPage {
    Logs,
    Doctor,
    Logins,
    Content,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FwShellState {
    pub hostname: Option<String>,
    pub console_origin: Option<String>,
    pub firewall_id: String,
    pub pages: HashMap<FwPage, bool>,
}

type StateFn = Arc<dyn Fn() -> FwShellState + Send + Sync>;
static STATE: OnceLock<StateFn> = OnceLock::new();
/// Which pages this firewall serves, as each part says (Logs here, Doctor and logins W5, content W4).
type PageOn = Arc<dyn Fn() -> bool + Send + Sync>;
static PAGES: LazyLock<Mutex<HashMap<FwPage, PageOn>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// `setFwShell`: set once, when the pages exist.
pub fn set_fw_shell(f: StateFn) {
    let _ = STATE.set(f);
}

/// A page this firewall serves, while `on()` holds.
pub fn set_page(page: FwPage, on: impl Fn() -> bool + Send + Sync + 'static) {
    if let Ok(mut p) = PAGES.lock() {
        p.insert(page, Arc::new(on));
    }
}

/// What the sidebar may list now.
pub fn pages_now() -> HashMap<FwPage, bool> {
    let p = PAGES.lock().map(|p| p.clone()).unwrap_or_default();
    [FwPage::Logs, FwPage::Doctor, FwPage::Logins, FwPage::Content]
        .into_iter()
        .map(|k| (k, p.get(&k).is_some_and(|f| f())))
        .collect()
}

fn state() -> FwShellState {
    match STATE.get() {
        Some(f) => f(),
        None => FwShellState {
            hostname: None,
            console_origin: None,
            firewall_id: String::new(),
            pages: HashMap::new(),
        },
    }
}

static CSS_OVERRIDE: Mutex<Option<String>> = Mutex::new(None);
static SHEET: Mutex<Option<(String, String)>> = Mutex::new(None);

#[cfg(test)]
pub fn set_fw_shell_css(css: Option<&str>) {
    if let Ok(mut o) = CSS_OVERRIDE.lock() {
        *o = css.map(str::to_string);
    }
    if let Ok(mut s) = SHEET.lock() {
        *s = None;
    }
}

/// The stylesheet and its path, named by its hash.
fn stylesheet() -> (String, String) {
    let mut cached = SHEET.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = cached.as_ref() {
        return s.clone();
    }
    let css = CSS_OVERRIDE
        .lock()
        .ok()
        .and_then(|o| o.clone())
        .unwrap_or_else(|| ui_asset("app.css"));
    let hash = hex::encode(Sha256::digest(css.as_bytes()));
    let made = (css, format!("{FW_UI_ROOT}/shell-{}.css", &hash[..12]));
    *cached = Some(made.clone());
    made
}

pub fn fw_shell_assets() -> ShellAssets {
    ShellAssets {
        css: stylesheet().1,
        js: format!("{FW_UI_ROOT}/shell.js"),
    }
}

pub fn owns_fw_ui_path(path: &str) -> bool {
    path.starts_with(&format!("{FW_UI_ROOT}/"))
}

/// What `serveFwUi` answers: status, content type, body, cache.
pub fn serve_fw_ui(method: &str, path: &str) -> (u16, &'static str, String, &'static str) {
    if method != "GET" && method != "HEAD" {
        return (405, "text/plain", String::new(), "no-store");
    }
    let (css, css_path) = stylesheet();
    let body = |b: String| if method == "HEAD" { String::new() } else { b };
    if path == css_path {
        return (200, "text/css", body(css), "public, max-age=31536000, immutable");
    }
    let rest = &path[FW_UI_ROOT.len().min(path.len())..];
    let old = rest
        .strip_prefix("/shell-")
        .and_then(|r| r.strip_suffix(".css"))
        .is_some_and(|h| h.len() == 12 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    if old {
        return (200, "text/css", body(css), "no-store");
    }
    if path == format!("{FW_UI_ROOT}/shell.js") {
        return (
            200,
            "text/javascript",
            body(SHELL_JS.to_string()),
            "public, max-age=3600",
        );
    }
    (404, "text/plain", String::new(), "no-store")
}

/// The hyper answer of [`serve_fw_ui`].
pub fn fw_ui_response(method: &str, path: &str) -> cc_http::Resp {
    let (status, ty, body, cache) = serve_fw_ui(method, path);
    let mut r = cc_http::full(
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::NOT_FOUND),
        &format!("{ty}; charset=utf-8"),
        body,
    );
    let h = r.headers_mut();
    for (k, v) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "same-origin"),
        ("content-security-policy", "default-src 'none'; frame-ancestors 'none'"),
        ("cache-control", cache),
    ] {
        if let Ok(v) = http::HeaderValue::from_str(v) {
            h.insert(k, v);
        }
    }
    r
}

/// `encodeURIComponent` for a query value, as `URLSearchParams.set` writes it.
fn query_value(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// The console route that signs a Doctor start intent for this firewall.
pub fn console_doctor_firewall_url(console_base: &str, vm_id: &str) -> Option<String> {
    if !console_base.starts_with("http") {
        return None;
    }
    let base = url::Url::parse(console_base).ok()?;
    let mut u = base.join("/dashboard/doctor/firewall").ok()?;
    if !vm_id.is_empty() {
        u.set_query(Some(&format!("vm={}", query_value(vm_id))));
    }
    Some(u.to_string())
}

struct Nav {
    page: FwPage,
    label: &'static str,
    self_path: &'static str,
    icon: &'static str,
}

const NAV: &[Nav] = &[
    Nav {
        page: FwPage::Logs,
        label: "Logs",
        self_path: "/__cc/doctor/logs/",
        icon: "logs",
    },
    Nav {
        page: FwPage::Doctor,
        label: "Doctor",
        self_path: "/__cc/doctor/start/",
        icon: "doctor",
    },
    Nav {
        page: FwPage::Logins,
        label: "Website logins",
        self_path: "/__cc/logins/",
        icon: "logins",
    },
    Nav {
        page: FwPage::Content,
        label: "Content rules",
        self_path: "/__cc/doctor/content-rules/",
        icon: "content",
    },
];

fn entry(page: FwPage, origin: &str, firewall_id: &str) -> String {
    match page {
        FwPage::Logs => format!("{origin}/dashboard/firewall/logs/open"),
        FwPage::Doctor => console_doctor_firewall_url(origin, firewall_id)
            .unwrap_or_else(|| format!("{origin}/dashboard/doctor/firewall")),
        FwPage::Logins => format!("{origin}/logins/open"),
        FwPage::Content => format!("{origin}/dashboard/firewall/content-rules/open"),
    }
}

/// `fwShellNav`: the pages this firewall serves, the current one always listed.
pub fn fw_shell_nav(active: Option<FwPage>, st: &FwShellState) -> Vec<ShellNavItem> {
    let origin = st.console_origin.as_deref();
    NAV.iter()
        .filter(|item| {
            Some(item.page) == active || (st.pages.get(&item.page).copied().unwrap_or(false) && origin.is_some())
        })
        .map(|item| ShellNavItem {
            label: item.label,
            href: origin.map(|o| {
                if Some(item.page) == active {
                    item.self_path.to_string()
                } else {
                    entry(item.page, o, &st.firewall_id)
                }
            }),
            icon: item.icon,
            active: Some(item.page) == active,
        })
        .collect()
}

/// `fwConsoleUrl`: an agent's page, or the Firewall page for this firewall itself.
pub fn fw_console_url(vm_id: &str, st: &FwShellState) -> Option<String> {
    let o = st.console_origin.as_ref()?;
    Some(if !vm_id.is_empty() && vm_id != st.firewall_id {
        format!(
            "{o}/dashboard/agents/{}",
            crate::core::permissions::encode_uri_component(vm_id)
        )
    } else {
        format!("{o}/dashboard/firewall")
    })
}

/// `consoleUrl` of `fwShellPage`: `None` is "the Firewall page"; `Some(None)` is no button.
pub fn fw_shell_page(
    title: &str,
    active: Option<FwPage>,
    body: &str,
    console_url: Option<Option<String>>,
    tail: &str,
    st: Option<&FwShellState>,
) -> String {
    let owned;
    let st = match st {
        Some(s) => s,
        None => {
            owned = state();
            &owned
        }
    };
    let back = match console_url {
        None => st.console_origin.as_ref().map(|o| format!("{o}/dashboard/firewall")),
        Some(u) => u,
    };
    let header = ShellHeader {
        mark: "shield",
        name: "Firewall".into(),
        sub: st.hostname.clone().unwrap_or_default(),
        console_url: back,
    };
    shell_frame(
        title,
        &fw_shell_assets(),
        &header,
        "Firewall pages",
        &fw_shell_nav(active, st),
        body,
        tail,
    )
}

/// `fwContent(body, width)`: the page's column.
pub fn fw_content(body: &str, width: &str) -> String {
    let max = match width {
        "narrow" => "max-w-[860px]",
        "wide" => "max-w-[1180px]",
        _ => "max-w-none",
    };
    format!(r#"<div class="mx-auto w-full {max} min-w-0 px-4 pt-6 pb-16 md:px-9">{body}</div>"#)
}

pub fn fw_minimal_page(title: &str, body: &str, tail: &str) -> String {
    shell_minimal_frame(title, &fw_shell_assets(), body, tail)
}

/// `fwNotice`: a minimal page that only says something.
pub fn fw_notice(title: &str, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
    let h = heading
        .map(|h| {
            format!(
                r#"<h1 class="text-[16px] font-semibold tracking-[-0.01em] text-ink mb-2">{}</h1>"#,
                escape_html(h)
            )
        })
        .unwrap_or_default();
    let id = id.map(|i| format!(r#" id="{i}""#)).unwrap_or_default();
    let body = format!(
        r#"{h}<p{id} class="text-[14px] text-ink-2" role="status">{}</p>"#,
        escape_html(text)
    );
    let tail = script
        .map(|s| format!(r#"<script src="{}"></script>"#, escape_html(s)))
        .unwrap_or_default();
    fw_minimal_page(title, &body, &tail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> FwShellState {
        FwShellState {
            hostname: Some("mitm-1.ccl.bot".into()),
            console_origin: Some("https://console.example".into()),
            firewall_id: "fw_1".into(),
            pages: [FwPage::Logs, FwPage::Doctor, FwPage::Logins, FwPage::Content]
                .into_iter()
                .map(|p| (p, true))
                .collect(),
        }
    }

    fn pairs(n: &[ShellNavItem]) -> Vec<(&'static str, Option<String>)> {
        n.iter().map(|i| (i.label, i.href.clone())).collect()
    }

    #[test]
    fn the_sidebar_goes_through_the_console() {
        let s = |x: &str| Some(x.to_string());
        assert_eq!(
            pairs(&fw_shell_nav(None, &st())),
            vec![
                ("Logs", s("https://console.example/dashboard/firewall/logs/open")),
                ("Doctor", s("https://console.example/dashboard/doctor/firewall?vm=fw_1")),
                ("Website logins", s("https://console.example/logins/open")),
                (
                    "Content rules",
                    s("https://console.example/dashboard/firewall/content-rules/open")
                ),
            ]
        );
        let mut some = st();
        some.pages.insert(FwPage::Doctor, false);
        some.pages.insert(FwPage::Content, false);
        let on = fw_shell_nav(Some(FwPage::Logins), &some);
        assert_eq!(
            pairs(&on),
            vec![
                ("Logs", s("https://console.example/dashboard/firewall/logs/open")),
                ("Website logins", s("/__cc/logins/"))
            ]
        );
        assert!(on[1].active);
        let mut alone = st();
        alone.console_origin = None;
        assert_eq!(
            pairs(&fw_shell_nav(Some(FwPage::Doctor), &alone)),
            vec![("Doctor", None)]
        );
        let page = fw_shell_page("x", Some(FwPage::Doctor), "", None, "", Some(&alone));
        assert!(page.contains(r#"<span aria-current="page" class="#));
        assert!(!page.contains("<a "));
        assert!(fw_shell_nav(None, &alone).is_empty());
    }

    #[test]
    fn back_to_console() {
        assert_eq!(
            console_doctor_firewall_url("https://console.example/api/vm-agent/firewall", "fw_1").as_deref(),
            Some("https://console.example/dashboard/doctor/firewall?vm=fw_1")
        );
        assert_eq!(console_doctor_firewall_url("", "fw_1"), None);
        assert_eq!(
            fw_console_url("vm_2", &st()).as_deref(),
            Some("https://console.example/dashboard/agents/vm_2")
        );
        assert_eq!(
            fw_console_url("fw_1", &st()).as_deref(),
            Some("https://console.example/dashboard/firewall")
        );
        let p = fw_shell_page("x", Some(FwPage::Logs), "", None, "", Some(&st()));
        assert!(p.contains(r#"<a href="https://console.example/dashboard/firewall""#) && p.contains("Back to console"));
        let p = fw_shell_page("x", Some(FwPage::Logs), "", Some(None), "", Some(&st()));
        assert!(!p.contains("Back to console"));
    }

    #[test]
    fn pages_escape_and_link_their_assets() {
        let mut s = st();
        s.hostname = Some("<b>.ccl.bot".into());
        let page = fw_shell_page(
            "<t>",
            Some(FwPage::Doctor),
            r#"<div id="root"></div>"#,
            None,
            r#"<script src="app.js"></script>"#,
            Some(&s),
        );
        assert!(page.contains(
            r#"<script src="/__cc/doctor/ui/shell.js"></script><link rel="stylesheet" href="/__cc/doctor/ui/shell-"#
        ));
        assert!(page.ends_with(r#"<script src="app.js"></script></body></html>"#));
        assert!(!page.contains("<b>") && !page.contains("<t>") && !page.contains("style="));
        let notice = fw_notice(
            "Logins",
            Some("It <failed>"),
            "Try & again",
            Some("s"),
            Some("/__cc/logins/open.js"),
        );
        assert!(notice.contains(
            r#"It &lt;failed&gt;</h1><p id="s" class="text-[14px] text-ink-2" role="status">Try &amp; again</p>"#
        ));
        assert!(notice.contains(r#"<script src="/__cc/logins/open.js"></script></body>"#));
    }

    #[test]
    fn assets_are_served_without_a_grant() {
        set_fw_shell_css(Some("body{color:red}"));
        let a = fw_shell_assets();
        assert!(owns_fw_ui_path(&a.css) && owns_fw_ui_path(&a.js));
        assert!(!owns_fw_ui_path("/__cc/doctor/logs/"));
        let (s, ty, body, cache) = serve_fw_ui("GET", &a.css);
        assert_eq!((s, ty, body.as_str()), (200, "text/css", "body{color:red}"));
        assert!(cache.contains("immutable"));
        let (s, _, body, cache) = serve_fw_ui("GET", &format!("{FW_UI_ROOT}/shell-000000000000.css"));
        assert_eq!((s, body.as_str(), cache), (200, "body{color:red}", "no-store"));
        let (s, ty, body, _) = serve_fw_ui("GET", &a.js);
        assert_eq!((s, ty), (200, "text/javascript"));
        assert!(body.contains("prefers-color-scheme: dark"));
        assert_eq!(serve_fw_ui("GET", &format!("{FW_UI_ROOT}/other.css")).0, 404);
        assert_eq!(serve_fw_ui("POST", &a.css).0, 405);
        set_fw_shell_css(None);
    }
}
