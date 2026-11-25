//! The look of the pages this firewall serves itself: the frame every box's `/__cc/` pages share
//! (`cc-shell`, the twin of `packages/cc-shell`) with the firewall's sidebar, a minimal frame for a
//! page with one purpose, and the stylesheet, theme script and page kit under `/__cc/doctor/ui/`,
//! the prefix Caddy on every firewall already hands to this daemon.
//!
//! The stylesheet is the console's theme built by `apps/firewall-panel/scripts/build-fw-files.mjs`
//! into the firewall's `dist-ui/app.css`, read at start from `CC_FW_UI_DIR`, or `dist-ui/` next to
//! the binary (empty when neither is there). The kit (`fw_kit.js`) is the parts the pages drawn
//! here share (page head, stat tiles, pills, day headings, segmented buttons), in the classes of
//! the agent pages' `box-kit`.
//!
//! SaaS: the sidebar's links go through the console, since every page here has its own short grant,
//! bought with an intent only the console can sign. Standalone: they go through the local panel
//! (`<panel>/open/<page>`), which makes the same kind of link with this firewall's own key.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use cc_shell::{Assets, Frame, NavItem, ShellCard, ShellHeader};
pub use cc_shell::{Tone, escape_html};
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

// ---- fw-shell ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FwPage {
    Logs,
    Content,
    /// The AI review history, opened per agent from the console: listed only while it is open.
    AiReview,
    Logins,
    Doctor,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FwShellState {
    pub hostname: Option<String>,
    /// The console's origin (SaaS), or the local panel's (standalone).
    pub console_origin: Option<String>,
    pub firewall_id: String,
    pub pages: HashMap<FwPage, bool>,
    /// A standalone firewall: the panel, not the console, makes the links.
    pub standalone: bool,
    /// "Running · 1.58.2" under the sidebar card.
    pub status: Option<String>,
    /// A count beside an entry ("1 held"), where the count is already at hand.
    pub badges: HashMap<FwPage, (String, Tone)>,
}

type StateFn = Arc<dyn Fn() -> FwShellState + Send + Sync>;
static STATE: OnceLock<StateFn> = OnceLock::new();
/// Which pages this firewall serves, as each part says (Logs here, Doctor and logins, content rules).
type PageOn = Arc<dyn Fn() -> bool + Send + Sync>;
static PAGES: LazyLock<Mutex<HashMap<FwPage, PageOn>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
type BadgeFn = Arc<dyn Fn() -> Option<(String, Tone)> + Send + Sync>;
static BADGES: LazyLock<Mutex<HashMap<FwPage, BadgeFn>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

const ALL: [FwPage; 5] = [
    FwPage::Logs,
    FwPage::Content,
    FwPage::AiReview,
    FwPage::Logins,
    FwPage::Doctor,
];

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

/// A note beside a page's entry, worked out at each page load: only for a count held in memory.
pub fn set_badge(page: FwPage, badge: impl Fn() -> Option<(String, Tone)> + Send + Sync + 'static) {
    if let Ok(mut b) = BADGES.lock() {
        b.insert(page, Arc::new(badge));
    }
}

/// What the sidebar may list now.
pub fn pages_now() -> HashMap<FwPage, bool> {
    let p = PAGES.lock().map(|p| p.clone()).unwrap_or_default();
    ALL.into_iter().map(|k| (k, p.get(&k).is_some_and(|f| f()))).collect()
}

/// The badges now.
pub fn badges_now() -> HashMap<FwPage, (String, Tone)> {
    let b = BADGES.lock().map(|b| b.clone()).unwrap_or_default();
    b.into_iter().filter_map(|(k, f)| f().map(|v| (k, v))).collect()
}

pub fn state() -> FwShellState {
    STATE.get().map(|f| f()).unwrap_or_default()
}

/// The shell's state for one viewer. The held count beside Content rules is only for someone who
/// may open that page (an owner or admin); a member opening Logs or a Doctor chat does not see it.
pub fn state_for(may_open_content: bool) -> FwShellState {
    for_viewer(state(), may_open_content)
}

fn for_viewer(mut st: FwShellState, may_open_content: bool) -> FwShellState {
    if !may_open_content {
        st.badges.remove(&FwPage::Content);
    }
    st
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

/// The page kit every page drawn here loads before its own script (`fw_kit.js`).
const KIT_JS: &str = include_str!("fw_kit.js");
static KIT_PATH: LazyLock<String> = LazyLock::new(|| {
    let hash = hex::encode(Sha256::digest(KIT_JS.as_bytes()));
    format!("{FW_UI_ROOT}/kit-{}.js", &hash[..12])
});

/// The kit's address, named by its hash: `<script src="…">` it before the page's own script.
pub fn fw_kit_src() -> &'static str {
    &KIT_PATH
}

/// `<script src="kit"></script>`, for a page's tail.
pub fn fw_kit_tag() -> String {
    format!(r#"<script src="{}"></script>"#, fw_kit_src())
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
            body(cc_shell::SHELL_JS.to_string()),
            "public, max-age=3600",
        );
    }
    if path == fw_kit_src() {
        return (
            200,
            "text/javascript",
            body(KIT_JS.to_string()),
            "public, max-age=31536000, immutable",
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
    /// The breadcrumb, when it says more than the entry.
    crumb: &'static str,
    self_path: &'static str,
    icon: &'static str,
    group: Option<&'static str>,
    /// The name the local panel opens it by (`local_intent::PAGES`); `None`: not on a standalone
    /// firewall.
    local: Option<&'static str>,
}

/// What the firewall recorded first, then setup, then help, as the agent pages group theirs.
const NAV: &[Nav] = &[
    Nav {
        page: FwPage::Logs,
        label: "Logs",
        crumb: "Logs",
        self_path: "/__cc/doctor/logs/",
        icon: "logs",
        group: None,
        local: Some("firewall-logs"),
    },
    Nav {
        page: FwPage::Content,
        label: "Content rules",
        crumb: "Content rules",
        self_path: "/__cc/doctor/content-rules/",
        icon: "content",
        group: None,
        local: Some("content-rules"),
    },
    Nav {
        page: FwPage::AiReview,
        label: "AI review",
        crumb: "AI review history",
        // Per agent (`/__cc/doctor/ai-review/a/<vm>/`): the page it is on.
        self_path: "./",
        icon: "review",
        group: None,
        local: None,
    },
    Nav {
        page: FwPage::Logins,
        label: "Website logins",
        crumb: "Website logins",
        self_path: "/__cc/logins/",
        icon: "logins",
        group: Some("Set up"),
        local: Some("logins"),
    },
    Nav {
        page: FwPage::Doctor,
        label: "Doctor",
        crumb: "Doctor",
        self_path: "/__cc/doctor/start/",
        icon: "doctor",
        group: Some("Help"),
        local: None,
    },
];

/// Where a page's entry goes from another page: the console route that signs its intent, or the
/// local panel's `/open/<page>`. `None`: it cannot be opened from here.
fn entry(item: &Nav, origin: &str, st: &FwShellState) -> Option<String> {
    if st.standalone {
        return item.local.map(|l| format!("{origin}/open/{l}"));
    }
    match item.page {
        FwPage::Logs => Some(format!("{origin}/dashboard/firewall/logs/open")),
        FwPage::Doctor => Some(
            console_doctor_firewall_url(origin, &st.firewall_id)
                .unwrap_or_else(|| format!("{origin}/dashboard/doctor/firewall")),
        ),
        FwPage::Logins => Some(format!("{origin}/logins/open")),
        FwPage::Content => Some(format!("{origin}/dashboard/firewall/content-rules/open")),
        // Opened per agent, from the console's AI review card.
        FwPage::AiReview => None,
    }
}

/// Where the sidebar's entry for `page` goes, when this firewall serves it and it can be opened
/// from another page; for a page that links to it from its body (Logs' "Repair with Doctor").
pub fn fw_nav_href(page: FwPage, st: &FwShellState) -> Option<String> {
    let item = NAV.iter().find(|i| i.page == page)?;
    if !st.pages.get(&page).copied().unwrap_or(false) {
        return None;
    }
    entry(item, st.console_origin.as_deref()?, st)
}

/// `fwShellNav`: the pages this firewall serves and can open from here, the current one always
/// listed.
pub fn fw_shell_nav(active: Option<FwPage>, st: &FwShellState) -> Vec<NavItem> {
    let origin = st.console_origin.as_deref();
    NAV.iter()
        .filter_map(|item| {
            let on = Some(item.page) == active;
            let href = if on {
                origin.map(|_| item.self_path.to_string())
            } else if st.pages.get(&item.page).copied().unwrap_or(false) {
                Some(entry(item, origin?, st)?)
            } else {
                return None;
            };
            let badge = st.badges.get(&item.page);
            Some(NavItem {
                label: item.label.into(),
                href,
                icon: item.icon,
                active: on,
                badge: badge.map(|b| b.0.clone()),
                badge_tone: badge.map(|b| b.1),
                external: false,
                group: item.group,
            })
        })
        .collect()
}

/// `fwConsoleUrl`: an agent's page, or the Firewall page for this firewall itself.
pub fn fw_console_url(vm_id: &str, st: &FwShellState) -> Option<String> {
    let o = st.console_origin.as_ref()?;
    if st.standalone {
        return Some(format!("{o}/"));
    }
    Some(if !vm_id.is_empty() && vm_id != st.firewall_id {
        format!(
            "{o}/dashboard/agents/{}",
            crate::core::permissions::encode_uri_component(vm_id)
        )
    } else {
        format!("{o}/dashboard/firewall")
    })
}

/// "Back to console" on a standalone firewall: the panel's page nearest to this one.
fn panel_back(origin: &str, active: Option<FwPage>) -> String {
    let path = match active {
        Some(FwPage::Logins) => "/logins",
        Some(FwPage::Content) => "/security",
        Some(FwPage::AiReview) => "/internet#ai-review",
        _ => "/",
    };
    format!("{origin}{path}")
}

/// Where "Back to console" goes, as `fw_shell_page` takes `console_url`. A page that links to the
/// same place from its body (Content rules' "Edit rules") asks here rather than reading the header.
pub fn fw_back_url(active: Option<FwPage>, console_url: Option<Option<String>>, st: &FwShellState) -> Option<String> {
    match (st.standalone, console_url) {
        (true, _) => st.console_origin.as_deref().map(|o| panel_back(o, active)),
        (false, None) => st.console_origin.as_ref().map(|o| format!("{o}/dashboard/firewall")),
        (false, Some(u)) => u,
    }
}

fn assets() -> (String, String) {
    (stylesheet().1, format!("{FW_UI_ROOT}/shell.js"))
}

/// `consoleUrl` of `fwShellPage`: `None` is "the Firewall page"; `Some(None)` is no button. A
/// standalone firewall always goes back to its panel.
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
        // A page that does not say who is viewing shows the held count only where only an owner or
        // admin gets in.
        None => {
            owned = state_for(matches!(active, Some(FwPage::Content | FwPage::Logins)));
            &owned
        }
    };
    let back = fw_back_url(active, console_url, st);
    let sub = st.hostname.clone().unwrap_or_default();
    let header = ShellHeader {
        mark: "shield",
        name: "Firewall",
        sub: &sub,
        console_url: back.as_deref(),
    };
    let card = ShellCard {
        mark: "shield",
        name: "Firewall",
        sub: &sub,
        status: st.status.as_deref(),
        status_tone: Tone::Allow,
    };
    let nav = fw_shell_nav(active, st);
    let page = NAV.iter().find(|i| Some(i.page) == active).map_or(title, |i| i.crumb);
    let foot = cc_shell::shell_foot(
        "Served by this firewall",
        &format!(
            "What you see here is read straight from {}. It never passes through ControlClaw.",
            if sub.is_empty() { "the firewall" } else { &sub }
        ),
    );
    let (css, js) = assets();
    cc_shell::shell_frame(&Frame {
        title,
        assets: &Assets { css: &css, js: &js },
        header: &header,
        page,
        card: &card,
        nav_label: "Firewall pages",
        nav: &nav,
        foot: &foot,
        body,
        head: "",
        tail,
    })
}

/// `fwContent(body, width)`: the page's column, as the agent pages' `BoxPageBody` puts it.
pub fn fw_content(body: &str, width: &str) -> String {
    let max = match width {
        "narrow" => "max-w-[860px]",
        "wide" => "max-w-[1180px]",
        _ => "max-w-[1100px]",
    };
    format!(r#"<div class="mx-auto w-full {max} min-w-0 px-4 pt-6 pb-16 md:px-9 md:pt-8">{body}</div>"#)
}

/// The line under a minimal page: served by this firewall, never through ControlClaw.
fn minimal_foot(st: &FwShellState) -> String {
    match st.hostname.as_deref().filter(|h| !h.is_empty()) {
        Some(h) => {
            cc_shell::shell_minimal_foot("Served by your firewall, ", h, ". It never passes through ControlClaw.")
        }
        None => cc_shell::shell_minimal_foot("Served by your firewall. It never passes through ControlClaw.", "", ""),
    }
}

pub fn fw_minimal_page(title: &str, body: &str, tail: &str) -> String {
    let (css, js) = assets();
    cc_shell::shell_minimal_frame(
        title,
        &Assets { css: &css, js: &js },
        body,
        "",
        tail,
        &minimal_foot(&state()),
    )
}

/// `fwNotice`: a minimal page that only says something. With a script it is a page on its way
/// somewhere ("Opening…"), drawn with a spinner; without, it says why a page did not open, with a
/// way back to the console (or the panel).
pub fn fw_notice(title: &str, heading: Option<&str>, text: &str, id: Option<&str>, script: Option<&str>) -> String {
    fw_notice_in(title, heading, text, id, script, &state())
}

fn fw_notice_in(
    title: &str,
    heading: Option<&str>,
    text: &str,
    id: Option<&str>,
    script: Option<&str>,
    st: &FwShellState,
) -> String {
    let busy = script.is_some();
    let mark = if busy {
        r#"<span aria-hidden="true" class="grid h-11 w-11 place-items-center rounded-full bg-brand-soft"><span class="h-5 w-5 rounded-full border-2 border-brand/30 border-t-brand motion-safe:animate-spin"></span></span>"#.to_string()
    } else {
        format!(
            r#"<span aria-hidden="true" class="grid h-11 w-11 place-items-center rounded-full bg-bg-2 text-ink-2">{}</span>"#,
            cc_shell::icon("info", "h-5 w-5")
        )
    };
    let h = heading
        .map(|h| {
            format!(
                r#"<h1 class="text-[17px] font-semibold tracking-[-0.01em] text-ink">{}</h1>"#,
                escape_html(h)
            )
        })
        .unwrap_or_default();
    let id = id.map(|i| format!(r#" id="{}""#, escape_html(i))).unwrap_or_default();
    let back = match (&st.console_origin, busy) {
        (Some(o), false) => format!(
            r#"<a href="{}" class="mt-1 inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-surface px-3 text-[13px] font-medium text-ink shadow-sm hover:bg-bg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand">{}{}</a>"#,
            escape_html(&if st.standalone {
                format!("{o}/")
            } else {
                format!("{o}/dashboard")
            }),
            if st.standalone {
                "Open the panel"
            } else {
                "Open the console"
            },
            cc_shell::icon("external", "h-3.5 w-3.5 text-ink-2")
        ),
        _ => String::new(),
    };
    let body = format!(
        r#"<div class="flex flex-col items-center gap-3 py-2 text-center">{mark}{h}<p{id} class="max-w-[46ch] text-[14px] text-pretty text-ink-2" role="status">{}</p>{back}</div>"#,
        escape_html(text)
    );
    let tail = script
        .map(|s| format!(r#"<script src="{}"></script>"#, escape_html(s)))
        .unwrap_or_default();
    let (css, js) = assets();
    cc_shell::shell_minimal_frame(
        title,
        &Assets { css: &css, js: &js },
        &body,
        "",
        &tail,
        &minimal_foot(st),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> FwShellState {
        FwShellState {
            hostname: Some("mitm-1.ccl.bot".into()),
            console_origin: Some("https://console.example".into()),
            firewall_id: "fw_1".into(),
            pages: ALL.into_iter().map(|p| (p, true)).collect(),
            ..FwShellState::default()
        }
    }

    fn pairs(n: &[NavItem]) -> Vec<(String, Option<String>)> {
        n.iter().map(|i| (i.label.clone(), i.href.clone())).collect()
    }

    fn s(x: &str) -> Option<String> {
        Some(x.to_string())
    }

    #[test]
    fn the_sidebar_goes_through_the_console() {
        let want = |v: Vec<(&str, Option<String>)>| v.into_iter().map(|(l, h)| (l.to_string(), h)).collect::<Vec<_>>();
        assert_eq!(
            pairs(&fw_shell_nav(None, &st())),
            want(vec![
                ("Logs", s("https://console.example/dashboard/firewall/logs/open")),
                (
                    "Content rules",
                    s("https://console.example/dashboard/firewall/content-rules/open")
                ),
                ("Website logins", s("https://console.example/logins/open")),
                ("Doctor", s("https://console.example/dashboard/doctor/firewall?vm=fw_1")),
            ])
        );
        let groups: Vec<_> = fw_shell_nav(None, &st()).iter().map(|i| i.group).collect();
        assert_eq!(groups, [None, None, Some("Set up"), Some("Help")]);
        // AI review is listed only while it is open: the console opens it per agent.
        let on = fw_shell_nav(Some(FwPage::AiReview), &st());
        assert_eq!(on[2].label, "AI review");
        assert_eq!(on[2].href, s("./"));
        assert!(on[2].active);
        let mut some = st();
        some.pages.insert(FwPage::Doctor, false);
        some.pages.insert(FwPage::Content, false);
        let on = fw_shell_nav(Some(FwPage::Logins), &some);
        assert_eq!(
            pairs(&on),
            want(vec![
                ("Logs", s("https://console.example/dashboard/firewall/logs/open")),
                ("Website logins", s("/__cc/logins/"))
            ])
        );
        assert!(on[1].active);
        let mut alone = st();
        alone.console_origin = None;
        assert_eq!(
            pairs(&fw_shell_nav(Some(FwPage::Doctor), &alone)),
            want(vec![("Doctor", None)])
        );
        let page = fw_shell_page("x", Some(FwPage::Doctor), "", None, "", Some(&alone));
        assert!(page.contains(r#"<span aria-current="page" class="#));
        assert!(!page.contains("<a "));
        assert!(fw_shell_nav(None, &alone).is_empty());
    }

    #[test]
    fn a_standalone_sidebar_goes_through_the_panel() {
        let mut p = st();
        p.standalone = true;
        p.console_origin = s("http://localhost:8800");
        let want: Vec<(String, Option<String>)> = vec![
            ("Logs".into(), s("http://localhost:8800/open/firewall-logs")),
            ("Content rules".into(), s("http://localhost:8800/open/content-rules")),
            ("Website logins".into(), s("/__cc/logins/")),
        ];
        // Doctor and the AI review history are not on a standalone firewall.
        assert_eq!(pairs(&fw_shell_nav(Some(FwPage::Logins), &p)), want);
        let page = fw_shell_page("x", Some(FwPage::Logins), "", Some(None), "", Some(&p));
        assert!(page.contains(r#"<a href="http://localhost:8800/logins""#) && page.contains("Back to console"));
        let page = fw_shell_page("x", Some(FwPage::Content), "", Some(s("https://c/x")), "", Some(&p));
        assert!(page.contains(r#"<a href="http://localhost:8800/security""#));
        assert_eq!(fw_console_url("vm_2", &p), s("http://localhost:8800/"));
    }

    #[test]
    fn badges_and_the_status_line() {
        let mut b = st();
        b.badges.insert(FwPage::Content, ("2 held".into(), Tone::Ask));
        b.status = s("Running · 1.58.2");
        let nav = fw_shell_nav(Some(FwPage::Logs), &b);
        assert_eq!(nav[1].badge.as_deref(), Some("2 held"));
        assert_eq!(nav[1].badge_tone, Some(Tone::Ask));
        let page = fw_shell_page("x", Some(FwPage::Logs), "", None, "", Some(&b));
        assert!(page.contains("text-ask-fg") && page.contains(">2 held</span>"));
        assert!(page.contains("Running · 1.58.2"));
        // A member (no write) does not see the held count; an owner or admin does.
        let member = for_viewer(b.clone(), false);
        assert!(!fw_shell_page("x", Some(FwPage::Logs), "", None, "", Some(&member)).contains("2 held"));
        assert!(fw_shell_page("x", Some(FwPage::Logs), "", None, "", Some(&for_viewer(b, true))).contains("2 held"));
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
        let p = fw_shell_page("x", Some(FwPage::AiReview), "", None, "", Some(&st()));
        assert!(
            p.contains(r#"<span aria-current="page" class="truncate font-medium text-ink">AI review history</span>"#)
        );
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
        let notice = fw_notice_in("Logins", Some("It <failed>"), "Try & again", Some("s"), None, &s);
        assert!(notice.contains(r#"It &lt;failed&gt;</h1><p id="s" class="#));
        assert!(notice.contains(r#"role="status">Try &amp; again</p>"#));
        assert!(notice.contains(r#"href="https://console.example/dashboard""#) && notice.contains("Open the console"));
        assert!(notice.contains("Served by your firewall, <span class=\"font-mono\">&lt;b&gt;.ccl.bot</span>"));
        let opening = fw_notice_in("Logins", None, "Opening…", Some("s"), Some("/__cc/logins/open.js"), &s);
        assert!(opening.contains(r#"<script src="/__cc/logins/open.js"></script></body>"#));
        assert!(opening.contains("animate-spin") && !opening.contains("Open the console"));
    }

    #[test]
    fn assets_are_served_without_a_grant() {
        set_fw_shell_css(Some("body{color:red}"));
        let (css, js) = assets();
        assert!(owns_fw_ui_path(&css) && owns_fw_ui_path(&js) && owns_fw_ui_path(fw_kit_src()));
        assert!(!owns_fw_ui_path("/__cc/doctor/logs/"));
        let (s, ty, body, cache) = serve_fw_ui("GET", &css);
        assert_eq!((s, ty, body.as_str()), (200, "text/css", "body{color:red}"));
        assert!(cache.contains("immutable"));
        let (s, _, body, cache) = serve_fw_ui("GET", &format!("{FW_UI_ROOT}/shell-000000000000.css"));
        assert_eq!((s, body.as_str(), cache), (200, "body{color:red}", "no-store"));
        let (s, ty, body, _) = serve_fw_ui("GET", &js);
        assert_eq!((s, ty), (200, "text/javascript"));
        assert!(body.contains("prefers-color-scheme: dark"));
        let (s, ty, body, cache) = serve_fw_ui("GET", fw_kit_src());
        assert_eq!((s, ty), (200, "text/javascript"));
        assert!(body.contains("ccKit") && cache.contains("immutable"));
        assert_eq!(serve_fw_ui("GET", &format!("{FW_UI_ROOT}/other.css")).0, 404);
        assert_eq!(serve_fw_ui("POST", &css).0, 405);
        set_fw_shell_css(None);
    }
}
