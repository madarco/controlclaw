//! The agent half of `packages/origin-guard`: one Origin check for everything a box serves to a
//! browser, and one way to read a cookie that cannot carry the `__Host-` prefix.
//!
//! Every agent box is `<handle>.vm.controlclaw.com` and the console is `controlclaw.com`, so they
//! are one site and `SameSite=Lax` does nothing between two boxes. The Origin check is what stands
//! between them; see the TS module for the full reasoning. The rules, in order:
//!
//! 1. A request with no cookie is not this check's problem (unless `uncredentialed` is `Check`).
//! 2. A top-level navigation passes when `allow_top_level_navigation` is set.
//! 3. `Sec-Fetch-Site: cross-site` is refused.
//! 4. An `Origin` that is present must be on the list, after normalisation.
//! 5. A state-changing request with no `Origin` is refused.

use http::HeaderMap;

/// Methods that do not change state. Everything else is state-changing, as is a WebSocket upgrade.
const SAFE_METHODS: [&str; 3] = ["GET", "HEAD", "OPTIONS"];

/// Destinations a navigation has when it loads us inside another page rather than in a tab of its own.
const EMBEDDED_DESTS: [&str; 5] = ["iframe", "frame", "fencedframe", "embed", "object"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginDenial {
    CrossSite,
    BadOrigin,
    MissingOrigin,
}

impl OriginDenial {
    /// The word the TS code uses (`cross_site`, `bad_origin`, `missing_origin`).
    pub fn as_str(self) -> &'static str {
        match self {
            OriginDenial::CrossSite => "cross_site",
            OriginDenial::BadOrigin => "bad_origin",
            OriginDenial::MissingOrigin => "missing_origin",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginVerdict {
    Ok,
    Denied {
        reason: OriginDenial,
        origin: Option<String>,
    },
}

impl OriginVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, OriginVerdict::Ok)
    }
}

/// What the check needs to know about a request, independent of the HTTP stack that served it.
#[derive(Debug, Clone, Default)]
pub struct RequestFacts {
    /// The real method. Behind a `forward_auth` sub-request that is `X-Forwarded-Method`.
    pub method: String,
    pub origin: Option<String>,
    pub sec_fetch_site: Option<String>,
    pub sec_fetch_mode: Option<String>,
    pub sec_fetch_dest: Option<String>,
    /// A WebSocket handshake, which is state-changing however safe its method looks.
    pub is_upgrade: bool,
    /// The request carries a `Cookie` header, so it spends browser credentials.
    pub credentialed: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Uncredentialed {
    /// A request without a cookie has nothing to spend (the default).
    #[default]
    Allow,
    Check,
}

#[derive(Debug, Clone, Default)]
pub struct OriginPolicy {
    /// The origins allowed, exactly. `None` entries are dropped, so callers can pass what they have.
    pub allowed: Vec<Option<String>>,
    /// Let a cross-site top-level navigation through: somebody following a link to their agent.
    pub allow_top_level_navigation: bool,
    pub uncredentialed: Uncredentialed,
}

impl OriginPolicy {
    pub fn allowing<I, S>(allowed: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allowed: allowed.into_iter().map(|s| Some(s.into())).collect(),
            ..Self::default()
        }
    }
}

/// Lower-case the scheme and host, drop a default port and any path. Anything unparseable is
/// returned trimmed, so it can only ever fail to match. `"null"` and empty are `None`.
pub fn normalize_origin(origin: Option<&str>) -> Option<String> {
    let raw = origin?.trim();
    if raw.is_empty() || raw == "null" {
        return None;
    }
    let Ok(url) = url::Url::parse(raw) else {
        return Some(raw.to_string());
    };
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Some(raw.to_string());
    }
    let host = url.host_str().unwrap_or("").to_lowercase();
    // `Url::port` is already `None` for the scheme's default port.
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Some(format!("{scheme}://{host}{port}"))
}

/// True for a POST/PUT/PATCH/DELETE, and for any WebSocket handshake whatever its method says.
pub fn is_state_changing(method: &str, is_upgrade: bool) -> bool {
    is_upgrade || !SAFE_METHODS.contains(&method.to_uppercase().as_str())
}

#[derive(PartialEq)]
enum Navigation {
    TopLevel,
    Framed,
}

/// A navigation is never state-changing; top-level is anything but an embedded destination,
/// because browsers do not all send `Sec-Fetch-Dest: document` on one.
fn navigation_kind(f: &RequestFacts) -> Option<Navigation> {
    if is_state_changing(&f.method, f.is_upgrade) || f.sec_fetch_mode.as_deref() != Some("navigate") {
        return None;
    }
    if EMBEDDED_DESTS.contains(&f.sec_fetch_dest.as_deref().unwrap_or("")) {
        Some(Navigation::Framed)
    } else {
        Some(Navigation::TopLevel)
    }
}

pub fn check_origin(facts: &RequestFacts, policy: &OriginPolicy) -> OriginVerdict {
    if !facts.credentialed && policy.uncredentialed == Uncredentialed::Allow {
        return OriginVerdict::Ok;
    }
    let origin = normalize_origin(facts.origin.as_deref());
    if policy.allow_top_level_navigation && navigation_kind(facts) == Some(Navigation::TopLevel) {
        return OriginVerdict::Ok;
    }
    if facts.sec_fetch_site.as_deref() == Some("cross-site") {
        return OriginVerdict::Denied {
            reason: OriginDenial::CrossSite,
            origin,
        };
    }
    if let Some(origin) = origin {
        let allowed = policy
            .allowed
            .iter()
            .filter_map(|o| normalize_origin(o.as_deref()))
            .any(|o| o == origin);
        return if allowed {
            OriginVerdict::Ok
        } else {
            OriginVerdict::Denied {
                reason: OriginDenial::BadOrigin,
                origin: Some(origin),
            }
        };
    }
    if is_state_changing(&facts.method, facts.is_upgrade) {
        return OriginVerdict::Denied {
            reason: OriginDenial::MissingOrigin,
            origin: None,
        };
    }
    OriginVerdict::Ok
}

/// One line for the log when a request is refused, with nothing in it the refused page chose.
pub fn denial_message(reason: OriginDenial, origin: Option<&str>) -> String {
    match reason {
        OriginDenial::CrossSite => "refused a cross-site request".into(),
        OriginDenial::MissingOrigin => "refused a state-changing request with no Origin".into(),
        OriginDenial::BadOrigin => format!("refused an unexpected Origin: {}", origin.unwrap_or("(none)")),
    }
}

/// A header the way `node:http` hands it over: repeated values joined with `", "` (`"; "` for
/// `Cookie`), or `None`. Joining matters: two Origin headers read as one value that matches nothing.
pub fn node_header(headers: &HeaderMap, name: &str) -> Option<String> {
    let values: Vec<&str> = headers.get_all(name).iter().map(|v| v.to_str().unwrap_or("")).collect();
    if values.is_empty() {
        return None;
    }
    let sep = if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    };
    Some(values.join(sep))
}

/// Facts from a request served by the agents (the TS `nodeRequestFacts`).
///
/// `method_override` exists for Caddy's `forward_auth`, which asks a GET about a request that may
/// have been a POST and puts the real one in `X-Forwarded-Method`; that header is read too.
pub fn agent_request_facts(method: &str, headers: &HeaderMap, method_override: Option<&str>) -> RequestFacts {
    let forwarded = node_header(headers, "x-forwarded-method");
    RequestFacts {
        method: method_override
            .map(str::to_string)
            .or(forwarded)
            .unwrap_or_else(|| method.to_string())
            .to_uppercase(),
        origin: node_header(headers, "origin"),
        sec_fetch_site: node_header(headers, "sec-fetch-site"),
        sec_fetch_mode: node_header(headers, "sec-fetch-mode"),
        sec_fetch_dest: node_header(headers, "sec-fetch-dest"),
        is_upgrade: node_header(headers, "upgrade").unwrap_or_default().to_lowercase() == "websocket",
        credentialed: node_header(headers, "cookie").is_some(),
    }
}

/// Facts for a server that is not behind `forward_auth` (the TS `fetchRequestFacts`).
/// `X-Forwarded-Method` is deliberately not read: there it is a header any client can send.
pub fn fetch_request_facts(method: &str, headers: &HeaderMap) -> RequestFacts {
    let mut f = agent_request_facts(method, headers, Some(method));
    f.method = method.to_uppercase();
    f
}

/// The origin this request was addressed to, from `Host` alone, never `X-Forwarded-Host`, which
/// any client can send. `X-Forwarded-Proto` can only pick a scheme, so a wrong one fails to match.
pub fn request_origin(host: Option<&str>, forwarded_proto: Option<&str>) -> Option<String> {
    let host = host?;
    let proto = forwarded_proto
        .unwrap_or("https")
        .split(',')
        .next()
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("https");
    normalize_origin(Some(&format!("{proto}://{host}")))
}

/// Every value a `Cookie` header carries for one name, in the order the browser sent them.
/// More than one means somebody tossed a cookie at another `Domain` or `Path`.
pub fn cookie_values(header: Option<&str>, name: &str) -> Vec<String> {
    let Some(header) = header else { return Vec::new() };
    let mut out = Vec::new();
    for part in header.split(';') {
        let trimmed = part.trim();
        let Some(eq) = trimmed.find('=') else { continue };
        if eq < 1 || &trimmed[..eq] != name {
            continue;
        }
        out.push(trimmed[eq + 1..].to_string());
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieReading {
    /// The single value, or `None` when there was none, or more than one.
    pub value: Option<String>,
    /// The header carried this name more than once. Worth a log line: it is an attack.
    pub duplicated: bool,
}

/// Read a cookie that must appear exactly once. A duplicate is refused rather than resolved.
pub fn read_unique_cookie(header: Option<&str>, name: &str) -> CookieReading {
    let mut values = cookie_values(header, name);
    if values.len() == 1 {
        return CookieReading {
            value: values.pop(),
            duplicated: false,
        };
    }
    CookieReading {
        value: None,
        duplicated: values.len() > 1,
    }
}

#[cfg(test)]
mod tests;
