//! The local panel's files (`apps/firewall-panel`), served next to the API on the panel listener,
//! so the page and `/api/` share one origin and the session cookie.
//!
//! The build is three flat files in the firewall's `dist-ui/` (rust/scripts/box-ui): `panel.js`
//! and `panel.css` by name, and `panel.html` for every other path that is not `/api/`, so the
//! SPA's own routes (`/agents`, `/oauth/callback`) load the app. No part of the request's path
//! reaches the filesystem. The files are read on each request; a firewall without them answers
//! 404 as before.
//!
//! The app logos are one more file, `connector-icons.pack` (written by
//! `apps/firewall-panel/scripts/build-fw-files.mjs`), served at
//! `/connector-icons/<version>/<service>.webp`. It is read once, on the first logo asked for.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use http::Method;
use serde_json::json;

use crate::admin::Admin;

/// What the panel's page may load: its own script and stylesheet, and inline styles the UI
/// library sets at run time. Nothing from elsewhere, and no framing.
const CSP: &str = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; \
                   connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

impl Admin {
    /// [`Admin::router`] plus the panel's files from `dir` (the firewall's `dist-ui/`).
    pub fn router_with_panel(self: &Arc<Self>, dir: PathBuf) -> cc_http::Router {
        let mut r = self.router();
        let me = self.clone();
        let dir = Arc::new(dir);
        let icons: Arc<tokio::sync::OnceCell<Icons>> = Arc::default();
        r.route(
            "api",
            |m, p| (*m == Method::GET || *m == Method::HEAD) && p != "/api" && !p.starts_with("/api/"),
            move |req, _ctx| {
                let (me, dir, icons) = (me.clone(), dir.clone(), icons.clone());
                async move {
                    let (parts, _) = req.into_parts();
                    if !me.host_ok(cc_http::header(&parts, "host")) {
                        return cc_http::json(
                            421,
                            &json!({"error": "This firewall's API is not served under that name"}),
                        );
                    }
                    let path = cc_http::pathname(parts.uri.path());
                    if let Some(rest) = path.strip_prefix("/connector-icons/") {
                        return icon(&dir, &icons, rest).await;
                    }
                    serve(&dir, &path).await
                }
            },
        );
        r
    }
}

/// The logos: one file, `CCICONS1\n`, then a JSON line `{"<service>": [offset, length]}`, then the
/// WebP bytes the offsets point into.
#[derive(Default)]
struct Icons {
    index: HashMap<String, (usize, usize)>,
    data: Vec<u8>,
}

const ICONS_FILE: &str = "connector-icons.pack";
const ICONS_MAGIC: &[u8] = b"CCICONS1\n";

impl Icons {
    fn parse(mut bytes: Vec<u8>) -> Option<Icons> {
        let rest = bytes.strip_prefix(ICONS_MAGIC)?;
        let end = rest.iter().position(|b| *b == b'\n')?;
        let index: HashMap<String, (usize, usize)> = serde_json::from_slice(&rest[..end]).ok()?;
        let data = bytes.split_off(ICONS_MAGIC.len() + end + 1);
        // Every entry inside the data, or none of them is used.
        index
            .values()
            .all(|(off, len)| off.checked_add(*len).is_some_and(|e| e <= data.len()))
            .then_some(Icons { index, data })
    }

    fn get(&self, service: &str) -> Option<&[u8]> {
        let (off, len) = *self.index.get(service)?;
        self.data.get(off..off + len)
    }
}

/// `rest` is `<version>/<service>.webp`. The version is there for the browser's cache only: this
/// firewall has the one set of logos its build came with.
async fn icon(dir: &Path, icons: &tokio::sync::OnceCell<Icons>, rest: &str) -> cc_http::Resp {
    let Some(service) = rest.split_once('/').and_then(|(_, file)| file.strip_suffix(".webp")) else {
        return cc_http::not_found();
    };
    // An empty set is kept too, so a firewall without the file does not read it for every logo.
    let pack = icons
        .get_or_init(|| async {
            match tokio::fs::read(dir.join(ICONS_FILE)).await {
                Ok(bytes) => Icons::parse(bytes).unwrap_or_else(|| {
                    tracing::warn!("{ICONS_FILE} is not a logo pack: no app logos");
                    Icons::default()
                }),
                Err(_) => Icons::default(),
            }
        })
        .await;
    let Some(body) = pack.get(service) else {
        return cc_http::not_found();
    };
    let mut r = cc_http::full(http::StatusCode::OK, "image/webp", body.to_vec());
    let h = r.headers_mut();
    h.insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    h.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    r
}

async fn serve(dir: &Path, path: &str) -> cc_http::Resp {
    let (file, kind) = match path {
        "/panel.js" => ("panel.js", "text/javascript; charset=utf-8"),
        "/panel.css" => ("panel.css", "text/css; charset=utf-8"),
        _ => ("panel.html", "text/html; charset=utf-8"),
    };
    let Ok(body) = tokio::fs::read(dir.join(file)).await else {
        return cc_http::not_found();
    };
    let mut r = cc_http::full(http::StatusCode::OK, kind, body);
    let h = r.headers_mut();
    h.insert(http::header::CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
    h.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        http::header::REFERRER_POLICY,
        http::HeaderValue::from_static("same-origin"),
    );
    if file == "panel.html" {
        h.insert(
            http::header::CONTENT_SECURITY_POLICY,
            http::HeaderValue::from_static(CSP),
        );
    }
    r
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::admin::{Admin, AdminConfig, Hooks};
    use crate::db::Db;
    use crate::plane::LocalControlPlane;

    async fn start(dir: &std::path::Path) -> String {
        let db = Arc::new(Db::memory().expect("db"));
        let plane = Arc::new(LocalControlPlane::new(db.clone()));
        let admin = Admin::new(db, plane, Hooks::default(), AdminConfig::with_hosts(false, []));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        tokio::spawn(cc_http::serve(
            listener,
            Arc::new(admin.router_with_panel(dir.to_path_buf())),
        ));
        base
    }

    async fn get(base: &str, path: &str, host: Option<&str>) -> (u16, String, String) {
        let mut r = reqwest::Client::new().get(format!("{base}{path}"));
        if let Some(h) = host {
            r = r.header("host", h);
        }
        let res = r.send().await.expect("send");
        let kind = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        (res.status().as_u16(), kind, res.text().await.unwrap_or_default())
    }

    #[tokio::test]
    async fn the_files_and_the_spa_routes() {
        let dir = tempfile::tempdir().expect("dir");
        let ui = dir.path().join("dist-ui");
        std::fs::create_dir(&ui).expect("ui");
        std::fs::write(ui.join("panel.html"), "<html>panel</html>").expect("html");
        std::fs::write(ui.join("panel.js"), "js()").expect("js");
        std::fs::write(ui.join("panel.css"), "a{}").expect("css");
        std::fs::write(dir.path().join("secret"), "no").expect("secret");
        let base = start(&ui).await;

        for p in ["/", "/agents", "/oauth/callback?code=x", "/panel.html"] {
            let (s, kind, body) = get(&base, p, None).await;
            assert_eq!((s, body.as_str()), (200, "<html>panel</html>"), "{p}");
            assert!(kind.starts_with("text/html"), "{p}: {kind}");
        }
        assert_eq!(get(&base, "/panel.js", None).await.2, "js()");
        assert!(get(&base, "/panel.css", None).await.1.starts_with("text/css"));
        // Nothing but the three files: a dot path is resolved before the match, the rest is the page.
        for p in ["/../secret", "/%2e%2e/secret", "/panel.js/../../secret", "/secret"] {
            assert_eq!(get(&base, p, None).await.2, "<html>panel</html>", "{p}");
        }
        // The API is not shadowed, nor its bare name.
        assert_eq!(get(&base, "/api", None).await.0, 404);
        let (s, _, body) = get(&base, "/api/session", None).await;
        assert_eq!(s, 200);
        assert!(body.contains("\"setup\":true"), "{body}");
        // The same Host check as the API.
        assert_eq!(get(&base, "/", Some("evil.example")).await.0, 421);

        // The logos, from the pack by service. Anything else under the path is a 404, not the page.
        let mut pack = b"CCICONS1\n{\"a_b\":[0,3],\"c-d\":[3,2]}\n".to_vec();
        pack.extend_from_slice(b"RIFxy");
        std::fs::write(ui.join("connector-icons.pack"), &pack).expect("pack");
        let res = reqwest::get(format!("{base}/connector-icons/v1/a_b.webp"))
            .await
            .expect("icon");
        assert_eq!(res.status().as_u16(), 200);
        assert_eq!(res.headers()["content-type"], "image/webp");
        assert!(
            res.headers()["cache-control"]
                .to_str()
                .unwrap_or_default()
                .contains("immutable")
        );
        assert_eq!(res.bytes().await.expect("body").as_ref(), b"RIF");
        assert_eq!(get(&base, "/connector-icons/v2/c-d.webp", None).await.2, "xy");
        for p in [
            "/connector-icons/v1/zz.webp",
            "/connector-icons/v1/a_b.png",
            "/connector-icons/a_b.webp",
            "/connector-icons/",
        ] {
            assert_eq!(get(&base, p, None).await.0, 404, "{p}");
        }
        // A pack whose offsets point past its end is not used.
        assert!(super::Icons::parse(b"CCICONS1\n{\"a\":[0,9]}\nxy".to_vec()).is_none());

        // No build on this firewall: 404, as before.
        std::fs::remove_file(ui.join("panel.html")).expect("rm");
        assert_eq!(get(&base, "/agents", None).await.0, 404);
    }
}
