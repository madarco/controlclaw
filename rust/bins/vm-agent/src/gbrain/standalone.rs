//! A standalone brain: GBrain next to a standalone firewall, with no ControlClaw console
//! (docs/plans/standalone-brain.md, parts A and B; docs/standalone/brain.md).
//!
//! Chosen by the agent's config file (`"mode": "brain"`, `unmanaged/config.rs`), which
//! `controlclaw brain install` and `brain connect` write. Like the unmanaged agent mode:
//!
//! - The firewall is the control plane. Its key, from the file, opens the firewall's routes (bound
//!   tokens for the paired address, `firewall.hostnames`) and the console's (`/health`, `/status`,
//!   `/brain/model`, which the firewall signs as its control plane); until pairing has set one, every
//!   route answers 401. No SaaS key, no ready report, no console token, no first boot: `brain install`
//!   or `brain connect` put the brain behind the firewall.
//! - What it serves of the SaaS brain, unchanged: `/llm/apply` (the user's own key's placeholder,
//!   `key::parse_standalone`), `/gbrain/connect|disconnect|lock|connections`, `/brain/model`, and the
//!   brain's own pages under `/__cc/brain` with their sign-in, and GBrain's admin page behind it.
//! - Agents reach it the way part B relays them (`gate::GateMode::Relayed`): the firewall's tools
//!   gate sends each call to `/gbrain/mcp/<vmId>` with a token bound to it. No 3131 listener.
//! - The root helpers run behind the file's `gbrain.exec` (`docker exec` into GBrain's container,
//!   or nothing when this agent is root next to GBrain), and GBrain is on `gbrain.port` on loopback.
//!
//! The pages: the firewall relays them to a person's browser (`BRAIN_PAGES_BIND`), on the name set
//! with `PUT /api/brain/pages`, which is this brain's `gbrain.pages_name` (its `vm_hostname`, so the
//! sign-in's Origin checks are `https://<name>`). The firewall pushes its own origin (`/access/config`),
//! enrolls the browser and sends it to `/__cc/open` with an intent it signs; the brain's sign-in does
//! the rest and lands on `/__cc/brain`. GBrain's own admin page is not served here.
//!
//! Not here: outside AI apps, backups, Activity and the counts by kind (shipped to the console on a
//! SaaS brain), updates, and start/stop/restart.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use cc_http::{Router, json};
use hyper::Method;
use serde_json::{Value, json as j};

use super::{gate, pages};
use crate::app::App;
use crate::stages;
use crate::unmanaged::config::{AgentFile, BrainHints};

pub const DEFAULT_GBRAIN_PORT: u16 = 3130;

pub struct Standalone {
    pub file: AgentFile,
    /// Where `file` was read from, for the log.
    pub path: PathBuf,
    /// The agent's own files (`file.state_dir`, resolved): its keys, sessions and the agents' tokens.
    pub state_dir: PathBuf,
    hints: BrainHints,
}

impl Standalone {
    pub fn new(file: AgentFile, path: PathBuf, home: &Path) -> Self {
        let state_dir = file.state_dir(home);
        let hints = file.gbrain.clone().unwrap_or_default();
        Self {
            file,
            path,
            state_dir,
            hints,
        }
    }

    pub fn gbrain_port(&self) -> u16 {
        self.hints.port.unwrap_or(DEFAULT_GBRAIN_PORT)
    }

    /// The helpers' prefix: the file's, else `sudo` as on a SaaS brain.
    pub fn exec(&self) -> Vec<String> {
        self.hints.exec.clone().unwrap_or_else(|| vec!["sudo".into()])
    }

    /// The name the brain's pages are reached at through the firewall's relay, when it has one.
    pub fn pages_name(&self) -> Option<&str> {
        self.hints
            .pages_name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
    }

    /// The pages' name as the firewall keeps it (lower case), else the brain's name on the firewall.
    fn hostname(&self) -> String {
        match self.pages_name() {
            Some(n) => n.to_ascii_lowercase(),
            None => self
                .hints
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty() && n.len() <= 253 && !n.contains(['\n', '\r']))
                .unwrap_or("brain")
                .to_string(),
        }
    }

    /// The files the shared code reads from the keys folder (here the state folder): this brain's id,
    /// its name (the pages' name, whose `https://` origin their sign-in checks, else its name on the
    /// firewall), and the panel for their "Back" link. Written at each start, so they follow the file.
    pub fn write_identity(&self) -> std::io::Result<()> {
        let mut files = vec![("vm_hostname", self.hostname())];
        if let Some(id) = self.file.agent_id.as_deref().filter(|v| !v.is_empty()) {
            files.push(("vm_id", id.to_string()));
        }
        // `allowed_origins` takes the console's origin from this URL; its path is never called here.
        if let Some(panel) = self.hints.panel_url.as_deref().and_then(|u| url::Url::parse(u).ok()) {
            files.push((
                "config_api_url",
                format!("{}/api", panel.origin().ascii_serialization()),
            ));
        }
        for (name, value) in files {
            cc_store::write_file(&self.state_dir.join(name), format!("{value}\n").as_bytes(), 0o600)?;
        }
        Ok(())
    }

    fn firewall(&self) -> Value {
        j!({ "url": self.file.firewall.url, "paired": self.file.firewall_key().is_some() })
    }
}

/// Whether GBrain answers its own `/health` on loopback. One client for every probe.
async fn gbrain_answers(port: u16) -> bool {
    static CLIENT: std::sync::LazyLock<Option<reqwest::Client>> =
        std::sync::LazyLock::new(|| reqwest::Client::builder().timeout(Duration::from_secs(3)).build().ok());
    let Some(client) = CLIENT.as_ref() else {
        return false;
    };
    client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .is_ok_and(|r| r.status().is_success())
}

/// The sign-in shim's options on a standalone brain, as on a SaaS brain: the brain's login routes, a
/// ticket for the pages landing on them (`next: "files"`), and any other (the firewall's GBrain admin
/// Open) on GBrain's own single-use admin link, which `/admin` below then serves.
fn access_options(app: &Arc<App>) -> crate::boxside::AccessOptions {
    let runner = app.runner.clone();
    crate::boxside::AccessOptions {
        only: Some(super::BRAIN_ACCESS_ROUTES),
        pages: Some(pages::LANDING),
        require_write: Some("Only the firewall's admin can open the brain.".into()),
        steps: Some(("Signing you in to the brain".into(), "Loading the brain".into())),
        landing: Some(Arc::new(move || {
            let runner = runner.clone();
            Box::pin(async move {
                super::login::login_path(runner.as_ref()).await.map_err(|e| {
                    tracing::error!("[access] {e}");
                    "The brain did not give a sign-in link for GBrain's admin page. It may be starting; try again in a minute.".to_string()
                })
            })
        })),
    }
}

/// GBrain's admin page (`/admin`, `/admin/*`), for a browser the brain's sign-in let in: what Caddy
/// does on a SaaS brain (`forward_auth` to `/__cc/verify`, then GBrain on loopback, unbuffered).
/// GBrain's own admin cookie, set by the single-use link, is on top of this.
async fn admin(app: &App, access: &crate::boxside::access::Access, port: u16, req: cc_http::Req) -> cc_http::Resp {
    let (parts, body) = req.into_parts();
    // `/__cc/verify`'s check: this brain's own origin (a page's navigation is let through, as there),
    // and a session for this brain.
    let policy = cc_origin::OriginPolicy {
        allowed: vec![access.allowed_origins().0],
        allow_top_level_navigation: true,
        uncredentialed: cc_origin::Uncredentialed::Allow,
    };
    let cookie = cc_origin::node_header(&parts.headers, "cookie");
    let vm_id = app.keys.read("vm_id").filter(|v| !v.is_empty());
    let signed_in = access.origin_allowed(&parts, &policy, "/admin")
        && vm_id.is_some_and(|vm| access.sessions.verify_session(cookie.as_deref(), &vm));
    if !signed_in {
        return cc_http::full(
            http::StatusCode::UNAUTHORIZED,
            "text/plain; charset=utf-8",
            "Open GBrain's admin page from the firewall's panel.",
        );
    }
    match forward_admin(port, parts, body).await {
        Ok(mut r) => {
            r.headers_mut()
                .insert("x-frame-options", http::HeaderValue::from_static("DENY"));
            r
        }
        Err(e) => {
            tracing::error!("[brain] GBrain's admin page: {e}");
            cc_http::full(
                http::StatusCode::BAD_GATEWAY,
                "text/plain; charset=utf-8",
                "GBrain did not answer.",
            )
        }
    }
}

/// One request to GBrain on loopback, its answer streamed back.
async fn forward_admin(
    port: u16,
    mut parts: http::request::Parts,
    body: hyper::body::Incoming,
) -> Result<cc_http::Resp, String> {
    use http_body_util::BodyExt;
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tcp))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    parts.headers.remove(http::header::AUTHORIZATION);
    let path = parts.uri.path_and_query().map_or("/admin", |p| p.as_str()).to_string();
    parts.uri = path.parse().map_err(|e: http::uri::InvalidUri| e.to_string())?;
    let up = sender
        .send_request(http::Request::from_parts(parts, body))
        .await
        .map_err(|e| e.to_string())?;
    let (mut parts, body) = up.into_parts();
    parts.headers.remove(http::header::TRANSFER_ENCODING);
    parts.headers.remove(http::header::CONNECTION);
    Ok(http::Response::from_parts(
        parts,
        body.map_err(std::io::Error::other).boxed(),
    ))
}

/// The router, on the one listener the firewall's address alone may reach (`firewall.allow_from`):
/// the firewall relays agents' calls and the browser's pages to it.
pub fn router(app: &Arc<App>) -> Router {
    let mut router = Router::new(stages::BRAIN_BOX);
    let Some(brain) = app.brain.clone() else {
        return router;
    };
    let a = app.clone();
    router.gate(stages::CONSOLE, move |parts, _| {
        let target = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let ok = a
            .console_auth
            .verify(parts.method.as_str(), target, cc_http::header(parts, "authorization"))
            .is_some();
        (!ok).then(cc_http::unauthorized)
    });
    let gate = Arc::new(gate::BrainGate::new(
        &brain.state_dir.join("gbrain-gate.json"),
        app.runner.clone(),
    ));
    let clients = Arc::new(super::clients::BrainClients::new(
        &brain.state_dir.join("gbrain-clients.json"),
        app.runner.clone(),
    ));
    super::register_llm_apply(&mut router, app);
    // Part B's relay, `/gbrain/mcp/<vmId>`, before `/gbrain/`'s routes (the first match wins). This is
    // the relayed half of `gbrain::register_with(.., GateMode::Relayed)`; the rest of it is the SaaS
    // box's (its systemd lifecycle, backups, updates, outside apps, the console's sign-in landing).
    super::register_relay(&mut router, app, &gate);
    super::register_gbrain_routes(&mut router, app, &gate, &clients, gate::GateMode::Relayed);
    super::model::register(&mut router, app);

    // "Back" goes to the panel's Brain page (`gbrain.panel_url`), never the SaaS console.
    let access = crate::boxside::access(app, Some("/brain".into()));
    let brain_pages = pages::BrainPages::new(
        app,
        access.clone(),
        gate.clone(),
        &format!("http://127.0.0.1:{}", brain.gbrain_port()),
    );
    // The pages before the sign-in shim's `/__cc/` in the same stage.
    pages::register(&mut router, &brain_pages, stages::BRAIN_OPEN);
    crate::boxside::register_access(
        &mut router,
        app,
        &access,
        access_options(app),
        stages::BRAIN_OPEN,
        stages::BRAIN_OPEN,
    );
    let (a, acc, port) = (app.clone(), access.clone(), brain.gbrain_port());
    router.route(
        stages::BRAIN_OPEN,
        |_, p| p == "/admin" || p.starts_with("/admin/"),
        move |req, _| {
            let (app, acc) = (a.clone(), acc.clone());
            async move { admin(&app, &acc, port, req).await }
        },
    );

    let (a, b) = (app.clone(), brain.clone());
    router.exact(stages::CONSOLE, Method::GET, "/health", move |_, _| {
        let (app, brain) = (a.clone(), b.clone());
        async move {
            let up = gbrain_answers(brain.gbrain_port()).await;
            json(
                200,
                &j!({
                    "status": "ok",
                    "role": "gbrain",
                    "uptime": app.started.elapsed().as_secs_f64(),
                    "services": {"gbrain": if up { "running" } else { "stopped" }},
                }),
            )
        }
    });
    let b = brain.clone();
    router.exact(stages::CONSOLE, Method::GET, "/status", move |_, _| {
        let brain = b.clone();
        async move {
            let up = gbrain_answers(brain.gbrain_port()).await;
            let state = if up { "running" } else { "stopped" };
            json(
                200,
                &j!({
                    "ok": true,
                    "action": "status",
                    "mode": "brain",
                    "active": up,
                    "status": state,
                    "state": state,
                    "gbrain": {"answers": up, "port": brain.gbrain_port()},
                    "pages": {"name": brain.pages_name()},
                    "firewall": brain.firewall(),
                }),
            )
        }
    });
    router
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unmanaged::config::parse;

    fn brain(raw: &str) -> Standalone {
        Standalone::new(parse(raw).expect("parse"), "/x/agent.json".into(), Path::new("/home/u"))
    }

    #[test]
    fn defaults() {
        let b = brain(r#"{"mode":"brain"}"#);
        assert_eq!(b.gbrain_port(), 3130);
        assert_eq!(b.exec(), vec!["sudo".to_string()]);
        assert_eq!(b.pages_name(), None);
    }

    #[test]
    fn what_the_file_says() {
        let b = brain(r#"{"mode":"brain","gbrain":{"port":4000,"exec":[],"pages_name":"brain.example.com"}}"#);
        assert_eq!(b.gbrain_port(), 4000);
        assert!(b.exec().is_empty());
        assert_eq!(b.pages_name(), Some("brain.example.com"));
    }

    /// A standalone brain's router, its keys in its state folder, served on loopback.
    async fn serve_brain() -> (tempfile::TempDir, cc_testkit::BoxKeys, cc_proc::RecordingRunner, String) {
        use std::sync::atomic::AtomicBool;
        let dir = tempfile::tempdir().expect("dir");
        let keys = cc_testkit::BoxKeys::write(&dir.path().join("state"), "vm_1", "box.example").expect("keys");
        let raw = format!(
            r#"{{"mode":"brain","agent_id":"vm_1","state_dir":"{}","firewall":{{"hostnames":["box.example"]}},"gbrain":{{"pages_name":"brain.example.com"}}}}"#,
            keys.dir.display()
        );
        let brain = brain(&raw);
        brain.write_identity().expect("identity");
        let mut config = crate::app::Config::from_env();
        config.keys_dir = keys.dir.clone();
        config.state_dir = keys.dir.clone();
        config.service = "gbrain".into();
        let runner = cc_proc::RecordingRunner::new();
        runner.answer(&["sudo"], cc_proc::ok("changed\n"));
        let fw = keys.firewall.public_pem.clone();
        let kd = cc_auth::keys::KeysDir::new(&keys.dir);
        let http = cc_client::HttpClient::new(true).expect("http");
        let app = Arc::new(App {
            // The firewall's key opens both gates, as the unmanaged agent's does.
            console_auth: cc_auth::console::ConsoleAuth::new(
                cc_auth::jwt::VerifyKey::ed25519_spki_pem(&fw).expect("key"),
                Some("vm_1".into()),
                "gbrain",
            ),
            firewall_auth: cc_auth::firewall::FirewallAuth::new(
                move || Some(fw.clone()),
                Some("vm_1".into()),
                || vec!["box.example".to_string()],
                None,
            ),
            runner: Arc::new(runner.clone()),
            console: cc_client::ConsoleClient::new(kd.clone(), http.clone()),
            http,
            keys: kd,
            pool_healthy: AtomicBool::new(false),
            bootstrap_ready: AtomicBool::new(false),
            contracts: crate::contracts::Contracts::default(),
            started: std::time::Instant::now(),
            unmanaged: None,
            brain: Some(Arc::new(brain)),
            config,
        });
        let main = router(&app);
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", l.local_addr().expect("addr"));
        tokio::spawn(cc_http::serve(l, Arc::new(main)));
        (dir, keys, runner, url)
    }

    #[tokio::test]
    async fn the_firewall_is_its_control_plane() {
        use cc_testkit::Signer;
        let (_d, keys, runner, url) = serve_brain().await;
        let c = reqwest::Client::new();
        let get = |path: &str, token: Option<String>| {
            let mut r = c.get(format!("{url}{path}"));
            if let Some(t) = token {
                r = r.bearer_auth(t);
            }
            r.send()
        };
        // No token, or the SaaS console's: nothing. The firewall's: the brain's status.
        assert_eq!(get("/status", None).await.expect("send").status(), 401);
        let console = keys.sign_with(Signer::Console, j!({"vmId": "vm_1"}), Some(30));
        assert_eq!(get("/status", Some(console)).await.expect("send").status(), 401);
        let fw = keys.sign_with(Signer::Firewall, j!({"vmId": "vm_1"}), Some(30));
        let r = get("/status", Some(fw)).await.expect("send");
        assert_eq!(r.status(), 200);
        let body: Value = r.json().await.expect("json");
        assert_eq!(body["mode"], "brain");
        assert_eq!(body["pages"]["name"], "brain.example.com");
        // The firewall's console calls: `/health` in the shape cc-local reads.
        let fw = keys.sign_with(Signer::Firewall, j!({"vmId": "vm_1"}), Some(30));
        let h: Value = get("/health", Some(fw))
            .await
            .expect("send")
            .json()
            .await
            .expect("json");
        assert_eq!(h["role"], "gbrain");
        assert!(h["services"]["gbrain"].is_string());

        // Who may use the brain: the firewall's bound token only.
        let t = keys.firewall_token("gbrain", "GET", "/gbrain/connections", None);
        let r = get("/gbrain/connections", Some(t)).await.expect("send");
        assert_eq!(r.status(), 200);

        // Its key: the user's own key's placeholder, never the included AI's.
        let post = |path: &str, purpose: &str, body: Value| {
            let raw = serde_json::to_vec(&body).expect("json");
            let token = keys.firewall_token(purpose, "POST", path, Some(&raw));
            c.post(format!("{url}{path}"))
                .bearer_auth(token)
                .header("content-type", "application/json")
                .body(raw)
                .send()
        };
        let included = j!({"memory": {"apiKey": "vck-cc-included-abcdefgh12"}});
        assert_eq!(post("/llm/apply", "llm", included).await.expect("send").status(), 400);
        let own =
            j!({"memory": {"apiKey": "vck-cc-0123456789abcdef01234567", "baseUrl": "https://ai-gateway.vercel.sh/v1"}});
        assert_eq!(post("/llm/apply", "llm", own).await.expect("send").status(), 200);
        let call = runner
            .calls()
            .into_iter()
            .find(|c| c.args.iter().any(|a| a.ends_with("cc-gbrain-key")))
            .expect("helper");
        assert_eq!(
            call.stdin.as_deref(),
            Some(&b"vck-cc-0123456789abcdef01234567 https://ai-gateway.vercel.sh/v1\n"[..])
        );

        // GBrain's admin page: only behind the pages' sign-in, never with a firewall token alone.
        let r = c.get(format!("{url}/admin")).send().await.expect("send");
        assert_eq!(r.status(), 401);
        let t = keys.firewall_token("gbrain", "GET", "/admin/api/stats", None);
        let r = c
            .get(format!("{url}/admin/api/stats"))
            .bearer_auth(t)
            .send()
            .await
            .expect("send");
        assert_eq!(r.status(), 401);

        // Agents come through the firewall's relay (part B): its bound token, purpose `gbrain-mcp`.
        let r = c
            .post(format!("{url}/gbrain/mcp/agent_1"))
            .body("{}")
            .send()
            .await
            .expect("send");
        assert_eq!(r.status(), 401, "no token: refused");
        let raw = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let t = keys.firewall_token("gbrain-mcp", "POST", "/gbrain/mcp/agent_1", Some(raw));
        let r = c
            .post(format!("{url}/gbrain/mcp/agent_1"))
            .bearer_auth(t)
            .header("content-type", "application/json")
            .body(&raw[..])
            .send()
            .await
            .expect("send");
        assert_eq!(
            r.status(),
            403,
            "the firewall's token, but an agent this brain was never told of"
        );
    }

    #[test]
    fn the_identity_files() {
        let d = tempfile::tempdir().expect("dir");
        let raw = format!(
            r#"{{"mode":"brain","agent_id":"agent_1","state_dir":"{}","gbrain":{{"panel_url":"http://localhost:8800/brain","name":"brain-b","pages_name":"brain.example.com"}}}}"#,
            d.path().display()
        );
        brain(&raw).write_identity().expect("write");
        let read = |n: &str| std::fs::read_to_string(d.path().join(n)).expect(n);
        // The pages' name, which the firewall's relay serves them under, before the brain's own name.
        assert_eq!(read("vm_hostname"), "brain.example.com\n");
        assert_eq!(read("vm_id"), "agent_1\n");
        assert_eq!(read("config_api_url"), "http://localhost:8800/api\n");
        // The pages' "Back" is that origin and the panel's Brain page (`access(app, Some("/brain"))`).
    }
}
