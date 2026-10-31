//! Runs one case against one build: a fresh folder, the agent started as a process with the same
//! environment the systemd unit gives it, the steps, then the agent stopped.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use cc_testkit::{BoxKeys, FakeConsole};
use serde_json::{Map, Value, json};
use sha2::Digest;

use crate::case::{Agent, Case, Listener, Signer, Step, Ticket, Token};
use crate::matcher::diff;
use crate::shim;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Ts,
    Rust,
}

impl Target {
    pub fn name(self) -> &'static str {
        match self {
            Target::Ts => "ts",
            Target::Rust => "rust",
        }
    }
}

/// Where the two builds of each agent are.
pub struct Builds {
    pub repo: PathBuf,
    pub rust_bin_dir: PathBuf,
    pub node: String,
}

impl Builds {
    fn command(&self, target: Target, agent: Agent, service: &str) -> (String, Vec<String>) {
        match (target, agent) {
            // A brain box runs the bundle's other entry; the Rust binary picks by CC_SERVICE.
            (Target::Ts, Agent::VmAgent) => {
                let entry = if service == "gbrain" { "gbrain.js" } else { "index.js" };
                (
                    self.node.clone(),
                    vec![
                        self.repo
                            .join("packages/vm-agent/dist")
                            .join(entry)
                            .display()
                            .to_string(),
                    ],
                )
            }
            (Target::Ts, Agent::MitmAgent) => (
                self.node.clone(),
                vec![
                    self.repo
                        .join("packages/mitm-agent/dist/index.js")
                        .display()
                        .to_string(),
                ],
            ),
            (Target::Rust, Agent::VmAgent) => (self.rust_bin_dir.join("vm-agent").display().to_string(), vec![]),
            (Target::Rust, Agent::MitmAgent) => (self.rust_bin_dir.join("mitm-agent").display().to_string(), vec![]),
        }
    }
}

fn tail(log: &str) -> String {
    let lines: Vec<&str> = log.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

async fn wait_port(port: u16, child: &mut tokio::process::Child, within: Duration) -> Result<()> {
    let until = Instant::now() + within;
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("the agent exited before listening ({status})");
        }
        if Instant::now() > until {
            bail!("nothing listened on {port} within {within:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

struct Running {
    child: tokio::process::Child,
    launch: Launch,
    wait_for: Vec<u16>,
    root: PathBuf,
    keys: BoxKeys,
    ports: HashMap<Listener, u16>,
    named: HashMap<String, u16>,
    console: Option<FakeConsole>,
    agent: Option<crate::fake_agent::FakeAgent>,
    target: Target,
    /// The case file's folder (`body_file`).
    dir: PathBuf,
}

impl Running {
    /// Every helper call so far: its command line and what it was given on stdin.
    fn calls(&self) -> Vec<(Vec<String>, String)> {
        let raw = std::fs::read_to_string(self.root.join("shim-log.jsonl")).unwrap_or_default();
        raw.lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter_map(|v| {
                let argv = serde_json::from_value(v["argv"].clone()).ok()?;
                Some((argv, v["stdin"].as_str().unwrap_or_default().to_string()))
            })
            .collect()
    }

    /// Stop the agent and start it again on the same folder (its state files survive, its memory
    /// does not).
    async fn restart(&mut self) -> Result<()> {
        self.child.kill().await.context("stop the agent")?;
        // Gone for certain before the new one starts: its ports closed, so the wait below cannot
        // be answered by the old process.
        for p in &self.wait_for {
            let until = Instant::now() + Duration::from_secs(10);
            while tokio::net::TcpStream::connect(("127.0.0.1", *p)).await.is_ok() {
                if Instant::now() > until {
                    bail!("port {p} still open after the agent stopped");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
        self.child = self.launch.spawn(&self.wait_for).await?;
        Ok(())
    }
}

async fn start(case: &Case, target: Target, builds: &Builds, root: &Path) -> Result<Running> {
    let case_dir = case.dir.clone();
    let (vm_id, host) = match case.agent {
        Agent::VmAgent => ("vm_1", "box.example"),
        Agent::MitmAgent => ("fw_1", "fw.example"),
    };
    let keys = BoxKeys::write(&root.join("keys"), vm_id, host)?;
    for d in ["state", "home", "run"] {
        std::fs::create_dir_all(root.join(d))?;
    }
    if case.pool {
        std::fs::write(root.join("pool-unclaimed"), "")?;
    }
    for (rel, content) in &case.files {
        let p = root.join(rel);
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, content)?;
    }
    // The helpers: links to this binary, first on the PATH.
    let shim_dir = root.join("shim");
    std::fs::create_dir_all(&shim_dir)?;
    let me = std::env::current_exe()?;
    for p in shim::PROGRAMS {
        std::os::unix::fs::symlink(&me, shim_dir.join(p))?;
    }
    let mut rules = case.shims.clone();
    rules.extend(shim::default_rules());
    std::fs::write(root.join("shim-rules.json"), serde_json::to_vec(&rules)?)?;

    let (program, args) = builds.command(target, case.agent, &case.service);
    let mut cmd = Launch {
        program: program.clone(),
        args,
        root: root.to_path_buf(),
        env: Vec::new(),
    };
    cmd.env("PATH", format!("{}:/usr/local/bin:/usr/bin:/bin", shim_dir.display()))
        .env("HOME", root.join("home"))
        .env("CC_SHIM_RULES", root.join("shim-rules.json"))
        .env("CC_SHIM_LOG", root.join("shim-log.jsonl"))
        .env("KEYS_DIR", root.join("keys"))
        .env("STATE_DIR", root.join("state"))
        .env("CC_POOL_MARKER", root.join("pool-unclaimed"))
        .env("CC_LOG", "info");
    let mut ports = HashMap::new();
    let main = free_port()?;
    ports.insert(Listener::Main, main);
    ports.insert(Listener::Tls, main);
    cmd.env("AGENT_PORT", main.to_string());
    let mut console = None;
    match case.agent {
        Agent::VmAgent => {
            cmd.env("AGENT_BIND", "127.0.0.1")
                .env("CC_SERVICE", &case.service)
                .env("CONNECTOR_RELAY_PORT", free_port()?.to_string())
                .env("OPENCLAW_GATEWAY_PORT", free_port()?.to_string());
        }
        Agent::MitmAgent => {
            let fake = FakeConsole::start().await?;
            for (path, answers) in &case.console {
                fake.answer(path, answers.clone());
            }
            let ingress = free_port()?;
            ports.insert(Listener::Ingress, ingress);
            // The page assets: next to the binary in the Docker rig, as on a box (the release ships
            // them there); here the debug binary has none, so the ones the TS build was made from.
            if target == Target::Rust && !builds.rust_bin_dir.join("dist-ui").is_dir() {
                cmd.env("CC_FW_UI_DIR", builds.repo.join("packages/mitm-agent/dist-ui"));
            }
            cmd.env("ORG_ID", "org_1")
                .env("BOX_ID", "fw_1")
                .env("BOX_KEY_PATH", root.join("keys/box_key"))
                .env("PROXY_CONFIG_DIR", root.join("run"))
                .env("INGRESS_PORT", ingress.to_string())
                .env("INGRESS_BIND", "127.0.0.1")
                .env("FIREWALL_URL", fake.url("/api/vm-agent/firewall"))
                .env("STORE_URL", fake.url("/api/vm-agent/store"))
                .env("RULES_URL", fake.url("/api/vm-agent/egress-rules"))
                .env("IDENTITIES_URL", fake.url("/api/vm-agent/identities"))
                .env("PERMISSION_URL", fake.url("/api/vm-agent/permission"))
                .env("CA_URL", fake.url("/api/vm-agent/ca"))
                .env("ACTIVITY_URL", fake.url("/api/vm-agent/activity"))
                .env("WEBHOOKS_URL", fake.url("/api/vm-agent/webhooks"))
                .env("TRAFFIC_LOG_PATH", root.join("run/traffic.jsonl"))
                .env("FIREWALL_POLL_MS", "200")
                .env("AI_JUDGE_PORT", "0");
            console = Some(fake);
        }
    }
    let mut agent = None;
    if let Some(answers) = &case.fake_agent {
        let (cert, key) = crate::fake_agent::cert_for_run(root)?;
        cmd.env("NODE_EXTRA_CA_CERTS", root.join("agent-ca.pem"));
        let a = crate::fake_agent::FakeAgent::start(&cert, &key).await?;
        for (path, list) in answers {
            a.answer(path, list.clone());
        }
        agent = Some(a);
    }
    let mut named = HashMap::new();
    for (name, var) in &case.ports {
        let p = free_port()?;
        cmd.env(var, p.to_string());
        named.insert(name.clone(), p);
    }
    for (k, v) in &case.env {
        // `$PORT_<NAME>`: a named port, in a setting that takes an address (`127.0.0.1:$PORT_PANEL`).
        let mut ports: Vec<(&String, &u16)> = named.iter().collect();
        ports.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        let v = ports
            .into_iter()
            .fold(v.replace("$ROOT", &root.display().to_string()), |v, (name, p)| {
                v.replace(&format!("$PORT_{}", name.to_uppercase()), &p.to_string())
            });
        cmd.env(k, v);
    }
    // An unclaimed firewall opens nothing but its loopback health.
    let wait_for: Vec<u16> = std::iter::once(main)
        .chain(ports.get(&Listener::Ingress).copied().filter(|_| !case.pool))
        .collect();
    let child = cmd.spawn(&wait_for).await?;
    Ok(Running {
        child,
        launch: cmd,
        wait_for,
        root: root.to_path_buf(),
        keys,
        ports,
        named,
        console,
        agent,
        target,
        dir: case_dir,
    })
}

/// How the agent was started, so a `restart` step starts it again the same way on the same folder.
struct Launch {
    program: String,
    args: Vec<String>,
    root: PathBuf,
    env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
}

impl Launch {
    fn env(&mut self, k: impl AsRef<std::ffi::OsStr>, v: impl AsRef<std::ffi::OsStr>) -> &mut Self {
        self.env.push((k.as_ref().to_owned(), v.as_ref().to_owned()));
        self
    }

    async fn spawn(&self, wait_for: &[u16]) -> Result<tokio::process::Child> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("agent.log"))?;
        let mut cmd = tokio::process::Command::new(&self.program);
        cmd.args(&self.args)
            .current_dir(&self.root)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            // The helpers the agent runs inherit this: an empty stdin, so the shim's read ends.
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .kill_on_drop(true);
        let mut child = cmd.spawn().with_context(|| format!("start {}", self.program))?;
        for p in wait_for {
            wait_port(*p, &mut child, Duration::from_secs(20)).await?;
        }
        Ok(child)
    }
}

fn token(
    t: &Token,
    r: &Running,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    sent: &HashMap<String, String>,
) -> Result<String> {
    if let Some(name) = &t.reuse {
        return sent
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("no token was sent by step {name}"));
    }
    let mut claims: Map<String, Value> = Map::new();
    if t.signer == Signer::Session {
        // The box's own browser cookies: `{sub: vmId, …}`, HS256 with its session secret.
        claims.insert("sub".into(), json!(r.keys.vm_id));
        claims.extend(t.claims.clone());
        let hex_secret = std::fs::read_to_string(r.root.join("keys/session_secret")).context("keys/session_secret")?;
        let secret = hex::decode(hex_secret.trim()).context("session_secret is not hex")?;
        let iat = (t.iat_offset != 0).then(|| cc_auth::jwt::now_s() + t.iat_offset);
        return Ok(cc_auth::jwt::sign(
            claims,
            &cc_auth::jwt::SignKey::Hs256(secret),
            Some(t.lifetime),
            iat,
        )?);
    }
    claims.insert("vmId".into(), json!(r.keys.vm_id));
    let signer = match t.signer {
        Signer::Session => unreachable!("signed above"),
        Signer::Console => cc_testkit::Signer::Console,
        Signer::Box => cc_testkit::Signer::Box,
        Signer::Firewall => {
            claims.insert("iss".into(), json!("fw_test"));
            if t.bind {
                // `body` signs a different body than the one sent (the body-mismatch case).
                let signed = t.body.as_ref().map(serde_json::to_vec).transpose()?;
                let body = signed.as_deref().or(body);
                claims.extend(cc_auth::sign::binding_claims(
                    method,
                    path,
                    Some(&r.keys.hostname),
                    body,
                ));
            }
            cc_testkit::Signer::Firewall
        }
    };
    claims.extend(t.claims.clone());
    let iat = (t.iat_offset != 0).then(|| cc_auth::jwt::now_s() + t.iat_offset);
    Ok(r.keys
        .sign_with_at(signer, Value::Object(claims), Some(t.lifetime), iat))
}

/// A firewall sign-in ticket for this box (`verifyFirewallTicket`): its `c` is the hash of the
/// newest bind cookie in the jar unless the case names one.
fn ticket(t: &Ticket, r: &Running, jar: &[(String, String)], sent: &HashMap<String, String>) -> Result<String> {
    if let Some(name) = &t.reuse {
        return sent
            .get(&format!("ticket:{name}"))
            .cloned()
            .ok_or_else(|| anyhow!("no ticket was sent by step {name}"));
    }
    let mut claims: Map<String, Value> = Map::new();
    claims.insert("vmId".into(), json!(r.keys.vm_id));
    claims.insert("purpose".into(), json!(t.purpose));
    claims.insert("iss".into(), json!("fw:fw_test"));
    claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    claims.insert("deviceId".into(), json!("dev_1"));
    if let Some((_, value)) = jar.iter().rev().find(|(n, _)| n.starts_with("__Host-cc_bind_")) {
        use base64::Engine;
        let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(value.as_bytes()));
        claims.insert("c".into(), json!(c));
    }
    claims.extend(t.claims.clone());
    Ok(r.keys
        .sign_with(cc_testkit::Signer::Firewall, Value::Object(claims), Some(t.lifetime)))
}

/// `*` matches any run of characters; the rest is literal.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || !text[first.len()..].ends_with(last) || text.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

/// A string `$<name>` in a JSON body: a value an earlier step kept.
fn kept_into(v: &mut Value, sent: &HashMap<String, String>) {
    match v {
        Value::String(s) => {
            if let Some(k) = s.strip_prefix('$').and_then(|n| sent.get(&format!("keep:{n}"))) {
                *s = k.clone();
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| kept_into(x, sent)),
        Value::Object(o) => o.values_mut().for_each(|x| kept_into(x, sent)),
        _ => {}
    }
}

/// Set up a standalone firewall's admin: the setup token from the agent's log, `POST /api/setup`.
async fn panel_login(
    name: &str,
    r: &Running,
    client: &reqwest::Client,
    sent: &mut HashMap<String, String>,
    jar: &mut Vec<(String, String)>,
) -> Result<()> {
    let port = *r
        .named
        .get(name)
        .ok_or_else(|| anyhow!("the case has no port {name}"))?;
    let until = Instant::now() + Duration::from_secs(10);
    let token = loop {
        let log = std::fs::read_to_string(r.root.join("agent.log")).unwrap_or_default();
        let found = log
            .lines()
            .rev()
            .find_map(|l| l.split("setup token (POST /api/setup): ").nth(1))
            .map(|t| t.chars().take_while(char::is_ascii_hexdigit).collect::<String>());
        if let Some(t) = found.filter(|t| !t.is_empty())
            && tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        {
            break t;
        }
        if Instant::now() > until {
            bail!("no setup token in the agent's log, or nothing on port {name} ({port})");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    let res = client
        .post(format!("http://127.0.0.1:{port}/api/setup"))
        .json(&json!({"token": token, "password": "a conformance password"}))
        .send()
        .await?;
    for c in res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        update_jar(jar, c, false);
    }
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    let csrf = body["csrf"]
        .as_str()
        .ok_or_else(|| anyhow!("setup answered {status}: {body}"))?;
    sent.insert("csrf".into(), csrf.to_string());
    Ok(())
}

/// `$<name>` in a header's value: a value an earlier step kept, longest name first.
fn with_kept(v: &str, sent: &HashMap<String, String>) -> String {
    let mut kept: Vec<(&String, &String)> = sent.iter().filter(|(k, _)| k.starts_with("keep:")).collect();
    kept.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    kept.into_iter()
        .fold(v.to_string(), |v, (k, x)| v.replace(&format!("${}", &k[5..]), x))
}

/// The value an answer's `Set-Cookie` gave the cookie `name`.
fn set_cookie_value(set_cookies: &[String], name: &str) -> Option<String> {
    set_cookies.iter().find_map(|c| {
        let (n, v) = c.split(';').next()?.split_once('=')?;
        (n.trim() == name).then(|| v.trim().to_string())
    })
}

/// A browser's jar, roughly: name to value, a `Max-Age=0` removes it. Paths and flags are not
/// modelled; cases name the cookies they send.
fn update_jar(jar: &mut Vec<(String, String)>, set_cookie: &str, keep_cleared: bool) {
    let first = set_cookie.split(';').next().unwrap_or_default();
    let Some((name, value)) = first.split_once('=') else {
        return;
    };
    let (name, value) = (name.trim().to_string(), value.trim().to_string());
    let gone = set_cookie
        .split(';')
        .any(|a| a.trim().eq_ignore_ascii_case("max-age=0"));
    if gone && keep_cleared {
        return;
    }
    jar.retain(|(n, _)| *n != name);
    if !gone {
        jar.push((name, value));
    }
}

/// The system-wide marker the TS agents read, which only the Docker rig may create.
const SYSTEM_POOL_MARKER: &str = "/etc/controlclaw/pool-unclaimed";
/// Where a case's `system_bins` go, in the Docker rig only.
const SYSTEM_BIN_DIR: &str = "/usr/local/bin";

/// A `system_bins` name: a plain file name, so a case cannot write anywhere else.
fn system_bin_path(name: &str) -> Result<PathBuf> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(anyhow!("system_bins: {name:?} is not a file name"));
    }
    Ok(Path::new(SYSTEM_BIN_DIR).join(name))
}

/// What a case put in system paths for its run, removed when it is dropped (also on a panic).
#[derive(Default)]
struct SystemFiles(Vec<PathBuf>);

impl SystemFiles {
    /// A new file at `path` with `content` and `mode`. `create_new` refuses one that exists, a
    /// symlink included, in the same call that creates it; the path is recorded before anything is
    /// written, so a write that fails halfway is removed too.
    fn create(&mut self, path: PathBuf, content: &str, mode: u32) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .with_context(|| format!("{}", path.display()))?;
        self.0.push(path);
        f.write_all(content.as_bytes())?;
        Ok(())
    }
}

impl Drop for SystemFiles {
    fn drop(&mut self) {
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub enum Outcome {
    Pass,
    Skip(String),
}

/// Run the case on one build. `Ok(Pass)` is a pass; the error says what differed.
pub async fn run(case: &Case, target: Target, builds: &Builds) -> Result<Outcome> {
    let in_rig = std::env::var_os("CC_RIG_SYSTEM_PATHS").is_some();
    if (case.pool || !case.system_bins.is_empty()) && target == Target::Ts && !in_rig {
        return Ok(Outcome::Skip("needs the Docker rig".into()));
    }
    // The TS agents keep stores under /opt/controlclaw/state by default; in the rig that folder
    // would carry over from the last case, sealed under another box key.
    if in_rig {
        let _ = std::fs::remove_dir_all("/opt/controlclaw/state");
    }
    let mut system = SystemFiles::default();
    if case.pool && in_rig {
        std::fs::create_dir_all("/etc/controlclaw")?;
        let _ = std::fs::remove_file(SYSTEM_POOL_MARKER);
        system.create(SYSTEM_POOL_MARKER.into(), "", 0o644)?;
    }
    // For the TS build only: the Rust build takes its helpers' paths from the case's env, and
    // helpers at the default paths would hide a missing env line.
    if in_rig && target == Target::Ts {
        for (name, content) in &case.system_bins {
            system.create(system_bin_path(name)?, content, 0o755)?;
        }
    }
    let result = run_in(case, target, builds).await;
    drop(system);
    result.map(|()| Outcome::Pass)
}

async fn run_in(case: &Case, target: Target, builds: &Builds) -> Result<()> {
    let mut root = tempfile::tempdir()?;
    let mut started = start(case, target, builds, root.path()).await;
    // The ports are picked free, then released for the agent to bind; the agent's own listeners on
    // port 0 can take one in between. One more start, on new ports, for that alone.
    if started.is_err()
        && std::fs::read_to_string(root.path().join("agent.log")).is_ok_and(|l| l.contains("Address already in use"))
    {
        root = tempfile::tempdir()?;
        started = start(case, target, builds, root.path()).await;
    }
    let mut r = match started {
        Ok(r) => r,
        Err(e) => {
            let log = std::fs::read_to_string(root.path().join("agent.log")).unwrap_or_default();
            return Err(anyhow!("{e:#}\n--- agent log ---\n{}", tail(&log)));
        }
    };
    let result = steps(case, &mut r).await;
    let _ = r.child.kill().await;
    result.map_err(|e| {
        anyhow!(
            "{e:#}\n--- agent log ---\n{}",
            tail(&std::fs::read_to_string(r.root.join("agent.log")).unwrap_or_default())
        )
    })
}

async fn steps(case: &Case, r: &mut Running) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut sent: HashMap<String, String> = HashMap::new();
    let mut jar: Vec<(String, String)> = Vec::new();
    for (i, step) in case.steps.iter().enumerate() {
        let label = step.name.clone().unwrap_or_else(|| format!("step {}", i + 1));
        run_step(step, &label, r, &client, &mut sent, &mut jar)
            .await
            .with_context(|| label.clone())?;
    }
    Ok(())
}

async fn run_step(
    step: &Step,
    label: &str,
    r: &mut Running,
    client: &reqwest::Client,
    sent: &mut HashMap<String, String>,
    jar: &mut Vec<(String, String)>,
) -> Result<()> {
    if step.restart {
        r.restart().await?;
    }
    for rel in &step.remove {
        let p = r.root.join(rel);
        std::fs::remove_file(&p).with_context(|| format!("remove {}", p.display()))?;
    }
    for (rel, content) in &step.write {
        let p = r.root.join(rel);
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&p, content).with_context(|| format!("write {}", p.display()))?;
    }
    if !step.agent_answers.is_empty() {
        let agent = r
            .agent
            .as_ref()
            .ok_or_else(|| anyhow!("agent answers need fake_agent on the case"))?;
        for (path, answers) in &step.agent_answers {
            agent.answer(path, answers.clone());
        }
    }
    if !step.console.is_empty() {
        let console = r
            .console
            .as_ref()
            .ok_or_else(|| anyhow!("console answers need the firewall agent"))?;
        for (path, answers) in &step.console {
            console.answer(path, answers.clone());
        }
    }
    if let Some(c) = &step.command {
        let console = r
            .console
            .as_ref()
            .ok_or_else(|| anyhow!("commands need the firewall agent"))?;
        console.queue_command(&c.id, &c.action, c.payload.clone());
        if let Some(want) = &c.result {
            let until = Instant::now() + Duration::from_millis(c.within_ms);
            loop {
                let found = console
                    .received()
                    .into_iter()
                    .filter_map(|x| x.body.get("results").and_then(Value::as_array).cloned())
                    .flatten()
                    .find(|res| res["command_id"] == c.id.as_str());
                if let Some(res) = found {
                    if let Some(d) = diff(want, &res, true, "$result") {
                        bail!("{d}");
                    }
                    break;
                }
                if Instant::now() > until {
                    bail!("no result for command {} within {} ms", c.id, c.within_ms);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    if let Some(b) = &step.beat {
        let console = r
            .console
            .as_ref()
            .ok_or_else(|| anyhow!("beats need the firewall agent"))?;
        let until = Instant::now() + Duration::from_millis(b.within_ms);
        // The newest beat must match: waited for, so a field that changes after a command can
        // still arrive, but an older beat that happened to match does not count.
        loop {
            let latest = console
                .received()
                .into_iter()
                .rev()
                .find(|x| x.path == "/api/vm-agent/firewall")
                .map(|x| x.body);
            let problem = match &latest {
                Some(beat) => diff(&b.json_subset, beat, true, "$beat"),
                None => Some(format!("no beat within {} ms", b.within_ms)),
            };
            let Some(problem) = problem else { break };
            if Instant::now() > until {
                bail!("{problem}");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    if let Some(name) = &step.panel_login {
        panel_login(name, r, client, sent, jar).await?;
    }
    let Some(req) = &step.request else {
        return after(step, r).await;
    };
    let port = match &req.port {
        Some(name) => {
            let p = *r
                .named
                .get(name)
                .ok_or_else(|| anyhow!("the case has no port {name}"))?;
            // A listener the agent opens after its main ones: wait for it.
            let until = Instant::now() + Duration::from_secs(10);
            while tokio::net::TcpStream::connect(("127.0.0.1", p)).await.is_err() {
                if Instant::now() > until {
                    bail!("nothing listened on port {name} ({p})");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            p
        }
        None => match req.listener {
            Listener::Port(p) => {
                let until = Instant::now() + Duration::from_secs(15);
                while tokio::net::TcpStream::connect(("127.0.0.1", p)).await.is_err() {
                    if Instant::now() > until {
                        bail!("nothing listened on {p}");
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                p
            }
            l => *r
                .ports
                .get(&l)
                .ok_or_else(|| anyhow!("this agent has no {l:?} listener"))?,
        },
    };
    let scheme = if req.listener == Listener::Tls { "https" } else { "http" };
    let mut json_body = req.json.clone();
    if let Some(t) = &req.ticket {
        let tk = ticket(t, r, jar, sent)?;
        sent.insert(format!("ticket:{label}"), tk.clone());
        json_body = Some(match json_body {
            None => json!({"token": tk}),
            Some(v) => replace_ticket(v, &tk),
        });
    }
    if let Some(v) = json_body.as_mut() {
        kept_into(v, sent);
    }
    let body = json_body.as_ref().map(serde_json::to_vec).transpose()?;
    let method: reqwest::Method = req.method.parse()?;
    // `$<name>`: a value an earlier step kept.
    let mut path = req.path.clone();
    // Longest name first, so `$keys` is never read as `$key` and an `s`.
    let mut kept: Vec<(&String, &String)> = sent.iter().filter(|(k, _)| k.starts_with("keep:")).collect();
    kept.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));
    for (k, v) in kept {
        path = path.replace(&format!("${}", &k[5..]), v);
    }
    let mut query_token = None;
    if let Some(t) = req.token.as_ref().filter(|t| t.query.is_some()) {
        let tok = token(t, r, &req.method, &req.path, body.as_deref(), sent)?;
        sent.insert(label.to_string(), tok.clone());
        let sep = if path.contains('?') { '&' } else { '?' };
        path = format!("{path}{sep}{}={tok}", t.query.as_deref().unwrap_or_default());
        query_token = Some(tok);
    }
    let mut b = client.request(method, format!("{scheme}://127.0.0.1:{port}{path}"));
    // One Cookie header, as a browser sends it: the jar, a token sent as a cookie, then the step's own.
    let mut cookies: Vec<String> = Vec::new();
    if req.jar {
        cookies.extend(jar.iter().map(|(n, v)| format!("{n}={v}")));
    }
    for (k, v) in &req.headers {
        if !k.eq_ignore_ascii_case("cookie") {
            let v = match v.as_str() {
                "$csrf" => sent
                    .get("csrf")
                    .cloned()
                    .ok_or_else(|| anyhow!("$csrf before a panel_login step"))?,
                _ => with_kept(v, sent),
            };
            b = b.header(k, v);
        }
    }
    if let Some(t) = req.token.as_ref().filter(|_| query_token.is_none()) {
        let tok = token(t, r, &req.method, &req.path, body.as_deref(), sent)?;
        sent.insert(label.to_string(), tok.clone());
        match &t.cookie {
            Some(name) => cookies.push(format!("{name}={tok}")),
            None => b = b.bearer_auth(tok),
        }
    }
    cookies.extend(
        req.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| with_kept(v, sent)),
    );
    if !cookies.is_empty() {
        b = b.header("cookie", cookies.join("; "));
    }
    if let Some(body) = body {
        b = b.header("content-type", "application/json").body(body);
    } else if let Some(raw) = &req.body {
        b = b.body(raw.clone());
    }
    if let Some(rc) = &req.recovery {
        let framed =
            cc_crypto::recovery::encode_recovery_body(&rc.head, rc.tail.as_bytes()).map_err(|e| anyhow!("{}", e.0))?;
        let digest = cc_crypto::recovery::recovery_body_digest(&framed);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64
            + rc.timestamp_offset_ms;
        let sig = cc_crypto::recovery::sign_recovery_request(&rc.secret, &req.method, &req.path, ts as f64, &digest)
            .map_err(|e| anyhow!("{}", e.0))?;
        b = b
            .header("x-cc-recovery-signature", sig)
            .header("x-cc-recovery-timestamp", ts.to_string())
            .header("content-type", "application/octet-stream")
            .body(framed);
    }
    let res = b.send().await?;
    let status = res.status().as_u16();
    let headers = res.headers().clone();
    let text = match &req.read_until {
        None => res.text().await?,
        Some(until) => {
            let mut res = res;
            let mut got = String::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !got.contains(until.as_str()) {
                let left = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(left, res.chunk()).await {
                    Ok(Ok(Some(c))) => got.push_str(&String::from_utf8_lossy(&c)),
                    Ok(Ok(None)) => break,
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => bail!("{until:?} did not arrive within 10 s; got {got:?}"),
                }
            }
            got
        }
    };
    let set_cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    for c in &set_cookies {
        update_jar(jar, c, req.keep_jar);
    }
    if !step.keep.is_empty() {
        let got: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        for (name, at) in &step.keep {
            if let Some(cookie) = at.strip_prefix("set-cookie:") {
                let v = set_cookie_value(&set_cookies, cookie)
                    .ok_or_else(|| anyhow!("keep {name}: the answer set no cookie {cookie}"))?;
                sent.insert(format!("keep:{name}"), v);
                continue;
            }
            let v = at
                .split('.')
                .try_fold(&got, |v, k| match k.parse::<usize>() {
                    Ok(i) => v.get(i),
                    Err(_) => v.get(k),
                })
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("keep {name}: no string at {at} in {text}"))?;
            sent.insert(format!("keep:{name}"), v.to_string());
        }
    }
    let Some(e) = &step.expect else {
        return after(step, r).await;
    };
    if let Some(s) = e.status
        && s != status
    {
        bail!("status: wanted {s}, got {status} ({text})");
    }
    for (k, v) in &e.headers {
        let got = headers.get(k).and_then(|h| h.to_str().ok());
        match (v.as_str(), got) {
            ("$absent", None) => {}
            ("$absent", Some(g)) => bail!("header {k}: should be absent, got {g}"),
            (w, Some(g)) if w == g => {}
            (w, g) => bail!("header {k}: wanted {w}, got {g:?}"),
        }
    }
    if let Some(want) = &e.body
        && *want != text
    {
        bail!("body: wanted {want:?}, got {text:?}");
    }
    if let Some(file) = &e.body_file {
        let path = r.dir.join(file);
        if r.target == Target::Ts && std::env::var_os("CC_WRITE_GOLDEN").is_some() {
            std::fs::write(&path, &text)?;
        } else {
            let want = std::fs::read_to_string(&path).with_context(|| format!("{}", path.display()))?;
            if want != text {
                let at = want.chars().zip(text.chars()).take_while(|(a, b)| a == b).count();
                let near = |s: &str| s.chars().skip(at.saturating_sub(40)).take(120).collect::<String>();
                bail!(
                    "body differs from {file} at character {at}:\n  wanted …{}…\n  got    …{}…",
                    near(&want),
                    near(&text)
                );
            }
        }
    }
    for want in &e.body_contains {
        if !text.contains(want.as_str()) {
            bail!(
                "body does not contain {want:?}: {}",
                text.chars().take(400).collect::<String>()
            );
        }
    }
    if let Some(patterns) = &e.set_cookies {
        if patterns.len() != set_cookies.len() {
            bail!("set-cookie: wanted {patterns:?}, got {set_cookies:?}");
        }
        let mut left: Vec<&String> = set_cookies.iter().collect();
        for p in patterns {
            match left.iter().position(|c| glob(p, c)) {
                Some(i) => {
                    left.remove(i);
                }
                None => bail!("set-cookie: no line matches {p:?}; got {set_cookies:?}"),
            }
        }
    }
    if e.json.is_some() || e.json_subset.is_some() || !e.absent.is_empty() {
        let got: Value = serde_json::from_str(&text).with_context(|| format!("body is not JSON: {text:?}"))?;
        if let Some(w) = &e.json
            && let Some(d) = diff(w, &got, false, "$")
        {
            bail!("{d}");
        }
        if let Some(w) = &e.json_subset
            && let Some(d) = diff(w, &got, true, "$")
        {
            bail!("{d}");
        }
        for k in &e.absent {
            if got.get(k).is_some() {
                bail!("$.{k}: should be absent");
            }
        }
    }
    if !e.calls_include.is_empty() {
        let calls = r.calls();
        for want in &e.calls_include {
            let (argv, stdin) = want.parts();
            let hit = calls.iter().any(|(c, got_stdin)| {
                c.len() >= argv.len() && c.iter().zip(argv).all(|(a, b)| a == b) && stdin.is_none_or(|s| s == got_stdin)
            });
            if !hit {
                bail!("no helper call {want:?}; calls were {calls:?}");
            }
        }
    }
    after(step, r).await
}

/// The step's files and console requests, waited for.
async fn after(step: &Step, r: &Running) -> Result<()> {
    for (rel, want) in &step.files {
        let path = r.root.join(rel);
        let until = Instant::now() + Duration::from_millis(want.within_ms);
        let mut matched: Option<Instant> = None;
        loop {
            let got = std::fs::read_to_string(&path).ok();
            let problem = match (&got, want) {
                (None, w) if w.absent => None,
                (Some(_), w) if w.absent => Some(format!("{rel}: should not exist")),
                (None, _) => Some(format!("{rel}: not written")),
                (Some(text), w) => {
                    if let Some(t) = &w.text
                        && t != text
                    {
                        Some(format!("{rel}: wanted {t:?}, got {text:?}"))
                    } else if let Some(j) = &w.json {
                        match serde_json::from_str::<Value>(text) {
                            Ok(v) => diff(j, &v, false, rel),
                            Err(_) => Some(format!("{rel}: not JSON: {text:?}")),
                        }
                    } else {
                        None
                    }
                }
            };
            match problem {
                None if matched.is_none() => matched = Some(Instant::now()),
                None => {}
                Some(p) if matched.is_some() => bail!("{p} (after it matched)"),
                Some(p) if Instant::now() > until => bail!("{p}"),
                Some(_) => {}
            }
            if matched.is_some_and(|m| m.elapsed() >= Duration::from_millis(want.for_ms)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    for want in &step.agent_received {
        let agent = r
            .agent
            .as_ref()
            .ok_or_else(|| anyhow!("agent_received needs fake_agent on the case"))?;
        let until = Instant::now() + Duration::from_millis(want.within_ms);
        loop {
            let mut last = None;
            let hit = agent.received().into_iter().any(|x| {
                if x["path"] != want.path.as_str() || want.method.as_ref().is_some_and(|m| x["method"] != m.as_str()) {
                    return false;
                }
                match want.json_subset.as_ref().and_then(|j| diff(j, &x, true, &want.path)) {
                    Some(d) => {
                        last = Some(d);
                        false
                    }
                    None => true,
                }
            });
            if hit {
                break;
            }
            if Instant::now() > until {
                bail!(
                    "no agent call to {} matched: {}; calls were {:?}",
                    want.path,
                    last.unwrap_or_else(|| "none came".into()),
                    agent.received().iter().map(|x| x["path"].clone()).collect::<Vec<_>>()
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    for want in &step.received {
        let console = r
            .console
            .as_ref()
            .ok_or_else(|| anyhow!("received needs the firewall agent"))?;
        let until = Instant::now() + Duration::from_millis(want.within_ms);
        loop {
            let mut last = None;
            let hit = console.received().into_iter().any(|x| {
                if x.path != want.path || want.method.as_ref().is_some_and(|m| *m != x.method) {
                    return false;
                }
                match want
                    .json_subset
                    .as_ref()
                    .and_then(|j| diff(j, &x.body, true, &want.path))
                {
                    Some(d) => {
                        last = Some(d);
                        false
                    }
                    None => true,
                }
            });
            if hit {
                break;
            }
            if Instant::now() > until {
                bail!(
                    "no request to {} matched: {}",
                    want.path,
                    last.unwrap_or_else(|| "none came".into())
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    Ok(())
}

/// The string `$ticket` anywhere in a JSON body becomes the ticket.
fn replace_ticket(v: Value, ticket: &str) -> Value {
    match v {
        Value::String(s) if s == "$ticket" => Value::String(ticket.to_string()),
        Value::Array(a) => Value::Array(a.into_iter().map(|x| replace_ticket(x, ticket)).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, x)| (k, replace_ticket(x, ticket))).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("a=*; Path=/", "a=xyz; Path=/"));
        assert!(glob("*", ""));
        assert!(!glob("a=*; Path=/", "b=xyz; Path=/"));
        assert!(glob("a*b*c", "a1b2c"));
        assert!(!glob("ab*ba", "aba"));
    }

    #[test]
    fn kept_values_in_headers_and_cookies() {
        let sent: HashMap<String, String> = [("keep:sess", "s1"), ("keep:sess_b", "s2")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(with_kept("cc=$sess_b; x=$sess", &sent), "cc=s2; x=s1");
        let set = vec!["a=1; Path=/".to_string(), "cc_local_session=abc; HttpOnly".to_string()];
        assert_eq!(set_cookie_value(&set, "cc_local_session").as_deref(), Some("abc"));
        assert_eq!(set_cookie_value(&set, "b"), None);
    }

    #[test]
    fn jar() {
        let mut j = Vec::new();
        update_jar(&mut j, "a=1; Path=/", false);
        update_jar(&mut j, "b=2; Path=/", false);
        update_jar(&mut j, "b=; Path=/; Max-Age=0", true);
        update_jar(&mut j, "a=; Path=/; Max-Age=0", false);
        assert_eq!(j, vec![("b".to_string(), "2".to_string())]);
    }

    #[test]
    fn system_bins_are_file_names_only() {
        assert_eq!(
            system_bin_path("cc-doctor-run").expect("name"),
            Path::new("/usr/local/bin/cc-doctor-run")
        );
        for bad in ["", ".", "..", "../sbin/x", "a/b", "/etc/shadow"] {
            assert!(system_bin_path(bad).is_err(), "{bad:?}");
        }
    }
}
