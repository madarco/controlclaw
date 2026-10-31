//! Finding an OpenClaw that something else installed: its CLI, version, config and state, and what
//! keeps its gateway running. Everything is asked of the OpenClaw CLI, Docker or pm2; no private
//! file of OpenClaw's is read.

use std::path::{Path, PathBuf};
use std::time::Duration;

use cc_proc::{Cmd, Runner};
use serde::Serialize;
use serde_json::Value;

use super::config::OpenClawHints;

/// OpenClaw's default gateway port.
pub const DEFAULT_GATEWAY_PORT: u16 = 18789;
/// The unit `openclaw gateway install` writes.
pub const DEFAULT_UNIT: &str = "openclaw-gateway.service";
/// `openclaw gateway status --json` probes the gateway: a few seconds on a small box.
const STATUS_TIMEOUT: Duration = Duration::from_secs(30);
const QUICK: Duration = Duration::from_secs(10);
/// The wrapper the agent runs for every OpenClaw command, in its state dir: it calls the CLI
/// discovery found, or the one in the container. Rewritten on every discovery, so the services
/// built at start keep one path whatever discovery finds later.
pub const CLI_WRAPPER: &str = "openclaw";

/// What keeps the gateway running.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Runs {
    SystemdUser {
        unit: String,
    },
    SystemdSystem {
        unit: String,
    },
    Docker {
        container: String,
    },
    Pm2 {
        name: String,
    },
    /// Started by hand (`openclaw gateway run`) or by something we do not know.
    Process {
        pid: Option<u32>,
    },
    /// Installed, but no gateway runs and no service is set up.
    NotRunning,
    /// No OpenClaw CLI on this machine.
    NotFound,
}

/// What discovery found. Shown on `GET /status` as `install`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Install {
    /// The program the agent runs for every OpenClaw command (a wrapper for a container).
    pub cli: Option<String>,
    pub version: Option<String>,
    pub config_file: Option<String>,
    pub state_dir: Option<String>,
    /// A container's state folder as the container names it: what is read and written there goes
    /// through `docker exec` and `docker cp`, which resolve it inside the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_state_dir: Option<String>,
    pub runs: Runs,
    pub gateway_port: u16,
}

impl Install {
    pub fn not_found(port: u16) -> Self {
        Self {
            cli: None,
            version: None,
            config_file: None,
            state_dir: None,
            container_state_dir: None,
            runs: Runs::NotFound,
            gateway_port: port,
        }
    }
}

/// Where the official installers put the CLI, after `PATH`.
fn usual_places(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".openclaw/bin/openclaw"),
        home.join(".npm-global/bin/openclaw"),
        home.join(".local/bin/openclaw"),
        PathBuf::from("/usr/local/bin/openclaw"),
        PathBuf::from("/usr/bin/openclaw"),
    ]
}

fn on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(name))
        .find(|p| is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// The CLI on this machine: the hint, `$OPENCLAW_BIN`, `PATH`, then the installers' places.
pub fn find_cli(hint: Option<&str>, home: &Path) -> Option<String> {
    if let Some(h) = hint.filter(|h| !h.is_empty()) {
        return Some(h.to_string());
    }
    if let Some(b) = std::env::var("OPENCLAW_BIN").ok().filter(|b| !b.is_empty()) {
        return Some(b);
    }
    on_path("openclaw")
        .or_else(|| usual_places(home).into_iter().find(|p| is_executable(p)))
        .map(|p| p.to_string_lossy().into_owned())
}

/// The wrapper's path for this state dir.
pub fn wrapper_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CLI_WRAPPER)
}

/// `OpenClaw 2026.10.9 (8b18b55)` → `2026.10.9`.
pub fn parse_version(out: &str) -> Option<String> {
    let line = out.lines().map(str::trim).find(|l| !l.is_empty())?;
    let v = line.strip_prefix("OpenClaw ").unwrap_or(line);
    v.split_whitespace().next().map(str::to_string)
}

/// The JSON a CLI printed, skipping anything it printed before it (warnings, banners, a
/// `[plugins] ...` log line): the first line from which the rest parses.
pub fn json_out(out: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str(out.trim()) {
        return Some(v);
    }
    let mut at = 0;
    for line in out.split_inclusive('\n') {
        let t = line.trim_start();
        if (t.starts_with('{') || t.starts_with('['))
            && let Ok(v) = serde_json::from_str(out[at..].trim())
        {
            return Some(v);
        }
        at += line.len();
    }
    None
}

/// What `openclaw gateway status --json` says about the service and the port.
pub fn parse_gateway_status(v: &Value) -> (Option<Runs>, Option<u16>) {
    let port = v
        .pointer("/gateway/port")
        .or_else(|| v.pointer("/port/port"))
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok());
    let service = v.get("service");
    // `loaded` is false for a unit that is not enabled, even while it runs (OpenClaw 2026.10.9).
    let loaded = service.and_then(|s| s.get("loaded")).and_then(Value::as_bool) == Some(true)
        || service
            .and_then(|s| s.pointer("/runtime/status"))
            .and_then(Value::as_str)
            == Some("running");
    let systemd = service.and_then(|s| s.get("systemdInstallation"));
    if loaded && let Some(sd) = systemd {
        let kind = sd.get("kind").and_then(Value::as_str).unwrap_or("user");
        let unit = sd
            .get(kind)
            .and_then(|k| k.get("unitName"))
            .or_else(|| service.and_then(|s| s.pointer("/runtime/systemd/unit")))
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_UNIT)
            .to_string();
        let runs = if kind == "system" {
            Runs::SystemdSystem { unit }
        } else {
            Runs::SystemdUser { unit }
        };
        return (Some(runs), port);
    }
    // No service: a gateway someone started by hand still holds the port.
    let pid = v
        .pointer("/port/listeners/0/pid")
        .and_then(Value::as_u64)
        .and_then(|p| u32::try_from(p).ok());
    let busy = v.pointer("/port/status").and_then(Value::as_str) == Some("busy");
    if busy || pid.is_some() {
        return (Some(Runs::Process { pid }), port);
    }
    (None, port)
}

/// An OpenClaw gateway in `pm2 jlist`: a process whose script or arguments name OpenClaw.
pub fn parse_pm2(v: &Value) -> Option<String> {
    v.as_array()?.iter().find_map(|p| {
        let env = p.get("pm2_env")?;
        let script = env.get("pm_exec_path").and_then(Value::as_str).unwrap_or("");
        let args = env.get("args").map(Value::to_string).unwrap_or_default();
        let name = p.get("name").and_then(Value::as_str)?;
        (script.contains("openclaw") || args.contains("openclaw") || name.contains("openclaw"))
            .then(|| name.to_string())
    })
}

/// A running OpenClaw container in `docker ps --format '{{json .}}'` (one object a line): the
/// image is OpenClaw's. With several, the one named for the gateway. Its host port for 18789.
pub fn parse_docker_ps(out: &str) -> Option<(String, Option<u16>)> {
    let rows: Vec<Value> = out
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())
        .filter(|r| {
            r.get("Image")
                .and_then(Value::as_str)
                .is_some_and(|i| i.to_ascii_lowercase().contains("openclaw"))
        })
        .collect();
    // Docker lists every name a container has, comma-joined (older links add `other/alias` ones):
    // the first that is a plain name.
    let name = |r: &Value| {
        r.get("Names")
            .and_then(Value::as_str)?
            .split(',')
            .map(str::trim)
            .find(|n| valid_container(n))
            .map(str::to_string)
    };
    let row = rows
        .iter()
        .find(|r| name(r).is_some_and(|n| n.contains("gateway")))
        .or_else(|| rows.iter().find(|r| name(r).is_some()))?;
    let ports = row.get("Ports").and_then(Value::as_str).unwrap_or("");
    Some((name(row)?, host_port(ports)))
}

/// `0.0.0.0:18789->18789/tcp, [::]:18789->18789/tcp` → 18789: the host side of the gateway port.
fn host_port(ports: &str) -> Option<u16> {
    ports.split(',').find_map(|p| {
        let (host, inner) = p.trim().split_once("->")?;
        inner
            .starts_with(&format!("{DEFAULT_GATEWAY_PORT}/"))
            .then(|| host.rsplit(':').next()?.parse().ok())?
    })
}

async fn stdout(runner: &dyn Runner, cmd: Cmd) -> Option<String> {
    match runner.run(cmd).await {
        Ok(o) if o.success() => Some(o.stdout_str()),
        _ => None,
    }
}

/// A word for `sh`, in single quotes.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Docker's own rule for container names.
pub fn valid_container(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// What the wrapper runs. In a container, the image's documented entry, `node dist/index.js` in
/// its work dir. With no CLI, it says so and fails.
pub fn wrapper_script(target: Option<&WrapperTarget>) -> String {
    let body = match target {
        Some(WrapperTarget::Host(cli)) => format!("exec {} \"$@\"", sh_quote(cli)),
        Some(WrapperTarget::Docker(c)) => format!("exec docker exec -i {} node dist/index.js \"$@\"", sh_quote(c)),
        None => "echo 'OpenClaw is not installed here' >&2\nexit 1".to_string(),
    };
    format!("#!/bin/sh\n{body}\n")
}

pub enum WrapperTarget {
    Host(String),
    Docker(String),
}

/// Write the wrapper, whole or not at all (a CLI call during the write must find the old one).
/// Unchanged content is not written again, and one discovery that finds no CLI does not replace a
/// wrapper that points at one: the next look decides. `write: false` is a dry run (`vm-agent
/// discover`) and writes nothing.
fn write_wrapper(state_dir: &Path, target: Option<&WrapperTarget>, write: bool) -> Option<String> {
    let path = wrapper_path(state_dir);
    if !write {
        return Some(path.to_string_lossy().into_owned());
    }
    let script = wrapper_script(target);
    let current = std::fs::read_to_string(&path).ok();
    let keep = current.as_deref() == Some(script.as_str())
        || (target.is_none() && current.is_some_and(|c| c != wrapper_script(None)));
    if !keep {
        std::fs::create_dir_all(state_dir).ok()?;
        cc_store::write_atomic(&path, script.as_bytes(), 0o755, cc_store::TmpName::HiddenPrefix).ok()?;
    }
    Some(path.to_string_lossy().into_owned())
}

/// A path inside the container, as the host sees it through the container's mounts (`docker
/// inspect`'s `.Mounts`): the mount with the longest destination that holds it.
/// Shown on `/status` only: nothing on this machine is read or written at it (the container's
/// own path is, through Docker). A relative path or one with `..` is not taken.
pub fn host_path(mounts: &Value, inside: &str) -> Option<String> {
    let inside = Path::new(inside);
    if !inside.is_absolute()
        || inside
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return None;
    }
    mounts
        .as_array()?
        .iter()
        .filter_map(|m| {
            let dest = Path::new(m.get("Destination")?.as_str()?);
            let source = m.get("Source")?.as_str()?;
            let rest = inside.strip_prefix(dest).ok()?;
            Some((dest.as_os_str().len(), Path::new(source).join(rest)))
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, p)| p.to_string_lossy().trim_end_matches('/').to_string())
}

/// Find the install. `home` is the user OpenClaw runs as (this agent's user); `state_dir` is the
/// agent's own, where a container's wrapper goes.
pub async fn discover(runner: &dyn Runner, hints: &OpenClawHints, home: &Path, state_dir: &Path) -> Install {
    find(runner, hints, home, state_dir, true).await
}

/// [`discover`] without writing anything (`vm-agent discover`, which may run on any box).
pub async fn dry_run(runner: &dyn Runner, hints: &OpenClawHints, home: &Path, state_dir: &Path) -> Install {
    find(runner, hints, home, state_dir, false).await
}

async fn find(runner: &dyn Runner, hints: &OpenClawHints, home: &Path, state_dir: &Path, write: bool) -> Install {
    let runs_hint = hints.runs.as_deref().unwrap_or("auto");
    let mut port = hints.gateway_port.unwrap_or(DEFAULT_GATEWAY_PORT);

    // A container first: its CLI is reached through Docker, whatever is on the host.
    let docker = match (runs_hint, &hints.container) {
        (_, Some(c)) if !c.is_empty() => {
            if !valid_container(c) {
                tracing::warn!("[unmanaged] openclaw.container {c:?} is not a container name: ignored");
            }
            valid_container(c).then(|| (c.clone(), None))
        }
        ("docker" | "auto", _) => stdout(
            runner,
            Cmd::new("docker").args(["ps", "--format", "{{json .}}"]).timeout(QUICK),
        )
        .await
        .and_then(|o| parse_docker_ps(&o)),
        _ => None,
    };
    // What runs the CLI for the questions below: the wrapper, or on a dry run (which writes no
    // wrapper) the program the wrapper would run.
    let mut direct: Option<Vec<String>> = None;
    let (cli, runs_found) = match docker {
        Some((container, host_port)) => {
            if hints.gateway_port.is_none()
                && let Some(p) = host_port
            {
                port = p;
            }
            let target = match hints.cli.clone() {
                Some(c) => WrapperTarget::Host(c),
                None => WrapperTarget::Docker(container.clone()),
            };
            if !write {
                direct = Some(match &target {
                    WrapperTarget::Host(c) => vec![c.clone()],
                    WrapperTarget::Docker(c) => ["docker", "exec", "-i", c.as_str(), "node", "dist/index.js"]
                        .map(str::to_string)
                        .to_vec(),
                });
            }
            (
                write_wrapper(state_dir, Some(&target), write),
                Some(Runs::Docker { container }),
            )
        }
        None => {
            let cli = find_cli(hints.cli.as_deref(), home);
            let target = cli.clone().map(WrapperTarget::Host);
            write_wrapper(state_dir, target.as_ref(), write);
            (cli, None)
        }
    };
    let Some(cli) = cli else {
        return Install::not_found(port);
    };
    let run = direct.unwrap_or_else(|| vec![cli.clone()]);
    let ask = |args: &[&str]| {
        Cmd::new(&run[0])
            .args(run[1..].iter().map(String::as_str).chain(args.iter().copied()))
            .timeout(QUICK)
    };

    let (version, config_file) = tokio::join!(
        stdout(runner, ask(&["--version"])),
        stdout(runner, ask(&["config", "file", "--json"])),
    );
    let version = version.and_then(|o| parse_version(&o));
    let mut config_file = config_file
        .and_then(|o| json_out(&o))
        .and_then(|v| v.get("path").and_then(Value::as_str).map(str::to_string));
    let mut state = hints
        .state_dir
        .clone()
        .or_else(|| match runs_found {
            // The agent's own environment says nothing about the container's.
            Some(_) => None,
            None => std::env::var_os("OPENCLAW_STATE_DIR").map(PathBuf::from),
        })
        .or_else(|| {
            config_file
                .as_ref()
                .and_then(|f| Path::new(f).parent().map(Path::to_path_buf))
        })
        .unwrap_or_else(|| home.join(".openclaw"));
    // A container's paths, as the host sees them: the agent reads channel state there. A path no
    // mount holds is the container's own, which names nothing here (or something else): none.
    let mut state_here = true;
    let mut inside = None;
    if let Some(Runs::Docker { container }) = &runs_found
        && hints.state_dir.is_none()
    {
        state_here = false;
        inside = Some(state.to_string_lossy().into_owned());
        let mounts = stdout(
            runner,
            Cmd::new("docker")
                .args(["inspect", "-f", "{{json .Mounts}}", "--", container.as_str()])
                .timeout(QUICK),
        )
        .await
        .and_then(|o| json_out(&o));
        match mounts {
            Some(m) => {
                if let Some(s) = host_path(&m, &state.to_string_lossy()) {
                    state = PathBuf::from(s);
                    state_here = true;
                }
                config_file = config_file.and_then(|f| host_path(&m, &f));
            }
            None => config_file = None,
        }
    }

    let runs = match runs_found {
        Some(r) => r,
        None => runs_of(runner, &cli, hints, runs_hint, &mut port).await,
    };
    Install {
        cli: Some(cli),
        version,
        config_file,
        state_dir: state_here.then(|| state.to_string_lossy().into_owned()),
        container_state_dir: inside,
        runs,
        gateway_port: port,
    }
}

/// How a gateway on the host runs: the hint, else OpenClaw's own status, else pm2.
async fn runs_of(runner: &dyn Runner, cli: &str, hints: &OpenClawHints, hint: &str, port: &mut u16) -> Runs {
    let unit = || hints.unit.clone().unwrap_or_else(|| DEFAULT_UNIT.to_string());
    match hint {
        "systemd-user" => return Runs::SystemdUser { unit: unit() },
        "systemd-system" => return Runs::SystemdSystem { unit: unit() },
        "process" => return Runs::Process { pid: None },
        "pm2" => {
            if let Some(name) = hints.pm2_name.clone() {
                return Runs::Pm2 { name };
            }
        }
        _ => {}
    }
    let status = stdout(
        runner,
        Cmd::new(cli)
            .args(["gateway", "status", "--json"])
            .timeout(STATUS_TIMEOUT),
    )
    .await
    .and_then(|o| json_out(&o));
    let (found, status_port) = status.as_ref().map_or((None, None), parse_gateway_status);
    if hints.gateway_port.is_none()
        && let Some(p) = status_port
    {
        *port = p;
    }
    // A gateway under pm2 shows to OpenClaw as a plain process.
    if matches!(found, None | Some(Runs::Process { .. })) {
        let pm2 = stdout(runner, Cmd::new("pm2").arg("jlist").timeout(QUICK))
            .await
            .and_then(|o| json_out(&o))
            .and_then(|v| parse_pm2(&v));
        if let Some(name) = pm2 {
            return Runs::Pm2 { name };
        }
    }
    found.unwrap_or(Runs::NotRunning)
}

#[cfg(test)]
mod tests;
