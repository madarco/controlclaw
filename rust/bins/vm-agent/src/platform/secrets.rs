//! Secret placeholders in OpenClaw's environment (`secrets.ts`, `routes/secrets.ts`). The firewall
//! sends the whole list; this rewrites the `NAME=CC-SEC-…` lines of `~/.openclaw/.env` that it owns,
//! never a line somebody else wrote, and restarts OpenClaw so it reads them.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use cc_http::{FirewallBody, FirewallRequest, ReadBody, Router, send_json};
use hyper::Method;
use regex::Regex;
use serde_json::{Map, Value, json};

use super::common::{BODY_LIMIT, Deps};
use crate::app::App;
use crate::stages;

static NAME_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]{0,63}$").expect("regex"));
static PLACEHOLDER_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CC-SEC-[a-f0-9]{48}$").expect("regex"));
static MANAGED_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Z][A-Z0-9_]{0,63}=CC-SEC-[a-f0-9]{48}$").expect("regex"));
/// `RESERVED_SECRET_NAME` (@controlclaw/templates/ids): variables the agent has by itself.
static RESERVED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:PATH|HOME|SHELL|USER|LOGNAME|ENV|BASH_ENV|IFS|NODE_.*|LD_.*|OPENCLAW_.*|CONTROLCLAW_.*|AGENTMAIL_.*)$",
    )
    .expect("regex")
});

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub placeholder: String,
}

/// `parseSecretApply`: at most 100 entries, each a name that is not reserved and a placeholder,
/// names unique. None for anything else.
pub fn parse(raw: &Map<String, Value>) -> Option<Vec<Entry>> {
    let list = raw.get("entries")?.as_array()?;
    if list.len() > 100 {
        return None;
    }
    let mut out: Vec<Entry> = Vec::new();
    for e in list {
        let name = e.get("name")?.as_str()?;
        let placeholder = e.get("placeholder")?.as_str()?;
        if !NAME_RE.is_match(name)
            || RESERVED.is_match(name)
            || !PLACEHOLDER_RE.is_match(placeholder)
            || out.iter().any(|x| x.name == name)
        {
            return None;
        }
        out.push(Entry {
            name: name.into(),
            placeholder: placeholder.into(),
        });
    }
    Some(out)
}

/// The new `.env` text: the lines this does not own, then one per entry. Err when an entry's name
/// is already a variable somebody else set.
pub fn render(current: &str, entries: &[Entry]) -> Result<String, &'static str> {
    let unmanaged: Vec<&str> = current
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !MANAGED_LINE.is_match(l))
        .collect();
    for e in entries {
        if unmanaged.iter().any(|l| sets(l, &e.name)) {
            return Err("An environment variable with this name already exists");
        }
    }
    let mut lines: Vec<String> = unmanaged
        .into_iter()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    lines.extend(entries.iter().map(|e| format!("{}={}", e.name, e.placeholder)));
    Ok(format!("{}\n", lines.join("\n")))
}

/// Whether `line` sets `name`: `^\s*(?:export\s+)?NAME\s*=`, with JavaScript's `\s`.
fn sets(line: &str, name: &str) -> bool {
    let rest = line.trim_start();
    let matches = |r: &str| {
        r.strip_prefix(name)
            .is_some_and(|after| after.trim_start().starts_with('='))
    };
    if matches(rest) {
        return true;
    }
    match rest.strip_prefix("export") {
        Some(after) if after.starts_with(char::is_whitespace) => matches(after.trim_start()),
        _ => false,
    }
}

pub struct SecretsService {
    env_path: PathBuf,
    deps: Deps,
    /// Unmanaged: OpenClaw's folder is its own user's, not ours to walk.
    unmanaged: Option<Unmanaged>,
}

/// Where an unmanaged OpenClaw's `.env` is written.
#[derive(Debug, Clone, PartialEq)]
pub enum Unmanaged {
    /// On this machine, by the vm-agent as OpenClaw's own user (it refuses to as root): a link can
    /// reach only that user's files. Nothing is followed at the last step all the same.
    Host,
    /// Inside the container (`docker exec`, as the container's own user), at the path it names:
    /// links resolve in the container, never on this machine, where the agent is root.
    Container { container: String, env_path: String },
}

impl SecretsService {
    pub fn new(env_path: PathBuf, deps: Deps) -> Self {
        Self {
            env_path,
            deps,
            unmanaged: None,
        }
    }

    /// Unmanaged: where the `.env` is written (above).
    pub fn unmanaged(mut self, how: Unmanaged) -> Self {
        self.unmanaged = Some(how);
        self
    }

    pub async fn apply(&self, entries: &[Entry]) -> Result<Value, String> {
        if let Some(Unmanaged::Container { container, env_path }) = &self.unmanaged {
            self.apply_in_container(container, env_path, entries).await?;
        } else if self.unmanaged.is_some() {
            self.apply_on_host(entries).map_err(|e| e.to_string())?;
        } else {
            let current = std::fs::read_to_string(&self.env_path).unwrap_or_default();
            let next = render(&current, entries).map_err(str::to_string)?;
            if current != next {
                write_env(&self.env_path, &next).map_err(|e| e.to_string())?;
            }
        }
        // Retried even when an earlier attempt saved the file and then failed to activate it.
        self.deps
            .restart()
            .await
            .map_err(|_| "Could not restart OpenClaw".to_string())?;
        Ok(json!({ "ok": true }))
    }
}

impl SecretsService {
    /// The container's `.env`, read and written by the container's own user: the shell's `cat`
    /// and `mv` resolve the path inside the container.
    async fn apply_in_container(&self, container: &str, env_path: &str, entries: &[Entry]) -> Result<(), String> {
        let read = CONTAINER_READ;
        let current = self
            .deps
            .exec(
                "docker",
                &["exec", "-i", container, "sh", "-c", read, "sh", env_path],
                CONTAINER_IO,
                None,
                &[],
            )
            .await?;
        if current.len() > ENV_CAP {
            return Err("OpenClaw's .env is over 1 MB: not changed".into());
        }
        // Read as text: bytes that are not UTF-8 would come back replaced.
        if current.contains('\u{FFFD}') {
            return Err("OpenClaw's .env is not plain UTF-8 text: not changed".into());
        }
        let next = render(&current, entries).map_err(str::to_string)?;
        if next.len() > ENV_CAP {
            return Err("OpenClaw's .env would be over 1 MB: not changed".into());
        }
        if current == next {
            return Ok(());
        }
        let write = CONTAINER_WRITE;
        self.deps
            .exec(
                "docker",
                &["exec", "-i", container, "sh", "-c", write, "sh", env_path],
                CONTAINER_IO,
                Some(next),
                &[],
            )
            .await
            .map(|_| ())
    }

    /// On this machine, as OpenClaw's own user (refused as root: a link would reach anything).
    /// A `.env` that is not a plain file is refused; the temp file is made new (a stale one, or a
    /// link in its place, is removed first, never written through).
    fn apply_on_host(&self, entries: &[Entry]) -> std::io::Result<()> {
        let bad = |m: String| std::io::Error::other(m);
        if rustix::process::geteuid().is_root() {
            return Err(bad(
                "The agent runs as root: it writes OpenClaw's .env only as OpenClaw's own user (or inside its container)".into(),
            ));
        }
        let current = match std::fs::symlink_metadata(&self.env_path) {
            Ok(m) if !m.file_type().is_file() => {
                return Err(bad(format!(
                    "{} is not a plain file: not written",
                    self.env_path.display()
                )));
            }
            Ok(_) => read_nofollow(&self.env_path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e),
        };
        let next = render(&current, entries).map_err(|e| bad(e.to_string()))?;
        if next.len() > ENV_CAP {
            return Err(bad(format!(
                "{} would be over 1 MB: not changed",
                self.env_path.display()
            )));
        }
        if current == next {
            return Ok(());
        }
        let mut tmp = self.env_path.as_os_str().to_owned();
        tmp.push(".secrets.tmp");
        let tmp = PathBuf::from(tmp);
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&tmp)?;
            f.write_all(next.as_bytes())?;
        }
        std::fs::rename(&tmp, &self.env_path)
    }
}

/// The shell in the container that reads the `.env` (`$1`), or nothing.
/// At most one byte past [`ENV_CAP`]: a longer file is refused, not read whole.
/// A file that is not there reads as empty; any other failure (a folder, no access) is an error,
/// never an empty file that the write would then replace the old one with.
pub(crate) const CONTAINER_READ: &str = "[ -e \"$1\" ] || [ -L \"$1\" ] || exit 0; exec head -c 1048577 -- \"$1\"";
/// The largest `.env` read or written.
const ENV_CAP: usize = 1024 * 1024;
/// The shell in the container that writes it, from stdin: a temp file, then a rename.
/// A stale temp file (or a link in its place) is removed first: the write never goes through one.
pub(crate) const CONTAINER_WRITE: &str =
    "umask 077 && rm -f -- \"$1.secrets.tmp\" && cat > \"$1.secrets.tmp\" && mv -f -- \"$1.secrets.tmp\" \"$1\"";

/// `docker exec` reading or writing the `.env`.
const CONTAINER_IO: std::time::Duration = std::time::Duration::from_secs(20);

/// A file's text, refusing a link at the last step (`O_NOFOLLOW`) and anything but a plain file
/// (`O_NONBLOCK`, so a FIFO does not hang the open; checked on the open file).
fn read_nofollow(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open(path)?;
    let m = f.metadata()?;
    if !m.file_type().is_file() {
        return Err(std::io::Error::other(format!("{} is not a plain file", path.display())));
    }
    if m.len() > ENV_CAP as u64 {
        return Err(std::io::Error::other(format!(
            "{} is over 1 MB: not changed",
            path.display()
        )));
    }
    let mut s = String::new();
    // Bounded even if it grows after the check.
    (&mut f).take(ENV_CAP as u64 + 1).read_to_string(&mut s)?;
    if s.len() > ENV_CAP {
        return Err(std::io::Error::other(format!(
            "{} is over 1 MB: not changed",
            path.display()
        )));
    }
    Ok(s)
}

fn write_env(path: &Path, text: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // `<path>.secrets.tmp`, 0600, then renamed over, as the TS does.
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".secrets.tmp");
    let tmp = PathBuf::from(tmp);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
    }
    std::fs::rename(&tmp, path)
}

/// `/secrets/*`: the firewall's token for `secrets`, then `POST /secrets/apply`.
pub fn register(router: &mut Router, app: &Arc<App>) {
    let app = app.clone();
    router.prefix(stages::PREFIXED, "/secrets/", move |req, _| {
        let app = app.clone();
        async move {
            let read = if req.method() == Method::POST {
                ReadBody::Json { limit: BODY_LIMIT }
            } else {
                ReadBody::No
            };
            let (parts, body) = match cc_http::firewall_request(&app.firewall_auth, req, "secrets", 0, read).await {
                FirewallRequest::Accepted { parts, body, .. } => (parts, body),
                FirewallRequest::Refused { .. } => {
                    return send_json(401, &json!({ "error": "Secrets changes must come from the org firewall" }));
                }
            };
            if parts.method != Method::POST || cc_http::pathname(&parts.uri.to_string()) != "/secrets/apply" {
                return send_json(404, &json!({ "error": "Not found" }));
            }
            let entries = match body {
                FirewallBody::Json(b) => parse(&b),
                _ => None,
            };
            let Some(entries) = entries else {
                return send_json(400, &json!({ "error": "Invalid secret placeholders" }));
            };
            let Some(service) = app.contracts.platform.get().and_then(|p| p.secrets.get().cloned()) else {
                return send_json(500, &json!({ "error": "Could not apply placeholders. Check for an existing environment variable or restart the agent." }));
            };
            match service.apply(&entries).await {
                Ok(v) => send_json(200, &v),
                Err(_) => send_json(
                    500,
                    &json!({ "error": "Could not apply placeholders. Check for an existing environment variable or restart the agent." }),
                ),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> Value {
        json!({ "name": name, "placeholder": format!("CC-SEC-{}", "a".repeat(48)) })
    }

    #[test]
    fn only_placeholders_and_names_that_are_not_reserved() {
        let p = |v: Value| parse(v.as_object().expect("o"));
        assert!(p(json!({ "entries": [entry("API_TOKEN")] })).is_some());
        assert!(p(json!({ "entries": [{ "name": "API_TOKEN", "placeholder": "real-value" }] })).is_none());
        assert!(p(json!({ "entries": [entry("NODE_OPTIONS")] })).is_none());
        assert!(p(json!({ "entries": [entry("A"), entry("A")] })).is_none());
        assert!(p(json!({ "entries": [entry("lower")] })).is_none());
        assert!(p(json!({})).is_none());
    }

    /// Unmanaged (OpenClaw's folder is a container's, the agent may be root): a link is never
    /// written through. A `.env` that is a link is refused; a link in the temp file's place is
    /// removed, and the file it pointed at is left as it was.
    #[tokio::test]
    async fn an_unmanaged_env_file_never_follows_a_link() {
        let d = tempfile::tempdir().expect("dir");
        let outside = d.path().join("outside");
        std::fs::create_dir(&outside).expect("d");
        let target = outside.join("cron");
        std::fs::write(&target, "untouched\n").expect("w");
        let state = d.path().join("state");
        std::fs::create_dir(&state).expect("d");
        let env = state.join(".env");
        let rig = super::super::llm::tests::rig(super::super::llm::tests::Fake::new());
        let s = SecretsService::new(env.clone(), rig.deps.clone()).unmanaged(Unmanaged::Host);
        let entries = parse(json!({ "entries": [entry("API_TOKEN")] }).as_object().expect("o")).expect("ok");
        std::os::unix::fs::symlink(&target, &env).expect("link");
        assert!(s.apply(&entries).await.is_err(), "a linked .env is refused");
        assert_eq!(std::fs::read_to_string(&target).expect("r"), "untouched\n");
        std::fs::remove_file(&env).expect("rm");
        std::os::unix::fs::symlink(&target, state.join(".env.secrets.tmp")).expect("link");
        s.apply(&entries).await.expect("applied");
        assert_eq!(
            std::fs::read_to_string(&target).expect("r"),
            "untouched\n",
            "not written through"
        );
        assert!(std::fs::symlink_metadata(&env).expect("m").file_type().is_file());
        assert!(std::fs::read_to_string(&env).expect("r").contains("API_TOKEN=CC-SEC-"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&env).expect("m").permissions().mode() & 0o777, 0o600);
    }

    /// In a container the `.env` is read and written by the container's own user, at the path the
    /// container names: nothing on this machine is opened, whatever links the folder holds.
    #[tokio::test]
    async fn a_containers_env_file_is_written_inside_it() {
        let rig = super::super::llm::tests::rig(super::super::llm::tests::Fake::new());
        // A path that would climb out on this machine, or that a link would lead elsewhere: here it
        // is only an argument to a shell inside the container.
        let inside = "/home/node/.openclaw/x/../../../etc/.env";
        let s =
            SecretsService::new(PathBuf::from("/nonexistent/.env"), rig.deps.clone()).unmanaged(Unmanaged::Container {
                container: "oc-gw".into(),
                env_path: inside.into(),
            });
        let entries = parse(json!({ "entries": [entry("API_TOKEN")] }).as_object().expect("o")).expect("ok");
        s.apply(&entries).await.expect("applied");
        let calls = rig.runner.calls();
        let write = calls
            .iter()
            .find(|c| c.args.iter().any(|a| a.contains("mv -f")))
            .expect("a write");
        assert_eq!(write.program, "docker");
        assert_eq!(&write.args[..3], ["exec", "-i", "oc-gw"]);
        assert_eq!(
            write.args.last().map(String::as_str),
            Some(inside),
            "a shell argument, not a host path"
        );
        let text = String::from_utf8(write.stdin.clone().unwrap_or_default()).expect("utf8");
        assert!(text.contains(&format!("API_TOKEN=CC-SEC-{}", "a".repeat(48))));
        assert!(calls.iter().all(|c| c.program == "docker"), "nothing else run");
    }

    /// A FIFO in the `.env`'s place does not hang the read: refused.
    #[tokio::test]
    async fn a_fifo_as_env_is_refused() {
        let d = tempfile::tempdir().expect("dir");
        let env = d.path().join(".env");
        let made = std::process::Command::new("mkfifo").arg(&env).status().expect("mkfifo");
        assert!(made.success());
        let rig = super::super::llm::tests::rig(super::super::llm::tests::Fake::new());
        let s = SecretsService::new(env.clone(), rig.deps.clone()).unmanaged(Unmanaged::Host);
        let entries = parse(json!({ "entries": [entry("API_TOKEN")] }).as_object().expect("o")).expect("ok");
        let r = tokio::time::timeout(std::time::Duration::from_secs(5), s.apply(&entries)).await;
        assert!(matches!(r, Ok(Err(_))), "refused at once");
        assert!(read_nofollow(&env).is_err(), "and the read alone does not block");
    }

    #[tokio::test]
    async fn keeps_unrelated_lines_and_refuses_a_taken_name() {
        let d = tempfile::tempdir().expect("dir");
        let env = d.path().join(".env");
        std::fs::write(&env, "OTHER=keep\n").expect("w");
        let rig = super::super::llm::tests::rig(super::super::llm::tests::Fake::new());
        let s = SecretsService::new(env.clone(), rig.deps.clone());
        let entries = parse(json!({ "entries": [entry("API_TOKEN")] }).as_object().expect("o")).expect("ok");
        s.apply(&entries).await.expect("applied");
        let text = std::fs::read_to_string(&env).expect("r");
        assert!(text.contains(&format!("API_TOKEN=CC-SEC-{}", "a".repeat(48))));
        s.apply(&[]).await.expect("applied");
        assert_eq!(std::fs::read_to_string(&env).expect("r"), "OTHER=keep\n");
        let taken = parse(json!({ "entries": [entry("OTHER")] }).as_object().expect("o")).expect("ok");
        assert!(s.apply(&taken).await.is_err());
        assert_eq!(rig.restarts.load(std::sync::atomic::Ordering::SeqCst), 2);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&env).expect("m").permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn crlf_lines_are_read_and_written_back_plain() {
        assert_eq!(render("A=1\r\nB=2\r\n", &[]).expect("ok"), "A=1\nB=2\n");
        assert_eq!(render("", &[]).expect("ok"), "\n");
        assert!(
            render(
                "  export TOKEN = x\n",
                &[Entry {
                    name: "TOKEN".into(),
                    placeholder: "p".into()
                }]
            )
            .is_err()
        );
    }
}
