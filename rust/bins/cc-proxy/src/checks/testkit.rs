//! A stand-in for one of the firewall agent's loopback services in unit tests: records each JSON
//! body it is posted, by path, and answers what the test told it to (the last answer for a path
//! repeats; a path without one gets `{}`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Debug)]
pub struct Answer {
    status: u16,
    body: String,
    chunked: bool,
    raw: Option<String>,
    length: Option<usize>,
    delay: Duration,
}

impl Answer {
    pub fn json(status: u16, v: Value) -> Self {
        Self::raw(status, &v.to_string())
    }
    pub fn raw(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_owned(),
            chunked: false,
            raw: None,
            length: None,
            delay: Duration::ZERO,
        }
    }
    pub fn chunked(status: u16, body: &str) -> Self {
        Self {
            chunked: true,
            ..Self::raw(status, body)
        }
    }
    /// A chunked answer whose body is written as given (chunk sizes and all).
    pub fn chunked_raw(self, raw: &str) -> Self {
        Self {
            chunked: true,
            raw: Some(raw.to_owned()),
            ..self
        }
    }
    /// A `Content-Length` header too (with a chunked answer: one that is not its length).
    pub fn with_length(self, n: usize) -> Self {
        Self {
            length: Some(n),
            ..self
        }
    }
    pub fn delayed(self, delay: Duration) -> Self {
        Self { delay, ..self }
    }
}

#[derive(Default)]
struct State {
    /// The queue per path, and whether its last answer has been given once (a new one replaces it then).
    answers: HashMap<String, (Vec<Answer>, bool)>,
    calls: Vec<(String, Value)>,
}

#[derive(Clone)]
pub struct FakeService {
    port: u16,
    state: Arc<Mutex<State>>,
}

impl FakeService {
    pub async fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let state = Arc::new(Mutex::new(State::default()));
        let s = state.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let s = s.clone();
                tokio::spawn(async move {
                    let _ = serve(stream, s).await;
                });
            }
        });
        Ok(Self { port, state })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The service's URL with this path (`""` for the bare origin).
    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Queue an answer for `path`.
    pub fn answer(&self, path: &str, a: Answer) {
        let mut st = self.lock();
        let (q, used) = st.answers.entry(path.to_owned()).or_default();
        if q.len() == 1 && *used {
            q.clear();
        }
        q.push(a);
        *used = false;
    }

    /// The bodies posted to `path`, in order.
    pub fn calls(&self, path: &str) -> Vec<Value> {
        self.lock()
            .calls
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, v)| v.clone())
            .collect()
    }

    pub fn all_calls(&self) -> Vec<(String, Value)> {
        self.lock().calls.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

async fn serve(mut stream: TcpStream, state: Arc<Mutex<State>>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let (path, body) = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        let path = head.split(' ').nth(1).unwrap_or("/").to_owned();
        let len: usize = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())?
            })
            .unwrap_or(0);
        if buf.len() >= end + 4 + len {
            break (path, buf[end + 4..end + 4 + len].to_vec());
        }
    };
    let answer = {
        let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        st.calls
            .push((path.clone(), serde_json::from_slice(&body).unwrap_or(Value::Null)));
        match st.answers.get_mut(&path) {
            Some((q, _)) if q.len() > 1 => q.remove(0),
            Some((q, used)) if q.len() == 1 => {
                *used = true;
                q[0].clone()
            }
            _ => Answer::raw(200, "{}"),
        }
    };
    tokio::time::sleep(answer.delay).await;
    let head = if answer.chunked {
        let length = answer
            .length
            .map(|n| format!("content-length: {n}\r\n"))
            .unwrap_or_default();
        format!(
            "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n{length}\r\n",
            answer.status
        )
    } else {
        format!(
            "HTTP/1.1 {} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            answer.status,
            answer.body.len()
        )
    };
    stream.write_all(head.as_bytes()).await?;
    if let Some(raw) = &answer.raw {
        stream.write_all(raw.as_bytes()).await?;
    } else if answer.chunked {
        if !answer.body.is_empty() {
            stream
                .write_all(format!("{:x}\r\n{}\r\n", answer.body.len(), answer.body).as_bytes())
                .await?;
        }
        stream.write_all(b"0\r\n\r\n").await?;
    } else {
        stream.write_all(answer.body.as_bytes()).await?;
    }
    stream.shutdown().await
}

/// The content rules with their two loopback services faked, the code buttons' service, and a
/// folder for the files (rules, marker, audit).
pub struct Rig {
    pub dir: tempfile::TempDir,
    /// 8794: holds, records, notices, `/own`.
    pub agent: FakeService,
    /// 3101: `/content`.
    pub judge: FakeService,
    /// 8793: button taps.
    pub buttons: FakeService,
    pub settings: crate::checks::env::Settings,
    pub content: Arc<crate::checks::content::Content>,
}

impl Rig {
    pub async fn new() -> Rig {
        Self::with_env(&[]).await
    }

    pub async fn with_env(extra: &[(&str, &str)]) -> Rig {
        let dir = tempfile::tempdir().expect("dir");
        let agent = FakeService::start().await.expect("agent");
        let judge = FakeService::start().await.expect("judge");
        let buttons = FakeService::start().await.expect("buttons");
        let d = dir.path().to_string_lossy().into_owned();
        let mut env: HashMap<String, String> = [
            ("MITM_CREDENTIALS_PATH", format!("{d}/credentials.json")),
            ("MITM_LOG_FILE", format!("{d}/traffic.jsonl")),
            ("MITM_CONTENT_RULES_URL", agent.url("")),
            ("MITM_AI_JUDGE_URL", judge.url("/judge")),
            ("MITM_CODE_BUTTONS_URL", buttons.url("/")),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        for (k, v) in extra {
            env.insert((*k).to_owned(), (*v).to_owned());
        }
        let settings = crate::checks::env::Settings::from_vars(&env);
        let content = crate::checks::content::Content::new(settings.clone());
        Rig {
            dir,
            agent,
            judge,
            buttons,
            settings,
            content,
        }
    }

    /// Write `content-rules.json` with these rules (a new mtime each time).
    pub fn write_rules(&self, rules: Value) {
        self.write_file(
            "content-rules.json",
            &serde_json::json!({"version": 1, "rules": rules}).to_string(),
        );
    }

    pub fn write_file(&self, name: &str, body: &str) {
        let path = self.dir.path().join(name);
        std::fs::write(&path, body).expect("write");
        bump(&path);
    }

    pub fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.path().join("content-rules.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }

    /// Fire-and-forget calls land after the step: give them a moment.
    pub async fn settle(&self) {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// A later mtime than any before, as the addon's tests force with `os.utime`.
pub fn bump(path: &std::path::Path) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let t = std::time::SystemTime::now() + Duration::from_secs(n);
    if let Ok(f) = std::fs::File::options().write(true).open(path) {
        let _ = f.set_modified(t);
    }
}

/// A rule as the addon's tests write them.
pub fn rule(
    id: &str,
    action: &str,
    direction: &str,
    patterns: &[&str],
    detectors: &[&str],
    channels: &[&str],
) -> Value {
    serde_json::json!({"id": id, "name": id, "direction": direction, "channels": channels, "patterns": patterns,
                       "detectors": detectors, "action": action, "reason": format!("{id} reason")})
}
