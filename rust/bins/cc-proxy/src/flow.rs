//! The `Flow` API: what every check sees, and the fixed order checks run in.
//!
//! One [`Flow`] per client connection (TCP) or per HTTP exchange, like a mitmproxy flow. The
//! plumbing (W1) builds it and calls [`Pipeline::run`] at each [`Hook`]; checks (W2, and W1's own
//! rules, windows and swaps) are [`Step`]s. A step reads and rewrites the flow in place and returns
//! a [`Verdict`]:
//!
//! - `Continue`: go on to the next step (also after rewriting the request, response or frame);
//! - `Answer`: stop here and send this response instead of contacting the server;
//! - `Drop`: drop the current websocket frame or TCP chunk and go on with the connection;
//! - `Kill`: close the connection (both sides), with a reason for the log.
//!
//! **Holding** is just awaiting inside the step: a step that asks the firewall agent and waits up
//! to 25 s for a person is one pending future on its own connection's task, so nothing else waits.
//! [`hold`] puts a deadline on such a wait and fails closed when it passes.
//!
//! **Order.** Steps register with a slot number from [`order`], copied from the addon's request
//! pipeline (appendix F §2.1); the pipeline sorts by slot and keeps registration order within one.
//! W1 and W2 register their steps from their own modules without editing each other's files, and
//! the order between them is still the addon's.
//!
//! Steps are `dyn Step` objects returning a boxed future: the pipeline holds steps of different
//! types in one list, and `async fn` in traits is not object-safe yet. One allocation per step call
//! is cheap next to a TLS record.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

/// Where in a connection's life a step is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hook {
    /// A full ClientHello was read; nothing has been decrypted or dialled yet.
    ClientHello,
    /// An HTTP request is buffered (`flow.request`), before any upstream connection.
    Request,
    /// The upstream response is buffered (`flow.response`).
    Response,
    /// A websocket upgrade was answered by the server (`flow.request`/`flow.response` are the handshake).
    WsStart,
    /// One websocket frame (`flow.ws_frame`).
    WsFrame,
    WsEnd,
    /// A connection that is spliced or dropped rather than intercepted.
    TcpStart,
    /// Bytes on a spliced connection (`flow.tcp_chunk`), for counting and budgets.
    TcpBytes,
    /// Something failed (`flow.error`).
    Error,
}

/// What a step decided.
#[derive(Debug)]
pub enum Verdict {
    Continue,
    /// Boxed: a response is large, and most verdicts are `Continue`.
    Answer(Box<http::Response<Bytes>>),
    Drop,
    Kill(String),
    /// Send the request on now, without the steps after this one: the addon's `return` out of
    /// `request` for the windows (code, update) and for a tunnel effect, which get no checks
    /// and no swap after them.
    Forward,
}

/// Which way a frame or chunk travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Agent to the internet.
    Out,
    /// The internet to the agent.
    In,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Text,
    Binary,
    Ping,
    Pong,
    Close,
}

#[derive(Debug, Clone)]
pub struct WsFrame {
    pub direction: Direction,
    pub kind: FrameKind,
    pub payload: Bytes,
}

#[derive(Debug, Clone)]
pub struct TcpChunk {
    pub direction: Direction,
    pub len: usize,
}

/// The connection's target as the client named it in `CONNECT` (behind redsocks: an IP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    pub host: String,
    pub port: u16,
}

/// Where a flow really goes: the name the firewall checked (the SNI, and for plain HTTP the Host),
/// and the address the firewall itself resolved that name to and dials. Set only by the network
/// layer once the CONNECT target, the SNI and the request's Host agree with it. Every credential
/// swap and every rule match uses this, never a header: a client chooses its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// Lower-case, no port.
    pub name: String,
    pub port: u16,
    /// The address checked and dialled; `None` for a name that did not resolve when the request
    /// came, which only the dial may resolve (and refuse). Nothing connects to a `None`.
    pub addr: Option<std::net::SocketAddr>,
}

/// One flow.
#[derive(Debug)]
pub struct Flow {
    /// A uuid: the traffic log's `flow_id`, the shipper's dedupe key.
    pub id: String,
    pub client_ip: IpAddr,
    /// The agent behind `client_ip`, from identities.json; `None` for an unknown source.
    pub vm_id: Option<String>,
    pub connect: Authority,
    /// What the client claims, unchecked: for the log and for the agreement check only.
    pub sni: Option<String>,
    /// The checked destination; `None` until the network layer has checked one.
    destination: Option<Destination>,
    pub alpn: Vec<Vec<u8>>,
    pub request: Option<http::Request<Bytes>>,
    pub response: Option<http::Response<Bytes>>,
    pub ws_frame: Option<WsFrame>,
    /// Frames a step wants sent, in order, after the current one (addon `inject.websocket`).
    pub inject: Vec<WsFrame>,
    pub tcp_chunk: Option<TcpChunk>,
    pub error: Option<String>,
    /// What steps leave for later steps and for the log record (addon `flow.metadata`): `rule`,
    /// `rule_id`, `effect`, `ai`, ... as JSON, so a new field needs no change here.
    pub meta: HashMap<&'static str, serde_json::Value>,
    /// When the flow began (the request's arrival for an HTTP exchange): the record's `duration_ms`.
    pub started: std::time::Instant,
    /// Typed values steps keep for the flow's life and never log: a credentials snapshot, the
    /// request path from before a swap. Dropped with the flow.
    pub extensions: http::Extensions,
}

impl Flow {
    pub fn new(client_ip: IpAddr, connect: Authority) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            client_ip,
            vm_id: None,
            connect,
            sni: None,
            destination: None,
            alpn: Vec::new(),
            request: None,
            response: None,
            ws_frame: None,
            inject: Vec::new(),
            tcp_chunk: None,
            error: None,
            meta: HashMap::new(),
            started: std::time::Instant::now(),
            extensions: http::Extensions::new(),
        }
    }

    /// The checked destination: what swaps and rule matches must use.
    pub fn destination(&self) -> Option<&Destination> {
        self.destination.as_ref()
    }

    /// Only the network layer sets it, after the checks in `net::destination`.
    pub(crate) fn set_destination(&mut self, d: Destination) {
        self.destination = Some(d);
    }

    /// The host the request names (URI authority, else Host), lower-cased and without a port.
    /// Unchecked: for the log and to refuse a request whose Host is not its destination. Never a
    /// reason to swap a credential or to match a rule.
    pub fn claimed_host(&self) -> Option<String> {
        let r = self.request.as_ref()?;
        let raw = r
            .uri()
            .host()
            .or_else(|| r.headers().get(http::header::HOST)?.to_str().ok())?;
        Some(strip_port(raw).to_ascii_lowercase())
    }
}

/// `host:port` → `host`; `[v6]:port` → `v6`; a bare IPv6 address is left alone.
fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match h.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => h,
    }
}

pub type StepFuture<'a> = Pin<Box<dyn Future<Output = Verdict> + Send + 'a>>;

/// One check.
pub trait Step: Send + Sync {
    /// For logs and tests.
    fn name(&self) -> &'static str;
    /// The hooks this step wants; it is not called for others.
    fn hooks(&self) -> &'static [Hook];
    fn run<'a>(&'a self, hook: Hook, flow: &'a mut Flow) -> StepFuture<'a>;
    /// For a websocket this step watches from outside its frames (a voice socket whose lease can
    /// end while it is quiet): a signal that turns `true` when the socket must close. The pumps
    /// close both sides then, frame or no frame. `None` (the default): nothing to watch.
    fn closing(&self, _flow: &Flow) -> Option<tokio::sync::watch::Receiver<bool>> {
        None
    }
    /// Whether this step reads the body at `hook` (the request's at `Request`, the answer's at
    /// `Response`) for this flow, decided from its head: the host, the method, the content type
    /// and length, the rules and credentials that apply. A body no step reads is streamed through
    /// as it comes, never held (owner, 2026-10-28); one a step reads is buffered for it, up to
    /// `http::MAX_BODY`. The default is `true`: a step that has not said reads every body. A
    /// streamed upload is answered within `http::upstream::ANSWER_TIMEOUT` (15 minutes) or cut
    /// off. A request streamed at `Request` has no body at `Response` either: a response step
    /// that reads the request's body checks `checks::request_body_ready`.
    ///
    /// The flow is mutable so the step can take what it decides from as the flow's own snapshot
    /// (the credentials, the rules) that `run` then reads: the decision and the step see the same
    /// files, even when one changes in between.
    fn reads_body(&self, _hook: Hook, _flow: &mut Flow) -> bool {
        true
    }
}

/// Where a step leaves the record a websocket writes when it ends (addon.py `websocket_end`: a
/// gpt-live socket's billed seconds): the record's own fields, which the plumbing writes after
/// `WsEnd` with the base fields (`flow_id`, `ts`, `tenant`, `vm_id`) under them.
pub const META_WS_END_RECORD: &str = "cc_voice_end_record";

/// Slots, in the addon's order (appendix F §2.1 for `request`; the others follow its hooks). Gaps
/// leave room. A step in the wrong slot is a bug even when every test passes, so keep these in
/// step with the addon until the cutover.
pub mod order {
    // request
    pub const VM_ID: u16 = 100;
    pub const NON_ROUTABLE: u16 = 200;
    pub const KILL_CODE_WINDOW: u16 = 300;
    pub const KILL_SWITCH: u16 = 400;
    pub const UPDATE_WINDOW: u16 = 500;
    pub const LOGIN_TRIPWIRE: u16 = 600;
    pub const MATCH_RULE: u16 = 700;
    pub const RESIDENTIAL_HTTP: u16 = 800;
    pub const AI_REVIEW: u16 = 900;
    pub const TUNNEL: u16 = 1000;
    pub const BLOCK: u16 = 1100;
    pub const PERMISSION: u16 = 1200;
    pub const EMAIL: u16 = 1300;
    pub const TELEGRAM: u16 = 1400;
    pub const SLACK: u16 = 1500;
    pub const TWILIO: u16 = 1600;
    pub const VOICE: u16 = 1700;
    pub const INCLUDED_AI: u16 = 1800;
    pub const MCP: u16 = 1900;
    pub const WEB_CONTENT_RULES: u16 = 2000;
    pub const SWAPS: u16 = 2100;
    /// The tail of the addon's `request` (a granted request's label).
    pub const REQUEST_TAIL: u16 = 2200;

    /// The checks W2 owns on the request side. A build in which any of these slots is empty does
    /// not have its checks, and intercepted traffic is refused (fail closed).
    pub const W2_REQUIRED: &[u16] = &[
        LOGIN_TRIPWIRE,
        EMAIL,
        TELEGRAM,
        SLACK,
        TWILIO,
        VOICE,
        MCP,
        WEB_CONTENT_RULES,
        // And on the other hooks: a build without one of these does not check what comes back.
        RESPONSE_MCP,
        RESPONSE_TELEGRAM_TAPS,
        RESPONSE_TELEGRAM_IN,
        RESPONSE_GMAIL_IN,
        RESPONSE_EMAIL_SETTLE,
        RESPONSE_AGENTMAIL,
        RESPONSE_PHONE_SETTLE,
        RESPONSE_VOICE,
        RESPONSE_LOGIN_LEARN,
        RESPONSE_LOGIN_REDACT,
        WS_AGENTMAIL,
        WS_SLACK,
        WS_VOICE,
        ERROR_MCP,
    ];
    // response, websocket, tcp, error: W1 and W2 add theirs here, in the addon's order.

    // W2's slots on the other hooks have numbers of their own, apart from the request's: a slot is
    // found by its number alone (`Pipeline::has_slot`), so a response step on a request number
    // would stand in for that request check in `W2_REQUIRED`.
    // response: W2's checks, in the addon's `response` order (addon.py 6820): MCP results,
    // Telegram taps, Telegram in, Gmail in, the email settle, AgentMail, the phone settle, the
    // voice token swap, then learning sign-in forms and redacting echoed logins.
    pub const RESPONSE_MCP: u16 = 3100;
    pub const RESPONSE_TELEGRAM_TAPS: u16 = 3200;
    pub const RESPONSE_TELEGRAM_IN: u16 = 3300;
    pub const RESPONSE_GMAIL_IN: u16 = 3400;
    pub const RESPONSE_EMAIL_SETTLE: u16 = 3500;
    pub const RESPONSE_AGENTMAIL: u16 = 3600;
    pub const RESPONSE_PHONE_SETTLE: u16 = 3700;
    pub const RESPONSE_VOICE: u16 = 3800;
    pub const RESPONSE_LOGIN_LEARN: u16 = 3900;
    pub const RESPONSE_LOGIN_REDACT: u16 = 4000;
    // websocket: W2's frame checks in `websocket_message`'s order (AgentMail, Slack, the voice).
    pub const WS_AGENTMAIL: u16 = 5100;
    pub const WS_SLACK: u16 = 5200;
    pub const WS_VOICE: u16 = 5300;
    // error: an MCP tool call that got no answer closes its row, before the record.
    pub const ERROR_MCP: u16 = 6100;

    // response: the addon's `response` runs its checks first, then the record. Checks go below this.
    /// The included key's 402 and a model provider's refusal, read just before the record.
    pub const MODEL_ANSWERS: u16 = 8900;
    /// The residential plain-HTTP record (response and error), before the allow record.
    pub const RESIDENTIAL_RECORD: u16 = 8800;
    pub const RESPONSE_LOG: u16 = 9000;
    // error: the record of an allowed request that got no answer, after any check's own clean-up.
    pub const ERROR_LOG: u16 = 9000;
}

struct Entry {
    slot: u16,
    seq: usize,
    step: Arc<dyn Step>,
}

/// The steps, sorted by slot.
#[derive(Default)]
pub struct Pipeline {
    steps: Vec<Entry>,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, slot: u16, step: Arc<dyn Step>) {
        let seq = self.steps.len();
        self.steps.push(Entry { slot, seq, step });
        self.steps.sort_by_key(|e| (e.slot, e.seq));
    }

    /// The step names in the order they run, for tests that pin the order.
    /// Whether a step is registered in this slot.
    pub fn has_slot(&self, slot: u16) -> bool {
        self.steps.iter().any(|e| e.slot == slot)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.steps.iter().map(|e| e.step.name()).collect()
    }

    /// Whether any step for `hook` reads this flow's body there (see [`Step::reads_body`]).
    /// Every step is asked (none is skipped once one says yes), so each takes its snapshots.
    pub fn reads_body(&self, hook: Hook, flow: &mut Flow) -> bool {
        let mut reads = false;
        for e in &self.steps {
            if e.step.hooks().contains(&hook) {
                reads |= e.step.reads_body(hook, flow);
            }
        }
        reads
    }

    /// The close signals of the steps that watch this websocket (see [`Step::closing`]).
    pub fn closing(&self, flow: &Flow) -> Vec<tokio::sync::watch::Receiver<bool>> {
        self.steps.iter().filter_map(|e| e.step.closing(flow)).collect()
    }

    /// Run every step registered for `hook`, in order, until one does not continue.
    pub async fn run(&self, hook: Hook, flow: &mut Flow) -> Verdict {
        for e in &self.steps {
            if !e.step.hooks().contains(&hook) {
                continue;
            }
            match e.step.run(hook, flow).await {
                Verdict::Continue => {}
                other => return other,
            }
        }
        Verdict::Continue
    }
}

/// Await `fut` for at most `limit`. Past it the flow is killed: a check that could not answer
/// refuses, it never lets through.
pub async fn hold<T>(limit: Duration, fut: impl Future<Output = T>) -> Result<T, Verdict> {
    tokio::time::timeout(limit, fut)
        .await
        .map_err(|_| Verdict::Kill("a check did not answer in time".into()))
}

/// Flows without sockets, for unit-testing steps (W2's checks above all).
pub mod testing {
    use super::*;

    /// A flow from `10.0.0.3` (agent `vm_test`) with this request buffered.
    pub fn request_flow(method: &str, url: &str, body: &'static [u8]) -> Flow {
        let uri: http::Uri = url.parse().unwrap_or_default();
        let host = uri.host().unwrap_or("example.com").to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let mut flow = Flow::new(
            IpAddr::from([10, 0, 0, 3]),
            Authority {
                host: host.clone(),
                port,
            },
        );
        flow.vm_id = Some("vm_test".into());
        flow.sni = Some(host.clone());
        flow.set_destination(super::Destination {
            name: host.to_ascii_lowercase(),
            port,
            addr: Some(std::net::SocketAddr::from(([203, 0, 113, 10], port))),
        });
        flow.request = http::Request::builder()
            .method(method)
            .uri(uri)
            .body(Bytes::from_static(body))
            .ok();
        flow
    }

    /// A request whose URL names one host while the flow really goes to `destination`: what a
    /// client that lies in its Host header looks like. A step must act on `destination`.
    pub fn lying_request_flow(method: &str, destination: &str, url: &str, body: &'static [u8]) -> Flow {
        let mut flow = request_flow(method, url, body);
        flow.sni = Some(destination.to_owned());
        flow.set_destination(super::Destination {
            name: destination.to_ascii_lowercase(),
            port: 443,
            addr: Some(std::net::SocketAddr::from(([203, 0, 113, 66], 443))),
        });
        flow
    }

    /// A flow carrying one websocket text frame.
    pub fn ws_text_flow(url: &str, direction: Direction, text: &str) -> Flow {
        let mut flow = request_flow("GET", url, b"");
        flow.ws_frame = Some(WsFrame {
            direction,
            kind: FrameKind::Text,
            payload: Bytes::from(text.to_owned()),
        });
        flow
    }

    /// A pipeline of just these steps, in slot order.
    pub fn pipeline(steps: Vec<(u16, Arc<dyn Step>)>) -> Pipeline {
        let mut p = Pipeline::new();
        for (slot, step) in steps {
            p.push(slot, step);
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    /// Records its name in `meta["seen"]`, then returns what it was built with.
    struct Mark(&'static str, fn() -> Verdict);

    impl Step for Mark {
        fn name(&self) -> &'static str {
            self.0
        }
        fn hooks(&self) -> &'static [Hook] {
            &[Hook::Request]
        }
        fn run<'a>(&'a self, _: Hook, flow: &'a mut Flow) -> StepFuture<'a> {
            Box::pin(async move {
                let seen = flow.meta.entry("seen").or_insert_with(|| serde_json::json!([]));
                if let Some(list) = seen.as_array_mut() {
                    list.push(self.0.into());
                }
                (self.1)()
            })
        }
    }

    fn cont() -> Verdict {
        Verdict::Continue
    }
    fn kill() -> Verdict {
        Verdict::Kill("no".into())
    }

    #[tokio::test]
    async fn runs_in_slot_order_and_stops_at_the_first_decision() {
        let p = pipeline(vec![
            (order::SWAPS, Arc::new(Mark("swaps", cont))),
            (order::VM_ID, Arc::new(Mark("vm", cont))),
            (order::BLOCK, Arc::new(Mark("block", kill))),
            (order::BLOCK, Arc::new(Mark("after-block", cont))),
        ]);
        assert_eq!(p.names(), ["vm", "block", "after-block", "swaps"]);
        let mut flow = request_flow("GET", "https://api.example.com/x", b"");
        assert!(matches!(p.run(Hook::Request, &mut flow).await, Verdict::Kill(_)));
        assert_eq!(flow.meta["seen"], serde_json::json!(["vm", "block"]));
        // Not registered for this hook: nothing runs.
        assert!(matches!(p.run(Hook::Response, &mut flow).await, Verdict::Continue));
    }

    #[tokio::test]
    async fn a_hold_that_runs_out_fails_closed() {
        let r = hold(Duration::from_millis(10), tokio::time::sleep(Duration::from_secs(5))).await;
        assert!(matches!(r, Err(Verdict::Kill(_))));
        assert!(hold(Duration::from_secs(1), async { 7 }).await.is_ok_and(|v| v == 7));
    }

    #[test]
    fn claimed_host_is_not_a_destination() {
        let flow = request_flow("GET", "https://api.example.com/x", b"");
        assert_eq!(flow.claimed_host().as_deref(), Some("api.example.com"));
        let lying = lying_request_flow(
            "POST",
            "attacker.example",
            "https://api.telegram.org/bot1/sendMessage",
            b"",
        );
        assert_eq!(lying.claimed_host().as_deref(), Some("api.telegram.org"));
        assert_eq!(lying.destination().map(|d| d.name.as_str()), Some("attacker.example"));
        assert_eq!(strip_port("Blocked.Example:443"), "Blocked.Example");
        assert_eq!(strip_port("[::1]:8080"), "::1");
        assert_eq!(strip_port("::1"), "::1");
        let f = ws_text_flow("https://wss.slack.com/link", Direction::In, "{}");
        assert_eq!(f.ws_frame.map(|w| w.kind), Some(FrameKind::Text));
    }
}
