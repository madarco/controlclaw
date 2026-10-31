//! Gmail push on the firewall (`gmail-push.ts`, docs/plans/email-rules.md §2.3).
//!
//! A Pub/Sub push only says "something changed in this mailbox, at history id N". The firewall
//! holds the real token, so it reads what changed itself: `history.list` from the last history id
//! it saw, then each new INBOX message's headers (never a body). Each message is checked against
//! the email rules, and only then does the agent box get a signed wake with the ids, the sender and
//! the subject. The watch (`users.watch`) is started and renewed here too.
//!
//! W3's webhooks call `watch`/`forget` (`core.webhooks.gmail`), and its ingress calls `on_push`
//! (`core.gmail_push`) with a body it verified (the Google OIDC rule of the registration). `wire`
//! connects them and renews the watches every 30 minutes (`index.ts:951-976`).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::channels::agent::{AgentCalls, Target};
use crate::channels::email::auth::GmailHeader;
use crate::channels::google::http::{GoogleHttp, Req};
use crate::channels::google::tokens::s;

const GMAIL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
/// Google expires a watch after seven days; renewing twice a day leaves plenty of room.
pub const WATCH_RENEW_MS: i64 = 12 * 3_600_000;
const SEEN_MAX: usize = 2000;
const HEADERS: [&str; 4] = ["From", "Subject", "Authentication-Results", "Message-ID"];
/// A wake the agent box keeps refusing must not hold every later email back.
pub const WAKE_ATTEMPTS: u32 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Watched {
    topic: String,
    at: i64,
    expiration: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    account: Option<String>,
    #[serde(rename = "historyId")]
    history_id: Option<String>,
    watched: IndexMap<String, Watched>,
    seen: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    failures: Option<IndexMap<String, u32>>,
}

/// The email rules' answer for one message: deliver, the reason it was not, and the sender.
pub type Verdict = (bool, Option<String>, Option<String>);
pub type VerdictFn = Arc<dyn Fn(&[GmailHeader], &[String]) -> Option<Verdict> + Send + Sync>;

pub struct GmailPushOptions {
    /// Plain JSON: history id, watch times, recently woken message ids. Nothing secret.
    pub state_path: PathBuf,
    /// The live account's address (lowercased) and token.
    pub access: Arc<dyn Fn() -> Option<(String, String)> + Send + Sync>,
    /// `None` when there are no email rules: nothing is woken for.
    pub verdict: VerdictFn,
    pub agent: Arc<dyn AgentCalls>,
    pub http: Arc<dyn GoogleHttp>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

pub struct GmailPush {
    opts: GmailPushOptions,
    serial: tokio::sync::Mutex<()>,
    state: Mutex<State>,
}

/// Something the processing could not get past: the history id stays where it was.
struct Stop;

/// `Buffer.from(s, "base64")`: padding optional, the URL-safe alphabet accepted, whitespace ignored.
fn node_base64(s: &str) -> Option<Vec<u8>> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(clean).ok()
}

fn enc(s: &str) -> String {
    crate::core::permissions::encode_uri_component(s)
}

impl GmailPush {
    pub fn new(opts: GmailPushOptions) -> Arc<Self> {
        // A file that does not parse starts over: the next push re-baselines the history id.
        let state = std::fs::read_to_string(&opts.state_path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Arc::new(Self {
            opts,
            serial: tokio::sync::Mutex::new(()),
            state: Mutex::new(state),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn save(&self, st: &mut State) {
        if st.seen.len() > SEEN_MAX {
            let cut = st.seen.len() - SEEN_MAX;
            st.seen.drain(..cut);
        }
        let path = &self.opts.state_path;
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return;
        };
        let tmp = path.with_file_name(format!(".{name}.tmp"));
        let Ok(body) = serde_json::to_string(&*st) else { return };
        // Kept in memory when this fails; the next push writes it again.
        let _ = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(body.as_bytes())?;
            std::fs::rename(&tmp, path)
        })();
    }

    async fn gmail(&self, token: &str, path: &str, post: Option<Value>) -> Result<(u16, Option<Value>), ()> {
        let mut req = Req::get(format!("{GMAIL}{path}"), token);
        req.timeout = Duration::from_secs(15);
        req.headers.push(("content-type".into(), "application/json".into()));
        if let Some(b) = post {
            req.method = "POST";
            req.body = Some(b.to_string().into_bytes());
        }
        let res = self.opts.http.send(req).await.map_err(|_| ())?;
        if !res.ok() {
            return Ok((res.status, None));
        }
        let body = serde_json::from_slice(&res.body).map_err(|_| ())?;
        Ok((res.status, Some(body)))
    }

    /// The account the stored history id belongs to; a different account starts over.
    fn access(&self) -> Option<(String, String)> {
        let (account, token) = (self.opts.access)()?;
        let mut st = self.lock();
        if st.account.as_deref() != Some(account.as_str()) {
            *st = State {
                account: Some(account.clone()),
                ..State::default()
            };
            self.save(&mut st);
        }
        Some((account, token))
    }

    /// Start or renew the watch on `topic` for one registration. Best effort; logged.
    pub async fn watch(&self, hook_id: &str, topic: &str) -> bool {
        let _serial = self.serial.lock().await;
        let Some((_, token)) = self.access() else {
            tracing::info!("[gmail-push] no live Google account; the watch is not started");
            return false;
        };
        let out = self
            .gmail(
                &token,
                "/watch",
                Some(json!({"topicName": topic, "labelIds": ["INBOX"], "labelFilterBehavior": "INCLUDE"})),
            )
            .await;
        match out {
            Ok((_, Some(body))) => {
                let mut st = self.lock();
                // Keep an existing position so nothing between the old watch and the new one is lost.
                if st.history_id.is_none() {
                    st.history_id = body.get("historyId").and_then(Value::as_str).map(str::to_string);
                }
                let exp = body
                    .get("expiration")
                    .and_then(|e| e.as_str().and_then(|x| x.parse::<f64>().ok()).or_else(|| e.as_f64()))
                    .filter(|x| x.is_finite());
                st.watched.insert(
                    hook_id.into(),
                    Watched {
                        topic: topic.into(),
                        at: (self.opts.now)(),
                        expiration: exp,
                    },
                );
                self.save(&mut st);
                tracing::info!("[gmail-push] watch started");
                true
            }
            Ok((status, None)) => {
                tracing::info!("[gmail-push] Gmail refused the watch (HTTP {status})");
                false
            }
            Err(()) => {
                tracing::info!("[gmail-push] the watch request failed");
                false
            }
        }
    }

    pub fn forget(&self, hook_id: &str) {
        let mut st = self.lock();
        st.watched.shift_remove(hook_id);
        self.save(&mut st);
    }

    /// Renew every watch that is due, or whose topic changed. Called on a timer.
    pub async fn renew_due(&self, hooks: &[(String, Option<String>)]) {
        for (id, topic) in hooks {
            let Some(topic) = topic else { continue };
            let due = {
                let st = self.lock();
                st.watched
                    .get(id)
                    .is_none_or(|w| &w.topic != topic || (self.opts.now)() - w.at >= WATCH_RENEW_MS)
            };
            if due {
                self.watch(id, topic).await;
            }
        }
    }

    /// One verified Pub/Sub delivery. Answered at once; the work runs behind it, one at a time,
    /// driven by the stored history id, so a push lost or delivered twice changes nothing.
    pub fn on_push(self: &Arc<Self>, target: Target, body_b64: &str) {
        let announced = match Self::parse(body_b64) {
            Some((email, announced)) => {
                let account = (self.opts.access)().map(|a| a.0);
                if let (Some(e), Some(a)) = (email, account)
                    && e.to_lowercase() != a
                {
                    tracing::info!("[gmail-push] a push for another mailbox was ignored");
                    return;
                }
                announced
            }
            None => {
                tracing::info!("[gmail-push] a push that did not parse was ignored");
                return;
            }
        };
        let me = self.clone();
        tokio::spawn(async move {
            let _serial = me.serial.lock().await;
            if me.process(&target, announced).await.is_err() {
                tracing::info!("[gmail-push] processing failed");
            }
        });
    }

    /// The envelope's `message.data`: the mailbox and the announced history id.
    fn parse(body_b64: &str) -> Option<(Option<String>, Option<String>)> {
        let envelope: Value = serde_json::from_slice(&node_base64(body_b64)?).ok()?;
        let data = envelope
            .get("message")
            .and_then(|m| m.get("data"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let data: Value = serde_json::from_slice(&node_base64(data)?).ok()?;
        let announced = match data.get("historyId") {
            None => None,
            Some(Value::String(h)) => Some(h.clone()),
            Some(v) => Some(v.to_string()),
        };
        Some((
            data.get("emailAddress").and_then(Value::as_str).map(str::to_string),
            announced,
        ))
    }

    async fn process(&self, target: &Target, announced: Option<String>) -> Result<(), Stop> {
        let Some((_, token)) = self.access() else { return Ok(()) };
        let start = self.lock().history_id.clone();
        let Some(start) = start else {
            // Nothing to compare with yet: start counting from here.
            let mut st = self.lock();
            st.history_id = announced;
            self.save(&mut st);
            return Ok(());
        };
        let mut ids: Vec<String> = vec![];
        let mut page_token: Option<String> = None;
        let mut latest = start.clone();
        for _ in 0..10 {
            let query = {
                let mut q = url::form_urlencoded::Serializer::new(String::new());
                q.append_pair("startHistoryId", &start)
                    .append_pair("historyTypes", "messageAdded")
                    .append_pair("labelId", "INBOX")
                    .append_pair("maxResults", "100");
                if let Some(t) = &page_token {
                    q.append_pair("pageToken", t);
                }
                q.finish()
            };
            let (status, body) = self
                .gmail(&token, &format!("/history?{query}"), None)
                .await
                .map_err(|_| Stop)?;
            if status == 404 {
                // Too old for Gmail: start again from the announced one. Mail in the gap is not
                // woken for, which is safer than waking for all of it.
                tracing::info!("[gmail-push] history id expired; starting again from the latest push");
                let mut st = self.lock();
                st.history_id = announced;
                self.save(&mut st);
                return Ok(());
            }
            let body = body.ok_or(Stop)?;
            for h in body.get("history").and_then(Value::as_array).into_iter().flatten() {
                for added in h.get("messagesAdded").and_then(Value::as_array).into_iter().flatten() {
                    let msg = added.get("message");
                    let Some(id) = msg.and_then(|m| s(m.get("id"))) else {
                        continue;
                    };
                    let labels: Vec<&str> = msg
                        .and_then(|m| m.get("labelIds"))
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    if labels.contains(&"INBOX")
                        && !labels.contains(&"SENT")
                        && !labels.contains(&"DRAFT")
                        && !ids.contains(&id)
                    {
                        ids.push(id);
                    }
                }
            }
            if let Some(h) = s(body.get("historyId")) {
                latest = h;
            }
            page_token = s(body.get("nextPageToken"));
            if page_token.is_none() {
                break;
            }
        }
        for id in ids {
            if self.lock().seen.contains(&id) {
                continue;
            }
            let query = {
                let mut q = url::form_urlencoded::Serializer::new(String::new());
                q.append_pair("format", "metadata");
                for h in HEADERS {
                    q.append_pair("metadataHeaders", h);
                }
                q.finish()
            };
            let (status, body) = self
                .gmail(&token, &format!("/messages/{}?{query}", enc(&id)), None)
                .await
                .map_err(|_| Stop)?;
            if status == 404 {
                continue; // deleted in the meantime
            }
            let body = body.ok_or(Stop)?;
            let headers: Vec<GmailHeader> = body
                .get("payload")
                .and_then(|p| p.get("headers"))
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|h| {
                            Some(GmailHeader {
                                name: h.get("name")?.as_str()?.into(),
                                value: h.get("value")?.as_str()?.into(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let labels: Vec<String> = body
                .get("labelIds")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                .unwrap_or_default();
            let verdict = (self.opts.verdict)(&headers, &labels);
            let Some((true, _, from)) = verdict.clone() else {
                let mut st = self.lock();
                st.seen.push(id);
                self.save(&mut st);
                tracing::info!(
                    "[gmail-push] a message was not woken for ({})",
                    verdict.and_then(|v| v.1).unwrap_or_else(|| "no email rules".into())
                );
                continue;
            };
            let subject = headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("subject"))
                .map_or(String::new(), |h| crate::channels::js::js_slice(&h.value, 998));
            let wake = json!({"messageId": body.get("id"), "threadId": body.get("threadId"), "from": from, "subject": subject});
            if self
                .opts
                .agent
                .post(target, "/hooks/gmail-wake", wake, None)
                .await
                .is_err()
            {
                let mut st = self.lock();
                let failures = st.failures.get_or_insert_with(IndexMap::new);
                let n = failures.entry(id.clone()).or_insert(0);
                *n += 1;
                if *n < WAKE_ATTEMPTS {
                    // The history id stays where it was, so the next push tries this one again.
                    self.save(&mut st);
                    tracing::info!("[gmail-push] the agent could not be woken; will retry on the next push");
                    return Err(Stop);
                }
                failures.shift_remove(&id);
                st.seen.push(id);
                self.save(&mut st);
                tracing::info!("[gmail-push] gave up waking the agent for a message after {WAKE_ATTEMPTS} attempts");
                continue;
            }
            let mut st = self.lock();
            if let Some(f) = st.failures.as_mut() {
                f.shift_remove(&id);
            }
            st.seen.push(id);
            self.save(&mut st);
            tracing::info!("[gmail-push] agent woken for a new message");
        }
        let mut st = self.lock();
        st.history_id = Some(latest);
        self.save(&mut st);
        Ok(())
    }
}

#[cfg(test)]
#[path = "gmail_push_tests.rs"]
mod tests;

/// W3's webhooks, as Gmail registrations come and go: watch the mailbox, and turn OpenClaw's hook on
/// now so the first email does not wait for a gateway restart.
struct Hooks {
    push: Arc<GmailPush>,
    agent: Arc<dyn AgentCalls>,
}

impl crate::core::webhooks::GmailHooks for Hooks {
    fn configure(&self, hook_id: &str, target: &crate::core::ingress::Target, topic: Option<&str>) {
        if let Some(topic) = topic.filter(|t| !t.is_empty()) {
            let (push, id, topic) = (self.push.clone(), hook_id.to_string(), topic.to_string());
            tokio::spawn(async move {
                push.watch(&id, &topic).await;
            });
        }
        let (agent, t) = (self.agent.clone(), Target::new(&target.vm_id, &target.hostname));
        tokio::spawn(async move {
            let _ = agent
                .post(&t, "/hooks/gmail-wake", json!({"configure": true}), None)
                .await;
        });
    }
    fn stop(&self, hook_id: &str) {
        self.push.forget(hook_id);
    }
}

/// Build the push and hand it to W3's webhooks and ingress. Nothing is wired on a box without the
/// webhooks module (no control channel).
pub fn wire(
    google: Arc<crate::channels::google::GoogleFirewall>,
    http: Arc<dyn GoogleHttp>,
    agent: Arc<dyn AgentCalls>,
    verdict: VerdictFn,
) {
    let Some(core) = crate::core::core() else { return };
    let Some(webhooks) = core.webhooks.get().cloned() else {
        return;
    };
    let g = google.clone();
    let push = GmailPush::new(GmailPushOptions {
        state_path: PathBuf::from("/opt/controlclaw/state/gmail-push.json"),
        access: Arc::new(move || g.gmail_access()),
        verdict,
        agent: agent.clone(),
        http,
        now: Arc::new(crate::channels::now_ms),
    });
    let _ = webhooks.gmail.set(Arc::new(Hooks {
        push: push.clone(),
        agent,
    }));
    let g = google.clone();
    let _ = webhooks.gmail_account.set(Arc::new(move || {
        g.summary()["account"]["accountLabel"].as_str().map(str::to_string)
    }));
    let p = push.clone();
    let _ = core.gmail_push.set(Arc::new(move |t, body_b64| {
        p.on_push(Target::new(&t.vm_id, &t.hostname), &body_b64);
    }));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30 * 60)).await;
            push.renew_due(&webhooks.gmail_hooks()).await;
        }
    });
}
