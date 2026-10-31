//! Content rules (docs/plans/firewall-content-rules.md): what an organization says its agents may
//! not send or receive, checked on the text of a message. One engine ([`engine`]) and one adapter
//! per channel (Telegram, Slack, email, web, apps, voice). The rules come from the mitm-agent
//! (`content-rules.ts`), which writes them only after a change was confirmed with a code; the proxy
//! only reads them. The "Leaking secrets" rule is not in that file: it ships here.
//!
//! Fail closed: a check that cannot run stops the message. Each adapter catches its own errors
//! and refuses.
//!
//! This module is addon.py 5006-5440 and the shared helpers around `_content_hold` (5760-5845).

pub mod detect;
pub mod engine;
pub mod rules;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use self::engine::{Action, Found, PolicyAsk, Rule, TooLong};
use self::rules::{OwnMarker, RuleFile, Unreadable};
use crate::checks::env::Settings;
use crate::checks::{loopback, pyjson};
use crate::flow::Flow;

/// The text the engine read, handed over with a hold: the approver's preview is built from it.
pub const HOLD_TEXT_MAX: usize = 8192;
pub const HOLD_BODY_MAX: usize = 262_144;
/// Of a stopped text, the mitm-agent keeps this much (`STOPPED_TEXT_MAX` in content-stopped.ts).
pub const STOPPED_TEXT_MAX: usize = 2000;
/// How long a hold waits for the mitm-agent, longer than it can take to ask everyone.
pub const HOLD_WAIT: Duration = Duration::from_secs(25);
/// A read the agent repeats is recorded once in this long.
const AUDIT_ONCE: Duration = Duration::from_secs(3600);

/// Flow metadata keys, the addon's names.
pub const META_STOPPED: &str = "cc_content_stopped";
pub const META_AI: &str = "cc_content_ai";

/// Why a check could not run, so the adapter refuses with the right words.
#[derive(Debug, thiserror::Error)]
pub enum CheckError {
    #[error(transparent)]
    TooLong(#[from] TooLong),
    #[error(transparent)]
    Unreadable(#[from] Unreadable),
    #[error("{0}")]
    Failed(String),
}

impl From<loopback::CallError> for CheckError {
    fn from(e: loopback::CallError) -> Self {
        Self::Failed(e.to_string())
    }
}

/// A message the mitm-agent is holding: its answer, and the key that cancels it.
pub struct Held {
    pub answer: Map<String, Value>,
    pub key: String,
}

/// The content rules' state, shared by every adapter.
pub struct Content {
    pub settings: Settings,
    pub file: RuleFile,
    pub own: OwnMarker,
    pub ask: PolicyAsk,
    audit_lock: Mutex<HashMap<String, Instant>>,
}

impl Content {
    pub fn new(settings: Settings) -> Arc<Self> {
        Arc::new(Self {
            file: RuleFile::new(settings.content_rules_path.clone()),
            own: OwnMarker::new(settings.content_own_path.clone()),
            ask: PolicyAsk {
                url: settings.content_policy_url.clone(),
                timeout: settings.content_policy_timeout,
            },
            audit_lock: Mutex::new(HashMap::new()),
            settings,
        })
    }

    pub fn rules(&self) -> Result<Arc<Vec<Rule>>, Unreadable> {
        self.file.rules()
    }

    /// `_content_audit`: the firewall's own record of a rule that fired. Metadata only, never the
    /// text: a block's text goes to the mitm-agent's encrypted record instead. `once` names the
    /// message on a read the agent repeats: recorded once an hour, under the same id.
    #[allow(clippy::too_many_arguments)] // the addon's `_content_audit`, argument for argument
    pub fn audit(
        &self,
        flow: Option<&mut Flow>,
        rule_id: &str,
        channel: &str,
        direction: &str,
        action: &str,
        once: Option<&str>,
        extra: Map<String, Value>,
    ) {
        let (vm_id, flow_id, stopping, by) = match flow {
            Some(f) => {
                let stopping = if action == "block" {
                    take_stopped(f, rule_id)
                } else {
                    None
                };
                let by = f
                    .meta
                    .get(META_AI)
                    .and_then(|m| m.get(rule_id))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                (f.vm_id.clone(), Some(f.id.clone()), stopping, by)
            }
            None => (None, None, None, None),
        };
        let mut line_id = uuid::Uuid::new_v4().simple().to_string()[..24].to_owned();
        if let Some(once) = once {
            // `f"{vm_id}"` is `None` for no agent.
            let key = format!(
                "{rule_id}|{channel}|{direction}|{action}|{}|{once}",
                vm_id.as_deref().unwrap_or("None")
            );
            {
                let mut seen = self
                    .audit_lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                if seen.get(&key).is_some_and(|t| now.duration_since(*t) < AUDIT_ONCE) {
                    return;
                }
                if seen.len() > 10000 {
                    seen.clear();
                }
                seen.insert(key.clone(), now);
            }
            line_id = hex::encode(Sha256::digest(key.as_bytes()))[..24].to_owned();
        }
        let mut rec = Map::new();
        rec.insert("ts".into(), json!(rules::now()));
        rec.insert("id".into(), json!(line_id));
        rec.insert("rule".into(), json!(rule_id));
        rec.insert("channel".into(), json!(channel));
        rec.insert("direction".into(), json!(direction));
        rec.insert("action".into(), json!(action));
        rec.insert("vm_id".into(), json!(vm_id));
        rec.insert("flow_id".into(), json!(flow_id));
        if let Some(by) = by {
            rec.insert("ai".into(), json!(by));
        }
        rec.extend(extra);
        let line = pyjson::dumps(&rec);
        tracing::info!("[content-rules] {line}");
        // Holds are recorded by the mitm-agent, which keeps them; a check that failed has no text worth keeping.
        if let Some((rule, text)) = stopping.filter(|_| rule_id != "error") {
            self.stopped(vm_id.as_deref(), &rule, channel, direction, &text, &line_id);
        }
        let Some(path) = &self.settings.content_audit_path else {
            return;
        };
        let _guard = self
            .audit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(e) = append_rotating(path, self.settings.log_max_bytes, &line) {
            tracing::warn!("[content-rules] audit write failed: {e}");
        }
    }

    /// `_content_stopped`: fire and forget, a stopped text to the mitm-agent's encrypted record.
    /// A rule that looks for secrets sends none: the record would be one more copy.
    pub fn stopped(&self, vm_id: Option<&str>, rule: &Rule, channel: &str, direction: &str, text: &str, line_id: &str) {
        let payload = stopped_payload(vm_id, rule, channel, direction, text, line_id);
        self.fire("/stopped", payload, "stopped text not handed over");
    }

    /// `_content_notice`: fire and forget, the firewall's own notice to the person in the chat.
    pub fn notice(&self, payload: Value) {
        self.fire("/notice", payload, "notice not handed over");
    }

    fn fire(&self, path: &'static str, payload: Value, what: &'static str) {
        let url = format!("{}{path}", self.settings.content_rules_url);
        let send = async move {
            if let Err(e) = post(&url, &payload, Duration::from_secs(5)).await {
                tracing::warn!("[content-rules] {what}: {e}");
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(send);
            }
            // Outside a runtime (a direct call from a plain thread): sent on a thread of its own.
            Err(_) => {
                std::thread::spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                        rt.block_on(send);
                    }
                });
            }
        }
    }

    /// `_content_post`: loopback to the mitm-agent. An error on anything but a JSON object.
    pub async fn post(&self, path: &str, payload: &Value, timeout: Duration) -> Result<Map<String, Value>, CheckError> {
        post(&format!("{}{path}", self.settings.content_rules_url), payload, timeout).await
    }

    /// `_content_hold`: hand a message to the mitm-agent to keep and ask about. Its answer, or
    /// `None` when nobody could be asked. When the wait fails the hold is cancelled (the agent is
    /// told it was stopped, so it must not survive) and the error returned.
    pub async fn hold(&self, flow: &mut Flow, mut payload: Map<String, Value>) -> Result<Option<Held>, CheckError> {
        if let Some(id) = payload.get("rule").and_then(|r| r.get("id")).and_then(Value::as_str) {
            unstop(flow, id);
        }
        let key = uuid::Uuid::new_v4().simple().to_string();
        payload.insert("key".into(), json!(key));
        let answer = match self.post("/hold", &Value::Object(payload), HOLD_WAIT).await {
            Ok(a) => a,
            Err(e) => {
                self.cancel(&key).await;
                return Err(e);
            }
        };
        let held = answer.get("ok") == Some(&Value::Bool(true)) && answer.get("holdId").is_some_and(Value::is_string);
        Ok(held.then_some(Held { answer, key }))
    }

    /// `_held_answer`: the agent is told its message went (decided 2026-10-15): the people who get
    /// codes decide. The record says `hold`, and so does the audit line, with the hold's id.
    pub fn held_answer(
        &self,
        flow: &mut Flow,
        rule: &Rule,
        channel: &str,
        hold_id: Value,
        status: u16,
        body: &Value,
    ) -> crate::flow::Verdict {
        let v = crate::checks::answer(flow, status, body, "hold", &format!("content: {}", rule.id), Map::new());
        let mut x = Map::new();
        x.insert("hold".into(), hold_id);
        self.audit(Some(flow), &rule.id, channel, "out", "hold", None, x);
        v
    }

    pub async fn cancel(&self, key: &str) {
        if let Err(e) = self.post("/cancel", &json!({"key": key}), Duration::from_secs(5)).await {
            tracing::warn!("[content-rules] hold cancel not handed over: {e}");
        }
    }

    /// `_content_own_ask`: the text with the firewall's own part taken out; `None` on any failure,
    /// so the message is checked whole.
    pub async fn own_ask(&self, text: &str) -> Option<String> {
        match self.post("/own", &json!({"text": text}), Duration::from_secs(2)).await {
            Ok(doc) => doc.get("rest").and_then(Value::as_str).map(str::to_owned),
            Err(e) => {
                tracing::warn!("[content-rules] could not ask about the firewall's own text: {e}");
                None
            }
        }
    }

    /// `_content_out_evaluate`: the engine and the policies on a Telegram or Slack message going
    /// out (the channels a code goes on). When a rule would act, or a policy is to be asked, and
    /// the marker is fresh, the mitm-agent is asked for the message with the firewall's own text
    /// taken out, and the rest is checked. The text that was checked comes back with the result.
    pub async fn out_evaluate(
        &self,
        rules: &[Rule],
        channel: &str,
        text: String,
        vm_id: Option<&str>,
    ) -> Result<(Found, String), CheckError> {
        let mut text = text;
        let mut found = evaluate_shown(rules, "out", channel, &text).await?;
        let policies = engine::policy_applies(rules, "out", channel);
        let acts = found.winner.as_ref().is_some_and(|w| w.action != Action::Log);
        if (acts || policies)
            && self.own.fresh()
            && let Some(rest) = self.own_ask(&text).await
        {
            text = rest;
            found = evaluate_shown(rules, "out", channel, &text).await?;
        }
        if policies {
            found = engine::judge(&self.ask, rules, "out", channel, &text, Some(found), vm_id).await?;
        }
        Ok((found, text))
    }

    /// `_content_acted`: every log-only hit recorded, and the rule that acts (block or hold).
    pub fn acted(
        &self,
        mut flow: Option<&mut Flow>,
        found: Found,
        direction: &str,
        channel: &str,
        text: &str,
        once: Option<&str>,
    ) -> Option<Rule> {
        if let Some(f) = flow.as_deref_mut() {
            mark(f, &found.hits);
        }
        for hit in found.hits.iter().filter(|h| h.action == Action::Log) {
            self.audit(
                flow.as_deref_mut(),
                &hit.id,
                channel,
                direction,
                "log",
                once,
                Map::new(),
            );
        }
        let rule = found.winner.filter(|w| w.action != Action::Log)?;
        if let Some(f) = flow {
            stopping(f, &rule, text);
        }
        Some(rule)
    }

    /// `_content_acting`: the engine and the policies on one text, then [`Self::acted`].
    pub async fn acting(
        &self,
        flow: Option<&mut Flow>,
        rules: &[Rule],
        direction: &str,
        channel: &str,
        text: &str,
        once: Option<&str>,
    ) -> Result<Option<Rule>, CheckError> {
        self.acting_found(flow, rules, direction, channel, text, once, None)
            .await
    }

    /// [`Self::acting`] with `found`: the engine's answer, when the caller read the text its own way.
    #[allow(clippy::too_many_arguments)]
    pub async fn acting_found(
        &self,
        flow: Option<&mut Flow>,
        rules: &[Rule],
        direction: &str,
        channel: &str,
        text: &str,
        once: Option<&str>,
        found: Option<Found>,
    ) -> Result<Option<Rule>, CheckError> {
        let vm_id = flow.as_ref().and_then(|f| f.vm_id.clone());
        let found = engine::judge(&self.ask, rules, direction, channel, text, found, vm_id.as_deref()).await?;
        Ok(self.acted(flow, found, direction, channel, text, once))
    }
}

#[allow(clippy::expect_used)] // fixed expressions, checked by the tests
mod shown_re {
    use regex::Regex;
    use std::sync::LazyLock;
    pub static MARKUP_TAG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"</?[A-Za-z][^<>]*>").expect("valid"));
    // MarkdownV2 lets any character from 1 to 126 be escaped.
    pub static MARKDOWN_ESCAPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\\([\x01-\x7e])").expect("valid"));
    pub static MARKDOWN_MARKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[*_~`|\[\]]").expect("valid"));
    // A Markdown link (`[label](url)`) and a Slack one (`<url|label>`): the chat shows the label.
    pub static MARKDOWN_LINK: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\[((?:\\.|[^\]\\])*)\]\((?:\\.|[^)\\])*\)").expect("valid"));
    pub static SLACK_LINK: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<([^<>|]*)\|([^<>]*)>").expect("valid"));
}

/// `_rendered`: the text, and the text as the chat shows it when the message is formatted: links
/// as their labels, then HTML tags out and entities decoded, or Markdown escapes and marks out.
/// Only the ways that differ, so a plain message is read once.
pub fn rendered(text: &str) -> Vec<String> {
    use shown_re::*;
    let mut variants = vec![text.to_owned()];
    let linked = if text.contains('|') {
        SLACK_LINK.replace_all(text, "${2}").into_owned()
    } else {
        text.to_owned()
    };
    if text.contains('<') || text.contains('&') {
        variants.push(crate::checks::mime::unescape(&MARKUP_TAG.replace_all(&linked, "")));
    }
    if text.contains('\\') || MARKDOWN_MARKS.is_match(text) {
        // Links first, on the text as written: an escaped `\)` belongs to the URL.
        let labelled = MARKDOWN_LINK.replace_all(&linked, "${1}");
        let labelled = MARKDOWN_ESCAPE.replace_all(&labelled, "${1}");
        variants.push(MARKDOWN_MARKS.replace_all(&labelled, "").into_owned());
    }
    let mut seen = Vec::new();
    for v in variants {
        if !seen.contains(&v) {
            seen.push(v);
        }
    }
    seen
}

/// `_content_evaluate_shown`: the engine on the text and on each way the chat can show it, each
/// on its own, so the length limit is the message's and not the sum: every hit, and the winner.
pub async fn evaluate_shown(rules: &[Rule], direction: &str, channel: &str, text: &str) -> Result<Found, TooLong> {
    let mut all = Found {
        winner: None,
        hits: Vec::new(),
    };
    for variant in rendered(text) {
        let found = engine::evaluate_off(rules, direction, channel, &variant).await?;
        for h in found.hits {
            if !all.hits.contains(&h) {
                all.hits.push(h);
            }
        }
        if let Some(r) = found.winner
            && all.winner.as_ref().is_none_or(|w| r.action > w.action)
        {
            all.winner = Some(r);
        }
    }
    Ok(all)
}

async fn post(url: &str, payload: &Value, timeout: Duration) -> Result<Map<String, Value>, CheckError> {
    match loopback::post_json(url, payload, timeout).await? {
        Value::Object(m) => Ok(m),
        _ => Err(CheckError::Failed("unexpected answer".into())),
    }
}

pub fn stopped_payload(
    vm_id: Option<&str>,
    rule: &Rule,
    channel: &str,
    direction: &str,
    text: &str,
    line_id: &str,
) -> Value {
    let secret = rule.id == engine::CORE_SECRETS_ID || rule.detectors.contains(&detect::Detector::Secrets);
    json!({
        "vmId": vm_id.filter(|v| !v.is_empty()),
        "rule": rule.brief(),
        "channel": channel,
        "direction": direction,
        "id": line_id,
        // One more than the record keeps, so it knows the text was cut.
        "text": if secret { String::new() } else { engine::cut(text, STOPPED_TEXT_MAX + 1) },
    })
}

/// `_content_mark`: the AI's part in each hit, left on the flow for the audit lines.
pub fn mark(flow: &mut Flow, hits: &[Rule]) {
    for hit in hits {
        if let Some(by) = &hit.by {
            let m = flow.meta.entry(META_AI).or_insert_with(|| json!({}));
            if let Some(o) = m.as_object_mut() {
                o.insert(hit.id.clone(), json!(by));
            }
        }
    }
}

/// `_content_stopping`: the text a rule acts on, left on the flow for the audit line that records
/// the block.
pub fn stopping(flow: &mut Flow, rule: &Rule, text: &str) {
    if matches!(rule.action, Action::Block | Action::Hold) {
        let m = flow.meta.entry(META_STOPPED).or_insert_with(|| json!({}));
        if let Some(o) = m.as_object_mut() {
            o.insert(rule.id.clone(), json!({"rule": rule, "text": text}));
        }
    }
}

/// `_content_unstop`: a hold is recorded by the mitm-agent, kept or not, so the proxy does not.
pub fn unstop(flow: &mut Flow, rule_id: &str) {
    if let Some(o) = flow.meta.get_mut(META_STOPPED).and_then(Value::as_object_mut) {
        o.remove(rule_id);
    }
}

fn take_stopped(flow: &mut Flow, rule_id: &str) -> Option<(Rule, String)> {
    let v = flow.meta.get_mut(META_STOPPED)?.as_object_mut()?.remove(rule_id)?;
    let rule: Rule = serde_json::from_value(v.get("rule")?.clone()).ok()?;
    Some((rule, v.get("text")?.as_str()?.to_owned()))
}

/// Append one line to a JSONL file, moving it to `<path>.1` once it has reached `max` bytes.
pub fn append_rotating(path: &std::path::Path, max: u64, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if std::fs::metadata(path).is_ok_and(|m| m.len() >= max) {
        let mut rotated = path.as_os_str().to_owned();
        rotated.push(".1");
        std::fs::rename(path, rotated)?;
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(format!("{line}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::{Answer, Rig};
    use crate::flow::testing::request_flow;

    fn rule(id: &str, action: &str, detectors: &[&str]) -> Rule {
        Rule::from_json(
            &json!({"id": id, "name": id, "direction": "out", "channels": ["telegram"], "patterns": [],
                                "detectors": detectors, "action": action, "reason": format!("{id} reason")}),
        )
        .expect("rule")
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    #[tokio::test]
    async fn audit_lines_and_stopped_texts() {
        let rig = Rig::new().await;
        let mut flow = request_flow("POST", "https://api.telegram.org/bot1:x/sendMessage", b"");
        let cust = rule("cust", "block", &[]);
        stopping(&mut flow, &cust, "Here is the customer list.");
        rig.content
            .audit(Some(&mut flow), "cust", "telegram", "out", "block", None, Map::new());
        settle().await;
        let line = rig.audit().pop().expect("a line");
        assert_eq!(line["rule"], "cust");
        assert_eq!(line["vm_id"], "vm_test");
        assert_eq!(line["flow_id"], json!(flow.id));
        assert_eq!(line["id"].as_str().map(str::len), Some(24));
        let raw = std::fs::read_to_string(rig.dir.path().join("content-rules.jsonl")).unwrap_or_default();
        assert!(!raw.contains("customer"), "the audit log never holds the text");
        assert_eq!(
            rig.agent.calls("/stopped"),
            vec![
                json!({"vmId": "vm_test", "rule": {"id": "cust", "name": "cust", "reason": "cust reason"}, "channel": "telegram",
                        "direction": "out", "id": line["id"], "text": "Here is the customer list."})
            ]
        );
        // Taken once: a second block line on the same flow sends nothing.
        rig.content
            .audit(Some(&mut flow), "cust", "telegram", "out", "block", None, Map::new());
        settle().await;
        assert_eq!(rig.agent.calls("/stopped").len(), 1);

        // A rule that looks for secrets sends no text; a long one is cut to one more than kept.
        let p = stopped_payload(
            Some("vm1"),
            &engine::core_secrets_rule(),
            "web",
            "out",
            "sk-live-1",
            "x",
        );
        assert_eq!(
            (p["text"].as_str(), p["rule"]["id"].as_str()),
            (Some(""), Some(engine::CORE_SECRETS_ID))
        );
        let p = stopped_payload(Some("vm1"), &cust, "web", "out", &"x".repeat(5000), "x");
        assert_eq!(p["text"].as_str().map(str::len), Some(STOPPED_TEXT_MAX + 1));
        assert_eq!(
            stopped_payload(Some(""), &cust, "web", "out", "t", "x")["vmId"],
            Value::Null
        );
    }

    #[tokio::test]
    async fn a_repeated_read_is_recorded_once_an_hour_under_one_id() {
        let rig = Rig::new().await;
        for _ in 0..2 {
            rig.content
                .audit(None, "cust", "email", "in", "block", Some("thread-1"), Map::new());
        }
        assert_eq!(rig.audit().len(), 1);
        rig.content.audit_lock.lock().expect("lock").clear();
        rig.content
            .audit(None, "cust", "email", "in", "block", Some("thread-1"), Map::new());
        let lines = rig.audit();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["id"], lines[1]["id"]);
        let key = "cust|email|in|block|None|thread-1";
        assert_eq!(
            lines[0]["id"],
            json!(hex::encode(Sha256::digest(key.as_bytes()))[..24].to_owned())
        );
        assert_eq!(lines[0]["vm_id"], Value::Null);
    }

    #[tokio::test]
    async fn the_audit_file_rotates() {
        let rig = Rig::new().await;
        let path = rig.dir.path().join("x.jsonl");
        append_rotating(&path, 10, "0123456789").expect("write");
        append_rotating(&path, 10, "next").expect("write");
        assert_eq!(std::fs::read_to_string(&path).expect("live"), "next\n");
        assert!(rig.dir.path().join("x.jsonl.1").exists());
    }

    #[tokio::test]
    async fn a_hold_that_fails_is_cancelled() {
        let rig = Rig::new().await;
        let mut flow = request_flow("POST", "https://api.telegram.org/bot1:x/sendMessage", b"");
        let iban = rule("iban", "hold", &["iban"]);
        stopping(&mut flow, &iban, "t");
        rig.agent.answer(
            "/hold",
            Answer::json(200, json!({"ok": true, "holdId": "h1", "messageId": 7})),
        );
        let mut p = Map::new();
        p.insert("rule".into(), iban.brief());
        let a = rig.content.hold(&mut flow, p.clone()).await.expect("held");
        assert_eq!(a.and_then(|a| a.answer.get("holdId").cloned()), Some(json!("h1")));
        assert!(
            flow.meta[META_STOPPED].as_object().is_some_and(Map::is_empty),
            "a hold is not kept as stopped"
        );
        assert_eq!(rig.agent.calls("/hold")[0]["key"].as_str().map(str::len), Some(32));

        rig.agent.answer("/hold", Answer::json(200, json!({"ok": false})));
        rig.agent.answer("/hold", Answer::json(200, json!({"ok": false})));
        assert!(
            rig.content
                .hold(&mut flow, p.clone())
                .await
                .expect("answered")
                .is_none(),
            "nobody could be asked"
        );

        let rig = Rig::new().await;
        rig.agent.answer("/hold", Answer::json(500, json!({})));
        assert!(rig.content.hold(&mut flow, p).await.is_err());
        let key = rig.agent.calls("/hold")[0]["key"].clone();
        assert_eq!(rig.agent.calls("/cancel"), vec![json!({"key": key})]);
    }

    #[tokio::test]
    async fn the_ai_part_is_marked_on_the_audit_line() {
        let rig = Rig::new().await;
        let mut salary = rule("salary", "block", &[]);
        salary.policy = Some("salary".into());
        let watch = Rule {
            id: "watch".into(),
            action: Action::Log,
            ..salary.clone()
        };
        rig.judge
            .answer("/content", Answer::json(200, json!({"matches": ["salary", "watch"]})));
        let mut flow = request_flow("POST", "https://api.telegram.org/bot1:x/sendMessage", b"");
        let acting = rig
            .content
            .acting(
                Some(&mut flow),
                &[salary, watch],
                "out",
                "telegram",
                "Anna earns 92k",
                None,
            )
            .await
            .expect("checked");
        assert_eq!(acting.map(|r| r.id).as_deref(), Some("salary"));
        assert_eq!(rig.judge.calls("/content")[0]["vm_id"], "vm_test");
        rig.content
            .audit(Some(&mut flow), "salary", "telegram", "out", "block", None, Map::new());
        let lines = rig.audit();
        assert_eq!(
            (
                lines[0]["rule"].as_str(),
                lines[0]["action"].as_str(),
                lines[0]["ai"].as_str()
            ),
            (Some("watch"), Some("log"), Some("found"))
        );
        assert_eq!(
            (lines[1]["rule"].as_str(), lines[1]["ai"].as_str()),
            (Some("salary"), Some("found"))
        );
    }

    #[tokio::test]
    async fn the_firewalls_own_text_is_taken_out() {
        let rig = Rig::new().await;
        let words = Rule::from_json(
            &json!({"id": "w", "name": "w", "direction": "out", "channels": ["telegram"],
            "patterns": ["customer list"], "detectors": [], "action": "block", "reason": "r"}),
        )
        .expect("rule");
        let rules = vec![engine::core_secrets_rule(), words];
        let mine = "ControlClaw: Code: 123 456\nWords: customer list";
        // No marker: the agent is not asked.
        let (f, _) = rig
            .content
            .out_evaluate(&rules, "telegram", mine.into(), None)
            .await
            .expect("checked");
        assert_eq!(f.winner.map(|w| w.id).as_deref(), Some("w"));
        assert!(rig.agent.calls("/own").is_empty());
        std::fs::write(
            rig.dir.path().join("content-own.json"),
            format!(r#"{{"until": {}}}"#, rules::now() + 60.0),
        )
        .expect("marker");
        rig.agent.answer("/own", Answer::json(200, json!({"rest": "\n"})));
        let (f, text) = rig
            .content
            .out_evaluate(&rules, "telegram", mine.into(), None)
            .await
            .expect("checked");
        assert!(f.winner.is_none());
        assert_eq!(text, "\n");
        // The agent cannot answer: the message is checked whole.
        rig.agent.answer("/own", Answer::json(500, json!({})));
        let (f, _) = rig
            .content
            .out_evaluate(&rules, "telegram", mine.into(), None)
            .await
            .expect("checked");
        assert!(f.winner.is_some());
    }
}
