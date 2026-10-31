//! The engine (addon.py `content_evaluate`, `content_judge`): which rules a text breaks and which
//! one acts. Pure except for the AI check, which is one call to the judge's `/content`.

use std::collections::HashSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::detect::{self, Detector};
use crate::checks::loopback;

pub const TEXT_MAX: usize = 65536;
/// Email, web and app call bodies are longer than any chat message; more than this is stopped, never cut.
pub const TEXT_MAX_LONG: usize = 524_288;
pub const LONG_CHANNELS: [&str; 3] = ["email", "web", "apps"];
/// The most text the AI judges (`CONTENT_AI_TEXT_MAX` in content-engine.ts).
pub const AI_TEXT_MAX: usize = 4 * (16000 - 500) + 500;
pub const AI_FAILED: &str = " (the AI check could not run)";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    // Weakest to strongest.
    Log,
    Hold,
    Block,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "log" => Self::Log,
            "hold" => Self::Hold,
            "block" => Self::Block,
            _ => return None,
        })
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Hold => "hold",
            Self::Block => "block",
        }
    }
}

/// One rule, as the addon holds it after `_content_rule_ok`. `by` is set on a hit the AI made
/// (`found`) or on one that acts because the AI could not run (`failed`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `in`, `out` or `both`.
    pub direction: String,
    pub channels: Vec<String>,
    pub patterns: Vec<String>,
    pub detectors: Vec<Detector>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    pub action: Action,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

impl Rule {
    /// The rule's shape check (`_content_rule_ok`) and the rule, from one entry of the file.
    pub fn from_json(v: &Value) -> Option<Self> {
        let o = v.as_object()?;
        let s = |k: &str| o.get(k).and_then(Value::as_str);
        let id = s("id")?.to_owned();
        let reason = s("reason")?.to_owned();
        let direction = s("direction")
            .filter(|d| matches!(*d, "in" | "out" | "both"))?
            .to_owned();
        let action = Action::parse(s("action")?)?;
        let strings = |k: &str| -> Option<Vec<String>> {
            o.get(k)?
                .as_array()?
                .iter()
                .map(|x| x.as_str().map(str::to_owned))
                .collect()
        };
        let channels = strings("channels")?;
        let patterns = strings("patterns")?;
        if !patterns.iter().all(|p| (1..=100).contains(&p.chars().count())) {
            return None;
        }
        let detectors = o
            .get("detectors")?
            .as_array()?
            .iter()
            .map(|d| d.as_str().and_then(Detector::parse))
            .collect::<Option<Vec<_>>>()?;
        let policy = match o.get("policy") {
            None | Some(Value::Null) => None,
            Some(Value::String(p)) if (1..=300).contains(&p.chars().count()) => Some(p.clone()),
            Some(_) => return None,
        };
        // `name` is not checked by the addon: anything that is not a string reads as missing.
        let name = s("name").map(str::to_owned);
        Some(Self {
            id,
            name,
            direction,
            channels,
            patterns,
            detectors,
            policy,
            action,
            reason,
            by: None,
        })
    }

    pub fn looks_at(&self, direction: &str, channel: &str) -> bool {
        (self.direction == direction || self.direction == "both")
            && self.channels.iter().any(|c| c == channel || c == "*")
    }

    /// `_rule_brief`: the rule as a hold or the stopped record names it.
    pub fn brief(&self) -> Value {
        let mut b = json!({
            "id": cut(&self.id, 64),
            "name": cut(self.name.as_deref().filter(|n| !n.is_empty()).unwrap_or(&self.id), 80),
            "reason": cut(&self.reason, 240),
        });
        if let Some(by) = self.by.as_deref().filter(|b| matches!(*b, "found" | "failed")) {
            b["ai"] = by.into();
        }
        b
    }
}

/// The first `n` characters (Python's `s[:n]`).
pub fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// "Leaking secrets": on for every organization, and nothing the control plane sends turns it off.
pub fn core_secrets_rule() -> Rule {
    Rule {
        id: "core-leaking-secrets".into(),
        name: Some("Leaking secrets".into()),
        direction: "out".into(),
        channels: ["telegram", "slack", "email", "teamchat", "voice", "apps"]
            .map(String::from)
            .to_vec(),
        patterns: vec![],
        detectors: vec![Detector::Secrets],
        policy: None,
        action: Action::Block,
        reason: "it looks like it contains a password, key or token".into(),
        by: None,
    }
}

pub const CORE_SECRETS_ID: &str = "core-leaking-secrets";

/// More text than a check reads: refused, never cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("too long: {0} characters")]
pub struct TooLong(pub usize);

pub fn text_max(channel: &str) -> usize {
    if LONG_CHANNELS.contains(&channel) {
        TEXT_MAX_LONG
    } else {
        TEXT_MAX
    }
}

/// Whether any rule looks at this direction and channel: when none does, nothing is read.
pub fn applies(rules: &[Rule], direction: &str, channel: &str) -> bool {
    rules.iter().any(|r| r.looks_at(direction, channel))
}

/// Whether a policy looks at this direction and channel: when none does, the model is not called.
pub fn policy_applies(rules: &[Rule], direction: &str, channel: &str) -> bool {
    rules
        .iter()
        .any(|r| r.policy.is_some() && r.looks_at(direction, channel))
}

/// What the engine found: the rule that acts (strongest action; the first listed among equals)
/// and every rule that matched, in order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Found {
    pub winner: Option<Rule>,
    pub hits: Vec<Rule>,
}

fn pick(winner: &mut Option<Rule>, r: &Rule) {
    if winner.as_ref().is_none_or(|w| r.action > w.action) {
        *winner = Some(r.clone());
    }
}

/// The engine: every rule for this direction and channel that matches, and the one that wins.
pub fn evaluate(rules: &[Rule], direction: &str, channel: &str, text: &str) -> Result<Found, TooLong> {
    let len = text.chars().count();
    if len > text_max(channel) {
        return Err(TooLong(len));
    }
    let mut found = Found::default();
    let mut folded: Option<String> = None;
    for rule in rules {
        if !rule.looks_at(direction, channel) {
            continue;
        }
        if !rule.patterns.is_empty() && folded.is_none() {
            folded = Some(detect::fold(text));
        }
        let hay = folded.as_deref().unwrap_or("");
        let words = rule
            .patterns
            .iter()
            .any(|p| detect::phrase_in_folded(&detect::fold(p), hay));
        if words || rule.detectors.iter().any(|d| detect::detect(*d, text)) {
            found.hits.push(rule.clone());
        }
    }
    for h in &found.hits {
        pick(&mut found.winner, h);
    }
    Ok(found)
}

/// The CPU-bound part of a check (the detectors and the word search over up to 512 KiB) runs on
/// the blocking pool, at most this many at once, so a slow text cannot stall the proxy's workers.
static CPU_GATE: std::sync::LazyLock<std::sync::Arc<tokio::sync::Semaphore>> =
    std::sync::LazyLock::new(|| std::sync::Arc::new(tokio::sync::Semaphore::new(4)));

/// Run `f` on the blocking pool behind [`CPU_GATE`]. Outside a runtime (a plain test) it runs here.
pub async fn off_workers<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    if tokio::runtime::Handle::try_current().is_err() {
        return f();
    }
    // The permit goes with the work: a caller that gives up (a dropped flow, a timeout) does not
    // free a slot while the scan still runs on the pool.
    let permit = CPU_GATE.clone().acquire_owned().await;
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e.into_panic()),
    }
}

/// [`evaluate`] on the blocking pool.
pub async fn evaluate_off(rules: &[Rule], direction: &str, channel: &str, text: &str) -> Result<Found, TooLong> {
    let (rules, direction, channel, text) = (
        rules.to_vec(),
        direction.to_owned(),
        channel.to_owned(),
        text.to_owned(),
    );
    off_workers(move || evaluate(&rules, &direction, &channel, &text)).await
}

/// Where the AI check is asked, and how long it may take.
#[derive(Debug, Clone)]
pub struct PolicyAsk {
    pub url: String,
    pub timeout: Duration,
}

/// The judge's answer (`/content`): the ids of the policies the message goes against, or `None`
/// when it could not answer.
pub async fn policy_ask(
    ask: &PolicyAsk,
    direction: &str,
    channel: &str,
    text: &str,
    asked: &[&Rule],
    vm_id: Option<&str>,
) -> Option<HashSet<String>> {
    if ask.url.is_empty() {
        return None;
    }
    // Secrets out first, as the judge does (the length is what it will judge).
    let owned = text.to_owned();
    let masked = off_workers(move || {
        let mut masked = owned;
        for r in detect::SECRET_RES.iter() {
            if let std::borrow::Cow::Owned(o) = r.replace_all(&masked, "[secret]") {
                masked = o;
            }
        }
        masked
    })
    .await;
    let n = masked.chars().count();
    if n > AI_TEXT_MAX {
        tracing::warn!("[content-rules] the AI check could not run: {n} characters is more than it judges");
        return None;
    }
    let payload = json!({
        "direction": direction,
        "channel": channel,
        "text": masked,
        "rules": asked.iter().map(|r| json!({"id": r.id, "policy": r.policy})).collect::<Vec<_>>(),
        "vm_id": vm_id,
    });
    let doc = match loopback::post(&ask.url, &serde_json::to_vec(&payload).unwrap_or_default(), ask.timeout).await {
        // `res.read(64 * 1024)`: what is past 64 KiB is not read, so such an answer is not JSON.
        Ok(raw) => serde_json::from_slice::<Value>(&raw[..raw.len().min(64 * 1024)]),
        Err(e) => {
            tracing::warn!("[content-rules] the AI check could not run: {e}");
            return None;
        }
    };
    let doc = match doc {
        Ok(d) => d,
        Err(_) => {
            tracing::warn!("[content-rules] the AI check could not run: JSONDecodeError");
            return None;
        }
    };
    match doc.get("matches").and_then(Value::as_array) {
        Some(list) if list.iter().all(Value::is_string) => {
            Some(list.iter().filter_map(|m| m.as_str().map(str::to_owned)).collect())
        }
        _ => {
            let why = doc.get("why").map_or_else(
                || "None".to_owned(),
                |w| w.as_str().map_or(w.to_string(), str::to_owned),
            );
            tracing::warn!("[content-rules] the AI check could not run: {}", cut(&why, 40));
            None
        }
    }
}

/// Python's whitespace (`str.strip`), which has `\x1c`-`\x1f` that Rust's does not.
pub fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// `evaluate`, then the AI on the policies that cover the text and did not match already, unless a
/// rule already blocks it. When the AI could not answer, every block or hold policy it was asked
/// about acts with "(the AI check could not run)" and `by: failed`; a log-only one records nothing.
pub async fn judge(
    ask: &PolicyAsk,
    rules: &[Rule],
    direction: &str,
    channel: &str,
    text: &str,
    found: Option<Found>,
    vm_id: Option<&str>,
) -> Result<Found, TooLong> {
    let mut found = match found {
        Some(f) => f,
        None => evaluate_off(rules, direction, channel, text).await?,
    };
    if found.winner.as_ref().is_some_and(|w| w.action == Action::Block) || text.trim_matches(py_space).is_empty() {
        return Ok(found);
    }
    let hit_ids: HashSet<&str> = found.hits.iter().map(|h| h.id.as_str()).collect();
    let asked: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.policy.is_some() && !hit_ids.contains(r.id.as_str()) && r.looks_at(direction, channel))
        .collect();
    if asked.is_empty() {
        return Ok(found);
    }
    let more: Vec<Rule> = match policy_ask(ask, direction, channel, text, &asked, vm_id).await {
        None => asked
            .iter()
            .filter(|r| r.action != Action::Log)
            .map(|r| Rule {
                reason: format!("{}{AI_FAILED}", r.reason.trim_end_matches([' ', '.'])),
                by: Some("failed".into()),
                ..(*r).clone()
            })
            .collect(),
        Some(matched) => asked
            .iter()
            .filter(|r| matched.contains(&r.id))
            .map(|r| Rule {
                by: Some("found".into()),
                ..(*r).clone()
            })
            .collect(),
    };
    for r in &more {
        pick(&mut found.winner, r);
    }
    found.hits.extend(more);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::testkit::{Answer, FakeService};

    pub fn rule(
        id: &str,
        action: &str,
        direction: &str,
        patterns: &[&str],
        detectors: &[&str],
        channels: &[&str],
    ) -> Rule {
        Rule::from_json(&json!({
            "id": id, "name": id, "direction": direction, "channels": channels, "patterns": patterns,
            "detectors": detectors, "action": action, "reason": format!("{id} reason"),
        }))
        .expect("a valid rule")
    }

    fn ev(rules: &[Rule], d: &str, c: &str, t: &str) -> Option<String> {
        evaluate(rules, d, c, t).expect("not too long").winner.map(|w| w.id)
    }

    #[test]
    fn the_engine() {
        let words = rule("words", "block", "out", &["customer list"], &[], &["telegram"]);
        let r = std::slice::from_ref(&words);
        assert_eq!(
            ev(r, "out", "telegram", "Here is the Customer List.").as_deref(),
            Some("words")
        );
        assert_eq!(ev(r, "out", "telegram", "customer listing"), None, "word boundaries");
        assert_eq!(ev(r, "in", "telegram", "customer list"), None, "direction");
        assert_eq!(ev(r, "out", "slack", "customer list"), None, "channel");
        let re = rule("re", "block", "out", &["(a+)+$"], &[], &["telegram"]);
        let r = std::slice::from_ref(&re);
        assert_eq!(ev(r, "out", "telegram", &format!("{}!", "a".repeat(5000))), None);
        assert_eq!(ev(r, "out", "telegram", "literally (a+)+$ here").as_deref(), Some("re"));
        let rules = [
            rule("l", "log", "out", &["list"], &[], &["telegram"]),
            rule("h", "hold", "out", &["list"], &[], &["telegram"]),
            rule("b", "log", "both", &["list"], &[], &["telegram"]),
        ];
        let f = evaluate(&rules, "out", "telegram", "a list").expect("short");
        assert_eq!(f.winner.map(|w| w.id).as_deref(), Some("h"));
        assert_eq!(f.hits.len(), 3);
    }

    /// The shared cases: content-engine.ts in the mitm-agent and addon.py give these answers.
    #[test]
    fn the_shared_vectors() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../packages/mitm-agent/src/content-vectors.json"
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json");
        for c in v["phrases"].as_array().expect("phrases") {
            let (p, t) = (c["phrase"].as_str().unwrap_or(""), c["text"].as_str().unwrap_or(""));
            assert_eq!(detect::phrase_in(p, t), c["found"] == true, "{c}");
        }
        for c in v["detectors"].as_array().expect("detectors") {
            let d = Detector::parse(c["detector"].as_str().unwrap_or("")).expect("detector");
            assert_eq!(
                detect::detect(d, c["text"].as_str().unwrap_or("")),
                c["found"] == true,
                "{c}"
            );
        }
        let org: Vec<Rule> = v["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|r| Rule::from_json(r).expect("rule"))
            .collect();
        for c in v["evaluations"].as_array().expect("evaluations") {
            let mut rules = if c["core"] == true {
                vec![core_secrets_rule()]
            } else {
                vec![]
            };
            rules.extend(org.iter().cloned());
            let f = evaluate(
                &rules,
                c["direction"].as_str().unwrap_or(""),
                c["channel"].as_str().unwrap_or(""),
                c["text"].as_str().unwrap_or(""),
            )
            .expect("short");
            assert_eq!(
                f.winner.map(|w| Value::from(w.id)).unwrap_or(Value::Null),
                c["rule"],
                "{c}"
            );
            let ids: Vec<Value> = f.hits.iter().map(|h| Value::from(h.id.clone())).collect();
            assert_eq!(Value::from(ids), c["hits"], "{c}");
        }
        let core = [core_secrets_rule()];
        for c in v["lengths"].as_array().expect("lengths") {
            let text = c["repeat"]
                .as_str()
                .unwrap_or("")
                .repeat(c["count"].as_u64().unwrap_or(0) as usize);
            assert_eq!(
                evaluate(&core, "out", c["channel"].as_str().unwrap_or(""), &text).is_err(),
                c["tooLong"] == true,
                "{c}"
            );
        }
        for c in v["limits"].as_array().expect("limits") {
            let ch = c["channel"].as_str().unwrap_or("");
            assert_eq!(Some(text_max(ch) as u64), c["max"].as_u64(), "{c}");
            assert!(evaluate(&core, "out", ch, &"x".repeat(text_max(ch) + 1)).is_err());
        }
    }

    #[test]
    fn the_rule_shape_check() {
        let ok = json!({"id": "a", "direction": "out", "channels": ["web"], "patterns": [], "detectors": [], "action": "log", "reason": "r"});
        assert!(Rule::from_json(&ok).is_some());
        for (k, bad) in [
            ("direction", json!("up")),
            ("action", json!("warn")),
            ("channels", json!("web")),
            ("patterns", json!([""])),
            ("patterns", json!(["x".repeat(101)])),
            ("detectors", json!(["phone"])),
            ("policy", json!("")),
            ("policy", json!(3)),
            ("reason", json!(null)),
        ] {
            let mut r = ok.clone();
            r[k] = bad;
            assert!(Rule::from_json(&r).is_none(), "{k}");
        }
        let mut r = ok.clone();
        r["policy"] = json!(null);
        assert!(Rule::from_json(&r).is_some(), "a null policy is no policy");
        assert_eq!(
            Rule::from_json(&ok).expect("rule").brief(),
            json!({"id": "a", "name": "a", "reason": "r"}),
            "no name: the id"
        );
    }

    /// A caller that gives up does not give the slot back before the work ends.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_cpu_gate_holds_until_the_work_ends() {
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
        let mut gone = Vec::new();
        for _ in 0..4 {
            let rx = rx.clone();
            let job = tokio::spawn(off_workers(move || {
                let _ = rx.lock().map(|r| r.recv());
            }));
            gone.push(job);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for job in &gone {
            job.abort();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            CPU_GATE.available_permits(),
            0,
            "the four blocked jobs still hold their slots"
        );
        for _ in 0..4 {
            let _ = tx.send(());
        }
        for _ in 0..50 {
            if CPU_GATE.available_permits() == 4 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "the slots came back only when the work ended: {}",
            CPU_GATE.available_permits()
        );
    }

    #[tokio::test]
    async fn policies_are_asked_once_and_fail_closed() -> anyhow::Result<()> {
        let judge_svc = FakeService::start().await?;
        let ask = PolicyAsk {
            url: judge_svc.url("/content"),
            timeout: Duration::from_millis(500),
        };
        let mut pay = rule("pay", "hold", "out", &[], &[], &["telegram"]);
        pay.policy = Some("Pay is not discussed.".into());
        pay.reason = "pay is private.".into();
        let mut watch = rule("watch", "log", "out", &[], &[], &["telegram"]);
        watch.policy = Some("Watch".into());
        let words = rule("words", "block", "out", &["secret plan"], &[], &["telegram"]);
        let rules = vec![core_secrets_rule(), pay.clone(), watch.clone(), words];

        judge_svc.answer(
            "/content",
            Answer::json(200, json!({"matches": ["pay"], "probabilities": {}})),
        );
        let f = judge(
            &ask,
            &rules,
            "out",
            "telegram",
            "salary talk sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
            Some("vm1"),
        )
        .await?;
        // The core rule blocks before the AI is asked.
        assert_eq!(f.winner.map(|w| w.id).as_deref(), Some(CORE_SECRETS_ID));
        assert!(judge_svc.calls("/content").is_empty());

        let f = judge(
            &ask,
            &rules,
            "out",
            "telegram",
            "what is your salary",
            None,
            Some("vm1"),
        )
        .await?;
        let w = f.winner.expect("a winner");
        assert_eq!((w.id.as_str(), w.by.as_deref()), ("pay", Some("found")));
        let call = &judge_svc.calls("/content")[0];
        assert_eq!(
            call,
            &json!({"direction": "out", "channel": "telegram", "text": "what is your salary",
                    "rules": [{"id": "pay", "policy": "Pay is not discussed."}, {"id": "watch", "policy": "Watch"}], "vm_id": "vm1"})
        );
        // Keys in the addon's order.
        assert_eq!(serde_json::to_string(call)?.find("direction"), Some(2));

        // No answer: the hold acts with the reason marked, the log-only one records nothing.
        judge_svc.answer("/content", Answer::json(200, json!({"failed": true, "why": "timeout"})));
        let f = judge(&ask, &rules[1..], "out", "telegram", "what is your salary", None, None).await?;
        let w = f.winner.expect("a winner");
        assert_eq!(w.reason, "pay is private (the AI check could not run)");
        assert_eq!(w.by.as_deref(), Some("failed"));
        assert_eq!(f.hits.len(), 1);
        assert_eq!(w.brief()["ai"], "failed");

        // A blank text is not asked about; neither is a judge that is off.
        assert!(
            judge(&ask, &rules[1..], "out", "telegram", "  ", None, None)
                .await?
                .winner
                .is_none()
        );
        let off = PolicyAsk {
            url: String::new(),
            timeout: ask.timeout,
        };
        assert_eq!(
            judge(&off, &rules[1..], "out", "telegram", "x", None, None)
                .await?
                .hits
                .len(),
            1,
            "off is failed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn no_call_without_a_policy_for_the_channel_or_when_a_word_already_blocks() -> anyhow::Result<()> {
        let svc = FakeService::start().await?;
        let ask = PolicyAsk {
            url: svc.url("/content"),
            timeout: Duration::from_millis(500),
        };
        let mut salary = rule("salary", "block", "both", &[], &[], &["*"]);
        salary.policy = Some("Can't ask about or share anyone's salary.".into());
        let mut slack_only = salary.clone();
        slack_only.channels = vec!["slack".into()];
        assert_eq!(
            judge(&ask, &[slack_only], "in", "telegram", "Anna", None, None).await?,
            Found::default()
        );
        let mut out_only = salary.clone();
        out_only.direction = "out".into();
        assert_eq!(
            judge(&ask, &[out_only], "in", "telegram", "Anna", None, None).await?,
            Found::default()
        );
        let words = rule("words", "block", "both", &["payroll"], &[], &["*"]);
        let f = judge(
            &ask,
            &[words.clone(), salary.clone()],
            "in",
            "telegram",
            "Anna and the payroll",
            None,
            None,
        )
        .await?;
        assert_eq!(f.winner.map(|w| w.id).as_deref(), Some("words"));
        assert!(svc.calls("/content").is_empty());
        assert!(!policy_applies(&[words], "in", "telegram"));
        assert!(policy_applies(&[salary], "in", "voice"));
        Ok(())
    }

    #[tokio::test]
    async fn a_slow_judge_is_a_judge_that_could_not_run() -> anyhow::Result<()> {
        let svc = FakeService::start().await?;
        let ask = PolicyAsk {
            url: svc.url("/content"),
            timeout: Duration::from_millis(300),
        };
        svc.answer(
            "/content",
            Answer::json(200, json!({"matches": []})).delayed(Duration::from_millis(800)),
        );
        let mut salary = rule("salary", "block", "both", &[], &[], &["*"]);
        salary.policy = Some("salary".into());
        let log_only = Rule {
            id: "pay-log".into(),
            action: Action::Log,
            ..salary.clone()
        };
        let f = judge(&ask, &[salary, log_only], "in", "email", "hello", None, None).await?;
        let w = f.winner.expect("a winner");
        assert_eq!(
            (w.id.as_str(), w.by.as_deref(), w.reason.as_str()),
            ("salary", Some("failed"), "salary reason (the AI check could not run)")
        );
        assert_eq!(f.hits.len(), 1, "a log-only policy records nothing");
        // A long text is judged whole.
        svc.answer("/content", Answer::json(200, json!({"matches": []})));
        let text = format!("{}Anna's salary is 92k.{}", "a ".repeat(5000), " b".repeat(5000));
        let mut p = rule("p", "block", "out", &[], &[], &["email"]);
        p.policy = Some("x".into());
        judge(&ask, &[p], "out", "email", &text, None, None).await?;
        assert_eq!(
            svc.calls("/content").last().map(|c| c["text"].clone()),
            Some(json!(text))
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_judge_sees_no_secret_and_not_too_much() -> anyhow::Result<()> {
        let svc = FakeService::start().await?;
        let ask = PolicyAsk {
            url: svc.url("/content"),
            timeout: Duration::from_millis(500),
        };
        let mut p = rule("p", "block", "out", &[], &[], &["web"]);
        p.policy = Some("x".into());
        let asked = [&p];
        svc.answer("/content", Answer::json(200, json!({"matches": []})));
        let got = policy_ask(
            &ask,
            "out",
            "web",
            &format!("key sk-proj-{} end", "A".repeat(40)),
            &asked,
            None,
        )
        .await;
        assert_eq!(got, Some(HashSet::new()));
        assert_eq!(svc.calls("/content")[0]["text"], "key [secret] end");
        assert_eq!(
            policy_ask(&ask, "out", "web", &"x".repeat(AI_TEXT_MAX + 1), &asked, None).await,
            None
        );
        assert_eq!(svc.calls("/content").len(), 1, "too long is not asked");
        svc.answer("/content", Answer::json(200, json!({"matches": [1]})));
        assert_eq!(
            policy_ask(&ask, "out", "web", "x", &asked, None).await,
            None,
            "not a list of strings"
        );
        svc.answer("/content", Answer::json(500, json!({"matches": []})));
        assert_eq!(policy_ask(&ask, "out", "web", "x", &asked, None).await, None);
        Ok(())
    }
}
