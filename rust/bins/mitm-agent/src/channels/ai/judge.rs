//! Inline AI review (`ai/judge.ts`, apps/saas/docs/features/ai-firewall-review.md): the proxy asks,
//! before an `allow` rule marked for review lets a request out, whether it should go, go to a
//! person, or be blocked; and, for an Ask rule with a policy, whether it may be approved on the
//! person's behalf. Also the content rules' policies, an integration rule's sentence and an MCP
//! tool's kind. Served on loopback only (`serve`); the agent boxes cannot reach it.
//!
//! Any failure answers `fallback` (the proxy keeps the rule's own decision) or `{failed}` (the
//! content rules act). Answers are cached per rule, method, host, path shape and body start for ten
//! minutes, and content answers a day.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cc_llm::{AiSettings, Answer, Evaluation, Provider};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use super::model::{AiClient, AiIdentity, EvaluateOptions};
use super::questions::{
    approve_questions, content_questions, inline_questions, integration_fits_question, owner_instructions,
    tool_kind_questions,
};
use crate::channels::content_engine::{CONTENT_CHANNELS, ai_chunks};
use crate::channels::js::{js_len, js_slice};
use crate::channels::llm::js_number;

const CACHE_TTL_MS: i64 = 10 * 60_000;
const CACHE_MAX: usize = 2000;
const EVALUATE_TIMEOUT: Duration = Duration::from_millis(2500);
const PATH_MAX: usize = 200;
const BODY_MAX: usize = 300;
const RECENT_MAX: usize = 20;
/// Mirrored in apps/saas: the rule's `aiPolicy` limit.
const POLICY_MAX: usize = 1000;
/// How sure the model must be that a request fits the policy before approving it.
pub const APPROVE_THRESHOLD: f64 = 0.9;

const CONTENT_TIMEOUT: Duration = Duration::from_millis(2500);
pub const CONTENT_DAILY_CAP: u64 = 50_000;
pub const CONTENT_AGENT_DAILY_CAP: u64 = 10_000;
pub const TOOL_LABEL_DAILY_CAP: u64 = 2_000;
const CONTENT_CACHE_TTL_MS: i64 = 24 * 60 * 60_000;
const CONTENT_CACHE_MAX: usize = 20_000;
/// Yes, at this probability or more.
pub const CONTENT_THRESHOLD: f64 = 0.5;
const CONTENT_RULES_MAX: usize = 50;

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn control() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[\x00-\x08\x0b-\x1f\x7f]").expect("regex"))
}

/// `/repos/acme/app/issues/1234` → `/repos/acme/app/issues/:id`: ids, uuids and long hex.
pub fn path_template(path: &str) -> String {
    static UUID: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static HEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let uuid = UUID.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f-]{27,}$").expect("regex"));
    let hex = HEX.get_or_init(|| Regex::new(r"(?i)^[0-9a-f]{16,}$").expect("regex"));
    path.split('?')
        .next()
        .unwrap_or_default()
        .split('/')
        .map(|seg| {
            let digits = !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit());
            if digits || uuid.is_match(seg) || hex.is_match(seg) {
                ":id"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn clip(v: Option<&Value>, max: usize) -> Option<String> {
    let s = v?.as_str().filter(|s| !s.is_empty())?;
    let s = control().replace_all(s, " ");
    Some(if js_len(&s) > max {
        format!("{}…", js_slice(&s, max))
    } else {
        s.into_owned()
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct JudgeRequest {
    pub mode: String,
    pub rule: String,
    pub policy: Option<String>,
    pub permission_id: Option<String>,
    pub scope: Option<String>,
    pub vm_id: Option<String>,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub content_type: Option<String>,
    pub body_start: Option<String>,
    pub recent: Vec<Value>,
}

/// Validate and cap what the proxy sent. `None` when it is not a request we can judge.
pub fn parse_judge_request(raw: &Value) -> Option<JudgeRequest> {
    let r = raw.as_object()?;
    let host = r.get("host")?.as_str().filter(|h| !h.is_empty())?;
    let method = r.get("method")?.as_str()?;
    let recent: Vec<Value> = r
        .get("recent")
        .and_then(Value::as_array)
        .map(|a| {
            let tail = &a[a.len().saturating_sub(RECENT_MAX)..];
            tail.iter()
                .filter_map(|e| e.as_object().cloned())
                .map(|mut e| {
                    // `path: clip(e.path) ?? undefined`: a path that clips to nothing drops out.
                    match clip(e.get("path"), 120) {
                        Some(p) => {
                            e.insert("path".into(), json!(p));
                        }
                        None => {
                            e.remove("path");
                        }
                    }
                    Value::Object(e)
                })
                .collect()
        })
        .unwrap_or_default();
    Some(JudgeRequest {
        mode: if r.get("mode").and_then(Value::as_str) == Some("approve") {
            "approve".into()
        } else {
            "review".into()
        },
        rule: clip(r.get("rule"), 120).unwrap_or_default(),
        policy: r.get("policy").and_then(|p| cc_llm::clean_instructions(p, POLICY_MAX)),
        permission_id: r.get("permission_id").and_then(Value::as_str).map(|p| js_slice(p, 128)),
        scope: clip(r.get("scope"), 2048),
        vm_id: r.get("vm_id").and_then(Value::as_str).map(str::to_string),
        method: js_slice(method, 16).to_uppercase(),
        host: js_slice(host, 253),
        path: clip(r.get("path"), PATH_MAX).unwrap_or_else(|| "/".into()),
        query_keys: r
            .get("query_keys")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .take(20)
                    .map(|k| js_slice(k, 60))
                    .collect()
            })
            .unwrap_or_default(),
        content_type: clip(r.get("content_type"), 100),
        body_start: clip(r.get("body_start"), BODY_MAX),
        recent,
    })
}

/// The content rules' policies: which of these rules a message goes against.
#[derive(Debug, Clone, PartialEq)]
pub struct ContentAsk {
    pub direction: String,
    pub channel: String,
    pub text: String,
    pub rules: Vec<(String, String)>,
    pub vm_id: Option<String>,
}

pub fn parse_content_ask(raw: &Value) -> Option<ContentAsk> {
    let r = raw.as_object()?;
    let direction = r.get("direction")?.as_str().filter(|d| *d == "in" || *d == "out")?;
    let channel = r.get("channel")?.as_str().filter(|c| CONTENT_CHANNELS.contains(c))?;
    let text = r.get("text")?.as_str().filter(|t| !t.trim().is_empty())?;
    let list = r
        .get("rules")?
        .as_array()
        .filter(|l| !l.is_empty() && l.len() <= CONTENT_RULES_MAX)?;
    let mut rules = Vec::new();
    for x in list {
        let id = x
            .get("id")
            .and_then(Value::as_str)
            .filter(|i| !i.is_empty() && js_len(i) <= 64)?;
        let policy = x.get("policy").and_then(|p| cc_llm::clean_instructions(p, 300))?;
        rules.push((id.to_string(), policy));
    }
    Some(ContentAsk {
        direction: direction.into(),
        channel: channel.into(),
        text: text.into(),
        rules,
        vm_id: r
            .get("vm_id")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
            .map(|v| js_slice(v, 100)),
    })
}

/// The model and key the content rules accepted with a code (`content-rules.ts`).
#[derive(Debug, Clone, PartialEq)]
pub struct AiPin {
    pub provider: Provider,
    pub model: String,
    pub key_fingerprint: Option<String>,
}

/// Only decision models judge policies: Jev and its versions, on the Gateway or the included tokens.
pub fn policy_model_allowed(id: &AiIdentity) -> bool {
    static JEV: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let jev = JEV.get_or_init(|| Regex::new(r"^typesafe-ai/jev(?:-[a-z0-9.-]+)?$").expect("regex"));
    matches!(id.provider, Provider::VercelGateway | Provider::ControlclawIncluded) && jev.is_match(&id.model)
}

/// What the content rules would pin for this identity.
pub fn pin_for(id: &AiIdentity) -> AiPin {
    AiPin {
        provider: id.provider,
        model: id.model.clone(),
        key_fingerprint: (id.provider != Provider::ControlclawIncluded).then(|| id.key_fingerprint.clone()),
    }
}

pub fn pin_matches(pin: Option<&AiPin>, id: Option<&AiIdentity>) -> bool {
    match (pin, id) {
        (Some(pin), Some(id)) => pin_for(id) == *pin,
        _ => false,
    }
}

/// `{decision, category?, cached?, by?}`.
#[derive(Debug, Clone, PartialEq)]
pub struct JudgeAnswer {
    pub decision: String,
    pub category: Option<String>,
    pub cached: bool,
    pub by_ai: bool,
}

impl JudgeAnswer {
    pub fn fallback() -> Self {
        Self {
            decision: "fallback".into(),
            category: None,
            cached: false,
            by_ai: false,
        }
    }

    fn of(decision: &str, category: &str) -> Self {
        Self {
            decision: decision.into(),
            category: Some(category.into()),
            cached: false,
            by_ai: false,
        }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("decision".into(), json!(self.decision));
        if let Some(c) = &self.category {
            m.insert("category".into(), json!(c));
        }
        if self.cached {
            m.insert("cached".into(), json!(true));
        }
        if self.by_ai {
            m.insert("by".into(), json!("ai"));
        }
        Value::Object(m)
    }
}

/// `{matches, probabilities, cached?}` or `{failed: true, why}`.
#[derive(Debug, Clone, PartialEq)]
pub enum ContentAnswer {
    Answered {
        matches: Vec<String>,
        probabilities: IndexMap<String, f64>,
        cached: bool,
    },
    Failed(String),
}

impl ContentAnswer {
    fn failed(why: &str) -> Self {
        ContentAnswer::Failed(why.into())
    }

    pub fn to_json(&self) -> Value {
        match self {
            ContentAnswer::Answered {
                matches,
                probabilities,
                cached,
            } => {
                let mut m = Map::new();
                m.insert("matches".into(), json!(matches));
                let p: Map<String, Value> = probabilities.iter().map(|(k, v)| (k.clone(), js_number(*v))).collect();
                m.insert("probabilities".into(), Value::Object(p));
                if *cached {
                    m.insert("cached".into(), json!(true));
                }
                Value::Object(m)
            }
            ContentAnswer::Failed(why) => json!({"failed": true, "why": why}),
        }
    }
}

fn choice<'a>(e: &'a Evaluation, id: &str) -> Option<&'a str> {
    match e.answer(id) {
        Some(Answer::Choice { choice, .. }) => Some(choice.as_str()),
        _ => None,
    }
}

fn probability(e: &Evaluation, id: &str) -> Option<f64> {
    match e.answer(id) {
        Some(Answer::Boolean { probability }) => Some(*probability),
        _ => None,
    }
}

/// Grants the approve mode writes: the one `grants.json` writer (W3's `core.grants`).
pub trait Grants: Send + Sync {
    fn set(&self, id: &str, expires_at: u64, scope: &str, by_ai: bool);
}

pub struct JudgeOptions {
    pub client: Arc<AiClient>,
    pub grants: Option<Arc<dyn Grants>>,
    /// How long an AI approval lasts, like a person's (`PERMISSION_TTL`).
    pub grant_ttl_seconds: u64,
    /// The model and key the content rules accepted.
    pub policy_pin: Arc<dyn Fn() -> Option<AiPin> + Send + Sync>,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

struct Cached<T> {
    at: i64,
    answer: T,
}

type ContentCached = (Vec<String>, IndexMap<String, f64>);

pub struct AiJudge {
    opts: JudgeOptions,
    cache: Mutex<IndexMap<String, Cached<JudgeAnswer>>>,
    content_cache: Mutex<IndexMap<String, Cached<ContentCached>>>,
    /// Approve mode: when each agent's recent auto-approvals happened (ms), for the hourly cap.
    approvals: Mutex<HashMap<String, Vec<i64>>>,
}

fn put<T>(cache: &Mutex<IndexMap<String, Cached<T>>>, max: usize, key: String, at: i64, answer: T) {
    let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
    if c.len() >= max {
        c.shift_remove_index(0);
    }
    // `Map.set` on an existing key keeps its place.
    c.insert(key, Cached { at, answer });
}

impl AiJudge {
    pub fn new(opts: JudgeOptions) -> Self {
        Self {
            opts,
            cache: Mutex::new(IndexMap::new()),
            content_cache: Mutex::new(IndexMap::new()),
            approvals: Mutex::new(HashMap::new()),
        }
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn client(&self) -> &AiClient {
        &self.opts.client
    }

    /// The cache key: the model, the owner's org-wide text (so an edit applies at once), the rule
    /// and the request's shape. From the settings this request was read with, once.
    fn key(settings: &AiSettings, req: &JudgeRequest) -> String {
        let org = sha256_hex(settings.request_instructions.as_deref().unwrap_or_default());
        let parts = [
            settings.provider.as_str().to_string(),
            settings.model.clone(),
            org,
            req.mode.clone(),
            req.policy.clone().unwrap_or_default(),
            req.rule.clone(),
            req.method.clone(),
            req.host.clone(),
            path_template(&req.path),
            req.body_start.clone().unwrap_or_default(),
        ];
        sha256_hex(&parts.join("|"))
    }

    fn state(req: &JudgeRequest) -> Value {
        let mut request = Map::new();
        request.insert("method".into(), json!(req.method));
        request.insert("host".into(), json!(req.host));
        request.insert("path".into(), json!(req.path));
        if !req.query_keys.is_empty() {
            request.insert("query_parameters".into(), json!(req.query_keys));
        }
        if let Some(c) = &req.content_type {
            request.insert("content_type".into(), json!(c));
        }
        if let Some(b) = &req.body_start {
            request.insert("body_start".into(), json!(b));
        }
        json!({
            "kind": "request_to_review",
            "rule": req.rule,
            "request": request,
            "previous_requests": req.recent,
        })
    }

    fn cached(&self, key: &str) -> Option<JudgeAnswer> {
        let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.get(key)
            .filter(|h| self.now() - h.at < CACHE_TTL_MS)
            .map(|h| h.answer.clone())
    }

    /// Approve mode: approves only when the model says "allow" AND is at least
    /// `APPROVE_THRESHOLD` sure the request fits the policy, under the hourly cap. Never blocks.
    async fn approve(&self, req: &JudgeRequest, ready: (AiSettings, String)) -> JudgeAnswer {
        // `!req.permission_id`: an empty id is no id.
        let permission_id = req.permission_id.as_ref().filter(|p| !p.is_empty());
        let (Some(policy), Some(permission_id), Some(grants)) = (&req.policy, permission_id, &self.opts.grants) else {
            return JudgeAnswer::fallback();
        };
        let settings = ready.0.clone();
        let key = Self::key(&settings, req);
        let (answer, cached) = match self.cached(&key) {
            Some(a) => (a, true),
            None => {
                let owner = owner_instructions(settings.request_instructions.as_deref(), None);
                let Ok(result) = self
                    .client()
                    .evaluate_ready(
                        Some(ready),
                        Self::state(req),
                        approve_questions(policy, &owner),
                        EvaluateOptions {
                            timeout: EVALUATE_TIMEOUT,
                            max_retries: 0,
                            caps: None,
                        },
                    )
                    .await
                else {
                    return JudgeAnswer::fallback();
                };
                let fits = probability(&result, "matches_policy").unwrap_or(0.0) >= APPROVE_THRESHOLD
                    && choice(&result, "verdict") == Some("allow");
                let category = choice(&result, "category").unwrap_or("normal").to_string();
                let answer = if fits {
                    JudgeAnswer::of("allow", &category)
                } else if category == "normal" {
                    JudgeAnswer::of("ask", "policy_mismatch")
                } else {
                    JudgeAnswer::of("ask", &category)
                };
                put(&self.cache, CACHE_MAX, key, self.now(), answer.clone());
                (answer, false)
            }
        };
        let category = answer.category.clone().unwrap_or_default();
        if answer.decision != "allow" {
            if !cached {
                tracing::info!(
                    "[ai] approve: no, to a person: {} {}{} ({category})",
                    req.method,
                    req.host,
                    req.path
                );
            }
            return JudgeAnswer { cached, ..answer };
        }
        let vm = req.vm_id.clone().unwrap_or_else(|| "unknown".into());
        let now = self.now();
        let cap = settings.auto_approve_per_hour;
        {
            // The count and the take under one lock: two approvals at once cannot both pass the cap.
            let mut approvals = self.approvals.lock().unwrap_or_else(|e| e.into_inner());
            let recent = approvals.entry(vm.clone()).or_default();
            recent.retain(|t| now - t < 3_600_000);
            if recent.len() as u64 >= cap {
                tracing::info!(
                    "[ai] approve: hourly cap of {cap} reached for {vm}; to a person: {} {}{}",
                    req.method,
                    req.host,
                    req.path
                );
                return JudgeAnswer::of("ask", &category);
            }
            recent.push(now);
        }
        let now_s = now.div_euclid(1000).max(0) as u64;
        grants.set(
            permission_id,
            now_s + self.opts.grant_ttl_seconds,
            req.scope.as_deref().unwrap_or(""),
            true,
        );
        tracing::info!(
            "[ai] approve: yes {} {}{} ({category}){}",
            req.method,
            req.host,
            req.path,
            if cached { " [cached]" } else { "" }
        );
        JudgeAnswer {
            decision: "allow".into(),
            category: Some(category),
            cached,
            by_ai: true,
        }
    }

    fn pinned_identity(&self) -> Option<AiIdentity> {
        let id = self.client().identity()?;
        if !self.client().checks_on()
            || !policy_model_allowed(&id)
            || !pin_matches((self.opts.policy_pin)().as_ref(), Some(&id))
        {
            return None;
        }
        Some(id)
    }

    fn content_hit(&self, key: &str) -> Option<ContentCached> {
        let c = self.content_cache.lock().unwrap_or_else(|e| e.into_inner());
        c.get(key)
            .filter(|h| self.now() - h.at < CONTENT_CACHE_TTL_MS)
            .map(|h| h.answer.clone())
    }

    /// The content rules' policies: the whole text, in pieces judged at once. Only an allowed model
    /// on the pinned key; never a part judged as the whole. A failure is never cached.
    pub async fn content(&self, ask: &ContentAsk) -> ContentAnswer {
        let id = self.client().identity();
        let Some(id) = id.filter(|_| self.client().checks_on()) else {
            return ContentAnswer::failed("off");
        };
        if !policy_model_allowed(&id) {
            return ContentAnswer::failed("model");
        }
        if !pin_matches((self.opts.policy_pin)().as_ref(), Some(&id)) {
            return ContentAnswer::failed("unpinned");
        }
        let Some(chunks) = ai_chunks(&ask.text) else {
            return ContentAnswer::failed("too_long");
        };
        let rules_json: Vec<Value> = ask.rules.iter().map(|(i, p)| json!({"id": i, "policy": p})).collect();
        let key = sha256_hex(
            &json!([
                "content",
                id.provider.as_str(),
                id.model,
                ask.direction,
                ask.channel,
                rules_json,
                ask.text
            ])
            .to_string(),
        );
        if let Some((matches, probabilities)) = self.content_hit(&key) {
            return ContentAnswer::Answered {
                matches,
                probabilities,
                cached: true,
            };
        }
        let policies: Vec<String> = ask.rules.iter().map(|(_, p)| p.clone()).collect();
        let questions = content_questions(&policies);
        let caps = vec![
            ("content".to_string(), CONTENT_DAILY_CAP),
            (
                format!("content:{}", ask.vm_id.as_deref().unwrap_or("console")),
                CONTENT_AGENT_DAILY_CAP,
            ),
        ];
        let started = self.now();
        let n = chunks.len();
        let calls = chunks.iter().enumerate().map(|(i, text)| {
            let mut state = json!({
                "kind": "message",
                "direction": if ask.direction == "out" { "from the agent" } else { "to the agent" },
                "channel": ask.channel,
                "text": text,
            });
            if n > 1 {
                state["part"] = json!(format!("{} of {n} of one message", i + 1));
            }
            self.client().evaluate_with_reason(
                state,
                questions.clone(),
                EvaluateOptions {
                    timeout: CONTENT_TIMEOUT,
                    max_retries: 0,
                    caps: Some(caps.clone()),
                },
            )
        });
        let outs = futures_util::future::join_all(calls).await;
        let took = format!(
            "{} {}, {} rule{}{}, {} ms",
            ask.channel,
            ask.direction,
            ask.rules.len(),
            if ask.rules.len() == 1 { "" } else { "s" },
            if n > 1 { format!(", {n} parts") } else { String::new() },
            self.now() - started
        );
        if let Some(Err(f)) = outs.iter().find(|o| o.is_err()) {
            tracing::info!("[ai] content: {took}: could not run ({})", f.kind());
            return ContentAnswer::failed(f.kind());
        }
        // A policy matches when any piece goes against it; its probability is the highest piece's.
        let mut probabilities: IndexMap<String, f64> = IndexMap::new();
        for out in outs.iter().flatten() {
            for (i, (rule_id, _)) in ask.rules.iter().enumerate() {
                let Some(p) = probability(out, &format!("rule_{i}")).filter(|p| (0.0..=1.0).contains(p)) else {
                    return ContentAnswer::failed("error");
                };
                // Rounded down: a policy shown at 0.5 matched.
                let p = (p * 1000.0).floor() / 1000.0;
                let e = probabilities.entry(rule_id.clone()).or_insert(0.0);
                *e = e.max(p);
            }
        }
        let matches: Vec<String> = ask
            .rules
            .iter()
            .filter(|(i, _)| probabilities.get(i).is_some_and(|p| *p >= CONTENT_THRESHOLD))
            .map(|(i, _)| i.clone())
            .collect();
        put(
            &self.content_cache,
            CONTENT_CACHE_MAX,
            key,
            self.now(),
            (matches.clone(), probabilities.clone()),
        );
        tracing::info!(
            "[ai] content: {took}: {}",
            if matches.is_empty() {
                "no match".to_string()
            } else {
                format!("matched {}", matches.join(", "))
            }
        );
        ContentAnswer::Answered {
            matches,
            probabilities,
            cached: false,
        }
    }

    /// An integration rule's sentence: does this call fit what the owner wrote? `unavailable` when
    /// it cannot answer.
    pub async fn integration_fits(
        &self,
        vm_id: &str,
        sentence: &str,
        integration: &str,
        tool: &str,
        input: &Value,
    ) -> &'static str {
        let Some(id) = self.pinned_identity() else {
            return "unavailable";
        };
        let Some(sentence) = cc_llm::clean_instructions(&json!(sentence), 300) else {
            return "unavailable";
        };
        let args = serde_json::to_string(input).unwrap_or_else(|_| "null".into());
        if js_len(&args) > 15_000 {
            return "unavailable";
        }
        let key = sha256_hex(
            &json!([
                "fits",
                id.provider.as_str(),
                id.model,
                sentence,
                integration,
                tool,
                args
            ])
            .to_string(),
        );
        if let Some((matches, _)) = self.content_hit(&key) {
            return if matches.is_empty() { "no" } else { "fits" };
        }
        let out = self
            .client()
            .evaluate_with_reason(
                json!({"kind": "integration_call", "integration": integration, "tool_or_action": tool, "arguments": args}),
                integration_fits_question(&sentence),
                EvaluateOptions {
                    timeout: CONTENT_TIMEOUT,
                    max_retries: 0,
                    caps: Some(vec![
                        ("content".into(), CONTENT_DAILY_CAP),
                        (format!("content:{vm_id}"), CONTENT_AGENT_DAILY_CAP),
                    ]),
                },
            )
            .await;
        let out = match out {
            Ok(o) => o,
            Err(f) => {
                tracing::info!("[ai] integration rule: could not run ({})", f.kind());
                return "unavailable";
            }
        };
        let Some(p) = probability(&out, "fits").filter(|p| (0.0..=1.0).contains(p)) else {
            return "unavailable";
        };
        let fits = p >= CONTENT_THRESHOLD;
        let mut probs = IndexMap::new();
        probs.insert("fits".to_string(), p);
        put(
            &self.content_cache,
            CONTENT_CACHE_MAX,
            key,
            self.now(),
            (if fits { vec!["fits".to_string()] } else { vec![] }, probs),
        );
        tracing::info!(
            "[ai] integration rule: {integration} {tool}: {}",
            if fits { "fits" } else { "does not fit" }
        );
        if fits { "fits" } else { "no" }
    }

    /// What an MCP tool does, for a tool whose server gave no hint. `None` when the AI cannot answer.
    pub async fn label_tool(
        &self,
        server: &str,
        name: &str,
        description: Option<&str>,
        argument_names: &[String],
    ) -> Option<&'static str> {
        self.pinned_identity()?;
        let out = self
            .client()
            .evaluate_with_reason(
                json!({
                    "kind": "mcp_tool",
                    "server": server,
                    "tool_name": name,
                    "description": js_slice(description.unwrap_or(""), 2000),
                    "argument_names": argument_names.iter().take(50).collect::<Vec<_>>(),
                }),
                tool_kind_questions(),
                EvaluateOptions {
                    timeout: CONTENT_TIMEOUT,
                    max_retries: 0,
                    caps: Some(vec![("labels".into(), TOOL_LABEL_DAILY_CAP)]),
                },
            )
            .await
            .ok()?;
        let ro = probability(&out, "read_only")?;
        let de = probability(&out, "destructive")?;
        // Destructive wins over read only.
        Some(if de >= CONTENT_THRESHOLD {
            "destructive"
        } else if ro >= CONTENT_THRESHOLD {
            "read"
        } else {
            "write"
        })
    }

    pub async fn judge(&self, req: &JudgeRequest) -> JudgeAnswer {
        // The settings and key are read once for the whole request.
        let Some(ready) = self.client().ready().filter(|(s, _)| s.checks) else {
            return JudgeAnswer::fallback();
        };
        if req.mode == "approve" {
            return self.approve(req, ready).await;
        }
        let settings = ready.0.clone();
        let key = Self::key(&settings, req);
        if let Some(hit) = self.cached(&key) {
            return JudgeAnswer { cached: true, ..hit };
        }
        let owner = owner_instructions(settings.request_instructions.as_deref(), req.policy.as_deref());
        let Ok(result) = self
            .client()
            .evaluate_ready(
                Some(ready),
                Self::state(req),
                inline_questions(&owner),
                EvaluateOptions {
                    timeout: EVALUATE_TIMEOUT,
                    max_retries: 0,
                    caps: None,
                },
            )
            .await
        else {
            return JudgeAnswer::fallback();
        };
        let verdict = choice(&result, "verdict").unwrap_or("allow");
        let category = choice(&result, "category").unwrap_or("normal");
        // A request the model calls ordinary is let through whatever the verdict.
        let decision = if category == "normal" { "allow" } else { verdict };
        let answer = JudgeAnswer::of(decision, category);
        put(&self.cache, CACHE_MAX, key, self.now(), answer.clone());
        if decision != "allow" {
            tracing::info!(
                "[ai] judge: {decision} {} {}{} ({category})",
                req.method,
                req.host,
                req.path
            );
        }
        answer
    }
}

/// The loopback endpoints the proxy calls: `POST /judge` → `{decision, category?, cached?}`, and
/// `POST /content` → `{matches}` or `{failed}`. Anything else is a 404.
pub fn router(judge: Arc<AiJudge>) -> cc_http::Router {
    let mut router = cc_http::Router::new(&["judge"]);
    router.route(
        "judge",
        |_, _| true,
        move |req, _| {
            let judge = judge.clone();
            async move {
                use http_body_util::BodyExt;
                let (parts, body) = req.into_parts();
                let path = parts
                    .uri
                    .path_and_query()
                    .map(|p| p.as_str())
                    .unwrap_or("/")
                    .to_string();
                if parts.method != hyper::Method::POST || (path != "/judge" && path != "/content") {
                    return cc_http::json(404, &json!({"error": "Not found"}));
                }
                let content = path == "/content";
                let max = if content { 512 * 1024 } else { 64 * 1024 };
                // Over the cap the TS drops the socket; this answers nothing either.
                let raw = match http_body_util::Limited::new(body, max).collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(_) => return cc_http::empty(413),
                };
                let parsed: Option<Value> = serde_json::from_slice(&raw).ok();
                if content {
                    let Some(ask) = parsed.as_ref().and_then(parse_content_ask) else {
                        return cc_http::json(400, &json!({"failed": true, "why": "bad request"}));
                    };
                    return cc_http::json(200, &judge.content(&ask).await.to_json());
                }
                let Some(req) = parsed.as_ref().and_then(parse_judge_request) else {
                    return cc_http::json(400, &json!({"decision": "fallback"}));
                };
                cc_http::json(200, &judge.judge(&req).await.to_json())
            }
        },
    );
    router
}
