//! The AI settings the console sends with the egress rules (`ai/settings.ts`), and the per-call
//! provider options (`providerOptionsFor` in `ai/model.ts`).

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    OpenAi,
    Anthropic,
    Google,
    VercelGateway,
    /// The plan's included AI tokens: an AI Gateway key.
    ControlclawIncluded,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "openai" => Self::OpenAi,
            "anthropic" => Self::Anthropic,
            "google" => Self::Google,
            "vercel_gateway" => Self::VercelGateway,
            "controlclaw_included" => Self::ControlclawIncluded,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Google => "google",
            Self::VercelGateway => "vercel_gateway",
            Self::ControlclawIncluded => "controlclaw_included",
        }
    }
}

/// Decision models answer typed questions only; they cannot write a sentence.
pub fn is_decision_model(model: &str) -> bool {
    model.starts_with("typesafe-ai/")
}

static GPT5: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^gpt-5(-mini|-nano)?(-\d{4}-\d{2}-\d{2})?$").unwrap()
});
static O_SERIES: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^o\d").unwrap()
});

/// Zero data retention on every Gateway call. AI SDK asks OpenAI for reasoning effort `none`, which
/// the first GPT-5 models and the o-series refuse, so those get the lowest they accept.
pub fn provider_options_for(provider: Provider, model: &str) -> Value {
    let mut opts = Map::new();
    opts.insert("gateway".into(), json!({ "zeroDataRetention": true }));
    if provider == Provider::OpenAi {
        if GPT5.is_match(model) {
            opts.insert("openai".into(), json!({ "reasoningEffort": "minimal" }));
        } else if O_SERIES.is_match(model) {
            opts.insert("openai".into(), json!({ "reasoningEffort": "low" }));
        }
    }
    Value::Object(opts)
}

/// The first 16 hex of the key's SHA-256: says whether the key changed, never what it is.
pub fn key_fingerprint(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))[..16].to_string()
}

/// Mirrored in apps/saas `AI_INSTRUCTIONS_MAX`.
pub const INSTRUCTIONS_MAX: usize = 2000;

static CONTROL: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"[\x00-\x08\x0b-\x1f\x7f]").unwrap()
});
static TRIPLE_QUOTE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r#""{3,}"#).unwrap()
});

/// Owner text made safe to quote: control characters out, `"""` collapsed so it cannot close its
/// own quote, trimmed and capped. None when empty. The cap counts chars; the TS counts UTF-16 units,
/// which differs only for text outside the BMP.
pub fn clean_instructions(v: &Value, max: usize) -> Option<String> {
    let s = v.as_str()?;
    let s = CONTROL.replace_all(s, " ");
    let s = TRIPLE_QUOTE.replace_all(&s, "\"");
    let s = s.trim();
    (!s.is_empty()).then(|| s.chars().take(max).collect())
}

/// `parseAiSettings`: the `ai` block of `GET /api/vm-agent/egress-rules`.
#[derive(Debug, Clone, PartialEq)]
pub struct AiSettings {
    pub credential_id: String,
    pub provider: Provider,
    pub model: String,
    pub checks: bool,
    pub log_review: bool,
    pub daily_call_cap: u64,
    pub scan_interval_hours: u64,
    pub auto_approve_per_hour: u64,
    pub request_instructions: Option<String>,
    pub review_instructions: Option<String>,
    /// Hosts and kinds of finding the owner marked as false alarms, newest first, at most
    /// `FALSE_ALARMS_MAX`. The review still reads the traffic: it is told the pair is expected, and
    /// a finding of that kind on that host below high, with no warning sign (refused, failed, a
    /// tripwire, more than 1 MB sent), is not posted again. Any other kind of finding is.
    pub false_alarms: Vec<FalseAlarm>,
    /// Hosts and kinds of finding the console's investigation dismissed for an agent in the last
    /// day, newest first, at most `FALSE_ALARMS_MAX`. Only a hint: the review is told an earlier
    /// finding like it was looked into and dismissed, and still posts what it finds new. Empty from
    /// an older console or a standalone firewall (no investigation there).
    pub recent_dismissals: Vec<FalseAlarm>,
    /// What each agent is set up to reach (its integrations, its model, the hosts its rules and
    /// the managed rules allow), so AI Log Review can tell expected traffic from the rest. Sent by
    /// the console with Log Review on; empty from an older console or a standalone firewall.
    pub agents: Vec<AgentContext>,
}

/// Mirrored in apps/saas `AI_FALSE_ALARMS_MAX`: the console sends at most this many.
pub const FALSE_ALARMS_MAX: usize = 50;

/// The AI review's finding categories a false alarm can name (`normal` is never a finding).
const FALSE_ALARM_CATEGORIES: [&str; 5] = [
    "data_exfiltration",
    "destructive_change",
    "credential_misuse",
    "unusual_destination",
    "policy_mismatch",
];

/// A finding the owner marked as a false alarm: this host, this kind of problem, on one agent
/// (`vm_id`) or on every agent (`None`).
#[derive(Debug, Clone, PartialEq)]
pub struct FalseAlarm {
    pub host: String,
    pub category: String,
    pub vm_id: Option<String>,
}

impl FalseAlarm {
    /// Whether this one is about the agent `vm_id`.
    pub fn applies_to(&self, vm_id: Option<&str>) -> bool {
        self.vm_id.is_none() || self.vm_id.as_deref() == vm_id
    }

    fn parse(v: &Value) -> Option<Self> {
        let r = v.as_object()?;
        let host = r.get("host")?.as_str()?.trim().to_ascii_lowercase();
        // A host name or an address, nothing else: it is quoted to the model.
        if host.is_empty()
            || host.len() > 253
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'))
        {
            return None;
        }
        let category = r.get("category")?.as_str()?;
        if !FALSE_ALARM_CATEGORIES.contains(&category) {
            return None;
        }
        let vm_id = match r.get("vm_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() && s.len() <= 100 => Some(s.clone()),
            Some(_) => return None,
        };
        Some(Self {
            host,
            category: category.into(),
            vm_id,
        })
    }

    /// The `false_alarms` list: the well-formed entries, in the order sent (newest first), capped.
    pub fn parse_list(v: Option<&Value>) -> Vec<Self> {
        v.and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Self::parse).take(FALSE_ALARMS_MAX).collect())
            .unwrap_or_default()
    }
}

/// Mirrored in apps/saas `AI_AGENT_CONTEXT_MAX`: the console sends at most this many agents, and this
/// many hosts and integrations per agent.
pub const AGENT_CONTEXT_MAX: usize = 100;
pub const AGENT_HOSTS_MAX: usize = 60;
pub const AGENT_INTEGRATIONS_MAX: usize = 40;

/// One agent's setup, as the first pass shows it to the model (`agent_context`). Every field is a
/// short token or a host pattern: nothing the console sends can carry a sentence into the state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AgentContext {
    pub vm_id: String,
    /// Kinds and short names: `telegram`, `google:gmail`, `connector:github`, `mcp:linear`.
    pub integrations: Vec<String>,
    /// The agent's own model: provider and model id.
    pub model: Option<(String, String)>,
    /// Hosts its integrations, its model and its Allow rules reach (`*.` allowed in front).
    pub expected_hosts: Vec<String>,
}

/// A host name, an address or a `*.` pattern, lower case.
fn host_token(v: &Value) -> Option<String> {
    let h = v.as_str()?.trim().to_ascii_lowercase();
    let rest = h.strip_prefix("*.").unwrap_or(&h);
    (!rest.is_empty()
        && h.len() <= 253
        && rest
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']')))
    .then_some(h)
}

/// A kind or a name: `[a-z0-9:_.-]`, at most 64.
fn short_token(v: &Value) -> Option<String> {
    let t = v.as_str()?.trim().to_ascii_lowercase();
    (!t.is_empty()
        && t.len() <= 64
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '_' | '.' | '-' | '/')))
    .then_some(t)
}

fn token_list(v: Option<&Value>, max: usize, f: fn(&Value) -> Option<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in v.and_then(Value::as_array).into_iter().flatten().filter_map(f) {
        if !out.contains(&t) {
            out.push(t);
        }
        if out.len() == max {
            break;
        }
    }
    out
}

impl AgentContext {
    fn parse(v: &Value) -> Option<Self> {
        let r = v.as_object()?;
        let vm_id = r
            .get("vm_id")?
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 100)?
            .to_string();
        let model = r
            .get("model")
            .and_then(Value::as_object)
            .and_then(|m| Some((short_token(m.get("provider")?)?, short_token(m.get("model")?)?)));
        Some(Self {
            vm_id,
            integrations: token_list(r.get("integrations"), AGENT_INTEGRATIONS_MAX, short_token),
            model,
            expected_hosts: token_list(r.get("expected_hosts"), AGENT_HOSTS_MAX, host_token),
        })
    }

    pub fn parse_list(v: Option<&Value>) -> Vec<Self> {
        v.and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Self::parse).take(AGENT_CONTEXT_MAX).collect())
            .unwrap_or_default()
    }

    /// The state's `agent_context`.
    pub fn to_state(&self) -> Value {
        let mut o = Map::new();
        if !self.integrations.is_empty() {
            o.insert("integrations".into(), json!(self.integrations));
        }
        if let Some((provider, model)) = &self.model {
            o.insert("model".into(), json!({"provider": provider, "model": model}));
        }
        if !self.expected_hosts.is_empty() {
            o.insert("expected_hosts".into(), json!(self.expected_hosts));
        }
        Value::Object(o)
    }
}

impl AiSettings {
    /// The setup of the agent `vm_id`, when the console sent one.
    pub fn agent(&self, vm_id: Option<&str>) -> Option<&AgentContext> {
        let vm_id = vm_id?;
        self.agents.iter().find(|a| a.vm_id == vm_id)
    }

    pub fn parse(raw: &Value) -> Option<Self> {
        let r = raw.as_object()?;
        let credential_id = r.get("credential_id")?.as_str().filter(|s| !s.is_empty())?.to_string();
        let provider = Provider::parse(r.get("provider")?.as_str()?)?;
        let model = r.get("model")?.as_str().filter(|s| !s.is_empty())?.to_string();
        Some(Self {
            credential_id,
            provider,
            model,
            checks: r.get("checks") != Some(&Value::Bool(false)),
            log_review: r.get("log_review") != Some(&Value::Bool(false)),
            daily_call_cap: positive_int(r.get("daily_call_cap"), 5000),
            scan_interval_hours: positive_int(r.get("scan_interval_hours"), 6),
            // 0 is meaningful: the AI never approves.
            auto_approve_per_hour: int_at_least(r.get("auto_approve_per_hour"), 0, 30),
            request_instructions: r
                .get("request_instructions")
                .and_then(|v| clean_instructions(v, INSTRUCTIONS_MAX)),
            review_instructions: r
                .get("review_instructions")
                .and_then(|v| clean_instructions(v, INSTRUCTIONS_MAX)),
            false_alarms: FalseAlarm::parse_list(r.get("false_alarms")),
            recent_dismissals: FalseAlarm::parse_list(r.get("recent_dismissals")),
            agents: AgentContext::parse_list(r.get("agents")),
        })
    }
}

fn positive_int(v: Option<&Value>, fallback: u64) -> u64 {
    int_at_least(v, 1, fallback)
}

/// A JS `Number.isInteger` check: 3.0 counts, 3.5 does not.
fn int_at_least(v: Option<&Value>, min: u64, fallback: u64) -> u64 {
    match v.and_then(Value::as_f64) {
        Some(f) if f.fract() == 0.0 && f >= min as f64 && f <= u64::MAX as f64 => f as u64,
        _ => fallback,
    }
}
