//! The email rules' shapes and pure logic (`email-rules-schema.ts`, docs/plans/email-rules.md). One
//! set per organization, held on the firewall, applying to every mailbox the org has. A mailbox is
//! `agentmail:<inbox id>` or `gmail:<address>`; an entry with `mailbox: null` applies to all.

use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

static MAILBOX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:agentmail|gmail):[^\s@]+@[^\s@]+$").expect("regex"));
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$").expect("regex")
});
static LOCAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^[^\s@"<>(),;:\\\[\]]{1,64}$"#).expect("regex"));

pub const PER_HOUR: (i64, i64) = (1, 200);
pub const PER_DAY: (i64, i64) = (1, 2000);
pub const MAX_RECIPIENTS: usize = 20;
pub const MAX_ENTRIES: usize = 200;
/// Approve once: how long one approved recipient may be emailed (docs/plans/email-rules.md §2.2).
pub const EMAIL_GRANT_SECONDS: i64 = 30 * 60;

use crate::channels::js::js_len;

/// `mailboxRef`: checked, then lowercased.
pub fn mailbox_ref(v: &Value) -> Option<String> {
    let s = v.as_str()?;
    (js_len(s) <= 300 && MAILBOX.is_match(s)).then(|| s.to_lowercase())
}

pub fn domain_ok(d: &str) -> bool {
    DOMAIN.is_match(d)
}

/// `addressPattern`: `bob@x.com` (one address) or `@x.com` (the whole domain). Trimmed and
/// lowercased first; no plus-tag folding.
pub fn address_pattern(v: &Value) -> Option<String> {
    let v = v.as_str()?.trim().to_lowercase();
    if js_len(&v) > 254 {
        return None;
    }
    let ok = if let Some(d) = v.strip_prefix('@') {
        domain_ok(d)
    } else {
        match v.rfind('@') {
            Some(at) if at > 0 => LOCAL.is_match(&v[..at]) && domain_ok(&v[at + 1..]),
            _ => false,
        }
    };
    ok.then_some(v)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEntry {
    pub value: String,
    pub mailbox: Option<String>,
}

fn rule_entry(v: &Value) -> Option<RuleEntry> {
    let o = v.as_object()?;
    let value = address_pattern(o.get("value")?)?;
    let mailbox = match o.get("mailbox") {
        None | Some(Value::Null) => None,
        Some(m) => Some(mailbox_ref(m)?),
    };
    Some(RuleEntry { value, mailbox })
}

/// `anyone`: any address, with no list check and no request. The limits still apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Listed,
    Ask,
    Block,
    Anyone,
}

impl Mode {
    fn parse(v: &Value) -> Option<Self> {
        serde_json::from_value(v.clone()).ok()
    }
    fn rank(self) -> u8 {
        match self {
            Mode::Block => 0,
            Mode::Listed => 1,
            Mode::Ask => 2,
            Mode::Anyone => 3,
        }
    }
    /// What agents will do in each mode, as the code message says it.
    fn words(self) -> &'static str {
        match self {
            Mode::Listed => "send only to listed people",
            Mode::Ask => "ask before emailing someone new",
            Mode::Block => "send no email",
            Mode::Anyone => "be able to email anyone, with no list and no request to you",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequireAuth {
    Aligned,
    Dmarc,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Inbound {
    pub require_auth: RequireAuth,
    pub senders: Vec<RuleEntry>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MailboxMode {
    pub mailbox: String,
    pub mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Outbound {
    pub mode: Mode,
    /// Per-mailbox modes; only ever stricter than `mode` (enforced in `effective_mode`).
    pub mailbox_modes: Vec<MailboxMode>,
    pub recipients: Vec<RuleEntry>,
    pub replies_to_senders: bool,
    pub per_hour: i64,
    pub per_day: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmailRules {
    pub version: u32,
    pub inbound: Inbound,
    pub outbound: Outbound,
}

impl Default for EmailRules {
    fn default() -> Self {
        Self {
            version: 1,
            inbound: Inbound {
                require_auth: RequireAuth::Aligned,
                senders: vec![],
            },
            outbound: Outbound {
                mode: Mode::Ask,
                mailbox_modes: vec![],
                recipients: vec![],
                replies_to_senders: true,
                per_hour: 20,
                per_day: 100,
            },
        }
    }
}

/// A JSON number that is an integer (`5` and `5.0` alike, as zod's `int()`), within bounds.
fn int_in(v: &Value, (min, max): (i64, i64)) -> Option<i64> {
    let f = v.as_f64()?;
    (f.fract() == 0.0 && f >= min as f64 && f <= max as f64).then_some(f as i64)
}

fn entries(v: Option<&Value>) -> Option<Vec<RuleEntry>> {
    let a = v?.as_array()?;
    if a.len() > MAX_ENTRIES {
        return None;
    }
    a.iter().map(rule_entry).collect()
}

/// `emailRules.parse`: every field checked as zod does, unknown keys dropped.
pub fn parse_rules(v: &Value) -> Option<EmailRules> {
    let o = v.as_object()?;
    if o.get("version")?.as_f64()? != 1.0 {
        return None;
    }
    let i = o.get("inbound")?.as_object()?;
    let out = o.get("outbound")?.as_object()?;
    let mm = out.get("mailboxModes")?.as_array()?;
    if mm.len() > MAX_ENTRIES {
        return None;
    }
    let mailbox_modes = mm
        .iter()
        .map(|m| {
            Some(MailboxMode {
                mailbox: mailbox_ref(m.get("mailbox")?)?,
                mode: Mode::parse(m.get("mode")?)?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(EmailRules {
        version: 1,
        inbound: Inbound {
            require_auth: serde_json::from_value(i.get("requireAuth")?.clone()).ok()?,
            senders: entries(i.get("senders"))?,
        },
        outbound: Outbound {
            mode: Mode::parse(out.get("mode")?)?,
            mailbox_modes,
            recipients: entries(out.get("recipients"))?,
            replies_to_senders: out.get("repliesToSenders")?.as_bool()?,
            per_hour: int_in(out.get("perHour")?, PER_HOUR)?,
            per_day: int_in(out.get("perDay")?, PER_DAY)?,
        },
    })
}

/// One change, as the console (or a WebMCP tool) proposes it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum EmailChange {
    AddSender {
        entry: RuleEntry,
    },
    RemoveSender {
        entry: RuleEntry,
    },
    AddRecipient {
        entry: RuleEntry,
    },
    RemoveRecipient {
        entry: RuleEntry,
    },
    SetInboundAuth {
        #[serde(rename = "requireAuth")]
        require_auth: RequireAuth,
    },
    SetOutbound {
        #[serde(skip_serializing_if = "Option::is_none")]
        mode: Option<Mode>,
        #[serde(rename = "repliesToSenders", skip_serializing_if = "Option::is_none")]
        replies_to_senders: Option<bool>,
        #[serde(rename = "perHour", skip_serializing_if = "Option::is_none")]
        per_hour: Option<i64>,
        #[serde(rename = "perDay", skip_serializing_if = "Option::is_none")]
        per_day: Option<i64>,
    },
    SetMailboxMode {
        mailbox: String,
        mode: Option<Mode>,
    },
}

/// `emailChange.parse`. `undefined` and absent are the same; `null` is refused where zod refuses it.
pub fn parse_change(v: &Value) -> Option<EmailChange> {
    let o = v.as_object()?;
    let opt = |k: &str| o.get(k);
    let entry = || rule_entry(opt("entry")?);
    Some(match opt("action")?.as_str()? {
        "add_sender" => EmailChange::AddSender { entry: entry()? },
        "remove_sender" => EmailChange::RemoveSender { entry: entry()? },
        "add_recipient" => EmailChange::AddRecipient { entry: entry()? },
        "remove_recipient" => EmailChange::RemoveRecipient { entry: entry()? },
        "set_inbound_auth" => EmailChange::SetInboundAuth {
            require_auth: serde_json::from_value(opt("requireAuth")?.clone()).ok()?,
        },
        "set_outbound" => EmailChange::SetOutbound {
            mode: match opt("mode") {
                None => None,
                Some(m) => Some(Mode::parse(m)?),
            },
            replies_to_senders: match opt("repliesToSenders") {
                None => None,
                Some(b) => Some(b.as_bool()?),
            },
            per_hour: match opt("perHour") {
                None => None,
                Some(n) => Some(int_in(n, PER_HOUR)?),
            },
            per_day: match opt("perDay") {
                None => None,
                Some(n) => Some(int_in(n, PER_DAY)?),
            },
        },
        "set_mailbox_mode" => EmailChange::SetMailboxMode {
            mailbox: mailbox_ref(opt("mailbox")?)?,
            mode: match opt("mode")? {
                Value::Null => None,
                m => Some(Mode::parse(m)?),
            },
        },
        _ => return None,
    })
}

/// `applyChange`: a copy of the rules with the change made. `Err` for a change that makes no sense.
pub fn apply_change(rules: &EmailRules, change: &EmailChange) -> Result<EmailRules, &'static str> {
    let mut next = rules.clone();
    fn add(list: &mut Vec<RuleEntry>, e: &RuleEntry) -> Result<(), &'static str> {
        if list.contains(e) {
            return Err("Already listed");
        }
        if list.len() >= MAX_ENTRIES {
            return Err("List is full");
        }
        list.push(e.clone());
        Ok(())
    }
    fn remove(list: &mut Vec<RuleEntry>, e: &RuleEntry) -> Result<(), &'static str> {
        let i = list.iter().position(|x| x == e).ok_or("Not listed")?;
        list.remove(i);
        Ok(())
    }
    match change {
        EmailChange::AddSender { entry } => add(&mut next.inbound.senders, entry)?,
        EmailChange::RemoveSender { entry } => remove(&mut next.inbound.senders, entry)?,
        EmailChange::AddRecipient { entry } => add(&mut next.outbound.recipients, entry)?,
        EmailChange::RemoveRecipient { entry } => remove(&mut next.outbound.recipients, entry)?,
        EmailChange::SetInboundAuth { require_auth } => next.inbound.require_auth = *require_auth,
        EmailChange::SetOutbound {
            mode,
            replies_to_senders,
            per_hour,
            per_day,
        } => {
            if let Some(m) = mode {
                next.outbound.mode = *m;
            }
            if let Some(r) = replies_to_senders {
                next.outbound.replies_to_senders = *r;
            }
            if let Some(n) = per_hour {
                next.outbound.per_hour = *n;
            }
            if let Some(n) = per_day {
                next.outbound.per_day = *n;
            }
        }
        EmailChange::SetMailboxMode { mailbox, mode } => {
            next.outbound.mailbox_modes.retain(|m| &m.mailbox != mailbox);
            if let Some(m) = mode {
                next.outbound.mailbox_modes.push(MailboxMode {
                    mailbox: mailbox.clone(),
                    mode: *m,
                });
            }
        }
    }
    // `emailRules.parse(next)`: only the list lengths can be out of bounds here.
    if next.outbound.mailbox_modes.len() > MAX_ENTRIES {
        return Err("Too many mailbox modes");
    }
    Ok(next)
}

/// The mode for one mailbox: the org mode, or the per-mailbox one when it is stricter.
pub fn effective_mode(rules: &EmailRules, mailbox: &str) -> Mode {
    let org = rules.outbound.mode;
    match rules.outbound.mailbox_modes.iter().find(|m| m.mailbox == mailbox) {
        Some(own) if own.mode.rank() < org.rank() => own.mode,
        _ => org,
    }
}

/// Whether `next` lets anybody new instruct an agent or receive mail from one, compared with
/// `prev`. Those changes need a confirmation code (docs/plans/email-rules.md §3). Rate limits are
/// policy, not consent, and never count.
pub fn widens(prev: &EmailRules, next: &EmailRules) -> bool {
    let added = |a: &[RuleEntry], b: &[RuleEntry]| b.iter().any(|e| !a.contains(e));
    if added(&prev.inbound.senders, &next.inbound.senders)
        || added(&prev.outbound.recipients, &next.outbound.recipients)
    {
        return true;
    }
    if prev.inbound.require_auth == RequireAuth::Dmarc && next.inbound.require_auth == RequireAuth::Aligned {
        return true;
    }
    if !prev.outbound.replies_to_senders && next.outbound.replies_to_senders {
        return true;
    }
    if next.outbound.mode.rank() > prev.outbound.mode.rank() {
        return true;
    }
    prev.outbound
        .mailbox_modes
        .iter()
        .chain(&next.outbound.mailbox_modes)
        .any(|m| effective_mode(next, &m.mailbox).rank() > effective_mode(prev, &m.mailbox).rank())
}

/// The domain part of an address, lowercased; `None` when there is none.
pub fn domain_of(address: &str) -> Option<String> {
    let at = address.rfind('@').filter(|&at| at > 0)?;
    let d = address[at + 1..].to_lowercase();
    domain_ok(&d).then_some(d)
}

/// Whether `address` is covered by one of `entries` for `mailbox`.
pub fn listed(entries: &[RuleEntry], address: &str, mailbox: &str) -> bool {
    let a = address.trim().to_lowercase();
    let d = domain_of(&a).map(|d| format!("@{d}"));
    entries.iter().any(|e| {
        e.mailbox.as_deref().is_none_or(|m| m == mailbox) && (e.value == a || d.as_deref() == Some(e.value.as_str()))
    })
}

fn bare(mailbox: &str) -> &str {
    mailbox.split_once(':').map_or(mailbox, |(_, r)| r)
}

/// One line a person reads on their phone next to the code. Written here, never by the console.
/// `next` is the rules as the change would leave them, so a mailbox's line says how it will really
/// send.
pub fn describe_change(change: &EmailChange, next: Option<&EmailRules>) -> String {
    let place = |e: &RuleEntry| {
        e.mailbox
            .as_deref()
            .map_or(String::new(), |m| format!(" ({} only)", bare(m)))
    };
    let who = |e: &RuleEntry| match e.value.strip_prefix('@') {
        Some(d) => format!("anyone at {d}"),
        None => e.value.clone(),
    };
    match change {
        EmailChange::AddSender { entry } => format!("Let {} email your agents{}", who(entry), place(entry)),
        EmailChange::RemoveSender { entry } => {
            format!("Stop {} from emailing your agents{}", who(entry), place(entry))
        }
        EmailChange::AddRecipient { entry } => {
            format!("Let your agents send email to {}{}", who(entry), place(entry))
        }
        EmailChange::RemoveRecipient { entry } => {
            format!("Stop your agents sending email to {}{}", who(entry), place(entry))
        }
        EmailChange::SetInboundAuth { require_auth } => match require_auth {
            RequireAuth::Dmarc => "Only accept email that passes DMARC".into(),
            RequireAuth::Aligned => {
                "Accept email that passes DMARC or has a DKIM signature from the sender's domain".into()
            }
        },
        EmailChange::SetOutbound {
            mode,
            replies_to_senders,
            per_hour,
            per_day,
        } => {
            let mut parts: Vec<String> = vec![];
            if let Some(m) = mode {
                parts.push(m.words().into());
            }
            if let Some(r) = replies_to_senders {
                parts.push(
                    if *r {
                        "reply to people allowed to email them"
                    } else {
                        "not reply unless the person is listed"
                    }
                    .into(),
                );
            }
            if per_hour.is_some() || per_day.is_some() {
                let n = |v: &Option<i64>| v.map_or("the same".to_string(), |n| n.to_string());
                parts.push(format!(
                    "send at most {} an hour and {} a day per mailbox",
                    n(per_hour),
                    n(per_day)
                ));
            }
            format!("Agents will {}", parts.join(", "))
        }
        EmailChange::SetMailboxMode { mailbox, mode } => {
            let effective = next.map(|n| effective_mode(n, mailbox)).or(*mode);
            let follows = if effective == Some(Mode::Anyone) {
                format!("follow the organization setting and {}", Mode::Anyone.words())
            } else {
                "follow the organization setting".into()
            };
            let what = match (mode, effective) {
                (Some(_), Some(m)) => m.words().to_string(),
                _ => follows,
            };
            format!("{} will {}", bare(mailbox), what)
        }
    }
}
