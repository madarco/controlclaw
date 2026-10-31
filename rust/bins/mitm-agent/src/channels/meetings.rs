//! Meetings on the firewall (`meetings.ts`): the approved settings for each agent and their codes,
//! the media lease an agent asks for when it joins a call (`/__cc/meetings/media` on the ingress),
//! and the speech credentials the proxy swaps in. The settings' shape and what widens them are the
//! agent's own code (`cc_meetings::policy`), so both read the same rules.

use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use bytes::Bytes;
use cc_meetings::policy::{
    OP_ID, auto_join_summary, auto_join_widens, full_agent_meeting, full_agent_summary, full_agent_widens,
    parse_auto_join_claim, parse_meeting_policy, present_summary, present_widens, speech_family, wake_sessions,
};
use cc_meetings::{MEDIA_MAX_BYTES, MEDIA_MAX_SECONDS, MEDIA_TTL_SECONDS, MEETING_ORDERS_MAX};
use http::StatusCode;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::channels::agent::{AgentCalls, Target};
use cc_meetings::js::{js_trim, len16 as js_len, truthy};

use crate::channels::js::js_slice_range;
use crate::commands::CommandOutcome;
use crate::contracts::{CodeAsk, CodeCheck, CodeRoute, CodeSent, ModuleCodes};
use crate::core::code_message::{BUTTONS_OUTRO, CodeParts, Details, TypedLine, build_code_message, clean_line};

/// The most of one line a line of the code message holds: a longer line is shown in pieces.
const PIECE: usize = 250;
static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-f0-9]{64}$").expect("regex"));

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Auto {
    pub day: String,
    pub count: i64,
}

/// One agent's approved settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub policy: Value,
    pub revision: i64,
    pub token: String,
    pub hostname: String,
    pub applied: bool,
    #[serde(rename = "voicePlaceholder", default, skip_serializing_if = "Option::is_none")]
    pub voice_placeholder: Option<String>,
    /// Joins the agent started by itself today (UTC), against autoJoin.maxPerDay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<Auto>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// New meeting instructions for the agent's AGENTS.md, and the version of them the console read.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Instructions {
    pub text: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Proposal {
    vm_id: String,
    change_id: String,
    policy: Value,
    base_revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    instructions: Option<Instructions>,
}

fn invalid() -> String {
    "Invalid meetings request".into()
}

/// The instructions a meetings change carries, or `None`. The agent checks the text itself.
fn parse_instructions(raw: Option<&Value>) -> Result<Option<Instructions>, String> {
    let Some(raw) = raw else { return Ok(None) };
    let m = raw.as_object().ok_or_else(invalid)?;
    let (Some(Value::String(text)), Some(Value::String(version))) = (m.get("text"), m.get("version")) else {
        return Err(invalid());
    };
    if m.len() != 2 || js_len(text) > MEETING_ORDERS_MAX || js_len(version) > 200 {
        return Err(invalid());
    }
    Ok(Some(Instructions {
        text: text.clone(),
        version: version.clone(),
    }))
}

/// The instructions as they are both shown and written: each line laid out as the code message lays
/// out a line, at most one blank line in a row. `hidden`: a line had characters the message cannot
/// show.
pub fn clean_instructions(text: &str) -> (String, bool) {
    static BLANKS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\n{3,}").expect("regex"));
    let mut hidden = false;
    let lines: Vec<String> = text
        .split('\n')
        .map(|line| {
            let (clean, replaced) = clean_line(line);
            hidden |= replaced;
            clean
        })
        .collect();
    let joined = BLANKS.replace_all(&lines.join("\n"), "\n\n").into_owned();
    (js_trim(&joined).to_string(), hidden)
}

/// The instructions as the code message shows them: each line in pieces; blank lines left out.
fn pieces(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.split('\n') {
        let units: Vec<u16> = line.encode_utf16().collect();
        let mut i = 0;
        while i < units.len() {
            let piece = js_slice_range(&units, i, i + PIECE);
            let piece = js_trim(&piece);
            if !piece.is_empty() {
                out.push(piece.to_string());
            }
            i += PIECE;
        }
    }
    out
}

/// The code message for new meeting instructions: every line of them, numbered, and a last line of
/// ours that says how many there were. `settings`: our sentence for a settings change that needs the
/// same code, or empty.
pub fn instructions_code_parts(hostname: &str, text: &str, settings: &str) -> CodeParts {
    let shown = pieces(text);
    let n = shown.len();
    let details = format!(
        "{}After each meeting the agent follows its meeting instructions. {}",
        if settings.is_empty() {
            String::new()
        } else {
            format!("{settings} ")
        },
        if n > 0 {
            format!(
                "The new ones are at the end of this message, in {n} {}, and its last line is “End: {n}”. If it is not, do not use the code.",
                if n == 1 { "line" } else { "lines" }
            )
        } else {
            "The new ones are empty: the agent will only save notes.".to_string()
        }
    );
    let mut typed: Vec<TypedLine> = shown
        .iter()
        .enumerate()
        .map(|(i, l)| TypedLine {
            label: format!("Line {}", i + 1),
            text: l.clone(),
            more: None,
        })
        .collect();
    if n > 0 {
        typed.push(TypedLine {
            label: "End".into(),
            text: n.to_string(),
            more: None,
        });
    }
    CodeParts {
        ask: format!(
            "Confirm new meeting instructions for {hostname}{}.",
            if settings.is_empty() {
                ""
            } else {
                ", and a change to its meetings"
            }
        ),
        details: Some(Details::Text(details)),
        typed,
        outro: None,
    }
}

/// Whether the code messages for these instructions, with and without the buttons, show every line
/// as written.
fn instructions_fit(hostname: &str, text: &str, settings: &str) -> bool {
    let parts = instructions_code_parts(hostname, text, settings);
    let shown = pieces(text);
    [None, Some(BUTTONS_OUTRO)].iter().all(|outro| {
        let Ok(message) = build_code_message("000000", Some(&parts), hostname, "", None, *outro) else {
            return false;
        };
        shown
            .iter()
            .enumerate()
            .all(|(i, l)| message.contains(&format!("Line {}: {l}\n", i + 1)))
            && (shown.is_empty() || message.ends_with(&format!("End: {}", shown.len())))
    })
}

/// An identity row the module reads: id, hostname, role.
pub type IdentityRow = (String, Option<String>, Option<String>);
type OrganizerAllowed = Arc<dyn Fn(&str, &Value) -> bool + Send + Sync>;
type OwnAccount = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;
type SpeechCredential = Option<(String, String, Option<String>)>;

pub struct MeetingsOptions {
    pub store_path: std::path::PathBuf,
    /// The directory of `meeting-media.json`.
    pub media_dir: std::path::PathBuf,
    pub box_key: String,
    pub org_id: String,
    pub box_id: String,
    pub agent: Arc<dyn AgentCalls>,
    pub identities: Arc<dyn Fn() -> Vec<IdentityRow> + Send + Sync>,
    pub firewall_origin: Arc<dyn Fn() -> String + Send + Sync>,
    /// This module's codes, typed on the Meetings card: no buttons.
    pub codes: Arc<dyn Fn() -> Option<Arc<dyn ModuleCodes>> + Send + Sync>,
    pub code_routes: Arc<dyn Fn() -> Vec<CodeRoute> + Send + Sync>,
    pub channels_ready: Arc<dyn Fn() -> bool + Send + Sync>,
    pub locked: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// The credential for a speech policy: secret, host, account id.
    pub speech_credential: Arc<dyn Fn(&Value) -> SpeechCredential + Send + Sync>,
    /// The proxy config rewritten with the new credentials; an error fails the change before the
    /// agent is told (the TS's `runSync` throws).
    pub on_credentials_changed: Arc<dyn Fn() -> cc_http::BoxFuture<Result<(), String>> + Send + Sync>,
    /// Whether the organizer of an invite may make this agent join.
    pub organizer_allowed: OrganizerAllowed,
    /// The Google account connected for this agent, lower-cased.
    pub own_account: OwnAccount,
    pub now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

struct State {
    entries: IndexMap<String, Entry>,
    leases: IndexMap<String, Map<String, Value>>,
}

pub struct MeetingsFirewall {
    opts: MeetingsOptions,
    aad: String,
    st: Mutex<State>,
    /// One publish at a time, from reading the leases to writing the file: a slower one cannot
    /// write an older lease back, and two never share the temp file.
    publishing: Mutex<()>,
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    hex::encode(b)
}

/// A number as JavaScript prints it: whole numbers without a point.
fn num(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 9e15 {
        json!(f as i64)
    } else {
        json!(f)
    }
}

fn out(ok: bool, status: &str, message: Option<&str>, data: Option<Value>) -> CommandOutcome {
    CommandOutcome {
        ok,
        status: status.into(),
        message: message.map(str::to_string),
        data: data.and_then(|d| d.as_object().cloned()),
    }
}

/// `JSON.stringify(x ?? null)` equality for the speech settings.
/// Both sides come from `parse_meeting_policy`, which rebuilds the speech settings in the TS's key
/// order, so value equality is `JSON.stringify` equality here.
fn same_speech(a: Option<&Value>, b: Option<&Value>) -> bool {
    a.unwrap_or(&Value::Null) == b.unwrap_or(&Value::Null)
}

impl MeetingsFirewall {
    pub fn new(opts: MeetingsOptions) -> Result<Arc<Self>, String> {
        let aad = format!("{}:{}:meetings", opts.org_id, opts.box_id);
        let entries =
            cc_crypto::enc_file::load_store_or_empty("meetings", &opts.store_path, &opts.box_key, &aad, &|l| {
                tracing::error!("{l}")
            })
            .map(serde_json::from_value::<IndexMap<String, Entry>>)
            .transpose()
            .map_err(|_| "meetings store unavailable".to_string())?
            .unwrap_or_default();
        let fw = Arc::new(Self {
            opts,
            aad,
            publishing: Mutex::new(()),
            st: Mutex::new(State {
                entries,
                leases: IndexMap::new(),
            }),
        });
        // A restart revokes all active leases. It never restores a running media tunnel.
        fw.publish()?;
        Ok(fw)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.opts.now)()
    }

    fn save(&self, entries: &IndexMap<String, Entry>) -> Result<(), String> {
        let v = serde_json::to_value(entries).map_err(|e| e.to_string())?;
        cc_crypto::enc_file::save_store("meetings", &self.opts.store_path, &v, &self.opts.box_key, &self.aad)
            .map_err(|e| e.0)
    }

    fn target(&self, vm_id: &str) -> Result<Target, String> {
        let row = (self.opts.identities)()
            .into_iter()
            .find(|(id, _, role)| id == vm_id && role.as_deref().is_none_or(|r| r.is_empty() || r == "openclaw"));
        let Some(hostname) = row.and_then(|r| r.1).filter(|h| !h.is_empty()) else {
            return Err("Agent unavailable".into());
        };
        if let Some(pinned) = self.lock().entries.get(vm_id).map(|e| e.hostname.clone())
            && !pinned.is_empty()
            && pinned != hostname
        {
            return Err("Agent identity changed".into());
        }
        Ok(Target::new(vm_id, &hostname))
    }

    /// `meetings.propose`, `meetings.confirm`, `meetings.cancel`, `meetings.push`; an error is what
    /// the TS throws.
    pub async fn command(&self, action: &str, p: Map<String, Value>) -> Result<CommandOutcome, String> {
        match action {
            "propose" => self.propose(&p).await,
            "confirm" => self.confirm(&p).await,
            "cancel" => {
                let (Some(vm), Some(id)) = (
                    p.get("vmId").and_then(Value::as_str),
                    p.get("changeId").and_then(Value::as_str),
                ) else {
                    return Err(invalid());
                };
                let cancelled = (self.opts.codes)().is_some_and(|c| c.cancel(&format!("meetings:{vm}"), Some(id)));
                if !cancelled {
                    return Ok(out(false, "conflict", None, None));
                }
                Ok(out(true, "cancelled", None, Some(json!({"changeId": id}))))
            }
            "push" => {
                let vm = p.get("vmId").and_then(Value::as_str).ok_or_else(invalid)?;
                Ok(self.push(vm).await)
            }
            _ => Err(invalid()),
        }
    }

    async fn propose(&self, raw: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let (Some(vm_id), Some(change_id)) = (
            raw.get("vmId").and_then(Value::as_str),
            raw.get("changeId")
                .and_then(Value::as_str)
                .filter(|c| OP_ID.is_match(c)),
        ) else {
            return Err(invalid());
        };
        let revision = cc_meetings::js::safe_int(raw.get("revision")).ok_or_else(invalid)?;
        let target = self.target(vm_id)?;
        let policy = parse_meeting_policy(raw.get("policy"))?;
        let asked = parse_instructions(raw.get("instructions"))?;
        // Shown and written the same way; a text with characters the message cannot show gets no code.
        let instructions = match asked {
            None => None,
            Some(a) => {
                let (text, hidden) = clean_instructions(&a.text);
                if hidden {
                    return Ok(out(
                        false,
                        "failed",
                        Some("The meeting instructions have characters the code message cannot show"),
                        Some(json!({"changeId": change_id, "instructions": "characters"})),
                    ));
                }
                Some(Instructions {
                    text,
                    version: a.version,
                })
            }
        };
        let enabled = truthy(policy.get("enabled"));
        let speech = policy.get("speech").filter(|s| truthy(Some(s)));
        if enabled && speech.is_some_and(|s| (self.opts.speech_credential)(s).is_none()) {
            return Err("Speech credential unavailable. Add a compatible API key or included credit first.".into());
        }
        let current = self.lock().entries.get(vm_id).cloned();
        if revision != current.as_ref().map_or(0, |c| c.revision) {
            return Ok(out(false, "conflict", None, Some(json!({"changeId": change_id}))));
        }
        let proposal = Proposal {
            vm_id: vm_id.into(),
            change_id: change_id.into(),
            policy: policy.clone(),
            base_revision: revision,
            instructions: instructions.clone(),
        };
        let scope = format!("meetings:{vm_id}");
        let forget = || {
            if let Some(c) = (self.opts.codes)() {
                c.forget(&scope);
            }
        };
        // New instructions always need a code: they are text the agent acts on after every meeting.
        if !enabled && instructions.is_none() {
            forget();
            return self.apply(proposal).await;
        }
        let cur_enabled = current.as_ref().is_some_and(|c| truthy(c.policy.get("enabled")));
        let cur = |k: &str| current.as_ref().and_then(|c| c.policy.get(k));
        // Letting the agent join more by itself is new access and needs a code.
        let widens = auto_join_widens(cur("autoJoin"), policy.get("autoJoin"));
        // So does Full agent, and presenting. Turning them off needs none.
        let full_widens = full_agent_widens(cur("fullAgent").filter(|_| cur_enabled), policy.get("fullAgent"));
        let present_on = present_widens(cur("present").filter(|_| cur_enabled), policy.get("present"));
        let same_speech_now = same_speech(cur("speech"), policy.get("speech"));
        let same_access = !enabled || (cur_enabled && !widens && !full_widens && !present_on && same_speech_now);
        if same_access && instructions.is_none() {
            forget();
            return self.apply(proposal).await;
        }
        if !(self.opts.channels_ready)() {
            return Ok(out(
                false,
                "failed",
                Some("Firewall confirmation is unavailable"),
                Some(json!({"changeId": change_id})),
            ));
        }
        let routes = (self.opts.code_routes)();
        // The first-owner bootstrap stays; Full agent, presenting and instructions never go without a code.
        if routes.is_empty() && (full_widens || present_on || instructions.is_some()) {
            let what = if instructions.is_some() {
                "New meeting instructions need"
            } else if full_widens {
                "Full agent needs"
            } else {
                "Presenting needs"
            };
            let mut d = json!({"changeId": change_id});
            if instructions.is_some() {
                d["instructions"] = json!("no_code");
            }
            return Ok(out(
                false,
                "failed",
                Some(&format!("{what} a confirmation code. Connect a chat for codes first.")),
                Some(d),
            ));
        }
        if routes.is_empty() {
            return self.apply(proposal).await;
        }
        let summary = self.summary_for(&policy, current.as_ref(), widens, full_widens, present_on, same_access);
        if let Some(i) = &instructions
            && !instructions_fit(&target.hostname, &i.text, &summary)
        {
            return Ok(out(
                false,
                "failed",
                Some("The meeting instructions do not fit in one code message"),
                Some(json!({"changeId": change_id, "instructions": "too_long"})),
            ));
        }
        let Some(codes) = (self.opts.codes)() else {
            return Ok(out(
                false,
                "failed",
                Some("Firewall confirmation is unavailable"),
                Some(json!({"changeId": change_id})),
            ));
        };
        let (summary_line, parts) = match &instructions {
            Some(i) => (
                "new meeting instructions".to_string(),
                Some(instructions_code_parts(&target.hostname, &i.text, &summary)),
            ),
            None => (summary, None),
        };
        let sent = codes
            .send(CodeAsk {
                scope,
                change_id: change_id.into(),
                proposal: serde_json::to_value(&proposal).map_err(|e| e.to_string())?,
                agent_name: target.hostname.clone(),
                summary: summary_line,
                routes,
                parts,
                // The Meetings card's code dialog has no change id to read a number for.
                no_buttons: true,
                ..Default::default()
            })
            .await;
        Ok(match &sent {
            CodeSent::Sent { .. } => {
                let mut d = Map::new();
                d.insert("changeId".into(), json!(change_id));
                d.extend(sent.awaiting_code_data().unwrap_or_default());
                out(true, "awaiting_code", None, Some(Value::Object(d)))
            }
            CodeSent::Failed { message } => out(false, "failed", Some(message), Some(json!({"changeId": change_id}))),
        })
    }

    /// The firewall's sentence for what the code allows.
    fn summary_for(
        &self,
        policy: &Value,
        current: Option<&Entry>,
        widens: bool,
        full_widens: bool,
        present_on: bool,
        same_access: bool,
    ) -> String {
        if same_access {
            return String::new();
        }
        let cur_enabled = current.is_some_and(|c| truthy(c.policy.get("enabled")));
        let auto = policy.get("autoJoin").cloned().unwrap_or(Value::Null);
        // Meetings are already on with this speech: the code is only about what widened.
        let auto_only = (widens || full_widens || present_on)
            && cur_enabled
            && same_speech(current.and_then(|c| c.policy.get("speech")), policy.get("speech"));
        if auto_only {
            let mut s = String::new();
            if widens {
                s.push_str(&format!(
                    "{} It joins as a guest; the camera stays off. Each call is counted and limited as today.",
                    auto_join_summary(&auto)
                ));
            }
            if full_widens {
                s.push_str(&format!(" {}", full_agent_summary()));
            }
            if present_on {
                s.push_str(&format!(" {}", present_summary()));
            }
            return s.trim().to_string();
        }
        let full = format!(
            "{}{}",
            if truthy(policy.get("fullAgent").and_then(|f| f.get("enabled"))) {
                format!(" {}", full_agent_summary())
            } else {
                String::new()
            },
            if truthy(policy.get("present")) {
                format!(" {}", present_summary())
            } else {
                String::new()
            }
        );
        let speech = policy.get("speech").filter(|s| truthy(Some(s)));
        let speech_part = match speech {
            Some(sp) => {
                let provider = sp.get("provider").and_then(Value::as_str).unwrap_or_default();
                let model = sp.get("model").and_then(Value::as_str).unwrap_or_default();
                let minutes = cc_meetings::js::js_string(sp.get("maxMinutes"));
                let live = if speech_family(provider, model) == Some("live") {
                    if wake_sessions(policy) > 0 {
                        " This model is billed for every connected second, about $3 an hour; with the wake word on, the agent listens on its own box and connects only when called by name."
                    } else {
                        " This model is billed for every connected second, about $3 an hour."
                    }
                } else {
                    ""
                };
                format!(
                    "Allow Bidi speech through {provider}, model {model}, for at most {minutes} minutes per call.{live} The speech provider receives meeting audio.{}",
                    if full.is_empty() {
                        " Meeting tools are read-only; actions need your private channel.".to_string()
                    } else {
                        full
                    }
                )
            }
            None => "Transcript keeps microphone and camera off.".into(),
        };
        format!(
            "Enable guest Google Meet from your enrolled browser. {speech_part} Allow uninspected Google TURN/TLS media for up to four hours and 512 MiB per call. Keep notes on the agent until deleted.{}{}",
            if truthy(policy.get("followUp").and_then(|f| f.get("enabled"))) {
                " After each meeting the agent acts on the notes by your standing orders."
            } else {
                ""
            },
            if widens {
                format!(" {}", auto_join_summary(&auto))
            } else {
                String::new()
            }
        )
    }

    async fn confirm(&self, p: &Map<String, Value>) -> Result<CommandOutcome, String> {
        let (Some(vm), Some(id), Some(code)) = (
            p.get("vmId").and_then(Value::as_str),
            p.get("changeId").and_then(Value::as_str),
            p.get("code").and_then(Value::as_str),
        ) else {
            return Err(invalid());
        };
        let check = (self.opts.codes)().map_or(CodeCheck::Expired, |c| c.verify(&format!("meetings:{vm}"), id, code));
        let proposal = match check {
            CodeCheck::Ok { proposal, .. } => proposal,
            CodeCheck::Wrong { tries_left } => {
                let status = if tries_left > 0 { "invalid_code" } else { "expired" };
                return Ok(out(false, status, None, Some(json!({"changeId": id}))));
            }
            CodeCheck::Expired => return Ok(out(false, "expired", None, Some(json!({"changeId": id})))),
        };
        let proposal: Proposal = serde_json::from_value(proposal).map_err(|_| invalid())?;
        self.apply(proposal).await
    }

    async fn apply(&self, p: Proposal) -> Result<CommandOutcome, String> {
        let change = json!({"changeId": p.change_id});
        if self.lock().entries.get(&p.vm_id).map_or(0, |e| e.revision) != p.base_revision {
            return Ok(out(false, "conflict", None, Some(change)));
        }
        let target = self.target(&p.vm_id)?;
        let speech = p.policy.get("speech").filter(|s| truthy(Some(s)));
        if truthy(p.policy.get("enabled")) && speech.is_some_and(|s| (self.opts.speech_credential)(s).is_none()) {
            return Err("Speech credential was removed before confirmation".into());
        }
        // The instructions first: when the agent refuses them, nothing of the change is applied.
        if let Some(i) = &p.instructions
            && let Err(e) = self
                .opts
                .agent
                .post(&target, "/meetings/instructions", json!(i), None)
                .await
        {
            static CHANGED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"changed since").expect("regex"));
            static WAITING: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"first message|set up its workspace").expect("regex"));
            let said = e.to_string();
            let why = if CHANGED.is_match(&said) {
                "changed"
            } else if WAITING.is_match(&said) {
                "waiting"
            } else {
                "failed"
            };
            return Ok(out(
                false,
                "failed",
                Some("The meeting instructions were not written on the agent"),
                Some(json!({"changeId": p.change_id, "instructions": why})),
            ));
        }
        {
            let mut st = self.lock();
            // Checked again where it is written: another change may have landed while the agent was asked.
            if st.entries.get(&p.vm_id).map_or(0, |e| e.revision) != p.base_revision {
                return Ok(out(false, "conflict", None, Some(change)));
            }
            let previous = st.entries.get(&p.vm_id).cloned();
            let same_access = previous.as_ref().is_some_and(|prev| {
                prev.policy.get("enabled") == p.policy.get("enabled")
                    // Parsed policies on both sides: `==` is the TS's `JSON.stringify` comparison.
                    && prev.policy.get("speech") == p.policy.get("speech")
            });
            let entry = Entry {
                policy: p.policy.clone(),
                revision: p.base_revision + 1,
                token: match (&previous, same_access) {
                    (Some(prev), true) => prev.token.clone(),
                    _ => rand_hex(32),
                },
                hostname: target.hostname.clone(),
                applied: false,
                voice_placeholder: match (&previous, same_access) {
                    (Some(prev), true) => prev.voice_placeholder.clone(),
                    _ => Some(format!("cc-speech-{}", rand_hex(24))),
                },
                auto: previous.as_ref().and_then(|prev| prev.auto.clone()),
                extra: Map::new(),
            };
            let mut next = st.entries.clone();
            next.insert(p.vm_id.clone(), entry);
            self.save(&next)?;
            st.entries = next;
            if !same_access {
                st.leases.shift_remove(&p.vm_id);
            }
        }
        self.publish()?;
        (self.opts.on_credentials_changed)().await?;
        let outcome = self.push(&p.vm_id).await;
        // Said also when the settings did not reach the agent: the console then drops the text it kept.
        let mut data = outcome.data.clone().unwrap_or_default();
        data.insert("changeId".into(), json!(p.change_id));
        if p.instructions.is_some() {
            data.insert("instructionsWritten".into(), json!(true));
        }
        Ok(CommandOutcome {
            data: Some(data),
            ..outcome
        })
    }

    async fn push(&self, vm_id: &str) -> CommandOutcome {
        let Some(entry) = self.lock().entries.get(vm_id).cloned() else {
            return out(false, "failed", Some("No approved meetings settings"), None);
        };
        let data = json!({"vmId": vm_id, "revision": entry.revision, "policy": entry.policy});
        let speech = entry.policy.get("speech").filter(|s| truthy(Some(s))).map(|s| {
            let mut s = s.clone();
            if let Some(m) = s.as_object_mut() {
                m.insert("placeholder".into(), json!(entry.voice_placeholder));
            }
            s
        });
        let sent = match self.target(vm_id) {
            Ok(t) => self
                .opts
                .agent
                .post(
                    &t,
                    "/meetings/apply",
                    json!({
                        "vmId": vm_id, "revision": entry.revision, "policy": entry.policy, "speech": speech,
                        "media": {"origin": (self.opts.firewall_origin)(), "token": entry.token},
                    }),
                    None,
                )
                .await
                .is_ok(),
            Err(_) => false,
        };
        if !sent {
            return out(
                false,
                "failed",
                Some("Settings are approved but the agent has not applied them"),
                Some(data),
            );
        }
        let saved = {
            let mut st = self.lock();
            let mut next = st.entries.clone();
            if let Some(e) = next.get_mut(vm_id) {
                e.applied = true;
            }
            let r = self.save(&next);
            if r.is_ok() {
                st.entries = next;
            }
            r
        };
        if saved.is_err() {
            return out(
                false,
                "failed",
                Some("Settings are approved but the agent has not applied them"),
                Some(data),
            );
        }
        out(true, "applied", None, Some(data))
    }

    /// The speech credentials the proxy swaps in for the agents' voice placeholders.
    pub fn credentials(&self) -> Vec<Value> {
        let entries = self.lock().entries.clone();
        let mut out = Vec::new();
        for (vm, e) in entries {
            let Some(speech) = e.policy.get("speech").filter(|s| truthy(Some(s))) else {
                continue;
            };
            let Some(ph) = e.voice_placeholder.as_ref().filter(|p| !p.is_empty()) else {
                continue;
            };
            if !truthy(e.policy.get("enabled")) || (self.opts.locked)(&vm) {
                continue;
            }
            let Some((secret, host, account)) = (self.opts.speech_credential)(speech) else {
                continue;
            };
            let mut c = Map::new();
            c.insert("placeholder".into(), json!(ph));
            c.insert("secret".into(), json!(secret));
            c.insert("match_domain".into(), json!(host));
            c.insert("locations".into(), json!(["header:authorization"]));
            c.insert("vm_id".into(), json!(vm));
            if let Some(a) = account.filter(|a| !a.is_empty()) {
                c.insert("speech_account_id".into(), json!(a));
            }
            c.insert(
                "speech".into(),
                json!({"provider": speech.get("provider"), "model": speech.get("model")}),
            );
            out.push(Value::Object(c));
        }
        out
    }

    /// The leases the proxy reads (`meeting-media.json`): one per agent in a call, with the speech
    /// it may use.
    pub fn publish(&self) -> Result<(), String> {
        let _publishing = self.publishing.lock().unwrap_or_else(|e| e.into_inner());
        let known: Vec<String> = (self.opts.identities)().into_iter().map(|r| r.0).collect();
        let now = self.now() as f64 / 1000.0;
        // The leases and their settings, taken under the lock; the other modules are asked after it.
        let taken: Vec<(String, Map<String, Value>, Option<Entry>)> = {
            let st = self.lock();
            st.leases
                .iter()
                .map(|(vm, l)| (vm.clone(), l.clone(), st.entries.get(vm).cloned()))
                .collect()
        };
        let mut gone = Vec::new();
        let mut live = Map::new();
        for (vm, mut lease, entry) in taken {
            let expires = lease.get("expires").and_then(Value::as_f64).unwrap_or(0.0);
            if !known.contains(&vm)
                || !entry.as_ref().is_some_and(|e| truthy(e.policy.get("enabled")))
                || (self.opts.locked)(&vm)
                || expires <= now
            {
                gone.push((vm, lease.get("id").cloned()));
                continue;
            }
            if let Some(e) = &entry
                && let Some(speech) = e.policy.get("speech").filter(|s| truthy(Some(s)))
                && (self.opts.speech_credential)(speech).is_some()
            {
                lease.insert("speech".into(), speech.clone());
                lease.insert("voice_placeholder".into(), json!(e.voice_placeholder));
            }
            live.insert(vm, Value::Object(lease));
        }
        if !gone.is_empty() {
            let mut st = self.lock();
            // Only the lease that was looked at: one started since stays.
            for (vm, id) in gone {
                if st.leases.get(&vm).is_some_and(|l| l.get("id").cloned() == id) {
                    st.leases.shift_remove(&vm);
                }
            }
        }
        cc_contracts::write_atomic(&self.opts.media_dir, &cc_contracts::FileSpec::MEETING_MEDIA, &live)
            .map_err(|e| e.to_string())
    }

    /// Why this agent may not join by itself now, or `None`. Does not count the join.
    fn auto_refusal(&self, vm: &str, entry: &Entry, claim: &Value) -> Option<&'static str> {
        let Some(auto) = entry.policy.get("autoJoin").filter(|a| truthy(a.get("enabled"))) else {
            return Some("off");
        };
        let email = claim.get("source") == Some(&json!("email"));
        if if email {
            !truthy(auto.get("email"))
        } else {
            auto.get("calendar") == Some(&json!("off"))
        } {
            return Some("source_off");
        }
        if !(self.opts.organizer_allowed)(vm, claim) {
            return Some("organizer");
        }
        self.daily_limit(entry)
    }

    /// `daily_limit` when today's automatic joins reached the policy's cap. Run again under the
    /// lock on the live entry before a join is counted: two starts at once must not both pass.
    fn daily_limit(&self, entry: &Entry) -> Option<&'static str> {
        let auto = entry.policy.get("autoJoin")?;
        let day = &cc_crypto::store_health::iso_from_millis(self.now())[..10];
        let max = auto.get("maxPerDay").and_then(Value::as_f64).unwrap_or(f64::NAN);
        entry
            .auto
            .as_ref()
            .is_some_and(|a| a.day == day && a.count as f64 >= max)
            .then_some("daily_limit")
    }

    /// `/__cc/meetings/media`: the box's own HTTPS call for a media lease. The token comes only in a
    /// signed apply.
    pub async fn media(&self, req: cc_http::Req) -> cc_http::Resp {
        let reply = |status: u16, v: Value| {
            let mut r = cc_http::full(
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                "application/json",
                v.to_string(),
            );
            r.headers_mut()
                .insert("cache-control", http::HeaderValue::from_static("no-store"));
            r
        };
        let unavailable = || reply(403, json!({"error": "Media unavailable"}));
        let bad = || reply(400, json!({"error": "Invalid request"}));
        let (parts, body) = req.into_parts();
        if parts.method != http::Method::POST {
            return reply(405, json!({"error": "Method not allowed"}));
        }
        let auth = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        let token = auth.strip_prefix("Bearer ").unwrap_or(auth).to_string();
        let found = {
            let st = self.lock();
            st.entries
                .iter()
                .find(|(_, e)| {
                    TOKEN.is_match(&token)
                        && TOKEN.is_match(&e.token)
                        && cc_crypto::ct_eq(token.as_bytes(), e.token.as_bytes())
                })
                .map(|(vm, e)| (vm.clone(), e.clone()))
        };
        let Some((vm, entry)) = found.filter(|(vm, e)| truthy(e.policy.get("enabled")) && !(self.opts.locked)(vm))
        else {
            return unavailable();
        };
        use http_body_util::BodyExt;
        let Ok(raw) = http_body_util::Limited::new(body, 4096).collect().await else {
            return reply(413, json!({"error": "Request too large"}));
        };
        let raw: Bytes = raw.to_bytes();
        let text = String::from_utf8_lossy(&raw);
        if js_len(&text) > 1024 {
            return reply(413, json!({"error": "Request too large"}));
        }
        let Ok(Value::Object(body)) = serde_json::from_str::<Value>(&text) else {
            return bad();
        };
        if body
            .keys()
            .any(|k| !["action", "leaseId", "auto"].contains(&k.as_str()))
        {
            return bad();
        }
        // A join the box starts by itself says where the invite came from; only `start` and `admit` take it.
        let claim = match body.get("auto") {
            None => None,
            Some(v) => match parse_auto_join_claim(Some(v)) {
                Ok(c) => Some(c),
                Err(_) => return bad(),
            },
        };
        let action = body.get("action").and_then(Value::as_str);
        if (claim.is_some() && action != Some("start") && action != Some("admit"))
            || (action == Some("admit") && claim.is_none())
        {
            return bad();
        }
        // Asked of the other modules before the lock: their own locks are never taken under ours.
        if (self.opts.locked)(&vm) {
            return unavailable();
        }
        let refusal = claim.as_ref().and_then(|c| self.auto_refusal(&vm, &entry, c));
        let own = (self.opts.own_account)(&vm);
        let mut st = self.lock();
        // Still the settings the token was given with (`entries[vmId] === found`): the same token and
        // revision. `applied` and the day's count may have changed meanwhile, as they do in place in the TS.
        if !st
            .entries
            .get(&vm)
            .is_some_and(|e| e.token == entry.token && e.revision == entry.revision)
            || !truthy(entry.policy.get("enabled"))
        {
            return unavailable();
        }
        let now = self.now() as f64 / 1000.0;
        // `admit` asks ahead of time, so the Meetings page can say why an invite will not be joined.
        if action == Some("admit") {
            return reply(
                200,
                match refusal {
                    Some(r) => json!({"ok": false, "reason": r}),
                    None => json!({"ok": true}),
                },
            );
        }
        let lease_now = st.leases.get(&vm).cloned();
        let expires_of = |l: &Map<String, Value>, k: &str| l.get(k).and_then(Value::as_f64).unwrap_or(0.0);
        let lease = if action == Some("start") {
            if lease_now.as_ref().is_some_and(|l| expires_of(l, "expires") > now) {
                return reply(409, json!({"error": "A call is already active"}));
            }
            // The count as it is now, not as it was before the body was read.
            let live = if claim.is_some() {
                st.entries.get(&vm).and_then(|e| self.daily_limit(e))
            } else {
                None
            };
            if let Some(r) = refusal.or(live) {
                return reply(403, json!({"error": "Automatic join refused", "reason": r}));
            }
            if claim.is_some() {
                let day = cc_crypto::store_health::iso_from_millis(self.now())[..10].to_string();
                let mut next = st.entries.clone();
                if let Some(e) = next.get_mut(&vm) {
                    let count = e.auto.as_ref().filter(|a| a.day == day).map_or(0, |a| a.count) + 1;
                    e.auto = Some(Auto { day, count });
                }
                // Counted in memory even when it cannot be saved, and the request fails (the TS's 500):
                // the daily limit holds either way.
                let saved = self.save(&next);
                st.entries = next;
                if saved.is_err() {
                    return reply(500, json!({}));
                }
            }
            let speech = entry.policy.get("speech").filter(|s| truthy(Some(s)));
            let span = match speech {
                Some(sp) => cc_meetings::js::safe_int(sp.get("maxMinutes")).unwrap_or(0) as f64 * 60.0,
                None => MEDIA_MAX_SECONDS as f64,
            };
            let mut l = Map::new();
            l.insert("id".into(), json!(rand_hex(16)));
            l.insert("started".into(), num(now));
            l.insert("expires".into(), num(now + MEDIA_TTL_SECONDS as f64));
            l.insert("deadline".into(), num(now + span));
            l.insert("max_bytes".into(), json!(MEDIA_MAX_BYTES));
            // The agent opens a voice session per request; the proxy allows that many.
            let sessions = wake_sessions(&entry.policy);
            if sessions > 0 {
                l.insert("wake_sessions".into(), json!(sessions));
            }
            // Full agent only in meetings an owner or admin sent it to; the agent reads it from the lease.
            if speech.is_some() && full_agent_meeting(&entry.policy, claim.as_ref(), own.as_deref()) {
                l.insert("full_agent".into(), json!(true));
            }
            // Presenting: every meeting the agent may join, when the owner turned it on with a code.
            if speech.is_some() && entry.policy.get("present") == Some(&json!(true)) {
                l.insert("present".into(), json!(true));
            }
            st.leases.insert(vm.clone(), l.clone());
            l
        } else {
            let Some(mut l) = lease_now.filter(|l| body.get("leaseId").is_some() && l.get("id") == body.get("leaseId"))
            else {
                return reply(409, json!({"error": "Media lease ended"}));
            };
            if action == Some("stop") {
                st.leases.shift_remove(&vm);
                drop(st);
                if self.publish().is_err() {
                    return reply(500, json!({}));
                }
                return reply(200, json!({"ok": true}));
            }
            if action != Some("renew") || expires_of(&l, "expires") <= now || expires_of(&l, "deadline") <= now {
                return reply(409, json!({"error": "Media lease ended"}));
            }
            let renewed = (now + MEDIA_TTL_SECONDS as f64).min(expires_of(&l, "deadline"));
            l.insert("expires".into(), num(renewed));
            st.leases.insert(vm.clone(), l.clone());
            l
        };
        drop(st);
        // A lease the proxy cannot read is no lease: the request fails (the TS's 500).
        if self.publish().is_err() {
            return reply(500, json!({}));
        }
        reply(200, Value::Object(lease))
    }
}

/// The proxy's swaps for the meetings' voice placeholders.
pub struct MeetingsCredentials(pub Arc<MeetingsFirewall>);

impl crate::contracts::CredentialContributor for MeetingsCredentials {
    fn order(&self) -> crate::contracts::CredentialOrder {
        crate::contracts::CredentialOrder::Meetings
    }
    fn credentials(&self) -> Vec<Value> {
        self.0.credentials()
    }
}

/// Builds the module from the ones registered before it (`index.ts:1157-1178`).
pub fn register(
    reg: &mut crate::app::Registry,
    app: &Arc<crate::app::App>,
    agent: Arc<dyn AgentCalls>,
    llm: Arc<crate::channels::llm::Llm>,
    google: Option<Arc<crate::channels::google::GoogleFirewall>>,
    agentmail: Option<Arc<crate::channels::email::agentmail::AgentMailFirewall>>,
    email_rules: Option<Arc<crate::channels::email::rules::EmailRulesFirewall>>,
) {
    let account = {
        let g = google.clone();
        Arc::new(move || {
            g.as_ref()
                .and_then(|g| g.summary()["account"]["accountLabel"].as_str().map(str::to_lowercase))
        })
    };
    let routes = {
        let app = app.clone();
        move || app.contracts.code_route_source.get()
    };
    let keys = app.keys.clone();
    let built = MeetingsFirewall::new(MeetingsOptions {
        store_path: std::path::PathBuf::from("/opt/controlclaw/state/meetings.enc"),
        media_dir: app.config.proxy_config_dir.clone(),
        box_key: app.box_key.clone(),
        org_id: app.config.org_id.clone(),
        box_id: app.config.box_id.clone(),
        agent,
        identities: Arc::new(|| {
            crate::core::core()
                .map(|c| {
                    c.agents
                        .agents()
                        .iter()
                        .map(|i| {
                            (
                                crate::core::identities::vm_id_of(i),
                                crate::core::identities::str_field(i, "hostname").map(str::to_string),
                                crate::core::identities::str_field(i, "role").map(str::to_string),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        }),
        firewall_origin: Arc::new(move || format!("https://{}", keys.read("vm_hostname").unwrap_or_default().trim())),
        codes: {
            let app = app.clone();
            Arc::new(move || app.contracts.code_service.get().map(|s| s.module("meetings")))
        },
        code_routes: {
            let r = routes.clone();
            Arc::new(move || r().filter(|s| s.ready()).map(|s| s.routes()).unwrap_or_default())
        },
        channels_ready: Arc::new(move || routes().is_some_and(|s| s.ready())),
        // No kill switch means no stream: an agent that cannot be checked counts as stopped.
        locked: Arc::new(|vm: &str| {
            crate::core::core()
                .and_then(|c| c.sync.hooks.kill.get().cloned())
                .is_none_or(|k| k.locked_vm_ids(&[vm.to_string()]).iter().any(|v| v == vm))
        }),
        speech_credential: Arc::new(move |speech: &Value| {
            let s = |k: &str| speech.get(k).and_then(Value::as_str).unwrap_or_default();
            llm.speech_credential(s("provider"), s("credentialId"))
                .map(|c| (c.secret, c.host, c.account_id))
        }),
        on_credentials_changed: Arc::new(|| {
            Box::pin(async {
                match crate::core::core() {
                    Some(core) => core.sync.run().await.map_err(|e| e.to_string()),
                    None => Ok(()),
                }
            })
        }),
        // An invite makes the agent join only when its organizer is the org's own Google account or
        // an allowed sender of the mailbox it came through. No rules, no join.
        organizer_allowed: {
            let (acct, rules) = (account.clone(), email_rules);
            Arc::new(move |vm: &str, claim: &Value| {
                let organizer = claim.get("organizer").and_then(Value::as_str).unwrap_or_default();
                let listed = |mailbox: &str| rules.as_ref().is_some_and(|r| r.sender_listed(organizer, mailbox));
                if claim.get("source") == Some(&json!("calendar")) {
                    let Some(a) = acct() else { return false };
                    return organizer == a || listed(&format!("gmail:{a}"));
                }
                agentmail
                    .as_ref()
                    .map(|m| m.inboxes_of(vm))
                    .unwrap_or_default()
                    .iter()
                    .any(|inbox| listed(&format!("agentmail:{inbox}")))
            })
        },
        own_account: Arc::new(move |_| account()),
        now: Arc::new(crate::channels::now_ms),
    });
    let m = match built {
        Ok(m) => m,
        Err(_) => {
            tracing::error!("[meetings] setup failed; meetings are unavailable");
            return;
        }
    };
    app.contracts.credentials.add(Arc::new(MeetingsCredentials(m.clone())));
    for action in ["propose", "confirm", "cancel", "push"] {
        let m = m.clone();
        reg.commands.handle(&format!("meetings.{action}"), move |p| {
            let m = m.clone();
            async move { crate::channels::finish(m.command(action, p).await) }
        });
    }
    let page = m.clone();
    reg.ingress.route(
        crate::stages::INGRESS_PAGES,
        |_, path| path == "/__cc/meetings/media",
        move |req, _| {
            let page = page.clone();
            async move { page.media(req).await }
        },
    );
    crate::channels::contracts_fill::feature(app, "meetings_transcript", || true);
    // Meetings settings carry autoJoin and the media lease checks it.
    crate::channels::contracts_fill::feature(app, "meetings_autojoin", || true);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if m.publish().is_err() {
                tracing::error!("[meetings] media lease publish failed");
            }
        }
    });
}

#[cfg(test)]
#[path = "meetings_tests.rs"]
mod tests;
