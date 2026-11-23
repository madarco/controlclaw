//! The firewall's records about its own or ControlClaw's traffic, which the AI log review skips: the
//! one list (apps/saas/docs/features/ai-firewall-review.md, "What the review skips").
//!
//! Each kind is known by what wrote it, never by a host alone: its rule (a name only the firewall
//! writes, and no `rule_id`, which every owner's or managed rule carries), its flow id (a prefix a
//! proxy uuid never has) and its host together. An owner's rule named the same, or an agent's request
//! to a look-alike host, carries a `rule_id` or a uuid flow id and is reviewed as usual.
//!
//! Most kinds are still reviewed when a record shows a warning sign: refused, failed, or a large
//! upload. A large upload is counted per agent and kind over an hour (`UPLOAD_WINDOW_SECS`), so many
//! uploads just under the bound are all reviewed together. A meeting's media is reviewed unless it
//! closed normally at a rate audio and a shared page can use (`MEDIA_*`). The phone stream's size says
//! nothing (Twilio sends the call to the firewall), and the firewall's notes carry no traffic.
//!
//! Not here, and why:
//! - The webhooks the firewall receives (`webhook`), held mail (`email_held`), the connector and MCP
//!   server calls (the calls log), the brain's own records (`brain_*`, the vm-agent's activity): no
//!   `host`, or not in the traffic log, so the review never reads them.
//! - The agent's model calls and its channels (Telegram, Slack, AgentMail, Gmail, the included AI):
//!   `cc_contracts::managed::is_routine`, by their managed rule.
//! - The role's package hosts during a confirmed update (rule `agent_update`): any process on the agent
//!   can use that window, not only the update, so it stays reviewed.
//! - The brain box's own traffic, the residential exit, Tailscale and DERP, Ubuntu's mirrors, the time
//!   servers, rclone's Drive sync, a phone call the agent places, the code and grant windows: real
//!   requests to real hosts under the owner's rules (or none). They stay reviewed; the console's
//!   investigation names the server's own ones (`known-infra.ts`).

use serde_json::Value;

/// The ControlClaw-tools gate (`integrations/tools_gate.rs`): the agent's MCP calls to ControlClaw.
pub const TOOLS_HOST: &str = "controlplane-mcp";
pub const TOOLS_FLOW: &str = "cpm-";
pub const TOOLS_RULE: &str = "controlclaw tools";
/// The team chat gate (`integrations/teamchat/gate.rs`): the agent in the organization's ClickClack room.
pub const TEAM_CHAT_HOST: &str = "team-chat";
pub const TEAM_CHAT_FLOW: &str = "tc-";
pub const TEAM_CHAT_RULE: &str = "team chat";
/// The firewall's notes about saved website logins (`integrations/logins/firewall.rs`).
pub const LOGINS_HOST: &str = "controlclaw-logins";
pub const LOGINS_FLOW: &str = "lgn-";
const LOGINS_NOTE: &str = "saved-login note";
/// On the two gates' records since T-222: `bytes_out` is what the agent sent. They wrote it the other
/// way round before, and the review and the console read a record without it that way
/// (`sizes`, `known-infra.ts` `rowSizes`).
pub const SIZES_FIELD: &str = "sizes";
pub const SIZES_OUT_IS_SENT: &str = "out_is_sent";
/// A phone call's audio stream from Twilio (`channels/phone/stream.rs`).
pub const PHONE_HOST: &str = "api.twilio.com";
pub const PHONE_PATH: &str = "/phone-stream/[stream]";
pub const PHONE_RULE: &str = "phone stream: ";

/// The record's rule: exactly this name, or this name and what follows (`<rule>: <why>`, a refusal).
#[derive(Clone, Copy)]
enum Rule {
    Is(&'static str),
    Starts(&'static str),
}

#[derive(Clone, Copy)]
enum Host {
    Is(&'static str),
    OneOf(&'static [&'static str]),
    /// The proxy's own name check holds it to the right host (the control plane's, the backup store's).
    Checked,
}

#[derive(Clone, Copy)]
enum Flow {
    Starts(&'static str),
    Ends(&'static str),
    /// A proxy uuid: the rule and its missing `rule_id` say what it is.
    Proxy,
}

/// What keeps a record of this kind reviewed.
#[derive(Clone, Copy, PartialEq)]
enum Signs {
    /// Refused, failed (an error or a status of 400 or more), or more than `LARGE_UPLOAD` sent by one
    /// agent in this kind's records within `UPLOAD_WINDOW_SECS`.
    All,
    /// Refused, ended for any reason but a normal close (the budget spent, the lease revoked), or more
    /// sent than `MEDIA_FLOOR_BYTES` plus `MEDIA_BYTES_PER_SEC` for as long as it was open; and every
    /// connection of a session that sent more than that all together (`media_sessions`).
    Media,
    /// Refused only: a stream's size and its end say nothing.
    Refused,
    /// Nothing: a note, not traffic.
    None,
}

struct Internal {
    /// What it is, for the comment and the tests.
    what: &'static str,
    rule: Rule,
    host: Host,
    flow: Flow,
    /// The record's path, when the kind has a fixed one.
    path: Option<&'static str>,
    /// A field the kind's records always carry, not empty.
    needs: Option<&'static str>,
    /// The effect it is written with when let through; any other is a refusal.
    effect: &'static str,
    signs: Signs,
}

/// More than this sent by one agent in one kind's records within `UPLOAD_WINDOW_SECS` is a large
/// upload (`review.rs` uses the same bound per host).
pub const LARGE_UPLOAD: f64 = 1_000_000.0;
pub const UPLOAD_WINDOW_SECS: f64 = 3600.0;
/// What a meeting connection may send and still be media. The agent's camera is always off: it sends
/// Opus audio (at most 64 kbit/s, under 0.15 Mbit/s with RTP, TURN and TLS around it) and, while it
/// presents, a page refreshed twice a second as screen-share video, which stays well under 2 Mbit/s.
/// 2 Mbit/s (250 kB/s) on average over the connection covers both; data sent faster than a shared page
/// uses is reviewed. The floor covers the handshakes of a short connection. A TURN relay forwards to
/// whatever peer the client names, which the firewall cannot see, so this bound and the lease's byte
/// budget are what keep the relay from being a quiet way out. Not measured on a live meeting: guest
/// joins have been refused by Google since 2026-11-18.
pub const MEDIA_BYTES_PER_SEC: f64 = 250_000.0;
pub const MEDIA_FLOOR_BYTES: f64 = 2_000_000.0;

const INTERNAL: &[Internal] = &[
    // The boxes' own calls to the control plane (`cc-proxy` `http/mod.rs` `mark_control_plane`): reports,
    // events, rules. Never the agent's doing.
    Internal {
        what: "control plane",
        rule: Rule::Is("control_plane"),
        host: Host::Checked,
        flow: Flow::Proxy,
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::Refused,
    },
    // Workspace backups to the organization's own presigned archive (`cc-proxy` `http/backup.rs`): large by
    // nature. Another bucket or another organization's archive is refused, and reviewed.
    Internal {
        what: "backup store",
        rule: Rule::Is("backup_store"),
        host: Host::Checked,
        flow: Flow::Proxy,
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::Refused,
    },
    // The agent calling ControlClaw's own tools (its agent MCP) through the firewall's gate.
    Internal {
        what: "ControlClaw tools",
        rule: Rule::Is(TOOLS_RULE),
        host: Host::Is(TOOLS_HOST),
        flow: Flow::Starts(TOOLS_FLOW),
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::All,
    },
    // The agent in the organization's team chat, on the firewall, through its gate.
    Internal {
        what: "team chat",
        rule: Rule::Is(TEAM_CHAT_RULE),
        host: Host::Is(TEAM_CHAT_HOST),
        flow: Flow::Starts(TEAM_CHAT_FLOW),
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::All,
    },
    // A saved login handed to the agent, or refused: a note. The proxy's own records of the sign-in
    // (and its tripwire) carry the real host and are reviewed.
    Internal {
        what: LOGINS_NOTE,
        rule: Rule::Starts(""),
        host: Host::Is(LOGINS_HOST),
        flow: Flow::Starts(LOGINS_FLOW),
        path: None,
        needs: Some("login"),
        effect: "allow",
        signs: Signs::None,
    },
    // A phone call's audio, Twilio to the firewall and back. The admission refusal is reviewed.
    Internal {
        what: "phone stream",
        rule: Rule::Starts(PHONE_RULE),
        host: Host::Is(PHONE_HOST),
        flow: Flow::Proxy,
        path: Some(PHONE_PATH),
        needs: None,
        effect: "allow",
        signs: Signs::Refused,
    },
    // A meeting's media to Google's TURN relays under the meeting's lease (`cc-proxy` `splice/meet.rs`):
    // only to those names at Google's addresses, within the lease's byte budget. An uninspected
    // tunnel, so only a normal close at a media rate is skipped.
    Internal {
        what: "meeting media",
        rule: Rule::Is("meet-media-v1"),
        host: Host::OneOf(&["meet.turns.goog", "workspace.turns.goog"]),
        flow: Flow::Starts("meet_"),
        path: None,
        needs: None,
        effect: "tunnel",
        signs: Signs::Media,
    },
    // The billed seconds of a live voice model (meeting or phone), written when its socket closes
    // (`cc-proxy` `checks/voice`): a second line for a request already in the log, no bytes.
    Internal {
        what: "voice billing note",
        rule: Rule::Starts("meeting_voice: "),
        host: Host::Checked,
        flow: Flow::Ends(":end"),
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::None,
    },
    Internal {
        what: "voice billing note",
        rule: Rule::Starts("phone_voice: "),
        host: Host::Checked,
        flow: Flow::Ends(":end"),
        path: None,
        needs: None,
        effect: "allow",
        signs: Signs::None,
    },
];

fn s<'a>(r: &'a Value, k: &str) -> Option<&'a str> {
    r.get(k).and_then(Value::as_str)
}

impl Internal {
    fn matches(&self, r: &Value) -> bool {
        let rule = s(r, "rule").unwrap_or("");
        let rule_ok = match self.rule {
            Rule::Is(n) => rule == n,
            Rule::Starts(p) => rule.starts_with(p),
        };
        let host = s(r, "host").unwrap_or("");
        let host_ok = match self.host {
            Host::Is(h) => host == h,
            Host::OneOf(hs) => hs.contains(&host),
            Host::Checked => !host.is_empty(),
        };
        let flow = s(r, "flow_id").unwrap_or("");
        let flow_ok = match self.flow {
            Flow::Starts(p) => flow.starts_with(p),
            Flow::Ends(e) => flow.len() > e.len() && flow.ends_with(e),
            Flow::Proxy => true,
        };
        let path_ok = self.path.is_none_or(|p| s(r, "path") == Some(p));
        let needs_ok = self.needs.is_none_or(|k| s(r, k).is_some_and(|v| !v.is_empty()));
        rule_ok
            && host_ok
            && flow_ok
            && path_ok
            && needs_ok
            && r.get("rule_id").is_none_or(Value::is_null)
            && r.get("managed").is_none()
    }

    /// A sign on this record alone. A large upload of an `All` kind is worked out over the window
    /// (`skipped_in`).
    fn warning(&self, r: &Value) -> bool {
        let refused = s(r, "effect") != Some(self.effect);
        let num = |k: &str| r.get(k).and_then(Value::as_f64);
        let failed = || s(r, "error").is_some_and(|e| !e.is_empty()) || num("status").is_some_and(|st| st >= 400.0);
        match self.signs {
            Signs::All => refused || failed(),
            Signs::Media => {
                let seconds = num("duration_ms").unwrap_or(0.0).max(0.0) / 1000.0;
                let sent = num("bytes_out").unwrap_or(0.0);
                refused || s(r, "reason") != Some("closed") || sent > MEDIA_FLOOR_BYTES + MEDIA_BYTES_PER_SEC * seconds
            }
            Signs::Refused => refused,
            Signs::None => false,
        }
    }
}

/// What the review every minute keeps across its passes, so sends in different passes still add up:
/// a pass sees only the records written since the last one. Kept per agent and kind, as aggregates,
/// never one entry per request, so one kind's flood cannot push another kind's history out:
/// - a gate's uploads as bytes per minute, for the hour (`UPLOAD_WINDOW_SECS`);
/// - meeting connections as sessions (`media_sessions`), for the hour after they end.
///
/// The last batch's sends stay apart (`pending`) until the next batch comes. A batch the review
/// could not finish is read again from the same place in the log (`LogTail::drain` keeps its cursor),
/// so the next batch starts with it: its sends take the place of the first try's, so nothing counts
/// twice. A gate's zero-byte sends are not kept; a meeting's connections are, bytes or not, as they
/// hold a session together.
#[derive(Default)]
pub struct Uploads {
    kinds: std::collections::HashMap<(Option<String>, usize), Memory>,
    pending: Vec<Sent>,
    /// Until when an agent and kind that is not kept has its records reviewed: some send could not be
    /// kept (`KINDS_KEPT`), and nothing says whose it will be next.
    unkept_until: Option<f64>,
}

#[derive(Default)]
struct Memory {
    /// Bytes sent per minute (`end / 60`), for an `All` kind.
    minutes: std::collections::BTreeMap<i64, f64>,
    /// Merged sessions, for a meeting.
    sessions: Vec<Sent>,
    /// Until when this agent and kind's records are all reviewed: its history was cut short.
    lost_until: Option<f64>,
}

/// Sessions kept per agent: a meeting is one, and connections more than a minute apart start
/// another, so an hour holds about 60 at most. A guard: past this the oldest go, and the agent's
/// meeting records are reviewed for the hour.
const SESSIONS_KEPT: usize = 120;
/// Agents and kinds kept at once. One more is not remembered, and its records are reviewed.
const KINDS_KEPT: usize = 10_000;

/// One send, or, kept from an earlier pass, a minute's or a session's worth: the agent, the kind's
/// index, when it started and ended, the bytes, the connections in it, the flow id (empty for kept ones).
#[derive(Clone)]
struct Sent {
    vm: Option<String>,
    kind: usize,
    start: f64,
    end: f64,
    bytes: f64,
    conns: usize,
    flow: String,
}

/// One agent's sends of one kind, keyed by agent and kind, each with its index in this batch (none
/// for an earlier pass's).
type Groups = std::collections::HashMap<(Option<String>, usize), Vec<(Sent, Option<usize>)>>;

/// The connections a meeting lease holds at once (`cc-proxy` `splice/meet.rs` `MAX_CONNECTIONS`).
const MEDIA_CONNECTIONS: usize = 8;
/// Connections of one agent's meeting that are this close are one session.
const MEDIA_SESSION_GAP_SECS: f64 = 60.0;

impl Uploads {
    /// Fold the last batch's sends into the aggregates: a new batch came, so it was not retried.
    fn commit(&mut self) {
        let mut sessions: std::collections::HashMap<(Option<String>, usize), Vec<Sent>> = Default::default();
        for x in std::mem::take(&mut self.pending) {
            let key = (x.vm.clone(), x.kind);
            if !self.kinds.contains_key(&key) && self.kinds.len() >= KINDS_KEPT {
                // Not kept: review every agent and kind not kept, until this send is out of the window.
                let until = x.end + UPLOAD_WINDOW_SECS;
                self.unkept_until = Some(self.unkept_until.map_or(until, |u| u.max(until)));
                continue;
            }
            let m = self.kinds.entry(key.clone()).or_default();
            if INTERNAL[x.kind].signs == Signs::Media {
                sessions.entry(key).or_default().push(x);
            } else {
                *m.minutes.entry((x.end / 60.0).floor() as i64).or_insert(0.0) += x.bytes;
            }
        }
        for (key, mut new) in sessions {
            if let Some(m) = self.kinds.get_mut(&key) {
                new.append(&mut m.sessions);
                m.sessions = merge_sessions(new);
            }
        }
    }

    /// Forget what is out of the window, and cut what is still too long, losing it on purpose.
    fn prune(&mut self, newest: f64) {
        let oldest_minute = ((newest - UPLOAD_WINDOW_SECS) / 60.0).floor() as i64 - 1;
        self.kinds.retain(|_, m| {
            m.minutes.retain(|minute, _| *minute >= oldest_minute);
            m.sessions.retain(|x| newest - x.end <= UPLOAD_WINDOW_SECS);
            if m.sessions.len() > SESSIONS_KEPT {
                let drop = m.sessions.len() - SESSIONS_KEPT;
                m.sessions.drain(..drop);
                m.lost_until = Some(newest + UPLOAD_WINDOW_SECS);
            }
            !m.minutes.is_empty() || !m.sessions.is_empty() || m.lost_until.is_some_and(|u| u > newest)
        });
    }

    /// What is kept for one agent and kind, as sends `uploads_over` and `media_sessions` read.
    fn kept(&self, key: &(Option<String>, usize)) -> Vec<Sent> {
        let Some(m) = self.kinds.get(key) else {
            return Vec::new();
        };
        let minutes = m.minutes.iter().map(|(minute, bytes)| {
            // At the minute's last second: an earlier send may look later, never earlier.
            let at = (*minute as f64) * 60.0 + 59.0;
            Sent {
                vm: key.0.clone(),
                kind: key.1,
                start: at,
                end: at,
                bytes: *bytes,
                conns: 1,
                flow: String::new(),
            }
        });
        minutes.chain(m.sessions.iter().cloned()).collect()
    }

    /// Whether this agent and kind lost history that would cover `at`, or is not kept while a send
    /// could not be kept, or could not be kept now.
    fn blind(&self, key: &(Option<String>, usize), at: f64) -> bool {
        match self.kinds.get(key) {
            Some(m) => m.lost_until.is_some_and(|u| at <= u),
            None => self.unkept_until.is_some_and(|u| at <= u) || self.kinds.len() >= KINDS_KEPT,
        }
    }
}

/// Meeting connections merged into sessions, as `media_sessions` groups them.
fn merge_sessions(mut v: Vec<Sent>) -> Vec<Sent> {
    v.sort_by(|a, b| a.start.total_cmp(&b.start));
    let mut out: Vec<Sent> = Vec::new();
    for x in v {
        match out.last_mut() {
            Some(s) if x.start <= s.end + MEDIA_SESSION_GAP_SECS => {
                s.end = s.end.max(x.end);
                s.bytes += x.bytes;
                s.conns += x.conns;
            }
            _ => out.push(Sent {
                flow: String::new(),
                ..x
            }),
        }
    }
    out
}

/// For each record, the internal kind it is when the review skips it; `None` for what is reviewed:
/// everything the agent did itself, and the firewall's own records with a warning sign. The records
/// of an `All` kind are reviewed together, every one in the window, when one agent sent more than
/// `LARGE_UPLOAD` in them within `UPLOAD_WINDOW_SECS`, counting what `earlier` passes skipped (the
/// scan reads the whole log and passes none). `earlier` then takes this batch's sends.
#[cfg(test)]
fn skipped_in(records: &[Value], earlier: Option<&mut Uploads>) -> Vec<Option<&'static str>> {
    skips(records, earlier).into_iter().map(|s| s.kind).collect()
}

/// What `skipped_in` decided for one record, and, when what the agent sent in the hour around it
/// (or its meeting) is what made it reviewed, that total: the record alone may look small.
pub struct Skip {
    pub kind: Option<&'static str>,
    pub sent_together: Option<f64>,
}

/// For each record, what `skipped_in` says, with the totals behind each record reviewed for one.
pub fn skips(records: &[Value], mut earlier: Option<&mut Uploads>) -> Vec<Skip> {
    use std::collections::{HashMap, HashSet};
    let kinds: Vec<Option<usize>> = records
        .iter()
        .map(|r| INTERNAL.iter().position(|k| k.matches(r) && !k.warning(r)))
        .collect();
    let mut out: Vec<Skip> = kinds
        .iter()
        .map(|k| Skip {
            kind: k.map(|i| INTERNAL[i].what),
            sent_together: None,
        })
        .collect();
    let num = |r: &Value, k: &str| r.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    // This batch's sends of the kinds that add up, each with its index here.
    let mut fresh: Vec<(Sent, usize)> = Vec::new();
    for (n, k) in kinds.iter().enumerate() {
        let Some(i) = *k else { continue };
        let r = &records[n];
        let end = num(r, "ts");
        let (start, bytes) = match INTERNAL[i].signs {
            Signs::All => (end, sent(r).unwrap_or(0.0).max(0.0)),
            Signs::Media => (
                end - num(r, "duration_ms").max(0.0) / 1000.0,
                num(r, "bytes_out").max(0.0),
            ),
            _ => continue,
        };
        let flow = s(r, "flow_id").unwrap_or("").to_string();
        let vm = s(r, "vm_id").map(str::to_string);
        fresh.push((
            Sent {
                vm,
                kind: i,
                start,
                end,
                bytes,
                conns: 1,
                flow,
            },
            n,
        ));
    }
    if let Some(e) = earlier.as_deref_mut() {
        // A batch the review retries comes again and takes the place of its first try's sends.
        let ours: HashSet<&str> = fresh.iter().map(|(x, _)| x.flow.as_str()).collect();
        e.pending.retain(|x| !ours.contains(x.flow.as_str()));
        e.commit();
    }
    let mut groups: Groups = HashMap::new();
    for (x, n) in &fresh {
        groups
            .entry((x.vm.clone(), x.kind))
            .or_default()
            .push((x.clone(), Some(*n)));
    }
    for (key, g) in &mut groups {
        if let Some(e) = earlier.as_deref() {
            // History cut short, or none can be kept: review this agent and kind, as a large upload would be.
            if g.iter().any(|(x, _)| e.blind(key, x.end)) {
                for (_, n) in g.iter() {
                    if let Some(n) = n {
                        out[*n] = Skip {
                            kind: None,
                            sent_together: None,
                        };
                    }
                }
            }
            g.extend(e.kept(key).into_iter().map(|x| (x, None)));
        }
    }
    for ((_, i), g) in groups {
        let over = match INTERNAL[i].signs {
            Signs::Media => media_sessions(g),
            _ => uploads_over(g),
        };
        for (n, total) in over {
            out[n] = Skip {
                kind: None,
                sent_together: Some(total),
            };
        }
    }
    if let Some(e) = earlier {
        e.pending = fresh
            .into_iter()
            .map(|(x, _)| x)
            .filter(|x| x.bytes > 0.0 || INTERNAL[x.kind].signs == Signs::Media)
            .collect();
        // The log's own clock: the newest record of the batch, whatever its kind.
        let newest = records.iter().map(|r| num(r, "ts")).fold(f64::MIN, f64::max);
        if newest > f64::MIN {
            e.prune(newest);
        }
    }
    out
}

/// The records of one agent's gate whose sends add up to more than `LARGE_UPLOAD` within
/// `UPLOAD_WINDOW_SECS`: every one in such a window.
fn uploads_over(mut g: Vec<(Sent, Option<usize>)>) -> Vec<(usize, f64)> {
    let mut over = Vec::new();
    g.sort_by(|a, b| a.0.end.total_cmp(&b.0.end));
    let (mut lo, mut sum, mut marked) = (0usize, 0.0f64, 0usize);
    for hi in 0..g.len() {
        sum += g[hi].0.bytes;
        while g[hi].0.end - g[lo].0.end > UPLOAD_WINDOW_SECS {
            sum -= g[lo].0.bytes;
            lo += 1;
        }
        if sum > LARGE_UPLOAD {
            over.extend(g[lo.max(marked)..=hi].iter().filter_map(|x| x.1.map(|n| (n, sum))));
            marked = hi + 1;
        }
    }
    over
}

/// One agent's meeting connections, as sessions: connections open at the same time, or within
/// `MEDIA_SESSION_GAP_SECS` of each other, carry one meeting, and a lease allows eight. A session
/// may send `MEDIA_FLOOR_BYTES` per connection (at most `MEDIA_CONNECTIONS` of them) plus
/// `MEDIA_BYTES_PER_SEC` for as long as it lasts,
/// all its connections together, not each; past that, every record of the session is reviewed.
fn media_sessions(mut g: Vec<(Sent, Option<usize>)>) -> Vec<(usize, f64)> {
    let mut over = Vec::new();
    g.sort_by(|a, b| a.0.start.total_cmp(&b.0.start));
    let mut i = 0;
    while i < g.len() {
        let (start, mut end, mut bytes, mut conns) = (g[i].0.start, g[i].0.end, 0.0, 0usize);
        let mut j = i;
        while j < g.len() && g[j].0.start <= end + MEDIA_SESSION_GAP_SECS {
            end = end.max(g[j].0.end);
            bytes += g[j].0.bytes;
            conns += g[j].0.conns;
            j += 1;
        }
        // A floor for each connection a lease can hold at once, not for every reconnect.
        let floors = conns.min(MEDIA_CONNECTIONS) as f64;
        let allowed = MEDIA_FLOOR_BYTES * floors + MEDIA_BYTES_PER_SEC * (end - start).max(0.0);
        if bytes > allowed {
            over.extend(g[i..j].iter().filter_map(|x| x.1.map(|n| (n, bytes))));
        }
        i = j;
    }
    over
}

/// A record the tools gate or the team chat gate wrote, let through or refused (its rule, or its rule
/// and why), with no rule id.
fn is_gate_record(r: &Value) -> bool {
    let rule = s(r, "rule").unwrap_or("");
    let flow = s(r, "flow_id").unwrap_or("");
    [
        (TOOLS_HOST, TOOLS_FLOW, TOOLS_RULE),
        (TEAM_CHAT_HOST, TEAM_CHAT_FLOW, TEAM_CHAT_RULE),
    ]
    .iter()
    .any(|(host, prefix, name)| {
        s(r, "host") == Some(host)
            && flow.starts_with(prefix)
            && (rule == *name || rule.strip_prefix(name).is_some_and(|w| w.starts_with(": ")))
            && r.get("rule_id").is_none_or(Value::is_null)
    })
}

/// What a record says was sent and received, as `(bytes_out, bytes_in)` would on any other record:
/// the gates wrote the request as `bytes_in` until T-222, and a gate record since says `bytes_out` is
/// what was sent (`SIZES_FIELD`). Every gate record before it had them the other way round, so one
/// without the marker is read that way. Every other record as written.
pub fn sizes(r: &Value) -> (Option<&Value>, Option<&Value>) {
    let (out, inn) = (r.get("bytes_out"), r.get("bytes_in"));
    if is_gate_record(r) && s(r, SIZES_FIELD) != Some(SIZES_OUT_IS_SENT) {
        (inn, out)
    } else {
        (out, inn)
    }
}

/// A number that is not zero, as JS reads one truthy.
pub fn nonzero(v: Option<&Value>) -> Option<&Value> {
    v.filter(|v| v.as_f64().is_some_and(|n| n != 0.0))
}

/// What the agent sent in one record (`sizes`).
pub fn sent(r: &Value) -> Option<f64> {
    sizes(r).0.and_then(Value::as_f64)
}

/// A saved-login note: the login windows leave these out too.
pub fn is_logins_note(r: &Value) -> bool {
    INTERNAL.iter().any(|k| k.what == LOGINS_NOTE && k.matches(r))
}

/// What one record is when the review skips it on its own (`skipped_in` with nothing around it).
#[cfg(test)]
fn skipped(r: &Value) -> Option<&'static str> {
    skipped_in(std::slice::from_ref(r), None)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn with(base: &Value, over: Value) -> Value {
        let mut r = base.clone();
        for (k, v) in over.as_object().expect("an object") {
            r[k] = v.clone();
        }
        r
    }

    fn reviewed(r: &Value) -> bool {
        super::super::review::reviewable(vec![r.clone()], &[], None).len() == 1
    }

    // One record of each kind, as its writer writes it.
    fn tools() -> Value {
        json!({"source": "egress", "flow_id": "cpm-0a1b2c3d4e5f60718293", "ts": 1.0, "method": "tools/list", "host": "controlplane-mcp",
               "path": "/mcp", "vm_id": "vm1", "effect": "allow", "status": 200, "bytes_out": 60, "bytes_in": 4214, "sizes": "out_is_sent",
               "duration_ms": 80, "rule": "controlclaw tools"})
    }
    fn team_chat() -> Value {
        json!({"source": "egress", "flow_id": "tc-0a1b2c3d4e5f60718293", "ts": 1.0, "method": "POST", "host": "team-chat",
               "path": "/api/channels/[id]/messages", "vm_id": "vm1", "effect": "allow", "status": 200, "bytes_out": 300, "sizes": "out_is_sent",
               "bytes_in": 900, "duration_ms": 30, "rule": "team chat"})
    }
    fn logins_note() -> Value {
        json!({"source": "egress", "flow_id": "lgn-0a1b2c3d4e5f60718293", "ts": 1.0, "method": "POST", "host": "controlclaw-logins",
               "path": "/use", "vm_id": "vm1", "effect": "allow", "status": 200, "rule": "login GitHub: handed to the agent",
               "login": "GitHub"})
    }
    fn phone() -> Value {
        json!({"source": "egress", "flow_id": "CA123-ab12", "ts": 1.0, "method": "WS", "host": "api.twilio.com",
               "path": "/phone-stream/[stream]", "vm_id": "vm1", "effect": "allow", "status": 101, "bytes_in": 3_000_000,
               "bytes_out": 2_500_000, "duration_ms": 300_000, "rule": "phone stream: close stop inbound realtime gpt-live"})
    }
    fn meet() -> Value {
        json!({"flow_id": "meet_0a1b2c3d4e5f607182930a1b", "ts": 1.0, "vm_id": "vm1", "host": "meet.turns.goog", "port": 443,
               "effect": "tunnel", "rule": "meet-media-v1", "bytes_in": 90_000_000, "bytes_out": 80_000_000, "reason": "closed",
               "duration_ms": 1_800_000, "rule_id": null})
    }
    fn voice_end() -> Value {
        json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000000:end", "ts": 1.0, "vm_id": "vm1", "host": "api.openai.com",
               "method": "GET", "path": "/v1/realtime", "effect": "allow", "rule": "meeting_voice: gpt-live 47 s billed", "rule_id": null})
    }
    fn control_plane() -> Value {
        json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000001", "ts": 1.0, "vm_id": "vm1", "host": "controlclaw.com",
               "method": "POST", "path": "/api/vm-agent/events", "effect": "allow", "status": 200, "rule": "control_plane", "rule_id": null})
    }
    fn backup() -> Value {
        json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000002", "ts": 1.0, "vm_id": "vm1",
               "host": "controlclaw-backups.s3.eu-west-1.amazonaws.com", "method": "PUT", "path": "/org1/b1/workspace.cc",
               "effect": "allow", "status": 200, "bytes_out": 50_000_000, "rule": "backup_store", "rule_id": null})
    }
    fn update() -> Value {
        json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000003", "ts": 1.0, "vm_id": "vm1", "host": "registry.npmjs.org",
               "method": "GET", "path": "/openclaw", "effect": "allow", "status": 200, "bytes_in": 9_000_000, "rule": "agent_update",
               "rule_id": null})
    }

    #[test]
    fn every_internal_kind_is_skipped() {
        for (r, what) in [
            (tools(), "ControlClaw tools"),
            (team_chat(), "team chat"),
            (logins_note(), "saved-login note"),
            (phone(), "phone stream"),
            (meet(), "meeting media"),
            (with(&meet(), json!({"host": "workspace.turns.goog"})), "meeting media"),
            (voice_end(), "voice billing note"),
            (
                with(&voice_end(), json!({"rule": "phone_voice: gpt-live 12 s billed"})),
                "voice billing note",
            ),
            (control_plane(), "control plane"),
            (backup(), "backup store"),
        ] {
            assert_eq!(skipped(&r), Some(what), "{r}");
            assert!(!reviewed(&r), "{r}");
        }
    }

    #[test]
    fn refused_failed_or_large_is_still_reviewed() {
        for r in [
            // Refused by the gates: their rule names why.
            with(
                &tools(),
                json!({"effect": "drop", "status": 429, "rule": "controlclaw tools: too many calls"}),
            ),
            with(
                &team_chat(),
                json!({"effect": "drop", "status": 403, "rule": "team chat: blocked by a rule"}),
            ),
            // Failed.
            with(&tools(), json!({"status": 502})),
            with(&team_chat(), json!({"status": 500})),
            // A large upload.
            with(&tools(), json!({"bytes_out": 2_000_000})),
            with(&team_chat(), json!({"bytes_out": 2_000_000})),
            // Any process on the agent can use an update's window: never skipped.
            update(),
            with(&update(), json!({"method": "PUT", "bytes_out": 900_000})),
            // A refused stream, a refused backup.
            with(
                &phone(),
                json!({"effect": "drop", "status": 403, "rule": "phone stream: refusal admission unknown classic none"}),
            ),
            with(&backup(), json!({"effect": "block", "status": 403})),
            // A meeting connection that did not close normally: the budget spent, the lease revoked.
            with(&meet(), json!({"reason": "byte_limit"})),
            with(&meet(), json!({"reason": "revoked_or_limit"})),
            with(&meet(), json!({"reason": null})),
            // More sent than audio and a shared page use for as long as it was open.
            with(&meet(), json!({"bytes_out": 2_000_000 + 250_000 * 1_800 + 1})),
            with(&meet(), json!({"duration_ms": 1_000, "bytes_out": 5_000_000})),
        ] {
            assert_eq!(skipped(&r), None, "{r}");
            assert!(reviewed(&r), "{r}");
        }
    }

    #[test]
    fn a_meeting_at_media_rates_that_closed_normally_is_skipped() {
        for r in [
            meet(),
            // 0.15 Mbit/s of audio for an hour; a short connection under the floor.
            with(&meet(), json!({"duration_ms": 3_600_000, "bytes_out": 68_000_000})),
            with(&meet(), json!({"duration_ms": 2_000, "bytes_out": 1_500_000})),
            with(&meet(), json!({"bytes_out": 2_000_000 + 250_000 * 1_800})),
        ] {
            assert_eq!(skipped(&r), Some("meeting media"), "{r}");
        }
    }

    fn at(base: &Value, ts: f64, vm: &str, sent: f64) -> Value {
        // The gate's flow prefix, and a flow id of its own for each send.
        let prefix = s(base, "flow_id").and_then(|f| f.split('-').next()).unwrap_or("x");
        with(
            base,
            json!({"ts": ts, "vm_id": vm, "bytes_out": sent, "flow_id": format!("{prefix}-{ts}-{vm}")}),
        )
    }

    #[test]
    fn uploads_just_under_the_bound_add_up_per_agent_and_kind_within_an_hour() {
        // Three posts of 900 kB within an hour: all three are reviewed, the first two too.
        let three = [
            at(&team_chat(), 1000.0, "vm1", 900_000.0),
            at(&team_chat(), 1600.0, "vm1", 900_000.0),
            at(&team_chat(), 2200.0, "vm1", 900_000.0),
        ];
        assert_eq!(skipped_in(&three, None), vec![None, None, None]);
        assert!(super::super::review::reviewable(three.to_vec(), &[], None).len() == 3);
        // The same, an hour and more apart: each is alone in its hour.
        let apart = [
            at(&team_chat(), 0.0, "vm1", 900_000.0),
            at(&team_chat(), 3700.0, "vm1", 900_000.0),
            at(&team_chat(), 7400.0, "vm1", 900_000.0),
        ];
        assert_eq!(skipped_in(&apart, None), vec![Some("team chat"); 3]);
        // Two agents, or two kinds, are counted apart.
        let two = [
            at(&tools(), 1000.0, "vm1", 900_000.0),
            at(&tools(), 1001.0, "vm2", 900_000.0),
            at(&team_chat(), 1002.0, "vm1", 900_000.0),
        ];
        assert_eq!(
            skipped_in(&two, None),
            vec![Some("ControlClaw tools"), Some("ControlClaw tools"), Some("team chat")]
        );
        // Ordinary calls in between are reviewed with the upload only while they share its hour.
        let mixed = [
            at(&tools(), 0.0, "vm1", 100.0),
            at(&tools(), 5000.0, "vm1", 600_000.0),
            at(&tools(), 5100.0, "vm1", 100.0),
            at(&tools(), 5200.0, "vm1", 600_000.0),
            at(&tools(), 20_000.0, "vm1", 100.0),
        ];
        assert_eq!(
            skipped_in(&mixed, None),
            vec![Some("ControlClaw tools"), None, None, None, Some("ControlClaw tools")]
        );
        // A refusal in the window is reviewed on its own sign and does not add to the sum.
        let refused = [
            at(&tools(), 0.0, "vm1", 900_000.0),
            with(
                &at(&tools(), 10.0, "vm1", 900_000.0),
                json!({"effect": "drop", "rule": "controlclaw tools: too large"}),
            ),
        ];
        assert_eq!(skipped_in(&refused, None), vec![Some("ControlClaw tools"), None]);
    }

    #[test]
    fn the_review_every_minute_adds_up_uploads_across_its_passes() {
        let mut uploads = Uploads::default();
        // Three passes, one 900 kB post each, minutes apart: the third pass reviews what tips it over.
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1000.0, "vm1", 900_000.0)], Some(&mut uploads)),
            vec![Some("team chat")]
        );
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1300.0, "vm1", 900_000.0)], Some(&mut uploads)),
            vec![None]
        );
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1600.0, "vm1", 900_000.0)], Some(&mut uploads)),
            vec![None]
        );
        // Another agent, or the tools gate, starts from nothing.
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1700.0, "vm2", 900_000.0)], Some(&mut uploads)),
            vec![Some("team chat")]
        );
        assert_eq!(
            skipped_in(&[at(&tools(), 1800.0, "vm1", 900_000.0)], Some(&mut uploads)),
            vec![Some("ControlClaw tools")]
        );
        // More than an hour on, the old sends are forgotten.
        assert_eq!(
            skipped_in(&[at(&team_chat(), 6000.0, "vm1", 900_000.0)], Some(&mut uploads)),
            vec![Some("team chat")]
        );
        assert!(uploads.kinds.values().all(|m| {
            m.minutes
                .keys()
                .all(|k| 6000.0 - (*k as f64) * 60.0 <= UPLOAD_WINDOW_SECS + 120.0)
        }));
        // Small calls in between stay small.
        let mut quiet = Uploads::default();
        for i in 0..100 {
            assert_eq!(
                skipped_in(&[at(&tools(), f64::from(i) * 30.0, "vm1", 300.0)], Some(&mut quiet)),
                vec![Some("ControlClaw tools")]
            );
        }
    }

    #[test]
    fn a_retried_batch_is_not_counted_twice_and_old_records_count_their_request() {
        let mut uploads = Uploads::default();
        let post = at(&team_chat(), 1000.0, "vm1", 400_000.0);
        for _ in 0..3 {
            assert_eq!(
                skipped_in(std::slice::from_ref(&post), Some(&mut uploads)),
                vec![Some("team chat")]
            );
        }
        // Counted once: the next batch folds it in.
        skips(&[at(&team_chat(), 1001.0, "vm2", 1.0)], Some(&mut uploads));
        let kept: f64 = uploads.kinds.values().flat_map(|m| m.minutes.values()).sum();
        assert_eq!(kept, 400_000.0);
        // A gate record from before T-222: the request is `bytes_in`, the answer `bytes_out`.
        let mut old = Vec::new();
        for i in 0..20 {
            let mut r = with(
                &tools(),
                json!({"ts": 1000.0 + f64::from(i) * 60.0, "flow_id": format!("cpm-old{i}"), "bytes_out": 69_754, "bytes_in": 46}),
            );
            r.as_object_mut().expect("an object").remove("sizes");
            old.push(r);
        }
        assert!(skipped_in(&old, None).iter().all(|k| *k == Some("ControlClaw tools")));
        let mut big = old[0].clone();
        big["bytes_in"] = json!(2_000_000);
        assert_eq!(skipped_in(&[big], None), vec![None]);
    }

    /// A meeting connection of `vm` that ended at `end` after `secs`, having sent `rate` bytes a second.
    fn conn(n: usize, vm: &str, end: f64, secs: f64, rate: f64) -> Value {
        with(
            &meet(),
            json!({"flow_id": format!("meet_{vm}{n}"), "vm_id": vm, "ts": end, "duration_ms": secs * 1000.0, "bytes_out": rate * secs}),
        )
    }

    #[test]
    fn a_meetings_connections_add_up_against_one_meetings_rate() {
        // Eight connections at 240 kB/s for 4.5 minutes: each fits the bound alone, together ~520 MB.
        let eight: Vec<Value> = (0..8)
            .map(|n| conn(n, "vm1", 10_000.0 + n as f64, 270.0, 240_000.0))
            .collect();
        for r in &eight {
            assert_eq!(skipped(r), Some("meeting media"), "alone");
        }
        assert_eq!(skipped_in(&eight, None), vec![None; 8]);
        // The same, each ending in a pass of its own.
        let mut uploads = Uploads::default();
        let passes: Vec<Option<&str>> = eight
            .iter()
            .map(|r| skipped_in(std::slice::from_ref(r), Some(&mut uploads))[0])
            .collect();
        assert!(passes.iter().skip(1).all(Option::is_none), "{passes:?}");
        // A real meeting: three connections of audio at 15 kB/s for 40 minutes, and a short one.
        let meeting = [
            conn(0, "vm1", 2400.0, 2400.0, 15_000.0),
            conn(1, "vm1", 2401.0, 2400.0, 15_000.0),
            conn(2, "vm1", 2390.0, 2380.0, 15_000.0),
            conn(3, "vm1", 30.0, 20.0, 50_000.0),
        ];
        assert_eq!(skipped_in(&meeting, None), vec![Some("meeting media"); 4]);
        // Two meetings an hour apart are two sessions; another agent's meeting is its own.
        let apart = [
            conn(0, "vm1", 1000.0, 600.0, 200_000.0),
            conn(1, "vm1", 5000.0, 600.0, 200_000.0),
            conn(2, "vm2", 1000.0, 600.0, 200_000.0),
        ];
        assert_eq!(skipped_in(&apart, None), vec![Some("meeting media"); 3]);
    }

    #[test]
    fn reconnecting_does_not_raise_the_meetings_allowance_and_the_total_goes_with_the_review() {
        // A new connection every 5 s for 10 minutes, ~2 MB each: ~400 kB/s, each alone within its floor.
        let churn: Vec<Value> = (0..120)
            .map(|n| conn(n, "vm1", 1000.0 + n as f64 * 5.0, 5.0, 400_000.0))
            .collect();
        assert_eq!(skipped(&churn[0]), Some("meeting media"));
        let s = skips(&churn, None);
        assert!(s.iter().all(|x| x.kind.is_none()));
        assert!(s[0].sent_together.is_some_and(|b| b > 200_000_000.0));
        // Gate posts that add up: each reviewed record carries the hour's total, and the review sees it.
        let mut uploads = Uploads::default();
        skips(&[at(&team_chat(), 1000.0, "vm1", 900_000.0)], Some(&mut uploads));
        let third = at(&team_chat(), 1300.0, "vm1", 900_000.0);
        let s = skips(std::slice::from_ref(&third), Some(&mut uploads));
        assert_eq!((s[0].kind, s[0].sent_together), (None, Some(1_800_000.0)));
        let mut uploads = Uploads::default();
        skips(&[at(&team_chat(), 1000.0, "vm1", 900_000.0)], Some(&mut uploads));
        let r = super::super::review::reviewable(vec![third], &[], Some(&mut uploads));
        assert_eq!(r[0]["sent_this_hour"], json!(1_800_000.0));
        assert_eq!(
            super::super::review::compact_event(&r[0])["sent_this_hour"],
            json!(1_800_000.0)
        );
    }

    fn kind_index(what: &str) -> usize {
        INTERNAL.iter().position(|k| k.what == what).expect("a kind")
    }

    #[test]
    fn a_flood_of_one_kind_does_not_push_another_kinds_history_out() {
        let mut uploads = Uploads::default();
        let eight: Vec<Value> = (0..8)
            .map(|n| conn(n, "vm1", 10_000.0 + n as f64 * 30.0, 270.0, 240_000.0))
            .collect();
        let mut passes = Vec::new();
        for (n, c) in eight.iter().enumerate() {
            passes.push(skipped_in(std::slice::from_ref(c), Some(&mut uploads))[0]);
            // Between two closes, 20,000 empty team chat reads and 20,000 small ones, in passes of 1,000.
            for p in 0..40 {
                let flood: Vec<Value> = (0..1000)
                    .map(|i| {
                        let mut r = at(
                            &team_chat(),
                            10_000.0 + n as f64 * 30.0 + f64::from(p) * 0.1,
                            "vm1",
                            if p % 2 == 0 { 0.0 } else { 10.0 },
                        );
                        r["flow_id"] = json!(format!("tc-{n}-{p}-{i}"));
                        r
                    })
                    .collect();
                skips(&flood, Some(&mut uploads));
            }
        }
        assert!(passes.iter().skip(1).all(Option::is_none), "{passes:?}");
        // Bounded: a minute's sum per agent and kind, and the meeting's merged sessions, not one entry a request.
        let m = &uploads.kinds[&(Some("vm1".into()), kind_index("team chat"))];
        assert!(m.minutes.len() <= 62 && uploads.kinds.values().all(|m| m.sessions.len() <= SESSIONS_KEPT));
        assert!(uploads.pending.len() <= 1000);
    }

    #[test]
    fn history_that_cannot_be_kept_fails_closed() {
        let mut uploads = Uploads::default();
        // As many agents as are kept, each with one meeting connection.
        for n in 0..KINDS_KEPT {
            skipped_in(&[conn(n, &format!("vm{n}"), 1000.0, 1.0, 1_000.0)], Some(&mut uploads));
        }
        skipped_in(&[conn(0, "vm0", 1001.0, 1.0, 1_000.0)], Some(&mut uploads));
        assert_eq!(uploads.kinds.len(), KINDS_KEPT);
        // One more agent cannot be remembered: its records are reviewed. A kept one's are not.
        assert_eq!(
            skipped_in(&[conn(1, "vm-new", 1002.0, 1.0, 1_000.0)], Some(&mut uploads)),
            vec![None]
        );
        assert_eq!(
            skipped_in(&[conn(2, "vm1", 1003.0, 1.0, 1_000.0)], Some(&mut uploads)),
            vec![Some("meeting media")]
        );
        // History cut short: reviewed until the hour it covered has passed.
        uploads
            .kinds
            .get_mut(&(Some("vm1".into()), kind_index("meeting media")))
            .expect("kept")
            .lost_until = Some(5000.0);
        assert_eq!(
            skipped_in(&[conn(3, "vm1", 4000.0, 1.0, 1_000.0)], Some(&mut uploads)),
            vec![None]
        );
    }

    #[test]
    fn a_retry_that_reads_further_counts_each_send_once_and_empty_connections_bridge_a_meeting() {
        let mut uploads = Uploads::default();
        let a = at(&team_chat(), 1000.0, "vm1", 400_000.0);
        let b = at(&team_chat(), 1010.0, "vm1", 400_000.0);
        skipped_in(std::slice::from_ref(&a), Some(&mut uploads));
        // The pass failed; the next starts at the same place and reads one more record.
        skipped_in(&[a.clone(), b], Some(&mut uploads));
        skipped_in(&[at(&team_chat(), 1020.0, "vm2", 1.0)], Some(&mut uploads));
        let kept: f64 = uploads.kinds[&(Some("vm1".into()), kind_index("team chat"))]
            .minutes
            .values()
            .sum();
        assert_eq!(kept, 800_000.0);
        // A meeting's empty connection holds its session together across passes.
        let mut uploads = Uploads::default();
        skipped_in(&[conn(0, "vm1", 1000.0, 100.0, 0.0)], Some(&mut uploads));
        skipped_in(&[conn(1, "vm1", 1050.0, 10.0, 0.0)], Some(&mut uploads));
        skipped_in(&[conn(2, "vm1", 1110.0, 10.0, 0.0)], Some(&mut uploads));
        skipped_in(&[conn(3, "vm1", 1120.0, 1.0, 0.0)], Some(&mut uploads));
        assert_eq!(
            uploads.kinds[&(Some("vm1".into()), kind_index("meeting media"))]
                .sessions
                .len(),
            1
        );
    }

    #[test]
    fn an_agent_not_kept_stays_reviewed_after_room_is_made() {
        let mut uploads = Uploads::default();
        for n in 0..KINDS_KEPT {
            skipped_in(&[conn(n, &format!("vm{n}"), 1000.0, 1.0, 1_000.0)], Some(&mut uploads));
        }
        // vm-new's send comes while the map is full: reviewed, and it cannot be kept.
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1001.0, "vm-new", 900_000.0)], Some(&mut uploads)),
            vec![None]
        );
        // Hours later the old agents are gone: room again, and nothing lost is in the window any more.
        skipped_in(&[at(&team_chat(), 9000.0, "vm0", 1.0)], Some(&mut uploads));
        assert!(uploads.kinds.len() < KINDS_KEPT);
        assert_eq!(
            skipped_in(&[at(&team_chat(), 9001.0, "vm-new", 200_000.0)], Some(&mut uploads)),
            vec![Some("team chat")]
        );
        // But within the hour after the lost send, vm-new is still reviewed even with room.
        let mut uploads = Uploads::default();
        for n in 0..KINDS_KEPT {
            skipped_in(&[conn(n, &format!("vm{n}"), 1000.0, 1.0, 1_000.0)], Some(&mut uploads));
        }
        skipped_in(&[at(&team_chat(), 1001.0, "vm-new", 900_000.0)], Some(&mut uploads));
        skipped_in(&[at(&team_chat(), 1002.0, "vm0", 1.0)], Some(&mut uploads));
        uploads.kinds.retain(|k, _| k.0.as_deref() == Some("vm0"));
        assert_eq!(
            skipped_in(&[at(&team_chat(), 1500.0, "vm-new", 200_000.0)], Some(&mut uploads)),
            vec![None]
        );
    }

    #[test]
    fn an_old_gate_record_is_read_the_other_way_round_everywhere() {
        let mut old = tools();
        old.as_object_mut().expect("an object").remove("sizes");
        old["bytes_out"] = json!(69_754);
        old["bytes_in"] = json!(46);
        assert_eq!(sent(&old), Some(46.0));
        assert_eq!(sent(&tools()), Some(60.0));
        // A refusal the gate wrote too.
        let refused = with(&old, json!({"effect": "drop", "rule": "controlclaw tools: too large"}));
        assert_eq!(sent(&refused), Some(46.0));
        // The agent's own request to a host of that name, and an owner's rule: as written.
        assert_eq!(
            sent(&with(&old, json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"}))),
            Some(69_754.0)
        );
        assert_eq!(sent(&with(&old, json!({"rule_id": "r1"}))), Some(69_754.0));
        let e = super::super::review::compact_event(&old);
        assert_eq!(
            (e["bytes_out"].clone(), e["bytes_in"].clone()),
            (json!(46), json!(69_754))
        );
    }

    #[test]
    fn a_login_note_carries_its_login() {
        assert_eq!(skipped(&with(&logins_note(), json!({"login": ""}))), None);
        let mut r = logins_note();
        r.as_object_mut().expect("an object").remove("login");
        assert_eq!(skipped(&r), None);
        assert!(!is_logins_note(&r));
    }

    #[test]
    fn a_look_alike_is_still_reviewed() {
        for r in [
            // An owner's rule named like the firewall's own: it carries its id.
            with(&tools(), json!({"rule_id": "r1"})),
            with(&team_chat(), json!({"rule_id": "r1"})),
            with(&control_plane(), json!({"host": "evil.example", "rule_id": "r1"})),
            with(&phone(), json!({"rule_id": "r1"})),
            with(&meet(), json!({"rule_id": "r1"})),
            with(&voice_end(), json!({"rule_id": "r1"})),
            // An agent's own request to a host named like the gates': the proxy's uuid flow id.
            with(&tools(), json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"})),
            with(&team_chat(), json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"})),
            with(
                &logins_note(),
                json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"}),
            ),
            with(&meet(), json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"})),
            with(&voice_end(), json!({"flow_id": "6f1e2d3c-0000-4000-8000-000000000009"})),
            // The gates' flow ids and rules on another host.
            with(&tools(), json!({"host": "controlplane-mcp.evil.example"})),
            with(&team_chat(), json!({"host": "team-chat.example"})),
            with(&phone(), json!({"host": "api.twilio.com.evil.example"})),
            with(
                &phone(),
                json!({"method": "POST", "path": "/2010-04-01/Accounts/AC1/Messages.json"}),
            ),
            with(&meet(), json!({"host": "turns.evil.example"})),
            // A managed rule's request is the managed check's business, never this list's.
            with(&tools(), json!({"managed": "telegram"})),
            // The rule of another kind.
            with(&tools(), json!({"rule": "team chat"})),
            with(&voice_end(), json!({"rule": "grant"})),
        ] {
            assert_eq!(skipped(&r), None, "{r}");
            assert!(reviewed(&r), "{r}");
        }
    }
}
