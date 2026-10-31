//! Team chat's counts for the console's Overview tab (`teamchat-stats.ts`,
//! docs/plans/team-chat-overview-charts.md).
//!
//! Every 5 minutes this reads the messages posted since its cursor through ClickClack's API, as the
//! owner, and ships one `teamchat_stats` record per finished 5-minute interval: per channel,
//! messages by people and by agents, files, @mentions of agents, how many of those the agent
//! answered within 5 minutes and how fast, and which agent @mentioned which. With each pass, the
//! channel list and how many people are in the workspace. No text leaves the firewall.
//!
//! An interval is counted once the 5 minutes after it are over too. The cursor moves only after the
//! console took the records, so delivery is at-least-once.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::api::{ApiError, Message, TeamChatReadApi};
use super::firewall::{CounterContext, TeamChatFirewall};
use crate::integrations::js;

pub const TEAMCHAT_STATS_MS: u64 = 5 * 60_000;
pub const INTERVAL_MS: i64 = 5 * 60_000;
/// An @mention counts as answered when the agent posts in the channel within this.
pub const ANSWER_MS: i64 = 5 * 60_000;
/// After an outage, or on the first pass, count at most this far back.
pub const LOOKBACK_MS: i64 = 24 * 60 * 60_000;
/// A channel further behind than this skips ahead rather than paging through all of it.
const MAX_BEHIND: i64 = 5_000;
const PAGE: i64 = 200;
/// Pages per channel per pass; the rest is read on the next pass.
const MAX_PAGES: usize = 10;
const POST_CHUNK: usize = 100;
/// Well under the console's 512 KB body limit: a 413 would drop the counts for good.
const POST_BYTES: usize = 256 * 1024;
const MAX_CHANNELS: usize = 200;
const MAX_PAIRS: usize = 200;
/// Message kinds that are not someone writing (a join, a rename). Anything else counts.
const NOT_WRITTEN: &[&str] = &[
    "system",
    "join",
    "leave",
    "event",
    "member_joined",
    "member_left",
    "channel_renamed",
];

fn floor_to(ms: i64, step: i64) -> i64 {
    ms.div_euclid(step) * step
}

/// `Math.round` of the middle two for an even count.
fn median(xs: &[i64]) -> Option<i64> {
    if xs.is_empty() {
        return None;
    }
    let mut s = xs.to_vec();
    s.sort_unstable();
    let mid = s.len() >> 1;
    Some(if s.len() % 2 == 1 {
        s[mid]
    } else {
        ((s[mid - 1] + s[mid]) as f64 / 2.0 + 0.5).floor() as i64
    })
}

/// What the counter keeps of a message once read: no body.
#[derive(Debug, Clone, PartialEq)]
pub struct Counted {
    pub seq: i64,
    pub author_id: String,
    pub author_kind: Option<String>,
    /// A person or an agent wrote it (not a join, a rename).
    pub written: bool,
    pub created_at: i64,
    pub files: i64,
    /// Bot user ids it @mentions, without its author.
    pub mentions: Vec<String>,
}

pub fn to_counted(m: &Message, handles: &HashMap<String, String>) -> Counted {
    Counted {
        seq: m.seq,
        author_id: m.author_id.clone(),
        author_kind: m.author_kind.clone(),
        written: m.kind.as_deref().is_none_or(|k| !NOT_WRITTEN.contains(&k)),
        created_at: m.created_at,
        files: m.files,
        mentions: mentioned_bots(&m.body, &m.author_id, handles),
    }
}

/// The agents a message @mentions, as bot user ids, without its author and without repeats.
pub fn mentioned_bots(body: &str, author: &str, handles: &HashMap<String, String>) -> Vec<String> {
    // JavaScript's `\w` and `\b` are ASCII.
    static MENTION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)(?:^|[^A-Za-z0-9_@./-])@([a-z0-9][a-z0-9_-]{1,31})(?-u:\b)").expect("pattern")
    });
    let mut out: Vec<String> = Vec::new();
    for c in MENTION.captures_iter(body) {
        if let Some(bot) = handles.get(&c[1].to_lowercase())
            && bot != author
            && !out.contains(bot)
        {
            out.push(bot.clone());
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelCounts {
    pub id: String,
    pub name: String,
    pub people_msgs: i64,
    pub agent_msgs: i64,
    pub files: i64,
    pub mentions: i64,
    pub answered: i64,
    pub reply_ms_median: Option<i64>,
    pub reply_n: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PairCount {
    pub from_vm_id: String,
    pub to_vm_id: String,
    pub channel_id: String,
    pub count: i64,
}

/// The counts of every interval in [from, to) for one channel, in one walk over its messages
/// (sequence order). Intervals with nothing in them are left out.
pub fn count_channel_range(
    id: &str,
    name: &str,
    messages: &[Counted],
    from: i64,
    to: i64,
    bots: &HashMap<String, String>,
    owner: &str,
) -> BTreeMap<i64, (ChannelCounts, Vec<PairCount>)> {
    // Insertion order of the starts is kept for the pairs; the map is by start.
    // Per interval: the counts, the pairs by `from to`, and the reply times.
    type Interval = (ChannelCounts, Vec<(String, PairCount)>, Vec<i64>);
    let mut by_start: BTreeMap<i64, Interval> = BTreeMap::new();
    for (i, m) in messages.iter().enumerate() {
        if m.created_at < from || m.created_at >= to || !m.written || m.author_id == owner {
            continue;
        }
        let start = floor_to(m.created_at, INTERVAL_MS);
        let iv = by_start.entry(start).or_insert_with(|| {
            (
                ChannelCounts {
                    id: id.into(),
                    name: name.into(),
                    people_msgs: 0,
                    agent_msgs: 0,
                    files: 0,
                    mentions: 0,
                    answered: 0,
                    reply_ms_median: None,
                    reply_n: 0,
                },
                Vec::new(),
                Vec::new(),
            )
        });
        let from_agent = bots.get(&m.author_id);
        if from_agent.is_some() || m.author_kind.as_deref() == Some("bot") {
            iv.0.agent_msgs += 1;
        } else {
            iv.0.people_msgs += 1;
        }
        iv.0.files += m.files;
        for bot in &m.mentions {
            iv.0.mentions += 1;
            let to_agent = bots.get(bot);
            if let (Some(f), Some(t)) = (from_agent, to_agent)
                && f != t
            {
                let key = format!("{f} {t}");
                match iv.1.iter_mut().find(|(k, _)| *k == key) {
                    Some((_, p)) => p.count += 1,
                    None => iv.1.push((
                        key,
                        PairCount {
                            from_vm_id: f.clone(),
                            to_vm_id: t.clone(),
                            channel_id: id.into(),
                            count: 1,
                        },
                    )),
                }
            }
            // Answered: the mentioned agent posted here within ANSWER_MS. Its first such post is the
            // reply time.
            for n in &messages[i + 1..] {
                if n.created_at - m.created_at > ANSWER_MS {
                    break;
                }
                if n.author_id == *bot && n.written {
                    iv.0.answered += 1;
                    iv.2.push((n.created_at - m.created_at).max(0));
                    break;
                }
            }
        }
    }
    by_start
        .into_iter()
        .map(|(start, (mut c, pairs, replies))| {
            c.reply_n = replies.len() as i64;
            c.reply_ms_median = median(&replies);
            (start, (c, pairs.into_iter().map(|(_, p)| p).collect()))
        })
        .collect()
}

/// Records in posts of at most POST_CHUNK records and about POST_BYTES of JSON, in order.
pub fn chunk_records(records: Vec<Value>) -> Vec<Vec<Value>> {
    let mut out = Vec::new();
    let mut cur: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    for r in records {
        let size = js::stringify(&r).encode_utf16().count();
        if !cur.is_empty() && (cur.len() >= POST_CHUNK || bytes + size > POST_BYTES) {
            out.push(std::mem::take(&mut cur));
            bytes = 0;
        }
        cur.push(r);
        bytes += size;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelState {
    pub seq: i64,
    pub last_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CounterState {
    pub version: u32,
    pub counted_until: i64,
    pub channels: crate::integrations::ordmap::OrdMap<ChannelState>,
}

pub fn empty_counter_state(now: i64) -> CounterState {
    CounterState {
        version: 1,
        counted_until: floor_to(now - LOOKBACK_MS, INTERVAL_MS),
        channels: Default::default(),
    }
}

/// Team chat's context while it runs (None while it is off).
pub type Context = Arc<dyn Fn() -> Option<CounterContext> + Send + Sync>;
/// The owner's session; `true` for a fresh one (the stored one was refused).
pub type Session = Arc<dyn Fn(bool) -> cc_http::BoxFuture<Result<String, ApiError>> + Send + Sync>;

/// Sends records to the console; true once it took them (or refused them for good).
pub type Post = Arc<dyn Fn(Vec<Value>) -> cc_http::BoxFuture<bool> + Send + Sync>;

struct Mem {
    state: Option<CounterState>,
    /// Read but not yet counted, per channel, in sequence order. Memory only.
    buffer: HashMap<String, Vec<Counted>>,
    /// The last sequence number read into `buffer`, per channel.
    read_seq: HashMap<String, i64>,
    last_error: Option<String>,
    failing: HashSet<String>,
}

pub struct TeamChatCounter {
    path: PathBuf,
    context: Context,
    session: Session,
    api: Arc<dyn TeamChatReadApi>,
    post: Post,
    mem: tokio::sync::Mutex<Mem>,
    now: super::firewall::Clock,
}

impl TeamChatCounter {
    pub fn new(
        path: PathBuf,
        chat: Arc<TeamChatFirewall>,
        api: Arc<dyn TeamChatReadApi>,
        post: Post,
        now: super::firewall::Clock,
    ) -> Arc<Self> {
        let (c1, c2) = (chat.clone(), chat);
        Self::with(
            path,
            Arc::new(move || c1.counter_context()),
            Arc::new(move |fresh| {
                let c = c2.clone();
                Box::pin(async move { c.owner_session(fresh).await })
            }),
            api,
            post,
            now,
        )
    }

    pub fn with(
        path: PathBuf,
        context: Context,
        session: Session,
        api: Arc<dyn TeamChatReadApi>,
        post: Post,
        now: super::firewall::Clock,
    ) -> Arc<Self> {
        Arc::new(Self {
            path,
            context,
            session,
            api,
            post,
            mem: tokio::sync::Mutex::new(Mem {
                state: None,
                buffer: HashMap::new(),
                read_seq: HashMap::new(),
                last_error: None,
                failing: HashSet::new(),
            }),
            now,
        })
    }

    fn load(&self, mem: &mut Mem) {
        if mem.state.is_some() {
            return;
        }
        let loaded =
            std::fs::read_to_string(&self.path)
                .ok()
                .and_then(|t| match serde_json::from_str::<CounterState>(&t) {
                    Ok(s) if s.version == 1 => Some(s),
                    Ok(_) => None,
                    Err(e) => {
                        tracing::info!("[teamchat-stats] cursor unreadable, starting over: {e}");
                        None
                    }
                });
        mem.state = Some(loaded.unwrap_or_else(|| empty_counter_state((self.now)())));
    }

    fn save(&self, state: &CounterState) {
        if let Some(d) = self.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let tmp = self.path.with_extension("json.tmp");
        let text = js::stringify(&serde_json::to_value(state).unwrap_or(Value::Null));
        let written = {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .and_then(|mut f| f.write_all(text.as_bytes()))
        };
        if written.is_ok() {
            let _ = std::fs::rename(&tmp, &self.path);
        }
    }

    /// One pass. Skips quietly while Team chat is off; logs a failure once until it changes.
    pub async fn tick(&self) -> Option<usize> {
        // One pass at a time: a tick while one runs is skipped.
        let Ok(mut mem) = self.mem.try_lock() else {
            return None;
        };
        match (self.context)() {
            None => None,
            Some(ctx) => match self.pass(&mut mem, &ctx).await {
                Ok(n) => {
                    mem.last_error = None;
                    Some(n)
                }
                Err(e) => {
                    let line = crate::integrations::connectors::firewall::js_slice(&e, 200);
                    if mem.last_error.as_deref() != Some(line.as_str()) {
                        tracing::info!("[teamchat-stats] skipped a pass: {line}");
                    }
                    mem.last_error = Some(line);
                    None
                }
            },
        }
    }

    /// `asOwner`: a read with the owner's session, and once more with a fresh one on a 401.
    async fn as_owner<T>(
        &self,
        call: impl Fn(String) -> cc_http::BoxFuture<Result<T, ApiError>>,
    ) -> Result<T, ApiError> {
        match call((self.session)(false).await?).await {
            Err(e) if e.status == 401 => call((self.session)(true).await?).await,
            r => r,
        }
    }

    async fn pass(&self, mem: &mut Mem, ctx: &CounterContext) -> Result<usize, String> {
        self.load(mem);
        let mut state = mem.state.clone().unwrap_or_else(|| empty_counter_state((self.now)()));
        let now = (self.now)();
        // A long outage: count the last day only, so a returning firewall does not send a flood.
        let floor = floor_to(now - LOOKBACK_MS, INTERVAL_MS);
        if state.counted_until < floor {
            state.counted_until = floor;
        }
        let w = ctx.workspace_id.clone();
        let (api, w2) = (self.api.clone(), w.clone());
        let api2 = self.api.clone();
        // Both at once, as the TS's `Promise.all`.
        let (listed, members) = tokio::join!(
            self.as_owner(move |s| api.channel_list(s, w2.clone())),
            self.as_owner(move |s| api2.members(s, w.clone()))
        );
        let (listed, members) = (listed.map_err(|e| e.message)?, members.map_err(|e| e.message)?);
        // Public channels only: a direct message or a private channel is neither counted nor named.
        let channels: Vec<_> = listed
            .into_iter()
            .filter(|c| c.kind.as_deref() == Some("public"))
            .collect();
        let live: HashSet<String> = channels.iter().map(|c| c.id.clone()).collect();
        state.channels.retain(|id, _| live.contains(id));
        mem.buffer.retain(|id, _| live.contains(id));
        // Nothing before the counted floor is needed again.
        let until = state.counted_until;
        for buf in mem.buffer.values_mut() {
            let k = buf.iter().take_while(|m| m.created_at < until).count();
            buf.drain(..k);
        }

        // Read what is new. A channel not caught up holds back how far this pass may count.
        let mut horizon = floor_to(now - ANSWER_MS, INTERVAL_MS);
        for ch in &channels {
            if !state.channels.contains_key(&ch.id) {
                state
                    .channels
                    .insert(ch.id.clone(), ChannelState { seq: 0, last_at: None });
            }
            let st_seq = state.channels.get(&ch.id).map(|c| c.seq).unwrap_or(0);
            let mut seq = st_seq.max(*mem.read_seq.get(&ch.id).unwrap_or(&st_seq));
            if ch.last_seq - seq > MAX_BEHIND {
                seq = ch.last_seq - MAX_BEHIND;
            }
            let mut buf = mem.buffer.remove(&ch.id).unwrap_or_default();
            let mut pages = 0;
            // A short page is the end, even below `last_seq`: a deleted message keeps its number.
            let mut caught_up = seq >= ch.last_seq;
            let mut failed: Option<String> = None;
            while !caught_up && pages < MAX_PAGES {
                let (api, id, after) = (self.api.clone(), ch.id.clone(), seq);
                match self.as_owner(move |s| api.messages(s, id.clone(), after, PAGE)).await {
                    Err(e) => {
                        failed = Some(e.message);
                        break;
                    }
                    Ok(page) => {
                        pages += 1;
                        for m in &page {
                            if m.seq > seq {
                                buf.push(to_counted(m, &ctx.handles));
                            }
                        }
                        if let Some(last) = page.last() {
                            seq = seq.max(last.seq);
                        }
                        if (page.len() as i64) < PAGE || seq >= ch.last_seq {
                            caught_up = true;
                        }
                    }
                }
            }
            match failed {
                // One channel ClickClack will not read must not stop the others: skipped this pass.
                Some(e) => {
                    if !mem.failing.contains(&ch.id) {
                        tracing::info!(
                            "[teamchat-stats] could not read a channel, skipping it this pass: {}",
                            crate::integrations::connectors::firewall::js_slice(&e, 160)
                        );
                    }
                    mem.failing.insert(ch.id.clone());
                    caught_up = true;
                }
                None => {
                    mem.failing.remove(&ch.id);
                }
            }
            mem.read_seq.insert(ch.id.clone(), seq);
            let newest = buf.last().map(|m| m.created_at);
            if let (Some(n), Some(st)) = (newest, state.channels.get_mut(&ch.id)) {
                st.last_at = Some(st.last_at.unwrap_or(0).max(n));
            }
            if !caught_up && let Some(n) = newest {
                horizon = horizon.min(floor_to(n - ANSWER_MS, INTERVAL_MS));
            }
            mem.buffer.insert(ch.id.clone(), buf);
        }
        if horizon < state.counted_until {
            horizon = state.counted_until;
        }

        let mut by_start: BTreeMap<i64, (Vec<ChannelCounts>, Vec<PairCount>)> = BTreeMap::new();
        for ch in &channels {
            let buf = mem.buffer.get(&ch.id).cloned().unwrap_or_default();
            for (start, (c, pairs)) in count_channel_range(
                &ch.id,
                &ch.name,
                &buf,
                state.counted_until,
                horizon,
                &ctx.bots,
                &ctx.owner_user_id,
            ) {
                let rec = by_start.entry(start).or_default();
                rec.0.push(c);
                rec.1.extend(pairs);
            }
        }
        let mut records: Vec<Value> = by_start
            .into_iter()
            .map(|(start, (mut chs, mut pairs))| {
                chs.truncate(MAX_CHANNELS);
                pairs.truncate(MAX_PAIRS);
                json!({"source": "teamchat_stats", "interval_start": js::iso(start), "channels": chs, "pairs": pairs})
            })
            .collect();
        // The channel list and the people ride the last record; a quiet pass sends one with no counts.
        let last_start = state.counted_until.max(horizon - INTERVAL_MS);
        if records.is_empty() {
            records.push(
                json!({"source": "teamchat_stats", "interval_start": js::iso(last_start), "channels": [], "pairs": []}),
            );
        }
        let public_members = members.iter().filter(|m| m.id != ctx.owner_user_id).count();
        let list: Vec<Value> = channels
            .iter()
            .take(MAX_CHANNELS * 2)
            .map(|ch| {
                let last = state.channels.get(&ch.id).and_then(|s| s.last_at).filter(|t| *t != 0);
                json!({
                    "id": ch.id,
                    "name": ch.name,
                    // ClickClack has no per-channel membership: a public channel has every member.
                    "members": if ch.kind.as_deref().is_none_or(|k| k == "public") { json!(public_members) } else { Value::Null },
                    "archived": ch.archived,
                    "last_message_at": last.map(js::iso),
                })
            })
            .collect();
        let people = members
            .iter()
            .filter(|m| m.id != ctx.owner_user_id && m.kind.as_deref() != Some("bot") && !ctx.bots.contains_key(&m.id))
            .count();
        if let Some(Value::Object(last)) = records.last_mut() {
            last.insert("channel_list".into(), Value::Array(list));
            last.insert("people".into(), json!(people));
        }
        let n = records.len();
        for chunk in chunk_records(records) {
            if !(self.post)(chunk).await {
                // The floor, the channel list and `lastAt` are kept, as the TS changes its state in
                // place before posting; only the cursor's move waits for the console.
                mem.state = Some(state);
                return Err("the console did not take the counts; trying again next pass".into());
            }
        }

        // Counted: move the cursor and drop what no later interval needs.
        state.counted_until = horizon;
        for ch in &channels {
            let buf = mem.buffer.entry(ch.id.clone()).or_default();
            let k = buf.iter().take_while(|m| m.created_at < horizon).count();
            let read = *mem.read_seq.get(&ch.id).unwrap_or(&0);
            if let Some(st) = state.channels.get_mut(&ch.id) {
                if k > 0 {
                    st.seq = st.seq.max(buf[k - 1].seq);
                } else if buf.is_empty() {
                    st.seq = st.seq.max(read);
                }
            }
            buf.drain(..k);
        }
        self.save(&state);
        mem.state = Some(state);
        Ok(n)
    }
}

/// Posts records to the console's activity route.
pub fn poster(app: &Arc<crate::app::App>, activity_url: String) -> Post {
    let app = app.clone();
    Arc::new(move |records: Vec<Value>| {
        let (app, url) = (app.clone(), activity_url.clone());
        Box::pin(async move {
            let n = records.len();
            match app
                .console
                .post_json(&url, &json!({"records": records}), std::time::Duration::from_secs(30))
                .await
            {
                Ok(r) if r.status == 400 || r.status == 413 => {
                    // Never accepted, whatever we do: move on rather than wedge.
                    tracing::info!(
                        "[teamchat-stats] the console refused {n} records (HTTP {}); dropping them",
                        r.status
                    );
                    true
                }
                Ok(r) => (200..300).contains(&r.status),
                Err(_) => false,
            }
        })
    })
}

#[cfg(test)]
mod tests;
