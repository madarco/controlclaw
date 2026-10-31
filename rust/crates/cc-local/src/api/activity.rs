//! Activity and the overview: what the SaaS's `activity.listActivity` and `firewallStats.*` give
//! the console, from this firewall's own database (`activity_raw`, kept 30 days, and
//! `activity_hourly`). Times are UTC: "today" starts at midnight UTC.

use std::collections::BTreeMap;

use rusqlite::params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Ctx, Reply, Result, Route};
use crate::db::{Db, now_s};
use crate::plane::{iso, parse_iso};

const TAG: &str = "activity";
/// A request over 25 s is a long-poll or a websocket: left out of the response time.
const RESPONSE_MAX_MS: i64 = 25_000;
const LIVE_MAX: i64 = 50;

pub fn routes() -> Vec<Route> {
    vec![
        Route::get::<ActivityQuery, ActivityPage, _, _>(
            "/api/activity",
            TAG,
            "Activity rows by kind and verdict, newest first, with the counts",
            |c| async move { list(&c) },
        ),
        Route::get::<RangeQuery, Overview, _, _>(
            "/api/overview",
            TAG,
            "The overview: the cards, the traffic chart, the live list, top hosts, agents and AI findings",
            |c| async move {
                let q: RangeQuery = c.query()?;
                Ok(Reply::ok(&overview(&c.db, q.range.unwrap_or_default(), now_s())?))
            },
        ),
        Route::get::<RangeQuery, Traffic, _, _>("/api/traffic", TAG, "The traffic chart for a range", |c| async move {
            let q: RangeQuery = c.query()?;
            let range = q.range.unwrap_or_default();
            Ok(Reply::ok(&Traffic {
                range,
                points: traffic(&c.db, range, now_s())?,
            }))
        }),
        Route::get::<LiveQuery, Vec<LiveRequest>, _, _>(
            "/api/live",
            TAG,
            "The newest requests (at most 50), after a cursor",
            |c| async move {
                let q: LiveQuery = c.query()?;
                let after = q.after_id;
                Ok(Reply::ok(&live(&c.db, after)?))
            },
        ),
    ]
}

// ---- the activity list ----

/// Which log: `network` is traffic and what the firewall decided about messages and webhooks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    #[default]
    Network,
    Tools,
    Runs,
    Findings,
    Connectors,
}

impl Kind {
    fn sources(self) -> &'static [&'static str] {
        match self {
            Self::Network => &["egress", "webhook", "content_rule", "email_held"],
            Self::Tools => &["tool_action"],
            Self::Runs => &["agent_run"],
            Self::Findings => &["ai_review"],
            Self::Connectors => &["connector_run", "connector_call"],
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VerdictFilter {
    #[default]
    All,
    Allow,
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allowed,
    Asked,
    Blocked,
    /// Neither: a finding, a record.
    Recorded,
}

/// Egress rows keep the rule's effect: these let the request out or held it; any other is blocked.
const EGRESS_ALLOW: &[&str] = &["allow", "tunnel", "residential"];
const EGRESS_ASK: &[&str] = &["require_permission"];
/// The other sources' statuses, by verdict; one in none of them is only recorded.
const OTHER_ALLOW: &[&str] = &["allowed", "allow", "succeeded", "delivered"];
const OTHER_ASK: &[&str] = &["asked", "ask", "held", "hold", "started"];
const OTHER_BLOCK: &[&str] = &[
    "blocked",
    "block",
    "denied",
    "refused",
    "failed",
    "timed_out",
    "cancelled",
    "stopped",
];

/// The verdict of a stored row. The filters below are the same lists, so a row is counted on the
/// tab its label names.
fn verdict(source: &str, status: &str) -> Verdict {
    let s = &status;
    if source == "egress" {
        return if EGRESS_ALLOW.contains(s) {
            Verdict::Allowed
        } else if EGRESS_ASK.contains(s) {
            Verdict::Asked
        } else {
            Verdict::Blocked
        };
    }
    if OTHER_ALLOW.contains(s) {
        Verdict::Allowed
    } else if OTHER_ASK.contains(s) {
        Verdict::Asked
    } else if OTHER_BLOCK.contains(s) {
        Verdict::Blocked
    } else {
        Verdict::Recorded
    }
}

/// `'a', 'b'`: the lists are ours, never the request's.
fn quoted(l: &[&str]) -> String {
    l.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", ")
}

/// SQL for the rows of a verdict filter; `None` for all.
fn verdict_sql(f: VerdictFilter) -> Option<String> {
    let (egress, other) = match f {
        VerdictFilter::All => return None,
        VerdictFilter::Allow => (format!("IN ({})", quoted(EGRESS_ALLOW)), quoted(OTHER_ALLOW)),
        VerdictFilter::Ask => (format!("IN ({})", quoted(EGRESS_ASK)), quoted(OTHER_ASK)),
        VerdictFilter::Block => (
            format!("NOT IN ({}, {})", quoted(EGRESS_ALLOW), quoted(EGRESS_ASK)),
            quoted(OTHER_BLOCK),
        ),
    };
    Some(format!(
        "((a.source = 'egress' AND a.status {egress}) OR (a.source <> 'egress' AND a.status IN ({other})))"
    ))
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct ActivityQuery {
    #[serde(default)]
    pub source: Kind,
    #[serde(default)]
    pub verdict: VerdictFilter,
    /// Words to find in the row's text, at most 200 characters.
    #[serde(default)]
    pub q: Option<String>,
    /// 1 to 100; 25 when left out.
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActivityRow {
    pub id: String,
    pub created_at: String,
    pub verdict: Verdict,
    pub source: String,
    pub message: String,
    /// The agent's name, or null for the firewall's own.
    pub agent: Option<String>,
    pub vm_id: Option<String>,
    /// The status as the box sent it (the rule's effect for traffic).
    pub status: String,
    /// Traffic only: the upstream's HTTP status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i64>,
    /// Traffic only: the rule that decided it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct Counts {
    pub all: i64,
    pub allow: i64,
    pub ask: i64,
    pub block: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityPage {
    pub rows: Vec<ActivityRow>,
    /// For the verdict tabs, whatever the verdict filter.
    pub counts: Counts,
    /// Rows the filter matches.
    pub total: i64,
}

/// `?1` to `?n` for a list.
fn marks(from: usize, n: usize) -> String {
    (from..from + n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ")
}

fn list(c: &Ctx) -> Result {
    let q: ActivityQuery = c.query()?;
    let limit = q.limit.unwrap_or(25).clamp(1, 100);
    let offset = q.offset.unwrap_or(0).max(0);
    let words = q.q.as_deref().map(str::trim).filter(|w| !w.is_empty());
    if words.is_some_and(|w| w.chars().count() > 200) {
        return Err(Reply::bad("q: at most 200 characters"));
    }
    let sources = q.source.sources();
    let like = words.map(|w| format!("%{}%", w.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    // The rows of these sources, matching the words: the base every count and the page share.
    let mut base = format!("a.source IN ({})", marks(1, sources.len()));
    let mut args: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
    if let Some(l) = &like {
        args.push(l.clone());
        base.push_str(&format!(
            " AND (a.summary LIKE ?{n} ESCAPE '\\' OR COALESCE(g.name, '') LIKE ?{n} ESCAPE '\\')",
            n = args.len()
        ));
    }
    let db = c.db.lock();
    // The four counts in one pass.
    let case = |f| {
        format!(
            "SUM(CASE WHEN {} THEN 1 ELSE 0 END)",
            verdict_sql(f).unwrap_or_default()
        )
    };
    let counts = db.query_row(
        &format!(
            "SELECT COUNT(*), {}, {}, {} FROM activity_raw a LEFT JOIN agents g ON g.vm_id = a.vm_id WHERE {base}",
            case(VerdictFilter::Allow),
            case(VerdictFilter::Ask),
            case(VerdictFilter::Block)
        ),
        rusqlite::params_from_iter(args.iter()),
        |r| {
            Ok(Counts {
                all: r.get(0)?,
                allow: r.get::<_, Option<i64>>(1)?.unwrap_or(0),
                ask: r.get::<_, Option<i64>>(2)?.unwrap_or(0),
                block: r.get::<_, Option<i64>>(3)?.unwrap_or(0),
            })
        },
    )?;
    let total = match q.verdict {
        VerdictFilter::All => counts.all,
        VerdictFilter::Allow => counts.allow,
        VerdictFilter::Ask => counts.ask,
        VerdictFilter::Block => counts.block,
    };
    let w = verdict_sql(q.verdict).map(|v| format!(" AND {v}")).unwrap_or_default();
    let mut stmt = db.prepare(&format!(
        "SELECT a.id, a.occurred_at, a.source, a.status, a.summary, a.vm_id, g.name,
                json_extract(a.record, '$.status_code'), json_extract(a.record, '$.rule')
         FROM activity_raw a LEFT JOIN agents g ON g.vm_id = a.vm_id
         WHERE {base}{w} ORDER BY a.occurred_at DESC, a.id DESC LIMIT {limit} OFFSET {offset}"
    ))?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(args.iter()), |r| {
            let (source, status): (String, String) = (r.get(2)?, r.get(3)?);
            Ok(ActivityRow {
                id: r.get::<_, i64>(0)?.to_string(),
                created_at: iso(r.get(1)?),
                verdict: verdict(&source, &status),
                message: r.get(4)?,
                vm_id: r.get(5)?,
                agent: r.get(6)?,
                status_code: r.get::<_, Option<i64>>(7).ok().flatten(),
                rule: r.get::<_, Option<String>>(8).ok().flatten(),
                source,
                status,
            })
        })?
        .collect::<rusqlite::Result<_>>()?;
    Ok(Reply::ok(&ActivityPage { rows, counts, total }))
}

// ---- the overview ----

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum Range {
    #[serde(rename = "1h")]
    Hour,
    #[default]
    #[serde(rename = "24h")]
    Day,
    #[serde(rename = "7d")]
    Week,
}

impl Range {
    /// (bucket count, bucket seconds): by minute, by half hour, by three hours.
    fn buckets(self) -> (i64, i64) {
        match self {
            Self::Hour => (60, 60),
            Self::Day => (48, 1800),
            Self::Week => (56, 3 * 3600),
        }
    }
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct RangeQuery {
    #[serde(default)]
    pub range: Option<Range>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LiveQuery {
    /// `id` of the newest row the list holds: only rows after it.
    #[serde(default)]
    pub after_id: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, JsonSchema)]
pub struct TrafficPoint {
    /// The bucket's start.
    pub at: String,
    pub allowed: i64,
    pub asked: i64,
    pub blocked: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Traffic {
    pub range: Range,
    pub points: Vec<TrafficPoint>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LiveRequest {
    /// The list's cursor (`afterId`).
    pub id: i64,
    pub created_at: String,
    pub occurred_at: String,
    pub method: Option<String>,
    pub host: String,
    pub agent: Option<String>,
    pub verdict: Verdict,
    pub duration_ms: Option<i64>,
    /// A tunnel or a request over 25 s.
    pub long: bool,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct CardSeries {
    /// Today so far, and yesterday up to the same time.
    pub today: i64,
    pub yesterday: i64,
    /// One value per hour, oldest first, matching `hours`.
    pub series: Vec<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PerMinute {
    /// Requests in the last full minute.
    pub value: i64,
    #[serde(flatten)]
    pub series: CardSeries,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ResponseTime {
    /// Median ms of allowed requests in the last hour; null with none.
    pub value: Option<i64>,
    pub today: Option<i64>,
    pub yesterday: Option<i64>,
    pub series: Vec<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct TopHost {
    pub host: String,
    pub total: i64,
    pub blocked: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentTraffic {
    /// Null for the firewall's own traffic.
    pub vm_id: Option<String>,
    pub name: String,
    pub total: i64,
    pub blocked: i64,
    /// Requests per hour over the last 24 hours.
    pub hourly: Vec<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AiFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub agent: Option<String>,
    pub at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct AiCard {
    pub enabled: bool,
    pub findings: Vec<AiFinding>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Shields {
    /// Enabled egress rules.
    pub site_rules: i64,
    pub ai_keys: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Month {
    /// Requests this calendar month (UTC).
    pub count: i64,
    pub resets_at: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub generated_at: String,
    /// The hour starts of the cards' series: the last 24, oldest first.
    pub hours: Vec<String>,
    pub per_minute: PerMinute,
    pub blocked: CardSeries,
    pub response: ResponseTime,
    pub month: Month,
    pub traffic: Traffic,
    pub live: Vec<LiveRequest>,
    pub top_hosts: Vec<TopHost>,
    pub by_agent: Vec<AgentTraffic>,
    pub ai: AiCard,
    pub shields: Shields,
}

/// SQL: the row is a request the firewall let out, blocked or held.
const EGRESS: &str = "source = 'egress'";
const BLOCKED: &str = "status IN ('block', 'drop')";

fn traffic(db: &Db, range: Range, now: i64) -> rusqlite::Result<Vec<TrafficPoint>> {
    let (n, size) = range.buckets();
    let last = now - now.rem_euclid(size);
    let first = last - (n - 1) * size;
    let mut points: Vec<TrafficPoint> = (0..n)
        .map(|i| TrafficPoint {
            at: iso(first + i * size),
            ..Default::default()
        })
        .collect();
    let c = db.lock();
    let mut q = c.prepare(&format!(
        "SELECT (occurred_at - ?1) / ?2, status, COUNT(*) FROM activity_raw
         WHERE {EGRESS} AND occurred_at >= ?1 AND occurred_at < ?3 GROUP BY 1, 2"
    ))?;
    let rows = q.query_map(params![first, size, last + size], |r| {
        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
    })?;
    for row in rows {
        let (i, status, count) = row?;
        let Some(p) = usize::try_from(i).ok().and_then(|i| points.get_mut(i)) else {
            continue;
        };
        match verdict("egress", &status) {
            Verdict::Allowed => p.allowed += count,
            Verdict::Asked => p.asked += count,
            _ => p.blocked += count,
        }
    }
    Ok(points)
}

fn live(db: &Db, after: Option<i64>) -> rusqlite::Result<Vec<LiveRequest>> {
    let c = db.lock();
    let mut q = c.prepare(&format!(
        "SELECT a.id, a.created_at, a.occurred_at, json_extract(a.record, '$.method'), json_extract(a.record, '$.host'),
                g.name, a.status, json_extract(a.record, '$.duration_ms')
         FROM activity_raw a LEFT JOIN agents g ON g.vm_id = a.vm_id
         WHERE a.{EGRESS} AND a.id > ?1 ORDER BY a.id DESC LIMIT {LIVE_MAX}"
    ))?;
    q.query_map([after.unwrap_or(0)], |r| {
        let status: String = r.get(6)?;
        let ms: Option<f64> = r.get(7).ok().flatten();
        let ms = ms.map(|m| m.round() as i64);
        Ok(LiveRequest {
            id: r.get(0)?,
            created_at: iso(r.get(1)?),
            occurred_at: iso(r.get(2)?),
            method: r.get(3).ok().flatten(),
            host: r.get::<_, Option<String>>(4).ok().flatten().unwrap_or_default(),
            agent: r.get(5)?,
            verdict: verdict("egress", &status),
            duration_ms: ms,
            long: status == "tunnel" || ms.is_some_and(|m| m > RESPONSE_MAX_MS),
        })
    })?
    .collect()
}

fn median(mut v: Vec<i64>) -> Option<i64> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

/// The response times (ms) of allowed requests between `from` and `to`, at most 20,000 of them.
fn durations(db: &Db, from: i64, to: i64) -> rusqlite::Result<Vec<(i64, i64)>> {
    let c = db.lock();
    let mut q = c.prepare(&format!(
        "SELECT occurred_at, json_extract(record, '$.duration_ms') FROM activity_raw
         WHERE {EGRESS} AND status = 'allow' AND occurred_at >= ?1 AND occurred_at < ?2
           AND json_extract(record, '$.duration_ms') IS NOT NULL
         ORDER BY occurred_at DESC LIMIT 20000"
    ))?;
    q.query_map(params![from, to], |r| {
        let ms: f64 = r.get(1)?;
        Ok((r.get::<_, i64>(0)?, ms.round() as i64))
    })?
    .filter(|r| r.as_ref().map_or(true, |(_, ms)| (0..=RESPONSE_MAX_MS).contains(ms)))
    .collect()
}

fn count(db: &Db, sql_where: &str, from: i64, to: i64) -> rusqlite::Result<i64> {
    db.lock().query_row(
        &format!("SELECT COUNT(*) FROM activity_raw WHERE {sql_where} AND occurred_at >= ?1 AND occurred_at < ?2"),
        params![from, to],
        |r| r.get(0),
    )
}

pub fn overview(db: &Db, range: Range, now: i64) -> rusqlite::Result<Overview> {
    let hour0 = now - now.rem_euclid(3600) - 23 * 3600;
    let hours: Vec<i64> = (0..24).map(|i| hour0 + i * 3600).collect();
    let today = now - now.rem_euclid(86_400);
    let (yday, yday_now) = (today - 86_400, now - 86_400);
    // Per hour, per agent and verdict, from the rollup.
    let mut per_hour: BTreeMap<(i64, String), (i64, i64)> = BTreeMap::new();
    {
        let c = db.lock();
        let mut q = c.prepare(
            "SELECT hour, vm_id, status, SUM(count) FROM activity_hourly WHERE source = 'egress' AND hour >= ?1 GROUP BY 1, 2, 3",
        )?;
        let rows = q.query_map([hour0], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })?;
        for row in rows {
            let (hour, vm, status, n) = row?;
            let e = per_hour.entry((hour, vm)).or_default();
            e.0 += n;
            if verdict("egress", &status) == Verdict::Blocked {
                e.1 += n;
            }
        }
    }
    let series = |pick: fn(&(i64, i64)) -> i64| -> Vec<i64> {
        hours
            .iter()
            .map(|h| {
                per_hour
                    .iter()
                    .filter(|((hh, _), _)| hh == h)
                    .map(|(_, v)| pick(v))
                    .sum()
            })
            .collect()
    };
    let totals = series(|v| v.0);
    let per_minute = PerMinute {
        value: count(db, EGRESS, now - now.rem_euclid(60) - 60, now - now.rem_euclid(60))?,
        series: CardSeries {
            today: count(db, EGRESS, today, now)?,
            yesterday: count(db, EGRESS, yday, yday_now)?,
            series: totals.iter().map(|n| n / 60).collect(),
        },
    };
    let blocked_where = format!("{EGRESS} AND {BLOCKED}");
    let blocked = CardSeries {
        today: count(db, &blocked_where, today, now)?,
        yesterday: count(db, &blocked_where, yday, yday_now)?,
        series: series(|v| v.1),
    };
    let times = durations(db, yday.min(hour0), now)?;
    let within = |from: i64, to: i64| {
        times
            .iter()
            .filter(|(t, _)| *t >= from && *t < to)
            .map(|(_, ms)| *ms)
            .collect()
    };
    let response = ResponseTime {
        value: median(within(now - 3600, now)),
        today: median(within(today, now)),
        yesterday: median(within(yday, yday_now)),
        series: hours
            .iter()
            .map(|h| median(within(*h, h + 3600)).unwrap_or(0))
            .collect(),
    };
    let (month_start, next_month) = month_bounds(now);
    let names: BTreeMap<String, String> = {
        let c = db.lock();
        let mut q = c.prepare("SELECT vm_id, name FROM agents WHERE role <> 'mitm'")?;
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let mut by_agent: BTreeMap<String, AgentTraffic> = BTreeMap::new();
    for ((hour, vm), (n, b)) in &per_hour {
        let a = by_agent.entry(vm.clone()).or_insert_with(|| AgentTraffic {
            vm_id: (!vm.is_empty()).then(|| vm.clone()),
            name: if vm.is_empty() {
                "Firewall".into()
            } else {
                names.get(vm).cloned().unwrap_or_else(|| vm.clone())
            },
            total: 0,
            blocked: 0,
            hourly: vec![0; 24],
        });
        a.total += n;
        a.blocked += b;
        if let Some(slot) = usize::try_from((hour - hour0) / 3600)
            .ok()
            .and_then(|i| a.hourly.get_mut(i))
        {
            *slot += n;
        }
    }
    let mut by_agent: Vec<AgentTraffic> = by_agent.into_values().collect();
    by_agent.sort_by_key(|a| std::cmp::Reverse(a.total));
    let (top_hosts, findings, site_rules, ai_keys, ai_on) = {
        let c = db.lock();
        let mut q = c.prepare(&format!(
            "SELECT json_extract(record, '$.host') AS h, COUNT(*), SUM(CASE WHEN {BLOCKED} THEN 1 ELSE 0 END)
             FROM activity_raw WHERE {EGRESS} AND occurred_at >= ?1 AND h IS NOT NULL
             GROUP BY h ORDER BY 2 DESC LIMIT 8"
        ))?;
        let top: Vec<TopHost> = q
            .query_map([now - 86_400], |r| {
                Ok(TopHost {
                    host: r.get(0)?,
                    total: r.get(1)?,
                    blocked: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut q = c.prepare(
            "SELECT a.id, a.status, a.summary, g.name, a.occurred_at FROM activity_raw a LEFT JOIN agents g ON g.vm_id = a.vm_id
             WHERE a.source = 'ai_review' AND a.status IN ('medium', 'high') AND a.occurred_at >= ?1
             ORDER BY a.occurred_at DESC LIMIT 5",
        )?;
        let findings: Vec<AiFinding> = q
            .query_map([now - 86_400], |r| {
                Ok(AiFinding {
                    id: r.get::<_, i64>(0)?.to_string(),
                    severity: r.get(1)?,
                    title: r.get(2)?,
                    agent: r.get(3)?,
                    at: iso(r.get(4)?),
                })
            })?
            .collect::<rusqlite::Result<_>>()?;
        let site_rules: i64 = c.query_row("SELECT COUNT(*) FROM egress_rules WHERE enabled = 1", [], |r| r.get(0))?;
        let ai_keys: i64 = c.query_row("SELECT COUNT(*) FROM llm_keys WHERE state = 'active'", [], |r| r.get(0))?;
        let ai: Option<String> = c
            .query_row("SELECT settings FROM ai_settings WHERE id = 1", [], |r| r.get(0))
            .ok();
        let ai_on = ai
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .is_some_and(|v| v.get("checks").and_then(Value::as_bool) == Some(true));
        (top, findings, site_rules, ai_keys, ai_on)
    };
    Ok(Overview {
        generated_at: iso(now),
        hours: hours.iter().map(|h| iso(*h)).collect(),
        per_minute,
        blocked,
        response,
        month: Month {
            count: count(db, EGRESS, month_start, now + 1)?,
            resets_at: iso(next_month),
        },
        traffic: Traffic {
            range,
            points: traffic(db, range, now)?,
        },
        live: live(db, None)?,
        top_hosts,
        by_agent,
        ai: AiCard {
            enabled: ai_on,
            findings,
        },
        shields: Shields { site_rules, ai_keys },
    })
}

/// The first second of this UTC month and of the next.
fn month_bounds(now: i64) -> (i64, i64) {
    let day = &iso(now)[..7];
    let (y, m): (i64, i64) = (day[..4].parse().unwrap_or(1970), day[5..7].parse().unwrap_or(1));
    let at = |y: i64, m: i64| parse_iso(&format!("{y:04}-{m:02}-01T00:00:00Z")).unwrap_or(0);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    (at(y, m), at(ny, nm))
}
